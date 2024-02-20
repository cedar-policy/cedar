/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Defines structures for entity type and action id information used by the
//! validator. The contents of these structures should be populated from and schema
//! with a few transformations applied to the data. Specifically, the
//! `member_of` relation from the schema is reversed and the transitive closure is
//! computed to obtain a `descendants` relation.

use std::collections::{hash_map::Entry, HashMap, HashSet};

use cedar_policy_core::{
    ast::{Entity, EntityType, EntityUID, Name},
    entities::{Entities, EntitiesError, TCComputation},
    extensions::Extensions,
    transitive_closure::compute_tc,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::NamespaceDefinition;
use crate::{
    err::*,
    human_schema::SchemaWarning,
    types::{Attributes, EntityRecordKind, OpenTag, Type},
    SchemaFragment,
};

mod action;
pub use action::ValidatorActionId;
pub(crate) use action::ValidatorApplySpec;
mod entity_type;
pub use entity_type::ValidatorEntityType;
mod namespace_def;
pub(crate) use namespace_def::is_action_entity_type;
pub use namespace_def::ValidatorNamespaceDef;
#[cfg(test)]
pub(crate) use namespace_def::ACTION_ENTITY_TYPE;

// We do not have a formal model for action attributes, so we disable them by default.
#[derive(Eq, PartialEq, Copy, Clone, Default)]
pub enum ActionBehavior {
    /// Action entities cannot have attributes. Attempting to declare attributes
    /// will result in a error when constructing the schema.
    #[default]
    ProhibitAttributes,
    /// Action entities may have attributes.
    PermitAttributes,
}

#[derive(Debug)]
pub struct ValidatorSchemaFragment(Vec<ValidatorNamespaceDef>);

impl TryInto<ValidatorSchemaFragment> for SchemaFragment {
    type Error = SchemaError;

    fn try_into(self) -> Result<ValidatorSchemaFragment> {
        ValidatorSchemaFragment::from_schema_fragment(
            self,
            ActionBehavior::default(),
            Extensions::all_available(),
        )
    }
}

impl ValidatorSchemaFragment {
    pub fn from_namespaces(namespaces: impl IntoIterator<Item = ValidatorNamespaceDef>) -> Self {
        Self(namespaces.into_iter().collect())
    }

    pub fn from_schema_fragment(
        fragment: SchemaFragment,
        action_behavior: ActionBehavior,
        extensions: Extensions<'_>,
    ) -> Result<Self> {
        Ok(Self(
            fragment
                .0
                .into_iter()
                .map(|(fragment_ns, ns_def)| {
                    ValidatorNamespaceDef::from_namespace_definition(
                        Some(fragment_ns),
                        ns_def,
                        action_behavior,
                        extensions,
                    )
                })
                .collect::<Result<Vec<_>>>()?,
        ))
    }

    /// Access the `Name`s for the namespaces in this fragment.
    pub fn namespaces(&self) -> impl Iterator<Item = &Option<Name>> {
        self.0.iter().map(|d| d.namespace())
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize)]
pub struct ValidatorSchema {
    /// Map from entity type names to the ValidatorEntityType object.
    #[serde(rename = "entityTypes")]
    #[serde_as(as = "Vec<(_, _)>")]
    entity_types: HashMap<Name, ValidatorEntityType>,

    /// Map from action id names to the ValidatorActionId object.
    #[serde(rename = "actionIds")]
    #[serde_as(as = "Vec<(_, _)>")]
    action_ids: HashMap<EntityUID, ValidatorActionId>,
}

impl std::str::FromStr for ValidatorSchema {
    type Err = SchemaError;

    fn from_str(s: &str) -> Result<Self> {
        serde_json::from_str::<SchemaFragment>(s)?.try_into()
    }
}

impl TryFrom<NamespaceDefinition> for ValidatorSchema {
    type Error = SchemaError;

    fn try_from(nsd: NamespaceDefinition) -> Result<ValidatorSchema> {
        ValidatorSchema::from_schema_fragments([ValidatorSchemaFragment::from_namespaces([
            nsd.try_into()?
        ])])
    }
}

impl TryFrom<SchemaFragment> for ValidatorSchema {
    type Error = SchemaError;

    fn try_from(frag: SchemaFragment) -> Result<ValidatorSchema> {
        ValidatorSchema::from_schema_fragments([frag.try_into()?])
    }
}

impl ValidatorSchema {
    // Create a ValidatorSchema without any entity types or actions ids.
    pub fn empty() -> ValidatorSchema {
        Self {
            entity_types: HashMap::new(),
            action_ids: HashMap::new(),
        }
    }

    /// Construct a `ValidatorSchema` from a JSON value (which should be an
    /// object matching the `SchemaFileFormat` shape).
    pub fn from_json_value(json: serde_json::Value, extensions: Extensions<'_>) -> Result<Self> {
        Self::from_schema_file(
            SchemaFragment::from_json_value(json)?,
            ActionBehavior::default(),
            extensions,
        )
    }

    /// Construct a `ValidatorSchema` directly from a file.
    pub fn from_file(file: impl std::io::Read, extensions: Extensions<'_>) -> Result<Self> {
        Self::from_schema_file(
            SchemaFragment::from_file(file)?,
            ActionBehavior::default(),
            extensions,
        )
    }

    pub fn from_file_natural(
        r: impl std::io::Read,
        extensions: Extensions<'_>,
    ) -> std::result::Result<(Self, impl Iterator<Item = SchemaWarning>), HumanSchemaError> {
        let (fragment, warnings) = SchemaFragment::from_file_natural(r)?;
        let schema_and_warnings =
            Self::from_schema_file(fragment, ActionBehavior::default(), extensions)
                .map(|schema| (schema, warnings))?;
        Ok(schema_and_warnings)
    }

    pub fn from_str_natural(
        src: &str,
        extensions: Extensions<'_>,
    ) -> std::result::Result<(Self, impl Iterator<Item = SchemaWarning>), HumanSchemaError> {
        let (fragment, warnings) = SchemaFragment::from_str_natural(src)?;
        let schema_and_warnings =
            Self::from_schema_file(fragment, ActionBehavior::default(), extensions)
                .map(|schema| (schema, warnings))?;
        Ok(schema_and_warnings)
    }

    pub fn from_schema_file(
        schema_file: SchemaFragment,
        action_behavior: ActionBehavior,
        extensions: Extensions<'_>,
    ) -> Result<ValidatorSchema> {
        Self::from_schema_fragments([ValidatorSchemaFragment::from_schema_fragment(
            schema_file,
            action_behavior,
            extensions,
        )?])
    }

    /// Construct a new `ValidatorSchema` from some number of schema fragments.
    pub fn from_schema_fragments(
        fragments: impl IntoIterator<Item = ValidatorSchemaFragment>,
    ) -> Result<ValidatorSchema> {
        let mut type_defs = HashMap::new();
        let mut entity_type_fragments = HashMap::new();
        let mut action_fragments = HashMap::new();

        for ns_def in fragments.into_iter().flat_map(|f| f.0.into_iter()) {
            // Build aggregate maps for the declared typedefs, entity types, and
            // actions, checking that nothing is defined twice.  Namespaces were
            // already added by the `ValidatorNamespaceDef`, so the same base
            // type name may appear multiple times so long as the namespaces are
            // different.
            for (name, ty) in ns_def.type_defs.type_defs {
                match type_defs.entry(name) {
                    Entry::Vacant(v) => v.insert(ty),
                    Entry::Occupied(o) => {
                        return Err(SchemaError::DuplicateCommonType(o.key().to_string()));
                    }
                };
            }

            for (name, entity_type) in ns_def.entity_types.entity_types {
                match entity_type_fragments.entry(name) {
                    Entry::Vacant(v) => v.insert(entity_type),
                    Entry::Occupied(o) => {
                        return Err(SchemaError::DuplicateEntityType(o.key().to_string()))
                    }
                };
            }

            for (action_euid, action) in ns_def.actions.actions {
                match action_fragments.entry(action_euid) {
                    Entry::Vacant(v) => v.insert(action),
                    Entry::Occupied(o) => {
                        return Err(SchemaError::DuplicateAction(o.key().to_string()))
                    }
                };
            }
        }

        // Invert the `parents` relation defined by entities and action so far
        // to get a `children` relation.
        let mut entity_children = HashMap::new();
        for (name, entity_type) in entity_type_fragments.iter() {
            for parent in entity_type.parents.iter() {
                entity_children
                    .entry(parent.clone())
                    .or_insert_with(HashSet::new)
                    .insert(name.clone());
            }
        }

        let mut entity_types = entity_type_fragments
            .into_iter()
            .map(|(name, entity_type)| -> Result<_> {
                // Keys of the `entity_children` map were values of an
                // `memberOfTypes` list, so they might not have been declared in
                // their fragment.  By removing entries from `entity_children`
                // where the key is a declared name, we will be left with a map
                // where the keys are undeclared. These keys are used to report
                // an error when undeclared entity types are referenced inside a
                // `memberOfTypes` list. The error is reported alongside the
                // error for any other undeclared entity types by
                // `check_for_undeclared`.
                let descendants = entity_children.remove(&name).unwrap_or_default();
                let (attributes, open_attributes) = Self::record_attributes_or_none(
                    entity_type.attributes.resolve_type_defs(&type_defs)?,
                )
                .ok_or(SchemaError::ContextOrShapeNotRecord(
                    ContextOrShape::EntityTypeShape(name.clone()),
                ))?;
                Ok((
                    name.clone(),
                    ValidatorEntityType {
                        name,
                        descendants,
                        attributes,
                        open_attributes,
                    },
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        let mut action_children = HashMap::new();
        for (euid, action) in action_fragments.iter() {
            for parent in action.parents.iter() {
                action_children
                    .entry(parent.clone())
                    .or_insert_with(HashSet::new)
                    .insert(euid.clone());
            }
        }
        let mut action_ids = action_fragments
            .into_iter()
            .map(|(name, action)| -> Result<_> {
                let descendants = action_children.remove(&name).unwrap_or_default();
                let (context, open_context_attributes) =
                    Self::record_attributes_or_none(action.context.resolve_type_defs(&type_defs)?)
                        .ok_or(SchemaError::ContextOrShapeNotRecord(
                            ContextOrShape::ActionContext(name.clone()),
                        ))?;
                Ok((
                    name.clone(),
                    ValidatorActionId {
                        name,
                        applies_to: action.applies_to,
                        descendants,
                        context: Type::record_with_attributes(
                            context.attrs,
                            open_context_attributes,
                        ),
                        attribute_types: action.attribute_types,
                        attributes: action.attributes,
                    },
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        // We constructed entity types and actions with child maps, but we need
        // transitively closed descendants.
        compute_tc(&mut entity_types, false)?;
        // Pass `true` here so that we also check that the action hierarchy does
        // not contain cycles.
        compute_tc(&mut action_ids, true)?;

        // Return with an error if there is an undeclared entity or action
        // referenced in any fragment. `{entity,action}_children` are provided
        // for the `undeclared_parent_{entities,actions}` arguments because
        // removed keys from these maps as we encountered declarations for the
        // entity types or actions. Any keys left in the map are therefore
        // undeclared.
        Self::check_for_undeclared(
            &entity_types,
            entity_children.into_keys(),
            &action_ids,
            action_children.into_keys(),
        )?;

        Ok(ValidatorSchema {
            entity_types,
            action_ids,
        })
    }

    /// Check that all entity types and actions referenced in the schema are in
    /// the set of declared entity type or action names. Point of caution: this
    /// function assumes that all entity types are fully qualified. This is
    /// handled by the `SchemaFragment` constructor.
    fn check_for_undeclared(
        entity_types: &HashMap<Name, ValidatorEntityType>,
        undeclared_parent_entities: impl IntoIterator<Item = Name>,
        action_ids: &HashMap<EntityUID, ValidatorActionId>,
        undeclared_parent_actions: impl IntoIterator<Item = EntityUID>,
    ) -> Result<()> {
        // When we constructed `entity_types`, we removed entity types from  the
        // `entity_children` map as we encountered a declaration for that type.
        // Any entity types left in the map are therefore undeclared. These are
        // any undeclared entity types which appeared in a `memberOf` list.
        let mut undeclared_e = undeclared_parent_entities
            .into_iter()
            .map(|n| n.to_string())
            .collect::<HashSet<_>>();
        // Looking at entity types, we need to check entity references in
        // attribute types. We already know that all elements of the
        // `descendants` list were declared because the list is a result of
        // inverting the `memberOf` relationship which mapped declared entity
        // types to their parent entity types.
        for entity_type in entity_types.values() {
            for (_, attr_typ) in entity_type.attributes() {
                Self::check_undeclared_in_type(
                    &attr_typ.attr_type,
                    entity_types,
                    &mut undeclared_e,
                );
            }
        }

        // Undeclared actions in a `memberOf` list.
        let undeclared_a = undeclared_parent_actions
            .into_iter()
            .map(|n| n.to_string())
            .collect::<HashSet<_>>();
        // For actions, we check entity references in the context attribute
        // types and `appliesTo` lists. See the `entity_types` loop for why the
        // `descendants` list is not checked.
        for action in action_ids.values() {
            Self::check_undeclared_in_type(&action.context, entity_types, &mut undeclared_e);

            for p_entity in action.applies_to.applicable_principal_types() {
                match p_entity {
                    EntityType::Specified(p_entity) => {
                        if !entity_types.contains_key(p_entity) {
                            undeclared_e.insert(p_entity.to_string());
                        }
                    }
                    EntityType::Unspecified => (),
                }
            }

            for r_entity in action.applies_to.applicable_resource_types() {
                match r_entity {
                    EntityType::Specified(r_entity) => {
                        if !entity_types.contains_key(r_entity) {
                            undeclared_e.insert(r_entity.to_string());
                        }
                    }
                    EntityType::Unspecified => (),
                }
            }
        }
        if !undeclared_e.is_empty() {
            return Err(SchemaError::UndeclaredEntityTypes(undeclared_e));
        }
        if !undeclared_a.is_empty() {
            return Err(SchemaError::UndeclaredActions(undeclared_a));
        }

        Ok(())
    }

    fn record_attributes_or_none(ty: Type) -> Option<(Attributes, OpenTag)> {
        match ty {
            Type::EntityOrRecord(EntityRecordKind::Record {
                attrs,
                open_attributes,
            }) => Some((attrs, open_attributes)),
            _ => None,
        }
    }

    // Check that all entity types appearing inside a type are in the set of
    // declared entity types, adding any undeclared entity types to the
    // `undeclared_types` set.
    fn check_undeclared_in_type(
        ty: &Type,
        entity_types: &HashMap<Name, ValidatorEntityType>,
        undeclared_types: &mut HashSet<String>,
    ) {
        match ty {
            Type::EntityOrRecord(EntityRecordKind::Entity(lub)) => {
                for name in lub.iter() {
                    if !entity_types.contains_key(name) {
                        undeclared_types.insert(name.to_string());
                    }
                }
            }

            Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) => {
                for (_, attr_ty) in attrs.iter() {
                    Self::check_undeclared_in_type(
                        &attr_ty.attr_type,
                        entity_types,
                        undeclared_types,
                    );
                }
            }

            Type::Set {
                element_type: Some(element_type),
            } => Self::check_undeclared_in_type(element_type, entity_types, undeclared_types),

            _ => (),
        }
    }

    /// Lookup the ValidatorActionId object in the schema with the given name.
    pub fn get_action_id(&self, action_id: &EntityUID) -> Option<&ValidatorActionId> {
        self.action_ids.get(action_id)
    }

    /// Lookup the ValidatorEntityType object in the schema with the given name.
    pub fn get_entity_type<'a>(&'a self, entity_type_id: &Name) -> Option<&'a ValidatorEntityType> {
        self.entity_types.get(entity_type_id)
    }

    /// Return true when the entity_type_id corresponds to a valid entity type.
    pub(crate) fn is_known_action_id(&self, action_id: &EntityUID) -> bool {
        self.action_ids.contains_key(action_id)
    }

    /// Return true when the entity_type_id corresponds to a valid entity type.
    pub(crate) fn is_known_entity_type(&self, entity_type: &Name) -> bool {
        is_action_entity_type(entity_type) || self.entity_types.contains_key(entity_type)
    }

    /// Return true when `euid` has an entity type declared by the schema. We
    /// treat an Unspecified as "known" because it is always possible to declare
    /// an action using an unspecified principal/resource type without first
    /// declaring unspecified as an entity type in the entity types list.
    pub(crate) fn euid_has_known_entity_type(&self, euid: &EntityUID) -> bool {
        match euid.entity_type() {
            EntityType::Specified(ety) => self.is_known_entity_type(ety),
            EntityType::Unspecified => true,
        }
    }

    /// An iterator over the action ids in the schema.
    pub(crate) fn known_action_ids(&self) -> impl Iterator<Item = &EntityUID> {
        self.action_ids.keys()
    }

    /// An iterator over the entity type names in the schema.
    pub(crate) fn known_entity_types(&self) -> impl Iterator<Item = &Name> {
        self.entity_types.keys()
    }

    /// An iterator matching the entity Types to their Validator Types
    pub fn entity_types(&self) -> impl Iterator<Item = (&Name, &ValidatorEntityType)> {
        self.entity_types.iter()
    }

    /// Get all entity types in the schema where an `{entity0} in {entity}` can
    /// evaluate to `true` for some `entity0` with that entity type. This
    /// includes all entity types that are descendants of the type of `entity`
    /// according  to the schema, and the type of `entity` itself because
    /// `entity in entity` evaluates to `true`.
    pub(crate) fn get_entity_types_in<'a>(&'a self, entity: &'a EntityUID) -> Vec<&Name> {
        match entity.entity_type() {
            EntityType::Specified(ety) => {
                let mut descendants = self
                    .get_entity_type(ety)
                    .map(|v_ety| v_ety.descendants.iter().collect::<Vec<_>>())
                    .unwrap_or_default();
                descendants.push(ety);
                descendants
            }
            EntityType::Unspecified => Vec::new(),
        }
    }

    /// Get all entity types in the schema where an `{entity0} in {euids}` can
    /// evaluate to `true` for some `entity0` with that entity type. See comment
    /// on `get_entity_types_in`.
    pub(crate) fn get_entity_types_in_set<'a>(
        &'a self,
        euids: impl IntoIterator<Item = &'a EntityUID> + 'a,
    ) -> impl Iterator<Item = &Name> {
        euids.into_iter().flat_map(|e| self.get_entity_types_in(e))
    }

    /// Get all action entities in the schema where `action in euids` evaluates
    /// to `true`. This includes all actions which are descendants of some
    /// element of `euids`, and all elements of `euids`.
    pub(crate) fn get_actions_in_set<'a>(
        &'a self,
        euids: impl IntoIterator<Item = &'a EntityUID> + 'a,
    ) -> Option<Vec<&'a EntityUID>> {
        euids
            .into_iter()
            .map(|e| {
                self.get_action_id(e).map(|action| {
                    action
                        .descendants
                        .iter()
                        .chain(std::iter::once(&action.name))
                })
            })
            .collect::<Option<Vec<_>>>()
            .map(|v| v.into_iter().flatten().collect::<Vec<_>>())
    }

    /// Get the `Type` of context expected for the given `action`.
    /// This always reutrns a closed record type.
    ///
    /// Returns `None` if the action is not in the schema.
    pub fn context_type(&self, action: &EntityUID) -> Option<Type> {
        // INVARIANT: `ValidatorActionId::context_type` always returns a closed
        // record type
        self.get_action_id(action)
            .map(ValidatorActionId::context_type)
    }

    /// Invert the action hierarchy to get the ancestor relation expected for
    /// the `Entity` datatype instead of descendants as stored by the schema.
    pub(crate) fn action_entities_iter(
        &self,
    ) -> impl Iterator<Item = cedar_policy_core::ast::Entity> + '_ {
        // We could store the un-inverted `memberOf` relation for each action,
        // but I [john-h-kastner-aws] judge that the current implementation is
        // actually less error prone, as it minimizes the threading of data
        // structures through some complicated bits of schema construction code,
        // and avoids computing the TC twice.
        let mut action_ancestors: HashMap<&EntityUID, HashSet<EntityUID>> = HashMap::new();
        for (action_euid, action_def) in &self.action_ids {
            for descendant in &action_def.descendants {
                action_ancestors
                    .entry(descendant)
                    .or_default()
                    .insert(action_euid.clone());
            }
        }
        self.action_ids.iter().map(move |(action_id, action)| {
            Entity::new_with_attr_partial_value_serialized_as_expr(
                action_id.clone(),
                action.attributes.clone(),
                action_ancestors.remove(action_id).unwrap_or_default(),
            )
        })
    }

    /// Construct an `Entity` object for each action in the schema
    pub fn action_entities(&self) -> std::result::Result<Entities, EntitiesError> {
        let extensions = Extensions::all_available();
        Entities::from_entities(
            self.action_entities_iter(),
            None::<&cedar_policy_core::entities::NoEntitiesSchema>, // we don't want to tell `Entities::from_entities()` to add the schema's action entities, that would infinitely recurse
            TCComputation::AssumeAlreadyComputed,
            extensions,
        )
        .map_err(Into::into)
    }
}

/// Used to write a schema implicitly overriding the default handling of action
/// groups.
#[derive(Debug, Clone, Deserialize)]
#[serde(transparent)]
pub(crate) struct NamespaceDefinitionWithActionAttributes(pub(crate) NamespaceDefinition);

impl TryInto<ValidatorSchema> for NamespaceDefinitionWithActionAttributes {
    type Error = SchemaError;

    fn try_into(self) -> Result<ValidatorSchema> {
        ValidatorSchema::from_schema_fragments([ValidatorSchemaFragment::from_namespaces([
            ValidatorNamespaceDef::from_namespace_definition(
                None,
                self.0,
                crate::ActionBehavior::PermitAttributes,
                Extensions::all_available(),
            )?,
        ])])
    }
}

// PANIC SAFETY unit tests
#[allow(clippy::panic)]
// PANIC SAFETY unit tests
#[allow(clippy::indexing_slicing)]
#[cfg(test)]
mod test {
    use std::sync::Arc;
    use std::{collections::BTreeMap, str::FromStr};

    use crate::types::Type;
    use crate::{SchemaType, SchemaTypeVariant};

    use cedar_policy_core::ast::RestrictedExpr;
    use cedar_policy_core::parser::err::{ParseError, ToASTError, ToASTErrorKind};
    use cedar_policy_core::parser::Loc;
    use cool_asserts::assert_matches;
    use serde_json::json;

    use super::*;

    // Well-formed schema
    #[test]
    fn test_from_schema_file() {
        let src = json!(
        {
            "entityTypes": {
                "User": {
                    "memberOfTypes": [ "Group" ]
                },
                "Group": {
                    "memberOfTypes": []
                },
                "Photo": {
                    "memberOfTypes": [ "Album" ]
                },
                "Album": {
                    "memberOfTypes": []
                }
            },
            "actions": {
                "view_photo": {
                    "appliesTo": {
                        "principalTypes": ["User", "Group"],
                        "resourceTypes": ["Photo"]
                    }
                }
            }
        });
        let schema_file: NamespaceDefinition = serde_json::from_value(src).expect("Parse Error");
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        assert!(schema.is_ok());
    }

    // Duplicate entity "Photo"
    #[test]
    fn test_from_schema_file_duplicate_entity() {
        // Test written using `from_str` instead of `from_value` because the
        // `json!` macro silently ignores duplicate map keys.
        let src = r#"
        {"": {
            "entityTypes": {
                "User": {
                    "memberOfTypes": [ "Group" ]
                },
                "Group": {
                    "memberOfTypes": []
                },
                "Photo": {
                    "memberOfTypes": [ "Album" ]
                },
                "Photo": {
                    "memberOfTypes": []
                }
            },
            "actions": {
                "view_photo": {
                    "memberOf": [],
                    "appliesTo": {
                        "principalTypes": ["User", "Group"],
                        "resourceTypes": ["Photo"]
                    }
                }
            }
        }}"#;

        match ValidatorSchema::from_str(src) {
            Err(SchemaError::Serde(_)) => (),
            _ => panic!("Expected serde error due to duplicate entity type."),
        }
    }

    // Duplicate action "view_photo"
    #[test]
    fn test_from_schema_file_duplicate_action() {
        // Test written using `from_str` instead of `from_value` because the
        // `json!` macro silently ignores duplicate map keys.
        let src = r#"
        {"": {
            "entityTypes": {
                "User": {
                    "memberOfTypes": [ "Group" ]
                },
                "Group": {
                    "memberOfTypes": []
                },
                "Photo": {
                    "memberOfTypes": []
                }
            },
            "actions": {
                "view_photo": {
                    "memberOf": [],
                    "appliesTo": {
                        "principalTypes": ["User", "Group"],
                        "resourceTypes": ["Photo"]
                    }
                },
                "view_photo": { }
            }
        }"#;
        match ValidatorSchema::from_str(src) {
            Err(SchemaError::Serde(_)) => (),
            _ => panic!("Expected serde error due to duplicate action type."),
        }
    }

    // Undefined entity types "Grop", "Usr", "Phoot"
    #[test]
    fn test_from_schema_file_undefined_entities() {
        let src = json!(
        {
            "entityTypes": {
                "User": {
                    "memberOfTypes": [ "Grop" ]
                },
                "Group": {
                    "memberOfTypes": []
                },
                "Photo": {
                    "memberOfTypes": []
                }
            },
            "actions": {
                "view_photo": {
                    "appliesTo": {
                        "principalTypes": ["Usr", "Group"],
                        "resourceTypes": ["Phoot"]
                    }
                }
            }
        });
        let schema_file: NamespaceDefinition = serde_json::from_value(src).expect("Parse Error");
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        match schema {
            Ok(_) => panic!("from_schema_file should have failed"),
            Err(SchemaError::UndeclaredEntityTypes(v)) => {
                assert_eq!(v.len(), 3)
            }
            _ => panic!("Unexpected error from from_schema_file"),
        }
    }

    #[test]
    fn undefined_entity_namespace_member_of() {
        let src = json!(
        {"Foo": {
            "entityTypes": {
                "User": {
                    "memberOfTypes": [ "Foo::Group", "Bar::Group" ]
                },
                "Group": { }
            },
            "actions": {}
        }});
        let schema_file: SchemaFragment = serde_json::from_value(src).expect("Parse Error");
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        match schema {
            Ok(_) => panic!("try_into should have failed"),
            Err(SchemaError::UndeclaredEntityTypes(v)) => {
                assert_eq!(v, HashSet::from(["Bar::Group".to_string()]))
            }
            _ => panic!("Unexpected error from try_into"),
        }
    }

    #[test]
    fn undefined_entity_namespace_applies_to() {
        let src = json!(
        {"Foo": {
            "entityTypes": { "User": { }, "Photo": { } },
            "actions": {
                "view_photo": {
                    "appliesTo": {
                        "principalTypes": ["Foo::User", "Bar::User"],
                        "resourceTypes": ["Photo", "Bar::Photo"],
                    }
                }
            }
        }});
        let schema_file: SchemaFragment = serde_json::from_value(src).expect("Parse Error");
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        match schema {
            Ok(_) => panic!("try_into should have failed"),
            Err(SchemaError::UndeclaredEntityTypes(v)) => {
                assert_eq!(
                    v,
                    HashSet::from(["Bar::Photo".to_string(), "Bar::User".to_string()])
                )
            }
            _ => panic!("Unexpected error from try_into"),
        }
    }

    // Undefined action "photo_actions"
    #[test]
    fn test_from_schema_file_undefined_action() {
        let src = json!(
        {
            "entityTypes": {
                "User": {
                    "memberOfTypes": [ "Group" ]
                },
                "Group": {
                    "memberOfTypes": []
                },
                "Photo": {
                    "memberOfTypes": []
                }
            },
            "actions": {
                "view_photo": {
                    "memberOf": [ {"id": "photo_action"} ],
                    "appliesTo": {
                        "principalTypes": ["User", "Group"],
                        "resourceTypes": ["Photo"]
                    }
                }
            }
        });
        let schema_file: NamespaceDefinition = serde_json::from_value(src).expect("Parse Error");
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        match schema {
            Ok(_) => panic!("from_schema_file should have failed"),
            Err(SchemaError::UndeclaredActions(v)) => assert_eq!(v.len(), 1),
            _ => panic!("Unexpected error from from_schema_file"),
        }
    }

    // Trivial cycle in action hierarchy
    // view_photo -> view_photo
    #[test]
    fn test_from_schema_file_action_cycle1() {
        let src = json!(
        {
            "entityTypes": {},
            "actions": {
                "view_photo": {
                    "memberOf": [ {"id": "view_photo"} ]
                }
            }
        });
        let schema_file: NamespaceDefinition = serde_json::from_value(src).expect("Parse Error");
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        assert_matches!(
            schema,
            Err(SchemaError::CycleInActionHierarchy(euid)) => {
                assert_eq!(euid, r#"Action::"view_photo""#.parse().unwrap());
            }
        )
    }

    // Slightly more complex cycle in action hierarchy
    // view_photo -> edit_photo -> delete_photo -> view_photo
    #[test]
    fn test_from_schema_file_action_cycle2() {
        let src = json!(
        {
            "entityTypes": {},
            "actions": {
                "view_photo": {
                    "memberOf": [ {"id": "edit_photo"} ]
                },
                "edit_photo": {
                    "memberOf": [ {"id": "delete_photo"} ]
                },
                "delete_photo": {
                    "memberOf": [ {"id": "view_photo"} ]
                },
                "other_action": {
                    "memberOf": [ {"id": "edit_photo"} ]
                }
            }
        });
        let schema_file: NamespaceDefinition = serde_json::from_value(src).expect("Parse Error");
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        assert_matches!(
            schema,
            // The exact action reported as being in the cycle isn't deterministic.
            Err(SchemaError::CycleInActionHierarchy(_)),
        )
    }

    #[test]
    fn namespaced_schema() {
        let src = r#"
        { "N::S": {
            "entityTypes": {
                "User": {},
                "Photo": {}
            },
            "actions": {
                "view_photo": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Photo"]
                    }
                }
            }
        } }
        "#;
        let schema_file: SchemaFragment = serde_json::from_str(src).expect("Parse Error");
        let schema: ValidatorSchema = schema_file
            .try_into()
            .expect("Namespaced schema failed to convert.");
        dbg!(&schema);
        let user_entity_type = &"N::S::User"
            .parse()
            .expect("Namespaced entity type should have parsed");
        let photo_entity_type = &"N::S::Photo"
            .parse()
            .expect("Namespaced entity type should have parsed");
        assert!(
            schema.entity_types.contains_key(user_entity_type),
            "Expected and entity type User."
        );
        assert!(
            schema.entity_types.contains_key(photo_entity_type),
            "Expected an entity type Photo."
        );
        assert_eq!(
            schema.entity_types.len(),
            2,
            "Expected exactly 2 entity types."
        );
        assert!(
            schema.action_ids.contains_key(
                &"N::S::Action::\"view_photo\""
                    .parse()
                    .expect("Namespaced action should have parsed")
            ),
            "Expected an action \"view_photo\"."
        );
        assert_eq!(schema.action_ids.len(), 1, "Expected exactly 1 action.");

        let apply_spec = &schema
            .action_ids
            .values()
            .next()
            .expect("Expected Action")
            .applies_to;
        assert_eq!(
            apply_spec.applicable_principal_types().collect::<Vec<_>>(),
            vec![&EntityType::Specified(user_entity_type.clone())]
        );
        assert_eq!(
            apply_spec.applicable_resource_types().collect::<Vec<_>>(),
            vec![&EntityType::Specified(photo_entity_type.clone())]
        );
    }

    #[test]
    fn cant_use_namespace_in_entity_type() {
        let src = r#"
        {
            "entityTypes": { "NS::User": {} },
            "actions": {}
        }
        "#;
        let schema_file: NamespaceDefinition = serde_json::from_str(src).expect("Parse Error");
        assert!(
            matches!(TryInto::<ValidatorSchema>::try_into(schema_file), Err(SchemaError::ParseEntityType(_))),
            "Expected that namespace in the entity type NS::User would cause a EntityType parse error.");
    }

    #[test]
    fn entity_attribute_entity_type_with_namespace() {
        let schema_json: SchemaFragment = serde_json::from_str(
            r#"
            {"A::B": {
                "entityTypes": {
                    "Foo": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "name": { "type": "Entity", "name": "C::D::Foo" }
                            }
                        }
                    }
                },
                "actions": {}
              }}
            "#,
        )
        .expect("Expected valid schema");

        let schema: Result<ValidatorSchema> = schema_json.try_into();
        match schema {
            Err(SchemaError::UndeclaredEntityTypes(tys)) => {
                assert_eq!(tys, HashSet::from(["C::D::Foo".to_string()]))
            }
            _ => panic!("Schema construction should have failed due to undeclared entity type."),
        }
    }

    #[test]
    fn entity_attribute_entity_type_with_declared_namespace() {
        let schema_json: SchemaFragment = serde_json::from_str(
            r#"
            {"A::B": {
                "entityTypes": {
                    "Foo": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "name": { "type": "Entity", "name": "A::B::Foo" }
                            }
                        }
                    }
                },
                "actions": {}
              }}
            "#,
        )
        .expect("Expected valid schema");

        let schema: ValidatorSchema = schema_json
            .try_into()
            .expect("Expected schema to construct without error.");

        let foo_name: Name = "A::B::Foo".parse().expect("Expected entity type name");
        let foo_type = schema
            .entity_types
            .get(&foo_name)
            .expect("Expected to find entity");
        let name_type = foo_type
            .attr("name")
            .expect("Expected attribute name")
            .attr_type
            .clone();
        let expected_name_type = Type::named_entity_reference(foo_name);
        assert_eq!(name_type, expected_name_type);
    }

    #[test]
    fn cannot_declare_action_type_when_prohibited() {
        let schema_json: NamespaceDefinition = serde_json::from_str(
            r#"
            {
                "entityTypes": { "Action": {} },
                "actions": {}
              }
            "#,
        )
        .expect("Expected valid schema");

        let schema: Result<ValidatorSchema> = schema_json.try_into();
        assert!(matches!(schema, Err(SchemaError::ActionEntityTypeDeclared)));
    }

    #[test]
    fn can_declare_other_type_when_action_type_prohibited() {
        let schema_json: NamespaceDefinition = serde_json::from_str(
            r#"
            {
                "entityTypes": { "Foo": { } },
                "actions": {}
              }
            "#,
        )
        .expect("Expected valid schema");

        TryInto::<ValidatorSchema>::try_into(schema_json).expect("Did not expect any errors.");
    }

    #[test]
    fn cannot_declare_action_in_group_when_prohibited() {
        let schema_json: SchemaFragment = serde_json::from_str(
            r#"
            {"": {
                "entityTypes": {},
                "actions": {
                    "universe": { },
                    "view_photo": {
                        "attributes": {"id": "universe"}
                    },
                    "edit_photo": {
                        "attributes": {"id": "universe"}
                    },
                    "delete_photo": {
                        "attributes": {"id": "universe"}
                    }
                }
              }}
            "#,
        )
        .expect("Expected valid schema");

        let schema = ValidatorSchemaFragment::from_schema_fragment(
            schema_json,
            ActionBehavior::ProhibitAttributes,
            Extensions::all_available(),
        );
        match schema {
            Err(SchemaError::UnsupportedFeature(UnsupportedFeature::ActionAttributes(actions))) => {
                assert_eq!(
                    actions.into_iter().collect::<HashSet<_>>(),
                    HashSet::from([
                        "view_photo".to_string(),
                        "edit_photo".to_string(),
                        "delete_photo".to_string(),
                    ])
                )
            }
            _ => panic!("Did not see expected error."),
        }
    }

    #[test]
    fn test_entity_type_no_namespace() {
        let src = json!({"type": "Entity", "name": "Foo"});
        let schema_ty: SchemaType = serde_json::from_value(src).expect("Parse Error");
        assert_eq!(
            schema_ty,
            SchemaType::Type(SchemaTypeVariant::Entity { name: "Foo".into() })
        );
        let ty: Type = ValidatorNamespaceDef::try_schema_type_into_validator_type(
            Some(&Name::parse_unqualified_name("NS").expect("Expected namespace.")),
            schema_ty,
        )
        .expect("Error converting schema type to type.")
        .resolve_type_defs(&HashMap::new())
        .unwrap();
        assert_eq!(ty, Type::named_entity_reference_from_str("NS::Foo"));
    }

    #[test]
    fn test_entity_type_namespace() {
        let src = json!({"type": "Entity", "name": "NS::Foo"});
        let schema_ty: SchemaType = serde_json::from_value(src).expect("Parse Error");
        assert_eq!(
            schema_ty,
            SchemaType::Type(SchemaTypeVariant::Entity {
                name: "NS::Foo".into()
            })
        );
        let ty: Type = ValidatorNamespaceDef::try_schema_type_into_validator_type(
            Some(&Name::parse_unqualified_name("NS").expect("Expected namespace.")),
            schema_ty,
        )
        .expect("Error converting schema type to type.")
        .resolve_type_defs(&HashMap::new())
        .unwrap();
        assert_eq!(ty, Type::named_entity_reference_from_str("NS::Foo"));
    }

    #[test]
    fn test_entity_type_namespace_parse_error() {
        let src = json!({"type": "Entity", "name": "::Foo"});
        let schema_ty: SchemaType = serde_json::from_value(src).expect("Parse Error");
        assert_eq!(
            schema_ty,
            SchemaType::Type(SchemaTypeVariant::Entity {
                name: "::Foo".into()
            })
        );
        match ValidatorNamespaceDef::try_schema_type_into_validator_type(
            Some(&Name::parse_unqualified_name("NS").expect("Expected namespace.")),
            schema_ty,
        ) {
            Err(SchemaError::ParseEntityType(_)) => (),
            _ => panic!("Did not see expected entity type parse error."),
        }
    }

    #[test]
    fn schema_type_record_is_validator_type_record() {
        let src = json!({"type": "Record", "attributes": {}});
        let schema_ty: SchemaType = serde_json::from_value(src).expect("Parse Error");
        assert_eq!(
            schema_ty,
            SchemaType::Type(SchemaTypeVariant::Record {
                attributes: BTreeMap::new(),
                additional_attributes: false,
            }),
        );
        let ty: Type = ValidatorNamespaceDef::try_schema_type_into_validator_type(None, schema_ty)
            .expect("Error converting schema type to type.")
            .resolve_type_defs(&HashMap::new())
            .unwrap();
        assert_eq!(ty, Type::closed_record_with_attributes(None));
    }

    #[test]
    fn get_namespaces() {
        let fragment: SchemaFragment = serde_json::from_value(json!({
            "Foo::Bar::Baz": {
                "entityTypes": {},
                "actions": {}
            },
            "Foo": {
                "entityTypes": {},
                "actions": {}
            },
            "Bar": {
                "entityTypes": {},
                "actions": {}
            },
        }))
        .unwrap();

        let schema_fragment: ValidatorSchemaFragment = fragment.try_into().unwrap();
        assert_eq!(
            schema_fragment
                .0
                .iter()
                .map(|f| f.namespace())
                .collect::<HashSet<_>>(),
            HashSet::from([
                &Some("Foo::Bar::Baz".parse().unwrap()),
                &Some("Foo".parse().unwrap()),
                &Some("Bar".parse().unwrap())
            ])
        );
    }

    #[test]
    fn schema_no_fragments() {
        let schema = ValidatorSchema::from_schema_fragments([]).unwrap();
        assert!(schema.entity_types.is_empty());
        assert!(schema.action_ids.is_empty());
    }

    #[test]
    fn same_action_different_namespace() {
        let fragment: SchemaFragment = serde_json::from_value(json!({
            "Foo::Bar": {
                "entityTypes": {},
                "actions": {
                    "Baz": {}
                }
            },
            "Bar::Foo": {
                "entityTypes": {},
                "actions": {
                    "Baz": { }
                }
            },
            "Biz": {
                "entityTypes": {},
                "actions": {
                    "Baz": { }
                }
            }
        }))
        .unwrap();

        let schema: ValidatorSchema = fragment.try_into().unwrap();
        assert!(schema
            .get_action_id(&"Foo::Bar::Action::\"Baz\"".parse().unwrap())
            .is_some());
        assert!(schema
            .get_action_id(&"Bar::Foo::Action::\"Baz\"".parse().unwrap())
            .is_some());
        assert!(schema
            .get_action_id(&"Biz::Action::\"Baz\"".parse().unwrap())
            .is_some());
    }

    #[test]
    fn same_type_different_namespace() {
        let fragment: SchemaFragment = serde_json::from_value(json!({
            "Foo::Bar": {
                "entityTypes": {"Baz" : {}},
                "actions": { }
            },
            "Bar::Foo": {
                "entityTypes": {"Baz" : {}},
                "actions": { }
            },
            "Biz": {
                "entityTypes": {"Baz" : {}},
                "actions": { }
            }
        }))
        .unwrap();
        let schema: ValidatorSchema = fragment.try_into().unwrap();

        assert!(schema
            .get_entity_type(&"Foo::Bar::Baz".parse().unwrap())
            .is_some());
        assert!(schema
            .get_entity_type(&"Bar::Foo::Baz".parse().unwrap())
            .is_some());
        assert!(schema
            .get_entity_type(&"Biz::Baz".parse().unwrap())
            .is_some());
    }

    #[test]
    fn member_of_different_namespace() {
        let fragment: SchemaFragment = serde_json::from_value(json!({
            "Bar": {
                "entityTypes": {
                    "Baz": {
                        "memberOfTypes": ["Foo::Buz"]
                    }
                },
                "actions": {}
            },
            "Foo": {
                "entityTypes": { "Buz": {} },
                "actions": { }
            }
        }))
        .unwrap();
        let schema: ValidatorSchema = fragment.try_into().unwrap();

        let buz = schema
            .get_entity_type(&"Foo::Buz".parse().unwrap())
            .unwrap();
        assert_eq!(
            buz.descendants,
            HashSet::from(["Bar::Baz".parse().unwrap()])
        );
    }

    #[test]
    fn attribute_different_namespace() {
        let fragment: SchemaFragment = serde_json::from_value(json!({
            "Bar": {
                "entityTypes": {
                    "Baz": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "fiz": {
                                    "type": "Entity",
                                    "name": "Foo::Buz"
                                }
                            }
                        }
                    }
                },
                "actions": {}
            },
            "Foo": {
                "entityTypes": { "Buz": {} },
                "actions": { }
            }
        }))
        .unwrap();

        let schema: ValidatorSchema = fragment.try_into().unwrap();
        let baz = schema
            .get_entity_type(&"Bar::Baz".parse().unwrap())
            .unwrap();
        assert_eq!(
            baz.attr("fiz").unwrap().attr_type,
            Type::named_entity_reference_from_str("Foo::Buz"),
        );
    }

    #[test]
    fn applies_to_different_namespace() {
        let fragment: SchemaFragment = serde_json::from_value(json!({
            "Foo::Bar": {
                "entityTypes": { },
                "actions": {
                    "Baz": {
                        "appliesTo": {
                            "principalTypes": [ "Fiz::Buz" ],
                            "resourceTypes": [ "Fiz::Baz" ],
                        }
                    }
                }
            },
            "Fiz": {
                "entityTypes": {
                    "Buz": {},
                    "Baz": {}
                },
                "actions": { }
            }
        }))
        .unwrap();
        let schema: ValidatorSchema = fragment.try_into().unwrap();

        let baz = schema
            .get_action_id(&"Foo::Bar::Action::\"Baz\"".parse().unwrap())
            .unwrap();
        assert_eq!(
            baz.applies_to
                .applicable_principal_types()
                .collect::<HashSet<_>>(),
            HashSet::from([&EntityType::Specified("Fiz::Buz".parse().unwrap())])
        );
        assert_eq!(
            baz.applies_to
                .applicable_resource_types()
                .collect::<HashSet<_>>(),
            HashSet::from([&EntityType::Specified("Fiz::Baz".parse().unwrap())])
        );
    }

    #[test]
    fn simple_defined_type() {
        let fragment: SchemaFragment = serde_json::from_value(json!({
            "": {
                "commonTypes": {
                    "MyLong": {"type": "Long"}
                },
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": {"type": "MyLong"}
                            }
                        }
                    }
                },
                "actions": {}
            }
        }))
        .unwrap();
        let schema: ValidatorSchema = fragment.try_into().unwrap();
        assert_eq!(
            schema.entity_types.iter().next().unwrap().1.attributes,
            Attributes::with_required_attributes([("a".into(), Type::primitive_long())])
        );
    }

    #[test]
    fn defined_record_as_attrs() {
        let fragment: SchemaFragment = serde_json::from_value(json!({
            "": {
                "commonTypes": {
                    "MyRecord": {
                        "type": "Record",
                        "attributes":  {
                            "a": {"type": "Long"}
                        }
                    }
                },
                "entityTypes": {
                    "User": { "shape": { "type": "MyRecord", } }
                },
                "actions": {}
            }
        }))
        .unwrap();
        let schema: ValidatorSchema = fragment.try_into().unwrap();
        assert_eq!(
            schema.entity_types.iter().next().unwrap().1.attributes,
            Attributes::with_required_attributes([("a".into(), Type::primitive_long())])
        );
    }

    #[test]
    fn cross_namespace_type() {
        let fragment: SchemaFragment = serde_json::from_value(json!({
            "A": {
                "commonTypes": {
                    "MyLong": {"type": "Long"}
                },
                "entityTypes": { },
                "actions": {}
            },
            "B": {
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": {"type": "A::MyLong"}
                            }
                        }
                    }
                },
                "actions": {}
            }
        }))
        .unwrap();
        let schema: ValidatorSchema = fragment.try_into().unwrap();
        assert_eq!(
            schema.entity_types.iter().next().unwrap().1.attributes,
            Attributes::with_required_attributes([("a".into(), Type::primitive_long())])
        );
    }

    #[test]
    fn cross_fragment_type() {
        let fragment1: ValidatorSchemaFragment = serde_json::from_value::<SchemaFragment>(json!({
            "A": {
                "commonTypes": {
                    "MyLong": {"type": "Long"}
                },
                "entityTypes": { },
                "actions": {}
            }
        }))
        .unwrap()
        .try_into()
        .unwrap();
        let fragment2: ValidatorSchemaFragment = serde_json::from_value::<SchemaFragment>(json!({
            "A": {
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": {"type": "MyLong"}
                            }
                        }
                    }
                },
                "actions": {}
            }
        }))
        .unwrap()
        .try_into()
        .unwrap();
        let schema = ValidatorSchema::from_schema_fragments([fragment1, fragment2]).unwrap();

        assert_eq!(
            schema.entity_types.iter().next().unwrap().1.attributes,
            Attributes::with_required_attributes([("a".into(), Type::primitive_long())])
        );
    }

    #[test]
    fn cross_fragment_duplicate_type() {
        let fragment1: ValidatorSchemaFragment = serde_json::from_value::<SchemaFragment>(json!({
            "A": {
                "commonTypes": {
                    "MyLong": {"type": "Long"}
                },
                "entityTypes": {},
                "actions": {}
            }
        }))
        .unwrap()
        .try_into()
        .unwrap();
        let fragment2: ValidatorSchemaFragment = serde_json::from_value::<SchemaFragment>(json!({
            "A": {
                "commonTypes": {
                    "MyLong": {"type": "Long"}
                },
                "entityTypes": {},
                "actions": {}
            }
        }))
        .unwrap()
        .try_into()
        .unwrap();

        let schema = ValidatorSchema::from_schema_fragments([fragment1, fragment2]);

        match schema {
            Err(SchemaError::DuplicateCommonType(s)) if s.contains("A::MyLong") => (),
            _ => panic!("should have errored because schema fragments have duplicate types"),
        };
    }

    #[test]
    fn undeclared_type_in_attr() {
        let fragment: SchemaFragment = serde_json::from_value(json!({
            "": {
                "commonTypes": { },
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": {"type": "MyLong"}
                            }
                        }
                    }
                },
                "actions": {}
            }
        }))
        .unwrap();
        match TryInto::<ValidatorSchema>::try_into(fragment) {
            Err(SchemaError::UndeclaredCommonTypes(_)) => (),
            s => panic!(
                "Expected Err(SchemaError::UndeclaredCommonType), got {:?}",
                s
            ),
        }
    }

    #[test]
    fn undeclared_type_in_type_def() {
        let fragment: SchemaFragment = serde_json::from_value(json!({
            "": {
                "commonTypes": {
                    "a": { "type": "b" }
                },
                "entityTypes": { },
                "actions": {}
            }
        }))
        .unwrap();
        match TryInto::<ValidatorSchema>::try_into(fragment) {
            Err(SchemaError::UndeclaredCommonTypes(_)) => (),
            s => panic!(
                "Expected Err(SchemaError::UndeclaredCommonType), got {:?}",
                s
            ),
        }
    }

    #[test]
    fn shape_not_record() {
        let fragment: SchemaFragment = serde_json::from_value(json!({
            "": {
                "commonTypes": {
                    "MyLong": { "type": "Long" }
                },
                "entityTypes": {
                    "User": {
                        "shape": { "type": "MyLong" }
                    }
                },
                "actions": {}
            }
        }))
        .unwrap();
        match TryInto::<ValidatorSchema>::try_into(fragment) {
            Err(SchemaError::ContextOrShapeNotRecord(_)) => (),
            s => panic!(
                "Expected Err(SchemaError::ContextOrShapeNotRecord), got {:?}",
                s
            ),
        }
    }

    /// This test checks for regressions on (adapted versions of) the examples
    /// mentioned in the thread at
    /// [cedar#134](https://github.com/cedar-policy/cedar/pull/134)
    #[test]
    fn counterexamples_from_cedar_134() {
        // non-normalized entity type name
        let bad1 = json!({
            "": {
                "entityTypes": {
                    "User // comment": {
                        "memberOfTypes": [
                            "UserGroup"
                        ]
                    },
                    "User": {
                        "memberOfTypes": [
                            "UserGroup"
                        ]
                    },
                    "UserGroup": {}
                },
                "actions": {}
            }
        });
        let fragment = serde_json::from_value::<SchemaFragment>(bad1)
            .expect("constructing the fragment itself should succeed"); // should this fail in the future?
        let err = ValidatorSchema::try_from(fragment)
            .expect_err("should error due to invalid entity type name");
        let problem_field = "User // comment";
        let expected_err = ParseError::ToAST(ToASTError::new(
            ToASTErrorKind::NonNormalizedString {
                kind: "Id",
                src: problem_field.to_string(),
                normalized_src: "User".to_string(),
            },
            Loc::new(4, Arc::from(problem_field)),
        ))
        .into();

        match err {
            SchemaError::ParseEntityType(parse_error) => assert_eq!(parse_error, expected_err),
            err => panic!("Incorrect error {err}"),
        }

        // non-normalized schema namespace
        let bad2 = json!({
            "ABC     :: //comment \n XYZ  ": {
                "entityTypes": {
                    "User": {
                        "memberOfTypes": []
                    }
                },
                "actions": {}
            }
        });
        let fragment = serde_json::from_value::<SchemaFragment>(bad2)
            .expect("constructing the fragment itself should succeed"); // should this fail in the future?
        let err = ValidatorSchema::try_from(fragment)
            .expect_err("should error due to invalid schema namespace");
        let problem_field = "ABC     :: //comment \n XYZ  ";
        let expected_err = ParseError::ToAST(ToASTError::new(
            ToASTErrorKind::NonNormalizedString {
                kind: "Name",
                src: problem_field.to_string(),
                normalized_src: "ABC::XYZ".to_string(),
            },
            Loc::new(3, Arc::from(problem_field)),
        ))
        .into();
        match err {
            SchemaError::ParseNamespace(parse_error) => assert_eq!(parse_error, expected_err),
            err => panic!("Incorrect error {:?}", err),
        };
    }

    #[test]
    fn simple_action_entity() {
        let src = json!(
        {
            "entityTypes": { },
            "actions": {
                "view_photo": { },
            }
        });

        let schema_file: NamespaceDefinition = serde_json::from_value(src).expect("Parse Error");
        let schema: ValidatorSchema = schema_file.try_into().expect("Schema Error");
        let actions = schema.action_entities().expect("Entity Construct Error");

        let action_uid = EntityUID::from_str("Action::\"view_photo\"").unwrap();
        let view_photo = actions.entity(&action_uid);
        assert_eq!(
            view_photo.unwrap(),
            &Entity::new_with_attr_partial_value(action_uid, HashMap::new(), HashSet::new())
        );
    }

    #[test]
    fn action_entity_hierarchy() {
        let src = json!(
        {
            "entityTypes": { },
            "actions": {
                "read": {},
                "view": {
                    "memberOf": [{"id": "read"}]
                },
                "view_photo": {
                    "memberOf": [{"id": "view"}]
                },
            }
        });

        let schema_file: NamespaceDefinition = serde_json::from_value(src).expect("Parse Error");
        let schema: ValidatorSchema = schema_file.try_into().expect("Schema Error");
        let actions = schema.action_entities().expect("Entity Construct Error");

        let view_photo_uid = EntityUID::from_str("Action::\"view_photo\"").unwrap();
        let view_uid = EntityUID::from_str("Action::\"view\"").unwrap();
        let read_uid = EntityUID::from_str("Action::\"read\"").unwrap();

        let view_photo_entity = actions.entity(&view_photo_uid);
        assert_eq!(
            view_photo_entity.unwrap(),
            &Entity::new_with_attr_partial_value(
                view_photo_uid,
                HashMap::new(),
                HashSet::from([view_uid.clone(), read_uid.clone()])
            )
        );

        let view_entity = actions.entity(&view_uid);
        assert_eq!(
            view_entity.unwrap(),
            &Entity::new_with_attr_partial_value(
                view_uid,
                HashMap::new(),
                HashSet::from([read_uid.clone()])
            )
        );

        let read_entity = actions.entity(&read_uid);
        assert_eq!(
            read_entity.unwrap(),
            &Entity::new_with_attr_partial_value(read_uid, HashMap::new(), HashSet::new())
        );
    }

    #[test]
    fn action_entity_attribute() {
        let src = json!(
        {
            "entityTypes": { },
            "actions": {
                "view_photo": {
                    "attributes": { "attr": "foo" }
                },
            }
        });

        let schema_file: NamespaceDefinitionWithActionAttributes =
            serde_json::from_value(src).expect("Parse Error");
        let schema: ValidatorSchema = schema_file.try_into().expect("Schema Error");
        let actions = schema.action_entities().expect("Entity Construct Error");

        let action_uid = EntityUID::from_str("Action::\"view_photo\"").unwrap();
        let view_photo = actions.entity(&action_uid);
        assert_eq!(
            view_photo.unwrap(),
            &Entity::new(
                action_uid,
                HashMap::from([("attr".into(), RestrictedExpr::val("foo"))]),
                HashSet::new(),
                &Extensions::none(),
            )
            .unwrap(),
        );
    }

    #[test]
    fn test_action_namespace_inference_multi_success() {
        let src = json!({
            "Foo" : {
                "entityTypes" : {},
                "actions" : {
                    "read" : {}
                }
            },
            "ExampleCo::Personnel" : {
                "entityTypes" : {},
                "actions" : {
                    "viewPhoto" : {
                        "memberOf" : [
                            {
                                "id" : "read",
                                "type" : "Foo::Action"
                            }
                        ]
                    }
                }
            },
        });
        let schema_fragment =
            serde_json::from_value::<SchemaFragment>(src).expect("Failed to parse schema");
        let schema: ValidatorSchema = schema_fragment.try_into().expect("Schema should construct");
        let view_photo = schema
            .action_entities_iter()
            .find(|e| e.uid() == &r#"ExampleCo::Personnel::Action::"viewPhoto""#.parse().unwrap())
            .unwrap();
        let ancestors = view_photo.ancestors().collect::<Vec<_>>();
        let read = ancestors[0];
        assert_eq!(read.eid().to_string(), "read");
        assert_eq!(read.entity_type().to_string(), "Foo::Action");
    }

    #[test]
    fn test_action_namespace_inference_multi() {
        let src = json!({
            "ExampleCo::Personnel::Foo" : {
                "entityTypes" : {},
                "actions" : {
                    "read" : {}
                }
            },
            "ExampleCo::Personnel" : {
                "entityTypes" : {},
                "actions" : {
                    "viewPhoto" : {
                        "memberOf" : [
                            {
                                "id" : "read",
                                "type" : "Foo::Action"
                            }
                        ]
                    }
                }
            },
        });
        let schema_fragment =
            serde_json::from_value::<SchemaFragment>(src).expect("Failed to parse schema");
        let schema: std::result::Result<ValidatorSchema, _> = schema_fragment.try_into();
        schema.expect_err("Schema should fail to construct as the normalization rules treat any qualification as starting from the root");
    }

    #[test]
    fn test_action_namespace_inference() {
        let src = json!({
            "ExampleCo::Personnel" : {
                "entityTypes" : { },
                "actions" : {
                    "read" : {},
                    "viewPhoto" : {
                        "memberOf" : [
                            {
                                "id" :  "read",
                                "type" : "Action"
                            }
                        ]
                    }
                }
            }
        });
        let schema_fragment =
            serde_json::from_value::<SchemaFragment>(src).expect("Failed to parse schema");
        let schema: ValidatorSchema = schema_fragment.try_into().unwrap();
        let view_photo = schema
            .action_entities_iter()
            .find(|e| e.uid() == &r#"ExampleCo::Personnel::Action::"viewPhoto""#.parse().unwrap())
            .unwrap();
        let ancestors = view_photo.ancestors().collect::<Vec<_>>();
        let read = ancestors[0];
        assert_eq!(read.eid().to_string(), "read");
        assert_eq!(
            read.entity_type().to_string(),
            "ExampleCo::Personnel::Action"
        );
    }

    #[test]
    fn qualified_undeclared_common_types() {
        let src = json!(
            {
                "Demo": {
                  "entityTypes": {
                    "User": {
                      "memberOfTypes": [],
                      "shape": {
                        "type": "Record",
                        "attributes": {
                          "id": { "type": "id" },
                        }
                      }
                    }
                  },
                  "actions": {}
                },
                "": {
                  "commonTypes": {
                    "id": {
                      "type": "String"
                    },
                  },
                  "entityTypes": {},
                  "actions": {}
                }
              }
        );
        let schema = ValidatorSchema::from_json_value(src, Extensions::all_available());
        assert_matches!(schema, Err(SchemaError::UndeclaredCommonTypes(types)) =>
            assert_eq!(types, HashSet::from(["Demo::id".to_string()])));
    }

    #[test]
    fn qualified_undeclared_common_types2() {
        let src = json!(
            {
                "Demo": {
                  "entityTypes": {
                    "User": {
                      "memberOfTypes": [],
                      "shape": {
                        "type": "Record",
                        "attributes": {
                          "id": { "type": "Demo::id" },
                        }
                      }
                    }
                  },
                  "actions": {}
                },
                "": {
                  "commonTypes": {
                    "id": {
                      "type": "String"
                    },
                  },
                  "entityTypes": {},
                  "actions": {}
                }
              }
        );
        let schema = ValidatorSchema::from_json_value(src, Extensions::all_available());
        assert_matches!(schema, Err(SchemaError::UndeclaredCommonTypes(types)) =>
            assert_eq!(types, HashSet::from(["Demo::id".to_string()])));
    }
}
