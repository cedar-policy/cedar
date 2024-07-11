/*
 * Copyright Cedar Contributors
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

use std::collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;

use cedar_policy_core::{
    ast::{Entity, EntityType, EntityUID, Id, Name},
    entities::{err::EntitiesError, Entities, TCComputation},
    extensions::Extensions,
    transitive_closure::compute_tc,
};
use itertools::Itertools;
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::ToSmolStr;

use super::NamespaceDefinition;
use crate::{
    err::schema_errors::*,
    err::*,
    human_schema::SchemaWarning,
    types::{Attributes, EntityRecordKind, OpenTag, Type},
    SchemaFragment, SchemaType, SchemaTypeVariant, TypeOfAttribute,
};

mod action;
pub use action::ValidatorActionId;
pub(crate) use action::ValidatorApplySpec;
mod entity_type;
pub use entity_type::ValidatorEntityType;
mod namespace_def;
pub(crate) use namespace_def::try_schema_type_into_validator_type;
pub use namespace_def::ValidatorNamespaceDef;
mod raw_name;
pub use raw_name::{ConditionalName, RawName, ReferenceType};

/// Configurable validator behaviors regarding actions
#[derive(Debug, Eq, PartialEq, Copy, Clone, Default)]
pub enum ActionBehavior {
    /// Action entities cannot have attributes. Attempting to declare attributes
    /// will result in a error when constructing the schema.
    ///
    /// Since we do not have a formal model for action attributes, this behavior
    /// (disabling/prohibiting them) is the default.
    #[default]
    ProhibitAttributes,
    /// Action entities may have attributes.
    PermitAttributes,
}

/// A `ValidatorSchemaFragment` consists of any number (even 0) of
/// `ValidatorNamespaceDef`s.
#[derive(Debug)]
pub struct ValidatorSchemaFragment<N>(Vec<ValidatorNamespaceDef<N>>);

impl TryInto<ValidatorSchemaFragment<ConditionalName>> for SchemaFragment<RawName> {
    type Error = SchemaError;

    fn try_into(self) -> Result<ValidatorSchemaFragment<ConditionalName>> {
        ValidatorSchemaFragment::from_schema_fragment(
            self,
            ActionBehavior::default(),
            Extensions::all_available(),
        )
    }
}

impl<N> ValidatorSchemaFragment<N> {
    /// Construct a [`ValidatorSchemaFragment`] from multiple [`ValidatorNamespaceDef`]s
    pub fn from_namespaces(namespaces: impl IntoIterator<Item = ValidatorNamespaceDef<N>>) -> Self {
        Self(namespaces.into_iter().collect())
    }

    /// Get the fully-qualified [`Name`]s for the namespaces in this fragment.
    /// `None` indicates the empty namespace.
    pub fn namespaces(&self) -> impl Iterator<Item = Option<&Name>> {
        self.0.iter().map(|d| d.namespace())
    }
}

impl ValidatorSchemaFragment<ConditionalName> {
    /// Construct a [`ValidatorSchemaFragment`] from a [`SchemaFragment`]
    pub fn from_schema_fragment(
        fragment: SchemaFragment<RawName>,
        action_behavior: ActionBehavior,
        extensions: Extensions<'_>,
    ) -> Result<Self> {
        Ok(Self(
            fragment
                .0
                .into_iter()
                .map(|(fragment_ns, ns_def)| {
                    ValidatorNamespaceDef::from_namespace_definition(
                        fragment_ns,
                        ns_def,
                        action_behavior,
                        extensions,
                    )
                })
                .collect::<Result<Vec<_>>>()?,
        ))
    }

    /// Convert this [`ValidatorSchemaFragment<ConditionalName>`] into a
    /// [`ValidatorSchemaFragment<Name>`] by fully-qualifying all typenames that
    /// appear anywhere in any definitions.
    ///
    /// `all_common_defs` and `all_entity_defs` need to be the full set of all
    /// fully-qualified typenames (of common and entity types respectively) that
    /// are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_common_defs: &HashSet<Name>,
        all_entity_defs: &HashSet<Name>,
    ) -> std::result::Result<ValidatorSchemaFragment<Name>, TypeResolutionError> {
        let (nsdefs, errs) = self
            .0
            .into_iter()
            .map(|ns_def| ns_def.fully_qualify_type_references(all_common_defs, all_entity_defs))
            .partition_result::<Vec<ValidatorNamespaceDef<Name>>, Vec<TypeResolutionError>, _, _>();
        if let Some(errs) = NonEmpty::from_vec(errs) {
            Err(TypeResolutionError::join_nonempty(errs))
        } else {
            Ok(ValidatorSchemaFragment(nsdefs))
        }
    }
}

/// Internal representation of the schema for use by the validator.
///
/// In this representation, all common types are fully expanded, and all entity
/// type names are fully disambiguated (fully qualified).
#[serde_as]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorSchema {
    /// Map from entity type names to the [`ValidatorEntityType`] object.
    #[serde_as(as = "Vec<(_, _)>")]
    entity_types: HashMap<EntityType, ValidatorEntityType>,

    /// Map from action id names to the [`ValidatorActionId`] object.
    #[serde_as(as = "Vec<(_, _)>")]
    action_ids: HashMap<EntityUID, ValidatorActionId>,
}

impl std::str::FromStr for ValidatorSchema {
    type Err = SchemaError;

    fn from_str(s: &str) -> Result<Self> {
        serde_json::from_str::<SchemaFragment<RawName>>(s)
            .map_err(|e| JsonDeserializationError::new(e, Some(s)))?
            .try_into()
    }
}

impl TryFrom<NamespaceDefinition<RawName>> for ValidatorSchema {
    type Error = SchemaError;

    fn try_from(nsd: NamespaceDefinition<RawName>) -> Result<ValidatorSchema> {
        ValidatorSchema::from_schema_fragments(
            [ValidatorSchemaFragment::from_namespaces([nsd.try_into()?])],
            Extensions::all_available(),
        )
    }
}

impl TryFrom<SchemaFragment<RawName>> for ValidatorSchema {
    type Error = SchemaError;

    fn try_from(frag: SchemaFragment<RawName>) -> Result<ValidatorSchema> {
        ValidatorSchema::from_schema_fragments([frag.try_into()?], Extensions::all_available())
    }
}

impl ValidatorSchema {
    /// Create a [`ValidatorSchema`] without any definitions (of entity types,
    /// common types, or actions).
    pub fn empty() -> ValidatorSchema {
        Self {
            entity_types: HashMap::new(),
            action_ids: HashMap::new(),
        }
    }

    /// Construct a [`ValidatorSchema`] from a JSON value in the appropriate
    /// shape.
    pub fn from_json_value(json: serde_json::Value, extensions: Extensions<'_>) -> Result<Self> {
        Self::from_schema_frag(
            SchemaFragment::<RawName>::from_json_value(json)?,
            ActionBehavior::default(),
            extensions,
        )
    }

    /// Construct a [`ValidatorSchema`] from a string containing JSON in the
    /// appropriate shape.
    pub fn from_json_str(json: &str, extensions: Extensions<'_>) -> Result<Self> {
        Self::from_schema_frag(
            SchemaFragment::<RawName>::from_json_str(json)?,
            ActionBehavior::default(),
            extensions,
        )
    }

    /// Construct a [`ValidatorSchema`] directly from a file containing JSON
    /// in the appropriate shape.
    pub fn from_file(file: impl std::io::Read, extensions: Extensions<'_>) -> Result<Self> {
        Self::from_schema_frag(
            SchemaFragment::<RawName>::from_file(file)?,
            ActionBehavior::default(),
            extensions,
        )
    }

    /// Construct a [`ValidatorSchema`] directly from a file containing Cedar
    /// "natural" schema syntax.
    pub fn from_file_natural(
        r: impl std::io::Read,
        extensions: Extensions<'_>,
    ) -> std::result::Result<(Self, impl Iterator<Item = SchemaWarning> + '_), HumanSchemaError>
    {
        let (fragment, warnings) = SchemaFragment::from_file_natural(r, extensions)?;
        let schema_and_warnings =
            Self::from_schema_frag(fragment, ActionBehavior::default(), extensions)
                .map(|schema| (schema, warnings))?;
        Ok(schema_and_warnings)
    }

    /// Construct a [`ValidatorSchema`] from a string containing Cedar "natural"
    /// schema syntax.
    pub fn from_str_natural<'a>(
        src: &str,
        extensions: Extensions<'a>,
    ) -> std::result::Result<(Self, impl Iterator<Item = SchemaWarning> + 'a), HumanSchemaError>
    {
        let (fragment, warnings) = SchemaFragment::from_str_natural(src, extensions)?;
        let schema_and_warnings =
            Self::from_schema_frag(fragment, ActionBehavior::default(), extensions)
                .map(|schema| (schema, warnings))?;
        Ok(schema_and_warnings)
    }

    /// Helper function to construct a [`ValidatorSchema`] from a single [`SchemaFragment`].
    pub(crate) fn from_schema_frag(
        schema_file: SchemaFragment<RawName>,
        action_behavior: ActionBehavior,
        extensions: Extensions<'_>,
    ) -> Result<ValidatorSchema> {
        Self::from_schema_fragments(
            [ValidatorSchemaFragment::from_schema_fragment(
                schema_file,
                action_behavior,
                extensions,
            )?],
            extensions,
        )
    }

    /// Construct a [`ValidatorSchema`] from some number of [`ValidatorSchemaFragment`]s.
    pub fn from_schema_fragments(
        fragments: impl IntoIterator<Item = ValidatorSchemaFragment<ConditionalName>>,
        extensions: Extensions<'_>,
    ) -> Result<ValidatorSchema> {
        let mut fragments = fragments
            .into_iter()
            // All schemas implicitly include the following fragment as well,
            // defining the items in the `__cedar` namespace.
            .chain(std::iter::once(cedar_fragment(extensions)))
            .collect::<Vec<_>>();

        // Build the sets of all entity and common type definitions
        // (fully-qualified `Name`s) in all fragments.
        let all_entity_defs = fragments
            .iter()
            .flat_map(|f| f.0.iter())
            .flat_map(|ns_def| ns_def.all_declared_entity_type_names().cloned())
            .collect::<HashSet<Name>>();
        let mut all_common_defs = fragments
            .iter()
            .flat_map(|f| f.0.iter())
            .flat_map(|ns_def| ns_def.all_declared_common_type_names().cloned())
            .collect::<HashSet<Name>>();

        // Add aliases for primitive and extension typenames in the empty namespace,
        // so that they can be accessed without `__cedar`.
        // (Only add each alias if it doesn't conflict with a user declaration --
        // if it does conflict, we won't add the alias and the user needs to use
        // `__cedar` to refer to the primitive/extension type.)
        // In the future, if we support some kind of `use` keyword to make names
        // available in the empty namespace, we'd probably add that here.
        for tyname in primitive_types()
            .map(Name::unqualified_name)
            .chain(extensions.ext_types().cloned())
        {
            if !all_entity_defs.contains(&tyname) && !all_common_defs.contains(&tyname) {
                assert!(
                    tyname.is_unqualified(),
                    "expected all primitive and extension type names to be unqualified"
                );
                fragments.push(single_alias_in_empty_namespace(
                    tyname.basename().clone(),
                    tyname.qualify_with(Some(&Name::__cedar())),
                ));
                all_common_defs.insert(tyname);
            }
        }

        // Now use `all_entity_defs` and `all_common_defs` to resolve all
        // [`ConditionalName`] type references into fully-qualified [`Name`]
        // references.
        // ("Resolve" here just means convert to fully-qualified `Name`s; it
        // does not mean inlining common types / typedefs -- that will come
        // later.)
        // This produces an intermediate form of schema fragment,
        // `ValidatorSchemaFragment<Name>`.
        let (fragments, errs) = fragments
            .into_iter()
            .map(|frag| frag.fully_qualify_type_references(&all_common_defs, &all_entity_defs))
            .partition_result::<Vec<ValidatorSchemaFragment<Name>>, Vec<TypeResolutionError>, _, _>(
            );
        if let Some(errs) = NonEmpty::from_vec(errs) {
            return Err(TypeResolutionError::join_nonempty(errs).into());
        }

        // Now that all references are fully-qualified, we can build the aggregate
        // maps for common types, entity types, and actions, checking that nothing
        // is defined twice. Since all of these names are already fully-qualified,
        // the same base type name may appear multiple times so long as the
        // namespaces are different.
        let mut type_defs = HashMap::new();
        let mut entity_type_fragments: HashMap<EntityType, _> = HashMap::new();
        let mut action_fragments = HashMap::new();
        for ns_def in fragments.into_iter().flat_map(|f| f.0.into_iter()) {
            for (name, ty) in ns_def.type_defs.type_defs {
                match type_defs.entry(name) {
                    Entry::Vacant(v) => v.insert(ty),
                    Entry::Occupied(o) => {
                        return Err(DuplicateCommonTypeError(o.key().clone()).into());
                    }
                };
            }

            for (name, entity_type) in ns_def.entity_types.entity_types {
                match entity_type_fragments.entry(name) {
                    Entry::Vacant(v) => v.insert(entity_type),
                    Entry::Occupied(o) => {
                        return Err(DuplicateEntityTypeError(o.key().clone()).into())
                    }
                };
            }

            for (action_euid, action) in ns_def.actions.actions {
                match action_fragments.entry(action_euid) {
                    Entry::Vacant(v) => v.insert(action),
                    Entry::Occupied(o) => {
                        return Err(DuplicateActionError(o.key().to_smolstr()).into())
                    }
                };
            }
        }

        let resolver = CommonTypeResolver::new(&type_defs);
        let type_defs = resolver.resolve(extensions)?;

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
                let (attributes, open_attributes) = {
                    let unresolved =
                        try_schema_type_into_validator_type(entity_type.attributes, extensions)?;
                    Self::record_attributes_or_none(unresolved.resolve_type_defs(&type_defs)?)
                        .ok_or(ContextOrShapeNotRecordError(
                            ContextOrShape::EntityTypeShape(name.clone()),
                        ))?
                };
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
                let (context, open_context_attributes) = {
                    let unresolved =
                        try_schema_type_into_validator_type(action.context, extensions)?;
                    Self::record_attributes_or_none(unresolved.resolve_type_defs(&type_defs)?)
                        .ok_or(ContextOrShapeNotRecordError(ContextOrShape::ActionContext(
                            name.clone(),
                        )))?
                };
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
        compute_tc(&mut entity_types, false)
            .map_err(|e| EntityTypeTransitiveClosureError::from(Box::new(e)))?;
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
        entity_types: &HashMap<EntityType, ValidatorEntityType>,
        undeclared_parent_entities: impl IntoIterator<Item = EntityType>,
        action_ids: &HashMap<EntityUID, ValidatorActionId>,
        undeclared_parent_actions: impl IntoIterator<Item = EntityUID>,
    ) -> Result<()> {
        // When we constructed `entity_types`, we removed entity types from  the
        // `entity_children` map as we encountered a declaration for that type.
        // Any entity types left in the map are therefore undeclared. These are
        // any undeclared entity types which appeared in a `memberOf` list.
        let mut undeclared_e = undeclared_parent_entities
            .into_iter()
            .collect::<BTreeSet<EntityType>>();
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
            .map(|n| n.to_smolstr())
            .collect::<BTreeSet<_>>();
        // For actions, we check entity references in the context attribute
        // types and `appliesTo` lists. See the `entity_types` loop for why the
        // `descendants` list is not checked.
        for action in action_ids.values() {
            Self::check_undeclared_in_type(&action.context, entity_types, &mut undeclared_e);

            for p_entity in action.applies_to_principals() {
                if !entity_types.contains_key(p_entity) {
                    undeclared_e.insert(p_entity.clone());
                }
            }

            for r_entity in action.applies_to_resources() {
                if !entity_types.contains_key(r_entity) {
                    undeclared_e.insert(r_entity.clone());
                }
            }
        }
        if !undeclared_e.is_empty() {
            return Err(UndeclaredEntityTypesError(undeclared_e).into());
        }
        if !undeclared_a.is_empty() {
            return Err(UndeclaredActionsError(undeclared_a).into());
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
        entity_types: &HashMap<EntityType, ValidatorEntityType>,
        undeclared_types: &mut BTreeSet<EntityType>,
    ) {
        match ty {
            Type::EntityOrRecord(EntityRecordKind::Entity(lub)) => {
                for name in lub.iter() {
                    if !entity_types.contains_key(name) {
                        undeclared_types.insert(name.clone());
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

    /// Lookup the [`ValidatorActionId`] object in the schema with the given name.
    pub fn get_action_id(&self, action_id: &EntityUID) -> Option<&ValidatorActionId> {
        self.action_ids.get(action_id)
    }

    /// Lookup the [`ValidatorEntityType`] object in the schema with the given name.
    pub fn get_entity_type<'a>(
        &'a self,
        entity_type_id: &EntityType,
    ) -> Option<&'a ValidatorEntityType> {
        self.entity_types.get(entity_type_id)
    }

    /// Return true when the `action_id` corresponds to a valid action.
    pub(crate) fn is_known_action_id(&self, action_id: &EntityUID) -> bool {
        self.action_ids.contains_key(action_id)
    }

    /// Return true when the `entity_type` corresponds to a valid entity type.
    pub(crate) fn is_known_entity_type(&self, entity_type: &EntityType) -> bool {
        entity_type.is_action() || self.entity_types.contains_key(entity_type)
    }

    /// Return true when `euid` has an entity type declared by the schema.
    pub(crate) fn euid_has_known_entity_type(&self, euid: &EntityUID) -> bool {
        self.is_known_entity_type(euid.entity_type())
    }

    /// An iterator over the action ids in the schema.
    pub(crate) fn known_action_ids(&self) -> impl Iterator<Item = &EntityUID> {
        self.action_ids.keys()
    }

    /// An iterator over the entity type names in the schema.
    pub(crate) fn known_entity_types(&self) -> impl Iterator<Item = &EntityType> {
        self.entity_types.keys()
    }

    /// An iterator matching the entity Types to their Validator Types
    pub fn entity_types(&self) -> impl Iterator<Item = (&EntityType, &ValidatorEntityType)> {
        self.entity_types.iter()
    }

    /// Get all entity types in the schema where an `{entity0} in {entity}` can
    /// evaluate to `true` for some `entity0` with that entity type. This
    /// includes all entity types that are descendants of the type of `entity`
    /// according  to the schema, and the type of `entity` itself because
    /// `entity in entity` evaluates to `true`.
    pub(crate) fn get_entity_types_in<'a>(&'a self, entity: &'a EntityUID) -> Vec<&EntityType> {
        let mut descendants = self
            .get_entity_type(entity.entity_type())
            .map(|v_ety| v_ety.descendants.iter().collect::<Vec<_>>())
            .unwrap_or_default();
        descendants.push(entity.entity_type());
        descendants
    }

    /// Get all entity types in the schema where an `{entity0} in {euids}` can
    /// evaluate to `true` for some `entity0` with that entity type. See comment
    /// on `get_entity_types_in`.
    pub(crate) fn get_entity_types_in_set<'a>(
        &'a self,
        euids: impl IntoIterator<Item = &'a EntityUID> + 'a,
    ) -> impl Iterator<Item = &EntityType> {
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
    /// This always returns a closed record type.
    ///
    /// Returns `None` if the action is not in the schema.
    pub fn context_type(&self, action: &EntityUID) -> Option<&Type> {
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
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[serde(transparent)]
pub(crate) struct NamespaceDefinitionWithActionAttributes<N>(pub(crate) NamespaceDefinition<N>);

impl TryInto<ValidatorSchema> for NamespaceDefinitionWithActionAttributes<RawName> {
    type Error = SchemaError;

    fn try_into(self) -> Result<ValidatorSchema> {
        ValidatorSchema::from_schema_fragments(
            [ValidatorSchemaFragment::from_namespaces([
                ValidatorNamespaceDef::from_namespace_definition(
                    None,
                    self.0,
                    crate::ActionBehavior::PermitAttributes,
                    Extensions::all_available(),
                )?,
            ])],
            Extensions::all_available(),
        )
    }
}

/// Get a `ValidatorSchemaFragment` describing the items that implicitly exist
/// in the `__cedar` namespace.
fn cedar_fragment(extensions: Extensions<'_>) -> ValidatorSchemaFragment<ConditionalName> {
    // PANIC SAFETY: these are valid `Id`s
    #[allow(clippy::unwrap_used)]
    let mut common_types = HashMap::from_iter([
        (
            Id::from_str("Bool").unwrap(),
            SchemaType::Type(SchemaTypeVariant::Boolean),
        ),
        (
            Id::from_str("Long").unwrap(),
            SchemaType::Type(SchemaTypeVariant::Long),
        ),
        (
            Id::from_str("String").unwrap(),
            SchemaType::Type(SchemaTypeVariant::String),
        ),
    ]);
    for ext_type in extensions.ext_types() {
        assert!(
            ext_type.is_unqualified(),
            "expected extension type names to be unqualified"
        );
        let ext_type = ext_type.basename().clone();
        common_types.insert(
            ext_type.clone(),
            SchemaType::Type(SchemaTypeVariant::Extension { name: ext_type }),
        );
    }

    // PANIC SAFETY: this is a valid schema fragment. This code is tested by every test that constructs `ValidatorSchema`, and this fragment is the same every time, modulo active extensions.
    #[allow(clippy::unwrap_used)]
    ValidatorSchemaFragment(vec![ValidatorNamespaceDef::from_common_typedefs(
        Some(Name::__cedar()),
        common_types,
    )
    .unwrap()])
}

/// Get a `ValidatorSchemaFragment` containing just one common-type definition,
/// defining the unqualified name `id` in the empty namespace as an alias for
/// the fully-qualified name `def`. (This will eventually cause an error if
/// `def` is not defined somewhere.)
fn single_alias_in_empty_namespace(id: Id, def: Name) -> ValidatorSchemaFragment<ConditionalName> {
    ValidatorSchemaFragment(vec![ValidatorNamespaceDef::from_common_typedef(
        None,
        (
            id,
            SchemaType::EntityOrCommonTypeRef {
                type_name: ConditionalName::unconditional(def, ReferenceType::CommonOrEntity),
            },
        ),
    )])
}

/// Get the names of all primitive types, as unqualified `Id`s
fn primitive_types() -> impl Iterator<Item = Id> {
    // PANIC SAFETY: these are valid `Id`s
    #[allow(clippy::unwrap_used)]
    [
        Id::from_str("Bool").unwrap(),
        Id::from_str("Long").unwrap(),
        Id::from_str("String").unwrap(),
    ]
    .into_iter()
}

/// A common type reference resolver.
/// This resolver is designed to operate on fully-qualified references.
/// It facilitates inlining the definitions of common types.
#[derive(Debug)]
struct CommonTypeResolver<'a> {
    /// Common type declarations to resolve.
    ///
    /// Here, both common-type definitions (keys in the map) and common-type
    /// references appearing in [`SchemaType`]s (values in the map) are already
    /// fully-qualified [`Name`]s.
    type_defs: &'a HashMap<Name, SchemaType<Name>>,
    /// The dependency graph among common type names.
    /// The graph contains a vertex for each [`Name`], and `graph.get(u)` gives
    /// the set of vertices `v` for which `(u,v)` is a directed edge in the
    /// graph.
    /// All common-type names (in both keys and values here) are already
    /// fully-qualified [`Name`]s.
    graph: HashMap<&'a Name, HashSet<&'a Name>>,
}

impl<'a> CommonTypeResolver<'a> {
    /// Construct the resolver.
    /// Note that this requires that all common-type references are already
    /// fully qualified, because it uses [`Name`] and not [`RawName`].
    fn new(type_defs: &'a HashMap<Name, SchemaType<Name>>) -> Self {
        let mut graph = HashMap::new();
        for (name, ty) in type_defs {
            graph.insert(name, HashSet::from_iter(ty.common_type_references()));
        }
        Self { type_defs, graph }
    }

    /// Perform topological sort on the dependency graph
    ///
    /// Let A -> B denote the RHS of type `A` refers to type `B` (i.e., `A`
    /// depends on `B`)
    ///
    /// `topo_sort(A -> B -> C)` produces [C, B, A]
    ///
    /// If there is a cycle, a type name involving in this cycle is the error
    ///
    /// It implements a variant of Kahn's algorithm
    fn topo_sort(&self) -> std::result::Result<Vec<&'a Name>, Name> {
        // The in-degree map
        // Note that the keys of this map may be a superset of all common type
        // names
        let mut indegrees: HashMap<&Name, usize> = HashMap::new();
        for (ty_name, deps) in self.graph.iter() {
            // Ensure that declared common types have values in `indegrees`
            indegrees.entry(ty_name).or_insert(0);
            for dep in deps {
                match indegrees.entry(dep) {
                    std::collections::hash_map::Entry::Occupied(mut o) => {
                        o.insert(o.get() + 1);
                    }
                    std::collections::hash_map::Entry::Vacant(v) => {
                        v.insert(1);
                    }
                }
            }
        }

        // The set that contains type names with zero incoming edges
        let mut work_set: HashSet<&'a Name> = HashSet::new();
        let mut res: Vec<&'a Name> = Vec::new();

        // Find all type names with zero incoming edges
        for (name, degree) in indegrees.iter() {
            let name = *name;
            if *degree == 0 {
                work_set.insert(name);
                // The result only contains *declared* type names
                if self.graph.contains_key(name) {
                    res.push(name);
                }
            }
        }

        // Pop a node
        while let Some(name) = work_set.iter().next().cloned() {
            work_set.remove(name);
            if let Some(deps) = self.graph.get(name) {
                for dep in deps {
                    if let Some(degree) = indegrees.get_mut(dep) {
                        // There will not be any underflows here because
                        // in order for the in-degree to underflow, `dep`'s
                        // in-degree must be 0 at this point
                        // The only possibility where a node's in-degree
                        // becomes 0 is through the subtraction below, which
                        // means it has been visited and hence has 0 in-degrees
                        // In other words, all its in-coming edges have been
                        // "removed" and hence contradicts with the fact that
                        // one of them is being "removed"
                        *degree -= 1;
                        if *degree == 0 {
                            work_set.insert(dep);
                            if self.graph.contains_key(dep) {
                                res.push(dep);
                            }
                        }
                    }
                }
            }
        }

        // The set of nodes that have not been added to the result
        // i.e., there are still in-coming edges and hence exists a cycle
        let mut set: HashSet<&Name> = HashSet::from_iter(self.graph.keys().cloned());
        for name in res.iter() {
            set.remove(name);
        }

        if let Some(cycle) = set.into_iter().next() {
            Err(cycle.clone())
        } else {
            // We need to reverse the result because, e.g.,
            // `res` is now [A,B,C] for A -> B -> C because no one depends on A
            res.reverse();
            Ok(res)
        }
    }

    // Substitute common type references in `ty` according to `resolve_table`
    fn resolve_type(
        resolve_table: &HashMap<&Name, SchemaType<Name>>,
        ty: SchemaType<Name>,
    ) -> Result<SchemaType<Name>> {
        match ty {
            SchemaType::CommonTypeRef { type_name } => resolve_table
                .get(&type_name)
                .ok_or(UndeclaredCommonTypeError(type_name).into())
                .cloned(),
            SchemaType::EntityOrCommonTypeRef { type_name } => {
                match resolve_table.get(&type_name) {
                    Some(def) => Ok(def.clone()),
                    None => Ok(SchemaType::Type(SchemaTypeVariant::Entity {
                        name: type_name,
                    })),
                }
            }
            SchemaType::Type(SchemaTypeVariant::Set { element }) => {
                Ok(SchemaType::Type(SchemaTypeVariant::Set {
                    element: Box::new(Self::resolve_type(resolve_table, *element)?),
                }))
            }
            SchemaType::Type(SchemaTypeVariant::Record {
                attributes,
                additional_attributes,
            }) => Ok(SchemaType::Type(SchemaTypeVariant::Record {
                attributes: BTreeMap::from_iter(
                    attributes
                        .into_iter()
                        .map(|(attr, attr_ty)| {
                            Ok((
                                attr,
                                TypeOfAttribute {
                                    required: attr_ty.required,
                                    ty: Self::resolve_type(resolve_table, attr_ty.ty)?,
                                },
                            ))
                        })
                        .collect::<Result<Vec<(_, _)>>>()?,
                ),
                additional_attributes,
            })),
            _ => Ok(ty),
        }
    }

    // Resolve common type references, returning a map from (fully-qualified)
    // [`Name`] of a common type to its [`Type`] definition
    fn resolve(&self, extensions: Extensions<'_>) -> Result<HashMap<&'a Name, Type>> {
        let sorted_names = self.topo_sort().map_err(|n| {
            SchemaError::CycleInCommonTypeReferences(CycleInCommonTypeReferencesError(n))
        })?;

        let mut resolve_table: HashMap<&Name, SchemaType<Name>> = HashMap::new();
        let mut tys: HashMap<&'a Name, Type> = HashMap::new();

        for &name in sorted_names.iter() {
            // PANIC SAFETY: `name.basename()` should be an existing common type id
            #[allow(clippy::unwrap_used)]
            let ty = self.type_defs.get(name).unwrap();
            let substituted_ty = Self::resolve_type(&resolve_table, ty.clone())?;
            resolve_table.insert(name, substituted_ty.clone());
            tys.insert(
                name,
                try_schema_type_into_validator_type(substituted_ty, extensions)?
                    .resolve_type_defs(&HashMap::new())?,
            );
        }

        Ok(tys)
    }
}

// PANIC SAFETY unit tests
#[allow(clippy::panic)]
// PANIC SAFETY unit tests
#[allow(clippy::indexing_slicing)]
#[cfg(test)]
mod test {
    use std::{
        collections::{BTreeMap, HashSet},
        str::FromStr,
    };

    use crate::types::Type;
    use crate::{SchemaType, SchemaTypeVariant};

    use cedar_policy_core::ast::RestrictedExpr;
    use cedar_policy_core::test_utils::{expect_err, ExpectedErrorMessageBuilder};
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
        let schema_file: NamespaceDefinition<RawName> =
            serde_json::from_value(src).expect("Parse Error");
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
            Err(SchemaError::JsonDeserialization(_)) => (),
            _ => panic!("Expected JSON deserialization error due to duplicate entity type."),
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
            Err(SchemaError::JsonDeserialization(_)) => (),
            _ => panic!("Expected JSON deserialization error due to duplicate action type."),
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
        let schema_file: NamespaceDefinition<RawName> =
            serde_json::from_value(src.clone()).expect("Parse Error");
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"failed to resolve types: Grop, Usr, Phoot"#)
                    .help("`Grop` has not been declared")
                    .build());
        });
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
        let schema_file: SchemaFragment<RawName> =
            serde_json::from_value(src.clone()).expect("Parse Error");
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"failed to resolve type: Bar::Group"#)
                    .help("`Bar::Group` has not been declared")
                    .build());
        });
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
        let schema_file: SchemaFragment<RawName> =
            serde_json::from_value(src.clone()).expect("Parse Error");
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"failed to resolve types: Bar::User, Bar::Photo"#)
                    .help("`Bar::User` has not been declared")
                    .build());
        });
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
        let schema_file: NamespaceDefinition<RawName> =
            serde_json::from_value(src.clone()).expect("Parse Error");
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"undeclared action: Action::"photo_action""#)
                    .help("any actions appearing in `memberOf` need to be declared in `actions`")
                    .build());
        });
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
        let schema_file: NamespaceDefinition<RawName> =
            serde_json::from_value(src).expect("Parse Error");
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        assert_matches!(
            schema,
            Err(SchemaError::CycleInActionHierarchy(CycleInActionHierarchyError(euid))) => {
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
        let schema_file: NamespaceDefinition<RawName> =
            serde_json::from_value(src).expect("Parse Error");
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
        let schema_file: SchemaFragment<RawName> = serde_json::from_str(src).expect("Parse Error");
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

        let action = &schema.action_ids.values().next().expect("Expected Action");
        assert_eq!(
            action.applies_to_principals().collect::<Vec<_>>(),
            vec![user_entity_type]
        );
        assert_eq!(
            action.applies_to_resources().collect::<Vec<_>>(),
            vec![photo_entity_type]
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
        assert_matches!(
            serde_json::from_str::<NamespaceDefinition<RawName>>(src),
            Err(_)
        );
    }

    #[test]
    fn entity_attribute_entity_type_with_namespace() {
        let src = json!(
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
          }});
        let schema_json: SchemaFragment<RawName> =
            serde_json::from_value(src.clone()).expect("Expected valid schema");

        let schema: Result<ValidatorSchema> = schema_json.try_into();
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"failed to resolve type: C::D::Foo"#)
                    .help("`C::D::Foo` has not been declared")
                    .build());
        });
    }

    #[test]
    fn entity_attribute_entity_type_with_declared_namespace() {
        let schema_json: SchemaFragment<RawName> = serde_json::from_str(
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

        let foo_name: EntityType = "A::B::Foo".parse().expect("Expected entity type name");
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
        let schema_json: NamespaceDefinition<RawName> = serde_json::from_str(
            r#"
            {
                "entityTypes": { "Action": {} },
                "actions": {}
              }
            "#,
        )
        .expect("Expected valid schema");

        let schema: Result<ValidatorSchema> = schema_json.try_into();
        assert!(matches!(
            schema,
            Err(SchemaError::ActionEntityTypeDeclared(_))
        ));
    }

    #[test]
    fn can_declare_other_type_when_action_type_prohibited() {
        let schema_json: NamespaceDefinition<RawName> = serde_json::from_str(
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
        let schema_json: SchemaFragment<RawName> = serde_json::from_str(
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
            Err(e) => {
                expect_err(
                    "",
                    &miette::Report::new(e),
                    &ExpectedErrorMessageBuilder::error("unsupported feature used in schema")
                        .source(r#"action declared with attributes: [delete_photo, edit_photo, view_photo]"#)
                        .build()
                )
            }
            _ => panic!("Did not see expected error."),
        }
    }

    #[test]
    fn test_entity_type_no_namespace() {
        let src = json!({"type": "Entity", "name": "Foo"});
        let schema_ty: SchemaType<RawName> = serde_json::from_value(src).expect("Parse Error");
        assert_eq!(
            schema_ty,
            SchemaType::Type(SchemaTypeVariant::Entity {
                name: "Foo".parse().unwrap()
            })
        );
        let schema_ty = schema_ty.conditionally_qualify_type_references(Some(
            &Name::parse_unqualified_name("NS").unwrap(),
        ));
        let all_entity_defs = HashSet::from_iter([
            Name::from_str("NS::Foo").unwrap(),
            Name::from_str("Foo").unwrap(),
        ]);
        let schema_ty = schema_ty
            .fully_qualify_type_references(&HashSet::new(), &all_entity_defs)
            .unwrap();
        let ty: Type = try_schema_type_into_validator_type(schema_ty, Extensions::all_available())
            .expect("Error converting schema type to type.")
            .resolve_type_defs(&HashMap::new())
            .unwrap();
        assert_eq!(ty, Type::named_entity_reference_from_str("NS::Foo"));
    }

    #[test]
    fn test_entity_type_namespace() {
        let src = json!({"type": "Entity", "name": "NS::Foo"});
        let schema_ty: SchemaType<RawName> = serde_json::from_value(src).expect("Parse Error");
        assert_eq!(
            schema_ty,
            SchemaType::Type(SchemaTypeVariant::Entity {
                name: "NS::Foo".parse().unwrap()
            })
        );
        let schema_ty = schema_ty.conditionally_qualify_type_references(Some(
            &Name::parse_unqualified_name("NS").unwrap(),
        ));
        let all_entity_defs = HashSet::from_iter([
            Name::from_str("NS::Foo").unwrap(),
            Name::from_str("Foo").unwrap(),
        ]);
        let schema_ty = schema_ty
            .fully_qualify_type_references(&HashSet::new(), &all_entity_defs)
            .unwrap();
        let ty: Type = try_schema_type_into_validator_type(schema_ty, Extensions::all_available())
            .expect("Error converting schema type to type.")
            .resolve_type_defs(&HashMap::new())
            .unwrap();
        assert_eq!(ty, Type::named_entity_reference_from_str("NS::Foo"));
    }

    #[test]
    fn test_entity_type_namespace_parse_error() {
        let src = json!({"type": "Entity", "name": "::Foo"});
        assert_matches!(serde_json::from_value::<SchemaType<RawName>>(src), Err(_));
    }

    #[test]
    fn schema_type_record_is_validator_type_record() {
        let src = json!({"type": "Record", "attributes": {}});
        let schema_ty: SchemaType<RawName> = serde_json::from_value(src).expect("Parse Error");
        assert_eq!(
            schema_ty,
            SchemaType::Type(SchemaTypeVariant::Record {
                attributes: BTreeMap::new(),
                additional_attributes: false,
            }),
        );
        let schema_ty = schema_ty.conditionally_qualify_type_references(None);
        let all_entity_defs = HashSet::from_iter([Name::from_str("Foo").unwrap()]);
        let schema_ty = schema_ty
            .fully_qualify_type_references(&HashSet::new(), &all_entity_defs)
            .unwrap();
        let ty: Type = try_schema_type_into_validator_type(schema_ty, Extensions::all_available())
            .expect("Error converting schema type to type.")
            .resolve_type_defs(&HashMap::new())
            .unwrap();
        assert_eq!(ty, Type::closed_record_with_attributes(None));
    }

    #[test]
    fn get_namespaces() {
        let fragment: SchemaFragment<RawName> = serde_json::from_value(json!({
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

        let schema_fragment: ValidatorSchemaFragment<ConditionalName> =
            fragment.try_into().unwrap();
        assert_eq!(
            schema_fragment
                .0
                .iter()
                .map(|f| f.namespace())
                .collect::<HashSet<_>>(),
            HashSet::from([
                Some(&"Foo::Bar::Baz".parse().unwrap()),
                Some(&"Foo".parse().unwrap()),
                Some(&"Bar".parse().unwrap())
            ])
        );
    }

    #[test]
    fn schema_no_fragments() {
        let schema =
            ValidatorSchema::from_schema_fragments([], Extensions::all_available()).unwrap();
        assert!(schema.entity_types.is_empty());
        assert!(schema.action_ids.is_empty());
    }

    #[test]
    fn same_action_different_namespace() {
        let fragment: SchemaFragment<RawName> = serde_json::from_value(json!({
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
        let fragment: SchemaFragment<RawName> = serde_json::from_value(json!({
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
        let fragment: SchemaFragment<RawName> = serde_json::from_value(json!({
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
        let fragment: SchemaFragment<RawName> = serde_json::from_value(json!({
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
        let fragment: SchemaFragment<RawName> = serde_json::from_value(json!({
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
            HashSet::from([&("Fiz::Buz".parse().unwrap())])
        );
        assert_eq!(
            baz.applies_to
                .applicable_resource_types()
                .collect::<HashSet<_>>(),
            HashSet::from([&("Fiz::Baz".parse().unwrap())])
        );
    }

    #[test]
    fn simple_defined_type() {
        let fragment: SchemaFragment<RawName> = serde_json::from_value(json!({
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
        let fragment: SchemaFragment<RawName> = serde_json::from_value(json!({
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
        let fragment: SchemaFragment<RawName> = serde_json::from_value(json!({
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
        let fragment1: ValidatorSchemaFragment<ConditionalName> =
            serde_json::from_value::<SchemaFragment<RawName>>(json!({
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
        let fragment2: ValidatorSchemaFragment<ConditionalName> =
            serde_json::from_value::<SchemaFragment<RawName>>(json!({
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
        let schema = ValidatorSchema::from_schema_fragments(
            [fragment1, fragment2],
            Extensions::all_available(),
        )
        .unwrap();

        assert_eq!(
            schema.entity_types.iter().next().unwrap().1.attributes,
            Attributes::with_required_attributes([("a".into(), Type::primitive_long())])
        );
    }

    #[test]
    fn cross_fragment_duplicate_type() {
        let fragment1: ValidatorSchemaFragment<ConditionalName> =
            serde_json::from_value::<SchemaFragment<RawName>>(json!({
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
        let fragment2: ValidatorSchemaFragment<ConditionalName> =
            serde_json::from_value::<SchemaFragment<RawName>>(json!({
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

        let schema = ValidatorSchema::from_schema_fragments(
            [fragment1, fragment2],
            Extensions::all_available(),
        );

        // should error because schema fragments have duplicate types
        assert_matches!(schema, Err(SchemaError::DuplicateCommonType(DuplicateCommonTypeError(s))) => {
            assert_eq!(s, "A::MyLong".parse().unwrap());
        });
    }

    #[test]
    fn undeclared_type_in_attr() {
        let fragment: SchemaFragment<RawName> = serde_json::from_value(json!({
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
        assert_matches!(
            TryInto::<ValidatorSchema>::try_into(fragment),
            Err(SchemaError::TypeResolution(_))
        );
    }

    #[test]
    fn undeclared_type_in_type_def() {
        let fragment: SchemaFragment<RawName> = serde_json::from_value(json!({
            "": {
                "commonTypes": {
                    "a": { "type": "b" }
                },
                "entityTypes": { },
                "actions": {}
            }
        }))
        .unwrap();
        assert_matches!(
            TryInto::<ValidatorSchema>::try_into(fragment),
            Err(SchemaError::TypeResolution(_))
        );
    }

    #[test]
    fn shape_not_record() {
        let fragment: SchemaFragment<RawName> = serde_json::from_value(json!({
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
        assert_matches!(
            TryInto::<ValidatorSchema>::try_into(fragment),
            Err(SchemaError::ContextOrShapeNotRecord(_))
        );
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
        assert_matches!(
            serde_json::from_value::<SchemaFragment<RawName>>(bad1),
            Err(_)
        );

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
        assert_matches!(
            serde_json::from_value::<SchemaFragment<RawName>>(bad2),
            Err(_)
        );
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

        let schema_file: NamespaceDefinition<RawName> =
            serde_json::from_value(src).expect("Parse Error");
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

        let schema_file: NamespaceDefinition<RawName> =
            serde_json::from_value(src).expect("Parse Error");
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

        let schema_file: NamespaceDefinitionWithActionAttributes<RawName> =
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
            serde_json::from_value::<SchemaFragment<RawName>>(src).expect("Failed to parse schema");
        let schema: ValidatorSchema = schema_fragment.try_into().expect("Schema should construct");
        let view_photo = schema
            .action_entities_iter()
            .find(|e| e.uid() == &r#"ExampleCo::Personnel::Action::"viewPhoto""#.parse().unwrap())
            .unwrap();
        let ancestors = view_photo.ancestors().collect::<Vec<_>>();
        let read = ancestors[0];
        let read_eid: &str = read.eid().as_ref();
        assert_eq!(read_eid, "read");
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
            serde_json::from_value::<SchemaFragment<RawName>>(src).expect("Failed to parse schema");
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
            serde_json::from_value::<SchemaFragment<RawName>>(src).expect("Failed to parse schema");
        let schema: ValidatorSchema = schema_fragment.try_into().unwrap();
        let view_photo = schema
            .action_entities_iter()
            .find(|e| e.uid() == &r#"ExampleCo::Personnel::Action::"viewPhoto""#.parse().unwrap())
            .unwrap();
        let ancestors = view_photo.ancestors().collect::<Vec<_>>();
        let read = ancestors[0];
        let read_eid: &str = read.eid().as_ref();
        assert_eq!(read_eid, "read");
        assert_eq!(
            read.entity_type().to_string(),
            "ExampleCo::Personnel::Action"
        );
    }

    #[test]
    fn fallback_to_empty_namespace() {
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
        let schema =
            ValidatorSchema::from_json_value(src.clone(), Extensions::all_available()).unwrap();
        let mut attributes = schema
            .get_entity_type(&"Demo::User".parse().unwrap())
            .unwrap()
            .attributes();
        let (attr_name, attr_ty) = attributes.next().unwrap();
        assert_eq!(attr_name, "id");
        assert_eq!(&attr_ty.attr_type, &Type::primitive_string());
        assert_matches!(attributes.next(), None);
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
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"failed to resolve type: Demo::id"#)
                    .help("`Demo::id` has not been declared")
                    .build());
        });
    }

    #[test]
    fn unknown_extension_type() {
        let src: serde_json::Value = json!({
            "": {
                "commonTypes": { },
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": {
                                    "type": "Extension",
                                    "name": "ip",
                                }
                            }
                        }
                    }
                },
                "actions": {}
            }
        });
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("unknown extension type `ip`")
                    .help("did you mean `ipaddr`?")
                    .build());
        });

        let src: serde_json::Value = json!({
            "": {
                "commonTypes": { },
                "entityTypes": {
                    "User": {},
                    "Folder" :{}
                },
                "actions": {
                    "A": {
                        "appliesTo": {
                            "principalTypes" : ["User"],
                            "resourceTypes" : ["Folder"],
                            "context": {
                                "type": "Record",
                                "attributes": {
                                    "a": {
                                        "type": "Extension",
                                        "name": "deciml",
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("unknown extension type `deciml`")
                    .help("did you mean `decimal`?")
                    .build());
        });

        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "ty": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Extension",
                                "name": "i",
                            }
                        }
                    }
                },
                "entityTypes": { },
                "actions": { },
            }
        });
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("unknown extension type `i`")
                    .help("did you mean `ipaddr`?")
                    .build());
        });

        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "ty": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Extension",
                                "name": "partial_evaluation",
                            }
                        }
                    }
                },
                "entityTypes": { },
                "actions": { },
            }
        });
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("unknown extension type `partial_evaluation`")
                    .help("did you mean `decimal`?")
                    .build());
        });
    }

    #[test]
    fn test_common_type_name_conflicts() {
        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "Record": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Record"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Ok(_));

        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "Extension": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Extension"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Ok(_));

        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "Entity": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Entity"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Ok(_));

        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "Set": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Set"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Ok(_));

        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "Long": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Long"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Ok(_));

        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "Boolean": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Boolean"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Ok(_));

        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "String": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "String"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Ok(_));
    }
}

/// Tests described in https://github.com/cedar-policy/cedar/issues/579
///
/// We test all possible (position, scenario) pairs where:
///
/// position is all places a typename can occur in a schema:
/// A. Inside a context attribute type
/// B. Inside an entity attribute type
/// C. Inside the body of a common-type definition
/// D. As an entity parent type
/// E. In an action `appliesTo` declaration
/// F. Inside an action attribute type?
/// G. In an action parent declaration?
///
/// and scenario is all the ways a typename can resolve:
/// 1. the typename is written without a namespace
///     a. and that typename is declared in the current namespace (but not the empty namespace)
///         1. as an entity type
///         2. as a common type
///     b. and that typename is declared in the empty namespace (but not the current namespace)
///         1. as an entity type
///         2. as a common type
///     c. and that typename is not declared in either the current namespace or the empty namespace
/// 2. the typename is written _with_ the current namespace explicit
///     a. and that typename is declared in the current namespace (but not the empty namespace)
///         1. as an entity type
///         2. as a common type
///     b. and that typename is declared in the empty namespace (but not the current namespace)
///         1. as an entity type
///         2. as a common type
///     c. and that typename is not declared in either the current namespace or the empty namespace
/// 3. the typename is written _with_ an explicit namespace NS (not the current namespace)
///     a. and that typename is declared in the current namespace (but not the empty namespace or NS)
///         1. as an entity type
///         2. as a common type
///     b. and that typename is declared in the empty namespace (but not the current namespace or NS)
///         1. as an entity type
///         2. as a common type
///     c. and that typename is not declared in the current namespace, the empty namespace, or NS
///     d. and that typename is declared in NS (and also the current namespace, but not the empty namespace)
///         1. as an entity type
///         2. as a common type
///
/// We also repeat all of these tests with both the human syntax and the JSON syntax.
/// The JSON syntax distinguishes syntactically between entity and common type _references_;
/// we only do the test for the more sensible one. (For instance, for 1a1, we
/// only test an entity type reference, not a common type reference.)
#[cfg(test)]
mod test_579 {
    use super::{SchemaWarning, ValidatorSchema};
    use cedar_policy_core::extensions::Extensions;
    use cedar_policy_core::test_utils::{
        expect_err, ExpectedErrorMessage, ExpectedErrorMessageBuilder,
    };
    use cool_asserts::assert_matches;
    use serde_json::json;

    /// Transform the output of functions like
    /// `ValidatorSchema::from_str_natural()`, which has type `(ValidatorSchema, impl Iterator<...>)`,
    /// into `(ValidatorSchema, Vec<...>)`, which implements `Debug` and thus can be used with
    /// `assert_matches`, `.unwrap_err()`, etc
    fn collect_warnings<A, B, E>(
        r: Result<(A, impl Iterator<Item = B>), E>,
    ) -> Result<(A, Vec<B>), E> {
        r.map(|(a, iter)| (a, iter.collect()))
    }

    #[track_caller]
    fn assert_parses_successfully_human(s: &str) -> (ValidatorSchema, Vec<SchemaWarning>) {
        println!("{s}");
        collect_warnings(ValidatorSchema::from_str_natural(
            s,
            Extensions::all_available(),
        ))
        .map_err(miette::Report::new)
        .unwrap()
    }

    #[track_caller]
    fn assert_parses_successfully_json(v: serde_json::Value) -> ValidatorSchema {
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
        ValidatorSchema::from_json_value(v, Extensions::all_available())
            .map_err(miette::Report::new)
            .unwrap()
    }

    #[track_caller]
    fn assert_parse_error_human(s: &str, e: &ExpectedErrorMessage<'_>) {
        println!("{s}");
        assert_matches!(collect_warnings(ValidatorSchema::from_str_natural(s, Extensions::all_available())), Err(err) => {
            expect_err(s, &miette::Report::new(err), e);
        });
    }

    #[track_caller]
    fn assert_parse_error_json(v: serde_json::Value, e: &ExpectedErrorMessage<'_>) {
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
        assert_matches!(ValidatorSchema::from_json_value(v.clone(), Extensions::all_available()), Err(err) => {
            expect_err(&v, &miette::Report::new(err), e);
        });
    }

    /// Makes a schema for all the XXa1 test cases, where different XX plug in
    /// different `mytype_use` (schema constructs that use `MyType`).
    ///
    /// In all of these cases, `MyType` is declared as an entity type in the
    /// current namespace (NS1).
    fn a1_human(mytype_use: &str) -> String {
        format!(
            r#"
        namespace NS1 {{
            entity User, Resource;
            entity MyType;
            {mytype_use}
        }}
        "#
        )
    }

    /// Makes a schema for all the XXa1 test cases, where different XX plug in a
    /// different schema construct that uses `MyType` (e.g., with a function
    /// like `A1_json()`).
    ///
    /// In all of these cases, `MyType` is declared as an entity type in the
    /// current namespace (NS1).
    fn a1_json() -> serde_json::Value {
        json!({
            "NS1": {
                "entityTypes": {
                    "User": { "memberOfTypes": [] },
                    "Resource": { "memberOfTypes": [] },
                    "MyType": { "memberOfTypes": [] },
                },
                "actions": {}
            }
        })
    }

    /// Makes a schema for all the XXa2 test cases, where different XX plug in
    /// different `mytype_use` (schema constructs that use `MyType`).
    ///
    /// In all of these cases, `MyType` is declared as a common type in the
    /// current namespace (NS1).
    fn a2_human(mytype_use: &str) -> String {
        format!(
            r#"
        namespace NS1 {{
            entity User, Resource;
            type MyType = String;
            {mytype_use}
        }}
        "#
        )
    }

    /// Makes a schema for all the XXa2 test cases, where different XX plug in a
    /// different schema construct that uses `MyType` (e.g., with a function
    /// like `A1_json()`).
    ///
    /// In all of these cases, `MyType` is declared as a common type in the
    /// current namespace (NS1).
    fn a2_json() -> serde_json::Value {
        json!({
            "NS1": {
                "entityTypes": {
                    "User": { "memberOfTypes": [] },
                    "Resource": { "memberOfTypes": [] },
                },
                "commonTypes": {
                    "MyType": { "type": "String" },
                },
                "actions": {}
            }
        })
    }

    /// Makes a schema for all the XXb1 test cases, where different XX plug in
    /// different `mytype_use` (schema constructs that use `MyType`).
    ///
    /// In all of these cases, `MyType` is declared as an entity type in the
    /// empty namespace.
    fn b1_human(mytype_use: &str) -> String {
        format!(
            r#"
        entity MyType;
        namespace NS1 {{
            entity User, Resource;
            {mytype_use}
        }}
        "#
        )
    }

    /// Makes a schema for all the XXb1 test cases, where different XX plug in a
    /// different schema construct that uses `MyType` (e.g., with a function
    /// like `A1_json()`).
    ///
    /// In all of these cases, `MyType` is declared as an entity type in the
    /// empty namespace.
    fn b1_json() -> serde_json::Value {
        json!({
            "": {
                "entityTypes": {
                    "MyType": { "memberOfTypes": [] }
                },
                "actions": {}
            },
            "NS1": {
                "entityTypes": {
                    "User": { "memberOfTypes": [] },
                    "Resource": { "memberOfTypes": [] },
                },
                "actions": {}
            }
        })
    }

    /// Makes a schema for all the XXb2 test cases, where different XX plug in
    /// different `mytype_use` (schema constructs that use `MyType`).
    ///
    /// In all of these cases, `MyType` is declared as a common type in the
    /// empty namespace.
    fn b2_human(mytype_use: &str) -> String {
        format!(
            r#"
        type MyType = String;
        namespace NS1 {{
            entity User, Resource;
            {mytype_use}
        }}
        "#
        )
    }

    /// Makes a schema for all the XXb2 test cases, where different XX plug in a
    /// different schema construct that uses `MyType` (e.g., with a function
    /// like `A1_json()`).
    ///
    /// In all of these cases, `MyType` is declared as a common type in the
    /// empty namespace.
    fn b2_json() -> serde_json::Value {
        json!({
            "": {
                "commonTypes": {
                    "MyType": { "type": "String" }
                },
                "entityTypes": {},
                "actions": {}
            },
            "NS1": {
                "entityTypes": {
                    "User": { "memberOfTypes": [] },
                    "Resource": { "memberOfTypes": [] },
                },
                "actions": {}
            }
        })
    }

    /// Makes a schema for all the XXc test cases, where different XX plug in
    /// different `mytype_use` (schema constructs that use `MyType`).
    ///
    /// In all of these cases, `MyType` is not declared in any namespace.
    fn c_human(mytype_use: &str) -> String {
        format!(
            r#"
        namespace NS1 {{
            entity User, Resource;
            {mytype_use}
        }}
        "#
        )
    }

    /// Makes a schema for all the XXc test cases, where different XX plug in a
    /// different schema construct that uses `MyType` (e.g., with a function
    /// like `A1_json()`).
    ///
    /// In all of these cases, `MyType` is not declared in any namespace.
    fn c_json() -> serde_json::Value {
        json!({
            "NS1": {
                "entityTypes": {
                    "User": { "memberOfTypes": [] },
                    "Resource": { "memberOfTypes": [] },
                },
                "actions": {}
            }
        })
    }

    /// Makes a schema for all the XXd1 test cases, where different XX plug in
    /// different `mytype_use` (schema constructs that use `MyType`).
    ///
    /// In all of these cases, `MyType` is declared as an entity type in an
    /// unrelated namespace (NS2).
    fn d1_human(mytype_use: &str) -> String {
        format!(
            r#"
        namespace NS2 {{
            entity MyType;
        }}
        namespace NS1 {{
            entity User, Resource;
            {mytype_use}
        }}
        "#
        )
    }

    /// Makes a schema for all the XXd1 test cases, where different XX plug in a
    /// different schema construct that uses `MyType` (e.g., with a function
    /// like `A1_json()`).
    ///
    /// In all of these cases, `MyType` is declared as an entity type in an
    /// unrelated namespace (NS2).
    fn d1_json() -> serde_json::Value {
        json!({
            "NS2": {
                "entityTypes": {
                    "MyType": { "memberOfTypes": [] },
                },
                "actions": {}
            },
            "NS1": {
                "entityTypes": {
                    "User": { "memberOfTypes": [] },
                    "Resource": { "memberOfTypes": [] },
                },
                "actions": {}
            }
        })
    }

    /// Makes a schema for all the XXd2 test cases, where different XX plug in
    /// different `mytype_use` (schema constructs that use `MyType`).
    ///
    /// In all of these cases, `MyType` is declared as a common type in an
    /// unrelated namespace (NS2).
    fn d2_human(mytype_use: &str) -> String {
        format!(
            r#"
        namespace NS2 {{
            type MyType = String;
        }}
        namespace NS1 {{
            entity User, Resource;
            {mytype_use}
        }}
        "#
        )
    }

    /// Makes a schema for all the XXd2 test cases, where different XX plug in a
    /// different schema construct that uses `MyType` (e.g., with a function
    /// like `A1_json()`).
    ///
    /// In all of these cases, `MyType` is declared as a common type in an
    /// unrelated namespace (NS2).
    fn d2_json() -> serde_json::Value {
        json!({
            "NS2": {
                "commonTypes": {
                    "MyType": { "type": "String" },
                },
                "entityTypes": {},
                "actions": {}
            },
            "NS1": {
                "entityTypes": {
                    "User": { "memberOfTypes": [] },
                    "Resource": { "memberOfTypes": [] },
                },
                "actions": {}
            }
        })
    }

    /// Generate human-schema syntax for a `MyType` use of kind A1.
    fn A1_human() -> &'static str {
        r#"action Read appliesTo { principal: [User], resource: [Resource], context: { foo: MyType }};"#
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind A1X1 (for any X), returning the new schema.
    fn A1X1_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["actions"]["Read"] = json!({
            "appliesTo": {
                "principalTypes": ["User"],
                "resourceTypes": ["Resource"],
                "context": {
                    "type": "Record",
                    "attributes": {
                        "foo": { "type": "Entity", "name": "MyType" }
                    }
                }
            }
        });
        schema
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind A1X2 (for any X), returning the new schema.
    fn A1X2_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["actions"]["Read"] = json!({
            "appliesTo": {
                "principalTypes": ["User"],
                "resourceTypes": ["Resource"],
                "context": {
                    "type": "Record",
                    "attributes": {
                        "foo": { "type": "MyType" }
                    }
                }
            }
        });
        schema
    }

    /// Generate human-schema syntax for a `MyType` use of kind A2.
    fn A2_human() -> &'static str {
        r#"action Read appliesTo { principal: [User], resource: [Resource], context: { foo: NS1::MyType }};"#
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind A2X1 (for any X), returning the new schema.
    fn A2X1_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["actions"]["Read"] = json!({
            "appliesTo": {
                "principalTypes": ["User"],
                "resourceTypes": ["Resource"],
                "context": {
                    "type": "Record",
                    "attributes": {
                        "foo": { "type": "Entity", "name": "NS1::MyType" }
                    }
                }
            }
        });
        schema
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind A2X2 (for any X), returning the new schema.
    fn A2X2_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["actions"]["Read"] = json!({
            "appliesTo": {
                "principalTypes": ["User"],
                "resourceTypes": ["Resource"],
                "context": {
                    "type": "Record",
                    "attributes": {
                        "foo": { "type": "NS1::MyType" }
                    }
                }
            }
        });
        schema
    }

    /// Generate human-schema syntax for a `MyType` use of kind A3.
    fn A3_human() -> &'static str {
        r#"action Read appliesTo { principal: [User], resource: [Resource], context: { foo: NS2::MyType }};"#
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind A3X1 (for any X), returning the new schema.
    fn A3X1_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["actions"]["Read"] = json!({
            "appliesTo": {
                "principalTypes": ["User"],
                "resourceTypes": ["Resource"],
                "context": {
                    "type": "Record",
                    "attributes": {
                        "foo": { "type": "Entity", "name": "NS2::MyType" }
                    }
                }
            }
        });
        schema
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind A3X2 (for any X), returning the new schema.
    fn A3X2_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["actions"]["Read"] = json!({
            "appliesTo": {
                "principalTypes": ["User"],
                "resourceTypes": ["Resource"],
                "context": {
                    "type": "Record",
                    "attributes": {
                        "foo": { "type": "NS2::MyType" }
                    }
                }
            }
        });
        schema
    }

    /// Generate human-schema syntax for a `MyType` use of kind B1.
    fn B1_human() -> &'static str {
        r#"entity E { foo: MyType };"#
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind B1X1 (for any X), returning the new schema.
    fn B1X1_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["entityTypes"]["E"] = json!({
            "memberOfTypes": [],
            "shape": {
                "type": "Record",
                "attributes": {
                    "foo": { "type": "Entity", "name": "MyType" }
                }
            }
        });
        schema
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind B1X2 (for any X), returning the new schema.
    fn B1X2_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["entityTypes"]["E"] = json!({
            "memberOfTypes": [],
            "shape": {
                "type": "Record",
                "attributes": {
                    "foo": { "type": "MyType" }
                }
            }
        });
        schema
    }

    /// Generate human-schema syntax for a `MyType` use of kind B2.
    fn B2_human() -> &'static str {
        r#"entity E { foo: NS1::MyType };"#
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind B2X1 (for any X), returning the new schema.
    fn B2X1_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["entityTypes"]["E"] = json!({
            "memberOfTypes": [],
            "shape": {
                "type": "Record",
                "attributes": {
                    "foo": { "type": "Entity", "name": "NS1::MyType" }
                }
            }
        });
        schema
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind B2X2 (for any X), returning the new schema.
    fn B2X2_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["entityTypes"]["E"] = json!({
            "memberOfTypes": [],
            "shape": {
                "type": "Record",
                "attributes": {
                    "foo": { "type": "NS1::MyType" }
                }
            }
        });
        schema
    }

    /// Generate human-schema syntax for a `MyType` use of kind B3.
    fn B3_human() -> &'static str {
        r#"entity E { foo: NS2::MyType };"#
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind B3X1 (for any X), returning the new schema.
    fn B3X1_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["entityTypes"]["E"] = json!({
            "memberOfTypes": [],
            "shape": {
                "type": "Record",
                "attributes": {
                    "foo": { "type": "Entity", "name": "NS2::MyType" }
                }
            }
        });
        schema
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind B3X2 (for any X), returning the new schema.
    fn B3X2_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["entityTypes"]["E"] = json!({
            "memberOfTypes": [],
            "shape": {
                "type": "Record",
                "attributes": {
                    "foo": { "type": "NS2::MyType" }
                }
            }
        });
        schema
    }

    /// Generate human-schema syntax for a `MyType` use of kind C1.
    fn C1_human() -> &'static str {
        r#"type E = { foo: MyType };"#
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind C1X1 (for any X), returning the new schema.
    fn C1X1_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["commonTypes"]["E"] = json!({
            "type": "Record",
            "attributes": {
                "foo": { "type": "Entity", "name": "MyType" }
                }
        });
        schema
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind C1X2 (for any X), returning the new schema.
    fn C1X2_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["commonTypes"]["E"] = json!({
            "type": "Record",
            "attributes": {
                "foo": { "type": "MyType" }
            }
        });
        schema
    }

    /// Generate human-schema syntax for a `MyType` use of kind C2.
    fn C2_human() -> &'static str {
        r#"type E = { foo: NS1::MyType };"#
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind C2X1 (for any X), returning the new schema.
    fn C2X1_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["commonTypes"]["E"] = json!({
            "type": "Record",
            "attributes": {
                "foo": { "type": "Entity", "name": "NS1::MyType" }
                }
        });
        schema
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind C2X2 (for any X), returning the new schema.
    fn C2X2_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["commonTypes"]["E"] = json!({
            "type": "Record",
            "attributes": {
                "foo": { "type": "NS1::MyType" }
            }
        });
        schema
    }

    /// Generate human-schema syntax for a `MyType` use of kind C3.
    fn C3_human() -> &'static str {
        r#"type E = { foo: NS2::MyType };"#
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind C3X1 (for any X), returning the new schema.
    fn C3X1_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["commonTypes"]["E"] = json!({
            "type": "Record",
            "attributes": {
                "foo": { "type": "Entity", "name": "NS2::MyType" }
                }
        });
        schema
    }

    /// Given a starting JSON schema (e.g., from `a1_json()`),
    /// add a `MyType` use of kind C3X2 (for any X), returning the new schema.
    fn C3X2_json(mut schema: serde_json::Value) -> serde_json::Value {
        schema["NS1"]["commonTypes"]["E"] = json!({
            "type": "Record",
            "attributes": {
                "foo": { "type": "NS2::MyType" }
            }
        });
        schema
    }

    // ####
    //
    // For explanations of all of the below tests and their naming, see comments
    // on this module.
    //
    // ####

    // human versions
    #[test]
    fn A1a1_human() {
        assert_parses_successfully_human(&a1_human(A1_human()));
    }
    #[test]
    fn A1a2_human() {
        assert_parses_successfully_human(&a2_human(A1_human()));
    }
    #[test]
    fn A1b1_human() {
        assert_parses_successfully_human(&b1_human(A1_human()));
    }
    #[test]
    fn A1b2_human() {
        assert_parses_successfully_human(&b2_human(A1_human()));
    }
    #[test]
    fn A1c_human() {
        assert_parse_error_human(
            &c_human(A1_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
                .help(
                    "neither `NS1::MyType` nor `MyType` refers to anything that has been declared",
                )
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("MyType")
                .build(),
        );
    }
    #[test]
    fn A2a1_human() {
        assert_parses_successfully_human(&a1_human(A2_human()));
    }
    #[test]
    fn A2a2_human() {
        assert_parses_successfully_human(&a2_human(A2_human()));
    }
    #[test]
    fn A2b1_human() {
        assert_parse_error_human(
            &b1_human(A2_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS1::MyType")
                .build(),
        );
    }
    #[test]
    fn A2b2_human() {
        assert_parse_error_human(
            &b2_human(A2_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS1::MyType")
                .build(),
        );
    }
    #[test]
    fn A2c_human() {
        assert_parse_error_human(
            &c_human(A2_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS1::MyType")
                .build(),
        );
    }
    #[test]
    fn A3a1_human() {
        assert_parse_error_human(
            &a1_human(A3_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS2::MyType")
                .build(),
        );
    }
    #[test]
    fn A3a2_human() {
        assert_parse_error_human(
            &a2_human(A3_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS2::MyType")
                .build(),
        );
    }
    #[test]
    fn A3b1_human() {
        assert_parse_error_human(
            &b1_human(A3_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS2::MyType")
                .build(),
        );
    }
    #[test]
    fn A3b2_human() {
        assert_parse_error_human(
            &b2_human(A3_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS2::MyType")
                .build(),
        );
    }
    #[test]
    fn A3c_human() {
        assert_parse_error_human(
            &c_human(A3_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS1::MyType")
                .build(),
        );
    }
    #[test]
    fn A3d1_human() {
        assert_parses_successfully_human(&d1_human(A3_human()));
    }
    #[test]
    fn A3d2_human() {
        assert_parses_successfully_human(&d2_human(A3_human()));
    }
    #[test]
    fn B1a1_human() {
        assert_parses_successfully_human(&a1_human(B1_human()));
    }
    #[test]
    fn B1a2_human() {
        assert_parses_successfully_human(&a2_human(B1_human()));
    }
    #[test]
    fn B1b1_human() {
        assert_parses_successfully_human(&b1_human(B1_human()));
    }
    #[test]
    fn B1b2_human() {
        assert_parses_successfully_human(&b2_human(B1_human()));
    }
    #[test]
    fn B1c_human() {
        assert_parse_error_human(
            &c_human(B1_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
                .help(
                    "neither `NS1::MyType` nor `MyType` refers to anything that has been declared",
                )
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("MyType")
                .build(),
        );
    }
    #[test]
    fn B2a1_human() {
        assert_parses_successfully_human(&a1_human(B2_human()));
    }
    #[test]
    fn B2a2_human() {
        assert_parses_successfully_human(&a2_human(B2_human()));
    }
    #[test]
    fn B2b1_human() {
        assert_parse_error_human(
            &b1_human(B2_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS1::MyType")
                .build(),
        );
    }
    #[test]
    fn B2b2_human() {
        assert_parse_error_human(
            &b2_human(B2_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS1::MyType")
                .build(),
        );
    }
    #[test]
    fn B2c_human() {
        assert_parse_error_human(
            &c_human(B2_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS1::MyType")
                .build(),
        );
    }
    #[test]
    fn B3a1_human() {
        assert_parse_error_human(
            &a1_human(B3_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS2::MyType")
                .build(),
        );
    }
    #[test]
    fn B3a2_human() {
        assert_parse_error_human(
            &a2_human(B3_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS2::MyType")
                .build(),
        );
    }
    #[test]
    fn B3b1_human() {
        assert_parse_error_human(
            &b1_human(B3_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS2::MyType")
                .build(),
        );
    }
    #[test]
    fn B3b2_human() {
        assert_parse_error_human(
            &b2_human(B3_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS2::MyType")
                .build(),
        );
    }
    #[test]
    fn B3c_human() {
        assert_parse_error_human(
            &c_human(B3_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS1::MyType")
                .build(),
        );
    }
    #[test]
    fn B3d1_human() {
        assert_parses_successfully_human(&d1_human(B3_human()));
    }
    #[test]
    fn B3d2_human() {
        assert_parses_successfully_human(&d2_human(B3_human()));
    }
    #[test]
    fn C1a1_human() {
        assert_parses_successfully_human(&a1_human(C1_human()));
    }
    #[test]
    fn C1a2_human() {
        assert_parses_successfully_human(&a2_human(C1_human()));
    }
    #[test]
    fn C1b1_human() {
        assert_parses_successfully_human(&b1_human(C1_human()));
    }
    #[test]
    fn C1b2_human() {
        assert_parses_successfully_human(&b2_human(C1_human()));
    }
    #[test]
    fn C1c_human() {
        assert_parse_error_human(
            &c_human(C1_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
                .help(
                    "neither `NS1::MyType` nor `MyType` refers to anything that has been declared",
                )
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("MyType")
                .build(),
        );
    }
    #[test]
    fn C2a1_human() {
        assert_parses_successfully_human(&a1_human(C2_human()));
    }
    #[test]
    fn C2a2_human() {
        assert_parses_successfully_human(&a2_human(C2_human()));
    }
    #[test]
    fn C2b1_human() {
        assert_parse_error_human(
            &b1_human(C2_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS1::MyType")
                .build(),
        );
    }
    #[test]
    fn C2b2_human() {
        assert_parse_error_human(
            &b2_human(C2_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS1::MyType")
                .build(),
        );
    }
    #[test]
    fn C2c_human() {
        assert_parse_error_human(
            &c_human(C2_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS1::MyType")
                .build(),
        );
    }
    #[test]
    fn C3a1_human() {
        assert_parse_error_human(
            &a1_human(C3_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS2::MyType")
                .build(),
        );
    }
    #[test]
    fn C3a2_human() {
        assert_parse_error_human(
            &a2_human(C3_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS2::MyType")
                .build(),
        );
    }
    #[test]
    fn C3b1_human() {
        assert_parse_error_human(
            &b1_human(C3_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS2::MyType")
                .build(),
        );
    }
    #[test]
    fn C3b2_human() {
        assert_parse_error_human(
            &b2_human(C3_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS2::MyType")
                .build(),
        );
    }
    #[test]
    fn C3c_human() {
        assert_parse_error_human(
            &c_human(C3_human()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
                //.exactly_one_underline("NS1::MyType")
                .build(),
        );
    }
    #[test]
    fn C3d1_human() {
        assert_parses_successfully_human(&d1_human(C3_human()));
    }
    #[test]
    fn C3d2_human() {
        assert_parses_successfully_human(&d2_human(C3_human()));
    }

    // json versions
    #[test]
    fn A1a1_json() {
        assert_parses_successfully_json(A1X1_json(a1_json()));
    }
    #[test]
    fn A1a2_json() {
        assert_parses_successfully_json(A1X2_json(a2_json()));
    }
    #[test]
    fn A1b1_json() {
        assert_parses_successfully_json(A1X1_json(b1_json()));
    }
    #[test]
    fn A1b2_json() {
        assert_parses_successfully_json(A1X2_json(b2_json()));
    }
    #[test]
    fn A1c_json() {
        assert_parse_error_json(
            A1X1_json(c_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
                .help(
                    "neither `NS1::MyType` nor `MyType` refers to anything that has been declared",
                )
                .build(),
        );
    }
    #[test]
    fn A2a1_json() {
        assert_parses_successfully_json(A2X1_json(a1_json()));
    }
    #[test]
    fn A2a2_json() {
        assert_parses_successfully_json(A2X2_json(a2_json()));
    }
    #[test]
    fn A2b1_json() {
        assert_parse_error_json(
            A2X1_json(b1_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn A2b2_json() {
        assert_parse_error_json(
            A2X2_json(b2_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn A2c_json() {
        assert_parse_error_json(
            A2X1_json(c_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn A3a1_json() {
        assert_parse_error_json(
            A3X1_json(a1_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn A3a2_json() {
        assert_parse_error_json(
            A3X2_json(a2_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn A3b1_json() {
        assert_parse_error_json(
            A3X1_json(b1_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn A3b2_json() {
        assert_parse_error_json(
            A3X2_json(b2_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn A3c_json() {
        assert_parse_error_json(
            A3X1_json(c_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn A3d1_json() {
        assert_parses_successfully_json(A3X1_json(d1_json()));
    }
    #[test]
    fn A3d2_json() {
        assert_parses_successfully_json(A3X2_json(d2_json()));
    }
    #[test]
    fn B1a1_json() {
        assert_parses_successfully_json(B1X1_json(a1_json()));
    }
    #[test]
    fn B1a2_json() {
        assert_parses_successfully_json(B1X2_json(a2_json()));
    }
    #[test]
    fn B1b1_json() {
        assert_parses_successfully_json(B1X1_json(b1_json()));
    }
    #[test]
    fn B1b2_json() {
        assert_parses_successfully_json(B1X2_json(b2_json()));
    }
    #[test]
    fn B1c_json() {
        assert_parse_error_json(
            B1X1_json(c_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
                .help(
                    "neither `NS1::MyType` nor `MyType` refers to anything that has been declared",
                )
                .build(),
        );
    }
    #[test]
    fn B2a1_json() {
        assert_parses_successfully_json(B2X1_json(a1_json()));
    }
    #[test]
    fn B2a2_json() {
        assert_parses_successfully_json(B2X2_json(a2_json()));
    }
    #[test]
    fn B2b1_json() {
        assert_parse_error_json(
            B2X1_json(b1_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn B2b2_json() {
        assert_parse_error_json(
            B2X2_json(b2_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn B2c_json() {
        assert_parse_error_json(
            B2X1_json(c_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn B3a1_json() {
        assert_parse_error_json(
            B3X1_json(a1_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn B3a2_json() {
        assert_parse_error_json(
            B3X2_json(a2_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn B3b1_json() {
        assert_parse_error_json(
            B3X1_json(b1_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn B3b2_json() {
        assert_parse_error_json(
            B3X2_json(b2_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn B3c_json() {
        assert_parse_error_json(
            B3X1_json(c_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn B3d1_json() {
        assert_parses_successfully_json(B3X1_json(d1_json()));
    }
    #[test]
    fn B3d2_json() {
        assert_parses_successfully_json(B3X2_json(d2_json()));
    }
    #[test]
    fn C1a1_json() {
        assert_parses_successfully_json(C1X1_json(a1_json()));
    }
    #[test]
    fn C1a2_json() {
        assert_parses_successfully_json(C1X2_json(a2_json()));
    }
    #[test]
    fn C1b1_json() {
        assert_parses_successfully_json(C1X1_json(b1_json()));
    }
    #[test]
    fn C1b2_json() {
        assert_parses_successfully_json(C1X2_json(b2_json()));
    }
    #[test]
    fn C1c_json() {
        assert_parse_error_json(
            C1X1_json(c_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
                .help(
                    "neither `NS1::MyType` nor `MyType` refers to anything that has been declared",
                )
                .build(),
        );
    }
    #[test]
    fn C2a1_json() {
        assert_parses_successfully_json(C2X1_json(a1_json()));
    }
    #[test]
    fn C2a2_json() {
        assert_parses_successfully_json(C2X2_json(a2_json()));
    }
    #[test]
    fn C2b1_json() {
        assert_parse_error_json(
            C2X1_json(b1_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn C2b2_json() {
        assert_parse_error_json(
            C2X2_json(b2_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn C2c_json() {
        assert_parse_error_json(
            C2X1_json(c_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
                .help("`NS1::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn C3a1_json() {
        assert_parse_error_json(
            C3X1_json(a1_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn C3a2_json() {
        assert_parse_error_json(
            C3X2_json(a2_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn C3b1_json() {
        assert_parse_error_json(
            C3X1_json(b1_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn C3b2_json() {
        assert_parse_error_json(
            C3X2_json(b2_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn C3c_json() {
        assert_parse_error_json(
            C3X1_json(c_json()),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
                .help("`NS2::MyType` has not been declared")
                .build(),
        );
    }
    #[test]
    fn C3d1_json() {
        assert_parses_successfully_json(C3X1_json(d1_json()));
    }
    #[test]
    fn C3d2_json() {
        assert_parses_successfully_json(C3X2_json(d2_json()));
    }
}

#[cfg(test)]
mod test_resolver {
    use std::collections::HashMap;

    use cedar_policy_core::{ast::Name, extensions::Extensions};
    use cool_asserts::assert_matches;

    use super::CommonTypeResolver;
    use crate::{
        err::SchemaError, types::Type, ConditionalName, RawName, SchemaFragment,
        ValidatorSchemaFragment,
    };

    fn resolve(schema_json: serde_json::Value) -> Result<HashMap<Name, Type>, SchemaError> {
        let sfrag: SchemaFragment<RawName> = serde_json::from_value(schema_json).unwrap();
        let schema: ValidatorSchemaFragment<ConditionalName> = sfrag.try_into().unwrap();
        let all_common_defs = schema
            .0
            .iter()
            .flat_map(|nsdef| nsdef.all_declared_common_type_names().cloned())
            .collect();
        let all_entity_defs = schema
            .0
            .iter()
            .flat_map(|nsdef| nsdef.all_declared_entity_type_names().cloned())
            .collect();
        let schema = schema
            .fully_qualify_type_references(&all_common_defs, &all_entity_defs)
            .unwrap();
        let mut type_defs = HashMap::new();
        for def in schema.0 {
            type_defs.extend(def.type_defs.type_defs.into_iter());
        }
        let resolver = CommonTypeResolver::new(&type_defs);
        resolver
            .resolve(Extensions::all_available())
            .map(|map| map.into_iter().map(|(k, v)| (k.clone(), v)).collect())
    }

    #[test]
    fn test_simple() {
        let schema = serde_json::json!(
            {
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "b"
                        },
                        "b": {
                            "type": "Boolean"
                        }
                    }
                }
            }
        );
        let res = resolve(schema).unwrap();
        assert_eq!(
            res,
            HashMap::from_iter([
                ("a".parse().unwrap(), Type::primitive_boolean()),
                ("b".parse().unwrap(), Type::primitive_boolean())
            ])
        );

        let schema = serde_json::json!(
            {
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "b"
                        },
                        "b": {
                            "type": "c"
                        },
                        "c": {
                            "type": "Boolean"
                        }
                    }
                }
            }
        );
        let res = resolve(schema).unwrap();
        assert_eq!(
            res,
            HashMap::from_iter([
                ("a".parse().unwrap(), Type::primitive_boolean()),
                ("b".parse().unwrap(), Type::primitive_boolean()),
                ("c".parse().unwrap(), Type::primitive_boolean())
            ])
        );
    }

    #[test]
    fn test_set() {
        let schema = serde_json::json!(
            {
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "Set",
                            "element": {
                                "type": "b"
                            }
                        },
                        "b": {
                            "type": "Boolean"
                        }
                    }
                }
            }
        );
        let res = resolve(schema).unwrap();
        assert_eq!(
            res,
            HashMap::from_iter([
                ("a".parse().unwrap(), Type::set(Type::primitive_boolean())),
                ("b".parse().unwrap(), Type::primitive_boolean())
            ])
        );
    }

    #[test]
    fn test_record() {
        let schema = serde_json::json!(
            {
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "Record",
                            "attributes": {
                                "foo": {
                                    "type": "b"
                                }
                            }
                        },
                        "b": {
                            "type": "Boolean"
                        }
                    }
                }
            }
        );
        let res = resolve(schema).unwrap();
        assert_eq!(
            res,
            HashMap::from_iter([
                (
                    "a".parse().unwrap(),
                    Type::record_with_required_attributes(
                        std::iter::once(("foo".into(), Type::primitive_boolean())),
                        crate::types::OpenTag::ClosedAttributes
                    )
                ),
                ("b".parse().unwrap(), Type::primitive_boolean())
            ])
        );
    }

    #[test]
    fn test_names() {
        let schema = serde_json::json!(
            {
                "A": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "B::a"
                        }
                    }
                },
                "B": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "Boolean"
                        }
                    }
                }
            }
        );
        let res = resolve(schema).unwrap();
        assert_eq!(
            res,
            HashMap::from_iter([
                ("A::a".parse().unwrap(), Type::primitive_boolean()),
                ("B::a".parse().unwrap(), Type::primitive_boolean())
            ])
        );
    }

    #[test]
    fn test_cycles() {
        // self reference
        let schema = serde_json::json!(
            {
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "a"
                        }
                    }
                }
            }
        );
        let res = resolve(schema);
        assert_matches!(res, Err(SchemaError::CycleInCommonTypeReferences(_)));

        // 2 node loop
        let schema = serde_json::json!(
            {
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "b"
                        },
                        "b" : {
                            "type": "a"
                        }
                    }
                }
            }
        );
        let res = resolve(schema);
        assert_matches!(res, Err(SchemaError::CycleInCommonTypeReferences(_)));

        // 3 node loop
        let schema = serde_json::json!(
            {
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "b"
                        },
                        "b" : {
                            "type": "c"
                        },
                        "c" : {
                            "type": "a"
                        }
                    }
                }
            }
        );
        let res = resolve(schema);
        assert_matches!(res, Err(SchemaError::CycleInCommonTypeReferences(_)));

        // cross-namespace 2 node loop
        let schema = serde_json::json!(
            {
                "A": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "B::a"
                        }
                    }
                },
                "B": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "A::a"
                        }
                    }
                }
            }
        );
        let res = resolve(schema);
        assert_matches!(res, Err(SchemaError::CycleInCommonTypeReferences(_)));

        // cross-namespace 3 node loop
        let schema = serde_json::json!(
            {
                "A": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "B::a"
                        }
                    }
                },
                "B": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "C::a"
                        }
                    }
                },
                "C": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "A::a"
                        }
                    }
                }
            }
        );
        let res = resolve(schema);
        assert_matches!(res, Err(SchemaError::CycleInCommonTypeReferences(_)));

        // cross-namespace 3 node loop
        let schema = serde_json::json!(
            {
                "A": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "B::a"
                        }
                    }
                },
                "B": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "c"
                        },
                        "c": {
                            "type": "A::a"
                        }
                    }
                }
            }
        );
        let res = resolve(schema);
        assert_matches!(res, Err(SchemaError::CycleInCommonTypeReferences(_)));
    }
}
