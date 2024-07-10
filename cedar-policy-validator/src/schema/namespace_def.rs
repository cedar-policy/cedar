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

//! This module contains the definition of `ValidatorNamespaceDef` and of types
//! it relies on

use std::collections::{hash_map::Entry, BTreeMap, HashMap, HashSet};

use cedar_policy_core::{
    ast::{
        Eid, EntityAttrEvaluationError, EntityType, EntityUID, Id, Name,
        PartialValueSerializedAsExpr,
    },
    entities::{json::err::JsonDeserializationErrorContext, CedarValueJson},
    evaluator::RestrictedEvaluator,
    extensions::Extensions,
    FromNormalizedStr,
};
use itertools::Itertools;
use nonempty::NonEmpty;
use smol_str::{SmolStr, ToSmolStr};

use super::ValidatorApplySpec;
use crate::{
    err::{schema_errors::*, SchemaError},
    fuzzy_match::fuzzy_search,
    schema_file_format,
    types::{AttributeType, Attributes, OpenTag, Type},
    ActionBehavior, ActionEntityUID, ActionType, ConditionalName, NamespaceDefinition, RawName,
    ReferenceType, SchemaType, SchemaTypeVariant, TypeOfAttribute,
};

/// A single namespace definition from the schema json or human syntax,
/// processed into a form which is closer to that used by the validator.
/// The processing includes detection of some errors, for example, parse errors
/// in entity/common type names or entity/common types which are declared
/// multiple times.
///
/// In this representation, there may still be references to undeclared
/// entity/common types, because any entity/common type may be declared in a
/// different fragment that will only be known about when building the complete
/// [`crate::ValidatorSchema`].
///
/// The parameter `N` is the type of entity type names and common type names in
/// attributes/parents fields in this [`ValidatorNamespaceDef`], including
/// recursively. (It doesn't affect the type of common and entity type names
/// _that are being declared here_, which are already fully-qualified in this
/// representation.)
/// For example:
/// - `N` = [`ConditionalName`]: References to entity/common types are not
///     yet fully qualified/disambiguated
/// - `N` = [`Name`]: All names have been resolved into fully-qualified
///     [`Name`]s
#[derive(Debug)]
pub struct ValidatorNamespaceDef<N> {
    /// The (fully-qualified) name of the namespace this is a definition of, or
    /// `None` if this is a definition for the empty namespace.
    ///
    /// This is informational only; it does not change the semantics of any
    /// definition in `type_defs`, `entity_types`, or `actions`. All
    /// entity/common type names in `type_defs`, `entity_types`, and `actions`
    /// are already either fully qualified/disambiguated, or stored in
    /// [`ConditionalName`] format which does not require referencing the
    /// implicit `namespace` directly any longer.
    /// This `namespace` field is used only in tests and by the `cedar_policy`
    /// function `SchemaFragment::namespaces()`.
    namespace: Option<Name>,
    /// Common type definitions, which can be used to define entity
    /// type attributes, action contexts, and other common types.
    pub(super) type_defs: TypeDefs<N>,
    /// Entity type declarations.
    pub(super) entity_types: EntityTypesDef<N>,
    /// Action declarations.
    pub(super) actions: ActionsDef<N>,
}

impl<N> ValidatorNamespaceDef<N> {
    /// Get the fully-qualified [`Name`]s of all entity types declared in this
    /// [`ValidatorNamespaceDef`].
    pub fn all_declared_entity_type_names(&self) -> impl Iterator<Item = &Name> {
        self.entity_types
            .entity_types
            .keys()
            .map(|ety| ety.as_ref())
    }

    /// Get the fully-qualified [`Name`]s of all common types declared in this
    /// [`ValidatorNamespaceDef`].
    pub fn all_declared_common_type_names(&self) -> impl Iterator<Item = &Name> {
        self.type_defs.type_defs.keys()
    }

    /// The fully-qualified [`Name`] of the namespace this is a definition of.
    /// `None` indicates this definition is for the empty namespace.
    pub fn namespace(&self) -> Option<&Name> {
        self.namespace.as_ref()
    }
}

impl ValidatorNamespaceDef<ConditionalName> {
    /// Construct a new [`ValidatorNamespaceDef<ConditionalName>`] from the raw [`NamespaceDefinition`]
    pub fn from_namespace_definition(
        namespace: Option<Name>,
        namespace_def: NamespaceDefinition<RawName>,
        action_behavior: ActionBehavior,
        extensions: Extensions<'_>,
    ) -> crate::err::Result<ValidatorNamespaceDef<ConditionalName>> {
        // Return early with an error if actions cannot be in groups or have
        // attributes, but the schema contains action groups or attributes.
        Self::check_action_behavior(&namespace_def, action_behavior)?;

        // Convert the type defs, actions and entity types from the schema file
        // into the representation used by the validator.
        let type_defs =
            TypeDefs::from_raw_typedefs(namespace_def.common_types, namespace.as_ref())?;
        let actions =
            ActionsDef::from_raw_actions(namespace_def.actions, namespace.as_ref(), extensions)?;
        let entity_types =
            EntityTypesDef::from_raw_entity_types(namespace_def.entity_types, namespace.as_ref())?;

        Ok(ValidatorNamespaceDef {
            namespace,
            type_defs,
            entity_types,
            actions,
        })
    }

    /// Convert this [`ValidatorNamespaceDef<ConditionalName>`] into a
    /// [`ValidatorNamespaceDef<Name>`] by fully-qualifying all typenames that
    /// appear anywhere in any definitions.
    ///
    /// `all_common_defs` and `all_entity_defs` need to be the full set of all
    /// fully-qualified typenames (of common and entity types respectively) that
    /// are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_common_defs: &HashSet<Name>,
        all_entity_defs: &HashSet<Name>,
    ) -> Result<ValidatorNamespaceDef<Name>, TypeResolutionError> {
        match (
            self.type_defs
                .fully_qualify_type_references(all_common_defs, all_entity_defs),
            self.entity_types
                .fully_qualify_type_references(all_common_defs, all_entity_defs),
            self.actions
                .fully_qualify_type_references(all_common_defs, all_entity_defs),
        ) {
            (Ok(type_defs), Ok(entity_types), Ok(actions)) => Ok(ValidatorNamespaceDef {
                namespace: self.namespace,
                type_defs,
                entity_types,
                actions,
            }),
            // PANIC SAFETY: at least one of the results is `Err`, so the input
            // to `TypeResolutionError::join()` is nonempty, so it returns Some,
            // as documented there
            #[allow(clippy::expect_used)]
            (res1, res2, res3) => Err(TypeResolutionError::join(
                res1.err()
                    .into_iter()
                    .chain(res2.err().into_iter())
                    .chain(res3.err().into_iter()),
            )
            .expect("at least one of these results was Err, so join() must return Some")),
        }
    }

    /// Check that `schema_nsdef` uses actions in a way consistent with the
    /// specified `action_behavior`. When the behavior specifies that actions
    /// should not be used in groups and should not have attributes, then this
    /// function will return `Err` if it sees any action groups or attributes
    /// declared in the schema.
    fn check_action_behavior<N>(
        schema_nsdef: &NamespaceDefinition<N>,
        action_behavior: ActionBehavior,
    ) -> crate::err::Result<()> {
        if schema_nsdef
            .entity_types
            .iter()
            // The `name` in an entity type declaration cannot be qualified
            // with a namespace (it always implicitly takes the schema
            // namespace), so we do this comparison directly.
            .any(|(name, _)| name.to_smolstr() == cedar_policy_core::ast::ACTION_ENTITY_TYPE)
        {
            return Err(ActionEntityTypeDeclaredError {}.into());
        }
        if action_behavior == ActionBehavior::ProhibitAttributes {
            let mut actions_with_attributes: Vec<String> = Vec::new();
            for (name, a) in &schema_nsdef.actions {
                if a.attributes.is_some() {
                    actions_with_attributes.push(name.to_string());
                }
            }
            if !actions_with_attributes.is_empty() {
                actions_with_attributes.sort(); // TODO(#833): sort required for deterministic error messages
                return Err(
                    UnsupportedFeatureError(UnsupportedFeature::ActionAttributes(
                        actions_with_attributes,
                    ))
                    .into(),
                );
            }
        }

        Ok(())
    }
}

/// Holds a map from (fully qualified) [`Name`]s of common type definitions to
/// their corresponding [`SchemaType`]. The common type [`Name`]s (keys in the
/// map) are fully qualified, but inside the [`SchemaType`]s (values in the
/// map), entity/common type references may or may not be fully qualified yet,
/// depending on `N`; see notes on [`SchemaType`].
#[derive(Debug)]
pub struct TypeDefs<N> {
    pub(super) type_defs: HashMap<Name, SchemaType<N>>,
}

impl TypeDefs<ConditionalName> {
    /// Construct a [`TypeDefs<ConditionalName>`] by converting the structures used by the schema
    /// format to those used internally by the validator.
    pub(crate) fn from_raw_typedefs(
        schema_file_type_def: HashMap<Id, SchemaType<RawName>>,
        schema_namespace: Option<&Name>,
    ) -> crate::err::Result<Self> {
        let mut type_defs = HashMap::with_capacity(schema_file_type_def.len());
        for (id, schema_ty) in schema_file_type_def {
            let name = RawName::new(id).qualify_with(schema_namespace); // the declaration name is always (unconditionally) prefixed by the current/active namespace
            match type_defs.entry(name) {
                Entry::Vacant(ventry) => {
                    ventry
                        .insert(schema_ty.conditionally_qualify_type_references(schema_namespace));
                }
                Entry::Occupied(oentry) => {
                    return Err(SchemaError::DuplicateCommonType(DuplicateCommonTypeError(
                        oentry.key().clone(),
                    )));
                }
            }
        }
        Ok(Self { type_defs })
    }

    /// Convert this [`TypeDefs<ConditionalName>`] into a [`TypeDefs<Name>`] by
    /// fully-qualifying all typenames that appear anywhere in any definitions.
    ///
    /// `all_common_defs` and `all_entity_defs` need to be the full set of all
    /// fully-qualified typenames (of common and entity types respectively) that
    /// are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_common_defs: &HashSet<Name>,
        all_entity_defs: &HashSet<Name>,
    ) -> Result<TypeDefs<Name>, TypeResolutionError> {
        Ok(TypeDefs {
            type_defs: self
                .type_defs
                .into_iter()
                .map(|(k, v)| {
                    Ok((
                        k,
                        v.fully_qualify_type_references(all_common_defs, all_entity_defs)?,
                    ))
                })
                .collect::<Result<_, _>>()?,
        })
    }
}

/// Holds a map from (fully qualified) [`EntityType`]s (names of entity types) to
/// their corresponding [`EntityTypeFragment`]. The [`EntityType`] keys in
/// the map are fully qualified, but inside the [`EntityTypeFragment`]s (values
/// in the map), entity/common type references may or may not be fully qualified
/// yet, depending on `N`; see notes on [`EntityTypeFragment`].
///
/// Inside the [`EntityTypeFragment`]s, entity type parents and attributes may
/// reference undeclared entity/common types (that will be declared in a
/// different schema fragment).
///
/// All [`EntityType`] keys in this map are declared in this schema fragment.
#[derive(Debug)]
pub struct EntityTypesDef<N> {
    pub(super) entity_types: HashMap<EntityType, EntityTypeFragment<N>>,
}

impl EntityTypesDef<ConditionalName> {
    /// Construct a [`EntityTypesDef<ConditionalName>`] by converting the
    /// structures used by the schema format to those used internally by the
    /// validator.
    pub(crate) fn from_raw_entity_types(
        schema_files_types: HashMap<Id, schema_file_format::EntityType<RawName>>,
        schema_namespace: Option<&Name>,
    ) -> crate::err::Result<Self> {
        let mut entity_types: HashMap<EntityType, _> =
            HashMap::with_capacity(schema_files_types.len());
        for (id, entity_type) in schema_files_types {
            let ety = cedar_policy_core::ast::EntityType::from(
                RawName::new(id.clone()).qualify_with(schema_namespace), // the declaration name is always (unconditionally) prefixed by the current/active namespace
            );
            match entity_types.entry(ety) {
                Entry::Vacant(ventry) => {
                    ventry.insert(EntityTypeFragment::from_raw_entity_type(
                        entity_type,
                        schema_namespace,
                    ));
                }
                Entry::Occupied(_) => {
                    return Err(DuplicateEntityTypeError(Name::unqualified_name(id).into()).into());
                }
            }
        }
        Ok(EntityTypesDef { entity_types })
    }

    /// Convert this [`EntityTypesDef<ConditionalName>`] into a
    /// [`EntityTypesDef<Name>`] by fully-qualifying all typenames that appear
    /// anywhere in any definitions.
    ///
    /// `all_common_defs` and `all_entity_defs` need to be the full set of all
    /// fully-qualified typenames (of common and entity types respectively) that
    /// are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_common_defs: &HashSet<Name>,
        all_entity_defs: &HashSet<Name>,
    ) -> Result<EntityTypesDef<Name>, TypeResolutionError> {
        Ok(EntityTypesDef {
            entity_types: self
                .entity_types
                .into_iter()
                .map(|(k, v)| {
                    Ok((
                        k,
                        v.fully_qualify_type_references(all_common_defs, all_entity_defs)?,
                    ))
                })
                .collect::<Result<_, _>>()?,
        })
    }
}

/// Holds the attributes and parents information for an entity type definition.
///
/// In this representation, references to common types may not yet have been
/// fully resolved/inlined, and both `parents` and `attributes` may reference
/// undeclared entity/common types. Furthermore, entity/common type references
/// in `attributes` may or may not be fully qualified yet, depending on `N`.
#[derive(Debug)]
pub struct EntityTypeFragment<N> {
    /// The attributes record type for this entity type. This may contain
    /// references to common types which have not yet been resolved/inlined
    /// (e.g., because they are not defined in this schema fragment).
    pub(super) attributes: SchemaType<N>,
    /// Direct parent entity types for this entity type.
    /// These are fully qualified entity types, but may be entity types declared
    /// in a different namespace or schema fragment.
    /// We will check for undeclared parent types when combining fragments into
    /// a [`crate::ValidatorSchema`].
    pub(super) parents: HashSet<EntityType>,
}

impl EntityTypeFragment<ConditionalName> {
    /// Construct a [`EntityTypeFragment<ConditionalName>`] by converting the
    /// structures used by the schema format to those used internally by the
    /// validator.
    pub(crate) fn from_raw_entity_type(
        schema_file_type: schema_file_format::EntityType<RawName>,
        schema_namespace: Option<&Name>,
    ) -> Self {
        Self {
            attributes: schema_file_type
                .shape
                .into_inner()
                .conditionally_qualify_type_references(schema_namespace),
            parents: schema_file_type
                .member_of_types
                .into_iter()
                .map(|raw_name| raw_name.qualify_with(schema_namespace).into())
                .collect(),
        }
    }

    /// Convert this [`EntityTypeFragment<ConditionalName>`] into a
    /// [`EntityTypeFragment<Name>`] by fully-qualifying all typenames that
    /// appear anywhere in any definitions.
    ///
    /// `all_common_defs` and `all_entity_defs` need to be the full set of all
    /// fully-qualified typenames (of common and entity types respectively) that
    /// are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_common_defs: &HashSet<Name>,
        all_entity_defs: &HashSet<Name>,
    ) -> Result<EntityTypeFragment<Name>, TypeResolutionError> {
        // Fully qualify typenames appearing in `attributes`
        let fully_qual_attributes = self
            .attributes
            .fully_qualify_type_references(all_common_defs, all_entity_defs);
        // `parents` are already fully qualified, but now is the time to check
        // whether any are dangling, i.e., refer to entity types that are not
        // declared in any fragment (since we now have the set of typenames that
        // are declared in all fragments).
        let undeclared_parents: Option<NonEmpty<ConditionalName>> = NonEmpty::collect(
            self.parents
                .iter()
                .filter(|ety| !all_entity_defs.contains(ety.as_ref()))
                .map(|ety| {
                    ConditionalName::unconditional(ety.as_ref().clone(), ReferenceType::Entity)
                }),
        );
        match (fully_qual_attributes, undeclared_parents) {
            (Ok(attributes), None) => Ok(EntityTypeFragment {
                attributes,
                parents: self.parents,
            }),
            (Ok(_), Some(undeclared_parents)) => Err(TypeResolutionError(undeclared_parents)),
            (Err(e), None) => Err(e),
            (Err(e), Some(mut undeclared)) => {
                undeclared.extend(e.0.into_iter());
                Err(TypeResolutionError(undeclared))
            }
        }
    }
}

/// Holds a map from (fully qualified) [`EntityUID`]s of action definitions
/// to their corresponding [`ActionFragment`]. The action [`EntityUID`]s (keys
/// in the map) are fully qualified, but inside the [`ActionFragment`]s (values
/// in the map), entity/common type references (including references to other actions)
/// may or may not be fully qualified yet, depending on `N`. See notes on
/// [`ActionFragment`].
///
/// The [`ActionFragment`]s may also reference undeclared entity/common types
/// and actions (that will be declared in a different schema fragment).
///
/// The current schema format specification does not include multiple action entity
/// types. All action entities are required to use a single `Action` entity
/// type. However, the action entity type may be namespaced, so an action entity
/// may have a fully qualified entity type `My::Namespace::Action`.
#[derive(Debug)]
pub struct ActionsDef<N> {
    pub(super) actions: HashMap<EntityUID, ActionFragment<N>>,
}

impl ActionsDef<ConditionalName> {
    /// Construct an [`ActionsDef<ConditionalName>`] by converting the structures used by the
    /// schema format to those used internally by the validator.
    pub(crate) fn from_raw_actions(
        schema_file_actions: HashMap<SmolStr, ActionType<RawName>>,
        schema_namespace: Option<&Name>,
        extensions: Extensions<'_>,
    ) -> crate::err::Result<Self> {
        let mut actions = HashMap::with_capacity(schema_file_actions.len());
        for (action_id_str, action_type) in schema_file_actions {
            let action_uid = parse_action_id_with_namespace(
                ActionEntityUID::default_type(action_id_str.clone()),
                schema_namespace,
            );
            match actions.entry(action_uid) {
                Entry::Vacant(ventry) => {
                    let frag = ActionFragment::from_raw_action(
                        ventry.key(),
                        action_type,
                        schema_namespace,
                        extensions,
                    )?;
                    ventry.insert(frag);
                }
                Entry::Occupied(_) => {
                    return Err(DuplicateActionError(action_id_str).into());
                }
            }
        }
        Ok(Self { actions })
    }

    /// Convert this [`ActionsDef<ConditionalName>`] into a [`ActionsDef<Name>`]
    /// by fully-qualifying all typenames that appear anywhere in any
    /// definitions.
    ///
    /// `all_common_defs` and `all_entity_defs` need to be the full set of all
    /// fully-qualified typenames (of common and entity types respectively) that
    /// are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_common_defs: &HashSet<Name>,
        all_entity_defs: &HashSet<Name>,
    ) -> Result<ActionsDef<Name>, TypeResolutionError> {
        Ok(ActionsDef {
            actions: self
                .actions
                .into_iter()
                .map(|(k, v)| {
                    Ok((
                        k,
                        v.fully_qualify_type_references(all_common_defs, all_entity_defs)?,
                    ))
                })
                .collect::<Result<_, _>>()?,
        })
    }
}

/// Holds the information about an action that comprises an action definition.
///
/// In this representation, references to common types may not yet have been
/// fully resolved/inlined, and entity/common type references (including
/// references to other actions) may not yet be fully qualified, depending on
/// `N`. This [`ActionFragment`] may also reference undeclared entity/common
/// types and actions (that will be declared in a different schema fragment).
#[derive(Debug)]
pub struct ActionFragment<N> {
    /// The type of the context record for this action. This may contain
    /// references to common types which have not yet been resolved/inlined
    /// (e.g., because they are not defined in this schema fragment).
    pub(super) context: SchemaType<N>,
    /// The principals and resources that an action can be applied to.
    pub(super) applies_to: ValidatorApplySpec<N>,
    /// The direct parent action entities for this action.
    /// These are fully qualified `EntityUID`s, but may be actions declared in a
    /// different namespace or schema fragment, and thus not declared yet.
    /// We will check for undeclared parents when combining fragments into a
    /// [`crate::ValidatorSchema`].
    pub(super) parents: HashSet<EntityUID>,
    /// The types for the attributes defined for this actions entity.
    /// Here, common types have been fully resolved/inlined.
    pub(super) attribute_types: Attributes,
    /// The values for the attributes defined for this actions entity, stored
    /// separately so that we can later extract these values to construct the
    /// actual `Entity` objects defined by the schema.
    pub(super) attributes: BTreeMap<SmolStr, PartialValueSerializedAsExpr>,
}

impl ActionFragment<ConditionalName> {
    pub(crate) fn from_raw_action(
        action_uid: &EntityUID,
        action_type: schema_file_format::ActionType<RawName>,
        schema_namespace: Option<&Name>,
        extensions: Extensions<'_>,
    ) -> crate::err::Result<Self> {
        let (principal_types, resource_types, context) = action_type
            .applies_to
            .map(|applies_to| {
                (
                    applies_to.principal_types,
                    applies_to.resource_types,
                    applies_to.context,
                )
            })
            .unwrap_or_default();
        let (attribute_types, attributes) = Self::convert_attr_jsonval_map_to_attributes(
            action_type.attributes.unwrap_or_default(),
            action_uid,
            extensions,
        )?;
        Ok(Self {
            context: context
                .into_inner()
                .conditionally_qualify_type_references(schema_namespace),
            applies_to: ValidatorApplySpec::<ConditionalName>::new(
                principal_types
                    .into_iter()
                    .map(|pty| {
                        pty.conditionally_qualify_with(schema_namespace, ReferenceType::Entity)
                    })
                    .collect(),
                resource_types
                    .into_iter()
                    .map(|rty| {
                        rty.conditionally_qualify_with(schema_namespace, ReferenceType::Entity)
                    })
                    .collect(),
            ),
            parents: action_type
                .member_of
                .unwrap_or_default()
                .into_iter()
                .map(|parent| parse_action_id_with_namespace(parent, schema_namespace))
                .collect(),
            attribute_types,
            attributes,
        })
    }

    /// Convert this [`ActionFragment<ConditionalName>`] into an
    /// [`ActionFragment<Name>`] by fully-qualifying all typenames that appear
    /// anywhere in any definitions.
    ///
    /// `all_common_defs` and `all_entity_defs` need to be the full set of all
    /// fully-qualified typenames (of common and entity types respectively) that
    /// are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_common_defs: &HashSet<Name>,
        all_entity_defs: &HashSet<Name>,
    ) -> Result<ActionFragment<Name>, TypeResolutionError> {
        Ok(ActionFragment {
            context: self
                .context
                .fully_qualify_type_references(all_common_defs, all_entity_defs)?,
            applies_to: self
                .applies_to
                .fully_qualify_type_references(all_common_defs, all_entity_defs)?,
            parents: self.parents,
            attribute_types: self.attribute_types,
            attributes: self.attributes,
        })
    }

    fn convert_attr_jsonval_map_to_attributes(
        m: HashMap<SmolStr, CedarValueJson>,
        action_id: &EntityUID,
        extensions: Extensions<'_>,
    ) -> crate::err::Result<(Attributes, BTreeMap<SmolStr, PartialValueSerializedAsExpr>)> {
        let mut attr_types: HashMap<SmolStr, Type> = HashMap::with_capacity(m.len());
        let mut attr_values: BTreeMap<SmolStr, PartialValueSerializedAsExpr> = BTreeMap::new();
        let evaluator = RestrictedEvaluator::new(&extensions);

        for (k, v) in m {
            let t = Self::jsonval_to_type_helper(&v, action_id);
            match t {
                Ok(ty) => attr_types.insert(k.clone(), ty),
                Err(e) => return Err(e),
            };

            // As an artifact of the limited `CedarValueJson` variants accepted by
            // `Self::jsonval_to_type_helper`, we know that this function will
            // never error. Also note that this is only ever executed when
            // action attributes are enabled, but they cannot be enabled when
            // using Cedar through the public API. This is fortunate because
            // handling an error here would mean adding a new error variant to
            // `SchemaError` in the public API, but we didn't make that enum
            // `non_exhaustive`, so any new variants are a breaking change.
            // PANIC SAFETY: see above
            #[allow(clippy::expect_used)]
            let e = v.into_expr(|| JsonDeserializationErrorContext::EntityAttribute { uid: action_id.clone(), attr: k.clone() }).expect("`Self::jsonval_to_type_helper` will always return `Err` for a `CedarValueJson` that might make `into_expr` return `Err`");
            let pv = evaluator
                .partial_interpret(e.as_borrowed())
                .map_err(|err| {
                    ActionAttrEvalError(EntityAttrEvaluationError {
                        uid: action_id.clone(),
                        attr: k.clone(),
                        err,
                    })
                })?;
            attr_values.insert(k.clone(), pv.into());
        }
        Ok((
            Attributes::with_required_attributes(attr_types),
            attr_values,
        ))
    }

    /// Helper to get types from `CedarValueJson`s. Currently doesn't support all
    /// `CedarValueJson` types. Note: If this function is extended to cover move
    /// `CedarValueJson`s, we must update `convert_attr_jsonval_map_to_attributes` to
    /// handle errors that may occur when parsing these values. This will require
    /// a breaking change in the `SchemaError` type in the public API.
    fn jsonval_to_type_helper(
        v: &CedarValueJson,
        action_id: &EntityUID,
    ) -> crate::err::Result<Type> {
        match v {
            CedarValueJson::Bool(_) => Ok(Type::primitive_boolean()),
            CedarValueJson::Long(_) => Ok(Type::primitive_long()),
            CedarValueJson::String(_) => Ok(Type::primitive_string()),
            CedarValueJson::Record(r) => {
                let mut required_attrs: HashMap<SmolStr, Type> = HashMap::with_capacity(r.len());
                for (k, v_prime) in r {
                    let t = Self::jsonval_to_type_helper(v_prime, action_id);
                    match t {
                        Ok(ty) => required_attrs.insert(k.clone(), ty),
                        Err(e) => return Err(e),
                    };
                }
                Ok(Type::record_with_required_attributes(
                    required_attrs,
                    OpenTag::ClosedAttributes,
                ))
            }
            CedarValueJson::Set(v) => match v.first() {
                //sets with elements of different types will be rejected elsewhere
                None => Err(ActionAttributesContainEmptySetError(action_id.clone()).into()),
                Some(element) => {
                    let element_type = Self::jsonval_to_type_helper(element, action_id);
                    match element_type {
                        Ok(t) => Ok(Type::Set {
                            element_type: Some(Box::new(t)),
                        }),
                        Err(_) => element_type,
                    }
                }
            },
            CedarValueJson::EntityEscape { __entity: _ } => Err(UnsupportedActionAttributeError(
                action_id.clone(),
                "entity escape (`__entity`)".into(),
            )
            .into()),
            CedarValueJson::ExprEscape { __expr: _ } => Err(UnsupportedActionAttributeError(
                action_id.clone(),
                "expression escape (`__expr`)".into(),
            )
            .into()),
            CedarValueJson::ExtnEscape { __extn: _ } => Err(UnsupportedActionAttributeError(
                action_id.clone(),
                "extension function escape (`__extn`)".into(),
            )
            .into()),
            CedarValueJson::Null => {
                Err(UnsupportedActionAttributeError(action_id.clone(), "null".into()).into())
            }
        }
    }
}

type ResolveFunc<T> = dyn FnOnce(&HashMap<&Name, Type>) -> crate::err::Result<T>;
/// Represent a type that might be defined in terms of some type definitions
/// which are not necessarily available in the current namespace.
pub(crate) enum WithUnresolvedTypeDefs<T> {
    WithUnresolved(Box<ResolveFunc<T>>),
    WithoutUnresolved(T),
}

impl<T: 'static> WithUnresolvedTypeDefs<T> {
    pub fn new(f: impl FnOnce(&HashMap<&Name, Type>) -> crate::err::Result<T> + 'static) -> Self {
        Self::WithUnresolved(Box::new(f))
    }

    pub fn map<U: 'static>(self, f: impl FnOnce(T) -> U + 'static) -> WithUnresolvedTypeDefs<U> {
        match self {
            Self::WithUnresolved(_) => {
                WithUnresolvedTypeDefs::new(|type_defs| self.resolve_type_defs(type_defs).map(f))
            }
            Self::WithoutUnresolved(v) => WithUnresolvedTypeDefs::WithoutUnresolved(f(v)),
        }
    }

    /// Instantiate any names referencing types with the definition of the type
    /// from the input `HashMap`.
    ///
    /// Be warned that `type_defs` should contain all definitions, from all
    /// schema fragments.
    /// If `self` references any type not in `type_defs`, this will return a
    /// `TypeResolutionError`.
    pub fn resolve_type_defs(self, type_defs: &HashMap<&Name, Type>) -> crate::err::Result<T> {
        match self {
            WithUnresolvedTypeDefs::WithUnresolved(f) => f(type_defs),
            WithUnresolvedTypeDefs::WithoutUnresolved(v) => Ok(v),
        }
    }
}

impl<T: 'static> From<T> for WithUnresolvedTypeDefs<T> {
    fn from(value: T) -> Self {
        Self::WithoutUnresolved(value)
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for WithUnresolvedTypeDefs<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WithUnresolvedTypeDefs::WithUnresolved(_) => f.debug_tuple("WithUnresolved").finish(),
            WithUnresolvedTypeDefs::WithoutUnresolved(v) => {
                f.debug_tuple("WithoutUnresolved").field(v).finish()
            }
        }
    }
}

impl TryInto<ValidatorNamespaceDef<ConditionalName>> for NamespaceDefinition<RawName> {
    type Error = SchemaError;

    fn try_into(self) -> crate::err::Result<ValidatorNamespaceDef<ConditionalName>> {
        ValidatorNamespaceDef::from_namespace_definition(
            None,
            self,
            ActionBehavior::default(),
            Extensions::all_available(),
        )
    }
}

/// Take an action identifier and use it to construct a fully-qualified
/// [`EntityUID`] for that action.
///
/// The entity type of the action will always have the base type `Action`.
/// The type will be qualified with any namespace provided in the
/// `namespace` argument or with the namespace inside the
/// [`ActionEntityUID`] if one is present.
fn parse_action_id_with_namespace(
    action_id: ActionEntityUID<RawName>,
    namespace: Option<&Name>,
) -> EntityUID {
    let action_ty =
        match action_id.ty {
            Some(ty) => ty.clone(),
            None => {
                // PANIC SAFETY: The constant ACTION_ENTITY_TYPE is valid entity type.
                #[allow(clippy::expect_used)]
            RawName::new(Id::from_normalized_str(cedar_policy_core::ast::ACTION_ENTITY_TYPE).expect(
                "Expected that the constant ACTION_ENTITY_TYPE would be a valid entity type.",
            ))
            }
        };
    EntityUID::from_components(
        action_ty.qualify_with(namespace).into(),
        Eid::new(action_id.id),
        None,
    )
}

/// Convert a type as represented in the schema file format (but with
/// fully-qualified names) into the [`Type`] type used by the validator.
///
/// Conversion can fail if an entity or record attribute name is invalid. It
/// will also fail for some types that can be written in the schema, but are
/// not yet implemented in the typechecking logic.
pub(crate) fn try_schema_type_into_validator_type(
    schema_ty: SchemaType<Name>,
    extensions: Extensions<'_>,
) -> crate::err::Result<WithUnresolvedTypeDefs<Type>> {
    match schema_ty {
        SchemaType::Type(SchemaTypeVariant::String) => Ok(Type::primitive_string().into()),
        SchemaType::Type(SchemaTypeVariant::Long) => Ok(Type::primitive_long().into()),
        SchemaType::Type(SchemaTypeVariant::Boolean) => Ok(Type::primitive_boolean().into()),
        SchemaType::Type(SchemaTypeVariant::Set { element }) => {
            Ok(try_schema_type_into_validator_type(*element, extensions)?.map(Type::set))
        }
        SchemaType::Type(SchemaTypeVariant::Record {
            attributes,
            additional_attributes,
        }) => {
            if cfg!(not(feature = "partial-validate")) && additional_attributes {
                Err(UnsupportedFeatureError(UnsupportedFeature::OpenRecordsAndEntities).into())
            } else {
                Ok(
                    parse_record_attributes(attributes, extensions)?.map(move |attrs| {
                        Type::record_with_attributes(
                            attrs,
                            if additional_attributes {
                                OpenTag::OpenAttributes
                            } else {
                                OpenTag::ClosedAttributes
                            },
                        )
                    }),
                )
            }
        }
        SchemaType::Type(SchemaTypeVariant::Entity { name }) => {
            Ok(Type::named_entity_reference(name.into()).into())
        }
        SchemaType::Type(SchemaTypeVariant::Extension { name }) => {
            let extension_type_name = Name::unqualified_name(name);
            if extensions.ext_types().contains(&extension_type_name) {
                Ok(Type::extension(extension_type_name).into())
            } else {
                let suggested_replacement = fuzzy_search(
                    &extension_type_name.to_string(),
                    &extensions
                        .ext_types()
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>(),
                );
                Err(SchemaError::UnknownExtensionType(
                    UnknownExtensionTypeError {
                        actual: extension_type_name,
                        suggested_replacement,
                    },
                ))
            }
        }
        SchemaType::CommonTypeRef { type_name } => {
            Ok(WithUnresolvedTypeDefs::new(move |typ_defs| {
                typ_defs
                    .get(&type_name)
                    .cloned()
                    // We should always have `Some` here, because if the common type
                    // wasn't defined, that error should have been caught earlier,
                    // when the `SchemaType<Name>` was created by resolving a
                    // `ConditionalName` into a fully-qualified `Name`. Nonetheless,
                    // instead of panicking if that internal invariant is violated,
                    // it's easy to return this dynamic error instead.
                    .ok_or(UndeclaredCommonTypeError(type_name).into())
            }))
        }
        SchemaType::EntityOrCommonTypeRef { type_name } => {
            Ok(WithUnresolvedTypeDefs::new(move |typ_defs| {
                // First check if it's a common type, because in the edge case where
                // the name is both a valid common type name and a valid entity type
                // name, we give preference to the common type (see RFC 24).
                match typ_defs.get(&type_name) {
                    Some(def) => Ok(def.clone()),
                    None => {
                        // It wasn't a common type, so we assume it must be a valid
                        // entity type. Otherwise, we would have had an error earlier,
                        // when the `SchemaType<Name>` was created by resolving a
                        // `ConditionalName` into a fully-qualified `Name`.
                        Ok(Type::named_entity_reference(EntityType::from(type_name)))
                    }
                }
            }))
        }
    }
}

/// Given the attributes for an entity type or action context in the schema
/// file format structures (but with fully-qualified names), convert the
/// types of the attributes into the [`Type`] data structure used by the
/// validator, and return the result as an [`Attributes`] structure.
fn parse_record_attributes(
    attrs: impl IntoIterator<Item = (SmolStr, TypeOfAttribute<Name>)>,
    extensions: Extensions<'_>,
) -> crate::err::Result<WithUnresolvedTypeDefs<Attributes>> {
    let attrs_with_type_defs = attrs
        .into_iter()
        .map(|(attr, ty)| -> crate::err::Result<_> {
            Ok((
                attr,
                (
                    try_schema_type_into_validator_type(ty.ty, extensions)?,
                    ty.required,
                ),
            ))
        })
        .collect::<crate::err::Result<Vec<_>>>()?;
    Ok(WithUnresolvedTypeDefs::new(|typ_defs| {
        attrs_with_type_defs
            .into_iter()
            .map(|(s, (attr_ty, is_req))| {
                attr_ty
                    .resolve_type_defs(typ_defs)
                    .map(|ty| (s, AttributeType::new(ty, is_req)))
            })
            .collect::<crate::err::Result<Vec<_>>>()
            .map(Attributes::with_attributes)
    }))
}
