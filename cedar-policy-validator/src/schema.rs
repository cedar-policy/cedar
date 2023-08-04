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
use std::sync::Arc;

use cedar_policy_core::{
    ast::{Eid, Entity, EntityType, EntityUID, Id, Name, RestrictedExpr},
    entities::{Entities, JSONValue, TCComputation},
    parser::err::ParseErrors,
    transitive_closure::{compute_tc, TCNode},
    FromNormalizedStr,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;

use crate::types::OpenTag;
use crate::{
    schema_file_format,
    types::{AttributeType, Attributes, EntityRecordKind, Type},
    ActionEntityUID, ActionType, SchemaFragment, SchemaType, SchemaTypeVariant, TypeOfAttribute,
    SCHEMA_TYPE_VARIANT_TAGS,
};

use super::err::*;
use super::NamespaceDefinition;

/// The current schema format specification does not include multiple action entity
/// types. All action entities are required to use a single `Action` entity
/// type. However, the action entity type may be namespaced, so an action entity
/// may have a fully qualified entity type `My::Namespace::Action`.
/// This string must be parsable by as an entity type name.
pub(crate) static ACTION_ENTITY_TYPE: &str = "Action";

#[test]
fn action_entity_type_parses() {
    Id::from_normalized_str(ACTION_ENTITY_TYPE).unwrap();
}

/// Return true when an entity type is an action entity type. This compares the
/// base name for the type, so this will return true for any entity type named
/// `Action` regardless of namespaces.
pub(crate) fn is_action_entity_type(ty: &Name) -> bool {
    ty.basename().as_ref() == ACTION_ENTITY_TYPE
}

// We do not have a dafny model for action attributes, so we disable them by defualt.
#[derive(Eq, PartialEq, Copy, Clone, Default)]
pub enum ActionBehavior {
    /// Action entities cannot have attributes. Attempting to declare attributes
    /// will result in a error when constructing the schema.
    #[default]
    ProhibitAttributes,
    /// Action entities may have attributes.
    PermitAttributes,
}

/// A single namespace definition from the schema json processed into a form
/// which is closer to that used by the validator. The processing includes
/// detection of some errors, for example, parse errors in entity type names or
/// entity type which are declared multiple times. This does not detect
/// references to undeclared entity types because any entity type may be
/// declared in a different fragment that will only be known about when building
/// the complete `ValidatorSchema`.
#[derive(Debug)]
pub struct ValidatorNamespaceDef {
    /// The namespace declared for the schema fragment. We track a namespace for
    /// fragments because they have at most one namespace that is applied
    /// everywhere. It would be less useful to track all namespaces for a
    /// complete schema.
    namespace: Option<Name>,
    /// Preprocessed common type definitions which can be used to define entity
    /// type attributes and action contexts.
    type_defs: TypeDefs,
    /// The preprocessed entity type declarations from the schema fragment json.
    entity_types: EntityTypesDef,
    /// The preprocessed action declarations from the schema fragment json.
    actions: ActionsDef,
}

/// Holds a map from `Name`s of common type definitions to their corresponding
/// `Type`.
#[derive(Debug)]
pub struct TypeDefs {
    type_defs: HashMap<Name, Type>,
}

/// Entity type declarations held in a `ValidatorNamespaceDef`. Entity type
/// parents and attributes may reference undeclared entity types.
#[derive(Debug)]
pub struct EntityTypesDef {
    entity_types: HashMap<Name, EntityTypeFragment>,
}

/// Defines an EntityType where we have not resolved typedefs occurring in the
/// attributes or verified that the parent entity types and entity types
/// occurring in attributes are defined.
#[derive(Debug)]
pub struct EntityTypeFragment {
    /// The attributes record type for this entity type.  The type is wrapped in
    /// a `WithUnresolvedTypeDefs` because it may contain typedefs which are not
    /// defined in this schema fragment. All entity type `Name` keys in this map
    /// are declared in this schema fragment.
    attributes: WithUnresolvedTypeDefs<Type>,
    /// The direct parent entity types for this entity type come from the
    /// `memberOfTypes` list. These types might be declared in a different
    /// namespace, so we will check if they are declared in any fragment when
    /// constructing a `ValidatorSchema`.
    parents: HashSet<Name>,
}

/// Action declarations held in a `ValidatorNamespaceDef`. Entity types
/// referenced here do not need to be declared in the schema.
#[derive(Debug)]
pub struct ActionsDef {
    actions: HashMap<EntityUID, ActionFragment>,
}

#[derive(Debug)]
pub struct ActionFragment {
    /// The type of the context record for this actions. The types is wrapped in
    /// a `WithUnresolvedTypeDefs` because it may refer to common types which
    /// are not defined in this fragment.
    context: WithUnresolvedTypeDefs<Type>,
    /// The principals and resources that an action can be applied to.
    applies_to: ValidatorApplySpec,
    /// The direct parent action entities for this action.
    parents: HashSet<EntityUID>,
    /// The types for the attributes defined for this actions entity.
    attribute_types: Attributes,
    /// The values for the attributes defined for this actions entity, stored
    /// separately so that we can later extract use these values to construct
    /// the actual `Entity` objects defined by the schema.
    attributes: HashMap<SmolStr, RestrictedExpr>,
}

type ResolveFunc<T> = dyn FnOnce(&HashMap<Name, Type>) -> Result<T>;
/// Represent a type that might be defined in terms of some type definitions
/// which are not necessarily available in the current namespace.
pub enum WithUnresolvedTypeDefs<T> {
    WithUnresolved(Box<ResolveFunc<T>>),
    WithoutUnresolved(T),
}

impl<T: 'static> WithUnresolvedTypeDefs<T> {
    pub fn new(f: impl FnOnce(&HashMap<Name, Type>) -> Result<T> + 'static) -> Self {
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
    /// from the input HashMap.
    pub fn resolve_type_defs(self, type_defs: &HashMap<Name, Type>) -> Result<T> {
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

impl TryInto<ValidatorNamespaceDef> for NamespaceDefinition {
    type Error = SchemaError;

    fn try_into(self) -> Result<ValidatorNamespaceDef> {
        ValidatorNamespaceDef::from_namespace_definition(None, self, ActionBehavior::default())
    }
}

impl ValidatorNamespaceDef {
    // We need to treat this as if it had `pub(crate)` visibility to avoid sharing
    // the file format. However, our fuzzing library currently needs it to be public.
    /// Construct a new `ValidatorSchema` from the underlying `SchemaFragment`.
    pub fn from_namespace_definition(
        namespace: Option<SmolStr>,
        namespace_def: NamespaceDefinition,
        action_behavior: ActionBehavior,
    ) -> Result<ValidatorNamespaceDef> {
        // Check that each entity types and action is only declared once.
        let mut e_types_ids: HashSet<SmolStr> = HashSet::new();
        for name in namespace_def.entity_types.keys() {
            if !e_types_ids.insert(name.clone()) {
                // insert returns false for duplicates
                return Err(SchemaError::DuplicateEntityType(name.to_string()));
            }
        }
        let mut a_name_eids: HashSet<SmolStr> = HashSet::new();
        for name in namespace_def.actions.keys() {
            if !a_name_eids.insert(name.clone()) {
                // insert returns false for duplicates
                return Err(SchemaError::DuplicateAction(name.to_string()));
            }
        }

        let schema_namespace = match namespace.as_deref() {
            None => None,
            Some("") => None, // we consider "" to be the same as the empty namespace for this purpose
            Some(ns) => Some(Name::from_normalized_str(ns).map_err(SchemaError::ParseNamespace)?),
        };

        // Return early with an error if actions cannot be in groups or have
        // attributes, but the schema contains action groups or attributes.
        Self::check_action_behavior(&namespace_def, action_behavior)?;

        // Convert the type defs, actions and entity types from the schema file
        // into the representation used by the validator.
        let type_defs =
            Self::build_type_defs(namespace_def.common_types, schema_namespace.as_ref())?;
        let actions = Self::build_action_ids(namespace_def.actions, schema_namespace.as_ref())?;
        let entity_types =
            Self::build_entity_types(namespace_def.entity_types, schema_namespace.as_ref())?;

        Ok(ValidatorNamespaceDef {
            namespace: schema_namespace,
            type_defs,
            entity_types,
            actions,
        })
    }

    fn is_builtin_type_name(name: &SmolStr) -> bool {
        SCHEMA_TYPE_VARIANT_TAGS
            .iter()
            .any(|type_name| name == type_name)
    }

    fn build_type_defs(
        schema_file_type_def: HashMap<SmolStr, SchemaType>,
        schema_namespace: Option<&Name>,
    ) -> Result<TypeDefs> {
        let type_defs = schema_file_type_def
            .into_iter()
            .map(|(name_str, schema_ty)| -> Result<_> {
                if Self::is_builtin_type_name(&name_str) {
                    return Err(SchemaError::DuplicateCommonType(name_str.to_string()));
                }
                let name = Self::parse_unqualified_name_with_namespace(
                    &name_str,
                    schema_namespace.cloned(),
                )
                .map_err(SchemaError::ParseCommonType)?;
                let ty = Self::try_schema_type_into_validator_type(schema_namespace, schema_ty)?
                    .resolve_type_defs(&HashMap::new())?;
                Ok((name, ty))
            })
            .collect::<Result<HashMap<_, _>>>()?;
        Ok(TypeDefs { type_defs })
    }

    // Transform the schema data structures for entity types into the structures
    // used internally by the validator. This is mostly accomplished by directly
    // copying data between fields.
    fn build_entity_types(
        schema_files_types: HashMap<SmolStr, schema_file_format::EntityType>,
        schema_namespace: Option<&Name>,
    ) -> Result<EntityTypesDef> {
        Ok(EntityTypesDef {
            entity_types: schema_files_types
                .into_iter()
                .map(|(name_str, entity_type)| -> Result<_> {
                    let name = Self::parse_unqualified_name_with_namespace(
                        &name_str,
                        schema_namespace.cloned(),
                    )
                    .map_err(SchemaError::ParseEntityType)?;

                    let parents = entity_type
                        .member_of_types
                        .iter()
                        .map(|parent| -> Result<_> {
                            Self::parse_possibly_qualified_name_with_default_namespace(
                                parent,
                                schema_namespace,
                            )
                            .map_err(SchemaError::ParseEntityType)
                        })
                        .collect::<Result<HashSet<_>>>()?;

                    let attributes = Self::try_schema_type_into_validator_type(
                        schema_namespace,
                        entity_type.shape.into_inner(),
                    )?;

                    Ok((
                        name,
                        EntityTypeFragment {
                            attributes,
                            parents,
                        },
                    ))
                })
                .collect::<Result<HashMap<_, _>>>()?,
        })
    }

    // Helper to get types from JSONValues. Currently doesn't support all
    // JSONValue types. Note: If this function is extended to cover move
    // `JSONValue`s, we must update `convert_attr_jsonval_map_to_attributes` to
    // handle errors that may occur when parsing these values. This will require
    // a breaking change in the `SchemaError` type in the public API.
    fn jsonval_to_type_helper(v: &JSONValue, action_id: &EntityUID) -> Result<Type> {
        match v {
            JSONValue::Bool(_) => Ok(Type::primitive_boolean()),
            JSONValue::Long(_) => Ok(Type::primitive_long()),
            JSONValue::String(_) => Ok(Type::primitive_string()),
            JSONValue::Record(r) => {
                let mut required_attrs: HashMap<SmolStr, Type> = HashMap::new();
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
            JSONValue::Set(v) => match v.get(0) {
                //sets with elements of different types will be rejected elsewhere
                None => Err(SchemaError::ActionAttributesContainEmptySet(
                    action_id.clone(),
                )),
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
            JSONValue::EntityEscape { __entity: _ } => {
                Err(SchemaError::UnsupportedActionAttribute(
                    action_id.clone(),
                    "entity escape (`__entity`)".to_owned(),
                ))
            }
            JSONValue::ExprEscape { __expr: _ } => Err(SchemaError::UnsupportedActionAttribute(
                action_id.clone(),
                "expression escape (`__expr`)".to_owned(),
            )),
            JSONValue::ExtnEscape { __extn: _ } => Err(SchemaError::UnsupportedActionAttribute(
                action_id.clone(),
                "extension function escape (`__extn`)".to_owned(),
            )),
        }
    }

    //Convert jsonval map to attributes
    fn convert_attr_jsonval_map_to_attributes(
        m: HashMap<SmolStr, JSONValue>,
        action_id: &EntityUID,
    ) -> Result<(Attributes, HashMap<SmolStr, RestrictedExpr>)> {
        let mut attr_types: HashMap<SmolStr, Type> = HashMap::new();
        let mut attr_values: HashMap<SmolStr, RestrictedExpr> = HashMap::new();

        for (k, v) in m {
            let t = Self::jsonval_to_type_helper(&v, action_id);
            match t {
                Ok(ty) => attr_types.insert(k.clone(), ty),
                Err(e) => return Err(e),
            };

            // As an artifact of the limited `JSONValue` variants accepted by
            // `Self::jsonval_to_type_helper`, we know that this function will
            // never error. Also note that this is only ever executed when
            // action attributes are enabled, but they cannot be enabled when
            // using Cedar through the public API. This is fortunate because
            // handling an error here would mean adding a new error variant to
            // `SchemaError` in the public API, but we didn't make that enum
            // `non_exhaustive`, so any new variants are a breaking change.
            // PANIC SAFETY: see above
            #[allow(clippy::expect_used)]
            let e = v.into_expr().expect("`Self::jsonval_to_type_helper` will always return `Err` for a `JSONValue` that might make `into_expr` return `Err`");
            attr_values.insert(k.clone(), e);
        }
        Ok((
            Attributes::with_required_attributes(attr_types),
            attr_values,
        ))
    }

    // Transform the schema data structures for actions into the structures used
    // internally by the validator. This is mostly accomplished by directly
    // copying data between fields.
    fn build_action_ids(
        schema_file_actions: HashMap<SmolStr, ActionType>,
        schema_namespace: Option<&Name>,
    ) -> Result<ActionsDef> {
        Ok(ActionsDef {
            actions: schema_file_actions
                .into_iter()
                .map(|(action_id_str, action_type)| -> Result<_> {
                    let action_id = Self::parse_action_id_with_namespace(
                        &ActionEntityUID::default_type(action_id_str),
                        schema_namespace,
                    )?;

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

                    // Convert the entries in the `appliesTo` lists into sets of
                    // `EntityTypes`. If one of the lists is `None` (absent from the
                    // schema), then the specification is undefined.
                    let applies_to = ValidatorApplySpec::new(
                        Self::parse_apply_spec_type_list(principal_types, schema_namespace)?,
                        Self::parse_apply_spec_type_list(resource_types, schema_namespace)?,
                    );

                    let context = Self::try_schema_type_into_validator_type(
                        schema_namespace,
                        context.into_inner(),
                    )?;

                    let parents = action_type
                        .member_of
                        .unwrap_or_default()
                        .iter()
                        .map(|parent| -> Result<_> {
                            Self::parse_action_id_with_namespace(parent, schema_namespace)
                        })
                        .collect::<Result<HashSet<_>>>()?;

                    let (attribute_types, attributes) =
                        Self::convert_attr_jsonval_map_to_attributes(
                            action_type.attributes.unwrap_or_default(),
                            &action_id,
                        )?;

                    Ok((
                        action_id,
                        ActionFragment {
                            context,
                            applies_to,
                            parents,
                            attribute_types,
                            attributes,
                        },
                    ))
                })
                .collect::<Result<HashMap<_, _>>>()?,
        })
    }

    // Check that `schema_file` uses actions in a way consistent with the
    // specified `action_behavior`. When the behavior specifies that actions
    // should not be used in groups and should not have attributes, then this
    // function will return `Err` if it sees any action groups or attributes
    // declared in the schema.
    fn check_action_behavior(
        schema_file: &NamespaceDefinition,
        action_behavior: ActionBehavior,
    ) -> Result<()> {
        if schema_file
            .entity_types
            .iter()
            // The `name` in an entity type declaration cannot be qualified
            // with a namespace (it always implicitly takes the schema
            // namespace), so we do this comparison directly.
            .any(|(name, _)| name == ACTION_ENTITY_TYPE)
        {
            return Err(SchemaError::ActionEntityTypeDeclared);
        }
        if action_behavior == ActionBehavior::ProhibitAttributes {
            let mut actions_with_attributes: Vec<String> = Vec::new();
            for (name, a) in &schema_file.actions {
                if a.attributes.is_some() {
                    actions_with_attributes.push(name.to_string());
                }
            }
            if !actions_with_attributes.is_empty() {
                return Err(SchemaError::UnsupportedFeature(
                    UnsupportedFeature::ActionAttributes(actions_with_attributes),
                ));
            }
        }

        Ok(())
    }

    /// Given the attributes for an entity type or action context as written in
    /// a schema file, convert the types of the attributes into the `Type` data
    /// structure used by the typechecker, and return the result as a map from
    /// attribute name to type.
    fn parse_record_attributes(
        schema_namespace: Option<&Name>,
        attrs: impl IntoIterator<Item = (SmolStr, TypeOfAttribute)>,
    ) -> Result<WithUnresolvedTypeDefs<Attributes>> {
        let attrs_with_type_defs = attrs
            .into_iter()
            .map(|(attr, ty)| -> Result<_> {
                Ok((
                    attr,
                    (
                        Self::try_schema_type_into_validator_type(schema_namespace, ty.ty)?,
                        ty.required,
                    ),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(WithUnresolvedTypeDefs::new(|typ_defs| {
            attrs_with_type_defs
                .into_iter()
                .map(|(s, (attr_ty, is_req))| {
                    attr_ty
                        .resolve_type_defs(typ_defs)
                        .map(|ty| (s, AttributeType::new(ty, is_req)))
                })
                .collect::<Result<Vec<_>>>()
                .map(Attributes::with_attributes)
        }))
    }

    /// Take an optional list of entity type name strings from an action apply
    /// spec and parse it into a set of `Name`s for those entity types. If any
    /// of the entity type names cannot be parsed, then the `Err` case is
    /// returned, and it will indicate which name did not parse.
    fn parse_apply_spec_type_list(
        types: Option<Vec<SmolStr>>,
        namespace: Option<&Name>,
    ) -> Result<HashSet<EntityType>> {
        types
            .map(|types| {
                types
                    .iter()
                    // Parse each type name string into a `Name`, generating an
                    // `EntityTypeParseError` when the string is not a valid
                    // name.
                    .map(|ty_str| {
                        Ok(EntityType::Concrete(
                            Self::parse_possibly_qualified_name_with_default_namespace(
                                ty_str, namespace,
                            )
                            .map_err(SchemaError::ParseEntityType)?,
                        ))
                    })
                    // Fail if any of the types failed.
                    .collect::<Result<HashSet<_>>>()
            })
            .unwrap_or_else(|| Ok(HashSet::from([EntityType::Unspecified])))
    }

    // Parse a `Name` from a string (possibly including namespaces). If it is
    // not qualified with any namespace, then apply the  default namespace to
    // create a qualified name.  Do not modify any existing namespace on the
    // type.
    pub(crate) fn parse_possibly_qualified_name_with_default_namespace(
        name_str: &SmolStr,
        default_namespace: Option<&Name>,
    ) -> std::result::Result<Name, ParseErrors> {
        let name = Name::from_normalized_str(name_str)?;

        let qualified_name = if name.namespace_components().next().is_some() {
            // The name is already qualified. Don't touch it.
            name
        } else {
            // The name does not have a namespace, so qualify the type to
            // use the default.
            match default_namespace {
                Some(namespace) => {
                    Name::type_in_namespace(name.basename().clone(), namespace.clone())
                }
                None => name,
            }
        };

        Ok(qualified_name)
    }

    /// Parse a name from a string into the `Id` (basename only).  Then
    /// initialize the namespace for this type with the provided namespace vec
    /// to create the qualified `Name`.
    fn parse_unqualified_name_with_namespace(
        type_name: impl AsRef<str>,
        namespace: Option<Name>,
    ) -> std::result::Result<Name, ParseErrors> {
        let type_name = Id::from_normalized_str(type_name.as_ref())?;
        match namespace {
            Some(namespace) => Ok(Name::type_in_namespace(type_name, namespace)),
            None => Ok(Name::unqualified_name(type_name)),
        }
    }

    /// Take an action identifier as a string and use it to construct an
    /// EntityUID for that action. The entity type of the action will always
    /// have the base type `Action`. The type will be qualified with any
    /// namespace provided in the `namespace` argument or with the namespace
    /// inside the ActionEntityUID if one is present.
    fn parse_action_id_with_namespace(
        action_id: &ActionEntityUID,
        namespace: Option<&Name>,
    ) -> Result<EntityUID> {
        let namespaced_action_type = if let Some(action_ty) = &action_id.ty {
            Self::parse_possibly_qualified_name_with_default_namespace(action_ty, namespace)
                .map_err(SchemaError::ParseEntityType)?
        } else {
            // PANIC SAFETY: The constant ACTION_ENTITY_TYPE is valid entity type.
            #[allow(clippy::expect_used)]
            let id = Id::from_normalized_str(ACTION_ENTITY_TYPE).expect(
                "Expected that the constant ACTION_ENTITY_TYPE would be a valid entity type.",
            );
            match namespace {
                Some(namespace) => Name::type_in_namespace(id, namespace.clone()),
                None => Name::unqualified_name(id),
            }
        };
        Ok(EntityUID::from_components(
            namespaced_action_type,
            Eid::new(action_id.id.clone()),
        ))
    }

    /// Implemented to convert a type as written in the schema json format into the
    /// `Type` type used by the validator. Conversion can fail if an entity or
    /// record attribute name is invalid. It will also fail for some types that can
    /// be written in the schema, but are not yet implemented in the typechecking
    /// logic.
    pub(crate) fn try_schema_type_into_validator_type(
        default_namespace: Option<&Name>,
        schema_ty: SchemaType,
    ) -> Result<WithUnresolvedTypeDefs<Type>> {
        match schema_ty {
            SchemaType::Type(SchemaTypeVariant::String) => Ok(Type::primitive_string().into()),
            SchemaType::Type(SchemaTypeVariant::Long) => Ok(Type::primitive_long().into()),
            SchemaType::Type(SchemaTypeVariant::Boolean) => Ok(Type::primitive_boolean().into()),
            SchemaType::Type(SchemaTypeVariant::Set { element }) => Ok(
                Self::try_schema_type_into_validator_type(default_namespace, *element)?
                    .map(Type::set),
            ),
            SchemaType::Type(SchemaTypeVariant::Record {
                attributes,
                additional_attributes,
            }) => {
                if additional_attributes {
                    Err(SchemaError::UnsupportedFeature(
                        UnsupportedFeature::OpenRecordsAndEntities,
                    ))
                } else {
                    Ok(
                        Self::parse_record_attributes(default_namespace, attributes)?.map(
                            |attrs| Type::record_with_attributes(attrs, OpenTag::ClosedAttributes),
                        ),
                    )
                }
            }
            SchemaType::Type(SchemaTypeVariant::Entity { name }) => {
                let entity_type_name = Self::parse_possibly_qualified_name_with_default_namespace(
                    &name,
                    default_namespace,
                )
                .map_err(SchemaError::ParseEntityType)?;
                Ok(Type::named_entity_reference(entity_type_name).into())
            }
            SchemaType::Type(SchemaTypeVariant::Extension { name }) => {
                let extension_type_name =
                    Name::from_normalized_str(&name).map_err(SchemaError::ParseExtensionType)?;
                Ok(Type::extension(extension_type_name).into())
            }
            SchemaType::TypeDef { type_name } => {
                let defined_type_name = Self::parse_possibly_qualified_name_with_default_namespace(
                    &type_name,
                    default_namespace,
                )
                .map_err(SchemaError::ParseCommonType)?;
                Ok(WithUnresolvedTypeDefs::new(move |typ_defs| {
                    typ_defs.get(&defined_type_name).cloned().ok_or(
                        SchemaError::UndeclaredCommonTypes(HashSet::from([type_name.to_string()])),
                    )
                }))
            }
        }
    }

    /// Access the `Name` for the namespace of this definition.
    pub fn namespace(&self) -> &Option<Name> {
        &self.namespace
    }
}

#[derive(Debug)]
pub struct ValidatorSchemaFragment(Vec<ValidatorNamespaceDef>);

impl TryInto<ValidatorSchemaFragment> for SchemaFragment {
    type Error = SchemaError;

    fn try_into(self) -> Result<ValidatorSchemaFragment> {
        ValidatorSchemaFragment::from_schema_fragment(self, ActionBehavior::default())
    }
}

impl ValidatorSchemaFragment {
    pub fn from_namespaces(namespaces: impl IntoIterator<Item = ValidatorNamespaceDef>) -> Self {
        Self(namespaces.into_iter().collect())
    }

    pub fn from_schema_fragment(
        fragment: SchemaFragment,
        action_behavior: ActionBehavior,
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
    pub fn from_json_value(json: serde_json::Value) -> Result<Self> {
        Self::from_schema_file(
            SchemaFragment::from_json_value(json)?,
            ActionBehavior::default(),
        )
    }

    /// Construct a `ValidatorSchema` directly from a file.
    pub fn from_file(file: impl std::io::Read) -> Result<Self> {
        Self::from_schema_file(SchemaFragment::from_file(file)?, ActionBehavior::default())
    }

    pub fn from_schema_file(
        schema_file: SchemaFragment,
        action_behavior: ActionBehavior,
    ) -> Result<ValidatorSchema> {
        Self::from_schema_fragments([ValidatorSchemaFragment::from_schema_fragment(
            schema_file,
            action_behavior,
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
                Ok((
                    name.clone(),
                    ValidatorEntityType {
                        name: name.clone(),
                        descendants,
                        attributes: Self::record_attributes_or_none(
                            entity_type.attributes.resolve_type_defs(&type_defs)?,
                        )
                        .ok_or(SchemaError::ContextOrShapeNotRecord(
                            ContextOrShape::EntityTypeShape(name),
                        ))?,
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

                Ok((
                    name.clone(),
                    ValidatorActionId {
                        name: name.clone(),
                        applies_to: action.applies_to,
                        descendants,
                        context: Self::record_attributes_or_none(
                            action.context.resolve_type_defs(&type_defs)?,
                        )
                        .ok_or(SchemaError::ContextOrShapeNotRecord(
                            ContextOrShape::ActionContext(name),
                        ))?,
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
            for (_, attr_typ) in action.context.iter() {
                Self::check_undeclared_in_type(
                    &attr_typ.attr_type,
                    entity_types,
                    &mut undeclared_e,
                );
            }

            for p_entity in action.applies_to.applicable_principal_types() {
                match p_entity {
                    EntityType::Concrete(p_entity) => {
                        if !entity_types.contains_key(p_entity) {
                            undeclared_e.insert(p_entity.to_string());
                        }
                    }
                    EntityType::Unspecified => (),
                }
            }

            for r_entity in action.applies_to.applicable_resource_types() {
                match r_entity {
                    EntityType::Concrete(r_entity) => {
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

    fn record_attributes_or_none(ty: Type) -> Option<Attributes> {
        match ty {
            Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) => Some(attrs),
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
    pub fn get_entity_type(&self, entity_type_id: &Name) -> Option<&ValidatorEntityType> {
        self.entity_types.get(entity_type_id)
    }

    /// Return true when the entity_type_id corresponds to a valid entity type.
    pub(crate) fn is_known_action_id(&self, action_id: &EntityUID) -> bool {
        self.action_ids.contains_key(action_id)
    }

    /// Return true when the entity_type_id corresponds to a valid entity type.
    pub(crate) fn is_known_entity_type(&self, entity_type: &Name) -> bool {
        self.entity_types.contains_key(entity_type)
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

    /// Get the validator entity equal to an EUID using the component for a head
    /// var kind.
    pub(crate) fn get_entity_eq<'a, H, K>(&self, var: H, euid: EntityUID) -> Option<K>
    where
        H: 'a + HeadVar<K>,
        K: 'a,
    {
        var.get_euid_component(euid)
    }

    /// Get the validator entities that are in the descendants of an EUID using
    /// the component for a head var kind.
    pub(crate) fn get_entities_in<'a, H, K>(
        &'a self,
        var: H,
        euid: EntityUID,
    ) -> impl Iterator<Item = K> + 'a
    where
        H: 'a + HeadVar<K>,
        K: 'a + Clone,
    {
        var.get_descendants_if_present(self, euid.clone())
            .into_iter()
            .flatten()
            .map(Clone::clone)
            .chain(var.get_euid_component_if_present(self, euid).into_iter())
    }

    /// Get the validator entities that are in the descendants of any of the
    /// entities in a set of EUID using the component for a head var kind.
    pub(crate) fn get_entities_in_set<'a, H, K>(
        &'a self,
        var: H,
        euids: impl IntoIterator<Item = EntityUID> + 'a,
    ) -> impl Iterator<Item = K> + 'a
    where
        H: 'a + HeadVar<K>,
        K: 'a + Clone,
    {
        euids
            .into_iter()
            .flat_map(move |e| self.get_entities_in(var, e))
    }

    /// Since different Actions have different schemas for `Context`, you must
    /// specify the `Action` in order to get a `ContextSchema`.
    ///
    /// Returns `None` if the action is not in the schema.
    pub fn get_context_schema(
        &self,
        action: &EntityUID,
    ) -> Option<impl cedar_policy_core::entities::ContextSchema> {
        self.get_action_id(action).map(|action_id| {
            // The invariant on `ContextSchema` requires that the inner type is
            // representable as a schema type. Here we build a closed record
            // type, which are representable as long as their values are
            // representable. The values are representable because they are
            // taken from the context of a `ValidatorActionId` which was
            // constructed directly from a schema.
            ContextSchema(crate::types::Type::record_with_attributes(
                action_id
                    .context
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone())),
                OpenTag::ClosedAttributes,
            ))
        })
    }

    /// Construct an `Entity` object for each action in the schema
    fn action_entities_iter(&self) -> impl Iterator<Item = cedar_policy_core::ast::Entity> + '_ {
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
            Entity::new(
                action_id.clone(),
                action.attributes.clone(),
                action_ancestors.remove(action_id).unwrap_or_default(),
            )
        })
    }

    /// Invert the action hierarchy to get the ancestor relation expected for
    /// the `Entity` datatype instead of descendant as stored by the schema.
    pub fn action_entities(&self) -> cedar_policy_core::entities::Result<Entities> {
        Entities::from_entities(
            self.action_entities_iter(),
            TCComputation::AssumeAlreadyComputed,
        )
    }
}

/// Struct which carries enough information that it can (efficiently) impl Core's `Schema`
pub struct CoreSchema<'a> {
    /// Contains all the information
    schema: &'a ValidatorSchema,
    /// For easy lookup, this is a map from action name to `Entity` object
    /// for each action in the schema. This information is contained in the
    /// `ValidatorSchema`, but not efficient to extract -- getting the `Entity`
    /// from the `ValidatorSchema` is O(N) as of this writing, but with this
    /// cache it's O(1).
    actions: HashMap<EntityUID, Arc<Entity>>,
}

impl<'a> CoreSchema<'a> {
    pub fn new(schema: &'a ValidatorSchema) -> Self {
        Self {
            actions: schema
                .action_entities_iter()
                .map(|e| (e.uid(), Arc::new(e)))
                .collect(),
            schema,
        }
    }
}

impl<'a> cedar_policy_core::entities::Schema for CoreSchema<'a> {
    type EntityTypeDescription = EntityTypeDescription;

    fn entity_type(
        &self,
        entity_type: &cedar_policy_core::ast::EntityType,
    ) -> Option<EntityTypeDescription> {
        match entity_type {
            cedar_policy_core::ast::EntityType::Unspecified => None, // Unspecified entities cannot be declared in the schema and should not appear in JSON data
            cedar_policy_core::ast::EntityType::Concrete(name) => {
                EntityTypeDescription::new(self.schema, name)
            }
        }
    }

    fn action(&self, action: &EntityUID) -> Option<Arc<cedar_policy_core::ast::Entity>> {
        self.actions.get(action).map(Arc::clone)
    }

    fn entity_types_with_basename<'b>(
        &'b self,
        basename: &'b Id,
    ) -> Box<dyn Iterator<Item = EntityType> + 'b> {
        Box::new(self.schema.entity_types().filter_map(move |(name, _)| {
            if name.basename() == basename {
                Some(EntityType::Concrete(name.clone()))
            } else {
                None
            }
        }))
    }
}

/// Struct which carries enough information that it can impl Core's `EntityTypeDescription`
pub struct EntityTypeDescription {
    /// Core `EntityType` this is describing
    core_type: cedar_policy_core::ast::EntityType,
    /// Contains most of the schema information for this entity type
    validator_type: ValidatorEntityType,
    /// Allowed parent types for this entity type. (As of this writing, this
    /// information is not contained in the `validator_type` by itself.)
    allowed_parent_types: Arc<HashSet<cedar_policy_core::ast::EntityType>>,
}

impl EntityTypeDescription {
    /// Create a description of the given type in the given schema.
    /// Returns `None` if the given type is not in the given schema.
    pub fn new(schema: &ValidatorSchema, type_name: &Name) -> Option<Self> {
        Some(Self {
            core_type: cedar_policy_core::ast::EntityType::Concrete(type_name.clone()),
            validator_type: schema.get_entity_type(type_name).cloned()?,
            allowed_parent_types: {
                let mut set = HashSet::new();
                for (possible_parent_typename, possible_parent_et) in &schema.entity_types {
                    if possible_parent_et.descendants.contains(type_name) {
                        set.insert(cedar_policy_core::ast::EntityType::Concrete(
                            possible_parent_typename.clone(),
                        ));
                    }
                }
                Arc::new(set)
            },
        })
    }
}

impl cedar_policy_core::entities::EntityTypeDescription for EntityTypeDescription {
    fn entity_type(&self) -> cedar_policy_core::ast::EntityType {
        self.core_type.clone()
    }

    fn attr_type(&self, attr: &str) -> Option<cedar_policy_core::entities::SchemaType> {
        let attr_type: &crate::types::Type = &self.validator_type.attr(attr)?.attr_type;
        // This converts a type from a schema into the representation of schema
        // types used by core. `attr_type` is taken from a `ValidatorEntityType`
        // which was constructed from a schema.
        // PANIC SAFETY: see above
        #[allow(clippy::expect_used)]
        let core_schema_type: cedar_policy_core::entities::SchemaType = attr_type
            .clone()
            .try_into()
            .expect("failed to convert validator type into Core SchemaType");
        debug_assert!(attr_type.is_consistent_with(&core_schema_type));
        Some(core_schema_type)
    }

    fn required_attrs<'s>(&'s self) -> Box<dyn Iterator<Item = SmolStr> + 's> {
        Box::new(
            self.validator_type
                .attributes
                .iter()
                .filter(|(_, ty)| ty.is_required)
                .map(|(attr, _)| attr.clone()),
        )
    }

    fn allowed_parent_types(&self) -> Arc<HashSet<cedar_policy_core::ast::EntityType>> {
        Arc::clone(&self.allowed_parent_types)
    }
}

/// Struct which carries enough information that it can impl Core's
/// `ContextSchema` INVARIANT: The `Type` stored in this struct must be
/// representable as a `SchemaType` to avoid panicking in `context_type`.
struct ContextSchema(crate::types::Type);

/// A `Type` contains all the information we need for a Core `ContextSchema`.
impl cedar_policy_core::entities::ContextSchema for ContextSchema {
    fn context_type(&self) -> cedar_policy_core::entities::SchemaType {
        // PANIC SAFETY: By `ContextSchema` invariant, `self.0` is representable as a schema type.
        #[allow(clippy::expect_used)]
        self.0
            .clone()
            .try_into()
            .expect("failed to convert validator type into Core SchemaType")
    }
}

/// Contains entity type information for use by the validator. The contents of
/// the struct are the same as the schema entity type structure, but the
/// `member_of` relation is reversed to instead be `descendants`.
#[derive(Clone, Debug, Serialize)]
pub struct ValidatorEntityType {
    /// The name of the entity type.
    pub(crate) name: Name,

    /// The set of entity types that can be members of this entity type. When
    /// this structure is initially constructed, the field will contain direct
    /// children, but it will be updated to contain the closure of all
    /// descendants before it is used in any validation.
    pub descendants: HashSet<Name>,

    /// The attributes associated with this entity. Keys are the attribute
    /// identifiers while the values are the type of the attribute.
    pub(crate) attributes: Attributes,
}

impl ValidatorEntityType {
    /// Get the type of the attribute with the given name, if it exists
    pub fn attr(&self, attr: &str) -> Option<&AttributeType> {
        self.attributes.get_attr(attr)
    }

    /// An iterator over the attributes of this entity
    pub fn attributes(&self) -> impl Iterator<Item = (&SmolStr, &AttributeType)> {
        self.attributes.iter()
    }
}

impl TCNode<Name> for ValidatorEntityType {
    fn get_key(&self) -> Name {
        self.name.clone()
    }

    fn add_edge_to(&mut self, k: Name) {
        self.descendants.insert(k);
    }

    fn out_edges(&self) -> Box<dyn Iterator<Item = &Name> + '_> {
        Box::new(self.descendants.iter())
    }

    fn has_edge_to(&self, e: &Name) -> bool {
        self.descendants.contains(e)
    }
}

/// Contains information about actions used by the validator.  The contents of
/// the struct are the same as the schema entity type structure, but the
/// `member_of` relation is reversed to instead be `descendants`.
#[derive(Clone, Debug, Serialize)]
pub struct ValidatorActionId {
    /// The name of the action.
    pub(crate) name: EntityUID,

    /// The principals and resources that the action can be applied to.
    #[serde(rename = "appliesTo")]
    pub(crate) applies_to: ValidatorApplySpec,

    /// The set of actions that can be members of this action. When this
    /// structure is initially constructed, the field will contain direct
    /// children, but it will be updated to contain the closure of all
    /// descendants before it is used in any validation.
    pub(crate) descendants: HashSet<EntityUID>,

    /// The context attributes associated with this action. Keys are the context
    /// attribute identifiers while the values are the type of the attribute.
    pub(crate) context: Attributes,

    /// The attribute types for this action, used for typechecking.
    pub(crate) attribute_types: Attributes,

    /// The actual attribute value for this action, used to construct an
    /// `Entity` for this action. Could also be used for more precise
    /// typechecking by partial evaluation.
    pub(crate) attributes: HashMap<SmolStr, RestrictedExpr>,
}

impl ValidatorActionId {
    /// An iterator over the attributes of this action's required context
    pub fn context(&self) -> impl Iterator<Item = (&SmolStr, &AttributeType)> {
        self.context.iter()
    }
}

impl TCNode<EntityUID> for ValidatorActionId {
    fn get_key(&self) -> EntityUID {
        self.name.clone()
    }

    fn add_edge_to(&mut self, k: EntityUID) {
        self.descendants.insert(k);
    }

    fn out_edges(&self) -> Box<dyn Iterator<Item = &EntityUID> + '_> {
        Box::new(self.descendants.iter())
    }

    fn has_edge_to(&self, e: &EntityUID) -> bool {
        self.descendants.contains(e)
    }
}

/// The principals and resources that an action can be applied to.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ValidatorApplySpec {
    /// The principal entity types the action can be applied to. This set may
    /// be a singleton set containing the unspecified entity type when the
    /// `principalTypes` list is omitted in the schema. A non-singleton set
    /// shouldn't contain the unspecified entity type, but validation will give
    /// the same success/failure result as when it is the only element of the
    /// set, perhaps with extra type errors.
    #[serde(rename = "principalApplySpec")]
    principal_apply_spec: HashSet<EntityType>,

    /// The resource entity types the action can be applied to. See comments on
    /// `principal_apply_spec` about the unspecified entity type.
    #[serde(rename = "resourceApplySpec")]
    resource_apply_spec: HashSet<EntityType>,
}

impl ValidatorApplySpec {
    /// Create an apply spec for an action that can only be applied to some
    /// specific entities.
    pub(crate) fn new(
        principal_apply_spec: HashSet<EntityType>,
        resource_apply_spec: HashSet<EntityType>,
    ) -> Self {
        Self {
            principal_apply_spec,
            resource_apply_spec,
        }
    }

    /// Get the applicable principal types for this spec.
    pub(crate) fn applicable_principal_types(&self) -> impl Iterator<Item = &EntityType> {
        self.principal_apply_spec.iter()
    }

    /// Get the applicable resource types for this spec.
    pub(crate) fn applicable_resource_types(&self) -> impl Iterator<Item = &EntityType> {
        self.resource_apply_spec.iter()
    }
}

/// This trait configures what sort of entity (principals, actions, or resources)
/// are returned by the function `get_entities_satisfying_constraint`.
pub(crate) trait HeadVar<K>: Copy {
    /// For a validator, get the known entities for this sort of head variable.
    /// This is all entity types (for principals and resources), or actions ids
    /// (for actions) that appear in the service description.
    fn get_known_vars<'a>(
        &self,
        schema: &'a ValidatorSchema,
    ) -> Box<dyn Iterator<Item = &'a K> + 'a>;

    /// Extract the relevant component of an entity uid. This is the entity type
    /// for principals and resources, and the entity id for actions.
    fn get_euid_component(&self, euid: EntityUID) -> Option<K>;

    /// Extract the relevant component of an entity uid if the entity uid is in
    /// the schema. Otherwise return None.
    fn get_euid_component_if_present(&self, schema: &ValidatorSchema, euid: EntityUID)
        -> Option<K>;

    /// Get and iterator containing the valid descendants of an entity, if that
    /// entity exists in the schema. Otherwise None.
    fn get_descendants_if_present<'a>(
        &self,
        schema: &'a ValidatorSchema,
        euid: EntityUID,
    ) -> Option<Box<dyn Iterator<Item = &'a K> + 'a>>;
}

/// Used to have `get_entities_satisfying_constraint` return the
/// `EntityTypeNames` for either principals or resources satisfying the head
/// constraints.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PrincipalOrResourceHeadVar {
    PrincipalOrResource,
}

impl HeadVar<Name> for PrincipalOrResourceHeadVar {
    fn get_known_vars<'a>(
        &self,
        schema: &'a ValidatorSchema,
    ) -> Box<dyn Iterator<Item = &'a Name> + 'a> {
        Box::new(schema.known_entity_types())
    }

    fn get_euid_component(&self, euid: EntityUID) -> Option<Name> {
        let (ty, _) = euid.components();
        match ty {
            EntityType::Unspecified => None,
            EntityType::Concrete(name) => Some(name),
        }
    }

    fn get_euid_component_if_present(
        &self,
        schema: &ValidatorSchema,
        euid: EntityUID,
    ) -> Option<Name> {
        let euid_component = self.get_euid_component(euid)?;
        if schema.is_known_entity_type(&euid_component) {
            Some(euid_component)
        } else {
            None
        }
    }

    fn get_descendants_if_present<'a>(
        &self,
        schema: &'a ValidatorSchema,
        euid: EntityUID,
    ) -> Option<Box<dyn Iterator<Item = &'a Name> + 'a>> {
        let euid_component = self.get_euid_component(euid)?;
        match schema.get_entity_type(&euid_component) {
            Some(entity_type) => Some(Box::new(entity_type.descendants.iter())),
            None => None,
        }
    }
}

/// Used to have `get_entities_satisfying_constraint` return the
/// `ActionIdNames` for actions satisfying the head constraints
#[derive(Debug, Clone, Copy)]
pub(crate) enum ActionHeadVar {
    Action,
}

impl HeadVar<EntityUID> for ActionHeadVar {
    fn get_known_vars<'a>(
        &self,
        schema: &'a ValidatorSchema,
    ) -> Box<dyn Iterator<Item = &'a EntityUID> + 'a> {
        Box::new(schema.known_action_ids())
    }

    fn get_euid_component(&self, euid: EntityUID) -> Option<EntityUID> {
        Some(euid)
    }

    fn get_euid_component_if_present(
        &self,
        schema: &ValidatorSchema,
        euid: EntityUID,
    ) -> Option<EntityUID> {
        let euid_component = self.get_euid_component(euid)?;
        if schema.is_known_action_id(&euid_component) {
            Some(euid_component)
        } else {
            None
        }
    }

    fn get_descendants_if_present<'a>(
        &self,
        schema: &'a ValidatorSchema,
        euid: EntityUID,
    ) -> Option<Box<dyn Iterator<Item = &'a EntityUID> + 'a>> {
        let euid_component = self.get_euid_component(euid)?;
        match schema.get_action_id(&euid_component) {
            Some(action_id) => Some(Box::new(action_id.descendants.iter())),
            None => None,
        }
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
            )?,
        ])])
    }
}

#[cfg(test)]
mod test {
    use std::{collections::BTreeMap, str::FromStr};

    use crate::types::Type;

    use cedar_policy_core::parser::err::{ParseError, ToASTError};
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
        match schema {
            Ok(_) => panic!("from_schema_file should have failed"),
            Err(SchemaError::CycleInActionHierarchy) => (), // expected result
            e => panic!("Unexpected error from from_schema_file: {:?}", e),
        }
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
        match schema {
            Ok(x) => {
                println!("{:?}", x);
                panic!("from_schema_file should have failed");
            }
            Err(SchemaError::CycleInActionHierarchy) => (), // expected result
            e => panic!("Unexpected error from from_schema_file: {:?}", e),
        }
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
            vec![&EntityType::Concrete(user_entity_type.clone())]
        );
        assert_eq!(
            apply_spec.applicable_resource_types().collect::<Vec<_>>(),
            vec![&EntityType::Concrete(photo_entity_type.clone())]
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
            HashSet::from([&EntityType::Concrete("Fiz::Buz".parse().unwrap())])
        );
        assert_eq!(
            baz.applies_to
                .applicable_resource_types()
                .collect::<HashSet<_>>(),
            HashSet::from([&EntityType::Concrete("Fiz::Baz".parse().unwrap())])
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
    #[should_panic]
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
        let schema = ValidatorSchema::from_schema_fragments([fragment1, fragment2]).unwrap();

        assert_eq!(
            schema.entity_types.iter().next().unwrap().1.attributes,
            Attributes::with_required_attributes([("a".into(), Type::primitive_long())])
        );
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
        let expected_err = ParseError::ToAST(ToASTError::NonNormalizedString {
            kind: "Id",
            src: "User // comment".to_string(),
            normalized_src: "User".to_string(),
        })
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
        let expected_err = ParseError::ToAST(ToASTError::NonNormalizedString {
            kind: "Name",
            src: "ABC     :: //comment \n XYZ  ".to_string(),
            normalized_src: "ABC::XYZ".to_string(),
        })
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
            &Entity::new(action_uid, HashMap::new(), HashSet::new())
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
            &Entity::new(
                view_photo_uid,
                HashMap::new(),
                HashSet::from([view_uid.clone(), read_uid.clone()])
            )
        );

        let view_entity = actions.entity(&view_uid);
        assert_eq!(
            view_entity.unwrap(),
            &Entity::new(view_uid, HashMap::new(), HashSet::from([read_uid.clone()]))
        );

        let read_entity = actions.entity(&read_uid);
        assert_eq!(
            read_entity.unwrap(),
            &Entity::new(read_uid, HashMap::new(), HashSet::new())
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
                HashSet::new()
            )
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
            .find(|e| e.uid() == r#"ExampleCo::Personnel::Action::"viewPhoto""#.parse().unwrap())
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
            .find(|e| e.uid() == r#"ExampleCo::Personnel::Action::"viewPhoto""#.parse().unwrap())
            .unwrap();
        let ancestors = view_photo.ancestors().collect::<Vec<_>>();
        let read = ancestors[0];
        assert_eq!(read.eid().to_string(), "read");
        assert_eq!(
            read.entity_type().to_string(),
            "ExampleCo::Personnel::Action"
        );
    }
}
