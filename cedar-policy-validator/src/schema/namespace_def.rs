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

use std::collections::{BTreeMap, HashMap, HashSet};

use cedar_policy_core::{
    ast::{
        Eid, EntityAttrEvaluationError, EntityType, EntityUID, Id, Name,
        PartialValueSerializedAsExpr,
    },
    entities::{CedarValueJson, JsonDeserializationErrorContext},
    evaluator::RestrictedEvaluator,
    extensions::Extensions,
    FromNormalizedStr,
};
use smol_str::{SmolStr, ToSmolStr};

use super::ValidatorApplySpec;
use crate::{
    err::*,
    is_builtin_type_name, schema_file_format,
    types::{AttributeType, Attributes, OpenTag, Type},
    ActionBehavior, ActionEntityUID, ActionType, NamespaceDefinition, SchemaType,
    SchemaTypeVariant, TypeOfAttribute,
};
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
    pub(super) type_defs: TypeDefs,
    /// The preprocessed entity type declarations from the schema fragment json.
    pub(super) entity_types: EntityTypesDef,
    /// The preprocessed action declarations from the schema fragment json.
    pub(super) actions: ActionsDef,
}

/// Holds a map from `Name`s of common type definitions to their corresponding
/// `SchemaType`. Note that the schema type should have all common type
/// references fully qualified.
#[derive(Debug)]
pub struct TypeDefs {
    pub(super) type_defs: HashMap<Name, SchemaType>,
}

/// Entity type declarations held in a `ValidatorNamespaceDef`. Entity type
/// parents and attributes may reference undeclared entity types.
#[derive(Debug)]
pub struct EntityTypesDef {
    pub(super) entity_types: HashMap<Name, EntityTypeFragment>,
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
    pub(super) attributes: WithUnresolvedTypeDefs<Type>,
    /// The direct parent entity types for this entity type come from the
    /// `memberOfTypes` list. These types might be declared in a different
    /// namespace, so we will check if they are declared in any fragment when
    /// constructing a `ValidatorSchema`.
    pub(super) parents: HashSet<Name>,
}

/// Action declarations held in a `ValidatorNamespaceDef`. Entity types
/// referenced here do not need to be declared in the schema.
#[derive(Debug)]
pub struct ActionsDef {
    pub(super) actions: HashMap<EntityUID, ActionFragment>,
}

#[derive(Debug)]
pub struct ActionFragment {
    /// The type of the context record for this actions. The types is wrapped in
    /// a `WithUnresolvedTypeDefs` because it may refer to common types which
    /// are not defined in this fragment.
    pub(super) context: WithUnresolvedTypeDefs<Type>,
    /// The principals and resources that an action can be applied to.
    pub(super) applies_to: ValidatorApplySpec,
    /// The direct parent action entities for this action.
    pub(super) parents: HashSet<EntityUID>,
    /// The types for the attributes defined for this actions entity.
    pub(super) attribute_types: Attributes,
    /// The values for the attributes defined for this actions entity, stored
    /// separately so that we can later extract use these values to construct
    /// the actual `Entity` objects defined by the schema.
    pub(super) attributes: BTreeMap<SmolStr, PartialValueSerializedAsExpr>,
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
        ValidatorNamespaceDef::from_namespace_definition(
            None,
            self,
            ActionBehavior::default(),
            Extensions::all_available(),
        )
    }
}

impl ValidatorNamespaceDef {
    // We need to treat this as if it had `pub(crate)` visibility to avoid sharing
    // the file format. However, our fuzzing library currently needs it to be public.
    /// Construct a new `ValidatorSchema` from the underlying `SchemaFragment`.
    pub fn from_namespace_definition(
        namespace: Option<Name>,
        namespace_def: NamespaceDefinition,
        action_behavior: ActionBehavior,
        extensions: Extensions<'_>,
    ) -> Result<ValidatorNamespaceDef> {
        // Check that each entity types and action is only declared once.
        let mut e_types_ids: HashSet<Id> = HashSet::new();
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

        // Return early with an error if actions cannot be in groups or have
        // attributes, but the schema contains action groups or attributes.
        Self::check_action_behavior(&namespace_def, action_behavior)?;

        // Convert the type defs, actions and entity types from the schema file
        // into the representation used by the validator.
        let type_defs = Self::build_type_defs(namespace_def.common_types, namespace.as_ref())?;
        let actions =
            Self::build_action_ids(namespace_def.actions, namespace.as_ref(), extensions)?;
        let entity_types =
            Self::build_entity_types(namespace_def.entity_types, namespace.as_ref())?;

        Ok(ValidatorNamespaceDef {
            namespace,
            type_defs,
            entity_types,
            actions,
        })
    }

    fn build_type_defs(
        schema_file_type_def: HashMap<Id, SchemaType>,
        schema_namespace: Option<&Name>,
    ) -> Result<TypeDefs> {
        let type_defs = schema_file_type_def
            .into_iter()
            .map(|(name, schema_ty)| -> Result<_> {
                let name_str = name.clone().into_smolstr();
                if is_builtin_type_name(&name_str) {
                    return Err(SchemaError::DuplicateCommonType(name_str.to_string()));
                }
                let name =
                    Name::from(name).prefix_namespace_if_unqualified(schema_namespace.cloned());
                Ok((
                    name,
                    schema_ty
                        .prefix_common_type_references_with_namespace(schema_namespace.cloned()),
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;
        Ok(TypeDefs { type_defs })
    }

    // Transform the schema data structures for entity types into the structures
    // used internally by the validator. This is mostly accomplished by directly
    // copying data between fields.
    fn build_entity_types(
        schema_files_types: HashMap<Id, schema_file_format::EntityType>,
        schema_namespace: Option<&Name>,
    ) -> Result<EntityTypesDef> {
        Ok(EntityTypesDef {
            entity_types: schema_files_types
                .into_iter()
                .map(|(id, entity_type)| -> Result<_> {
                    let name =
                        Name::from(id).prefix_namespace_if_unqualified(schema_namespace.cloned());

                    let parents = entity_type
                        .member_of_types
                        .into_iter()
                        .map(|ty| ty.prefix_namespace_if_unqualified(schema_namespace.cloned()))
                        .collect();

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

    // Helper to get types from `CedarValueJson`s. Currently doesn't support all
    // `CedarValueJson` types. Note: If this function is extended to cover move
    // `CedarValueJson`s, we must update `convert_attr_jsonval_map_to_attributes` to
    // handle errors that may occur when parsing these values. This will require
    // a breaking change in the `SchemaError` type in the public API.
    fn jsonval_to_type_helper(v: &CedarValueJson, action_id: &EntityUID) -> Result<Type> {
        match v {
            CedarValueJson::Bool(_) => Ok(Type::primitive_boolean()),
            CedarValueJson::Long(_) => Ok(Type::primitive_long()),
            CedarValueJson::String(_) => Ok(Type::primitive_string()),
            CedarValueJson::Record(r) => {
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
            CedarValueJson::Set(v) => match v.first() {
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
            CedarValueJson::EntityEscape { __entity: _ } => {
                Err(SchemaError::UnsupportedActionAttribute(
                    action_id.clone(),
                    "entity escape (`__entity`)".to_owned(),
                ))
            }
            CedarValueJson::ExprEscape { __expr: _ } => {
                Err(SchemaError::UnsupportedActionAttribute(
                    action_id.clone(),
                    "expression escape (`__expr`)".to_owned(),
                ))
            }
            CedarValueJson::ExtnEscape { __extn: _ } => {
                Err(SchemaError::UnsupportedActionAttribute(
                    action_id.clone(),
                    "extension function escape (`__extn`)".to_owned(),
                ))
            }
            CedarValueJson::Null => Err(SchemaError::UnsupportedActionAttribute(
                action_id.clone(),
                "null".to_owned(),
            )),
        }
    }

    //Convert jsonval map to attributes
    fn convert_attr_jsonval_map_to_attributes(
        m: HashMap<SmolStr, CedarValueJson>,
        action_id: &EntityUID,
        extensions: Extensions<'_>,
    ) -> Result<(Attributes, BTreeMap<SmolStr, PartialValueSerializedAsExpr>)> {
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
                    SchemaError::ActionAttrEval(EntityAttrEvaluationError {
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

    // Transform the schema data structures for actions into the structures used
    // internally by the validator. This is mostly accomplished by directly
    // copying data between fields.
    fn build_action_ids(
        schema_file_actions: HashMap<SmolStr, ActionType>,
        schema_namespace: Option<&Name>,
        extensions: Extensions<'_>,
    ) -> Result<ActionsDef> {
        Ok(ActionsDef {
            actions: schema_file_actions
                .into_iter()
                .map(|(action_id_str, action_type)| -> Result<_> {
                    let action_id = Self::parse_action_id_with_namespace(
                        &ActionEntityUID::default_type(action_id_str),
                        schema_namespace,
                    );

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
                        Self::parse_apply_spec_type_list(principal_types, schema_namespace),
                        Self::parse_apply_spec_type_list(resource_types, schema_namespace),
                    );

                    let context = Self::try_schema_type_into_validator_type(
                        schema_namespace,
                        context.into_inner(),
                    )?;

                    let parents = action_type
                        .member_of
                        .unwrap_or_default()
                        .iter()
                        .map(|parent| {
                            Self::parse_action_id_with_namespace(parent, schema_namespace)
                        })
                        .collect::<HashSet<_>>();

                    let (attribute_types, attributes) =
                        Self::convert_attr_jsonval_map_to_attributes(
                            action_type.attributes.unwrap_or_default(),
                            &action_id,
                            extensions,
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
            .any(|(name, _)| name.to_smolstr() == ACTION_ENTITY_TYPE)
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
        types: Option<Vec<Name>>,
        namespace: Option<&Name>,
    ) -> HashSet<EntityType> {
        types
            .map(|types| {
                types
                    .iter()
                    // Parse each type name string into a `Name`, generating an
                    // `EntityTypeParseError` when the string is not a valid
                    // name.
                    .map(|ty| {
                        EntityType::Specified(
                            ty.prefix_namespace_if_unqualified(namespace.cloned()),
                        )
                    })
                    // Fail if any of the types failed.
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_else(|| HashSet::from([EntityType::Unspecified]))
    }

    /// Take an action identifier as a string and use it to construct an
    /// EntityUID for that action. The entity type of the action will always
    /// have the base type `Action`. The type will be qualified with any
    /// namespace provided in the `namespace` argument or with the namespace
    /// inside the ActionEntityUID if one is present.
    fn parse_action_id_with_namespace(
        action_id: &ActionEntityUID,
        namespace: Option<&Name>,
    ) -> EntityUID {
        let namespaced_action_type = if let Some(action_ty) = &action_id.ty {
            action_ty.prefix_namespace_if_unqualified(namespace.cloned())
        } else {
            // PANIC SAFETY: The constant ACTION_ENTITY_TYPE is valid entity type.
            #[allow(clippy::expect_used)]
            let id = Id::from_normalized_str(ACTION_ENTITY_TYPE).expect(
                "Expected that the constant ACTION_ENTITY_TYPE would be a valid entity type.",
            );
            match namespace {
                Some(namespace) => Name::type_in_namespace(id, namespace.clone(), None),
                None => Name::unqualified_name(id),
            }
        };
        EntityUID::from_components(namespaced_action_type, Eid::new(action_id.id.clone()), None)
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
                if cfg!(not(feature = "partial-validate")) && additional_attributes {
                    Err(SchemaError::UnsupportedFeature(
                        UnsupportedFeature::OpenRecordsAndEntities,
                    ))
                } else {
                    Ok(
                        Self::parse_record_attributes(default_namespace, attributes)?.map(
                            move |attrs| {
                                Type::record_with_attributes(
                                    attrs,
                                    if additional_attributes {
                                        OpenTag::OpenAttributes
                                    } else {
                                        OpenTag::ClosedAttributes
                                    },
                                )
                            },
                        ),
                    )
                }
            }
            SchemaType::Type(SchemaTypeVariant::Entity { name }) => {
                Ok(Type::named_entity_reference(
                    name.prefix_namespace_if_unqualified(default_namespace.cloned()),
                )
                .into())
            }
            SchemaType::Type(SchemaTypeVariant::Extension { name }) => {
                let extension_type_name = Name::unqualified_name(name);
                Ok(Type::extension(extension_type_name).into())
            }
            SchemaType::TypeDef { type_name } => {
                let defined_type_name =
                    type_name.prefix_namespace_if_unqualified(default_namespace.cloned());
                Ok(WithUnresolvedTypeDefs::new(move |typ_defs| {
                    typ_defs.get(&defined_type_name).cloned().ok_or(
                        SchemaError::UndeclaredCommonTypes(HashSet::from([
                            defined_type_name.to_string()
                        ])),
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
