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
//! This module defines the ADTs that represent the symbolic environment.
//! The environment consists of a symbolic request, entity store, and action store.
//!
//! A symbolic environment is _literal_ when it consists of literal terms and
//! interpreted functions (UDFs).

use crate::symcc::op;
use crate::symcc::tags::SymTags;
use crate::symcc::term::{Term, TermPrim, TermVar, TermX};
use crate::symcc::term_type::TermType;
use crate::symcc::type_abbrevs::*;
use crate::symcc::{
    function::{
        self,
        UnaryFunction::{self, Udf, Uuf},
    },
    result,
};
use cedar_policy_core::validator::ValidatorSchema;
use cedar_policy_core::validator::{
    types::{Attributes, EntityRecordKind, OpenTag, Type},
    ValidatorActionId,
};
use cedar_policy_core::validator::{ValidatorEntityType, ValidatorEntityTypeKind};
use smol_str::SmolStr;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;
use std::sync::Arc;

/// A symbolic request is analogous to a concrete request. It binds
/// request variables to Terms.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct SymRequest {
    pub principal: Term,
    pub action: Term,
    pub resource: Term,
    pub context: Term,
}

impl SymRequest {
    #[cfg(test)]
    pub fn empty_sym_req() -> Self {
        use crate::symcc::term::TermX;

        SymRequest {
            principal: Term::new(TermX::Var(TermVar {
                id: "principal".to_string(),
                ty: TermType::Bool,
            })),
            action: Term::new(TermX::Var(TermVar {
                id: "action".to_string(),
                ty: TermType::Bool,
            })),
            resource: Term::new(TermX::Var(TermVar {
                id: "resource".to_string(),
                ty: TermType::Bool,
            })),
            context: Term::new(TermX::Record(BTreeMap::new())),
        }
    }

    pub fn is_literal(&self) -> bool {
        self.principal.is_literal()
            && self.action.is_literal()
            && self.resource.is_literal()
            && self.context.is_literal()
    }
}

// A symbolic entity store is analogous to the concrete entity store. The concrete
// entity store is a map from EntityUIDs to Record values. The symbolic entity
// store partitions this map into multiple maps:  one for each entity type. These
// maps are represented as unary functions from entities to records. The functions
// can be uninterpreted or defined. The type-based partition is required for
// reduction to SMT. The symbolic store also carries a representation of the
// `entityIn` relation on entities. The symbolic store partitions this relation
// into multiple maps, one for each pair of an entity type and its ancestor type.

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct SymEntityData {
    pub attrs: UnaryFunction,
    pub ancestors: BTreeMap<EntityType, UnaryFunction>,
    /// Specifies EIDs of enum members, if applicable
    pub members: Option<BTreeSet<String>>,
    pub tags: Option<SymTags>,
}

impl SymEntityData {
    pub fn is_literal(&self) -> bool {
        self.attrs.is_literal()
            && self.ancestors.values().all(|uf| uf.is_literal())
            && self.tags.as_ref().is_none_or(|t| t.is_literal())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct SymEntities(pub BTreeMap<EntityType, SymEntityData>);

impl Deref for SymEntities {
    type Target = BTreeMap<EntityType, SymEntityData>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SymEntities {
    pub fn attrs(&self, ety: &EntityType) -> Option<&UnaryFunction> {
        Some(&self.get(ety)?.attrs)
    }

    pub fn ancestors(&self, ety: &EntityType) -> Option<&BTreeMap<EntityType, UnaryFunction>> {
        Some(&self.get(ety)?.ancestors)
    }

    pub fn ancestors_of_type(
        &self,
        ety: &EntityType,
        anc_ty: &EntityType,
    ) -> Option<&UnaryFunction> {
        self.ancestors(ety)?.get(anc_ty)
    }

    pub fn is_valid_entity_type(&self, ety: &EntityType) -> bool {
        self.contains_key(ety)
    }

    pub fn is_valid_entity_uid(&self, uid: &EntityUID) -> bool {
        match self.get(uid.type_name()) {
            Some(d) => {
                if let Some(eids) = &d.members {
                    eids.contains(AsRef::<str>::as_ref(uid.id()))
                } else {
                    true
                }
            }
            None => false,
        }
    }

    pub fn tags(&self, ety: &EntityType) -> Option<&Option<SymTags>> {
        self.get(ety).map(|sed| &sed.tags)
    }

    pub fn is_literal(&self) -> bool {
        self.values().all(|d| d.is_literal())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct SymEnv {
    pub request: SymRequest,
    pub entities: SymEntities,
}

impl SymEnv {
    pub fn is_literal(&self) -> bool {
        self.request.is_literal() && self.entities.is_literal()
    }
}

// ----- Functions for constructing symbolic input from a schema -----
impl SymEntityData {
    pub fn of_entity_type(
        ety: &EntityType,
        validator_ety: &ValidatorEntityType,
        schema: &ValidatorSchema,
    ) -> Result<Self, result::Error> {
        match EntitySchemaEntry::of_schema(ety, validator_ety, schema) {
            // Corresponds to `SymEntityData.ofStandardEntityType` in Lean
            EntitySchemaEntry::Standard(sch) => {
                let attrs_uuf = Uuf(op::Uuf {
                    id: format!("attrs[{ety}]"),
                    arg: entity(ety.clone()), // more efficient than the Lean: avoids `TermType::of_type()` and constructs the `TermType` directly
                    out: TermType::of_type(record(sch.attrs))?,
                });
                let ancs_uuf = |anc_ty: &EntityType| {
                    Uuf(op::Uuf {
                        id: format!("ancs[{ety}, {anc_ty}]"),
                        arg: entity(ety.clone()), // more efficient than the Lean: avoids `TermType::of_type()` and constructs the `TermType` directly
                        out: TermType::set_of(entity(anc_ty.clone())), // more efficient than the Lean: avoids `TermType::of_type()` and constructs the `TermType` directly
                    })
                };
                let sym_tags = |tag_ty: Type| -> Result<SymTags, result::Error> {
                    Ok(SymTags {
                        keys: Uuf(op::Uuf {
                            id: format!("tagKeys[{ety}]"),
                            arg: entity(ety.clone()), // more efficient than the Lean: avoids `TermType::of_type()` and constructs the `TermType` directly
                            out: TermType::set_of(TermType::String),
                        }),
                        vals: Uuf(op::Uuf {
                            id: format!("tagVals[{ety}]"),
                            arg: TermType::tag_for(ety.clone()), // record representing the pair type (ety, .string)
                            out: TermType::of_type(tag_ty)?,
                        }),
                    })
                };

                Ok(SymEntityData {
                    attrs: attrs_uuf,
                    ancestors: sch
                        .ancestors
                        .into_iter()
                        .map(|anc_ty| {
                            let uuf = ancs_uuf(&anc_ty);
                            (anc_ty, uuf)
                        })
                        .collect(),
                    members: None,
                    tags: sch.tags.map(sym_tags).transpose()?,
                })
            }

            // Corresponds to `SymEntityData.ofEnumEntityType` in Lean
            EntitySchemaEntry::Enum(eids) => {
                let attrs_udf = Udf(function::Udf {
                    arg: entity(ety.clone()),
                    out: TermType::Record {
                        rty: Arc::new(BTreeMap::new()),
                    },
                    table: BTreeMap::new(),
                    default: Term::new(TermX::Record(BTreeMap::new())),
                });
                Ok(SymEntityData {
                    attrs: attrs_udf,
                    ancestors: BTreeMap::new(),
                    members: Some(eids.iter().map(|s| s.to_string()).collect()),
                    tags: None,
                })
            }
        }
    }

    fn of_action_type<'a>(
        act_ty: &EntityType,
        act_tys: impl IntoIterator<Item = &'a EntityType>,
        schema: &ValidatorSchema,
    ) -> Self {
        let sch = ActionSchemaEntries::of_schema(schema);
        let attrs_udf = Udf(function::Udf {
            arg: entity(act_ty.clone()),
            out: TermType::Record {
                rty: Arc::new(BTreeMap::new()),
            },
            table: BTreeMap::new(),
            default: Term::new(TermX::Record(BTreeMap::new())),
        });
        let term_of_type = |ety: EntityType, uid: EntityUID| -> Option<Term> {
            if uid.type_name() == &ety {
                Some(Term::new(TermX::Prim(TermPrim::Entity(uid))))
            } else {
                None
            }
        };
        let ancs_term = |anc_ty: &EntityType, ancs: &BTreeSet<EntityUID>| -> Term {
            Term::new(TermX::Set {
                elts: ancs.iter()
                    .filter_map(|anc| term_of_type(anc_ty.clone(), anc.clone()))
                    .collect(),
                elts_ty: TermType::set_of(entity(anc_ty.clone())),
            })
        };
        let ancs_udf = |anc_ty: &EntityType| -> UnaryFunction {
            Udf(function::Udf {
                arg: entity(act_ty.clone()),
                out: TermType::set_of(entity(anc_ty.clone())),
                table: sch
                    .iter()
                    .filter_map(|(uid, entry)| {
                        Some((
                            term_of_type(act_ty.clone(), uid.clone())?,
                            ancs_term(anc_ty, &entry.ancestors),
                        ))
                    })
                    .collect(),
                default: Term::new(TermX::Set {
                    elts: BTreeSet::new(),
                    elts_ty: TermType::set_of(entity(anc_ty.clone())),
                }),
            })
        };
        let acts = sch
            .iter()
            .filter_map(|(uid, _)| {
                if uid.type_name() == act_ty {
                    Some(<EntityID as AsRef<str>>::as_ref(uid.id()).into())
                } else {
                    None
                }
            })
            .collect();
        SymEntityData {
            attrs: attrs_udf,
            ancestors: act_tys
                .into_iter()
                .map(|anc_ty| {
                    let udf = ancs_udf(anc_ty);
                    (anc_ty.clone(), udf)
                })
                .collect(),
            members: Some(acts),
            tags: None,
        }
    }
}

impl SymEntities {
    /// Creates symbolic entities for the given schema.
    ///
    /// This function assumes that the schemas are well-formed in the following
    /// sense:
    /// * All entity types that appear in the attributes or ancestors fields of `ets` are
    ///   declared either in `ets` or `acts`.
    /// * All entity types that appear in the ancestors fields of `acts` are declared in `acts`.
    ///
    /// An entity type is declared in `ets` if it's a key in the underlying map; it's
    /// declared in `acts` if it's the type of a key in the underlying map. This
    /// function also assumes `ets` and `ats` declare disjoint sets of types.
    ///
    /// This function assumes that no entity types have tags, and that action types
    /// have no attributes.
    pub fn of_schema(schema: &ValidatorSchema) -> Result<Self, result::Error> {
        let e_data = schema.entity_types().map(|vdtr_ety| {
            let ety = core_entity_type_into_entity_type(vdtr_ety.name());
            match SymEntityData::of_entity_type(ety, vdtr_ety, schema) {
                Ok(sym_edata) => Ok((ety.clone(), sym_edata)),
                Err(e) => Err(e),
            }
        });
        // PANIC SAFETY
        #[allow(
            clippy::expect_used,
            reason = "ValidatorSchema::action_entities should not error"
        )]
        let acts = schema
            .action_entities()
            .expect("Schema should have action entities");
        let act_tys: BTreeSet<&EntityType> = acts
            .iter()
            .map(|act| core_entity_type_into_entity_type(act.uid().entity_type()))
            .collect();
        let a_data = act_tys.iter().map(|&act_ty| {
            Ok((
                act_ty.clone(),
                SymEntityData::of_action_type(act_ty, act_tys.clone(), schema),
            ))
        });
        Ok(SymEntities(
            e_data.into_iter().chain(a_data).collect::<Result<_, _>>()?,
        ))
    }
}

impl SymRequest {
    /// Creates a symbolic request for the given request type.
    fn of_request_type(req_ty: &RequestType<'_>) -> Result<Self, result::Error> {
        Ok(Self {
            principal: Term::new(TermX::Var(TermVar {
                id: "principal".to_string(),
                ty: TermType::Entity {
                    ety: req_ty.principal.clone(),
                },
            })),
            action: Term::new(TermX::Prim(TermPrim::Entity(req_ty.action.clone()))),
            resource: Term::new(TermX::Var(TermVar {
                id: "resource".to_string(),
                ty: TermType::Entity {
                    ety: req_ty.resource.clone(),
                },
            })),
            context: Term::new(TermX::Var(TermVar {
                id: "context".to_string(),
                ty: TermType::of_type(record(req_ty.context.clone()))?,
            })),
        })
    }
}

impl SymEnv {
    /// Returns a symbolic environment that conforms to the given
    /// type Environment.
    pub fn of_env(ty_env: &Environment<'_>) -> Result<Self, result::Error> {
        Ok(SymEnv {
            request: SymRequest::of_request_type(&ty_env.req_ty)?,
            entities: SymEntities::of_schema(ty_env.schema)?,
        })
    }
}

// --------------Code not present in Lean--------------
//
// Starting from this point, this file differs from the Lean.
//
// The Lean representation of the schema doesn't match the Rust, so we define
// structs that match the Lean and convert the cedar-policy-validator schema
// representation to these structs.
// `cedar-policy-validator` doesn't have an equivalent of several types like
// `RequestType` that are only used in `Cedar/SymCC/Env.lean`, so we define
// them here.

// TODO: test this

// Convenience functions

fn entity(ety: EntityType) -> TermType {
    TermType::Entity { ety }
}

fn record(attrs: Attributes) -> Type {
    Type::EntityOrRecord(EntityRecordKind::Record {
        attrs,
        open_attributes: OpenTag::ClosedAttributes,
    })
}

// From `Validation/Types.lean`
struct StandardEntitySchemaEntry {
    ancestors: BTreeSet<EntityType>,
    attrs: Attributes,
    tags: Option<Type>,
}

enum EntitySchemaEntry {
    Standard(StandardEntitySchemaEntry),
    Enum(BTreeSet<SmolStr>),
}

impl EntitySchemaEntry {
    fn of_schema(
        ety: &EntityType,
        validator_ety: &ValidatorEntityType,
        schema: &ValidatorSchema,
    ) -> Self {
        if let Some(entry) = schema.get_entity_type(ety.as_ref()) {
            if let ValidatorEntityTypeKind::Enum(eids) = &entry.kind {
                return EntitySchemaEntry::Enum(eids.iter().cloned().collect());
            }
        }

        EntitySchemaEntry::Standard(StandardEntitySchemaEntry {
            // Reverse the descendants relation to get the ancestors relation
            ancestors: schema
                .entity_types()
                .filter(|other_ety| other_ety.descendants.contains(ety.as_ref()))
                .map(|other_ety| core_entity_type_into_entity_type(other_ety.name()))
                .cloned()
                .collect(),
            attrs: validator_ety.attributes().clone(),
            tags: validator_ety.tag_type().cloned(),
        })
    }
}

// From `Validation/Types.lean`
struct ActionSchemaEntry {
    ancestors: BTreeSet<EntityUID>,
    // present in the Lean, but not used in SymCC
    // applies_to_principal: BTreeSet<EntityType>,
    // present in the Lean, but not used in SymCC
    // applies_to_resource: BTreeSet<EntityType>,
    // present in the Lean, but not used in SymCC
    // context: Attributes,
}

struct ActionSchemaEntries(BTreeMap<EntityUID, ActionSchemaEntry>);

impl Deref for ActionSchemaEntries {
    type Target = BTreeMap<EntityUID, ActionSchemaEntry>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ActionSchemaEntries {
    fn of_schema(schema: &ValidatorSchema) -> Self {
        Self(
            // PANIC SAFETY
            #[allow(
                clippy::expect_used,
                reason = "ValidatorSchema::action_entities should not error"
            )]
            schema
                .action_entities()
                .expect("Failed to get action entities from schema")
                .into_iter()
                .map(|action| {
                    let action_schema_entry = ActionSchemaEntry {
                        ancestors: action.ancestors().map(core_uid_into_uid).cloned().collect(),
                    };
                    (core_uid_into_uid(action.uid()).clone(), action_schema_entry)
                })
                .collect(),
        )
    }
}

fn context_attributes(action: &ValidatorActionId) -> Result<&Attributes, result::Error> {
    match action.context_type() {
        Type::EntityOrRecord(EntityRecordKind::Record {
            attrs,
            open_attributes: OpenTag::ClosedAttributes,
        }) => Ok(attrs),
        _ => Err(result::Error::Unreachable(
            "Context type should be a closed record".into(),
        )),
    }
}

// From `Validation/Types.lean`
#[derive(Debug)]
struct RequestType<'a> {
    principal: &'a EntityType,
    action: &'a EntityUID,
    resource: &'a EntityType,
    context: &'a Attributes,
}

// From `Validation/Types.lean`
#[derive(Debug)]
pub struct Environment<'a> {
    schema: &'a ValidatorSchema,
    req_ty: RequestType<'a>,
}

impl<'a> Environment<'a> {
    /// No real counterpart in the Lean; this function maps from
    /// `cedar_policy::RequestEnv` to the `Environment` struct
    ///
    /// Returns `None` if the `renv` specifies an `action` not found in the `schema`
    pub fn from_request_env(
        renv: &'a cedar_policy::RequestEnv,
        schema: &'a ValidatorSchema,
    ) -> Option<Self> {
        Some(Self {
            schema,
            req_ty: RequestType {
                principal: renv.principal(),
                action: renv.action(),
                resource: renv.resource(),
                context: context_attributes(schema.get_action_id(renv.action().as_ref())?).ok()?,
            },
        })
    }
}

pub fn to_validator_request_env<'a>(
    env: &'a cedar_policy::RequestEnv,
    schema: &'a ValidatorSchema,
) -> Option<cedar_policy_core::validator::types::RequestEnv<'a>> {
    let principal = env.principal().as_ref();
    let resource = env.resource().as_ref();
    let action = env.action().as_ref();
    let context_type = schema.context_type(action);
    context_type.map(
        |context| cedar_policy_core::validator::types::RequestEnv::DeclaredAction {
            principal,
            action,
            resource,
            context,
            principal_slot: None,
            resource_slot: None,
        },
    )
}
