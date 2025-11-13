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

use super::function::{
    self,
    UnaryFunction::{self, Udf, Uuf},
};
use super::op;
use super::result::CompileError;
use super::tags::SymTags;
use super::term::{Term, TermPrim, TermVar};
use super::term_type::{TermType, TermTypeInner};
use super::type_abbrevs::*;
use cedar_policy_core::validator::ValidatorSchema;
use cedar_policy_core::validator::{
    types::{Attributes, EntityRecordKind, OpenTag, Type},
    ValidatorActionId,
};
use cedar_policy_core::validator::{ValidatorEntityType, ValidatorEntityTypeKind};
use hashconsing::{HConsign, HashConsign};
use smol_str::{format_smolstr, SmolStr};
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
    pub fn empty_sym_req(h: &mut HConsign<TermTypeInner>) -> Self {
        let bool_ty = TermType {
            inner: h.mk(TermTypeInner::Bool),
        };
        SymRequest {
            principal: Term::Var(TermVar {
                id: "principal".into(),
                ty: bool_ty.clone(),
            }),
            action: Term::Var(TermVar {
                id: "action".into(),
                ty: bool_ty.clone(),
            }),
            resource: Term::Var(TermVar {
                id: "resource".into(),
                ty: bool_ty,
            }),
            context: Term::Record(Arc::new(BTreeMap::new())),
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

use std::cell::RefCell;
use std::rc::Rc;

/// Symbolic representation of a request environment.
#[derive(Clone)]
#[allow(missing_docs)]
pub struct SymEnv {
    pub request: SymRequest,
    pub entities: SymEntities,
    pub h: Rc<RefCell<HConsign<TermTypeInner>>>,
}

impl std::fmt::Debug for SymEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymEnv")
            .field("request", &self.request)
            .field("entities", &self.entities)
            .field("h", &"<HConsign>")
            .finish()
    }
}

impl PartialEq for SymEnv {
    fn eq(&self, other: &Self) -> bool {
        self.request == other.request && self.entities == other.entities
    }
}

impl Eq for SymEnv {}

impl PartialOrd for SymEnv {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SymEnv {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (&self.request, &self.entities).cmp(&(&other.request, &other.entities))
    }
}

impl SymEnv {
    /// Checks if the symbolic environment only contains literal terms.
    pub fn is_literal(&self) -> bool {
        self.request.is_literal() && self.entities.is_literal()
    }

    /// Returns a mutable reference to the hash-consing table.
    pub fn h_mut(&self) -> std::cell::RefMut<'_, HConsign<TermTypeInner>> {
        self.h.borrow_mut()
    }
}

// ----- Functions for constructing symbolic input from a schema -----
impl SymEntityData {
    pub fn of_entity_type(
        ety: &EntityType,
        validator_ety: &ValidatorEntityType,
        schema: &ValidatorSchema,
        h: &mut HConsign<TermTypeInner>,
    ) -> Result<Self, CompileError> {
        match EntitySchemaEntry::of_schema(ety, validator_ety, schema) {
            // Corresponds to `SymEntityData.ofStandardEntityType` in Lean
            EntitySchemaEntry::Standard(sch) => {
                let ety_ty = entity(ety.clone(), h);
                let attrs_uuf = Uuf(Arc::new(op::Uuf {
                    id: format_smolstr!("attrs[{ety}]"),
                    arg: ety_ty.clone(),
                    out: TermType::of_type(&record(sch.attrs), h)?,
                }));
                let ancestors = sch
                    .ancestors
                    .into_iter()
                    .map(|anc_ty| {
                        let anc_ety_ty = entity(anc_ty.clone(), h);
                        let uuf = Uuf(Arc::new(op::Uuf {
                            id: format_smolstr!("ancs[{ety}, {anc_ty}]"),
                            arg: ety_ty.clone(),
                            out: TermType::set_of(anc_ety_ty, h),
                        }));
                        (anc_ty, uuf)
                    })
                    .collect();
                let tags = if let Some(tag_ty) = sch.tags {
                    let string_ty = TermType {
                        inner: h.mk(TermTypeInner::String),
                    };
                    Some(SymTags {
                        keys: Uuf(Arc::new(op::Uuf {
                            id: format_smolstr!("tagKeys[{ety}]"),
                            arg: ety_ty.clone(),
                            out: TermType::set_of(string_ty, h),
                        })),
                        vals: Uuf(Arc::new(op::Uuf {
                            id: format_smolstr!("tagVals[{ety}]"),
                            arg: TermType::tag_for(ety.clone(), h),
                            out: TermType::of_type(&tag_ty, h)?,
                        })),
                    })
                } else {
                    None
                };

                Ok(SymEntityData {
                    attrs: attrs_uuf,
                    ancestors,
                    members: None,
                    tags,
                })
            }

            // Corresponds to `SymEntityData.ofEnumEntityType` in Lean
            EntitySchemaEntry::Enum(eids) => {
                let attrs_udf = Udf(Arc::new(function::Udf {
                    arg: entity(ety.clone(), h),
                    out: TermType {
                        inner: h.mk(TermTypeInner::Record {
                            rty: Arc::new(BTreeMap::new()),
                        }),
                    },
                    table: Arc::new(BTreeMap::new()),
                    default: Term::Record(Arc::new(BTreeMap::new())),
                }));
                Ok(SymEntityData {
                    attrs: attrs_udf,
                    ancestors: BTreeMap::new(),
                    members: Some(eids.iter().map(|s| s.to_string()).collect()),
                    tags: None,
                })
            }
        }
    }

    pub(super) fn of_action_type<'a>(
        act_ty: &EntityType,
        act_tys: impl IntoIterator<Item = &'a EntityType>,
        schema: &ValidatorSchema,
        h: &mut HConsign<TermTypeInner>,
    ) -> Self {
        let sch = ActionSchemaEntries::of_schema(schema);
        let act_ty_ty = entity(act_ty.clone(), h);
        let attrs_udf = Udf(Arc::new(function::Udf {
            arg: act_ty_ty.clone(),
            out: TermType {
                inner: h.mk(TermTypeInner::Record {
                    rty: Arc::new(BTreeMap::new()),
                }),
            },
            table: Arc::new(BTreeMap::new()),
            default: Term::Record(Arc::new(BTreeMap::new())),
        }));
        let term_of_type = |ety: &EntityType, uid: &EntityUID| -> Option<Term> {
            if uid.type_name() == ety {
                Some(Term::Prim(TermPrim::Entity(uid.clone())))
            } else {
                None
            }
        };
        let ancestors = act_tys
            .into_iter()
            .map(|anc_ty| {
                let anc_ety_ty = entity(anc_ty.clone(), h);
                let table = sch
                    .iter()
                    .filter_map(|(uid, entry)| {
                        let key = term_of_type(act_ty, uid)?;
                        let val = Term::Set {
                            elts: Arc::new(
                                entry
                                    .ancestors
                                    .iter()
                                    .filter_map(|anc| term_of_type(anc_ty, anc))
                                    .collect(),
                            ),
                            elts_ty: anc_ety_ty.clone(),
                        };
                        Some((key, val))
                    })
                    .collect();
                let udf = Udf(Arc::new(function::Udf {
                    arg: act_ty_ty.clone(),
                    out: TermType::set_of(anc_ety_ty.clone(), h),
                    table: Arc::new(table),
                    default: Term::Set {
                        elts: Arc::new(BTreeSet::new()),
                        elts_ty: anc_ety_ty,
                    },
                }));
                (anc_ty.clone(), udf)
            })
            .collect();
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
            ancestors,
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
    fn of_schema(
        schema: &ValidatorSchema,
        h: &mut HConsign<TermTypeInner>,
    ) -> Result<Self, CompileError> {
        let mut e_data = Vec::new();
        for vdtr_ety in schema.entity_types() {
            let ety = core_entity_type_into_entity_type(vdtr_ety.name());
            let sym_edata = SymEntityData::of_entity_type(ety, vdtr_ety, schema, h)?;
            e_data.push((ety.clone(), sym_edata));
        }
        // PANIC SAFETY
        #[allow(
            clippy::expect_used,
            reason = "ValidatorSchema::action_entities should not error"
        )]
        let acts = schema
            .action_entities()
            .expect("Schema should have action entities");
        let act_tys: Vec<&EntityType> = acts
            .iter()
            .map(|act| core_entity_type_into_entity_type(act.uid().entity_type()))
            .collect();
        let mut a_data = Vec::new();
        for &act_ty in &act_tys {
            a_data.push((
                act_ty.clone(),
                SymEntityData::of_action_type(act_ty, act_tys.iter().copied(), schema, h),
            ));
        }
        Ok(SymEntities(e_data.into_iter().chain(a_data).collect()))
    }
}

impl SymRequest {
    /// Creates a symbolic request for the given request type.
    fn of_request_type(
        req_ty: &RequestType<'_>,
        h: &mut HConsign<TermTypeInner>,
    ) -> Result<Self, CompileError> {
        Ok(Self {
            principal: Term::Var(TermVar {
                id: "principal".into(),
                ty: TermType {
                    inner: h.mk(TermTypeInner::Entity {
                        ety: req_ty.principal.clone(),
                    }),
                },
            }),
            action: Term::Prim(TermPrim::Entity(req_ty.action.clone())),
            resource: Term::Var(TermVar {
                id: "resource".into(),
                ty: TermType {
                    inner: h.mk(TermTypeInner::Entity {
                        ety: req_ty.resource.clone(),
                    }),
                },
            }),
            context: Term::Var(TermVar {
                id: "context".into(),
                ty: TermType::of_type(&record(req_ty.context.clone()), h)?,
            }),
        })
    }
}

impl SymEnv {
    /// Returns a symbolic environment that conforms to the given
    /// type Environment.
    pub fn of_env(
        ty_env: &Environment<'_>,
        h: &mut HConsign<TermTypeInner>,
    ) -> Result<Self, CompileError> {
        let request = SymRequest::of_request_type(&ty_env.req_ty, h)?;
        let entities = SymEntities::of_schema(ty_env.schema, h)?;
        // Create a new HConsign and swap with the input
        let mut new_h = HConsign::empty();
        std::mem::swap(h, &mut new_h);
        let h_rc = Rc::new(RefCell::new(new_h));
        Ok(SymEnv {
            request,
            entities,
            h: h_rc,
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

fn entity(ety: EntityType, h: &mut HConsign<TermTypeInner>) -> TermType {
    TermType {
        inner: h.mk(TermTypeInner::Entity { ety }),
    }
}

fn record(attrs: Attributes) -> Type {
    Type::EntityOrRecord(EntityRecordKind::Record {
        attrs,
        open_attributes: OpenTag::ClosedAttributes,
    })
}

// From `Validation/Types.lean`
pub(super) struct StandardEntitySchemaEntry {
    pub(super) ancestors: BTreeSet<EntityType>,
    pub(super) attrs: Attributes,
    pub(super) tags: Option<Type>,
}

pub(super) enum EntitySchemaEntry {
    Standard(StandardEntitySchemaEntry),
    Enum(BTreeSet<SmolStr>),
}

impl EntitySchemaEntry {
    pub fn of_schema(
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

fn context_attributes(action: &ValidatorActionId) -> Result<&Attributes, CompileError> {
    match action.context_type() {
        Type::EntityOrRecord(EntityRecordKind::Record {
            attrs,
            open_attributes: OpenTag::ClosedAttributes,
        }) => Ok(attrs),
        _ => Err(CompileError::NonRecordContext),
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

    pub fn schema(&self) -> &'a ValidatorSchema {
        self.schema
    }

    /// Returns the type of the context.
    pub fn context_type(&self) -> Type {
        Type::record_with_attributes(self.req_ty.context.clone(), OpenTag::ClosedAttributes)
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
