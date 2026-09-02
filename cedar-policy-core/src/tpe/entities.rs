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

//! This module contains partial entities.

use crate::ast;
use crate::ast::Entity;
use crate::ast::RestrictedExpr;
use crate::entities::conformance::err::{
    AttrOrTag, EntitySchemaConformanceError, UndeclaredAction, UnexpectedEntityTypeError,
};
use crate::entities::conformance::typecheck_value_against_schematype;
use crate::entities::conformance::TypecheckError;
use crate::entities::conformance::{validate_euid, EntitySchemaConformanceChecker};
use crate::entities::err::Duplicate;
use crate::entities::json::err::TypeMismatchError;
use crate::entities::{Dereference, Entities, Schema, SchemaType, TCComputation};
use crate::tpe::err::MismatchedActionAncestorsError;
use crate::tpe::err::{
    AncestorValidationError, EntitiesConsistencyError, EntitiesError, EntityConsistencyError,
    EntityValidationError, JsonDeserializationError, MismatchedAncestorError,
    MismatchedAttributeError, MismatchedTagError, MissingEntityError, UnexpectedActionError,
    UnknownActionComponentError, UnknownAttributeError, UnknownEntityError, UnknownTagError,
};
use crate::tpe::value::{AttrState, PartialRecord};
use crate::{
    ast::{EntityUID, Value},
    entities::{
        json::{err::JsonDeserializationErrorContext, ValueParser},
        EntityTypeDescription, EntityUidJson,
    },
    evaluator::RestrictedEvaluator,
    extensions::Extensions,
    jsonvalue::JsonValueWithNoDuplicateKeys,
    transitive_closure::{compute_tc, enforce_tc_and_dag, repair_tc, TCNode, TcError},
    validator::{types::Type, CoreSchema, ValidatorEntityType, ValidatorSchema},
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde_as]
#[serde(transparent)]
struct DeduplicatedMap {
    #[serde_as(as = "serde_with::MapPreventDuplicates<_,_>")]
    pub map: HashMap<SmolStr, JsonValueWithNoDuplicateKeys>,
}

/// Serde JSON format for a single entity
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct EntityJson {
    /// UID of the entity, specified in any form accepted by `EntityUidJson`
    uid: EntityUidJson,
    /// attributes, whose values can be any JSON value.
    /// (Probably a `CedarValueJson`, but for schema-based parsing, it could for
    /// instance be an `EntityUidJson` if we're expecting an entity reference,
    /// so for now we leave it in its raw json-value form, albeit not allowing
    /// any duplicate keys in any records that may occur in an attribute value
    /// (even nested).)
    #[serde(default)]
    // the annotation covers duplicates in this `HashMap` itself, while the `JsonValueWithNoDuplicateKeys` covers duplicates in any records contained in attribute values (including recursively)
    attrs: Option<DeduplicatedMap>,
    #[serde(default)]
    /// Parents of the entity, specified in any form accepted by `EntityUidJson`
    parents: Option<Vec<EntityUidJson>>,
    #[serde(default)]
    // the annotation covers duplicates in this `HashMap` itself, while the `JsonValueWithNoDuplicateKeys` covers duplicates in any records contained in tag values (including recursively)
    // Note that unlike the concrete JSON entity format, when the `tags` field
    // is missing, it means `tags` are unknown
    // This is because we need to represent `tags` being unknowns
    tags: Option<DeduplicatedMap>,
}

/// The partial entity
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialEntity {
    // The uid of the partial entity
    uid: EntityUID,
    // Optional attributes
    attrs: Option<PartialRecord>,
    // Optional ancestors
    ancestors: Option<HashSet<EntityUID>>,
    // Optional tags
    tags: Option<PartialRecord>,
}

fn unexpected_attr(uid: EntityUID, attr: SmolStr) -> EntitiesError {
    EntityValidationError::Concrete(EntitySchemaConformanceError::unexpected_entity_attr(
        uid, attr,
    ))
    .into()
}

fn unexpected_tag(uid: EntityUID, tag: SmolStr) -> EntitiesError {
    EntityValidationError::Concrete(EntitySchemaConformanceError::unexpected_entity_tag(
        uid, tag,
    ))
    .into()
}

impl PartialEntity {
    fn from_non_action_entity(
        value: Entity,
        schema: &ValidatorSchema,
    ) -> Result<Self, EntitiesError> {
        let entity_type = lookup_entity_type(schema, value.uid())?;
        let (uid, attrs, ancestors, mut parents, tags) = value.into_inner();
        parents.extend(ancestors);
        let attrs = PartialRecord::from_concrete_record(
            &attrs
                .into_iter()
                .map(|(a, v)| Ok((a, Value::try_from(v)?)))
                .collect::<Result<BTreeMap<_, _>, EntitiesError>>()?,
            entity_type.attributes(),
        );
        let tags = tags
            .into_iter()
            .map(|(a, v)| {
                if entity_type.tag_type().is_none() {
                    return Err(unexpected_tag(uid.clone(), a));
                }
                Ok((a, Value::try_from(v)?))
            })
            .collect::<Result<Vec<_>, EntitiesError>>()?;
        Self::new(
            uid,
            Some(attrs),
            Some(parents),
            Some(PartialRecord::from_concrete_tags(tags)),
            schema,
        )
    }

    /// Convert a concrete `Entity` into a `PartialEntity`
    pub fn from_entity(e: Entity, schema: &ValidatorSchema) -> Result<Self, EntitiesError> {
        if e.uid().is_action() {
            // Actions cannot have attribute or tags
            if let Some(attr) = e.keys().next() {
                return Err(unexpected_attr(e.uid().clone(), attr.clone()));
            }
            if let Some(tag) = e.tag_keys().next() {
                return Err(unexpected_tag(e.uid().clone(), tag.clone()));
            }
            Self::new(
                e.uid().clone(),
                Some(PartialRecord::new()),
                Some(e.ancestors().cloned().collect()),
                Some(PartialRecord::new()),
                schema,
            )
        } else {
            Self::from_non_action_entity(e, schema)
        }
    }

    /// Construct a new [`PartialEntity`]
    pub fn new(
        uid: EntityUID,
        attrs: Option<PartialRecord>,
        ancestors: Option<HashSet<EntityUID>>,
        tags: Option<PartialRecord>,
        schema: &ValidatorSchema,
    ) -> Result<Self, EntitiesError> {
        let e = Self {
            uid,
            attrs,
            ancestors,
            tags,
        };
        e.validate(schema)?;
        Ok(e)
    }

    /// Get the uid of this partial entity
    pub fn uid(&self) -> &EntityUID {
        &self.uid
    }

    /// Get the optional attributes of this partial entity
    pub fn attrs(&self) -> Option<&PartialRecord> {
        self.attrs.as_ref()
    }

    /// Get the optional ancestors of this partial entity
    pub fn ancestors(&self) -> Option<&HashSet<EntityUID>> {
        self.ancestors.as_ref()
    }

    /// Get the optional tags of this partial entity
    pub fn tags(&self) -> Option<&PartialRecord> {
        self.tags.as_ref()
    }

    /// Check if an [`Entity`] is consistent with a [`PartialEntity`]
    pub(crate) fn check_consistency(&self, entity: &Entity) -> Result<(), EntityConsistencyError> {
        // `Entity` stores values as the old `ast::PartialValue`, but we should never see the unknown here.
        fn as_values<'a>(
            pairs: impl Iterator<Item = (&'a SmolStr, &'a ast::PartialValue)>,
        ) -> Result<BTreeMap<SmolStr, Value>, SmolStr> {
            pairs
                .map(|(a, pv)| match pv {
                    ast::PartialValue::Value(v) => Ok((a.clone(), v.clone())),
                    ast::PartialValue::Residual(_) => Err(a.clone()),
                })
                .collect()
        }

        if let Some(attrs) = &self.attrs {
            let other_attrs = as_values(entity.attrs()).map_err(|attr| UnknownAttributeError {
                uid: self.uid.clone(),
                attr,
            })?;
            if !attrs.check_consistency(&other_attrs) {
                return Err(MismatchedAttributeError {
                    uid: self.uid.clone(),
                }
                .into());
            }
        }
        if let Some(ancestors) = &self.ancestors {
            let other_ancestors: HashSet<EntityUID> = entity.ancestors().cloned().collect();
            if ancestors != &other_ancestors {
                return Err(MismatchedAncestorError {
                    uid: self.uid.clone(),
                }
                .into());
            }
        }
        if let Some(tags) = &self.tags {
            let other_tags = as_values(entity.tags()).map_err(|tag| UnknownTagError {
                uid: self.uid.clone(),
                tag,
            })?;
            if !tags.check_consistency(&other_tags) {
                return Err(MismatchedTagError {
                    uid: self.uid.clone(),
                }
                .into());
            }
        }
        Ok(())
    }
}

/// Build a `PartialRecord` from restricted expressions
fn partial_record_from_exprs(
    exprs: impl IntoIterator<Item = (SmolStr, AttrState<RestrictedExpr>)>,
) -> Result<PartialRecord, SmolStr> {
    exprs
        .into_iter()
        .map(|(k, attr)| {
            let state = match attr {
                AttrState::Value(expr) => {
                    let eval = RestrictedEvaluator::new(Extensions::all_available());
                    let value = eval.interpret(expr.as_borrowed()).map_err(|_| k.clone())?;
                    AttrState::Value(value)
                }
                AttrState::PartialRecord(r) => AttrState::PartialRecord(r),
                AttrState::Present => AttrState::Present,
                AttrState::Absent => AttrState::Absent,
                AttrState::Unknown => AttrState::Unknown,
            };
            Ok((k, state))
        })
        .collect::<Result<PartialRecord, SmolStr>>()
}

/// Construct a `PartialEntity` from concrete attribute and tag expressions
pub fn partial_entity_from_exprs(
    uid: EntityUID,
    attrs: Option<impl IntoIterator<Item = (SmolStr, AttrState<RestrictedExpr>)>>,
    ancestors: Option<HashSet<EntityUID>>,
    tags: Option<impl IntoIterator<Item = (SmolStr, AttrState<RestrictedExpr>)>>,
    schema: &ValidatorSchema,
) -> Result<PartialEntity, EntitiesError> {
    let attrs = attrs
        .map(|exprs| partial_record_from_exprs(exprs).map_err(|k| unexpected_attr(uid.clone(), k)))
        .transpose()?;
    let tags = tags
        .map(|exprs| partial_record_from_exprs(exprs).map_err(|k| unexpected_tag(uid.clone(), k)))
        .transpose()?;
    PartialEntity::new(uid, attrs, ancestors, tags, schema)
}

/// Look up the `ValidatorEntityType` declaring `uid`'s attributes and tags.
fn lookup_entity_type<'a>(
    schema: &'a ValidatorSchema,
    uid: &EntityUID,
) -> Result<&'a ValidatorEntityType, EntitiesError> {
    schema.get_entity_type(uid.entity_type()).ok_or_else(|| {
        EntityValidationError::Concrete(EntitySchemaConformanceError::unexpected_entity_type(
            &CoreSchema::new(schema),
            uid.clone(),
        ))
        .into()
    })
}

/// Parse a JSON map of attribute/tag values into a [`PartialRecord`]
///
/// `type_of` returns the expected [`SchemaType`] for a given key (tag or attribute). If `uid`'s
/// entity type is not declared in the schema, an `UnexpectedEntityType` error
/// is raised.
fn parse_value_map(
    map: DeduplicatedMap,
    uid: &EntityUID,
    unexpected: impl Fn(SmolStr) -> EntitySchemaConformanceError,
    vparser: &ValueParser<'_>,
    type_of: impl Fn(&str) -> Option<(Type, SchemaType)>,
) -> Result<PartialRecord, JsonDeserializationError> {
    let unexpected = |key: SmolStr| JsonDeserializationError::Concrete(unexpected(key).into());
    let exprs = map
        .map
        .into_iter()
        .map(|(k, v)| {
            let (_, schema_attr_ty) = type_of(&k).ok_or_else(|| unexpected(k.clone()))?;
            let expr =
                vparser.val_into_restricted_expr(v.into(), Some(&schema_attr_ty), &|| {
                    JsonDeserializationErrorContext::EntityAttribute {
                        uid: uid.clone(),
                        attr: k.clone(),
                    }
                })?;
            // Concrete entity JSON states a fully known value for every listed attribute or tag.
            Ok((k, AttrState::Value(expr)))
        })
        .collect::<std::result::Result<Vec<_>, JsonDeserializationError>>()?;
    // Every key above already had to have a declared type, so nothing further to check.
    partial_record_from_exprs(exprs).map_err(unexpected)
}

/// Parse an [`EntityJson`] into a [`PartialEntity`] according to `schema`
pub fn parse_ejson(
    e: EntityJson,
    schema: &ValidatorSchema,
) -> Result<PartialEntity, JsonDeserializationError> {
    let uid = e
        .uid
        .into_euid(&|| JsonDeserializationErrorContext::EntityUid)?;
    let core_schema = CoreSchema::new(schema);

    if uid.is_action() {
        return Err(UnexpectedActionError { action: uid }.into());
    }
    let vparser = ValueParser::new(Extensions::all_available());
    let validator_entity_type = schema.get_entity_type(uid.entity_type()).ok_or_else(|| {
        JsonDeserializationError::Concrete(
            crate::entities::json::err::JsonDeserializationError::from(
                EntitySchemaConformanceError::UnexpectedEntityType(UnexpectedEntityTypeError {
                    uid: uid.clone(),
                    suggested_types: core_schema
                        .entity_types_with_basename(&uid.entity_type().name().basename())
                        .collect(),
                }),
            ),
        )
    })?;
    let schema_ty = core_schema.entity_type(uid.entity_type()).ok_or_else(|| {
        JsonDeserializationError::Concrete(
            EntitySchemaConformanceError::unexpected_entity_type(&core_schema, uid.clone()).into(),
        )
    })?;
    let attrs = e
        .attrs
        .map(|m| {
            let type_of = |k: &str| {
                let attr_ty = validator_entity_type.attr(k)?.attr_type.as_ref().clone();
                Some((attr_ty, schema_ty.attr_type(k)?))
            };
            parse_value_map(
                m,
                &uid,
                |k| EntitySchemaConformanceError::unexpected_entity_attr(uid.clone(), k),
                &vparser,
                type_of,
            )
        })
        .transpose()?;

    let ancestors = e
        .parents
        .map(|parents| {
            parents
                .into_iter()
                .map(|parent| {
                    parent
                        .into_euid(&|| JsonDeserializationErrorContext::EntityParents {
                            uid: uid.clone(),
                        })
                        .map_err(JsonDeserializationError::Concrete)
                })
                .collect::<Result<HashSet<_>, _>>()
        })
        .transpose()?;

    let tags = e
        .tags
        .map(|m| {
            let type_of = |_k: &str| {
                Some((
                    validator_entity_type.tag_type().cloned()?,
                    schema_ty.tag_type()?,
                ))
            };
            parse_value_map(
                m,
                &uid,
                |k| EntitySchemaConformanceError::unexpected_entity_tag(uid.clone(), k),
                &vparser,
                type_of,
            )
        })
        .transpose()?;

    Ok(PartialEntity {
        uid,
        attrs,
        ancestors,
        tags,
    })
}

impl TCNode<EntityUID> for PartialEntity {
    fn add_edge_to(&mut self, k: EntityUID) {
        self.add_ancestor(k);
    }

    fn get_key(&self) -> EntityUID {
        self.uid.clone()
    }

    fn has_edge_to(&self, k: &EntityUID) -> bool {
        match self.ancestors.as_ref() {
            Some(ancestors) => ancestors.contains(k),
            None => false,
        }
    }

    fn out_edges(&self) -> Box<dyn Iterator<Item = &EntityUID> + '_> {
        match self.ancestors.as_ref() {
            Some(ancestors) => Box::new(ancestors.iter()),
            None => Box::new(std::iter::empty()),
        }
    }

    fn reset_edges(&mut self) {}
}

impl PartialEntity {
    /// This method should be only called on entities that have known ancestors
    pub(crate) fn add_ancestor(&mut self, uid: EntityUID) {
        #[expect(
            clippy::expect_used,
            reason = "this method should be only called on entities that have known ancestors"
        )]
        self.ancestors
            .as_mut()
            .expect("should not be unknown")
            .insert(uid);
    }
    /// Validate `self` according to `schema`
    pub fn validate(&self, schema: &ValidatorSchema) -> Result<(), EntityValidationError> {
        let schema = CoreSchema::new(schema);
        if self.uid.is_action() {
            return self.validate_action(&schema);
        }

        validate_euid(&schema, &self.uid).map_err(EntitySchemaConformanceError::from)?;
        let schema_etype = schema
            .entity_type(self.uid.entity_type())
            .ok_or_else(|| {
                let suggested_types = schema
                    .entity_types_with_basename(&self.uid.entity_type().name().basename())
                    .collect();
                UnexpectedEntityTypeError {
                    uid: self.uid.clone(),
                    suggested_types,
                }
            })
            .map_err(EntitySchemaConformanceError::from)?;
        let checker = EntitySchemaConformanceChecker::new(&schema, Extensions::all_available());
        if let Some(ancestors) = &self.ancestors {
            checker.validate_entity_ancestors(&self.uid, ancestors.iter(), &schema_etype)?;
        }
        if let Some(attrs) = &self.attrs {
            validate_partial_record_as_attrs(attrs, &self.uid, &schema_etype, &schema)?;
        }
        if let Some(tags) = &self.tags {
            validate_partial_record_as_tags(tags, &self.uid, &schema_etype, &schema)?;
        }
        Ok(())
    }

    /// Validate an action entity
    fn validate_action<S: Schema>(&self, core_schema: &S) -> Result<(), EntityValidationError> {
        let (Some(attrs), Some(ancestors), Some(tags)) = (&self.attrs, &self.ancestors, &self.tags)
        else {
            return Err(UnknownActionComponentError {
                action: (&self.uid).clone(),
            }
            .into());
        };
        let Some(action) = core_schema.action(&self.uid) else {
            return Err(
                EntitySchemaConformanceError::UndeclaredAction(UndeclaredAction {
                    uid: self.uid.clone(),
                })
                .into(),
            );
        };
        if let Some((attr, _)) = attrs.attrs().next() {
            return Err(EntitySchemaConformanceError::unexpected_entity_attr(
                self.uid.clone(),
                attr.clone(),
            )
            .into());
        }
        if let Some((tag, _)) = tags.attrs().next() {
            return Err(EntitySchemaConformanceError::unexpected_entity_tag(
                self.uid.clone(),
                tag.clone(),
            )
            .into());
        }
        let schema_ancestors: HashSet<EntityUID> = action.ancestors().cloned().collect();
        if &schema_ancestors != ancestors {
            return Err(MismatchedActionAncestorsError {
                action: self.uid.clone(),
            }
            .into());
        }
        Ok(())
    }
}

/// Is the partial attribute state valid for the declared type
///
/// This is like normal value typechecking except for partially-known records. If an attribute is
/// known to exist, then the schema must allow it to exist with some type. If the attribute is fully
/// unknown, then it needs no validation.
pub(crate) fn typecheck_attr_state(
    state: &AttrState,
    expected_ty: &SchemaType,
    extensions: &Extensions<'_>,
) -> Result<(), TypecheckError> {
    match state {
        AttrState::Value(v) => {
            // no partial state, delegate to concrete typechecking
            typecheck_value_against_schematype(&v.clone().into(), expected_ty, extensions)
        }
        AttrState::PartialRecord(rec) => typecheck_partial_record(rec, expected_ty, extensions),
        // For present/absent, `typecheck_partial_record` is responsible for ensuring the (non-)existence is valid.
        AttrState::Present | AttrState::Absent | AttrState::Unknown => Ok(()),
    }
}

/// Is the partial record `rec` valid as a record of type `expected_ty`?
pub(crate) fn typecheck_partial_record(
    rec: &PartialRecord,
    expected_ty: &SchemaType,
    extensions: &Extensions<'_>,
) -> Result<(), TypecheckError> {
    // TODO: Return a new error type. `TypecheckError` carries a restricted expression, but we want to give it a partial record.
    let bogus_actual_val = RestrictedExpr::val(false);
    let SchemaType::Record { attrs, .. } = expected_ty else {
        return Err(
            TypeMismatchError::type_mismatch(expected_ty.clone(), None, bogus_actual_val).into(),
        );
    };

    for (k, aty) in attrs {
        match rec.attr(k) {
            AttrState::Absent if aty.required => {
                // The attribute is explicitly absent, but the typ requires it.
                return Err(TypeMismatchError::missing_required_attr(
                    expected_ty.clone(),
                    k.clone(),
                    bogus_actual_val,
                )
                .into());
            }
            state => typecheck_attr_state(state, &aty.attr_type, extensions)?,
        }
    }

    if let Some((k, _)) = rec
        .attrs()
        .find(|(k, state)| state.exists() && attrs.get(*k).is_none())
    {
        // An attribute exists when the schema doesn't expect it. `.exists()`
        // filters our absent/unknown attributes.
        return Err(TypeMismatchError::unexpected_attr(
            expected_ty.clone(),
            k.clone(),
            bogus_actual_val,
        )
        .into());
    }
    Ok(())
}

fn validate_partial_attr<S: Schema>(
    partial_val: &AttrState,
    expected_ty: &SchemaType,
    uid: &EntityUID,
    key: &SmolStr,
    kind: AttrOrTag,
    schema: &S,
) -> Result<(), EntitySchemaConformanceError> {
    match typecheck_attr_state(partial_val, expected_ty, Extensions::all_available()) {
        Ok(()) => {}
        Err(TypecheckError::TypeMismatch(e)) => {
            return Err(EntitySchemaConformanceError::type_mismatch(
                uid.clone(),
                key.clone(),
                kind,
                e,
            ));
        }
        Err(TypecheckError::ExtensionFunctionLookup(e)) => {
            return Err(EntitySchemaConformanceError::extension_function_lookup(
                uid.clone(),
                key.clone(),
                kind,
                e,
            ));
        }
    }
    partial_val.validate_euids(schema)?;
    Ok(())
}

/// Validate a `PartialRecord` as entity attributes against the schema.
fn validate_partial_record_as_attrs<S: Schema>(
    record: &PartialRecord,
    uid: &EntityUID,
    schema_etype: &impl EntityTypeDescription,
    schema: &S,
) -> Result<(), EntitySchemaConformanceError> {
    if let Some(absent) = schema_etype
        .required_attrs()
        .find(|attr| matches!(record.attr(&attr), AttrState::Absent))
    {
        return Err(EntitySchemaConformanceError::missing_entity_attr(
            uid.clone(),
            absent,
        ));
    }

    for (attr, partial_val) in record.attrs() {
        if matches!(partial_val, AttrState::Absent | AttrState::Unknown) {
            // `Absent` was already checked against the required attributes, and `Unknown` claims
            // nothing, so neither can conflict with what the schema declares.
            continue;
        }

        let Some(expected_ty) = schema_etype.attr_type(attr) else {
            return Err(EntitySchemaConformanceError::unexpected_entity_attr(
                uid.clone(),
                attr.clone(),
            ));
        };

        validate_partial_attr(
            partial_val,
            &expected_ty,
            uid,
            attr,
            AttrOrTag::Attr,
            schema,
        )?
    }
    Ok(())
}

/// Validate a [`PartialRecord`] as entity tags against the schema.
///
/// Mirrors [`EntitySchemaConformanceChecker::validate_tags`]:
/// - If schema says no tags allowed, errors on any present tag
/// - For each `Value` tag, typechecks against the schema tag type and validates EUIDs
/// - `Exists` tags are skipped
fn validate_partial_record_as_tags<S: Schema>(
    record: &PartialRecord,
    uid: &EntityUID,
    schema_etype: &impl EntityTypeDescription,
    schema: &S,
) -> Result<(), EntitySchemaConformanceError> {
    match schema_etype.tag_type() {
        None => {
            // No tags allowed, so a tag claimed to exist is an error
            if let Some((tag, _)) = record.attrs().find(|(_, a)| a.exists()) {
                return Err(EntitySchemaConformanceError::unexpected_entity_tag(
                    uid.clone(),
                    tag.clone(),
                ));
            }
        }
        // Tags share one declared type and have no fixed key set, so any key is allowed and every
        // value is checked against the same type.
        Some(expected_ty) => {
            for (tag, partial_val) in record.attrs() {
                validate_partial_attr(partial_val, &expected_ty, uid, tag, AttrOrTag::Tag, schema)?;
            }
        }
    }
    Ok(())
}

// Validate if ancestors are well-formed
// i.e., ancestors of any ancestor of a `PartialEntity` should not be unknown
// This ensures that we can always compute a TC for entities with concrete
// ancestors
pub(crate) fn validate_concrete_ancestors_concrete(
    entities: &HashMap<EntityUID, PartialEntity>,
) -> Result<(), AncestorValidationError> {
    for e in entities.values() {
        if let Some(ancestors) = e.ancestors.as_ref() {
            for ancestor in ancestors {
                if let Some(ancestor_entity) = entities.get(ancestor) {
                    if ancestor_entity.ancestors.is_none() {
                        return Err(AncestorValidationError {
                            uid: e.uid.clone(),
                            ancestor: ancestor.clone(),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

/// The partial entity store
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialEntities {
    /// Important internal invariant: for any `Entities` object that exists,
    /// the `ancestor` relation is transitively closed.
    entities: HashMap<EntityUID, PartialEntity>,
}

impl PartialEntities {
    /// Get an empty partial entities
    pub fn new() -> Self {
        Self::default()
    }

    /// Get an iterator of entities
    pub fn entities(&self) -> impl Iterator<Item = &PartialEntity> {
        self.entities.values()
    }

    /// Compute transitive closure
    pub fn compute_tc(&mut self) -> Result<(), TcError<EntityUID>> {
        compute_tc(&mut self.entities, true)
    }

    /// Check that the tc is computed and forms a dag
    pub fn enforce_tc_and_dag(&self) -> Result<(), TcError<EntityUID>> {
        enforce_tc_and_dag(&self.entities)
    }

    /// Get the `PartialEntity` with this identifier
    pub fn get(&self, euid: &EntityUID) -> Option<&PartialEntity> {
        self.entities.get(euid)
    }

    /// Get the ancestors for this `PartialEntity`
    ///
    /// Returns ancestors if this entity exists and its ancestors are known. TPE treats a missing
    /// entity and unknown ancestors identically. If you need to distinguish them, get the full
    /// partial entity (if it exists) using [`PartialEntities::get`].
    pub fn get_ancestors(&self, euid: &EntityUID) -> Option<&HashSet<EntityUID>> {
        self.get(euid).and_then(|e| e.ancestors())
    }

    /// Get the attributes for this `PartialEntity`
    ///
    /// Returns attributes if this entity exists and its attributes are known. TPE treats a missing
    /// entity and unknown attributes identically. If you need to distinguish them, get the full
    /// partial entity (if it exists) using [`PartialEntities::get`].
    pub fn get_attrs(&self, euid: &EntityUID) -> Option<&PartialRecord> {
        self.get(euid).and_then(|e| e.attrs())
    }

    /// Get the tags for this `PartialEntity`
    ///
    /// Returns tags if this entity exists and its tags are known. TPE treats a missing entity and
    /// unknown tags identically. If you need to distinguish them, get the full partial entity (if
    /// it exists) using [`PartialEntities::get`].
    pub fn get_tags(&self, euid: &EntityUID) -> Option<&PartialRecord> {
        self.get(euid).and_then(|e| e.tags())
    }

    /// Check if there is a `PartialEntity` with identifier
    pub fn contains_entity(&self, euid: &EntityUID) -> bool {
        self.entities.contains_key(euid)
    }

    /// Shared internal constructor for building from maps. Validates each
    /// entity, concreteness of the ancestor hierarchy, and optionally compute
    /// the transitive closure. Also inserts actions entities from the schema.
    fn from_entities_map(
        entities: HashMap<EntityUID, PartialEntity>,
        schema: &ValidatorSchema,
        compute_tc: bool,
    ) -> Result<Self, EntitiesError> {
        entities.values().try_for_each(|e| e.validate(schema))?;
        validate_concrete_ancestors_concrete(&entities)?;
        let mut entities = Self { entities };
        if compute_tc {
            entities.compute_tc()?;
        }
        entities.insert_actions(schema);
        Ok(entities)
    }

    fn collect_unique(
        entities: impl Iterator<Item = PartialEntity>,
    ) -> Result<HashMap<EntityUID, PartialEntity>, EntitiesError> {
        let mut map: HashMap<EntityUID, PartialEntity> = HashMap::new();
        for entity in entities {
            match map.entry(entity.uid.clone()) {
                Entry::Vacant(e) => {
                    e.insert(entity);
                }
                Entry::Occupied(e) => {
                    return Err(Duplicate {
                        euid: e.key().clone(),
                    }
                    .into())
                }
            }
        }
        Ok(map)
    }

    /// Construct `PartialEntities` from `Entities`, ensuring that the entities are valid.
    /// TC is already computed in the source `Entities`, so we skip recomputation.
    pub fn from_concrete(
        entities: Entities,
        schema: &ValidatorSchema,
    ) -> Result<Self, EntitiesError> {
        let entities_map: HashMap<EntityUID, PartialEntity> = entities
            .into_iter()
            .map(|e| PartialEntity::from_entity(e, schema).map(|pe| (pe.uid.clone(), pe)))
            .try_collect()?;
        // TC is already computed in the source Entities — the conversion to
        // PartialEntity preserves all ancestors (direct + indirect).
        Self::from_entities_map(entities_map, schema, false)
    }

    /// Construct `PartialEntities` from an iterator
    pub fn from_entities(
        entity_mappings: impl Iterator<Item = PartialEntity>,
        schema: &ValidatorSchema,
    ) -> Result<Self, EntitiesError> {
        Self::from_entities_map(Self::collect_unique(entity_mappings)?, schema, true)
    }

    /// Add a partial entity without checking if it conforms to the schema,
    /// assuming the TC is already computed.
    /// Errors on duplicate entries.
    pub(crate) fn add_entity_trusted(
        &mut self,
        uid: EntityUID,
        entity: PartialEntity,
    ) -> Result<(), EntitiesError> {
        match self.entities.entry(uid) {
            Entry::Vacant(e) => {
                e.insert(entity);
            }
            Entry::Occupied(e) => {
                return Err(Duplicate {
                    euid: e.key().clone(),
                }
                .into())
            }
        }

        Ok(())
    }

    /// Add a set of partial entities to this store,
    /// erroring on duplicates.
    pub fn add_entities(
        &mut self,
        entity_mappings: impl Iterator<Item = (EntityUID, PartialEntity)>,
        schema: &ValidatorSchema,
        tc_computation: TCComputation,
    ) -> Result<(), EntitiesError> {
        let mut entities_touched: HashSet<EntityUID> = HashSet::new();
        for (id, entity) in entity_mappings {
            entity.validate(schema)?;
            entities_touched.insert(id.clone());
            self.add_entity_trusted(id, entity)?;
        }

        validate_concrete_ancestors_concrete(&self.entities)?;

        match tc_computation {
            TCComputation::AssumeAlreadyComputed => (),
            TCComputation::EnforceAlreadyComputed => {
                self.enforce_tc_and_dag()?;
            }
            TCComputation::ComputeNow => {
                for entity in self.entities.values() {
                    if let Some(ancestors) = entity.ancestors.as_ref() {
                        if !entities_touched.is_disjoint(ancestors) {
                            entities_touched.insert(entity.uid.clone());
                        }
                    }
                }
                repair_tc(&entities_touched, &mut self.entities, true)?;
            }
        }
        Ok(())
    }

    // Insert action entities from the schema
    // Overwriting existing action entities is fine because they should come
    // from schema or be consistent with schema anyways
    fn insert_actions(&mut self, schema: &ValidatorSchema) {
        for (uid, action) in &schema.actions {
            let ancestors = action.ancestors().cloned().collect();
            self.entities.insert(
                uid.clone(),
                PartialEntity {
                    uid: uid.clone(),
                    attrs: Some(PartialRecord::new()),
                    ancestors: Some(ancestors),
                    tags: Some(PartialRecord::new()),
                },
            );
        }
    }

    /// Construct [`PartialEntities`] from a JSON list
    pub fn from_json_value(
        value: serde_json::Value,
        schema: &ValidatorSchema,
    ) -> Result<Self, EntitiesError> {
        let entities: Vec<EntityJson> = serde_json::from_value(value)
            .map_err(|e| JsonDeserializationError::Concrete(e.into()))?;
        let parsed = entities
            .into_iter()
            .map(|e| parse_ejson(e, schema))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_entities_map(Self::collect_unique(parsed.into_iter())?, schema, true)
    }

    /// Check if [`PartialEntities`] are consistent with [`Entities`]
    pub fn check_consistency(&self, concrete: &Entities) -> Result<(), EntitiesConsistencyError> {
        for (uid, e) in &self.entities {
            match concrete.entity(uid) {
                Dereference::NoSuchEntity => {
                    return Err(MissingEntityError { uid: uid.clone() }.into());
                }
                Dereference::Residual(_) => {
                    return Err(UnknownEntityError { uid: uid.clone() }.into());
                }
                Dereference::Data(entity) => e.check_consistency(entity)?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use crate::tpe::err::AncestorValidationError;
    use crate::tpe::value::{AttrState, PartialRecord};
    use crate::validator::ValidatorSchema;
    use crate::{
        ast::{EntityUID, Value},
        extensions::Extensions,
    };
    use cool_asserts::assert_matches;

    use super::{
        parse_ejson, validate_concrete_ancestors_concrete, EntityJson, PartialEntities,
        PartialEntity,
    };

    #[track_caller]
    fn basic_schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            r#"
        entity A {
            a? : String,
            b? : Long,
            c? : {"x" : Bool}
        } tags Long;
         action a appliesTo {
           principal : A,
           resource : A
         };
        "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    #[test]
    fn basic() {
        let schema = basic_schema();
        // unlike the existing JSON format, absence of `tags` or `tags` being
        // `null` means unknown tags, as opposed to empty tags
        let json = serde_json::json!(
            {
                "uid" : {
                    "type" : "A",
                    "id" : "",
                },
                "tags" : null,
            }
        );
        let ejson: EntityJson = serde_json::from_value(json).expect("should parse");
        assert_matches!(parse_ejson(ejson, &schema), Ok(e) => {
            assert_eq!(e, PartialEntity { uid: r#"A::"""#.parse().unwrap(), attrs: None, ancestors: None, tags: None });
        });

        // empty tags need to be specified explicitly
        let schema = basic_schema();
        let json = serde_json::json!(
            {
                "uid" : {
                    "type" : "A",
                    "id" : "",
                },
                "tags" : {},
            }
        );
        let ejson: EntityJson = serde_json::from_value(json).expect("should parse");
        assert_matches!(parse_ejson(ejson, &schema), Ok(e) => {
            assert_eq!(e, PartialEntity { uid: r#"A::"""#.parse().unwrap(), attrs: None, ancestors: None, tags: Some(PartialRecord::new()) });
        });

        let schema = basic_schema();
        let json = serde_json::json!(
            {
                "uid" : {
                    "type" : "A",
                    "id" : "",
                },
                "parents" : [],
                "attrs" : {},
                "tags" : {},
            }
        );
        let ejson: EntityJson = serde_json::from_value(json).expect("should parse");
        assert_matches!(parse_ejson(ejson, &schema), Ok(e) => {
            assert_eq!(e, PartialEntity { uid: r#"A::"""#.parse().unwrap(), attrs: Some(PartialRecord::new()), ancestors: Some(HashSet::default()), tags: Some(PartialRecord::new()) });
        });

        let schema = basic_schema();
        let json = serde_json::json!(
            {
                "uid" : {
                    "type" : "A",
                    "id" : "",
                },
                "parents" : [],
                "attrs" : {
                    "b" : 1,
                    "c" : {"x": false},
                },
                "tags" : {},
            }
        );
        let ejson: EntityJson = serde_json::from_value(json).expect("should parse");
        assert_matches!(parse_ejson(ejson, &schema), Ok(e) => {
            let expected_attrs = [
                ("b".into(), AttrState::Value(1.into())),
                ("c".into(), AttrState::Value(Value::record(std::iter::once(("x", false)), None))),
            ].into_iter().collect();
            assert_eq!(e, PartialEntity { uid: r#"A::"""#.parse().unwrap(), attrs: Some(expected_attrs), ancestors: Some(HashSet::default()), tags: Some(PartialRecord::new()) });
        });
    }

    #[test]
    fn undescribed_json_keys_rejected() {
        let schema = ValidatorSchema::from_cedarschema_str(
            r#"entity NoTags { a: Long };
               entity WithTags { a: Long } tags Long;"#,
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        let parse = |json: serde_json::Value| {
            PartialEntities::from_json_value(json, &schema).map_err(|e| e.to_string())
        };

        assert_matches!(
            parse(serde_json::json!([{ "uid": {"type":"NoTags","id":"x"}, "attrs": {"bogus": 1} }])),
            Err(e) => assert!(e.contains("attribute `bogus`"), "{e}")
        );
        assert_matches!(
            parse(serde_json::json!([{ "uid": {"type":"NoTags","id":"x"}, "tags": {"t": 1} }])),
            Err(e) => assert!(e.contains("found a tag `t`"), "{e}")
        );
        assert_matches!(
            parse(serde_json::json!([{ "uid": {"type":"WithTags","id":"x"}, "tags": {"t": 1} }])),
            Ok(_)
        );
        assert_matches!(
            parse(serde_json::json!([{ "uid": {"type":"NoTags","id":"x"}, "attrs": {"a": 1} }])),
            Ok(_)
        );
    }

    #[test]
    fn action_entity_attrs_and_tags_rejected() {
        use crate::ast::Entity;

        let schema = basic_schema();
        let action: EntityUID = r#"Action::"a""#.parse().unwrap();
        let mk = |attrs: Vec<(smol_str::SmolStr, Value)>, tags: Vec<(smol_str::SmolStr, Value)>| {
            Entity::new_with_attr_partial_value(
                action.clone(),
                attrs.into_iter().map(|(k, v)| (k, v.into())),
                HashSet::new(),
                HashSet::new(),
                tags.into_iter().map(|(k, v)| (k, v.into())),
            )
        };

        assert_matches!(
            PartialEntity::from_entity(mk(vec![("bogus".into(), 1.into())], vec![]), &schema)
                .map_err(|e| e.to_string()),
            Err(e) => assert!(e.contains("attribute `bogus`"), "{e}")
        );
        assert_matches!(
            PartialEntity::from_entity(mk(vec![], vec![("t".into(), 1.into())]), &schema)
                .map_err(|e| e.to_string()),
            Err(e) => assert!(e.contains("tag `t`"), "{e}")
        );
        assert_matches!(
            PartialEntity::from_entity(mk(vec![], vec![]), &schema),
            Ok(e) => {
                assert_eq!(e.attrs(), Some(&PartialRecord::new()));
                assert_eq!(e.tags(), Some(&PartialRecord::new()));
            }
        );
    }

    #[test]
    fn invalid_hierarchy() {
        let uid_a: EntityUID = r#"A::"a""#.parse().unwrap();
        let uid_b: EntityUID = r#"A::"b""#.parse().unwrap();
        assert_matches!(
            validate_concrete_ancestors_concrete(&HashMap::from_iter([
                (
                    uid_a.clone(),
                    PartialEntity {
                        uid: uid_a,
                        ancestors: Some(HashSet::from_iter([uid_b.clone()])),
                        attrs: None,
                        tags: None
                    }
                ),
                (
                    uid_b.clone(),
                    PartialEntity {
                        uid: uid_b,
                        ancestors: None,
                        attrs: None,
                        tags: None
                    }
                )
            ])),
            Err(AncestorValidationError { .. })
        )
    }

    #[test]
    fn tc_computation() {
        let a = PartialEntity {
            uid: r#"E::"a""#.parse().unwrap(),
            attrs: None,
            ancestors: Some(HashSet::from_iter([
                r#"E::"b""#.parse().unwrap(),
                r#"E::"c""#.parse().unwrap(),
            ])),
            tags: None,
        };
        let b = PartialEntity {
            uid: r#"E::"b""#.parse().unwrap(),
            attrs: None,
            ancestors: Some(HashSet::from_iter([r#"E::"d""#.parse().unwrap()])),
            tags: None,
        };
        let c = PartialEntity {
            uid: r#"E::"c""#.parse().unwrap(),
            attrs: None,
            ancestors: Some(HashSet::from_iter([r#"E::"e""#.parse().unwrap()])),
            tags: None,
        };
        let e = PartialEntity {
            uid: r#"E::"e""#.parse().unwrap(),
            attrs: None,
            ancestors: Some(HashSet::from_iter([r#"E::"f""#.parse().unwrap()])),
            tags: None,
        };
        let x = PartialEntity {
            uid: r#"E::"x""#.parse().unwrap(),
            attrs: None,
            ancestors: None,
            tags: None,
        };
        let mut entities = PartialEntities {
            entities: vec![a, b, c, e, x]
                .into_iter()
                .map(|e| (e.uid.clone(), e))
                .collect(),
        };
        entities.compute_tc().expect("should compute tc");
        assert_eq!(
            entities
                .entities
                .get(&r#"E::"a""#.parse().unwrap())
                .as_ref()
                .unwrap()
                .ancestors
                .clone()
                .unwrap(),
            HashSet::from_iter([
                r#"E::"b""#.parse().unwrap(),
                r#"E::"c""#.parse().unwrap(),
                r#"E::"d""#.parse().unwrap(),
                r#"E::"e""#.parse().unwrap(),
                r#"E::"f""#.parse().unwrap()
            ])
        );
        assert_eq!(
            entities
                .entities
                .get(&r#"E::"b""#.parse().unwrap())
                .as_ref()
                .unwrap()
                .ancestors
                .clone()
                .unwrap(),
            HashSet::from_iter([r#"E::"d""#.parse().unwrap(),])
        );
        assert_eq!(
            entities
                .entities
                .get(&r#"E::"c""#.parse().unwrap())
                .as_ref()
                .unwrap()
                .ancestors
                .clone()
                .unwrap(),
            HashSet::from_iter([r#"E::"e""#.parse().unwrap(), r#"E::"f""#.parse().unwrap()])
        );
        assert_eq!(
            entities
                .entities
                .get(&r#"E::"e""#.parse().unwrap())
                .as_ref()
                .unwrap()
                .ancestors
                .clone()
                .unwrap(),
            HashSet::from_iter([r#"E::"f""#.parse().unwrap()])
        );
        assert_eq!(
            entities
                .entities
                .get(&r#"E::"x""#.parse().unwrap())
                .as_ref()
                .unwrap()
                .ancestors,
            None
        );
    }
}

#[cfg(test)]
mod test_validate {

    use std::collections::HashSet;

    use crate::ast::{RestrictedExpr, Value};
    use crate::entities::conformance::err::EntitySchemaConformanceError;
    use crate::extensions::Extensions;
    use crate::tpe::entities::{partial_entity_from_exprs, PartialEntity};
    use crate::tpe::err::{
        EntitiesError, EntityValidationError, MismatchedActionAncestorsError,
        UnknownActionComponentError,
    };
    use crate::tpe::value::{AttrState, PartialRecord};
    use crate::validator::ValidatorSchema;
    use cool_asserts::assert_matches;
    use smol_str::SmolStr;

    fn test_schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            r#"
        entity User {
            name: String,
        } tags String;

        entity Resource;

        action view appliesTo {
            principal: User,
            resource: Resource
        };
        "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    fn record_from_lits(
        pairs: impl IntoIterator<Item = (smol_str::SmolStr, crate::ast::Literal)>,
    ) -> PartialRecord {
        PartialRecord::from_iter(
            pairs
                .into_iter()
                .map(|(k, v)| (k, AttrState::Value(Value::new(v, None)))),
        )
    }

    #[test]
    fn valid_entity() {
        let schema = test_schema();
        let entity = PartialEntity {
            uid: "User::\"alice\"".parse().unwrap(),
            attrs: Some(record_from_lits([("name".into(), "Alice".into())])),
            ancestors: Some(HashSet::new()),
            tags: Some(record_from_lits([(
                "department".into(),
                "Engineering".into(),
            )])),
        };

        assert_matches!(entity.validate(&schema), Ok(()));
    }

    #[test]
    fn valid_action() {
        let schema = test_schema();
        let action = PartialEntity {
            uid: "Action::\"view\"".parse().unwrap(),
            attrs: Some(PartialRecord::new()),
            ancestors: Some(HashSet::new()),
            tags: Some(PartialRecord::new()),
        };

        assert_matches!(action.validate(&schema), Ok(()));
    }

    #[test]
    fn invalid_action_with_unknown_ancestors() {
        let schema = test_schema();
        let action = PartialEntity {
            uid: "Action::\"view\"".parse().unwrap(),
            attrs: Some(PartialRecord::new()),
            ancestors: None,
            tags: Some(PartialRecord::new()),
        };

        assert_matches!(
            action.validate(&schema),
            Err(EntityValidationError::UnknownActionComponent(
                UnknownActionComponentError { .. }
            ))
        );
    }

    #[test]
    fn invalid_action_with_unknown_tags() {
        let schema = test_schema();
        let action = PartialEntity {
            uid: "Action::\"view\"".parse().unwrap(),
            attrs: Some(PartialRecord::new()),
            ancestors: Some(HashSet::new()),
            tags: None,
        };

        assert_matches!(
            action.validate(&schema),
            Err(EntityValidationError::UnknownActionComponent(
                UnknownActionComponentError { .. }
            ))
        );
    }

    #[test]
    fn invalid_action_with_unknown_attrs() {
        let schema = test_schema();
        let action = PartialEntity {
            uid: "Action::\"view\"".parse().unwrap(),
            attrs: None,
            ancestors: Some(HashSet::new()),
            tags: Some(PartialRecord::new()),
        };

        assert_matches!(
            action.validate(&schema),
            Err(EntityValidationError::UnknownActionComponent(
                UnknownActionComponentError { .. }
            ))
        );
    }

    #[test]
    fn invalid_action_with_unexpected_attr() {
        let schema = test_schema();
        let action = PartialEntity {
            uid: "Action::\"view\"".parse().unwrap(),
            attrs: Some(record_from_lits([(
                "unexpected_attr".into(),
                "value".into(),
            )])),
            ancestors: Some(HashSet::new()),
            tags: Some(PartialRecord::new()),
        };

        assert_matches!(
            action.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::UnexpectedEntityAttr(_)
            ))
        );
    }

    #[test]
    fn invalid_action_with_unexpected_tag() {
        let schema = test_schema();
        let action = PartialEntity {
            uid: "Action::\"view\"".parse().unwrap(),
            attrs: Some(PartialRecord::new()),
            ancestors: Some(HashSet::new()),
            tags: Some(record_from_lits([(
                "unexpected_tag".into(),
                "value".into(),
            )])),
        };

        assert_matches!(
            action.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::UnexpectedEntityTag(_)
            ))
        );
    }

    #[test]
    fn invalid_action_with_incorrect_ancestors() {
        let schema = test_schema();
        let action = PartialEntity {
            uid: "Action::\"view\"".parse().unwrap(),
            attrs: Some(PartialRecord::new()),
            ancestors: Some(HashSet::from_iter(["Action::\"other\"".parse().unwrap()])),
            tags: Some(PartialRecord::new()),
        };

        assert_matches!(
            action.validate(&schema),
            Err(EntityValidationError::MismatchedActionAncestors(
                MismatchedActionAncestorsError { .. }
            ))
        );
    }

    #[test]
    fn invalid_unexpected_action() {
        let schema = test_schema();
        let action = PartialEntity {
            uid: "Action::\"other\"".parse().unwrap(),
            attrs: Some(PartialRecord::new()),
            ancestors: Some(HashSet::new()),
            tags: Some(PartialRecord::new()),
        };

        assert_matches!(
            action.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::UndeclaredAction(_)
            ))
        );
    }

    #[test]
    fn invalid_unexpected_entity_type() {
        let schema = test_schema();
        let entity = PartialEntity {
            uid: "UnknownType::\"test\"".parse().unwrap(),
            attrs: None,
            ancestors: None,
            tags: None,
        };

        assert_matches!(
            entity.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::UnexpectedEntityType(_)
            ))
        );
    }

    #[test]
    fn invalid_entity_invalid_ancestor() {
        let schema = test_schema();
        let entity = PartialEntity {
            uid: "User::\"alice\"".parse().unwrap(),
            attrs: None,
            ancestors: Some(HashSet::from_iter(["Resource::\"doc1\"".parse().unwrap()])),
            tags: None,
        };

        assert_matches!(
            entity.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::InvalidAncestorType(_)
            ))
        );
    }

    #[test]
    fn invalid_entity_invalid_attr() {
        let schema = test_schema();
        let entity = PartialEntity {
            uid: "User::\"alice\"".parse().unwrap(),
            attrs: Some(record_from_lits([("name".into(), 42.into())])),
            ancestors: None,
            tags: None,
        };

        assert_matches!(
            entity.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::TypeMismatch(_)
            ))
        );
    }

    #[test]
    fn invalid_entity_invalid_tag() {
        let schema = test_schema();
        let entity = PartialEntity {
            uid: "User::\"alice\"".parse().unwrap(),
            attrs: None,
            ancestors: None,
            tags: Some(record_from_lits([("department".into(), 42.into())])),
        };

        assert_matches!(
            entity.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::TypeMismatch(_)
            ))
        );
    }

    #[test]
    fn valid_entity_with_unknown_attrs() {
        let schema = test_schema();
        let entity = PartialEntity {
            uid: "User::\"alice\"".parse().unwrap(),
            attrs: None,
            ancestors: Some(HashSet::new()),
            tags: None,
        };

        assert_matches!(entity.validate(&schema), Ok(()));
    }

    #[test]
    fn valid_entity_with_unknown_individual_attr() {
        let schema = test_schema();
        // `Exists` on a required attr passes: it exists, we just don't know its value.
        let attrs = PartialRecord::from_iter([("name".into(), AttrState::Present)]);
        let entity = PartialEntity {
            uid: "User::\"alice\"".parse().unwrap(),
            attrs: Some(attrs),
            ancestors: Some(HashSet::new()),
            tags: Some(PartialRecord::new()),
        };

        assert_matches!(entity.validate(&schema), Ok(()));
    }

    #[test]
    fn valid_entity_with_nested_unknown_in_record_attr() {
        let schema = ValidatorSchema::from_cedarschema_str(
            r#"
        entity Item {
            info: { name: String, count: Long },
        };
        "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0;

        let inner_record = PartialRecord::from_iter([
            ("name".into(), AttrState::Value(Value::from("hello"))),
            ("count".into(), AttrState::Present),
        ]);
        let entity = PartialEntity {
            uid: "Item::\"i1\"".parse().unwrap(),
            attrs: Some(PartialRecord::from_iter([(
                "info".into(),
                AttrState::PartialRecord(inner_record),
            )])),
            ancestors: Some(HashSet::new()),
            tags: Some(PartialRecord::new()),
        };

        assert_matches!(entity.validate(&schema), Ok(()));
    }

    #[test]
    fn invalid_entity_with_nested_wrong_type_in_partial_record() {
        let schema = ValidatorSchema::from_cedarschema_str(
            r#"
        entity Item {
            info: { name: String, count: Long },
        };
        "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0;

        let inner_record = PartialRecord::from_iter([
            ("name".into(), AttrState::Value(Value::from(42))),
            ("count".into(), AttrState::Present),
        ]);
        let entity = PartialEntity {
            uid: "Item::\"i1\"".parse().unwrap(),
            attrs: Some(PartialRecord::from_iter([(
                "info".into(),
                AttrState::PartialRecord(inner_record),
            )])),
            ancestors: Some(HashSet::new()),
            tags: Some(PartialRecord::new()),
        };

        assert_matches!(
            entity.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::TypeMismatch(_)
            ))
        );
    }

    #[test]
    fn invalid_entity_unexpected_unknown_attr() {
        let schema = test_schema();
        // Undeclared attr is rejected even as `Exists`: it claims to exist.
        let entity = PartialEntity {
            uid: "User::\"alice\"".parse().unwrap(),
            attrs: Some(PartialRecord::from_iter([
                ("name".into(), AttrState::Value(Value::from("Alice"))),
                ("bogus".into(), AttrState::Present),
            ])),
            ancestors: Some(HashSet::new()),
            tags: Some(PartialRecord::new()),
        };

        assert_matches!(
            entity.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::UnexpectedEntityAttr(_)
            ))
        );
    }

    #[test]
    fn invalid_entity_unexpected_unknown_tag() {
        let schema = test_schema();
        let entity = PartialEntity {
            uid: "Resource::\"r1\"".parse().unwrap(),
            attrs: Some(PartialRecord::new()),
            ancestors: Some(HashSet::new()),
            tags: Some(PartialRecord::from_iter([(
                "sometag".into(),
                AttrState::Present,
            )])),
        };

        assert_matches!(
            entity.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::UnexpectedEntityTag(_)
            ))
        );
    }

    #[test]
    fn invalid_entity_absent_required_attr() {
        let schema = test_schema();
        // `Absent` on a required attr is a definitive error, unlike not-in-map.
        let entity = PartialEntity {
            uid: "User::\"alice\"".parse().unwrap(),
            attrs: Some(PartialRecord::from_iter([(
                "name".into(),
                AttrState::Absent,
            )])),
            ancestors: Some(HashSet::new()),
            tags: Some(PartialRecord::new()),
        };

        assert_matches!(
            entity.validate(&schema),
            Err(EntityValidationError::Concrete(
                EntitySchemaConformanceError::MissingRequiredEntityAttr(_)
            ))
        );
    }

    #[test]
    fn valid_entity_absent_unexpected_attr() {
        let schema = test_schema();
        // `Absent` on an undeclared attr is fine: it asserts non-existence.
        let entity = PartialEntity {
            uid: "User::\"alice\"".parse().unwrap(),
            attrs: Some(PartialRecord::from_iter([
                ("name".into(), AttrState::Value(Value::from("Alice"))),
                ("bogus".into(), AttrState::Absent),
            ])),
            ancestors: Some(HashSet::new()),
            tags: Some(PartialRecord::new()),
        };

        assert_matches!(entity.validate(&schema), Ok(()));
    }

    #[test]
    fn valid_entity_unknown_unexpected_attr() {
        let schema = test_schema();
        // `Unknown` on an undeclared attr is fine: it asserts nothing, so it cannot contradict a
        // schema that says the attribute must not exist. Only `Value`/`Exists` claim existence.
        let entity = PartialEntity {
            uid: "User::\"alice\"".parse().unwrap(),
            attrs: Some(PartialRecord::from_iter([
                ("name".into(), AttrState::Value(Value::from("Alice"))),
                ("bogus".into(), AttrState::Unknown),
            ])),
            ancestors: Some(HashSet::new()),
            tags: Some(PartialRecord::new()),
        };

        assert_matches!(entity.validate(&schema), Ok(()));
    }

    #[test]
    fn valid_entity_unknown_tag_when_no_tags_declared() {
        let schema = test_schema();
        // As above, for a type declaring no tags: an `Unknown` tag claims no tag is there.
        let entity = PartialEntity {
            uid: "Resource::\"r\"".parse().unwrap(),
            attrs: Some(PartialRecord::new()),
            ancestors: Some(HashSet::new()),
            tags: Some(PartialRecord::from_iter([(
                "bogus".into(),
                AttrState::Unknown,
            )])),
        };

        assert_matches!(entity.validate(&schema), Ok(()));
    }

    /// Build a `User::"alice"` from expression-valued attributes, with no tags.
    #[track_caller]
    fn user_from_exprs(
        attrs: Vec<(SmolStr, AttrState<RestrictedExpr>)>,
        schema: &ValidatorSchema,
    ) -> Result<PartialEntity, EntitiesError> {
        partial_entity_from_exprs(
            "User::\"alice\"".parse().unwrap(),
            Some(attrs),
            Some(HashSet::new()),
            Some(Vec::<(SmolStr, AttrState<RestrictedExpr>)>::new()),
            schema,
        )
    }

    fn alice_name() -> (SmolStr, AttrState<RestrictedExpr>) {
        (
            "name".into(),
            AttrState::Value(RestrictedExpr::val("Alice")),
        )
    }

    #[test]
    fn from_exprs_accepts_undeclared_absent_attr() {
        let e = user_from_exprs(
            vec![alice_name(), ("bogus".into(), AttrState::Absent)],
            &test_schema(),
        );
        assert_matches!(e, Ok(e) => {
            assert_eq!(e.attrs().unwrap().attr("bogus"), &AttrState::Absent);
        });
    }

    #[test]
    fn from_exprs_accepts_undeclared_unknown_attr() {
        let e = user_from_exprs(
            vec![alice_name(), ("bogus".into(), AttrState::Unknown)],
            &test_schema(),
        );
        assert_matches!(e, Ok(e) => {
            assert_eq!(e.attrs().unwrap().attr("bogus"), &AttrState::Unknown);
        });
    }

    #[test]
    fn from_exprs_rejects_undeclared_present_attr() {
        let e = user_from_exprs(vec![("bogus".into(), AttrState::Present)], &test_schema());
        assert_matches!(
            e,
            Err(EntitiesError::Validation(EntityValidationError::Concrete(
                EntitySchemaConformanceError::UnexpectedEntityAttr(_)
            )))
        );
    }

    #[test]
    fn from_exprs_rejects_any_attr_on_action() {
        let schema = test_schema();
        let e = partial_entity_from_exprs(
            "Action::\"view\"".parse().unwrap(),
            Some(vec![("anything".into(), AttrState::Unknown)]),
            Some(HashSet::new()),
            Some(Vec::<(SmolStr, AttrState<RestrictedExpr>)>::new()),
            &schema,
        );
        assert_matches!(
            e,
            Err(EntitiesError::Validation(EntityValidationError::Concrete(
                EntitySchemaConformanceError::UnexpectedEntityAttr(_)
            )))
        );
    }
}

#[cfg(test)]
mod test_consistency {
    use cool_asserts::assert_matches;

    use crate::{
        ast::Entity,
        entities::{Entities, EntityJsonParser, TCComputation},
        extensions::Extensions,
        tpe::{self, entities::PartialEntities},
        validator::ValidatorSchema,
    };

    fn schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            "entity A { a: Bool } tags Long;",
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    #[track_caller]
    fn parse_concrete_json(entity_json: serde_json::Value) -> Entity {
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::all_available(), TCComputation::ComputeNow);
        eparser.single_from_json_value(entity_json).unwrap()
    }

    #[test]
    fn consistent_eq_entity() {
        let entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "tags" : { "t": 0 },
                "parents" : [ {"type": "A", "id": "bar"} ],
            }
        );
        let partial_entity = tpe::entities::parse_ejson(
            serde_json::from_value(entity_json.clone()).unwrap(),
            &schema(),
        )
        .unwrap();
        let entity = parse_concrete_json(entity_json);
        assert_matches!(partial_entity.check_consistency(&entity), Ok(()))
    }

    #[test]
    fn consistent_missing_attrs() {
        let partial_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "tags" : { "t": 0 },
                "parents" : [ {"type": "A", "id": "bar"} ],
            }
        );
        let concrete_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "tags" : { "t": 0 },
                "parents" : [ {"type": "A", "id": "bar"} ],
            }
        );
        let partial_entity = tpe::entities::parse_ejson(
            serde_json::from_value(partial_entity_json).unwrap(),
            &schema(),
        )
        .unwrap();
        let entity = parse_concrete_json(concrete_entity_json);
        assert_matches!(partial_entity.check_consistency(&entity), Ok(()))
    }

    #[test]
    fn consistent_missing_tags() {
        let partial_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "parents" : [ {"type": "A", "id": "bar"} ],
            }
        );
        let concrete_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "tags" : { "t": 0 },
                "parents" : [ {"type": "A", "id": "bar"} ],
            }
        );
        let partial_entity = tpe::entities::parse_ejson(
            serde_json::from_value(partial_entity_json).unwrap(),
            &schema(),
        )
        .unwrap();
        let entity = parse_concrete_json(concrete_entity_json);
        assert_matches!(partial_entity.check_consistency(&entity), Ok(()))
    }

    #[test]
    fn consistent_missing_parents() {
        let partial_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "tags" : { "t": 0 },
            }
        );
        let concrete_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "tags" : { "t": 0 },
                "parents" : [ {"type": "A", "id": "bar"} ],
            }
        );
        let partial_entity = tpe::entities::parse_ejson(
            serde_json::from_value(partial_entity_json).unwrap(),
            &schema(),
        )
        .unwrap();
        let entity = parse_concrete_json(concrete_entity_json);
        assert_matches!(partial_entity.check_consistency(&entity), Ok(()))
    }

    #[test]
    fn not_consistent_different_attrs() {
        let partial_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": true },
            }
        );
        let concrete_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "tags" : { "t": 0 },
                "parents" : [ {"type": "A", "id": "bar"} ],
            }
        );
        let partial_entity = tpe::entities::parse_ejson(
            serde_json::from_value(partial_entity_json).unwrap(),
            &schema(),
        )
        .unwrap();
        let entity = parse_concrete_json(concrete_entity_json);
        assert_matches!(
            partial_entity.check_consistency(&entity),
            Err(tpe::err::EntityConsistencyError::MismatchedAttribute(_))
        )
    }

    #[test]
    fn not_consistent_different_tags() {
        let partial_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "tags" : { "t": 1 },
            }
        );
        let concrete_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "tags" : { "t": 0 },
                "parents" : [ {"type": "A", "id": "bar"} ],
            }
        );
        let partial_entity = tpe::entities::parse_ejson(
            serde_json::from_value(partial_entity_json).unwrap(),
            &schema(),
        )
        .unwrap();
        let entity = parse_concrete_json(concrete_entity_json);
        assert_matches!(
            partial_entity.check_consistency(&entity),
            Err(tpe::err::EntityConsistencyError::MismatchedTag(_))
        )
    }

    #[test]
    fn not_consistent_different_parents() {
        let partial_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "parents" : [ {"type": "A", "id": "baz"} ],  // Different parent
            }
        );
        let concrete_entity_json = serde_json::json!(
            {
                "uid" : { "type" : "A", "id" : "foo", },
                "attrs": { "a": false },
                "tags" : { "t": 0 },
                "parents" : [ {"type": "A", "id": "bar"} ],  // Different parent
            }
        );
        let partial_entity = tpe::entities::parse_ejson(
            serde_json::from_value(partial_entity_json).unwrap(),
            &schema(),
        )
        .unwrap();
        let entity = parse_concrete_json(concrete_entity_json);
        assert_matches!(
            partial_entity.check_consistency(&entity),
            Err(tpe::err::EntityConsistencyError::MismatchedAncestor(_))
        )
    }

    #[test]
    fn not_consistent_missing_entity() {
        let partial_entity_json = serde_json::json!(
            [{ "uid" : { "type" : "A", "id" : "foo", }, }]
        );
        let partial_entities = PartialEntities::from_json_value(
            serde_json::from_value(partial_entity_json).unwrap(),
            &schema(),
        )
        .unwrap();
        let concrete_entities = Entities::new();
        assert_matches!(
            partial_entities.check_consistency(&concrete_entities),
            Err(tpe::err::EntitiesConsistencyError::MissingEntity(_))
        )
    }
}
