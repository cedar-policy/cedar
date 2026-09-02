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

//! Defines partial values, values where individual record attributes may be partially known.

use std::{collections::BTreeMap, sync::Arc};

use smol_str::SmolStr;

use crate::ast::{self, EntityUID, Value};
use crate::entities::conformance::{validate_euids_in_partial_value, ValidateEuidError};
use crate::entities::Schema;
use crate::tpe::evaluator::normalize_ext_value;
use crate::tpe::residual::Residual;
use crate::validator::types::{AttributeType, Attributes, Type};
use crate::validator::ValidatorSchema;
use miette::Diagnostic;
use thiserror::Error;

/// A value was supplied that the schema gives no type to, so TPE cannot represent it.
#[derive(Debug, Clone, PartialEq, Eq, Error, Diagnostic)]
pub enum UntypedValueError {
    /// A context was supplied for an action the schema does not declare
    #[error("action `{}` is not declared in the schema, so its context has no type", .0)]
    UntypedContext(EntityUID),
}

/// Possibly-partial information about an attribute (or tag).
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub enum AttrState<V = Value> {
    /// The attribute exists and its value is fully known
    Value(V),
    /// The attribute exists and is a record, of which only part is known
    ///
    /// We might like to have the invariant that a partial record is not fully known, but this is
    /// not the case. E.g., a fully known context record is represented as sa partial record.
    PartialRecord(PartialRecord),
    /// The attribute exists but its value is unknown
    Present,
    /// The attribute is known not to exist
    Absent,
    /// Whether the attribute exists at all is unknown
    Unknown,
}

impl<V> AttrState<V> {
    /// Does this state assert that the attribute exists?
    pub(crate) fn exists(&self) -> bool {
        match self {
            AttrState::Value(_) | AttrState::PartialRecord(_) | AttrState::Present => true,
            AttrState::Absent | AttrState::Unknown => false,
        }
    }

    /// The partial information about an attribute implied by its declared type.
    ///
    /// Note that for an attribute of an entity, we need to know that the entity exists before we
    /// can trust the `Present` truly the attribute is there.
    pub(crate) fn from_declared(declared: Option<&AttributeType>) -> Self {
        match declared {
            // Declared as required, so we can assume it exists
            Some(at) if at.is_required => AttrState::Present,
            // Declared as optional, so we can't assume anything
            Some(_) => AttrState::Unknown,
            // Not declared, so we can assume it doesn't exist
            None => AttrState::Absent,
        }
    }
}

impl AttrState {
    /// Validate every entity UID appearing in the known parts of this attribute
    pub(crate) fn validate_euids(&self, schema: &impl Schema) -> Result<(), ValidateEuidError> {
        match self {
            AttrState::Value(v) => {
                validate_euids_in_partial_value(schema, &ast::PartialValue::from(v.clone()))
            }
            AttrState::PartialRecord(r) => r.validate_euids(schema),
            AttrState::Present | AttrState::Absent | AttrState::Unknown => Ok(()),
        }
    }

    /// Is this state consistent with the concrete (possibly absent) attribute value `other`?
    fn check_consistency(&self, other: Option<&Value>) -> bool {
        match (self, other) {
            (AttrState::Value(v), Some(c)) => v == c,
            (AttrState::PartialRecord(r), Some(c)) => match c.get_as_record() {
                Ok(m) => r.check_consistency(m),
                Err(_) => false,
            },
            (AttrState::Present, Some(_)) => true,
            (AttrState::Absent, None) => true,
            (AttrState::Unknown, _) => true,
            _ => false,
        }
    }

    /// Get `self` a value, if it is fully known
    fn as_value_at(&self, declared: Option<&AttributeType>) -> Option<Value> {
        match self {
            AttrState::Value(v) => Some(v.clone()),
            AttrState::PartialRecord(r) => match declared.map(|at| at.attr_type.as_ref()) {
                Some(Type::Record { attrs, .. }) => {
                    r.as_values(attrs).map(|m| Value::record(m, None))
                }
                _ => None,
            },
            AttrState::Present | AttrState::Absent | AttrState::Unknown => None,
        }
    }

    /// Reduce a resolved attribute state to a residual of type `ty`.
    ///
    /// If we have a fully known value, return this as a concrete residual. Otherwise, `self_` use
    /// self to build a residual, assuming it is semantically equivalent.
    pub(crate) fn to_residual(&self, ty: &Type, self_: impl FnOnce() -> Residual) -> Residual {
        let concrete = |value: Value| Residual::Concrete {
            value: normalize_ext_value(value),
            ty: ty.clone(),
        };
        match self {
            AttrState::Value(v) => concrete(v.clone()),
            AttrState::Absent => Residual::Error(ty.clone()),
            AttrState::PartialRecord(r) => match ty {
                Type::Record { attrs, .. } => match r.as_values(attrs) {
                    Some(m) => concrete(Value::record(m, None)),
                    None => self_(),
                },
                _ => self_(),
            },
            AttrState::Present | AttrState::Unknown => self_(),
        }
    }
}

/// A record in which individual attributes may be unknown.
///
/// Attributes that the map does not mention are assumed to be [`AttrState::Unknown`].
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct PartialRecord(Arc<BTreeMap<SmolStr, AttrState>>);

impl FromIterator<(SmolStr, AttrState)> for PartialRecord {
    fn from_iter<T: IntoIterator<Item = (SmolStr, AttrState)>>(iter: T) -> Self {
        PartialRecord(Arc::new(iter.into_iter().collect()))
    }
}

impl PartialRecord {
    /// Construct an empty `PartialRecord`
    pub(crate) fn new() -> Self {
        PartialRecord(Arc::new(BTreeMap::new()))
    }

    /// The state of `attr` in this record.
    ///
    /// Any attribute the record does not list is `Unknown`.
    pub(crate) fn attr(&self, attr: &str) -> &AttrState {
        self.0.get(attr).unwrap_or(&AttrState::Unknown)
    }

    /// The attributes this record explicitly states
    pub fn attrs(&self) -> impl Iterator<Item = (&SmolStr, &AttrState)> {
        self.0.iter()
    }

    /// The state of `attr`, informed by the record's declared attribute types
    ///
    /// An attribute not explicitly in the record has partial information based on what we can infer
    /// from the attribute types.
    pub(crate) fn resolve_attr(&self, attr: &str, attr_tys: &Attributes) -> AttrState {
        match self.attr(attr) {
            // The record says nothing, so recover what the declared type implies.
            AttrState::Unknown => AttrState::from_declared(attr_tys.get_attr(attr)),
            state => state.clone(),
        }
    }

    /// Is this record fully concrete at `attrs_ty`
    ///
    /// Every declared attribute must be explicitly defined.
    fn is_concrete_at(&self, attr_tys: &Attributes) -> bool {
        if attr_tys.keys().any(|k| !self.0.contains_key(k)) {
            return false;
        }
        self.attrs().all(|(k, state)| match state {
            AttrState::Value(_) => attr_tys.get_attr(k).is_some(),
            AttrState::Absent => true,
            AttrState::PartialRecord(r) => {
                match attr_tys.get_attr(k).map(|at| at.attr_type.as_ref()) {
                    Some(Type::Record { attrs, .. }) => r.is_concrete_at(attrs),
                    _ => false,
                }
            }
            AttrState::Present | AttrState::Unknown => false,
        })
    }

    /// Convert to a concrete record, if this record is concrete at `attr_tys`
    fn as_values(&self, attr_tys: &Attributes) -> Option<BTreeMap<SmolStr, Value>> {
        if !self.is_concrete_at(attr_tys) {
            return None;
        }
        self.attrs()
            .filter_map(|(k, state)| {
                // `Absent` is concrete but contributes no attribute. It might be invalid
                // according to the type, but this function assumes well-typed values.
                state
                    .as_value_at(attr_tys.get_attr(k))
                    .map(|v| (k.clone(), v))
            })
            .collect::<BTreeMap<_, _>>()
            .into()
    }

    /// Build a partial record from a fully concrete record of type `attr_tys`.
    ///
    /// Concrete records are closed, so a declared attribute the record lacks is `Absent`. Present
    /// attributes are `Value`. This uses `attr_tys` to populate absent attributes; it does not typecheck the values.
    pub fn from_concrete_record(attrs: &BTreeMap<SmolStr, Value>, attr_tys: &Attributes) -> Self {
        attrs
            .iter()
            .map(|(k, v)| (k.clone(), AttrState::Value(v.clone())))
            .chain(
                attr_tys
                    .iter()
                    .filter(|(k, _)| !attrs.contains_key(*k))
                    .map(|(k, _)| (k.clone(), AttrState::Absent)),
            )
            .collect()
    }

    /// Build a partial record from a fully concrete set of entity tags.
    ///
    /// Unlike in `from_concrete_record`, we cannot infer that any missing tag is absent because
    /// there is not declared set of tags.
    pub fn from_concrete_tags(tags: impl IntoIterator<Item = (SmolStr, Value)>) -> Self {
        tags.into_iter()
            .map(|(k, v)| (k, AttrState::Value(v)))
            .collect()
    }

    /// The concrete context for a specific action represented as a partial record
    pub fn concrete_context_for_action(
        attrs: &BTreeMap<SmolStr, Value>,
        action: &EntityUID,
        schema: &ValidatorSchema,
    ) -> Result<Self, UntypedValueError> {
        let Some(Type::Record { attrs: atys, .. }) =
            schema.get_action_id(action).map(|a| a.context_type())
        else {
            return Err(UntypedValueError::UntypedContext(action.clone()));
        };
        Ok(Self::from_concrete_record(attrs, atys))
    }

    pub(crate) fn validate_euids(&self, schema: &impl Schema) -> Result<(), ValidateEuidError> {
        self.attrs()
            .try_for_each(|(_, attr)| attr.validate_euids(schema))
    }

    /// Check whether this partial record is consistent with a concrete record.
    ///
    /// This is checking consistency, not validity. To guarantee TPE soundness we must also check
    /// that `other` is valid with respect to its expected type.
    pub fn check_consistency(&self, other: &BTreeMap<SmolStr, Value>) -> bool {
        self.attrs()
            .all(|(k, attr)| attr.check_consistency(other.get(k)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::types::{AttributeType, Attributes, OpenTag};

    fn long_attrs(required: impl IntoIterator<Item = &'static str>) -> Attributes {
        Attributes::with_attributes(required.into_iter().map(|k| {
            (
                k.into(),
                AttributeType::required_attribute(Arc::new(Type::primitive_long())),
            )
        }))
    }

    #[test]
    fn from_concrete_map_marks_missing_declared_absent() {
        let map = BTreeMap::from_iter([("a".into(), Value::from(1))]);
        let rec = PartialRecord::from_concrete_record(&map, &long_attrs(["a", "b"]));
        assert_eq!(rec.attr("a"), &AttrState::Value(Value::from(1)));
        assert_eq!(rec.attr("b"), &AttrState::Absent);
    }

    #[test]
    fn from_concrete_map_keeps_undeclared_attr() {
        let map = BTreeMap::from_iter([
            ("declared".into(), Value::from(1)),
            ("undeclared".into(), Value::from(2)),
        ]);
        let rec = PartialRecord::from_concrete_record(&map, &long_attrs(["declared"]));
        assert_eq!(rec.attr("undeclared"), &AttrState::Value(Value::from(2)));
        // ... and it is exactly what stops the record determining a concrete one.
        assert_eq!(rec.as_values(&long_attrs(["declared"])), None);
    }

    #[test]
    fn from_concrete_map_does_not_split_nested_record() {
        let inner = Value::record([("inner", Value::from(1))], None);
        let map = BTreeMap::from_iter([("outer".into(), inner.clone())]);
        let attrs = Attributes::with_attributes([(
            "outer".into(),
            AttributeType::required_attribute(Arc::new(Type::record_with_required_attributes(
                [("inner".into(), Arc::new(Type::primitive_long()))],
                OpenTag::ClosedAttributes,
            ))),
        )]);
        let rec = PartialRecord::from_concrete_record(&map, &attrs);
        assert_eq!(rec.attr("outer"), &AttrState::Value(inner));
    }

    #[test]
    fn as_values_requires_every_declared_attr_decided() {
        let attrs = long_attrs(["a", "b"]);
        let rec = PartialRecord::from_iter([("a".into(), AttrState::Value(Value::from(1)))]);
        assert_eq!(rec.as_values(&attrs), None);

        let rec = PartialRecord::from_iter([
            ("a".into(), AttrState::Value(Value::from(1))),
            ("b".into(), AttrState::Absent),
        ]);
        assert_eq!(
            rec.as_values(&attrs),
            Some(BTreeMap::from_iter([("a".into(), Value::from(1))]))
        );
    }

    #[test]
    fn as_values_folds_nested_partial_record() {
        let inner_ty = Type::record_with_required_attributes(
            [("inner".into(), Arc::new(Type::primitive_long()))],
            OpenTag::ClosedAttributes,
        );
        let attrs = Attributes::with_attributes([(
            "outer".into(),
            AttributeType::required_attribute(Arc::new(inner_ty)),
        )]);
        let inner = PartialRecord::from_iter([("inner".into(), AttrState::Value(Value::from(1)))]);
        let rec = PartialRecord::from_iter([("outer".into(), AttrState::PartialRecord(inner))]);
        assert_eq!(
            rec.as_values(&attrs),
            Some(BTreeMap::from_iter([(
                "outer".into(),
                Value::record([("inner", Value::from(1))], None)
            )]))
        );
    }

    #[test]
    fn check_consistency_per_state() {
        let concrete = BTreeMap::from_iter([("a".into(), Value::from(1))]);
        let cases: [(AttrState, bool); 5] = [
            (AttrState::Value(Value::from(1)), true),
            (AttrState::Value(Value::from(2)), false),
            (AttrState::Present, true),
            (AttrState::Absent, false),
            (AttrState::Unknown, true),
        ];
        for (state, expected) in cases {
            let rec = PartialRecord::from_iter([("a".into(), state.clone())]);
            assert_eq!(
                rec.check_consistency(&concrete),
                expected,
                "state {state:?} against {concrete:?}"
            );
        }
        let rec = PartialRecord::from_iter([("b".into(), AttrState::Absent)]);
        assert!(rec.check_consistency(&concrete));
        let rec = PartialRecord::from_iter([("b".into(), AttrState::Present)]);
        assert!(!rec.check_consistency(&concrete));
    }

    #[test]
    fn check_consistency_value_record_is_exact() {
        let concrete = BTreeMap::from_iter([(
            "a".into(),
            Value::record([("x", Value::from(1)), ("y", Value::from(2))], None),
        )]);
        let rec = PartialRecord::from_iter([(
            "a".into(),
            AttrState::Value(Value::record([("x", Value::from(1))], None)),
        )]);
        assert!(!rec.check_consistency(&concrete));

        // The same partial knowledge stated as a `PartialRecord` *is* consistent.
        let rec = PartialRecord::from_iter([(
            "a".into(),
            AttrState::PartialRecord(PartialRecord::from_iter([(
                "x".into(),
                AttrState::Value(Value::from(1)),
            )])),
        )]);
        assert!(rec.check_consistency(&concrete));
    }

    #[test]
    fn resolve_attr_recovers_omitted_attr_from_type() {
        let attrs = Attributes::with_required_attributes([(
            "req".into(),
            Arc::new(Type::primitive_long()),
        )]);
        let rec = PartialRecord::new();
        assert_eq!(rec.resolve_attr("req", &attrs), AttrState::Present,);
        assert_eq!(rec.resolve_attr("undeclared", &attrs), AttrState::Absent,);
    }
}
