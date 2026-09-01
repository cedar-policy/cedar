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

//! Defines partial values which may have unknown values for record attributes.

use std::{collections::BTreeMap, sync::Arc};

use smol_str::SmolStr;

use crate::ast::{self, EntityUID, Literal, RepresentableExtensionValue, Set, Value, ValueKind};
use crate::entities::conformance::{
    validate_euid, validate_euids_in_partial_value, ValidateEuidError,
};
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
    /// An attribute (or tag) that the schema declares no type for
    #[error("type of attribute or tag `{}` is not declared in the schema", .0)]
    UntypedAttrOrTag(SmolStr),
    /// A context was supplied for an action the schema does not declare
    #[error("action `{}` is not declared in the schema, so its context has no type", .0)]
    UntypedContext(EntityUID),
}

/// A value that may contain unknown record attributes at any nesting level.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub enum PartialValue {
    /// A literal value
    Lit(Literal),
    /// A set of values
    Set(Set),
    /// A record that may contain unknown attributes
    Record(PartialRecord),
    /// An extension value
    ExtensionValue(Arc<RepresentableExtensionValue>),
}

/// A record where individual attributes may be unknown.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct PartialRecord(Arc<BTreeMap<SmolStr, PartialAttribute>>);

impl FromIterator<(SmolStr, PartialAttribute)> for PartialRecord {
    fn from_iter<T: IntoIterator<Item = (SmolStr, PartialAttribute)>>(iter: T) -> Self {
        PartialRecord(Arc::new(iter.into_iter().collect()))
    }
}

impl PartialRecord {
    /// Construct a `PartialRecord` from an attributes map
    pub fn from_attrs(attrs: Arc<BTreeMap<SmolStr, PartialAttribute>>) -> Self {
        PartialRecord(attrs)
    }

    /// Construct an empty `PartialRecord`
    pub(crate) fn new() -> Self {
        PartialRecord(Arc::new(BTreeMap::new()))
    }

    /// Get the partial value of `attr`
    ///
    /// Any attribute not explicitly in the record is `Unknown`
    pub(crate) fn attr(&self, attr: &str) -> &PartialAttribute {
        self.0.get(attr).unwrap_or(&PartialAttribute::Unknown)
    }

    /// The attributes this record explicitly states
    pub fn attrs(&self) -> impl Iterator<Item = (&SmolStr, &PartialAttribute)> {
        self.0.iter()
    }

    /// Get the partial value of `attr`, informed by the declared attribute types
    ///
    /// An attribute not explicitly in the record has partial information based on what we can infer
    /// from the attribute types.
    pub(crate) fn resolve_attr<'a, 'b>(
        &'a self,
        attr: &str,
        attr_tys: &'b Attributes,
    ) -> PartialAttribute<(&'a PartialValue, &'b Type)> {
        let attr_ty = attr_tys.get_attr(attr);
        match self.attr(attr) {
            PartialAttribute::Value(value) => match attr_ty {
                Some(at) => PartialAttribute::Value((value, &at.attr_type)),
                None => PartialAttribute::Exists,
            },
            PartialAttribute::Exists => PartialAttribute::Exists,
            PartialAttribute::Absent => PartialAttribute::Absent,
            PartialAttribute::Unknown => PartialAttribute::from_declared(attr_ty),
        }
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
        Self::from_concrete_record(attrs, atys).map_err(UntypedValueError::UntypedAttrOrTag)
    }

    /// Construct a partial context for `action` from partial attributes information
    pub fn partial_context_for_action<V>(
        attrs: impl IntoIterator<Item = (SmolStr, PartialAttribute<V>)>,
        action: &EntityUID,
        schema: &ValidatorSchema,
        resolve: impl Fn(V, &Type) -> Result<PartialValue, Option<SmolStr>>,
    ) -> Result<Self, UntypedValueError> {
        let Some(Type::Record { attrs: atys, .. }) =
            schema.get_action_id(action).map(|a| a.context_type())
        else {
            return Err(UntypedValueError::UntypedContext(action.clone()));
        };
        attrs
            .into_iter()
            .map(|(k, attr)| {
                let state = match attr {
                    PartialAttribute::Value(v) => {
                        let ty = atys
                            .get_attr(&k)
                            .map(|a| a.attr_type.as_ref().clone())
                            .ok_or_else(|| UntypedValueError::UntypedAttrOrTag(k.clone()))?;
                        PartialAttribute::Value(resolve(v, &ty).map_err(|e| {
                            UntypedValueError::UntypedAttrOrTag(e.unwrap_or_else(|| k.clone()))
                        })?)
                    }
                    PartialAttribute::Exists => PartialAttribute::Exists,
                    PartialAttribute::Absent => PartialAttribute::Absent,
                    PartialAttribute::Unknown => PartialAttribute::Unknown,
                };
                Ok((k, state))
            })
            .collect::<Result<Self, UntypedValueError>>()
    }

    /// Construct from a concrete attributes map and its type
    ///
    /// Because we're converting from a concrete record, we will never create an `Unknown` attribute.
    /// Any attribute that is optional in `attrs_tys` but not in `attrs` is known to be absent.
    pub fn from_concrete_record(
        attrs: &BTreeMap<SmolStr, Value>,
        attr_tys: &Attributes,
    ) -> Result<Self, SmolStr> {
        if let Some((attr, _)) = attrs.iter().find(|(k, _)| attr_tys.get_attr(k).is_none()) {
            return Err(attr.clone());
        }
        attr_tys
            .iter()
            .map(|(k, aty)| {
                let pv = match attrs.get(k) {
                    Some(v) => PartialAttribute::Value(PartialValue::from_value(
                        v.clone(),
                        aty.attr_type.as_ref(),
                    )?),
                    // We have a concrete record, so an attribute not in the record is absent.
                    None => PartialAttribute::Absent,
                };
                Ok((k.clone(), pv))
            })
            .collect()
    }

    /// Try to convert to a concrete record
    ///
    /// Conversion fails if any partial information is still incomplete. Specifically, if an attribute
    /// is `Exists` or `Unknown`, or if any attribute (required or optional) declared in the type is
    /// not explicit in the map.
    fn try_into_concrete_record(&self, expected_ty: &Type) -> Option<BTreeMap<SmolStr, Value>> {
        let Type::Record {
            attrs: expected_attrs,
            ..
        } = expected_ty
        else {
            return None;
        };
        if expected_attrs.keys().any(|k| !self.0.contains_key(k)) {
            // The record is not concrete if an attribute expected by the type is not present.
            return None;
        }
        if self
            .attrs()
            .any(|(_, v)| matches!(v, PartialAttribute::Exists | PartialAttribute::Unknown))
        {
            // The record is not concrete if any attribute isn't fully known
            return None;
        }

        self.attrs()
            .filter_map(|(k, v)| {
                if let PartialAttribute::Value(v) = v {
                    Some((k, v))
                } else {
                    // `v` might be absent, which might be _invalid_ according to the type, but it is
                    // nonetheless concrete. This function assumes well-typed values and does not typecheck.
                    None
                }
            })
            .map(|(k, v)| {
                let v = v
                    .clone()
                    .try_into_value(&expected_attrs.get_attr(k)?.attr_type)?;
                Some((k.clone(), v))
            })
            .collect()
    }

    pub(crate) fn validate_euids(&self, schema: &impl Schema) -> Result<(), ValidateEuidError> {
        self.attrs()
            .map(|(_, attr)| attr)
            .try_for_each(|attr| match attr {
                PartialAttribute::Value(v) => v.validate_euids(schema),
                PartialAttribute::Exists | PartialAttribute::Absent | PartialAttribute::Unknown => {
                    Ok(())
                }
            })
    }

    /// Check whether this partial record is consistent with a concrete record.
    ///
    /// This is checking consistency, not validity. To guarantee TPE soundness
    /// we must also check that `other` is valid with respect to it's expected type.
    pub fn check_consistency(&self, other: &BTreeMap<SmolStr, Value>) -> bool {
        self.attrs().all(|(k, attr)| match attr {
            PartialAttribute::Value(v) => other.get(k).is_some_and(|c| v.check_consistency(c)),
            PartialAttribute::Exists => other.contains_key(k),
            PartialAttribute::Absent => !other.contains_key(k),
            PartialAttribute::Unknown => true,
        })
    }
}

/// Possibly partial information about a attribute in a `PartialRecord`
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub enum PartialAttribute<V = PartialValue> {
    /// The attribute exists and has a known value
    Value(V),
    /// The attribute exists but its value is unknown
    Exists,
    /// The attribute is known to not exist
    Absent,
    /// Whether the attribute exists at all is unknown
    Unknown,
}

impl<V> PartialAttribute<V> {
    /// The partial information about an attribute implied by its declared type
    pub(crate) fn from_declared(declared: Option<&AttributeType>) -> Self {
        match declared {
            // Declared as required, so we can assume it exists
            Some(at) if at.is_required => PartialAttribute::Exists,
            // Declared as optional, so we can't assume anything
            Some(_) => PartialAttribute::Unknown,
            // Not declared, so we can assume it doesn't exist
            None => PartialAttribute::Absent,
        }
    }
}

impl PartialAttribute {
    /// The attribute's value, if it has a known one.
    pub fn as_value(&self) -> Option<&PartialValue> {
        match self {
            PartialAttribute::Value(v) => Some(v),
            PartialAttribute::Exists | PartialAttribute::Absent | PartialAttribute::Unknown => None,
        }
    }
}

impl PartialValue {
    /// Convert a concrete `ast::Value` into a `PartialValue`
    ///
    /// Conversion is informed by the type of the attribute, which lets us mark
    /// optional attribute explicitly absent if not present in the record.
    pub fn from_value(value: Value, ty: &Type) -> Result<Self, SmolStr> {
        match value.value {
            ValueKind::Lit(literal) => Ok(PartialValue::Lit(literal)),
            ValueKind::Set(set) => Ok(PartialValue::Set(set)),
            ValueKind::Record(attrs) => {
                let Type::Record {
                    attrs: attrs_tys, ..
                } = ty
                else {
                    // A record value but we see a non-record type
                    return Err(attrs.keys().next().cloned().unwrap_or_default());
                };
                Ok(PartialValue::Record(PartialRecord::from_concrete_record(
                    attrs.as_ref(),
                    attrs_tys,
                )?))
            }
            ValueKind::ExtensionValue(extn) => Ok(PartialValue::ExtensionValue(extn)),
        }
    }

    /// Try to convert back to an `ast::Value`.
    ///
    /// Returns `None` if this value is not fully concrete. `expected_ty` is required to know what
    /// attributes must be present in a concrete record value, but it is not used to typecheck the
    /// value. This function assumes the partial value is well typed.
    fn try_into_value(self, expected_ty: &Type) -> Option<Value> {
        match self {
            PartialValue::Lit(lit) => Some(Value::new(lit, None)),
            PartialValue::Set(set) => Some(Value {
                value: ValueKind::Set(set),
                loc: None,
            }),
            PartialValue::Record(rec) => rec
                .try_into_concrete_record(expected_ty)
                .map(|attrs| Value::record(attrs, None)),
            PartialValue::ExtensionValue(ext) => Some(Value {
                value: ValueKind::ExtensionValue(ext),
                loc: None,
            }),
        }
    }

    /// Convert into a concrete residual, if this value is fully known.
    pub(crate) fn try_into_residual(self, ty: Type) -> Option<Residual> {
        self.try_into_value(&ty).map(|value| Residual::Concrete {
            value: normalize_ext_value(value),
            ty,
        })
    }

    /// Validate every entity UID appearing in the known parts of this value
    pub fn validate_euids(&self, schema: &impl Schema) -> Result<(), ValidateEuidError> {
        match self {
            PartialValue::Lit(Literal::EntityUID(euid)) => validate_euid(schema, euid.as_ref()),
            PartialValue::Lit(_) | PartialValue::ExtensionValue(_) => Ok(()),
            PartialValue::Set(set) => set.iter().try_for_each(|v| {
                validate_euids_in_partial_value(schema, &ast::PartialValue::from(v.clone()))
            }),
            PartialValue::Record(rec) => rec.validate_euids(schema),
        }
    }

    /// Check whether this partial value is consistent with a concrete value
    pub fn check_consistency(&self, other: &Value) -> bool {
        match (self, &other.value) {
            (PartialValue::Record(attrs0), ValueKind::Record(attrs1)) => {
                attrs0.check_consistency(attrs1)
            }
            // Everything else is concrete, so we check exact equality
            (PartialValue::Lit(l0), ValueKind::Lit(l1)) => l0 == l1,
            (PartialValue::Set(s0), ValueKind::Set(s1)) => s0 == s1,
            (PartialValue::ExtensionValue(e0), ValueKind::ExtensionValue(e1)) => e0 == e1,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::types::{AttributeType, Attributes, OpenTag};
    use cool_asserts::assert_matches;

    fn long_attrs(required: impl IntoIterator<Item = &'static str>) -> Attributes {
        Attributes::with_attributes(required.into_iter().map(|k| {
            (
                k.into(),
                AttributeType::required_attribute(Arc::new(Type::primitive_long())),
            )
        }))
    }

    #[test]
    fn from_concrete_map_rejects_undeclared_attr() {
        let map = BTreeMap::from_iter([
            ("declared".into(), Value::from(1)),
            ("undeclared".into(), Value::from(2)),
        ]);
        assert_matches!(
            PartialRecord::from_concrete_record(&map, &long_attrs(["declared"])),
            Err(attr) => assert_eq!(attr, "undeclared")
        );
    }

    #[test]
    fn from_concrete_map_marks_missing_declared_absent() {
        let map = BTreeMap::from_iter([("a".into(), Value::from(1))]);
        let rec = PartialRecord::from_concrete_record(&map, &long_attrs(["a", "b"]))
            .expect("all attributes are declared");
        assert_eq!(
            rec.attr("a"),
            &PartialAttribute::Value(PartialValue::Lit(1.into()))
        );
        assert_eq!(rec.attr("b"), &PartialAttribute::Absent);
    }

    /// A schema violation with no type to represent it: reported, not panicked on.
    #[test]
    fn from_value_rejects_record_with_non_record_type() {
        let value = Value::record([("q", Value::from(1))], None);
        assert_matches!(
            PartialValue::from_value(value, &Type::primitive_long()),
            Err(attr) => assert_eq!(attr, "q")
        );
    }

    #[test]
    fn try_into_value_rejects_undeclared_present_attr() {
        let ty = &Type::record_with_required_attributes(
            [(SmolStr::new_static("x"), Arc::new(Type::Long))],
            OpenTag::ClosedAttributes,
        );
        let rec = PartialRecord::from_iter([
            (
                "x".into(),
                PartialAttribute::Value(PartialValue::Lit(1.into())),
            ),
            (
                "undeclared".into(),
                PartialAttribute::Value(PartialValue::Lit(2.into())),
            ),
        ]);
        assert_eq!(PartialValue::Record(rec.clone()).try_into_value(ty), None);
        assert_eq!(rec.try_into_concrete_record(ty), None);
    }

    #[test]
    fn from_value_rejects_nested_undeclared_attr() {
        let inner_ty = Type::record_with_required_attributes(
            [("inner".into(), Arc::new(Type::primitive_long()))],
            OpenTag::ClosedAttributes,
        );
        let outer_ty = Type::record_with_required_attributes(
            [("outer".into(), Arc::new(inner_ty))],
            OpenTag::ClosedAttributes,
        );
        let value = Value::record(
            [(
                "outer",
                Value::record([("inner", Value::from(1)), ("bogus", Value::from(2))], None),
            )],
            None,
        );
        assert_matches!(
            PartialValue::from_value(value, &outer_ty),
            Err(attr) => assert_eq!(attr, "bogus")
        );
    }
}
