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

use crate::ast::{EntityUID, Literal, RepresentableExtensionValue, Set, Value, ValueKind};
use crate::entities::SchemaType;
use crate::tpe::evaluator::normalize_ext_value;
use crate::validator::types::{Attributes, Type};
use crate::validator::ValidatorSchema;
use std::ops::Deref;

/// A value that may contain unknown record attributes at any nesting level.
/// Unlike `ast::PartialValue` (which is either fully known or a residual
/// expression), this type allows individual record fields to be unknown while
/// the rest of the value is concrete.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub enum PartialValue {
    /// A literal value (bool, long, string, entity UID)
    Lit(Literal),
    /// A set of values
    Set(Set),
    /// A record that may contain unknown attributes
    Record(PartialRecord),
    /// An extension value (e.g., decimal, ipaddr)
    ExtensionValue(Arc<RepresentableExtensionValue>),
}

/// A record where individual attributes may be unknown.
/// Wraps a `BTreeMap<SmolStr, PartialAttribute>` in an `Arc` for cheap cloning.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct PartialRecord(Arc<BTreeMap<SmolStr, PartialAttribute>>);

impl Deref for PartialRecord {
    type Target = BTreeMap<SmolStr, PartialAttribute>;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl Default for PartialRecord {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialRecord {
    /// Construct a [`PartialRecord`] from an iterator of (key, attribute) pairs
    pub fn from_attrs(attrs: impl IntoIterator<Item = (SmolStr, PartialAttribute)>) -> Self {
        PartialRecord(Arc::new(attrs.into_iter().collect()))
    }

    /// Construct an empty [`PartialRecord`]
    pub fn new() -> Self {
        PartialRecord(Arc::new(BTreeMap::new()))
    }

    /// Construct from a concrete context record for this action based on the actions context type in the schema.
    pub fn concrete_context_for_action(
        map: &BTreeMap<SmolStr, Value>,
        action: &EntityUID,
        schema: &ValidatorSchema,
    ) -> Option<Self> {
        let action = schema.get_action_id(action)?;
        let Type::Record { attrs, .. } = action.context_type() else {
            panic!("An action context type declared in a schema can only ever by a record type")
        };
        Some(Self::from_concrete_map(map, attrs))
    }

    /// Construct from a concrete `BTreeMap<SmolStr, Value>`, wrapping all
    /// attributes in the map with `Present`. Any attributes that are allowed by
    /// the schema but not in the are be absent.
    pub fn from_concrete_map(map: &BTreeMap<SmolStr, Value>, attr_tys: &Attributes) -> Self {
        PartialRecord::from_attrs(attr_tys.iter().map(|(k, aty)| {
            let pv = match map.get(k) {
                Some(v) => PartialAttribute::Present(PartialValue::from_value(
                    v.clone(),
                    aty.attr_type.as_ref(),
                )),
                // We're starting from a concrete record where any attribute
                // that isn't in a record is absent, and so should not be
                // unknown by default.
                None => PartialAttribute::Absent,
            };
            (k.clone(), pv)
        }))
    }

    /// Ensure that all required attributes declared in `ty` are present in the
    /// map. Required fields not already in the map are added as [`PartialAttribute::Unknown`]
    /// (the schema guarantees they exist, but we don't know their value).
    pub fn fill_required_attrs(&mut self, ty: &Type) {
        let Type::Record { attrs, .. } = ty else {
            return;
        };
        let map = Arc::make_mut(&mut self.0);
        for (k, attr_ty) in attrs.iter() {
            if attr_ty.is_required && !map.contains_key(k) {
                map.insert(k.clone(), PartialAttribute::Unknown);
            }
        }
    }

    /// Try to convert to a concrete `BTreeMap<SmolStr, Value>`.
    /// Returns `None` if any field is `Unknown`, or if `expected_ty` declares
    /// attributes that are not present in the map (not-in-map = unknown
    /// existence = not concrete). `Absent` fields are skipped (they
    /// definitively don't exist, so the concrete map simply won't have them).
    pub fn try_into_concrete_map(
        &self,
        expected_ty: Option<&SchemaType>,
    ) -> Option<BTreeMap<SmolStr, Value>> {
        let expected_attrs = match expected_ty {
            Some(SchemaType::Record { attrs, .. }) => Some(attrs),
            _ => None,
        };
        if let Some(schema_attrs) = expected_attrs {
            for k in schema_attrs.keys() {
                if !self.contains_key(k) {
                    return None;
                }
            }
        }
        let mut map = BTreeMap::new();
        for (k, attr) in self.iter() {
            let field_ty = expected_attrs.and_then(|a| a.get(k)).map(|a| &a.attr_type);
            match attr {
                PartialAttribute::Present(v) => {
                    map.insert(k.clone(), v.try_into_value(field_ty)?);
                }
                PartialAttribute::Absent => {}
                PartialAttribute::Unknown => return None,
            }
        }
        Some(map)
    }

    /// Check whether this partial record is consistent with a concrete record.
    ///
    /// For each attribute in the partial record:
    /// - `Present(v)`: the concrete record must have the key with a matching value
    /// - `Unknown`: the concrete record must have the key (value is unchecked)
    /// - `Absent`: the concrete record must NOT have the key
    /// - Not in map: no constraint (unknown existence)
    pub fn check_consistency(&self, other: &BTreeMap<SmolStr, Value>) -> bool {
        for (k, attr) in self.iter() {
            match attr {
                PartialAttribute::Present(v) => match other.get(k) {
                    Some(concrete) => {
                        if !v.check_consistency(concrete) {
                            return false;
                        }
                    }
                    None => return false,
                },
                PartialAttribute::Unknown => {
                    if !other.contains_key(k) {
                        return false;
                    }
                }
                PartialAttribute::Absent => {
                    if other.contains_key(k) {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Convert this `PartialRecord` to a record `Residual`, using `parent_expr`
    /// as the base for unknown field references. Delegates to
    /// `PartialValue::Record(self).to_residual_with_expr(ty, parent_expr)`.
    pub fn to_partial_residual(
        &self,
        ty: &crate::validator::types::Type,
        parent_expr: &crate::tpe::residual::Residual,
    ) -> crate::tpe::residual::Residual {
        PartialValue::Record(self.clone()).to_residual_with_expr(ty, parent_expr)
    }
}

/// An attribute in a [`PartialRecord`]: present, unknown, or absent.
///
/// There are four states for an attribute in a partial record:
/// - **Not in the map**: we don't know whether the attribute exists in the
///   entity at all.
/// - **`Absent`**: the attribute is definitively not present in the entity.
///   A required attribute that is `Absent` is a validation error.
/// - **`Unknown`**: the attribute definitely exists, but we don't know its
///   value. Unexpected `Unknown` attributes are rejected; value typechecking
///   is skipped.
/// - **`Present(v)`**: the attribute exists and has value `v`. Both existence
///   and value are validated.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub enum PartialAttribute {
    /// The attribute exists and has a known value
    Present(PartialValue),
    /// The attribute exists but its value is unknown
    Unknown,
    /// The attribute is known to not exist
    Absent,
}

impl PartialAttribute {
    /// If this attribute is `Present`, return a reference to the value
    pub fn as_present(&self) -> Option<&PartialValue> {
        match self {
            PartialAttribute::Present(v) => Some(v),
            PartialAttribute::Unknown | PartialAttribute::Absent => None,
        }
    }
}

impl PartialValue {
    /// Convert an `ast::Value` into a [`PartialValue`] (all attributes present).
    /// Assumes that `value` has type `ty` and may panic if this is not the case.
    pub fn from_value(value: Value, ty: &Type) -> Self {
        match value.value {
            ValueKind::Lit(literal) => PartialValue::Lit(literal),
            ValueKind::Set(set) => PartialValue::Set(set),
            ValueKind::Record(attrs) => {
                let Type::Record {
                    attrs: attrs_tys, ..
                } = ty
                else {
                    panic!("a record value may only have a record type")
                };
                PartialValue::Record(PartialRecord::from_concrete_map(attrs.as_ref(), attrs_tys))
            }
            ValueKind::ExtensionValue(extn) => PartialValue::ExtensionValue(extn),
        }
    }

    /// Try to convert back to an `ast::Value`. Returns `None` if this value
    /// contains any `Unknown` attributes at any nesting level, or if
    /// `expected_ty` declares attributes not present in the record (not-in-map
    /// means unknown existence, so we can't produce a concrete value).
    pub fn try_into_value(&self, expected_ty: Option<&SchemaType>) -> Option<Value> {
        match self {
            PartialValue::Lit(lit) => Some(Value::new(lit.clone(), None)),
            PartialValue::Set(set) => Some(Value {
                value: ValueKind::Set(set.clone()),
                loc: None,
            }),
            PartialValue::Record(rec) => {
                let expected_attrs = match expected_ty {
                    Some(SchemaType::Record { attrs, .. }) => Some(attrs),
                    _ => None,
                };
                if let Some(schema_attrs) = expected_attrs {
                    for k in schema_attrs.keys() {
                        if !rec.contains_key(k) {
                            return None;
                        }
                    }
                }
                let mut attrs = BTreeMap::new();
                for (k, attr) in rec.iter() {
                    let field_ty = expected_attrs.and_then(|a| a.get(k)).map(|a| &a.attr_type);
                    match attr {
                        PartialAttribute::Unknown => return None,
                        PartialAttribute::Absent => {} // not present, skip
                        PartialAttribute::Present(v) => {
                            attrs.insert(k.clone(), v.try_into_value(field_ty)?);
                        }
                    }
                }
                Some(Value::record(attrs, None))
            }
            PartialValue::ExtensionValue(ext) => Some(Value {
                value: ValueKind::ExtensionValue(ext.clone()),
                loc: None,
            }),
        }
    }

    /// Convert to a [`Residual`]. `parent_expr` is the residual expression
    /// that produced this value (e.g., `Document::"doc".meta`), used to
    /// construct references for unknown fields.
    ///
    /// For records, only `Present` and `Unknown` entries are included:
    /// - `Present` → concrete value or nested residual
    /// - `Unknown` → `GetAttr(parent_expr, field)` residual
    /// - `Absent` → omitted (not in record → `has` and access produce residuals)
    /// - Not in map → not iterated (same as above)
    ///
    /// This loses precision for `Absent` in nested records (residual instead
    /// of error/false), but is sound and avoids conflating `Absent` with
    /// erroring subexpressions.
    pub fn to_residual_with_expr(
        &self,
        ty: &crate::validator::types::Type,
        parent_expr: &crate::tpe::residual::Residual,
    ) -> crate::tpe::residual::Residual {
        use crate::tpe::residual::{Residual, ResidualAttribute, ResidualKind};
        use crate::validator::types::Type;
        match self {
            PartialValue::Record(rec) => {
                let mut residual_map = BTreeMap::new();
                for (k, attr) in rec.iter() {
                    // Look up this field's type from the parent record type.
                    let field_ty = match ty {
                        Type::Record { attrs, .. } => attrs
                            .get_attr(k)
                            .map(|a| a.attr_type.as_ref().clone())
                            .unwrap_or(Type::Never),
                        _ => Type::Never,
                    };
                    let field_getattr = || Residual::Partial {
                        kind: ResidualKind::GetAttr {
                            expr: Arc::new(parent_expr.clone()),
                            attr: k.clone(),
                        },
                        ty: field_ty.clone(),
                    };
                    match attr {
                        PartialAttribute::Present(v) => {
                            let field_residual =
                                v.to_residual_with_expr(&field_ty, &field_getattr());
                            residual_map
                                .insert(k.clone(), ResidualAttribute::Value(field_residual));
                        }
                        PartialAttribute::Unknown => {
                            residual_map
                                .insert(k.clone(), ResidualAttribute::Unknown(parent_expr.clone()));
                        }
                        PartialAttribute::Absent => {
                            residual_map.insert(k.clone(), ResidualAttribute::Absent);
                        }
                    }
                }
                // Enumerate schema-declared fields not in the PartialRecord:
                // - Required fields → Unknown (must exist, value unknown)
                // - Optional fields → UnknownExistence (might not exist)
                if let Type::Record { attrs, .. } = ty {
                    for (k, attr_ty) in attrs.iter() {
                        if !residual_map.contains_key(k) {
                            if attr_ty.is_required {
                                residual_map.insert(
                                    k.clone(),
                                    ResidualAttribute::Unknown(parent_expr.clone()),
                                );
                            } else {
                                residual_map.insert(
                                    k.clone(),
                                    ResidualAttribute::UnknownExistence(parent_expr.clone()),
                                );
                            }
                        }
                    }
                }
                Residual::Partial {
                    kind: ResidualKind::Record {
                        fields: Arc::new(residual_map),
                    },
                    ty: ty.clone(),
                }
            }
            _ => Residual::Concrete {
                value: normalize_ext_value(
                    self.try_into_value(SchemaType::try_from(ty.clone()).ok().as_ref())
                        .expect("non-record PartialValue should always convert to Value"),
                ),
                ty: ty.clone(),
            },
        }
    }

    /// Check whether this partial value is consistent with a concrete value
    pub fn check_consistency(&self, other: &Value) -> bool {
        match (self, &other.value) {
            (PartialValue::Lit(l0), ValueKind::Lit(l1)) => l0 == l1,
            (PartialValue::Set(s0), ValueKind::Set(s1)) => s0 == s1,
            (PartialValue::Record(attrs0), ValueKind::Record(attrs1)) => {
                attrs0.check_consistency(attrs1)
            }
            (PartialValue::ExtensionValue(e0), ValueKind::ExtensionValue(e1)) => e0 == e1,
            _ => false,
        }
    }
}
