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
use crate::entities::conformance::{
    validate_euid, validate_euids_in_partial_value, ValidateEuidError,
};
use crate::entities::{Schema, SchemaType};
use crate::tpe::evaluator::normalize_ext_value;
use crate::tpe::residual::Residual;
use crate::validator::types::{Attributes, Type};
use crate::validator::ValidatorSchema;
use miette::Diagnostic;
use std::ops::Deref;
use thiserror::Error;

/// A value was supplied that the schema gives no type to, so TPE — which is
/// type-aware — cannot represent it.
#[derive(Debug, Clone, PartialEq, Eq, Error, Diagnostic)]
pub enum UntypedValueError {
    /// An attribute (or tag) that the schema declares no type for
    #[error("attribute `{attr}` is not declared in the schema, so it has no type")]
    UndeclaredAttr {
        /// The attribute (or tag) with no declared type
        attr: SmolStr,
    },
    /// A context was supplied for an action the schema does not declare, so
    /// there is no context type to interpret it against
    #[error("action `{action}` is not declared in the schema, so its context has no type")]
    UndeclaredAction {
        /// The action with no declared context type
        action: EntityUID,
    },
}

impl UntypedValueError {
    /// The name of the offending attribute (or tag), or the action's id when the
    /// whole context is untyped.
    pub fn attr_name(&self) -> SmolStr {
        match self {
            Self::UndeclaredAttr { attr } => attr.clone(),
            Self::UndeclaredAction { action } => action.eid().escaped(),
        }
    }
}

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

    /// Construct from a concrete context record for this action based on the context type in the schema.
    ///
    /// Errors if `action` is undeclared, or if the context supplies an attribute
    /// its context type does not declare. Neither is reported as a *missing*
    /// context, which would silently discard the one the caller supplied.
    pub fn concrete_context_for_action(
        map: &BTreeMap<SmolStr, Value>,
        action: &EntityUID,
        schema: &ValidatorSchema,
    ) -> Result<Self, UntypedValueError> {
        let action_id =
            schema
                .get_action_id(action)
                .ok_or_else(|| UntypedValueError::UndeclaredAction {
                    action: action.clone(),
                })?;
        let Type::Record { attrs, .. } = action_id.context_type() else {
            #[expect(
                clippy::panic,
                reason = "an action context type declared in a schema is always a record type"
            )]
            {
                panic!("An action context type declared in a schema can only ever be a record type")
            }
        };
        Self::from_concrete_map(map, attrs)
    }

    /// Construct from a concrete `BTreeMap<SmolStr, Value>`, wrapping all
    /// attributes in the map with `Value`. Any attributes that are allowed by
    /// the schema but not in the map are absent.
    ///
    /// Every value in `map` must have a type in `attr_tys`: TPE is type-aware,
    /// so a value the schema does not describe has no place in a
    /// [`PartialRecord`]. Such an attribute is reported via
    /// [`UntypedValueError`] rather than being stored untyped or dropped.
    pub fn from_concrete_map(
        map: &BTreeMap<SmolStr, Value>,
        attr_tys: &Attributes,
    ) -> Result<Self, UntypedValueError> {
        // Reject anything the schema doesn't describe before building. An
        // undeclared attribute is a schema violation, and we have no type to
        // represent its value with.
        if let Some((attr, _)) = map.iter().find(|(k, _)| attr_tys.get_attr(k).is_none()) {
            return Err(UntypedValueError::UndeclaredAttr { attr: attr.clone() });
        }
        attr_tys
            .iter()
            .map(|(k, aty)| {
                let pv = match map.get(k) {
                    Some(v) => PartialAttribute::Value(PartialValue::from_value(
                        v.clone(),
                        aty.attr_type.as_ref(),
                    )?),
                    // We're starting from a concrete record where any attribute
                    // that isn't in a record is absent, and so should not be
                    // unknown by default.
                    None => PartialAttribute::Absent,
                };
                Ok((k.clone(), pv))
            })
            .collect::<Result<Vec<_>, UntypedValueError>>()
            .map(PartialRecord::from_attrs)
    }

    /// Try convert to a concrete `BTreeMap<SmolStr, Value>`, assuming that all required attribute are present.
    ///
    /// Returns `None` if any field is `Exists` or holds a nested unknown.
    /// Unlike [`Self::try_into_concrete_map`], this cannot detect a
    /// schema-declared field missing from the map (that requires the type), so
    /// it is only for records already known to list every field — e.g. one built
    /// from a concrete `Context`.
    pub(crate) fn into_concrete_map_assuming_complete(&self) -> Option<BTreeMap<SmolStr, Value>> {
        let mut map = BTreeMap::new();
        for (k, attr) in self.iter() {
            match attr {
                PartialAttribute::Value(v) => {
                    map.insert(k.clone(), v.into_value_assuming_complete()?);
                }
                PartialAttribute::Absent => {}
                PartialAttribute::Exists => return None,
            }
        }
        Some(map)
    }

    /// Try to convert to a concrete `BTreeMap<SmolStr, Value>`.
    ///
    /// Returns `None` if any field is `Exists`, if `expected_ty` declares a
    /// field not in the map (not-in-map = unknown existence = not concrete), if
    /// a `Value` field is not declared by `expected_ty` (no type to convert it
    /// against), or if `expected_ty` is not a record type. `Absent` fields are
    /// skipped: they definitively don't exist, so the map simply omits them.
    pub fn try_into_concrete_map(
        &self,
        expected_ty: &SchemaType,
    ) -> Option<BTreeMap<SmolStr, Value>> {
        let SchemaType::Record {
            attrs: expected_attrs,
            ..
        } = expected_ty
        else {
            // A record can't be concrete at a non-record type.
            return None;
        };
        for k in expected_attrs.keys() {
            if !self.contains_key(k) {
                return None;
            }
        }
        let mut map = BTreeMap::new();
        for (k, attr) in self.iter() {
            match attr {
                PartialAttribute::Value(v) => {
                    let field_ty = &expected_attrs.get(k)?.attr_type;
                    map.insert(k.clone(), v.try_into_value(field_ty)?);
                }
                PartialAttribute::Absent => {}
                PartialAttribute::Exists => return None,
            }
        }
        Some(map)
    }

    /// Validate every entity UID in the known parts of this record; see
    /// [`PartialValue::validate_euids`].
    pub fn validate_euids(&self, schema: &impl Schema) -> Result<(), ValidateEuidError> {
        self.values().try_for_each(|attr| match attr {
            PartialAttribute::Value(v) => v.validate_euids(schema),
            PartialAttribute::Exists | PartialAttribute::Absent => Ok(()),
        })
    }

    /// Check whether this partial record is consistent with a concrete record.
    ///
    /// For each attribute in the partial record:
    /// - `Value(v)`: the concrete record must have the key with a matching value
    /// - `Exists`: the concrete record must have the key (value is unchecked)
    /// - `Absent`: the concrete record must NOT have the key
    /// - Not in map: no constraint (existence unknown)
    ///
    /// This deliberately imposes *no* constraint on keys of `other` that are
    /// absent from `self`, and cannot: with no schema type in hand it cannot
    /// tell an omitted optional attribute (existence unknown — an extra key in
    /// `other` is legal) from an undeclared one (which TPE folded to `Absent` —
    /// an extra key would be inconsistent). The two are indistinguishable here,
    /// so a "reject extra keys" rule would wrongly reject valid optional data.
    /// The undeclared-attribute fold is instead kept sound by the concrete
    /// entity's schema-conformance check at reauthorization
    /// ([`crate::tpe::response::Response::reauthorize`]): against a *closed*
    /// record type, a concrete record carrying an undeclared key fails
    /// conformance before authorization runs. That closed-record guarantee — the
    /// same one [`crate::tpe::residual::RecordValue::attr_state`] relies on — is
    /// what discharges this case, not `check_consistency`.
    pub fn check_consistency(&self, other: &BTreeMap<SmolStr, Value>) -> bool {
        for (k, attr) in self.iter() {
            match attr {
                PartialAttribute::Value(v) => match other.get(k) {
                    Some(concrete) => {
                        if !v.check_consistency(concrete) {
                            return false;
                        }
                    }
                    None => return false,
                },
                PartialAttribute::Exists => {
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
    pub fn to_partial_residual(&self, ty: &Type, parent_expr: &Residual) -> Residual {
        PartialValue::Record(self.clone()).to_residual_with_expr(ty, parent_expr)
    }
}

/// An attribute in a [`PartialRecord`], in one of three explicit states plus a
/// fourth expressed by absence from the map.
///
/// - **`Value(v)`**: the attribute exists and has value `v`. Both existence and
///   value are validated.
/// - **`Exists`**: the attribute definitely exists, but its value is unknown.
///   Unexpected `Exists` attributes are rejected; value typechecking is skipped.
/// - **`Absent`**: the attribute is definitively not present. A required
///   attribute that is `Absent` is a validation error.
/// - **Not in the map** (no variant): existence is itself unknown — we don't
///   know whether the attribute is present at all.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub enum PartialAttribute {
    /// The attribute exists and has a known value
    Value(PartialValue),
    /// The attribute exists but its value is unknown
    Exists,
    /// The attribute is known to not exist
    Absent,
}

impl PartialAttribute {
    /// The attribute's value, if it has a known one.
    pub fn as_value(&self) -> Option<&PartialValue> {
        match self {
            PartialAttribute::Value(v) => Some(v),
            PartialAttribute::Exists | PartialAttribute::Absent => None,
        }
    }
}

impl PartialValue {
    /// Convert an `ast::Value` into a [`PartialValue`] (all attributes present).
    ///
    /// `ty` must be the type of `value` according to the schema; it decides
    /// which record attributes are `Absent` (declared by the type but missing
    /// from the value). A record value whose type is not a record type, or a
    /// record attribute the type does not declare, is a schema violation with
    /// no type to represent it: TPE is type-aware, so this is reported as an
    /// [`UntypedValueError`] rather than stored untyped.
    pub fn from_value(value: Value, ty: &Type) -> Result<Self, UntypedValueError> {
        match value.value {
            ValueKind::Lit(literal) => Ok(PartialValue::Lit(literal)),
            ValueKind::Set(set) => Ok(PartialValue::Set(set)),
            ValueKind::Record(attrs) => {
                let Type::Record {
                    attrs: attrs_tys, ..
                } = ty
                else {
                    // A record value with a non-record type. Name a field so
                    // the error points somewhere useful.
                    return Err(UntypedValueError::UndeclaredAttr {
                        attr: attrs.keys().next().cloned().unwrap_or_else(|| "".into()),
                    });
                };
                Ok(PartialValue::Record(PartialRecord::from_concrete_map(
                    attrs.as_ref(),
                    attrs_tys,
                )?))
            }
            ValueKind::ExtensionValue(extn) => Ok(PartialValue::ExtensionValue(extn)),
        }
    }

    /// Convert to an `ast::Value`. See [`PartialRecord::into_concrete_map_unchecked`] for assumptions.
    pub(crate) fn into_value_assuming_complete(&self) -> Option<Value> {
        match self {
            PartialValue::Lit(lit) => Some(Value::new(lit.clone(), None)),
            PartialValue::Set(set) => Some(Value {
                value: ValueKind::Set(set.clone()),
                loc: None,
            }),
            PartialValue::Record(rec) => rec
                .into_concrete_map_assuming_complete()
                .map(|attrs| Value::record(attrs, None)),
            PartialValue::ExtensionValue(ext) => Some(Value {
                value: ValueKind::ExtensionValue(ext.clone()),
                loc: None,
            }),
        }
    }

    /// Try to convert back to an `ast::Value`. Returns `None` if this value is
    /// not fully concrete at `expected_ty`; see
    /// [`PartialRecord::try_into_concrete_map`] for the record cases.
    pub fn try_into_value(&self, expected_ty: &SchemaType) -> Option<Value> {
        match self {
            PartialValue::Lit(lit) => Some(Value::new(lit.clone(), None)),
            PartialValue::Set(set) => Some(Value {
                value: ValueKind::Set(set.clone()),
                loc: None,
            }),
            PartialValue::Record(rec) => rec
                .try_into_concrete_map(expected_ty)
                .map(|attrs| Value::record(attrs, None)),
            PartialValue::ExtensionValue(ext) => Some(Value {
                value: ValueKind::ExtensionValue(ext.clone()),
                loc: None,
            }),
        }
    }

    /// Convert to a [`Residual`]. `parent_expr` is the residual expression
    /// that produced this value (e.g., `Document::"doc".meta`); it becomes the
    /// [`RecordValue`](crate::tpe::residual::RecordValue)'s `base` and the target
    /// of any attribute reference recovered from the type.
    ///
    /// A record that is not fully concrete keeps its attributes as they are,
    /// unlowered; each is lowered individually when read. Attributes not stated
    /// here are not enumerated; they are recovered from the record type at access
    /// time (see
    /// [`RecordValue::attr_state`](crate::tpe::residual::RecordValue::attr_state)).
    pub fn to_residual_with_expr(
        &self,
        ty: &crate::validator::types::Type,
        parent_expr: &crate::tpe::residual::Residual,
    ) -> crate::tpe::residual::Residual {
        use crate::tpe::residual::{RecordValue, Residual, ResidualKind};
        match self {
            PartialValue::Record(rec) => {
                // A record with nothing unknown reduces to a value, as the
                // context var does. Only attempt this with a `SchemaType` in
                // hand: `try_into_value` needs it to tell an unlisted declared
                // field (existence unknown, so not concrete) from one that isn't
                // declared at all. Passing `None` would fold too eagerly.
                if let Ok(schema_ty) = SchemaType::try_from(ty.clone()) {
                    if let Some(concrete) = self.try_into_value(&schema_ty) {
                        return Residual::Concrete {
                            value: normalize_ext_value(concrete),
                            ty: ty.clone(),
                        };
                    }
                }
                // Store the attributes exactly as stated, without lowering them.
                // Each is lowered individually when accessed, so reading one
                // attribute costs a lookup rather than a walk of the whole
                // subtree. Attributes not listed here are recovered from the
                // record type at access time (required → exists, optional →
                // existence unknown, undeclared → absent).
                Residual::Partial {
                    kind: ResidualKind::RecordValue(RecordValue {
                        base: Arc::new(parent_expr.clone()),
                        known: rec.clone(),
                    }),
                    ty: ty.clone(),
                }
            }
            // Non-record values hold no partial state, so each converts with no
            // fallible step. `normalize_ext_value` applies to all of them: it
            // also rewrites extension values nested in a set.
            PartialValue::Lit(lit) => Residual::Concrete {
                value: normalize_ext_value(Value::new(lit.clone(), None)),
                ty: ty.clone(),
            },
            PartialValue::Set(set) => Residual::Concrete {
                value: normalize_ext_value(Value {
                    value: ValueKind::Set(set.clone()),
                    loc: None,
                }),
                ty: ty.clone(),
            },
            PartialValue::ExtensionValue(ext) => Residual::Concrete {
                value: normalize_ext_value(Value {
                    value: ValueKind::ExtensionValue(ext.clone()),
                    loc: None,
                }),
                ty: ty.clone(),
            },
        }
    }

    /// All literal entity uids appearing in the known parts of this value.
    pub fn all_literal_uids(&self) -> std::collections::HashSet<EntityUID> {
        match self {
            PartialValue::Lit(Literal::EntityUID(euid)) => {
                std::iter::once(euid.as_ref().clone()).collect()
            }
            PartialValue::Lit(_) | PartialValue::ExtensionValue(_) => {
                std::collections::HashSet::new()
            }
            PartialValue::Set(set) => set.iter().flat_map(Value::all_literal_uids).collect(),
            PartialValue::Record(rec) => rec
                .values()
                .filter_map(PartialAttribute::as_value)
                .flat_map(PartialValue::all_literal_uids)
                .collect(),
        }
    }

    /// Validate every entity UID appearing in the known parts of this value,
    /// via [`validate_euid`].
    ///
    /// Walks the partial structure directly: `Exists` and `Absent` attributes
    /// hold no euids to check, and their presence does not stop the rest of the
    /// value being validated.
    pub fn validate_euids(&self, schema: &impl Schema) -> Result<(), ValidateEuidError> {
        match self {
            PartialValue::Lit(Literal::EntityUID(euid)) => validate_euid(schema, euid.as_ref()),
            PartialValue::Lit(_) | PartialValue::ExtensionValue(_) => Ok(()),
            PartialValue::Set(set) => set.iter().try_for_each(|v| {
                validate_euids_in_partial_value(schema, &crate::ast::PartialValue::from(v.clone()))
            }),
            PartialValue::Record(rec) => rec.validate_euids(schema),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::types::{AttributeType, Attributes};
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
            PartialRecord::from_concrete_map(&map, &long_attrs(["declared"])),
            Err(UntypedValueError::UndeclaredAttr { attr }) => assert_eq!(attr, "undeclared")
        );
    }

    #[test]
    fn from_concrete_map_marks_missing_declared_absent() {
        let map = BTreeMap::from_iter([("a".into(), Value::from(1))]);
        let rec = PartialRecord::from_concrete_map(&map, &long_attrs(["a", "b"]))
            .expect("all attributes are declared");
        assert_eq!(
            rec.get("a"),
            Some(&PartialAttribute::Value(PartialValue::Lit(1.into())))
        );
        assert_eq!(rec.get("b"), Some(&PartialAttribute::Absent));
    }

    /// A schema violation with no type to represent it: reported, not panicked on.
    #[test]
    fn from_value_rejects_record_with_non_record_type() {
        let value = Value::record([("q", Value::from(1))], None);
        assert_matches!(
            PartialValue::from_value(value, &Type::primitive_long()),
            Err(UntypedValueError::UndeclaredAttr { attr }) => assert_eq!(attr, "q")
        );
    }

    #[test]
    fn try_into_value_rejects_undeclared_present_attr() {
        let ty = SchemaType::Record {
            attrs: [(
                "x".into(),
                crate::entities::AttributeType::required(SchemaType::Long),
            )]
            .into_iter()
            .collect(),
            open_attrs: false,
        };
        let rec = PartialRecord::from_attrs([
            (
                "x".into(),
                PartialAttribute::Value(PartialValue::Lit(1.into())),
            ),
            (
                "undeclared".into(),
                PartialAttribute::Value(PartialValue::Lit(2.into())),
            ),
        ]);
        assert_eq!(PartialValue::Record(rec.clone()).try_into_value(&ty), None);
        assert_eq!(rec.try_into_concrete_map(&ty), None);
    }

    #[test]
    fn from_value_rejects_nested_undeclared_attr() {
        let inner_ty = Type::record_with_required_attributes(
            [("inner".into(), Arc::new(Type::primitive_long()))],
            crate::validator::types::OpenTag::ClosedAttributes,
        );
        let outer_ty = Type::record_with_required_attributes(
            [("outer".into(), Arc::new(inner_ty))],
            crate::validator::types::OpenTag::ClosedAttributes,
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
            Err(UntypedValueError::UndeclaredAttr { attr }) => assert_eq!(attr, "bogus")
        );
    }
}
