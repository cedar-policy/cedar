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

use super::{
    err::{JsonDeserializationError, JsonDeserializationErrorContext, JsonSerializationError},
    SchemaType,
};
use crate::entities::{
    conformance::err::EntitySchemaConformanceError,
    json::err::{EscapeKind, TypeMismatchError},
};
use crate::extensions::Extensions;
use crate::FromNormalizedStr;
use crate::{
    ast::{
        expression_construction_errors, BorrowedRestrictedExpr, Eid, EntityUID, ExprKind,
        ExpressionConstructionError, Literal, RestrictedExpr, Unknown, Value, ValueKind,
    },
    entities::Name,
};
use either::Either;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::{DeserializeAs, SerializeAs};
use smol_str::{SmolStr, ToSmolStr};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

#[cfg(feature = "wasm")]
extern crate tsify;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
enum RawCedarValueJson {
    /// JSON bool => Cedar bool
    Bool(bool),
    /// JSON int => Cedar long (64-bit signed integer)
    Long(i64),
    /// JSON string => Cedar string
    String(SmolStr),
    /// JSON list => Cedar set; can contain any `RawCedarValueJson`s, even
    /// heterogeneously
    Set(Vec<RawCedarValueJson>),
    /// JSON object => Cedar record; must have string keys, but values
    /// can be any `RawCedarValueJson`s, even heterogeneously
    Record(RawJsonRecord),
    /// JSON null, which is never valid, but we put this here in order to
    /// provide a better error message.
    Null,
}

/// The canonical JSON representation of a Cedar value.
/// Many Cedar values have a natural one-to-one mapping to and from JSON values.
/// Cedar values of some types, like entity references or extension values,
/// cannot easily be represented in JSON and thus are represented using the
/// `__entity`, or `__extn` escapes.
///
/// For example, this is the JSON format for attribute values expected by
/// `EntityJsonParser`, when schema-based parsing is not used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum CedarValueJson {
    /// The `__expr` escape has been removed, but is still reserved in order to throw meaningful errors.
    ExprEscape {
        /// Contents, will be ignored and an error is thrown when attempting to parse this
        #[cfg_attr(feature = "wasm", tsify(type = "__skip"))]
        __expr: SmolStr,
    },
    /// Special JSON object with single reserved "__entity" key:
    /// the following item should be a JSON object of the form
    /// `{ "type": "xxx", "id": "yyy" }`.
    /// This escape is necessary for entity references.
    //
    // listed before `Record` so that it takes priority: otherwise, the escape
    // would be interpreted as a Record with a key "__entity". see docs on
    // `serde(untagged)`
    EntityEscape {
        /// JSON object containing the entity type and ID
        __entity: TypeAndId,
    },
    /// Special JSON object with single reserved "__extn" key:
    /// the following item should be a JSON object of the form
    /// `{ "fn": "xxx", "arg": "yyy" }`.
    /// This escape is necessary for extension values.
    //
    // listed before `Record` so that it takes priority: otherwise, the escape
    // would be interpreted as a Record with a key "__extn". see docs on
    // `serde(untagged)`
    ExtnEscape {
        /// JSON object containing the extension-constructor call
        __extn: FnAndArgs,
    },
    /// JSON bool => Cedar bool
    Bool(bool),
    /// JSON int => Cedar long (64-bit signed integer)
    Long(i64),
    /// JSON string => Cedar string
    String(#[cfg_attr(feature = "wasm", tsify(type = "string"))] SmolStr),
    /// JSON list => Cedar set; can contain any `CedarValueJson`s, even
    /// heterogeneously
    Set(Vec<CedarValueJson>),
    /// JSON object => Cedar record; must have string keys, but values
    /// can be any `CedarValueJson`s, even heterogeneously
    Record(
        #[cfg_attr(feature = "wasm", tsify(type = "{ [key: string]: CedarValueJson }"))] JsonRecord,
    ),
    /// JSON null, which is never valid, but we put this here in order to
    /// provide a better error message.
    Null,
}

impl<'de> Deserialize<'de> for CedarValueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v: RawCedarValueJson = RawCedarValueJson::deserialize(deserializer)?;
        Ok(v.into())
    }
}

impl From<RawCedarValueJson> for CedarValueJson {
    fn from(value: RawCedarValueJson) -> Self {
        match value {
            RawCedarValueJson::Bool(b) => Self::Bool(b),
            RawCedarValueJson::Long(l) => Self::Long(l),
            RawCedarValueJson::Null => Self::Null,
            RawCedarValueJson::Record(r) => {
                let values = &r.values;
                if values.len() == 1 {
                    match values.iter().map(|(k, v)| (k.as_str(), v)).collect_vec()[..] {
                        [("__extn", RawCedarValueJson::Record(r))] => {
                            if r.values.len() >= 2 {
                                if let Some(RawCedarValueJson::String(fn_name)) = r.values.get("fn")
                                {
                                    if let Some(arg) = r.values.get("arg") {
                                        return Self::ExtnEscape {
                                            __extn: FnAndArgs::Single {
                                                ext_fn: fn_name.clone(),
                                                arg: Box::new(arg.clone().into()),
                                            },
                                        };
                                    }
                                    if let Some(RawCedarValueJson::Set(args)) = r.values.get("args")
                                    {
                                        return Self::ExtnEscape {
                                            __extn: FnAndArgs::Multi {
                                                ext_fn: fn_name.clone(),
                                                args: args
                                                    .iter()
                                                    .cloned()
                                                    .map(Into::into)
                                                    .collect(),
                                            },
                                        };
                                    }
                                }
                            }
                        }
                        [("__expr", RawCedarValueJson::String(s))] => {
                            return Self::ExprEscape { __expr: s.clone() };
                        }
                        [("__entity", RawCedarValueJson::Record(r))] => {
                            if r.values.len() >= 2 {
                                if let Some(RawCedarValueJson::String(ty)) = r.values.get("type") {
                                    if let Some(RawCedarValueJson::String(id)) = r.values.get("id")
                                    {
                                        return Self::EntityEscape {
                                            __entity: TypeAndId {
                                                entity_type: ty.clone(),
                                                id: id.clone(),
                                            },
                                        };
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Self::Record(r.into())
            }
            RawCedarValueJson::Set(s) => Self::Set(s.into_iter().map(Into::into).collect()),
            RawCedarValueJson::String(s) => Self::String(s),
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct RawJsonRecord {
    /// Cedar records must have string keys, but values can be any
    /// `CedarValueJson`s, even heterogeneously
    #[serde_as(as = "serde_with::MapPreventDuplicates<_, _>")]
    #[serde(flatten)]
    values: BTreeMap<SmolStr, RawCedarValueJson>,
}

impl From<RawJsonRecord> for JsonRecord {
    fn from(value: RawJsonRecord) -> Self {
        JsonRecord {
            values: value
                .values
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}

/// Structure representing a Cedar record in JSON
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JsonRecord {
    /// Cedar records must have string keys, but values can be any
    /// `CedarValueJson`s, even heterogeneously
    #[serde(flatten)]
    values: BTreeMap<SmolStr, CedarValueJson>,
}

impl IntoIterator for JsonRecord {
    type Item = (SmolStr, CedarValueJson);
    type IntoIter = <BTreeMap<SmolStr, CedarValueJson> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
    }
}

impl<'a> IntoIterator for &'a JsonRecord {
    type Item = (&'a SmolStr, &'a CedarValueJson);
    type IntoIter = <&'a BTreeMap<SmolStr, CedarValueJson> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}

// At this time, this doesn't check for duplicate keys upon constructing a
// `JsonRecord` from an iterator.
// As of this writing, we only construct `JsonRecord` from an iterator during
// _serialization_, not _deserialization_, and we can assume that values being
// serialized (i.e., coming from the Cedar engine itself) are already free of
// duplicate keys.
impl FromIterator<(SmolStr, CedarValueJson)> for JsonRecord {
    fn from_iter<T: IntoIterator<Item = (SmolStr, CedarValueJson)>>(iter: T) -> Self {
        Self {
            values: BTreeMap::from_iter(iter),
        }
    }
}

impl JsonRecord {
    /// Iterate over the (k, v) pairs in the record
    pub fn iter(&self) -> impl Iterator<Item = (&'_ SmolStr, &'_ CedarValueJson)> {
        self.values.iter()
    }

    /// Get the number of attributes in the record
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Is the record empty (no attributes)
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Structure expected by the `__entity` escape
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct TypeAndId {
    /// Entity typename
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    #[serde(rename = "type")]
    entity_type: SmolStr,
    /// Entity id
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    id: SmolStr,
}

impl From<EntityUID> for TypeAndId {
    fn from(euid: EntityUID) -> TypeAndId {
        let (entity_type, eid) = euid.components();
        TypeAndId {
            entity_type: entity_type.to_smolstr(),
            id: AsRef::<str>::as_ref(&eid).into(),
        }
    }
}

impl From<&EntityUID> for TypeAndId {
    fn from(euid: &EntityUID) -> TypeAndId {
        TypeAndId {
            entity_type: euid.entity_type().to_smolstr(),
            id: AsRef::<str>::as_ref(&euid.eid()).into(),
        }
    }
}

impl TryFrom<TypeAndId> for EntityUID {
    type Error = crate::parser::err::ParseErrors;

    fn try_from(e: TypeAndId) -> Result<EntityUID, crate::parser::err::ParseErrors> {
        Ok(EntityUID::from_components(
            Name::from_normalized_str(&e.entity_type)?.into(),
            Eid::new(e.id),
            None,
        ))
    }
}

/// Structure expected by the `__extn` escape
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(untagged)]
pub enum FnAndArgs {
    /// Single-argument function
    Single {
        /// Extension constructor function
        #[serde(rename = "fn")]
        #[cfg_attr(feature = "wasm", tsify(type = "string"))]
        ext_fn: SmolStr,
        /// Argument to that constructor
        arg: Box<CedarValueJson>,
    },
    /// Multi-argument function
    Multi {
        /// Extension constructor function
        #[serde(rename = "fn")]
        #[cfg_attr(feature = "wasm", tsify(type = "string"))]
        ext_fn: SmolStr,
        /// Arguments to that constructor
        args: Vec<CedarValueJson>,
    },
}

impl FnAndArgs {
    pub(crate) fn fn_str(&self) -> &str {
        match self {
            Self::Multi { ext_fn, .. } | Self::Single { ext_fn, .. } => ext_fn,
        }
    }

    pub(crate) fn args(&self) -> &[CedarValueJson] {
        match self {
            Self::Multi { args, .. } => args,
            Self::Single { arg, .. } => std::slice::from_ref(arg),
        }
    }
}

impl CedarValueJson {
    /// Encode the given `EntityUID` as a `CedarValueJson`
    pub fn uid(euid: &EntityUID) -> Self {
        Self::EntityEscape {
            __entity: TypeAndId::from(euid.clone()),
        }
    }

    /// Convert this `CedarValueJson` into a Cedar "restricted expression"
    pub fn into_expr(
        self,
        ctx: impl Fn() -> JsonDeserializationErrorContext + Clone,
    ) -> Result<RestrictedExpr, JsonDeserializationError> {
        match self {
            Self::Bool(b) => Ok(RestrictedExpr::val(b)),
            Self::Long(i) => Ok(RestrictedExpr::val(i)),
            Self::String(s) => Ok(RestrictedExpr::val(s)),
            Self::Set(vals) => Ok(RestrictedExpr::set(
                vals.into_iter()
                    .map(|v| v.into_expr(ctx.clone()))
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            Self::Record(map) => Ok(RestrictedExpr::record(
                map.into_iter()
                    .map(|(k, v)| Ok((k, v.into_expr(ctx.clone())?)))
                    .collect::<Result<Vec<_>, JsonDeserializationError>>()?,
            )
            .map_err(|e| match e {
                ExpressionConstructionError::DuplicateKey(
                    expression_construction_errors::DuplicateKeyError { key, .. },
                ) => JsonDeserializationError::duplicate_key(ctx(), key),
            })?),
            Self::EntityEscape { __entity: entity } => Ok(RestrictedExpr::val(
                EntityUID::try_from(entity.clone()).map_err(|errs| {
                    let err_msg = serde_json::to_string_pretty(&entity)
                        .unwrap_or_else(|_| format!("{:?}", &entity));
                    JsonDeserializationError::parse_escape(EscapeKind::Entity, err_msg, errs)
                })?,
            )),
            Self::ExtnEscape { __extn: extn } => extn.into_expr(ctx),
            Self::ExprEscape { .. } => Err(JsonDeserializationError::ExprTag(Box::new(ctx()))),
            Self::Null => Err(JsonDeserializationError::Null(Box::new(ctx()))),
        }
    }

    /// Convert a Cedar "restricted expression" into a `CedarValueJson`.
    pub fn from_expr(expr: BorrowedRestrictedExpr<'_>) -> Result<Self, JsonSerializationError> {
        match expr.as_ref().expr_kind() {
            ExprKind::Lit(lit) => Ok(Self::from_lit(lit.clone())),
            ExprKind::ExtensionFunctionApp { fn_name, args } => match args.as_slice() {
                [] => Err(JsonSerializationError::call_0_args(fn_name.clone())),
                [arg] => Ok(Self::ExtnEscape {
                    __extn: FnAndArgs::Single {
                        ext_fn: fn_name.to_smolstr(),
                        arg: Box::new(CedarValueJson::from_expr(
                            // assuming the invariant holds for `expr`, it must also hold here
                            BorrowedRestrictedExpr::new_unchecked(arg),
                        )?),
                    },
                }),
                args => Ok(Self::ExtnEscape {
                    __extn: FnAndArgs::Multi {
                        ext_fn: fn_name.to_smolstr(),
                        args: args
                            .iter()
                            .map(|arg| {
                                CedarValueJson::from_expr(BorrowedRestrictedExpr::new_unchecked(
                                    arg,
                                ))
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                    },
                }),
            },
            ExprKind::Set(exprs) => Ok(Self::Set(
                exprs
                    .iter()
                    .map(BorrowedRestrictedExpr::new_unchecked) // assuming the invariant holds for `expr`, it must also hold here
                    .map(CedarValueJson::from_expr)
                    .collect::<Result<_, JsonSerializationError>>()?,
            )),
            ExprKind::Record(map) => {
                // if `map` contains a key which collides with one of our JSON
                // escapes, then we have a problem because it would be interpreted
                // as an escape when being read back in.
                check_for_reserved_keys(map.keys())?;
                Ok(Self::Record(
                    map.iter()
                        .map(|(k, v)| {
                            Ok((
                                k.clone(),
                                CedarValueJson::from_expr(
                                    // assuming the invariant holds for `expr`, it must also hold here
                                    BorrowedRestrictedExpr::new_unchecked(v),
                                )?,
                            ))
                        })
                        .collect::<Result<_, JsonSerializationError>>()?,
                ))
            }
            kind => Err(JsonSerializationError::unexpected_restricted_expr_kind(
                kind.clone(),
            )),
        }
    }

    /// Convert a Cedar value into a `CedarValueJson`.
    ///
    /// Only throws errors in two cases:
    /// 1. `value` is (or contains) a record with a reserved key such as
    ///    "__entity"
    /// 2. `value` is (or contains) an extension value, and the argument to the
    ///    extension constructor that produced that extension value can't
    ///    itself be converted to `CedarJsonValue`. (Either because that
    ///    argument falls into one of these two cases itself, or because the
    ///    argument is a nontrivial residual.)
    pub fn from_value(value: Value) -> Result<Self, JsonSerializationError> {
        Self::from_valuekind(value.value)
    }

    /// Convert a Cedar `ValueKind` into a `CedarValueJson`.
    ///
    /// For discussion of when this throws errors, see notes on `from_value`.
    pub fn from_valuekind(value: ValueKind) -> Result<Self, JsonSerializationError> {
        match value {
            ValueKind::Lit(lit) => Ok(Self::from_lit(lit)),
            ValueKind::Set(set) => Ok(Self::Set(
                set.iter()
                    .cloned()
                    .map(Self::from_value)
                    .collect::<Result<_, _>>()?,
            )),
            ValueKind::Record(record) => {
                // if `map` contains a key which collides with one of our JSON
                // escapes, then we have a problem because it would be interpreted
                // as an escape when being read back in.
                check_for_reserved_keys(record.keys())?;
                Ok(Self::Record(
                    record
                        .iter()
                        .map(|(k, v)| Ok((k.clone(), Self::from_value(v.clone())?)))
                        .collect::<Result<JsonRecord, JsonSerializationError>>()?,
                ))
            }
            ValueKind::ExtensionValue(ev) => {
                let ext_func = &ev.func;
                match ev.args.as_slice() {
                    [] => Err(JsonSerializationError::call_0_args(ext_func.clone())),
                    [ref expr] => Ok(Self::ExtnEscape {
                        __extn: FnAndArgs::Single {
                            ext_fn: ext_func.to_smolstr(),
                            arg: Box::new(Self::from_expr(expr.as_borrowed())?),
                        },
                    }),
                    exprs => Ok(Self::ExtnEscape {
                        __extn: FnAndArgs::Multi {
                            ext_fn: ext_func.to_smolstr(),
                            args: exprs
                                .iter()
                                .map(|expr| Self::from_expr(expr.as_borrowed()))
                                .collect::<Result<Vec<_>, _>>()?,
                        },
                    }),
                }
            }
        }
    }

    /// Convert a Cedar literal into a `CedarValueJson`.
    pub fn from_lit(lit: Literal) -> Self {
        match lit {
            Literal::Bool(b) => Self::Bool(b),
            Literal::Long(i) => Self::Long(i),
            Literal::String(s) => Self::String(s),
            Literal::EntityUID(euid) => Self::EntityEscape {
                __entity: Arc::unwrap_or_clone(euid).into(),
            },
        }
    }

    /// Substitute entity literals
    pub fn sub_entity_literals(
        self,
        mapping: &BTreeMap<EntityUID, EntityUID>,
    ) -> Result<Self, JsonDeserializationError> {
        match self {
            // Since we are modifying an already legal policy, this should be unreachable.
            CedarValueJson::ExprEscape { __expr } => Err(JsonDeserializationError::ExprTag(
                Box::new(JsonDeserializationErrorContext::Unknown),
            )),
            CedarValueJson::EntityEscape { __entity } => {
                let euid = EntityUID::try_from(__entity.clone());
                match euid {
                    Ok(euid) => match mapping.get(&euid) {
                        Some(new_euid) => Ok(CedarValueJson::EntityEscape {
                            __entity: new_euid.into(),
                        }),
                        None => Ok(CedarValueJson::EntityEscape { __entity }),
                    },
                    Err(_) => Ok(CedarValueJson::EntityEscape { __entity }),
                }
            }
            CedarValueJson::ExtnEscape {
                __extn: FnAndArgs::Single { ext_fn, arg },
            } => Ok(CedarValueJson::ExtnEscape {
                __extn: FnAndArgs::Single {
                    ext_fn,
                    arg: Box::new((*arg).sub_entity_literals(mapping)?),
                },
            }),
            CedarValueJson::ExtnEscape {
                __extn: FnAndArgs::Multi { ext_fn, args },
            } => Ok(CedarValueJson::ExtnEscape {
                __extn: FnAndArgs::Multi {
                    ext_fn,
                    args: args
                        .into_iter()
                        .map(|arg| arg.sub_entity_literals(mapping))
                        .collect::<Result<Vec<_>, _>>()?,
                },
            }),
            v @ CedarValueJson::Bool(_) => Ok(v),
            v @ CedarValueJson::Long(_) => Ok(v),
            v @ CedarValueJson::String(_) => Ok(v),
            CedarValueJson::Set(v) => Ok(CedarValueJson::Set(
                v.into_iter()
                    .map(|e| e.sub_entity_literals(mapping))
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            CedarValueJson::Record(r) => {
                let mut new_m = BTreeMap::new();
                for (k, v) in r.values {
                    new_m.insert(k, v.sub_entity_literals(mapping)?);
                }
                Ok(CedarValueJson::Record(JsonRecord { values: new_m }))
            }
            v @ CedarValueJson::Null => Ok(v),
        }
    }
}

/// helper function to check if the given keys contain any reserved keys,
/// throwing an appropriate `JsonSerializationError` if so
fn check_for_reserved_keys<'a>(
    mut keys: impl Iterator<Item = &'a SmolStr>,
) -> Result<(), JsonSerializationError> {
    // We could be a little more permissive here, but to be
    // conservative, we throw an error for any record that contains
    // any key with a reserved name, not just single-key records
    // with the reserved names.
    let reserved_keys: HashSet<&str> = HashSet::from_iter(["__entity", "__extn", "__expr"]);
    let collision = keys.find(|k| reserved_keys.contains(k.as_str()));
    match collision {
        Some(collision) => Err(JsonSerializationError::reserved_key(collision.clone())),
        None => Ok(()),
    }
}

impl FnAndArgs {
    /// Convert this `FnAndArg` into a Cedar "restricted expression" (which will be a call to an extension constructor)
    pub fn into_expr(
        self,
        ctx: impl Fn() -> JsonDeserializationErrorContext + Clone,
    ) -> Result<RestrictedExpr, JsonDeserializationError> {
        let ext_fn = self.fn_str();
        let args = self.args();
        Ok(RestrictedExpr::call_extension_fn(
            Name::from_normalized_str(ext_fn).map_err(|errs| {
                JsonDeserializationError::parse_escape(EscapeKind::Extension, ext_fn, errs)
            })?,
            args.iter()
                .map(|arg| CedarValueJson::into_expr(arg.clone(), ctx.clone()))
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }
}

/// Struct used to parse Cedar values from JSON.
#[derive(Debug, Clone)]
pub struct ValueParser<'e> {
    /// Extensions which are active for the JSON parsing.
    extensions: &'e Extensions<'e>,
}

impl<'e> ValueParser<'e> {
    /// Create a new `ValueParser`.
    pub fn new(extensions: &'e Extensions<'e>) -> Self {
        Self { extensions }
    }

    /// internal function that converts a Cedar value (in JSON) into a
    /// `RestrictedExpr`. Performs schema-based parsing if `expected_ty` is
    /// provided. This does not mean that this function fully validates the
    /// value against `expected_ty` -- it does not.
    pub fn val_into_restricted_expr(
        &self,
        val: serde_json::Value,
        expected_ty: Option<&SchemaType>,
        ctx: impl Fn() -> JsonDeserializationErrorContext + Clone,
    ) -> Result<RestrictedExpr, JsonDeserializationError> {
        // First we have to check if we've been given an Unknown. This is valid
        // regardless of the expected type (see #418).
        let parse_as_unknown = |val: serde_json::Value| {
            let extjson: ExtnValueJson = serde_json::from_value(val).ok()?;
            match extjson {
                ExtnValueJson::ExplicitExtnEscape {
                    __extn: FnAndArgs::Single { ext_fn, arg },
                } if ext_fn == "unknown" => {
                    let arg = arg.into_expr(ctx.clone()).ok()?;
                    let name = arg.as_string()?;
                    Some(RestrictedExpr::unknown(Unknown::new_untyped(name.clone())))
                }
                _ => None, // only explicit `__extn` escape is valid for this purpose. For instance, if we allowed `ImplicitConstructor` here, then all strings would parse as calls to `unknown()`, which is clearly not what we want.
            }
        };
        if let Some(rexpr) = parse_as_unknown(val.clone()) {
            return Ok(rexpr);
        }
        // otherwise, we do normal schema-based parsing based on the expected type.
        match expected_ty {
            // The expected type is an entity reference. Special parsing rules
            // apply: for instance, the `__entity` escape can optionally be omitted.
            // What this means is that we parse the contents as `EntityUidJson`, and
            // then convert that into an entity reference `RestrictedExpr`
            Some(SchemaType::Entity { .. }) => {
                let uidjson: EntityUidJson = serde_json::from_value(val)?;
                Ok(RestrictedExpr::val(uidjson.into_euid(ctx)?))
            }
            // The expected type is an extension type. Special parsing rules apply:
            // for instance, the `__extn` escape can optionally be omitted. What
            // this means is that we parse the contents as `ExtnValueJson`, and then
            // convert that into an extension-function-call `RestrictedExpr`
            Some(SchemaType::Extension { ref name, .. }) => {
                let extjson: ExtnValueJson = serde_json::from_value(val)?;
                match extjson {
                    ExtnValueJson::ExplicitExprEscape { .. } => {
                        Err(JsonDeserializationError::ExprTag(Box::new(ctx())))
                    }
                    ExtnValueJson::ExplicitExtnEscape { __extn }
                    | ExtnValueJson::ImplicitExtnEscape(__extn) => {
                        let func = self.extensions.func(
                            &Name::from_normalized_str(__extn.fn_str()).map_err(|errs| {
                                JsonDeserializationError::parse_escape(
                                    EscapeKind::Extension,
                                    __extn.fn_str(),
                                    errs,
                                )
                            })?,
                        )?;
                        let arg_types = func.arg_types();
                        let args = __extn.args();
                        if args.len() != arg_types.len() {
                            return Err(JsonDeserializationError::incorrect_num_of_arguments(
                                arg_types.len(),
                                args.len(),
                                __extn.fn_str(),
                            ));
                        }
                        Ok(RestrictedExpr::call_extension_fn(
                            func.name().clone(),
                            arg_types
                                .iter()
                                .zip(args.iter())
                                .map(|(arg_type, arg)| {
                                    // We need to recur here because there
                                    // could be arguments of non-primitive
                                    // types like `datetime`, which could be
                                    // expressed using `ImplicitExtnEscape` or
                                    // `ImplicitConstructor`
                                    self.val_into_restricted_expr(
                                        // So, we have to serialize
                                        // `CedarValueJson` here
                                        serde_json::to_value(arg)?,
                                        Some(arg_type),
                                        ctx.clone(),
                                    )
                                })
                                .collect::<Result<Vec<_>, _>>()?,
                        ))
                    }
                    ExtnValueJson::ImplicitConstructor(val) => {
                        let expected_return_type = SchemaType::Extension { name: name.clone() };
                        // Unfortunately, we can only allow one argument
                        // constructor here because it's impossible to
                        // distinguish two cases where there are
                        // multiple arguments and where there is one
                        // argument of a set type
                        if let Some(constructor) = self
                            .extensions
                            .lookup_single_arg_constructor(&expected_return_type)
                        {
                            // PANIC SAFETY: we've concluded above that it has one arugment
                            #[allow(clippy::indexing_slicing)]
                            Ok(RestrictedExpr::call_extension_fn(
                                constructor.name().clone(),
                                std::iter::once(self.val_into_restricted_expr(
                                    serde_json::to_value(val)?,
                                    Some(&constructor.arg_types()[0]),
                                    ctx,
                                )?),
                            ))
                        } else {
                            Err(JsonDeserializationError::missing_implied_constructor(
                                ctx(),
                                expected_return_type,
                            ))
                        }
                    }
                }
            }
            // The expected type is a set type. No special parsing rules apply, but
            // we need to parse the elements according to the expected element type
            Some(expected_ty @ SchemaType::Set { element_ty }) => match val {
                serde_json::Value::Array(elements) => Ok(RestrictedExpr::set(
                    elements
                        .into_iter()
                        .map(|element| {
                            self.val_into_restricted_expr(element, Some(element_ty), ctx.clone())
                        })
                        .collect::<Result<Vec<RestrictedExpr>, JsonDeserializationError>>()?,
                )),
                val => {
                    let actual_val = {
                        let jvalue: CedarValueJson = serde_json::from_value(val)?;
                        jvalue.into_expr(ctx.clone())?
                    };
                    let err = TypeMismatchError::type_mismatch(
                        expected_ty.clone(),
                        actual_val.try_type_of(self.extensions),
                        actual_val,
                    );
                    match ctx() {
                        JsonDeserializationErrorContext::EntityAttribute { uid, attr } => {
                            Err(JsonDeserializationError::EntitySchemaConformance(
                                EntitySchemaConformanceError::type_mismatch(
                                    uid,
                                    attr,
                                    crate::entities::conformance::err::AttrOrTag::Attr,
                                    err,
                                ),
                            ))
                        }
                        ctx => Err(JsonDeserializationError::type_mismatch(ctx, err)),
                    }
                }
            },
            // The expected type is a record type. No special parsing rules
            // apply, but we need to parse the attribute values according to
            // their expected element types
            Some(
                expected_ty @ SchemaType::Record {
                    attrs: expected_attrs,
                    open_attrs,
                },
            ) => match val {
                serde_json::Value::Object(mut actual_attrs) => {
                    let ctx2 = ctx.clone(); // for borrow-check, so the original `ctx` can be moved into the closure below
                    let mut_actual_attrs = &mut actual_attrs; // for borrow-check, so only a mut ref gets moved into the closure, and we retain ownership of `actual_attrs`
                    let rexpr_pairs = expected_attrs
                        .iter()
                        .filter_map(move |(k, expected_attr_ty)| {
                            match mut_actual_attrs.remove(k.as_str()) {
                                Some(actual_attr) => {
                                    match self.val_into_restricted_expr(actual_attr, Some(expected_attr_ty.schema_type()), ctx.clone()) {
                                        Ok(actual_attr) => Some(Ok((k.clone(), actual_attr))),
                                        Err(e) => Some(Err(e)),
                                    }
                                }
                                None if expected_attr_ty.is_required() => Some(Err(JsonDeserializationError::missing_required_record_attr(ctx(), k.clone()))),
                                None => None,
                            }
                        })
                        .collect::<Result<Vec<(SmolStr, RestrictedExpr)>, JsonDeserializationError>>()?;

                    if !open_attrs {
                        // we've now checked that all expected attrs exist, and removed them from `actual_attrs`.
                        // we still need to verify that we didn't have any unexpected attrs.
                        if let Some((record_attr, _)) = actual_attrs.into_iter().next() {
                            return Err(JsonDeserializationError::unexpected_record_attr(
                                ctx2(),
                                record_attr,
                            ));
                        }
                    }

                    // having duplicate keys should be impossible here (because
                    // neither `actual_attrs` nor `expected_attrs` can have
                    // duplicate keys; they're both maps), but we can still throw
                    // the error properly in the case that it somehow happens
                    RestrictedExpr::record(rexpr_pairs).map_err(|e| match e {
                        ExpressionConstructionError::DuplicateKey(
                            expression_construction_errors::DuplicateKeyError { key, .. },
                        ) => JsonDeserializationError::duplicate_key(ctx2(), key),
                    })
                }
                val => {
                    let actual_val = {
                        let jvalue: CedarValueJson = serde_json::from_value(val)?;
                        jvalue.into_expr(ctx.clone())?
                    };
                    let err = TypeMismatchError::type_mismatch(
                        expected_ty.clone(),
                        actual_val.try_type_of(self.extensions),
                        actual_val,
                    );
                    match ctx() {
                        JsonDeserializationErrorContext::EntityAttribute { uid, attr } => {
                            Err(JsonDeserializationError::EntitySchemaConformance(
                                EntitySchemaConformanceError::type_mismatch(
                                    uid,
                                    attr,
                                    crate::entities::conformance::err::AttrOrTag::Attr,
                                    err,
                                ),
                            ))
                        }
                        ctx => Err(JsonDeserializationError::type_mismatch(ctx, err)),
                    }
                }
            },
            // The expected type is any other type, or we don't have an expected type.
            // No special parsing rules apply; we do ordinary, non-schema-based parsing.
            Some(_) | None => {
                // Everything is parsed as `CedarValueJson`, and converted into
                // `RestrictedExpr` from that.
                let jvalue: CedarValueJson = serde_json::from_value(val)?;
                Ok(jvalue.into_expr(ctx)?)
            }
        }
    }
}

/// A (optional) static context for deserialization of entity uids
/// This is useful when, for plumbing reasons, we can't get the appopriate values into the dynamic
/// context. Primary use case is in the [`DeserializeAs`] trait.
pub trait DeserializationContext {
    /// Access the (optional) static context.
    /// If returns [`None`], use the dynamic context.
    fn static_context() -> Option<JsonDeserializationErrorContext>;
}

/// A [`DeserializationContext`] that always returns [`None`].
/// This is the default behaviour,
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct NoStaticContext;

impl DeserializationContext for NoStaticContext {
    fn static_context() -> Option<JsonDeserializationErrorContext> {
        None
    }
}

/// Serde JSON format for Cedar values where we know we're expecting an entity
/// reference
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum EntityUidJson<Context = NoStaticContext> {
    /// This was removed in 3.0 and is only here for generating nice error messages.
    ExplicitExprEscape {
        /// Contents are ignored.
        #[cfg_attr(feature = "wasm", tsify(type = "__skip"))]
        __expr: String,
        /// Phantom value for the `Context` type parameter
        #[serde(skip)]
        context: std::marker::PhantomData<Context>,
    },
    /// Explicit `__entity` escape; see notes on `CedarValueJson::EntityEscape`
    ExplicitEntityEscape {
        /// JSON object containing the entity type and ID
        __entity: TypeAndId,
    },
    /// Implicit `__entity` escape, in which case we'll see just the TypeAndId
    /// structure
    ImplicitEntityEscape(TypeAndId),

    /// Implicit catch-all case for error handling
    FoundValue(#[cfg_attr(feature = "wasm", tsify(type = "__skip"))] serde_json::Value),
}

impl<'de, C: DeserializationContext> DeserializeAs<'de, EntityUID> for EntityUidJson<C> {
    fn deserialize_as<D>(deserializer: D) -> Result<EntityUID, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        // We don't know the context that called us, so we'll rely on the statically set context
        let context = || JsonDeserializationErrorContext::Unknown;
        let s = EntityUidJson::<C>::deserialize(deserializer)?;
        let euid = s.into_euid(context).map_err(Error::custom)?;
        Ok(euid)
    }
}

impl<C> SerializeAs<EntityUID> for EntityUidJson<C> {
    fn serialize_as<S>(source: &EntityUID, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let json: EntityUidJson = source.clone().into();
        json.serialize(serializer)
    }
}

impl<C: DeserializationContext> EntityUidJson<C> {
    /// Construct an `EntityUidJson` from entity type name and eid.
    ///
    /// This will use the `ImplicitEntityEscape` form, if it matters.
    pub fn new(entity_type: impl Into<SmolStr>, id: impl Into<SmolStr>) -> Self {
        Self::ImplicitEntityEscape(TypeAndId {
            entity_type: entity_type.into(),
            id: id.into(),
        })
    }

    /// Convert this `EntityUidJson` into an `EntityUID`
    pub fn into_euid(
        self,
        dynamic_ctx: impl Fn() -> JsonDeserializationErrorContext + Clone,
    ) -> Result<EntityUID, JsonDeserializationError> {
        let ctx = || C::static_context().unwrap_or_else(&dynamic_ctx);
        match self {
            Self::ExplicitEntityEscape { __entity } | Self::ImplicitEntityEscape(__entity) => {
                // reuse the same logic that parses CedarValueJson
                let jvalue = CedarValueJson::EntityEscape { __entity };
                let expr = jvalue.into_expr(ctx)?;
                match expr.expr_kind() {
                    ExprKind::Lit(Literal::EntityUID(euid)) => Ok((**euid).clone()),
                    _ => Err(JsonDeserializationError::expected_entity_ref(
                        ctx(),
                        Either::Right(expr.clone().into()),
                    )),
                }
            }
            Self::FoundValue(v) => Err(JsonDeserializationError::expected_entity_ref(
                ctx(),
                Either::Left(v),
            )),
            Self::ExplicitExprEscape { __expr, .. } => {
                Err(JsonDeserializationError::ExprTag(Box::new(ctx())))
            }
        }
    }
}

/// Convert an `EntityUID` to `EntityUidJson`, using the `ExplicitEntityEscape` option
impl From<EntityUID> for EntityUidJson {
    fn from(uid: EntityUID) -> EntityUidJson {
        EntityUidJson::ExplicitEntityEscape {
            __entity: uid.into(),
        }
    }
}

/// Convert an `EntityUID` to `EntityUidJson`, using the `ExplicitEntityEscape` option
impl From<&EntityUID> for EntityUidJson {
    fn from(uid: &EntityUID) -> EntityUidJson {
        EntityUidJson::ExplicitEntityEscape {
            __entity: uid.into(),
        }
    }
}

/// Serde JSON format for Cedar values where we know we're expecting an
/// extension value
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ExtnValueJson {
    /// This was removed in 3.0 and is only here for generating nice error messages.
    ExplicitExprEscape {
        /// Contents are ignored.
        __expr: String,
    },
    /// Explicit `__extn` escape; see notes on `CedarValueJson::ExtnEscape`
    ExplicitExtnEscape {
        /// JSON object containing the extension-constructor call
        __extn: FnAndArgs,
    },
    /// Implicit `__extn` escape, in which case we'll just see the `FnAndArg`
    /// directly
    ImplicitExtnEscape(FnAndArgs),
    /// Implicit `__extn` escape and constructor. Constructor is implicitly
    /// selected based on the argument type and the expected type.
    //
    // This is listed last so that it has lowest priority when deserializing.
    // If one of the above forms fits, we use that.
    ImplicitConstructor(CedarValueJson),
}
