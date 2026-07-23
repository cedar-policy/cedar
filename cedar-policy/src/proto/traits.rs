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

use cedar_policy_core::{
    ast::{ExprValidationError, Infallible, PolicySetValidationError, TemplateValidationError},
    entities::err::EntitiesError,
    validator::SchemaError,
};

use crate::api;

use super::ast::ProtobufConversionError;

/// Error type for protobuf decoding failures
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// The input buffer does not contain a valid protobuf message
    #[error(transparent)]
    Proto(prost::DecodeError),
    /// The protobuf message was well-formed but its contents could not be
    /// converted into the target Cedar type
    #[error(transparent)]
    Conversion(ProtobufConversionError),
}

impl From<prost::DecodeError> for DecodeError {
    fn from(e: prost::DecodeError) -> Self {
        Self::Proto(e)
    }
}

impl From<ProtobufConversionError> for DecodeError {
    fn from(e: ProtobufConversionError) -> Self {
        Self::Conversion(e)
    }
}

/// Error type for protobuf encoding failures
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
    /// The input data contains too many recursion levels to be encoded
    #[error("data structure depth exceeds maximum encodable depth of {MAX_ENCODE_DEPTH}")]
    MaxDepthExceeded,
    /// The protobuf message could not be encoded (e.g., buffer too small)
    #[error(transparent)]
    Proto(#[from] prost::EncodeError),
}

/// Maximum allowed protobuf recursion depth for encoding.
///
/// Prost's decoder has a hardcoded recursion limit of 100, where each nested
/// message entry counts as one level. We use this limit when calculating the
/// depth of a `prost::Message` (i.e. the `models::...`), not the depth of
/// syntax tree (e.g. type or expression).
/// Typically, the depth of a model is twice the one of the internal representation's
/// tree.
///
/// We set this to 90 to leave a small margin (10 levels) for outer wrappers
/// like `TemplateBody` or `Entity` that contain an `Expr` field.
pub const MAX_ENCODE_DEPTH: usize = 90;

/// A trait for protobuf model types that require validation before encoding.
///
/// Model types implement this to perform structural checks (such as depth limits)
/// before the protobuf encoding step. Types that need no pre-encode validation
/// implement this as a no-op returning `Ok(())`.
pub trait EncodeCheck {
    /// Check that this model is safe to encode.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if the model violates encoding constraints
    /// (e.g., exceeds the maximum nesting depth).
    fn check_for_encode(&self) -> Result<(), EncodeError> {
        self.check_for_encode_from_depth(1)
    }

    /// Check that this model is safe to encode, assuming an `init` recursion
    /// level.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if the model violates encoding constraints
    /// (e.g., exceeds the maximum nesting depth).
    fn check_for_encode_from_depth(&self, init: usize) -> Result<(), EncodeError>;
}

/// A trait for objects that have a `try_validate` method returning `self` if the object is
/// valid.
pub trait TryValidate: Sized {
    /// The type of errors returned by the validation method.
    type Err: Display;
    /// A validation method that returns the object itself, or an error if it is invalid.
    ///
    /// # Errors
    ///
    /// Will return errors when the implementing structure is invalid, according to its own
    ///  invariants.
    fn try_validate(self) -> Result<Self, Self::Err>;
}

mod private {
    use crate::api;
    pub trait Sealed {}
    impl Sealed for api::PolicySet {}
    impl Sealed for api::Entities {}
    impl Sealed for api::Entity {}
    impl Sealed for api::Schema {}
    impl Sealed for api::EntityTypeName {}
    impl Sealed for api::EntityNamespace {}
    impl Sealed for api::Template {}
    impl Sealed for api::Expression {}
    impl Sealed for api::Request {}
}

/// Trait allowing serializing and deserializing in protobuf format.
pub trait Protobuf: Sized + TryValidate + private::Sealed {
    /// Encode into protobuf format. Returns a freshly-allocated buffer containing binary data.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::MaxDepthExceeded`] if the data structure has too many
    /// recursion levels to be safely encoded and decoded by prost.
    fn encode(&self) -> Result<Vec<u8>, EncodeError>;

    /// Decode the binary data in `buf`, producing something of type `Self`
    ///
    /// # Errors
    ///
    /// Will return [`DecodeError::Proto`] when the input buffer does not
    /// contain a valid protobuf message. Returns [`DecodeError::Conversion`] when
    /// the message is well-formed but cannot be converted into the target type or the
    /// validation on the target type failed.
    fn decode(buf: impl prost::bytes::Buf) -> Result<Self, DecodeError> {
        Self::decode_unchecked(buf)?
            .try_validate()
            .map_err(|e| ProtobufConversionError::InvalidValue(format!("invalid: {e}")).into())
    }

    /// Decode the binary data in `buf`, producing something of type `Self`,
    /// but without the additional validation that the [`Self::decode`] method performs on the
    /// resulting `Self`.
    /// This is useful for performance if you can guarantee the binary data is the result of
    /// [`Self::encode`] of the same implementation.
    ///
    /// # Errors
    ///
    /// Will return [`DecodeError::Proto`] when the input buffer does not
    /// contain a valid protobuf message, or [`DecodeError::Conversion`] when
    /// the message is well-formed but cannot be converted into the target type.
    fn decode_unchecked(buf: impl prost::bytes::Buf) -> Result<Self, DecodeError>;
}

/// Encode `thing` into a caller provided buffer using the protobuf format `M`
///
/// # Errors
///
/// Returns [`EncodeError`] if the model fails pre-encode checks
/// (e.g., expression depth exceeds [`MAX_ENCODE_DEPTH`]) or the
/// user-provided buffer does not have enough capacity.
#[expect(
    dead_code,
    reason = "experimental feature, we might have use for this one in the future"
)]
pub(crate) fn encode_with_buf<M: prost::Message + EncodeCheck + for<'a> From<&'a T>, T>(
    thing: &T,
    buf: &mut impl prost::bytes::BufMut,
) -> Result<(), EncodeError> {
    let model = M::from(thing);
    model.check_for_encode()?;
    model.encode(buf)?;
    Ok(())
}

/// Encode `thing` into a freshly-allocated buffer using the protobuf format `M`
///
/// # Errors
///
/// Returns [`EncodeError`] if the model fails pre-encoding validation
/// (e.g., expression depth exceeds [`MAX_ENCODE_DEPTH`]).
pub(crate) fn encode_to_vec<M: prost::Message + EncodeCheck + for<'a> From<&'a T>, T>(
    thing: &T,
) -> Result<Vec<u8>, EncodeError> {
    let model = M::from(thing);
    model.check_for_encode()?;
    Ok(model.encode_to_vec())
}

use std::{default::Default, fmt::Display};

/// Decode something of type `T` from `buf` using the protobuf format `M`
#[expect(
    dead_code,
    reason = "available for types with infallible From conversions"
)]
pub(crate) fn decode<M: prost::Message + Default, T: From<M>>(
    buf: impl prost::bytes::Buf,
) -> Result<T, DecodeError> {
    Ok(M::decode(buf)?.into())
}

/// Decode something of type `T` from `buf` using the protobuf format `M`,
/// where the conversion from `M` to `T` is fallible
pub(crate) fn try_decode<
    M: prost::Message + Default,
    E: Into<ProtobufConversionError>,
    T: TryFrom<M, Error = E>,
>(
    buf: impl prost::bytes::Buf,
) -> Result<T, DecodeError> {
    M::decode(buf)?
        .try_into()
        .map_err(|e: E| DecodeError::Conversion(e.into()))
}

// ====================================================================
// TryValidate implementations for api types
// ====================================================================

impl TryValidate for api::PolicySet {
    type Err = PolicySetValidationError;
    fn try_validate(self) -> Result<Self, Self::Err> {
        self.ast.try_validate().map(Into::into)
    }
}

impl TryValidate for api::Entities {
    type Err = EntitiesError;
    fn try_validate(self) -> Result<Self, EntitiesError> {
        Ok(Self(self.0.try_validate()?))
    }
}

impl TryValidate for api::Entity {
    type Err = EntitiesError;
    fn try_validate(self) -> Result<Self, EntitiesError> {
        Ok(Self(self.0.try_validate()?))
    }
}

impl TryValidate for api::Schema {
    type Err = SchemaError;
    fn try_validate(self) -> Result<Self, SchemaError> {
        Ok(Self(self.0.try_validate()?))
    }
}

impl TryValidate for api::Template {
    type Err = TemplateValidationError;
    fn try_validate(self) -> Result<Self, TemplateValidationError> {
        Ok(Self {
            ast: self.ast.try_validate()?,
            ..self
        })
    }
}

impl TryValidate for api::Expression {
    type Err = ExprValidationError;
    fn try_validate(self) -> Result<Self, ExprValidationError> {
        Ok(Self(self.0.try_validate()?))
    }
}

impl TryValidate for api::Request {
    type Err = Infallible;
    fn try_validate(self) -> Result<Self, Infallible> {
        // We don't actually do any additional validation on requests, the structural validation enforced
        // by types and the existing conversion is sufficient.
        Ok(self)
    }
}

impl TryValidate for api::EntityTypeName {
    type Err = Infallible;
    fn try_validate(self) -> Result<Self, Infallible> {
        // EntityTypeName also doesn't need additional validation
        Ok(self)
    }
}

impl TryValidate for api::EntityNamespace {
    type Err = Infallible;
    fn try_validate(self) -> Result<Self, Infallible> {
        // EntityNamespace also doesn't need additional validation
        Ok(self)
    }
}

// ====================================================================
// EncodeCheck implementations for protobuf model types.
// Encoding checks are implemented on the protobuf model type rather than
// the AST/Validator level type to get a more predictable outcome: it is easier to
// know how much recursion is needed to decode the protobuf representation
// at this level than at the expression/type level.
// ====================================================================

use super::models;

impl EncodeCheck for models::Expr {
    #[expect(
        clippy::too_many_lines,
        reason = "many variants in expr and more readable that way"
    )]
    fn check_for_encode_from_depth(&self, init: usize) -> Result<(), EncodeError> {
        // Iterative depth-first traversal measuring protobuf recursion depth.
        let mut stack: Vec<(&Self, usize)> = vec![(self, init)];

        while let Some((expr, depth)) = stack.pop() {
            if depth > MAX_ENCODE_DEPTH {
                return Err(EncodeError::MaxDepthExceeded);
            }

            if let Some(ref kind) = expr.expr_kind {
                use models::expr::ExprKind;
                // Prost counts each message entry as one recursion level. For our Expr
                // schema, entering an Expr costs 1 level, and entering the variant
                // wrapper message (BinaryApp, UnaryApp, If, etc.) costs another 1 level.
                let child_depth = depth + 2;
                match kind {
                    ExprKind::Lit(lit) => {
                        // A literal EUid adds 3: (Literal (EntityUuid (Name ...))
                        if let Some(models::expr::literal::Lit::Euid(_)) = lit.lit {
                            let euid_name_depth = depth + 3;
                            if euid_name_depth > MAX_ENCODE_DEPTH {
                                return Err(EncodeError::MaxDepthExceeded);
                            }
                        }
                    }
                    ExprKind::Var(_) | ExprKind::Slot(_) => {}
                    ExprKind::If(if_expr) => {
                        if let Some(ref e) = if_expr.test_expr {
                            stack.push((e, child_depth));
                        }
                        if let Some(ref e) = if_expr.then_expr {
                            stack.push((e, child_depth));
                        }
                        if let Some(ref e) = if_expr.else_expr {
                            stack.push((e, child_depth));
                        }
                    }
                    ExprKind::And(bin) => {
                        if let Some(ref e) = bin.left {
                            stack.push((e, child_depth));
                        }
                        if let Some(ref e) = bin.right {
                            stack.push((e, child_depth));
                        }
                    }
                    ExprKind::Or(bin) => {
                        if let Some(ref e) = bin.left {
                            stack.push((e, child_depth));
                        }
                        if let Some(ref e) = bin.right {
                            stack.push((e, child_depth));
                        }
                    }
                    ExprKind::UApp(unary) => {
                        if let Some(ref e) = unary.expr {
                            stack.push((e, child_depth));
                        }
                    }
                    ExprKind::BApp(binary) => {
                        if let Some(ref e) = binary.left {
                            stack.push((e, child_depth));
                        }
                        if let Some(ref e) = binary.right {
                            stack.push((e, child_depth));
                        }
                    }
                    ExprKind::ExtApp(ext) => {
                        for arg in &ext.args {
                            stack.push((arg, child_depth));
                        }
                        // a `fn_name` adds 2 : (ExtApp(Name(..)).
                        if ext.fn_name.is_some() {
                            let name_depth = depth + 2;
                            if name_depth > MAX_ENCODE_DEPTH {
                                return Err(EncodeError::MaxDepthExceeded);
                            }
                        }
                    }
                    ExprKind::GetAttr(get) => {
                        if let Some(ref e) = get.expr {
                            stack.push((e, child_depth));
                        }
                    }
                    ExprKind::HasAttr(has) => {
                        if let Some(ref e) = has.expr {
                            stack.push((e, child_depth));
                        }
                    }
                    ExprKind::Like(like) => {
                        if let Some(ref e) = like.expr {
                            stack.push((e, child_depth));
                        }
                        // PatternElem adds 2 (Like(Vec<PatternElem>(..))
                        if !like.pattern.is_empty() {
                            let pattern_depth = depth + 2;
                            if pattern_depth > MAX_ENCODE_DEPTH {
                                return Err(EncodeError::MaxDepthExceeded);
                            }
                        }
                    }
                    ExprKind::Is(is) => {
                        if let Some(ref e) = is.expr {
                            stack.push((e, child_depth));
                        }
                        // `entity_type` adds 2 (Is (Name (..)))
                        if is.entity_type.is_some() {
                            let name_depth = depth + 2;
                            if name_depth > MAX_ENCODE_DEPTH {
                                return Err(EncodeError::MaxDepthExceeded);
                            }
                        }
                    }
                    ExprKind::Set(set) => {
                        for elem in &set.elements {
                            stack.push((elem, child_depth));
                        }
                    }
                    ExprKind::Record(record) => {
                        // map<string, Expr> adds an extra map-entry wrapper message:
                        // Record (+1) → map entry (+1) → Expr (+1) = +3 from parent Expr
                        let record_child_depth = depth + 3;
                        for value in record.items.values() {
                            stack.push((value, record_child_depth));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl EncodeCheck for models::Entity {
    fn check_for_encode_from_depth(&self, init: usize) -> Result<(), EncodeError> {
        // Validate all attribute and tag expressions
        for expr in self.attrs.values().chain(self.tags.values()) {
            // Map: +1 for entering the list, +1 for entering the map entry
            expr.check_for_encode_from_depth(init + 2)?;
        }
        Ok(())
    }
}

impl EncodeCheck for models::Entities {
    fn check_for_encode_from_depth(&self, init: usize) -> Result<(), EncodeError> {
        for entity in &self.entities {
            entity.check_for_encode_from_depth(init + 1)?;
        }
        Ok(())
    }
}

impl EncodeCheck for models::TemplateBody {
    fn check_for_encode_from_depth(&self, init: usize) -> Result<(), EncodeError> {
        // Validate the non-scope constraint expression within the template body
        if let Some(ref expr) = self.non_scope_constraints {
            // List: +1 for entering the list
            expr.check_for_encode_from_depth(init + 1)?;
        }
        Ok(())
    }
}

impl EncodeCheck for models::PolicySet {
    fn check_for_encode_from_depth(&self, init: usize) -> Result<(), EncodeError> {
        for template in &self.templates {
            // List: +1 for entering the list
            template.check_for_encode_from_depth(init + 1)?;
        }
        Ok(())
    }
}

/// Trivial `EncodeCheck` for model types that have no recursive structure
/// requiring depth checks.
impl EncodeCheck for models::Name {
    fn check_for_encode_from_depth(&self, _init: usize) -> Result<(), EncodeError> {
        Ok(())
    }
}

impl EncodeCheck for models::Request {
    fn check_for_encode_from_depth(&self, init: usize) -> Result<(), EncodeError> {
        // The context field contains expressions that may be deeply nested
        for expr in self.context.values() {
            // Map: +1 for entering the list, +1 for entering the map entry
            expr.check_for_encode_from_depth(init + 2)?;
        }
        Ok(())
    }
}

impl EncodeCheck for models::Schema {
    fn check_for_encode_from_depth(&self, init: usize) -> Result<(), EncodeError> {
        for entity_decl in &self.entity_decls {
            // + 1 for entering entity decls
            for attr_type in entity_decl.attributes.values() {
                // Map: +1 for entering the list, +1 for entering the map entry
                check_type_depth(attr_type, init + 3)?;
            }
            if let Some(ref tag_type) = entity_decl.tags {
                // Map: +1 for entering the list, +1 for entering the map entry
                check_type_depth_inner(tag_type, init + 3)?;
            }
        }
        for action_decl in &self.action_decls {
            // + 1 for entering action decls list
            for attr_type in action_decl.context.values() {
                // Map: +1 for entering the list, +1 for entering the map entry
                check_type_depth(attr_type, init + 3)?;
            }
        }
        Ok(())
    }
}

/// Validate that an [`AttributeType`](models::AttributeType) doesn't exceed
/// the prost recursion budget.
///
/// Prost recursion cost from an `AttributeType`:
/// +1 (`AttributeType` message) + cost of inner `Type`
fn check_type_depth(attr_type: &models::AttributeType, init: usize) -> Result<(), EncodeError> {
    if let Some(ref ty) = attr_type.attr_type {
        // AttributeType itself costs 1 prost level, then the Type inside costs 1 more
        check_type_depth_inner(ty, init + 2)?;
    }
    Ok(())
}

/// Iteratively check `Type` nesting depth in prost recursion terms.
///
/// Prost recursion costs per `Type` variant:
/// - `SetElem(Box<Type>)`: the child `Type` is directly nested → +1 per level
/// - `Record`: +1 (`Record` message) + 1 (`AttributeType` message) + 1 (child `Type`) = +3
/// - Primitive/Entity/Extension: terminal, no recursion
fn check_type_depth_inner(root: &models::Type, starting_depth: usize) -> Result<(), EncodeError> {
    // Stack of (Type, prost_depth)
    let mut stack: Vec<(&models::Type, usize)> = vec![(root, starting_depth)];

    while let Some((ty, depth)) = stack.pop() {
        if depth > MAX_ENCODE_DEPTH {
            return Err(EncodeError::MaxDepthExceeded);
        }

        if let Some(ref data) = ty.data {
            use models::r#type::Data;
            match data {
                Data::Prim(_) => {}
                Data::Entity(_) | Data::Ext(_) => {
                    // Entity/Ext adds 1: (Name(..))
                    let name_depth = depth + 1;
                    if name_depth > MAX_ENCODE_DEPTH {
                        return Err(EncodeError::MaxDepthExceeded);
                    }
                }
                Data::SetElem(inner_type) => {
                    // set_elem is directly a Type field: +1 prost level
                    stack.push((inner_type, depth + 1));
                }
                Data::Record(record) => {
                    // Record message (+1) -> map entry (+1) -> AttributeType (+1) -> Type (+1) = +4
                    for attr_type in record.attrs.values() {
                        if let Some(ref inner_ty) = attr_type.attr_type {
                            stack.push((inner_ty, depth + 4));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
