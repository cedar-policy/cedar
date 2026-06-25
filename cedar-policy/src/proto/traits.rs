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

/// A trait for objects that have a `try_validate` method returning `self` if the object is
/// valid.
pub trait TryValidate: Sized {
    /// The type of errors returned by the validation method.
    type Err: Display;
    /// A validation method that returns the object itself, or an error if it is invalid.
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
    fn encode(&self) -> Vec<u8>;
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

/// Encode `thing` into `buf` using the protobuf format `M`
///
/// `Err` is only returned if `buf` has insufficient space.
#[expect(
    dead_code,
    reason = "experimental feature, we might have use for this one in the future"
)]
pub(crate) fn encode<M: prost::Message>(
    thing: impl Into<M>,
    buf: &mut impl prost::bytes::BufMut,
) -> Result<(), prost::EncodeError> {
    thing.into().encode(buf)
}

/// Encode `thing` into a freshly-allocated buffer using the protobuf format `M`
pub(crate) fn encode_to_vec<M: prost::Message>(thing: impl Into<M>) -> Vec<u8> {
    thing.into().encode_to_vec()
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

impl TryValidate for api::PolicySet {
    type Err = PolicySetValidationError;
    fn try_validate(self) -> Result<Self, Self::Err> {
        self.ast.try_validate().map(|o| o.into())
    }
}

impl TryValidate for api::Entities {
    type Err = EntitiesError;
    fn try_validate(self) -> Result<api::Entities, EntitiesError> {
        Ok(api::Entities(self.0.try_validate()?))
    }
}

impl TryValidate for api::Entity {
    type Err = EntitiesError;
    fn try_validate(self) -> Result<api::Entity, EntitiesError> {
        Ok(api::Entity(self.0.try_validate()?))
    }
}

impl TryValidate for api::Schema {
    type Err = SchemaError;
    fn try_validate(self) -> Result<Self, SchemaError> {
        Ok(api::Schema(self.0.try_validate()?))
    }
}

impl TryValidate for api::Template {
    type Err = TemplateValidationError;
    fn try_validate(self) -> Result<Self, TemplateValidationError> {
        Ok(api::Template {
            ast: self.ast.try_validate()?,
            ..self
        })
    }
}

impl TryValidate for api::Expression {
    type Err = ExprValidationError;
    fn try_validate(self) -> Result<Self, ExprValidationError> {
        Ok(api::Expression(self.0.try_validate()?))
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
