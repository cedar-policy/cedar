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

/// Trait allowing serializing and deserializing in protobuf format
pub trait Protobuf: Sized {
    /// Encode into protobuf format. Returns a freshly-allocated buffer containing binary data.
    fn encode(&self) -> Vec<u8>;
    /// Decode the binary data in `buf`, producing something of type `Self`
    ///
    /// # Errors
    ///
    /// Will return [`DecodeError::Proto`] when the input buffer does not
    /// contain a valid protobuf message, or [`DecodeError::Conversion`] when
    /// the message is well-formed but cannot be converted into the target type.
    fn decode(buf: impl prost::bytes::Buf) -> Result<Self, DecodeError>;
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

use std::default::Default;

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
