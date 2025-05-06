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

/// Trait allowing serializing and deserializing in protobuf format
pub trait Protobuf: Sized {
    /// Encode into protobuf format. Returns a freshly-allocated buffer containing binary data.
    fn encode(&self) -> Vec<u8>;
    /// Decode the binary data in `buf`, producing something of type `Self`
    ///
    /// # Errors
    ///
    /// Will return a `prost::DecodeError` when the input buffer does not contain a
    /// valid Protobuf message.
    fn decode(buf: impl prost::bytes::Buf) -> Result<Self, prost::DecodeError>;
}

/// Encode `thing` into `buf` using the protobuf format `M`
///
/// `Err` is only returned if `buf` has insufficient space.
#[allow(dead_code)] // experimental feature, we might have use for this one in the future
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
pub(crate) fn decode<M: prost::Message + Default, T: for<'a> From<&'a M>>(
    buf: impl prost::bytes::Buf,
) -> Result<T, prost::DecodeError> {
    M::decode(buf).map(|m| T::from(&m))
}

/// Decode something of type `T` from `buf` using the protobuf format `M`
pub(crate) fn try_decode<M: prost::Message + Default, E, T: for<'a> TryFrom<&'a M, Error = E>>(
    buf: impl prost::bytes::Buf,
) -> Result<Result<T, E>, prost::DecodeError> {
    M::decode(buf).map(|m| T::try_from(&m))
}
