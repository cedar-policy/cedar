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

use super::super::api;
use super::{models, traits};

/// Macro that implements From<> both ways for cases where the `A` type is a
/// simple wrapper around a different type `C` which already has From<>
/// conversions both ways with `B`
macro_rules! standard_conversions {
    ( $A:ty, $A_expr:expr, $B:ty ) => {
        impl From<&$A> for $B {
            fn from(v: &$A) -> $B {
                Self::from(&v.0)
            }
        }

        impl From<&$B> for $A {
            fn from(v: &$B) -> $A {
                $A_expr(v.into())
            }
        }
    };
}

// standard conversions

standard_conversions!(api::Entity, api::Entity, models::Entity);
standard_conversions!(api::EntityUid, api::EntityUid, models::EntityUid);
standard_conversions!(api::Entities, api::Entities, models::Entities);
standard_conversions!(api::Schema, api::Schema, models::Schema);
standard_conversions!(api::EntityTypeName, api::EntityTypeName, models::Name);
standard_conversions!(api::EntityNamespace, api::EntityNamespace, models::Name);
standard_conversions!(api::Expression, api::Expression, models::Expr);
standard_conversions!(api::Request, api::Request, models::Request);

// nonstandard conversions

impl From<&api::Template> for models::TemplateBody {
    fn from(v: &api::Template) -> Self {
        Self::from(&v.ast)
    }
}

impl From<&models::TemplateBody> for api::Template {
    fn from(v: &models::TemplateBody) -> Self {
        Self::from_ast(v.into())
    }
}

impl From<&api::Policy> for models::Policy {
    fn from(v: &api::Policy) -> Self {
        Self::from(&v.ast)
    }
}

impl TryFrom<&models::Policy> for api::Policy {
    type Error = cedar_policy_core::ast::ReificationError;
    fn try_from(v: &models::Policy) -> Result<Self, Self::Error> {
        let p = cedar_policy_core::ast::Policy::try_from(v)?;
        Ok(Self::from_ast(p))
    }
}

impl From<&api::PolicySet> for models::PolicySet {
    fn from(v: &api::PolicySet) -> Self {
        Self::from(&v.ast)
    }
}

impl TryFrom<&models::PolicySet> for api::PolicySet {
    type Error = api::PolicySetError;
    fn try_from(v: &models::PolicySet) -> Result<Self, Self::Error> {
        // PANIC SAFETY: experimental feature
        #[allow(clippy::expect_used)]
        Self::from_ast(
            v.try_into()
                .expect("proto-encoded policy set should be a valid policy set"),
        )
    }
}

#[allow(clippy::use_self)]
impl From<&api::ValidationMode> for models::ValidationMode {
    fn from(v: &api::ValidationMode) -> Self {
        match v {
            api::ValidationMode::Strict => models::ValidationMode::Strict,
            #[cfg(feature = "permissive-validate")]
            api::ValidationMode::Permissive => models::ValidationMode::Permissive,
            #[cfg(feature = "partial-validate")]
            api::ValidationMode::Partial => models::ValidationMode::Partial,
        }
    }
}

#[allow(clippy::use_self)]
impl From<&models::ValidationMode> for api::ValidationMode {
    fn from(v: &models::ValidationMode) -> Self {
        match v {
            models::ValidationMode::Strict => api::ValidationMode::Strict,
            #[cfg(feature = "permissive-validate")]
            models::ValidationMode::Permissive => api::ValidationMode::Permissive,
            #[cfg(not(feature = "permissive-validate"))]
            models::ValidationMode::Permissive => panic!("Protobuf specifies permissive validation, but `permissive-validate` feature not enabled in this build"),
            #[cfg(feature = "partial-validate")]
            models::ValidationMode::Partial => api::ValidationMode::Partial,
            #[cfg(not(feature = "partial-validate"))]
            models::ValidationMode::Partial => panic!("Protobuf specifies partial validation, but `partial-validate` feature not enabled in this build"),
        }
    }
}

/// Macro that implements `traits::Protobuf` for cases where From<> conversions
/// exist both ways between the api type `$api` and the protobuf model type `$model`
macro_rules! standard_protobuf_impl {
    ( $api:ty, $model:ty ) => {
        impl traits::Protobuf for $api {
            fn encode(&self) -> Vec<u8> {
                traits::encode_to_vec::<$model>(self)
            }
            fn decode(buf: impl prost::bytes::Buf) -> Result<Self, prost::DecodeError> {
                traits::decode::<$model, _>(buf)
            }
        }
    };
}

// standard implementations of `traits::Protobuf`

standard_protobuf_impl!(api::Entity, models::Entity);
standard_protobuf_impl!(api::Entities, models::Entities);
standard_protobuf_impl!(api::Schema, models::Schema);
standard_protobuf_impl!(api::EntityTypeName, models::Name);
standard_protobuf_impl!(api::EntityNamespace, models::Name);
standard_protobuf_impl!(api::Template, models::TemplateBody);
standard_protobuf_impl!(api::Expression, models::Expr);
standard_protobuf_impl!(api::Request, models::Request);

// nonstandard implementations of `traits::Protobuf`

impl traits::Protobuf for api::PolicySet {
    fn encode(&self) -> Vec<u8> {
        traits::encode_to_vec::<models::PolicySet>(self)
    }
    fn decode(buf: impl prost::bytes::Buf) -> Result<Self, prost::DecodeError> {
        // PANIC SAFETY: experimental feature
        #[allow(clippy::expect_used)]
        Ok(traits::try_decode::<models::PolicySet, _, Self>(buf)?
            .expect("protobuf-encoded policy set should be a valid policy set"))
    }
}

impl traits::Protobuf for api::Policy {
    fn encode(&self) -> Vec<u8> {
        traits::encode_to_vec::<models::Policy>(self)
    }
    fn decode(buf: impl prost::bytes::Buf) -> Result<Self, prost::DecodeError> {
        // PANIC SAFETY: experimental feature
        #[allow(clippy::expect_used)]
        Ok(traits::try_decode::<models::Policy, _, Self>(buf)?
            .expect("protobuf-encoded policy should be a valid policy"))
    }
}
