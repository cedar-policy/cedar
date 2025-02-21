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
standard_conversions!(api::Entities, api::Entities, models::Entities);
standard_conversions!(api::Schema, api::Schema, models::ValidatorSchema);
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

impl From<&api::Policy> for models::LiteralPolicy {
    fn from(v: &api::Policy) -> Self {
        Self::from(&v.ast)
    }
}

impl TryFrom<&models::LiteralPolicy> for api::Policy {
    type Error = cedar_policy_core::ast::ReificationError;
    fn try_from(v: &models::LiteralPolicy) -> Result<Self, Self::Error> {
        let p = cedar_policy_core::ast::Policy::try_from(v)?;
        Ok(Self::from_ast(p))
    }
}

impl From<&api::PolicySet> for models::LiteralPolicySet {
    fn from(v: &api::PolicySet) -> Self {
        Self::from(&v.ast)
    }
}

impl TryFrom<&models::LiteralPolicySet> for api::PolicySet {
    type Error = api::PolicySetError;
    fn try_from(v: &models::LiteralPolicySet) -> Result<Self, Self::Error> {
        // PANIC SAFETY: experimental feature
        #[allow(clippy::expect_used)]
        Self::from_ast(
            v.try_into()
                .expect("proto-encoded policy set should be a valid policy set"),
        )
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
standard_protobuf_impl!(api::Schema, models::ValidatorSchema);
standard_protobuf_impl!(api::EntityTypeName, models::Name);
standard_protobuf_impl!(api::EntityNamespace, models::Name);
standard_protobuf_impl!(api::Template, models::TemplateBody);
standard_protobuf_impl!(api::Expression, models::Expr);
standard_protobuf_impl!(api::Request, models::Request);

// nonstandard implementations of `traits::Protobuf`

impl traits::Protobuf for api::PolicySet {
    fn encode(&self) -> Vec<u8> {
        traits::encode_to_vec::<models::LiteralPolicySet>(self)
    }
    fn decode(buf: impl prost::bytes::Buf) -> Result<Self, prost::DecodeError> {
        // PANIC SAFETY: experimental feature
        #[allow(clippy::expect_used)]
        Ok(
            traits::try_decode::<models::LiteralPolicySet, _, Self>(buf)?
                .expect("protobuf-encoded policy set should be a valid policy set"),
        )
    }
}

impl traits::Protobuf for api::Policy {
    fn encode(&self) -> Vec<u8> {
        traits::encode_to_vec::<models::LiteralPolicy>(self)
    }
    fn decode(buf: impl prost::bytes::Buf) -> Result<Self, prost::DecodeError> {
        // PANIC SAFETY: experimental feature
        #[allow(clippy::expect_used)]
        Ok(traits::try_decode::<models::LiteralPolicy, _, Self>(buf)?
            .expect("protobuf-encoded policy should be a valid policy"))
    }
}
