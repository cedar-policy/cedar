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

        impl From<$B> for $A {
            fn from(v: $B) -> $A {
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

impl From<models::TemplateBody> for api::Template {
    fn from(v: models::TemplateBody) -> Self {
        Self::from_ast(v.into())
    }
}

impl From<&api::Policy> for models::Policy {
    fn from(v: &api::Policy) -> Self {
        Self::from(&v.ast)
    }
}

impl From<&api::PolicySet> for models::PolicySet {
    fn from(v: &api::PolicySet) -> Self {
        Self::from(&v.ast)
    }
}

impl TryFrom<models::PolicySet> for api::PolicySet {
    type Error = api::PolicySetError;
    fn try_from(v: models::PolicySet) -> Result<Self, Self::Error> {
        #[expect(clippy::expect_used, reason = "experimental feature")]
        Self::from_ast(
            v.try_into()
                .expect("proto-encoded policy set should be a valid policy set"),
        )
    }
}

#[expect(clippy::use_self, reason = "readability")]
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

#[expect(clippy::use_self, reason = "readability")]
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
        #[expect(clippy::expect_used, reason = "experimental feature")]
        Ok(traits::try_decode::<models::PolicySet, _, Self>(buf)?
            .expect("protobuf-encoded policy set should be a valid policy set"))
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, str::FromStr};

    use prost::Message as _;

    /// Performs a series of conversions: API -> Protobuf model -> Protobuf bytes -> Protobuf model -> API.
    /// Checks that the input API policy set is equal to the converted policy set.
    fn roundtrip_policies(policies: crate::PolicySet) {
        // API -> Protobuf model
        let policies_proto = crate::proto::models::PolicySet::from(&policies);
        // Protobuf model -> Protobuf bytes
        let buf = policies_proto.encode_to_vec();
        // Protobuf bytes -> Protobuf model
        let roundtripped_proto = crate::proto::models::PolicySet::decode(&buf[..])
            .expect("Failed to deserialize PolicySet from protobuf");
        // -> Protobuf model -> API
        let roundtripped = crate::PolicySet::try_from(roundtripped_proto)
            .expect("Failed to convert from protobuf to PolicySet");
        similar_asserts::assert_eq!(policies, roundtripped);
    }

    fn roundtrip_policies_text(text: &str) {
        let pset = crate::PolicySet::from_str(text).expect("Failed to parse policy set");
        roundtrip_policies(pset);
    }

    #[test]
    fn roundtrip_policyset_with_template_link() {
        let mut pset = crate::PolicySet::from_str(
            r#"
            permit(principal == ?principal, action, resource);
            "#,
        )
        .expect("Failed to parse policy set");
        pset.link(
            crate::PolicyId::new("policy0"),
            crate::PolicyId::new("link0"),
            HashMap::from([(
                crate::SlotId::principal(),
                crate::EntityUid::from_strs("User", "alice"),
            )]),
        )
        .expect("Failed to link template");
        roundtrip_policies(pset);
    }

    #[test]
    fn roundtrip_policyset_empty() {
        roundtrip_policies_text("");
    }

    #[test]
    fn roundtrip_policyset_with_static_policy() {
        roundtrip_policies_text(
            r#"
            permit(principal, action, resource);
            "#,
        );
    }

    #[test]
    fn roundtrip_policyset_with_multiple_static_policies() {
        roundtrip_policies_text(
            r#"
            permit(principal, action, resource);

            forbid(principal, action, resource) when { context.is_restricted };

            permit(principal == User::"alice", action == Action::"read", resource in Folder::"shared");
            "#,
        );
    }

    #[test]
    fn roundtrip_policyset_with_when_and_unless() {
        roundtrip_policies_text(
            r#"
            permit(principal, action, resource)
                when { resource.owner == principal }
                unless { principal.suspended };
            "#,
        );
    }

    #[test]
    fn roundtrip_policyset_with_annotations() {
        roundtrip_policies_text(
            r#"
            @advice("allow owner access")
            permit(principal, action == Action::"write", resource)
            when { resource.owner == principal };
            "#,
        );
    }

    #[test]
    fn roundtrip_policyset_with_multiple_template_links() {
        let mut pset = crate::PolicySet::from_str(
            r#"
            permit(principal == ?principal, action, resource in ?resource);
            "#,
        )
        .expect("Failed to parse policy set");
        pset.link(
            crate::PolicyId::new("policy0"),
            crate::PolicyId::new("link0"),
            HashMap::from([
                (
                    crate::SlotId::principal(),
                    crate::EntityUid::from_strs("User", "alice"),
                ),
                (
                    crate::SlotId::resource(),
                    crate::EntityUid::from_strs("Folder", "shared"),
                ),
            ]),
        )
        .expect("Failed to link template");
        pset.link(
            crate::PolicyId::new("policy0"),
            crate::PolicyId::new("link1"),
            HashMap::from([
                (
                    crate::SlotId::principal(),
                    crate::EntityUid::from_strs("User", "bob"),
                ),
                (
                    crate::SlotId::resource(),
                    crate::EntityUid::from_strs("Folder", "private"),
                ),
            ]),
        )
        .expect("Failed to link template");
        roundtrip_policies(pset);
    }

    #[test]
    fn roundtrip_policyset_with_static_and_templates() {
        let mut pset = crate::PolicySet::from_str(
            r#"
            forbid(principal, action, resource) unless { context.authenticated };

            permit(principal == ?principal, action, resource);
            "#,
        )
        .expect("Failed to parse policy set");
        println!("{:?}", pset);
        pset.link(
            crate::PolicyId::new("policy1"),
            crate::PolicyId::new("link0"),
            HashMap::from([(
                crate::SlotId::principal(),
                crate::EntityUid::from_strs("User", "admin"),
            )]),
        )
        .expect("Failed to link template");
        roundtrip_policies(pset);
    }

    #[test]
    fn roundtrip_policyset_with_is_constraint() {
        roundtrip_policies_text(
            r#"
            permit(principal is User, action, resource is Folder);
            "#,
        );
    }

    #[test]
    fn roundtrip_policyset_with_is_in_constraint() {
        roundtrip_policies_text(
            r#"
            permit(principal is User in Group::"admins", action, resource);
            "#,
        );
    }

    #[test]
    fn roundtrip_policyset_with_action_in_set() {
        roundtrip_policies_text(
            r#"
            permit(principal, action in [Action::"read", Action::"list"], resource);
            "#,
        );
    }

    #[test]
    fn roundtrip_policyset_with_extension_functions() {
        roundtrip_policies_text(
            r#"
            forbid(principal, action, resource)
                when { !context.src_ip.isInRange(ip("10.0.0.0/8")) };
            "#,
        );
    }

    #[test]
    fn roundtrip_policyset_with_unlinked_template() {
        roundtrip_policies_text(
            r#"
            permit(principal == ?principal, action, resource);
            "#,
        );
    }
}
