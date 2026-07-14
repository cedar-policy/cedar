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

use crate::proto::entities::entities_model_to_api;

use super::super::api;
use super::{ast::ProtobufConversionError, models, traits};
use prost::Message as _;
use traits::TryValidate as _;

/// Macro that implements `From<A>` and `TryFrom<B>` for types where
/// one conversion direction is infallible, the other is not. This is typically the case where
/// the API type converts to protobuf models without failing, but converting the protobuf model
/// to the API type requires additional checks.
macro_rules! fallible_conversions {
    ( $A:ty, $A_expr:expr, $B:ty ) => {
        impl From<&$A> for $B {
            fn from(v: &$A) -> $B {
                Self::from(&v.0)
            }
        }

        impl TryFrom<$B> for $A {
            type Error = ProtobufConversionError;
            fn try_from(v: $B) -> Result<$A, Self::Error> {
                Ok($A_expr(v.try_into()?))
            }
        }
    };
}

// fallible conversions (encode infallible, decode fallible)

fallible_conversions!(api::Entity, api::Entity, models::Entity);
fallible_conversions!(api::EntityUid, api::EntityUid, models::EntityUid);
fallible_conversions!(api::Entities, api::Entities, models::Entities);
fallible_conversions!(api::Schema, api::Schema, models::Schema);
fallible_conversions!(api::EntityTypeName, api::EntityTypeName, models::Name);
fallible_conversions!(api::EntityNamespace, api::EntityNamespace, models::Name);
fallible_conversions!(api::Expression, api::Expression, models::Expr);
fallible_conversions!(api::Request, api::Request, models::Request);

// nonstandard conversions

impl From<&api::Template> for models::TemplateBody {
    fn from(v: &api::Template) -> Self {
        Self::from(&v.ast)
    }
}

impl TryFrom<models::TemplateBody> for api::Template {
    type Error = ProtobufConversionError;
    fn try_from(v: models::TemplateBody) -> Result<Self, Self::Error> {
        Ok(Self::from_ast(v.try_into()?))
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
    type Error = ProtobufConversionError;
    fn try_from(v: models::PolicySet) -> Result<Self, Self::Error> {
        let ast: cedar_policy_core::ast::PolicySet = v.try_into()?;
        Ok(Self::from_ast(ast))
    }
}

/// Macro that implements `traits::Protobuf` for cases where `From<>` and `TryFrom<>`
/// conversions exist between the api type `$api` and the protobuf model type `$model`
macro_rules! standard_protobuf_impl {
    ( $api:ty, $model:ty) => {
        impl traits::Protobuf for $api {
            fn encode(&self) -> Vec<u8> {
                traits::encode_to_vec::<$model>(self)
            }
            fn decode_unchecked(buf: impl prost::bytes::Buf) -> Result<Self, traits::DecodeError> {
                traits::try_decode::<$model, _, _>(buf)
            }
        }
    };
}

// standard implementations of `traits::Protobuf`

standard_protobuf_impl!(api::Entity, models::Entity);
standard_protobuf_impl!(api::Schema, models::Schema);
standard_protobuf_impl!(api::EntityTypeName, models::Name);
standard_protobuf_impl!(api::EntityNamespace, models::Name);
standard_protobuf_impl!(api::Template, models::TemplateBody);
standard_protobuf_impl!(api::Expression, models::Expr);
standard_protobuf_impl!(api::Request, models::Request);

// nonstandard implementations of `traits::Protobuf`

impl traits::Protobuf for api::Entities {
    fn encode(&self) -> Vec<u8> {
        traits::encode_to_vec::<models::Entities>(self)
    }
    fn decode(buf: impl prost::bytes::Buf) -> Result<Self, traits::DecodeError> {
        // Uses the standard TryFrom path which computes TC via ComputeNow
        let entities: Self = traits::try_decode::<models::Entities, _, _>(buf)?;
        entities
            .try_validate()
            .map_err(|e| ProtobufConversionError::InvalidValue(format!("invalid: {e}")).into())
    }
    fn decode_unchecked(buf: impl prost::bytes::Buf) -> Result<Self, traits::DecodeError> {
        let msg = models::Entities::decode(buf)?;
        // Skip TC computation for trusted data
        let core_entities = entities_model_to_api(
            msg,
            cedar_policy_core::entities::TCComputation::AssumeAlreadyComputed,
        )?;
        Ok(Self(core_entities))
    }
}

impl traits::Protobuf for api::PolicySet {
    fn encode(&self) -> Vec<u8> {
        traits::encode_to_vec::<models::PolicySet>(self)
    }
    fn decode_unchecked(buf: impl prost::bytes::Buf) -> Result<Self, traits::DecodeError> {
        traits::try_decode::<models::PolicySet, _, Self>(buf)
    }
}

#[cfg(test)]
mod test {
    use crate::proto::traits::Protobuf;
    use cool_asserts::assert_matches;
    use prost::Message as _;
    use std::{collections::HashMap, str::FromStr};

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

    /// [`decode`] and [`decode_unchecked`] should produce the same data when they don't fail.
    fn decode_eq_decode_unchecked<T: Protobuf + PartialEq>(x: T) {
        let buf = x.encode();
        let checked = T::decode(&buf[..]).expect("decode failed");
        let unchecked = T::decode_unchecked(&buf[..]).expect("decode_unchecked failed");
        similar_asserts::assert_eq!(checked, unchecked);
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

    /// Decoding arbitrary bytes must never panic — it should return `Err`.
    #[test]
    fn decode_random_bytes_does_not_panic() {
        use crate::proto::traits::Protobuf;

        let inputs: &[&[u8]] = &[
            b"",
            b"\x00",
            b"\xff\xff\xff\xff",
            b"not a protobuf",
            &[0u8; 1024],
            &{
                let mut v = Vec::new();
                for i in 0u8..=255 {
                    v.push(i);
                }
                v
            },
        ];

        for input in inputs {
            let _ = crate::Entity::decode(*input);
            let _ = crate::Entities::decode(*input);
            let _ = crate::Schema::decode(*input);
            let _ = crate::EntityTypeName::decode(*input);
            let _ = crate::EntityNamespace::decode(*input);
            let _ = crate::Template::decode(*input);
            let _ = crate::Expression::decode(*input);
            let _ = crate::Request::decode(*input);
            let _ = crate::PolicySet::decode(*input);
        }
    }

    #[test]
    fn decode_conversion_error_path() {
        use crate::proto::traits::Protobuf;
        // An Entity with a uid whose type name is empty string triggers
        // ProtobufConversionError, exercising the DecodeError::Conversion path.
        let model = crate::proto::models::Entity {
            uid: Some(crate::proto::models::EntityUid {
                ty: Some(crate::proto::models::Name {
                    id: String::new(), // invalid: empty identifier
                    path: vec![],
                }),
                eid: "x".to_string(),
            }),
            attrs: Default::default(),
            ancestors: vec![],
            tags: Default::default(),
        };
        let buf = prost::Message::encode_to_vec(&model);
        assert_matches!(
            crate::Entity::decode(&buf[..]),
            Err(crate::proto::traits::DecodeError::Conversion(_))
        );
    }

    #[test]
    fn roundtrip_decode_unchecked_entities() {
        let entities = crate::Entities::from_json_str(
            r#"[
                {"uid": {"type": "User", "id": "alice"}, "attrs": {"age": 25}, "parents": [{"type": "Group", "id": "admins"}]},
                {"uid": {"type": "Group", "id": "admins"}, "attrs": {}, "parents": []}
            ]"#,
            None,
        )
        .expect("Failed to parse entities");
        decode_eq_decode_unchecked::<crate::Entities>(entities);
    }

    #[test]
    fn roundtrip_decode_unchecked_policy_set() {
        let pset = crate::PolicySet::from_str(
            r#"
            permit(principal == User::"alice", action, resource);
            forbid(principal, action, resource) when { context.restricted };
            "#,
        )
        .expect("Failed to parse policy set");
        decode_eq_decode_unchecked::<crate::PolicySet>(pset);
    }

    #[test]
    fn roundtrip_decode_unchecked_template() {
        let template =
            crate::Template::from_str(r#"permit(principal == ?principal, action, resource);"#)
                .expect("Failed to parse template");

        decode_eq_decode_unchecked::<crate::Template>(template);
    }

    #[test]
    fn roundtrip_decode_unchecked_entity() {
        let entity = crate::Entity::from_json_value(
            serde_json::json!({"uid": {"type": "User", "id": "bob"}, "attrs": {"active": true}, "parents": []}),
            None,
        )
        .expect("Failed to parse entity");
        decode_eq_decode_unchecked::<crate::Entity>(entity);
    }

    #[test]
    fn roundtrip_decode_unchecked_request() {
        let request = crate::Request::new(
            crate::EntityUid::from_strs("User", "alice"),
            crate::EntityUid::from_strs("Action", "read"),
            crate::EntityUid::from_strs("Document", "doc1"),
            crate::Context::empty(),
            None,
        )
        .expect("Failed to create request");
        decode_eq_decode_unchecked::<crate::Request>(request);
    }
}
