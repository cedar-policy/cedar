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
            fn encode(&self) -> Result<Vec<u8>, traits::EncodeError> {
                traits::encode_to_vec::<$model, _>(self)
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
    fn encode(&self) -> Result<Vec<u8>, traits::EncodeError> {
        traits::encode_to_vec::<models::Entities, _>(self)
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
    fn encode(&self) -> Result<Vec<u8>, traits::EncodeError> {
        traits::encode_to_vec::<models::PolicySet, _>(self)
    }
    fn decode_unchecked(buf: impl prost::bytes::Buf) -> Result<Self, traits::DecodeError> {
        traits::try_decode::<models::PolicySet, _, Self>(buf)
    }
}

#[cfg(test)]
mod roundtrip_test {
    use super::models;
    use prost::Message as _;
    use std::{collections::HashMap, str::FromStr};

    /// Performs a series of conversions: API -> Protobuf model -> Protobuf bytes -> Protobuf model -> API.
    /// Checks that the input API policy set is equal to the converted policy set.
    fn roundtrip_policies(policies: crate::PolicySet) {
        // API -> Protobuf model
        let policies_proto = models::PolicySet::from(&policies);
        // Protobuf model -> Protobuf bytes
        let buf = policies_proto.encode_to_vec();
        // Protobuf bytes -> Protobuf model
        let roundtripped_proto = models::PolicySet::decode(&buf[..])
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

#[cfg(test)]
mod decode_test {
    use crate::proto::traits::Protobuf;
    use cool_asserts::assert_matches;
    use std::collections::HashMap;
    use std::str::FromStr;

    /// [`decode`] and [`decode_unchecked`] should produce the same data when they don't fail.
    fn decode_eq_decode_unchecked<T: Protobuf + PartialEq>(x: T) {
        let buf = x.encode().expect("encode failed");
        let checked = T::decode(&buf[..]).expect("decode failed");
        let unchecked = T::decode_unchecked(&buf[..]).expect("decode_unchecked failed");
        similar_asserts::assert_eq!(checked, unchecked);
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
            attrs: HashMap::new(),
            ancestors: vec![],
            tags: HashMap::new(),
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

#[cfg(test)]
mod encode_test {
    use super::models;
    use super::traits::{EncodeCheck, EncodeError, Protobuf, MAX_ENCODE_DEPTH};
    use crate::proto::test_utils::*;
    use crate::Expression;
    use cedar_policy_core::ast;
    use cool_asserts::assert_matches;
    use std::str::FromStr;

    // ================================================================
    // Helpers for building deeply nested expressions of various kinds
    // ================================================================

    /// Build `n` levels of `!(!(...lit_bool(true)...))`.
    fn deep_unary(n: usize) -> models::Expr {
        let mut e = lit_bool(true);
        for _ in 0..n {
            e = not(e);
        }
        e
    }

    /// Build `n` levels of `{k: {k: ...lit_bool(true)...}}`.
    fn deep_record_expr(n: usize) -> models::Expr {
        let mut e = lit_bool(true);
        for _ in 0..n {
            e = record([("k", e)]);
        }
        e
    }

    /// Build `n` levels of `if true then (if true then ... else false) else false`.
    fn deep_if(n: usize) -> models::Expr {
        let mut e = lit_bool(true);
        for _ in 0..n {
            e = if_then_else(lit_bool(true), e, lit_bool(false));
        }
        e
    }

    /// Build `n` levels of `true && (true && ...)`.
    fn deep_and(n: usize) -> models::Expr {
        let mut e = lit_bool(true);
        for _ in 0..n {
            e = models::Expr {
                expr_kind: Some(models::expr::ExprKind::And(Box::new(models::expr::And {
                    left: Some(Box::new(lit_bool(true))),
                    right: Some(Box::new(e)),
                }))),
            };
        }
        e
    }

    /// Build `n` levels of `true || (true || ...)`.
    fn deep_or(n: usize) -> models::Expr {
        let mut e = lit_bool(false);
        for _ in 0..n {
            e = models::Expr {
                expr_kind: Some(models::expr::ExprKind::Or(Box::new(models::expr::Or {
                    left: Some(Box::new(lit_bool(true))),
                    right: Some(Box::new(e)),
                }))),
            };
        }
        e
    }

    /// Build `n` levels of `(... + 1) + 1`.
    fn deep_binary(n: usize) -> models::Expr {
        let mut e = lit_long(0);
        for _ in 0..n {
            e = binary(models::expr::binary_app::Op::Add, e, lit_long(1));
        }
        e
    }

    /// Build `n` levels of `ext(ext(...))`.
    fn deep_ext(n: usize) -> models::Expr {
        let mut e = lit_str("1.0");
        for _ in 0..n {
            e = ext_call("decimal", [e]);
        }
        e
    }

    /// Build `n` levels of `.attr.attr...`.
    fn deep_get_attr(n: usize) -> models::Expr {
        let mut e = var(models::expr::Var::Context);
        for _ in 0..n {
            e = get_attr(e, "x");
        }
        e
    }

    /// Build `n` levels of `has attr has attr ...`.
    fn deep_has_attr(n: usize) -> models::Expr {
        // has returns bool, so wrap: if (e has "x") then (inner has "x") else false
        // Simpler: just chain `has` on nested get_attr
        let mut e = var(models::expr::Var::Context);
        for _ in 0..n {
            e = has_attr(e, "x");
        }
        e
    }

    /// Build `n` levels of `like` wrapping.
    fn deep_like(n: usize) -> models::Expr {
        // `like` takes an expr child, so we can nest: like(like(...))
        // But `like` returns bool... use if to re-wrap.
        // Simpler: just nest the expr child of Like.
        let mut e = lit_str("hello");
        for _ in 0..n {
            e = models::Expr {
                expr_kind: Some(models::expr::ExprKind::Like(Box::new(models::expr::Like {
                    expr: Some(Box::new(e)),
                    pattern: vec![],
                }))),
            };
        }
        e
    }

    /// Build `n` levels of `is` wrapping.
    fn deep_is(n: usize) -> models::Expr {
        let mut e = var(models::expr::Var::Principal);
        for _ in 0..n {
            e = models::Expr {
                expr_kind: Some(models::expr::ExprKind::Is(Box::new(models::expr::Is {
                    expr: Some(Box::new(e)),
                    entity_type: Some(name("User")),
                }))),
            };
        }
        e
    }

    /// Build `n` levels of nested sets: `[[[[...]]]]`.
    fn deep_set(n: usize) -> models::Expr {
        let mut e = lit_long(1);
        for _ in 0..n {
            e = set([e]);
        }
        e
    }

    /// Maximum nesting levels that fit within `MAX_ENCODE_DEPTH`.
    /// Each nesting costs 2 prost levels; root `Expr` costs 1.
    /// So max nestings = (`MAX_ENCODE_DEPTH` - 1) / 2.
    const MAX_NESTING: usize = (MAX_ENCODE_DEPTH - 1) / 2;

    // ================================================================
    // Depth limit tests for all expression variants
    // ================================================================

    /// Assert that the given expression passes or fails the encode check.
    /// When `expect_ok`, also verifies the encode→decode roundtrip succeeds
    /// (i.e., prost can decode what we encoded).
    #[track_caller]
    fn assert_encode_check(name: &str, expr: &models::Expr, expect_ok: bool) {
        if expect_ok {
            assert!(
                expr.check_for_encode().is_ok(),
                "{name}: expected Ok but got MaxDepthExceeded"
            );
            // Verify prost can actually decode the encoded bytes.
            let bytes = prost::Message::encode_to_vec(expr);
            assert!(
                <models::Expr as prost::Message>::decode(&bytes[..]).is_ok(),
                "{name}: decoding failed despite depth check",
            );
        } else {
            assert_matches!(
                expr.check_for_encode(),
                Err(EncodeError::MaxDepthExceeded),
                "{name} did not error with MaxDepthExceeded"
            );
        }
    }

    #[test]
    fn depth_all_expr_variants_at_limit() {
        let builders: &[(&str, fn(usize) -> models::Expr, usize)] = &[
            ("unary", deep_unary, MAX_NESTING),
            ("record", deep_record_expr, (MAX_ENCODE_DEPTH - 1) / 3),
            ("if", deep_if, MAX_NESTING),
            ("and", deep_and, MAX_NESTING),
            ("or", deep_or, MAX_NESTING),
            ("binary", deep_binary, MAX_NESTING),
            ("ext", deep_ext, MAX_NESTING),
            ("get_attr", deep_get_attr, MAX_NESTING),
            ("has_attr", deep_has_attr, MAX_NESTING),
            ("like", deep_like, MAX_NESTING),
            ("is", deep_is, MAX_NESTING),
            ("set", deep_set, MAX_NESTING),
        ];
        for (name, builder, limit) in builders {
            let ok = builder(*limit);
            assert_encode_check(name, &ok, true);
            let bad = builder(*limit + 1);
            assert_encode_check(name, &bad, false);
        }
    }

    // ================================================================
    // Full API encode path tests
    // ================================================================

    #[test]
    fn encode_expression_api_returns_error_on_deep_expr() {
        let mut e = ast::Expr::var(ast::Var::Principal);
        for _ in 0..=MAX_NESTING {
            e = ast::Expr::not(e);
        }
        let expression = crate::Expression(e);
        assert_matches!(expression.encode(), Err(EncodeError::MaxDepthExceeded));
    }

    #[test]
    fn encode_policyset_with_deep_condition_fails() {
        let mut e = ast::Expr::val(true);
        for _ in 0..=MAX_NESTING {
            e = ast::Expr::not(e);
        }
        let template = ast::Template::new(
            ast::PolicyID::from_string("deep_policy"),
            None,
            ast::Annotations::new(),
            ast::Effect::Permit,
            ast::PrincipalConstraint::any(),
            ast::ActionConstraint::any(),
            ast::ResourceConstraint::any(),
            Some(e),
        );
        let mut pset = ast::PolicySet::new();
        pset.add_template(template).expect("add template");
        let api_pset = crate::PolicySet::from_ast(pset);
        assert_matches!(api_pset.encode(), Err(EncodeError::MaxDepthExceeded));
    }

    #[test]
    fn encode_entities_with_deep_attr_fails() {
        let deep_expr = deep_unary(MAX_NESTING + 1);
        let ent = entity("User", "alice", [("deep_attr", deep_expr)]);
        assert_matches!(ent.check_for_encode(), Err(EncodeError::MaxDepthExceeded));
    }

    #[test]
    fn encode_entity_with_deep_tag_fails() {
        let deep_expr = deep_unary(MAX_NESTING + 1);
        let ent = entity_full("User", "alice", [], [], [("deep_tag", deep_expr)]);
        assert_matches!(ent.check_for_encode(), Err(EncodeError::MaxDepthExceeded));
    }

    #[test]
    fn encode_request_with_deep_context_fails() {
        let deep_expr = deep_unary(MAX_NESTING + 1);
        let req = models::Request {
            principal: Some(entity_uid("User", "alice")),
            action: Some(entity_uid("Action", "read")),
            resource: Some(entity_uid("Doc", "readme")),
            context: [("deep".to_string(), deep_expr)].into_iter().collect(),
        };
        assert_matches!(req.check_for_encode(), Err(EncodeError::MaxDepthExceeded));
    }

    #[test]
    fn encode_request_shallow_context_succeeds() {
        let req = models::Request {
            principal: Some(entity_uid("User", "alice")),
            action: Some(entity_uid("Action", "read")),
            resource: Some(entity_uid("Doc", "readme")),
            context: [("flag".to_string(), lit_bool(true))].into_iter().collect(),
        };
        assert!(req.check_for_encode().is_ok());
    }

    // ================================================================
    // Schema type depth tests
    // ================================================================

    /// Build `n` levels of `Set(Set(...Long...))`.
    fn deep_set_type(n: usize) -> models::Type {
        let mut ty = long_type();
        for _ in 0..n {
            ty = set_type(ty);
        }
        ty
    }

    /// Build `n` levels of `Record { x: Record { x: ... Long } }`.
    fn deep_record_type(n: usize) -> models::Type {
        let mut ty = long_type();
        for _ in 0..n {
            ty = record_type([("x", required(ty))]);
        }
        ty
    }

    #[test]
    fn encode_schema_set_type_limit() {
        // Set nesting costs 1 prost level per level, starting at depth 2
        // (AttributeType + Type). Exceeds when 2 + n > MAX_ENCODE_DEPTH.
        let max_set_depth = MAX_ENCODE_DEPTH - 2;
        let ok_schema = schema([entity_decl(
            "Foo",
            [("a", required(deep_set_type(max_set_depth)))],
        )]);
        assert!(ok_schema.check_for_encode().is_ok());

        let bad_schema = schema([entity_decl(
            "Foo",
            [("a", required(deep_set_type(max_set_depth + 1)))],
        )]);
        assert_matches!(
            bad_schema.check_for_encode(),
            Err(EncodeError::MaxDepthExceeded)
        );
    }

    #[test]
    fn encode_schema_record_type_limit() {
        // Record nesting costs 3 prost levels per level, starting at depth 2.
        // Exceeds when 2 + 3*n > MAX_ENCODE_DEPTH.
        let max_rec_depth = (MAX_ENCODE_DEPTH - 2) / 3;
        let ok_schema = schema([entity_decl(
            "Bar",
            [("a", required(deep_record_type(max_rec_depth)))],
        )]);
        assert!(ok_schema.check_for_encode().is_ok());

        let bad_schema = schema([entity_decl(
            "Bar",
            [("a", required(deep_record_type(max_rec_depth + 1)))],
        )]);
        assert_matches!(
            bad_schema.check_for_encode(),
            Err(EncodeError::MaxDepthExceeded)
        );
    }

    #[test]
    fn encode_schema_tag_type_deep_fails() {
        // Tags start at depth 1 (no AttributeType wrapper), so Set nesting
        // exceeds at 1 + n > MAX_ENCODE_DEPTH → n > MAX_ENCODE_DEPTH - 1.
        let bad_tag = deep_set_type(MAX_ENCODE_DEPTH);
        let decl = entity_decl_full("Foo", [], [], Some(bad_tag));
        let s = schema([decl]);
        assert_matches!(s.check_for_encode(), Err(EncodeError::MaxDepthExceeded));
    }

    #[test]
    fn encode_schema_action_context_deep_fails() {
        let deep_ty = deep_set_type(MAX_ENCODE_DEPTH);
        let action = action_decl(
            ("Action", "read"),
            ["User"],
            ["Doc"],
            [("deep_ctx", required(deep_ty))],
        );
        let s = schema_full([], [action]);
        assert_matches!(s.check_for_encode(), Err(EncodeError::MaxDepthExceeded));
    }

    #[test]
    fn encode_schema_shallow_type_succeeds() {
        let (schema, _) =
            crate::Schema::from_cedarschema_str("entity User { name: String, age: Long };")
                .expect("parse schema");
        assert!(schema.encode().is_ok());
    }

    // ================================================================
    // Roundtrip test (encode at limit → decode succeeds)
    // ================================================================

    #[test]
    fn encode_shallow_expression_succeeds() {
        let expression = crate::Expression::from_str("1 + 2").expect("parse");
        assert!(expression.encode().is_ok());
    }

    #[test]
    fn encode_at_limit_roundtrips_through_prost() {
        let expr = deep_unary(MAX_NESTING);
        assert!(expr.check_for_encode().is_ok());
        // Encode via the API and decode to confirm prost doesn't reject it.
        let mut e = ast::Expr::val(true);
        for _ in 0..MAX_NESTING {
            e = ast::Expr::not(e);
        }
        let expression = crate::Expression(e);
        let buf = expression.encode().expect("should encode within limit");
        Expression::decode(&buf[..]).expect("should decode within prost's recursion limit");
    }
}
