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

//! Contains tests for defining entity tags and typechecking their
//! access using the ability added by capabilities.
// GRCOV_STOP_COVERAGE

use std::str::FromStr;

use cedar_policy_core::{
    ast::{EntityType, Expr, ExprBuilder, PolicyID},
    parser::parse_policy,
};

use crate::{
    diagnostics::ValidationError, types::{EntityLUB, Type},
};

use super::test_utils::{assert_policy_typecheck_fails, assert_policy_typechecks, get_loc};

fn schema_with_tags() -> &'static str {
    r#"
        entity E tags String;
        entity F { foo: String } tags Set<String>;
        action A1 appliesTo {
            principal: [E],
            resource: [F],
        };
        action A2 appliesTo {
            principal: [F],
            resource: [E],
        };
        action A3 appliesTo {
            principal: [E, F],
            resource: [E, F],
        };
    "#
}

fn string_tag(tag: &str) -> Expr<Option<Type>> {
    ExprBuilder::with_data(Some(Type::primitive_string())).val(tag)
}

#[test]
fn tag_access_success() {
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"
        permit(principal, action == Action::"A1", resource) when {
            principal.hasTag("foo") && principal.getTag("foo") == "foo"
        };
        "#,
    )
    .unwrap();
    assert_policy_typechecks(schema_with_tags(), policy);
}

#[test]
fn tag_access_missing_has_check() {
    let src = r#"
        permit(principal, action == Action::"A1", resource) when {
            principal.getTag("foo") == "foo"
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    assert_policy_typecheck_fails(
        schema_with_tags(),
        policy,
        [
            ValidationError::unsafe_tag_access(
                get_loc(src, r#"principal.getTag("foo")"#),
                PolicyID::from_string("0"),
                Some(EntityLUB::single_entity(EntityType::from_str("E").unwrap())),
                string_tag("foo"),
            )
        ],
    );
}
