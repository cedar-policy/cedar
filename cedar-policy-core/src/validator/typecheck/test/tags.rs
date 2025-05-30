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

use super::test_utils::{
    assert_exactly_one_diagnostic, assert_policy_typecheck_fails,
    assert_policy_typecheck_fails_for_mode, assert_policy_typecheck_warns,
    assert_policy_typechecks, assert_policy_typechecks_for_mode,
};
use crate::validator::ValidationMode;
use crate::{
    ast::PolicyID,
    parser::parse_policy,
    test_utils::{expect_err, ExpectedErrorMessageBuilder},
};
use cool_asserts::assert_matches;
use itertools::Itertools;

fn schema_with_tags() -> &'static str {
    r#"
        entity E tags String;
        entity F { foo: String, opt?: String } tags Set<String>;
        entity Blank;
        action A1 appliesTo {
            principal: [E],
            resource: [F],
            context: { bool: Bool },
        };
        action A2 appliesTo {
            principal: [F],
            resource: [E],
            context: { bool: Bool },
        };
        action A3 appliesTo {
            principal: [E, F],
            resource: [E, F],
            context: { bool: Bool },
        };
        action A4 appliesTo {
            principal: [E],
            resource: [Blank],
            context: { bool: Bool },
        };
    "#
}

#[test]
fn tag_access_success() {
    // constant-keys case
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

    // computed-keys case
    let policy = parse_policy(
        Some(PolicyID::from_string("0")),
        r#"
        permit(principal, action == Action::"A1", resource) when {
            principal.hasTag(resource.foo) && principal.getTag(resource.foo) == "foo"
        };
        "#,
    )
    .unwrap();
    assert_policy_typechecks(schema_with_tags(), policy);
}

#[test]
fn tag_access_missing_has_check() {
    // constant-keys case
    let src = r#"
        permit(principal, action == Action::"A1", resource) when {
            principal.getTag("foo") == "foo"
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    let errors = assert_policy_typecheck_fails(schema_with_tags(), policy);
    let error = assert_exactly_one_diagnostic(errors);
    expect_err(
        src,
        &miette::Report::new(error),
        &ExpectedErrorMessageBuilder::error(r#"for policy `0`, unable to guarantee safety of access to tag `"foo"` on entity type `E`"#)
            .help(r#"try testing for the tag's presence with `.hasTag("foo") && ..`"#)
            .exactly_one_underline(r#"principal.getTag("foo")"#)
            .build(),
    );

    // computed-keys case
    let src = r#"
        permit(principal, action == Action::"A1", resource) when {
            principal.getTag(resource.foo) == "foo"
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    let errors = assert_policy_typecheck_fails(schema_with_tags(), policy);
    let error = assert_exactly_one_diagnostic(errors);
    expect_err(
        src,
        &miette::Report::new(error),
        &ExpectedErrorMessageBuilder::error(r#"for policy `0`, unable to guarantee safety of access to tag `resource["foo"]` on entity type `E`"#)
            .help(r#"try testing for the tag's presence with `.hasTag(resource["foo"]) && ..`"#)
            .exactly_one_underline(r#"principal.getTag(resource.foo)"#)
            .build(),
    );
}

#[test]
fn tag_access_type_error() {
    // constant-keys case
    let src = r#"
        permit(principal, action == Action::"A1", resource) when {
            principal.hasTag("foo") && principal.getTag("foo").contains("bar")
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    let errors = assert_policy_typecheck_fails(schema_with_tags(), policy);
    let error = assert_exactly_one_diagnostic(errors);
    expect_err(
        src,
        &miette::Report::new(error),
        &ExpectedErrorMessageBuilder::error(r#"for policy `0`, unexpected type: expected Set<__cedar::internal::Any> but saw String"#)
            .help("try using `like` to examine the contents of a string")
            .exactly_one_underline(r#"principal.getTag("foo").contains("bar")"#)
            .build(),
    );

    // computed-keys case
    let src = r#"
        permit(principal, action == Action::"A1", resource) when {
            principal.hasTag(resource.foo) && principal.getTag(resource.foo).contains("bar")
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    let errors = assert_policy_typecheck_fails(schema_with_tags(), policy);
    let error = assert_exactly_one_diagnostic(errors);
    expect_err(
        src,
        &miette::Report::new(error),
        &ExpectedErrorMessageBuilder::error(r#"for policy `0`, unexpected type: expected Set<__cedar::internal::Any> but saw String"#)
            .help("try using `like` to examine the contents of a string")
            .exactly_one_underline(r#"principal.getTag(resource.foo).contains("bar")"#)
            .build(),
    );

    // works for one principal type this action applies to, but not for all
    let src = r#"
        permit(principal, action == Action::"A3", resource) when {
            principal.hasTag("foo") && principal.getTag("foo") == "bar"
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    let errors = assert_policy_typecheck_fails(schema_with_tags(), policy);
    let error = assert_exactly_one_diagnostic(errors);
    expect_err(
        src,
        &miette::Report::new(error),
        &ExpectedErrorMessageBuilder::error(r#"the types String and Set<String> are not compatible"#)
            .help("for policy `0`, both operands to a `==` expression must have compatible types. Types must be exactly equal to be compatible")
            .exactly_one_underline(r#"principal.getTag("foo") == "bar""#)
            .build(),
    );

    // works for one action this policy applies to, but not for all
    let src = r#"
        permit(principal, action in [Action::"A1", Action::"A2"], resource) when {
            principal.hasTag("foo") && principal.getTag("foo") == "bar"
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    let errors = assert_policy_typecheck_fails(schema_with_tags(), policy);
    let error = assert_exactly_one_diagnostic(errors);
    expect_err(
        src,
        &miette::Report::new(error),
        &ExpectedErrorMessageBuilder::error(r#"the types String and Set<String> are not compatible"#)
            .help("for policy `0`, both operands to a `==` expression must have compatible types. Types must be exactly equal to be compatible")
            .exactly_one_underline(r#"principal.getTag("foo") == "bar""#)
            .build(),
    );
}

#[test]
fn no_tags_allowed() {
    // .hasTag() on an entity with no tags is allowed
    let src = r#"
        permit(principal, action == Action::"A4", resource) when {
            resource.hasTag("foo")
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    assert_policy_typechecks(schema_with_tags(), policy);

    // .getTag() on an entity with no tags is not allowed
    let src = r#"
        permit(principal, action == Action::"A4", resource) when {
            resource.getTag("foo") == "bar"
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    let errors = assert_policy_typecheck_fails(schema_with_tags(), policy);
    let error = assert_exactly_one_diagnostic(errors);
    expect_err(
        src,
        &miette::Report::new(error),
        &ExpectedErrorMessageBuilder::error(r#"for policy `0`, unable to guarantee safety of access to tag `"foo"` on entity type `Blank`"#)
            .help(r#"try testing for the tag's presence with `.hasTag("foo") && ..`"#)
            .exactly_one_underline(r#"resource.getTag("foo")"#)
            .build(),
    );

    // .getTag() on an entity with no tags _is_ allowed if guarded by an
    // appropriate `.hasTag()` check, because of short-circuiting
    let src = r#"
        permit(principal, action == Action::"A4", resource) when {
            resource.hasTag("foo") && resource.getTag("foo") == "bar"
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    assert_policy_typechecks(schema_with_tags(), policy);
}

/// having a capability for attribute "foo" doesn't let you access tag "foo", and vice versa
#[test]
fn mixed_tags_and_attrs() {
    // have attr capability, try to access tag
    let src = r#"
        permit(principal, action == Action::"A1", resource) when {
            resource has opt && resource.getTag("opt").contains("foo")
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    let errors = assert_policy_typecheck_fails(schema_with_tags(), policy);
    let error = assert_exactly_one_diagnostic(errors);
    expect_err(
        src,
        &miette::Report::new(error),
        &ExpectedErrorMessageBuilder::error(r#"for policy `0`, unable to guarantee safety of access to tag `"opt"` on entity type `F`"#)
            .help(r#"try testing for the tag's presence with `.hasTag("opt") && ..`"#)
            .exactly_one_underline(r#"resource.getTag("opt").contains("foo")"#) // why does the `.contains("foo")` part get underlined?
            .build(),
    );

    // have tag capability, try to access attr
    let src = r#"
        permit(principal, action == Action::"A1", resource) when {
            resource.hasTag("opt") && resource.opt == "foo"
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    let errors = assert_policy_typecheck_fails(schema_with_tags(), policy);
    let error = assert_exactly_one_diagnostic(errors);
    expect_err(
        src,
        &miette::Report::new(error),
        &ExpectedErrorMessageBuilder::error(r#"for policy `0`, unable to guarantee safety of access to optional attribute `opt` on entity type `F`"#)
            .help(r#"try testing for the attribute's presence with `e has opt && ..`"#)
            .exactly_one_underline("resource.opt")
            .build(),
    );

    // gaining a capability for an attr doesn't wipe out your capability for the tag
    let src = r#"
        permit(principal, action == Action::"A1", resource) when {
            resource.hasTag("opt") && resource has opt && resource.getTag("opt").contains("bar")
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    assert_policy_typechecks(schema_with_tags(), policy);

    // gaining a capability for a tag doesn't wipe out your capability for the attr
    let src = r#"
        permit(principal, action == Action::"A1", resource) when {
            resource has opt && resource.hasTag("opt") && resource.opt == "bar"
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    assert_policy_typechecks(schema_with_tags(), policy);
}

#[test]
fn tags_on_actions() {
    // hasTag on an action. This succeeds, although warns that it's always false
    let src = r#"
        permit(principal, action == Action::"A1", resource) when {
            action.hasTag("foo")
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    let warnings = assert_policy_typecheck_warns(schema_with_tags(), policy);
    let warning = assert_exactly_one_diagnostic(warnings);
    expect_err(
        src,
        &miette::Report::new(warning),
        &ExpectedErrorMessageBuilder::error("for policy `0`, policy is impossible: the policy expression evaluates to false for all valid requests")
            .exactly_one_underline(r#"permit(principal, action == Action::"A1", resource) when {
            action.hasTag("foo")
        };"#)
            .build(),
    );

    // getTag on an action. This fails
    let src = r#"
        permit(principal, action == Action::"A4", resource) when {
            action.getTag("foo") == "bar"
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    let errors = assert_policy_typecheck_fails(schema_with_tags(), policy);
    let error = assert_exactly_one_diagnostic(errors);
    expect_err(
        src,
        &miette::Report::new(error),
        &ExpectedErrorMessageBuilder::error(
            r#"for policy `0`, unable to guarantee safety of access to tag `"foo"`"#,
        )
        .help(r#"try testing for the tag's presence with `.hasTag("foo") && ..`"#)
        .exactly_one_underline(r#"action.getTag("foo")"#)
        .build(),
    );
}

#[test]
fn permissive_tags() {
    // LUB with only one valid tag type, this is fine in permissive mode
    let src = r#"
        permit(principal, action == Action::"A1", resource) when {
            (if context.bool then principal else Blank::"").hasTag("foo") &&
            (if context.bool then principal else Blank::"").getTag("foo") == "bar"
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    assert_policy_typechecks_for_mode(schema_with_tags(), policy, ValidationMode::Permissive);

    // (that policy is an error in strict mode though)
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    let errors =
        assert_policy_typecheck_fails_for_mode(schema_with_tags(), policy, ValidationMode::Strict);
    // two errors, one for each if-then-else
    assert_eq!(
        errors.len(),
        2,
        "actual errors were:\n\n{}",
        errors
            .into_iter()
            .map(|e| format!("{:?}", miette::Report::new(e)))
            .join("\n\n")
    );
    // we only check one error, because they're identical other than which if-then-else is underlined
    expect_err(
        src,
        &miette::Report::new(errors.into_iter().next().expect("already checked that len is 2")),
        &ExpectedErrorMessageBuilder::error("the types Blank and E are not compatible")
            .help("for policy `0`, both branches of a conditional must have compatible types. Different entity types are never compatible even when their attributes would be compatible")
            .exactly_one_underline(r#"if context.bool then principal else Blank::"""#)
            .build(),
    );

    // LUB with multiple valid tag types, not fine even in permissive mode
    let src = r#"
        permit(principal, action == Action::"A1", resource) when {
            (if context.bool then principal else resource).hasTag("foo") &&
            (if context.bool then principal else resource).getTag("foo") == "bar"
        };
    "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).unwrap();
    let errors = assert_policy_typecheck_fails_for_mode(
        schema_with_tags(),
        policy,
        ValidationMode::Permissive,
    );
    let error = assert_exactly_one_diagnostic(errors);
    expect_err(
        src,
        &miette::Report::new(error),
        &ExpectedErrorMessageBuilder::error("the types String and Set<String> are not compatible")
            .help("for policy `0`, tag types for a `.getTag()` operation must have compatible types. Types must be exactly equal to be compatible")
            .exactly_one_underline(r#"(if context.bool then principal else resource).getTag("foo")"#)
            .build(),
    );
}

/// Not a test of tag functionality itself, but just double-checking that
/// although tags support computed keys (as evidenced by above tests),
/// attributes do not
#[test]
fn computed_attribute_fails() {
    let src = r#"
        permit(principal, action == Action::"A1", resource) when {
            principal.hasTag("foo") && resource[principal.getTag("foo")] == "bar"
        };
    "#;
    assert_matches!(parse_policy(Some(PolicyID::from_string("0")), src), Err(e) => {
        expect_err(
            src,
            &miette::Report::new(e),
            &ExpectedErrorMessageBuilder::error(r#"invalid string literal: principal.getTag("foo")"#)
                .exactly_one_underline(r#"principal.getTag("foo")"#)
                .build()
        )
    });
}
