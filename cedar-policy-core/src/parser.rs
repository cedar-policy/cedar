/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

//! This module contains the parser for the Cedar language.

/// Concrete Syntax Tree def used as parser first pass
pub mod cst;
/// Step two: convert CST to package AST
mod cst_to_ast;
/// error handling utilities
pub mod err;
/// implementations for formatting, like `Display`
mod fmt;
/// Metadata wrapper for CST Nodes
mod node;
pub use node::{ASTNode, SourceInfo};
/// Step one: Convert text to CST
pub mod text_to_cst;
/// Utility functions to unescape string literals
pub(crate) mod unescape;

use smol_str::SmolStr;
use std::collections::HashMap;

use crate::ast;
use crate::ast::RestrictedExprParseError;
use crate::est;

/// simple main function for parsing policies
/// generates numbered ids
pub fn parse_policyset(text: &str) -> Result<ast::PolicySet, err::ParseErrors> {
    let mut errs = err::ParseErrors::new();
    let cst = text_to_cst::parse_policies(text)?;
    let Some(ast) = cst.to_policyset(&mut errs) else {
        return Err(errs);
    };
    if errs.is_empty() {
        Ok(ast)
    } else {
        Err(errs)
    }
}

/// Like `parse_policyset()`, but also returns the (lossless) original text of
/// each individual policy.
/// INVARIANT: The `PolicyId` of every `Policy` and `Template` returned by the
/// `policies()` and `templates()` methods on the returned `Policy` _must_
/// appear as a key in the returned map.
pub fn parse_policyset_and_also_return_policy_text(
    text: &str,
) -> Result<(HashMap<ast::PolicyID, &str>, ast::PolicySet), err::ParseErrors> {
    let mut errs = err::ParseErrors::new();
    let cst = text_to_cst::parse_policies(text)?;
    let Some(pset) = cst.to_policyset(&mut errs) else {
        return Err(errs);
    };
    if errs.is_empty() {
        // PANIC SAFETY Shouldn't be `none` since `parse_policies()` and `to_policyset()` didn't return `Err`
        #[allow(clippy::expect_used)]
        // PANIC SAFETY Indexing is safe because of how `SourceInfo` is constructed
        #[allow(clippy::indexing_slicing)]
        // The `PolicyID` keys for `texts` are generated by
        // `cst.with_generated_policyids()`. This is the same method used to
        // generate the ids for policies and templates in `cst.to_policyset()`,
        // so every static policy and template in the policy set will have its
        // `PolicyId` present as a key in this map.
        let texts = cst
            .with_generated_policyids()
            .expect("shouldn't be None since parse_policies() and to_policyset() didn't return Err")
            .map(|(id, policy)| (id, &text[policy.info.0.clone()]))
            .collect::<HashMap<ast::PolicyID, &str>>();
        Ok((texts, pset))
    } else {
        Err(errs)
    }
}

/// Like `parse_policyset()`, but also returns the (lossless) ESTs -- that is,
/// the ESTs of the original policies without any of the lossy transforms
/// involved in converting to AST.
pub fn parse_policyset_to_ests_and_pset(
    text: &str,
) -> Result<(HashMap<ast::PolicyID, est::Policy>, ast::PolicySet), err::ParseErrors> {
    let mut errs = err::ParseErrors::new();
    let cst = text_to_cst::parse_policies(text)?;
    let Some(pset) = cst.to_policyset(&mut errs) else {
        return Err(errs);
    };
    if errs.is_empty() {
        // PANIC SAFETY Shouldn't be `None` since `parse_policies()` and `to_policyset()` didn't return `Err`
        #[allow(clippy::expect_used)]
        let ests = cst
            .with_generated_policyids()
            .expect("missing policy set node")
            .map(|(id, policy)| {
                let p = policy.node.as_ref().expect("missing policy node").clone();
                Ok((id, p.try_into()?))
            })
            .collect::<Result<HashMap<ast::PolicyID, est::Policy>, err::ParseErrors>>()?;
        Ok((ests, pset))
    } else {
        Err(errs)
    }
}

/// Simple main function for parsing a policy template.
/// If `id` is Some, then the resulting template will have that `id`.
/// If the `id` is None, the parser will use "policy0".
pub fn parse_policy_template(
    id: Option<String>,
    text: &str,
) -> Result<ast::Template, err::ParseErrors> {
    let mut errs = err::ParseErrors::new();
    let id = match id {
        Some(id) => ast::PolicyID::from_string(id),
        None => ast::PolicyID::from_string("policy0"),
    };
    let cst = text_to_cst::parse_policy(text)?;
    let Some(ast) = cst.to_policy_template(id, &mut errs) else {
        return Err(errs);
    };
    if errs.is_empty() {
        Ok(ast)
    } else {
        Err(errs)
    }
}

/// Like `parse_policy_template()`, but also returns the (lossless) EST -- that
/// is, the EST of the original template without any of the lossy transforms
/// involved in converting to AST.
pub fn parse_policy_template_to_est_and_ast(
    id: Option<String>,
    text: &str,
) -> Result<(est::Policy, ast::Template), err::ParseErrors> {
    let mut errs = err::ParseErrors::new();
    let id = match id {
        Some(id) => ast::PolicyID::from_string(id),
        None => ast::PolicyID::from_string("policy0"),
    };
    let cst = text_to_cst::parse_policy(text)?;
    let (Some(ast), Some(cst_node)) = (cst.to_policy_template(id, &mut errs), cst.node) else {
        return Err(errs);
    };
    if errs.is_empty() {
        let est = cst_node.try_into()?;
        Ok((est, ast))
    } else {
        Err(errs)
    }
}

/// simple main function for parsing a policy.
/// If `id` is Some, then the resulting policy will have that `id`.
/// If the `id` is None, the parser will use "policy0".
pub fn parse_policy(id: Option<String>, text: &str) -> Result<ast::StaticPolicy, err::ParseErrors> {
    let mut errs = err::ParseErrors::new();
    let id = match id {
        Some(id) => ast::PolicyID::from_string(id),
        None => ast::PolicyID::from_string("policy0"),
    };
    let cst = text_to_cst::parse_policy(text)?;
    let Some(ast) = cst.to_policy(id, &mut errs) else {
        return Err(errs);
    };
    if errs.is_empty() {
        Ok(ast)
    } else {
        Err(errs)
    }
}

/// Like `parse_policy()`, but also returns the (lossless) EST -- that is, the
/// EST of the original policy without any of the lossy transforms involved in
/// converting to AST.
pub fn parse_policy_to_est_and_ast(
    id: Option<String>,
    text: &str,
) -> Result<(est::Policy, ast::StaticPolicy), err::ParseErrors> {
    let mut errs = err::ParseErrors::new();
    let id = match id {
        Some(id) => ast::PolicyID::from_string(id),
        None => ast::PolicyID::from_string("policy0"),
    };
    let cst = text_to_cst::parse_policy(text)?;
    let (Some(ast), Some(cst_node)) = (cst.to_policy(id, &mut errs), cst.node) else {
        return Err(errs);
    };
    if errs.is_empty() {
        let est = cst_node.try_into()?;
        Ok((est, ast))
    } else {
        Err(errs)
    }
}

/// Parse a policy or template (either one works) to its EST representation
pub fn parse_policy_or_template_to_est(text: &str) -> Result<est::Policy, err::ParseErrors> {
    let cst = text_to_cst::parse_policy(text)?;
    // PANIC SAFETY Shouldn't be `none` since `parse_policy()` didn't return `Err`
    #[allow(clippy::expect_used)]
    let cst_node = cst.node.expect("missing policy or template node");
    cst_node.try_into()
}

/// parse an Expr
///
/// Private to this crate. Users outside Core should use `Expr`'s `FromStr` impl
/// or its constructors
pub(crate) fn parse_expr(ptext: &str) -> Result<ast::Expr, err::ParseErrors> {
    let mut errs = err::ParseErrors::new();
    let cst = text_to_cst::parse_expr(ptext)?;
    let Some(ast) = cst.to_expr(&mut errs) else {
        return Err(errs);
    };
    if errs.is_empty() {
        Ok(ast)
    } else {
        Err(errs)
    }
}

/// parse a RestrictedExpr
///
/// Private to this crate. Users outside Core should use `RestrictedExpr`'s
/// `FromStr` impl or its constructors
pub(crate) fn parse_restrictedexpr(
    ptext: &str,
) -> Result<ast::RestrictedExpr, RestrictedExprParseError> {
    let expr = parse_expr(ptext)?;
    Ok(ast::RestrictedExpr::new(expr)?)
}

/// parse an EntityUID
///
/// Private to this crate. Users outside Core should use `EntityUID`'s `FromStr`
/// impl or its constructors
pub(crate) fn parse_euid(euid: &str) -> Result<ast::EntityUID, err::ParseErrors> {
    let mut errs = err::ParseErrors::new();
    let cst = text_to_cst::parse_ref(euid)?;
    let Some(ast) = cst.to_ref(&mut errs) else {
        return Err(errs);
    };
    if errs.is_empty() {
        Ok(ast)
    } else {
        Err(errs)
    }
}

/// parse a Name
///
/// Private to this crate. Users outside Core should use `Name`'s `FromStr` impl
/// or its constructors
pub(crate) fn parse_name(name: &str) -> Result<ast::Name, err::ParseErrors> {
    let mut errs = err::ParseErrors::new();
    let cst = text_to_cst::parse_name(name)?;
    let Some(ast) = cst.to_name(&mut errs) else {
        return Err(errs);
    };
    if errs.is_empty() {
        Ok(ast)
    } else {
        Err(errs)
    }
}

/// parse a string into an ast::Literal (does not support expressions)
///
/// Private to this crate. Users outside Core should use `Literal`'s `FromStr` impl
/// or its constructors
pub(crate) fn parse_literal(val: &str) -> Result<ast::Literal, err::ParseErrors> {
    let mut errs = err::ParseErrors::new();
    let cst = text_to_cst::parse_primary(val)?;
    let Some(ast) = cst.to_expr(&mut errs) else {
        return Err(errs);
    };
    if errs.is_empty() {
        match ast.into_expr_kind() {
            ast::ExprKind::Lit(v) => Ok(v),
            _ => Err(
                err::ParseError::ParseLiteral(err::ParseLiteralError::ParseLiteral(
                    val.to_string(),
                ))
                .into(),
            ),
        }
    } else {
        Err(errs)
    }
}

/// parse a string into an internal Cedar string
///
/// This performs unescaping and validation, returning
/// a String suitable for an attr, eid, or literal.
///
/// Quote handling is as if the input is surrounded by
/// double quotes ("{val}").
///
/// It does not return a string suitable for a pattern. Use the
/// full expression parser for those.
pub fn parse_internal_string(val: &str) -> Result<SmolStr, err::ParseErrors> {
    let mut errs = err::ParseErrors::new();
    // we need to add quotes for this to be a valid string literal
    let cst = text_to_cst::parse_primary(&format!(r#""{val}""#))?;
    let Some(ast) = cst.to_string_literal(&mut errs) else {
        return Err(errs);
    };
    if errs.is_empty() {
        Ok(ast)
    } else {
        Err(errs)
    }
}

/// parse an identifier
///
/// Private to this crate. Users outside Core should use `Id`'s `FromStr` impl
/// or its constructors
pub(crate) fn parse_ident(id: &str) -> Result<ast::Id, err::ParseErrors> {
    let mut errs = err::ParseErrors::new();
    let cst = text_to_cst::parse_ident(id)?;
    let Some(ast) = cst.to_valid_ident(&mut errs) else {
        return Err(errs);
    };
    if errs.is_empty() {
        Ok(ast)
    } else {
        Err(errs)
    }
}

/// Utilities used in tests in this file
#[cfg(test)]
mod test_utils {
    use super::err::ParseErrors;
    use miette::Diagnostic;

    pub struct ExpectedErrorMessage<'a> {
        /// Expected contents of `Display`
        error: &'a str,
        /// Expected contents of `help()`, or `None` if no help
        help: Option<&'a str>,
    }

    impl<'a> ExpectedErrorMessage<'a> {
        /// Expect the given error message and no help text.
        pub fn error(msg: &'a str) -> Self {
            Self {
                error: msg,
                help: None,
            }
        }

        /// Expect the given error message and help text.
        pub fn error_and_help(error: &'a str, help: &'a str) -> Self {
            Self {
                error,
                help: Some(help),
            }
        }
    }

    /// Expect that the given `err` is an error with the given `ExpectedErrorMessage`.
    ///
    /// `src` is the original input text, just for better assertion-failure messages
    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    pub fn expect_err(src: &str, err: &impl miette::Diagnostic, msg: &ExpectedErrorMessage<'_>) {
        assert_eq!(
            &err.to_string(),
            msg.error,
            "for the following input:\n{src}\nactual error was {err}"
        );
        let help = err.help().map(|h| h.to_string());
        assert_eq!(
            help.as_deref(),
            msg.help,
            "for the following input:\n{src}\nactual help was {help:?}"
        );
    }

    /// Expect that the given `ParseErrors` contains at least one error with the given `ExpectedErrorMessage`.
    ///
    /// `src` is the original input text, just for better assertion-failure messages
    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    pub fn expect_some_error_matches(
        src: &str,
        errs: &ParseErrors,
        msg: &ExpectedErrorMessage<'_>,
    ) {
        assert!(
            errs.iter().any(|e| {
                &e.to_string() == msg.error
                    && e.help().map(|h| h.to_string()).as_deref() == msg.help
            }),
            "for the following input:\n{src}\nactual errors were:\n{}",
            errs.pretty_with_helps(),
        );
    }
}

// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
#[cfg(test)]
mod test {
    use super::*;
    use crate::ast::{test_generators::*, Template};
    use std::collections::HashSet;

    #[test]
    fn test_template_parsing() {
        for template in all_templates().map(Template::from) {
            let id = template.id();
            let src = format!("{template}");
            let parsed = parse_policy_template(Some(id.to_string()), &src);
            match parsed {
                Ok(p) => {
                    assert_eq!(
                        p.slots().collect::<HashSet<_>>(),
                        template.slots().collect::<HashSet<_>>()
                    );
                    assert_eq!(p.id(), template.id());
                    assert_eq!(p.effect(), template.effect());
                    assert_eq!(p.principal_constraint(), template.principal_constraint());
                    assert_eq!(p.action_constraint(), template.action_constraint());
                    assert_eq!(p.resource_constraint(), template.resource_constraint());
                    assert!(
                        p.non_head_constraints()
                            .eq_shape(template.non_head_constraints()),
                        "{:?} and {:?} should have the same shape.",
                        p.non_head_constraints(),
                        template.non_head_constraints()
                    );
                }
                Err(e) => panic!("Failed to parse {src}, {}", e.pretty_with_helps()),
            }
        }
    }

    #[test]
    fn test_error_out() {
        let errors = parse_policyset(
            r#"
            permit(principal:p,action:a,resource:r)
            when{w or if c but not z} // expr error
            unless{u if c else d or f} // expr error
            advice{"doit"};

            permit(principality in Group::"jane_friends", // policy error
            action in [PhotoOp::"view", PhotoOp::"comment"],
            resource in Album::"jane_trips");

            forbid(principal, action, resource)
            when   { "private" in resource.tags }
            unless { resource in principal.account };
        "#,
        )
        .expect_err("multiple errors above");
        println!("{}", errors.pretty_with_helps());
        assert!(errors.len() >= 3);
    }
}

#[cfg(test)]
mod eval_tests {
    use super::err::{ParseErrors, ToASTErrorKind};
    use super::*;
    use crate::evaluator as eval;
    use crate::extensions::Extensions;
    use crate::parser::err::ParseError;

    #[test]
    fn entity_literals1() {
        let src = r#"Test::{ test : "Test" }"#;
        let ParseErrors(errs) = parse_euid(src).err().unwrap();
        assert_eq!(errs.len(), 1);
        let expected = ToASTErrorKind::UnsupportedEntityLiterals;
        assert!(errs
            .iter()
            .any(|e| matches!(e, ParseError::ToAST(e) if e.kind() == &expected)));
    }

    #[test]
    fn entity_literals2() {
        let src = r#"permit(principal == Test::{ test : "Test" }, action, resource);"#;
        let ParseErrors(errs) = parse_policy(None, src).err().unwrap();
        assert_eq!(errs.len(), 1);
        let expected = ToASTErrorKind::UnsupportedEntityLiterals;
        assert!(errs
            .iter()
            .any(|e| matches!(e, ParseError::ToAST(e) if e.kind() == &expected)));
    }

    #[test]
    fn interpret_exprs() {
        let request = eval::test::basic_request();
        let entities = eval::test::basic_entities();
        let exts = Extensions::none();
        let evaluator = eval::Evaluator::new(request, &entities, &exts);

        // bools
        let expr = parse_expr("false").expect("parse fail");
        assert_eq!(
            evaluator
                .interpret_inline_policy(&expr)
                .expect("interpret fail"),
            ast::Value::Lit(ast::Literal::Bool(false))
        );
        let expr = parse_expr("true && true").expect("parse fail");
        assert_eq!(
            evaluator
                .interpret_inline_policy(&expr)
                .expect("interpret fail"),
            ast::Value::Lit(ast::Literal::Bool(true))
        );
        let expr = parse_expr("!true || false && !true").expect("parse fail");
        assert_eq!(
            evaluator
                .interpret_inline_policy(&expr)
                .expect("interpret fail"),
            ast::Value::Lit(ast::Literal::Bool(false))
        );
        let expr = parse_expr("!!!!true").expect("parse fail");
        assert_eq!(
            evaluator
                .interpret_inline_policy(&expr)
                .expect("interpret fail"),
            ast::Value::Lit(ast::Literal::Bool(true))
        );

        let expr = parse_expr(
            r#"
        if false || true != 4 then
            600
        else
            -200
        "#,
        )
        .expect("parse fail");
        assert_eq!(
            evaluator
                .interpret_inline_policy(&expr)
                .expect("interpret fail"),
            ast::Value::Lit(ast::Literal::Long(600))
        );
    }

    #[test]
    fn interpret_membership() {
        let request = eval::test::basic_request();
        let entities = eval::test::rich_entities();
        let exts = Extensions::none();
        let evaluator = eval::Evaluator::new(request, &entities, &exts);

        let expr = parse_expr(
            r#"

        test_entity_type::"child" in
            test_entity_type::"unrelated"

        "#,
        )
        .expect("parse fail");
        assert_eq!(
            evaluator
                .interpret_inline_policy(&expr)
                .expect("interpret fail"),
            ast::Value::Lit(ast::Literal::Bool(false))
        );
        let expr = parse_expr(
            r#"

        test_entity_type::"child" in
            test_entity_type::"child"

        "#,
        )
        .expect("parse fail");
        assert_eq!(
            evaluator
                .interpret_inline_policy(&expr)
                .expect("interpret fail"),
            ast::Value::Lit(ast::Literal::Bool(true))
        );
        let expr = parse_expr(
            r#"

        other_type::"other_child" in
            test_entity_type::"parent"

        "#,
        )
        .expect("parse fail");
        assert_eq!(
            evaluator
                .interpret_inline_policy(&expr)
                .expect("interpret fail"),
            ast::Value::Lit(ast::Literal::Bool(true))
        );
        let expr = parse_expr(
            r#"

        test_entity_type::"child" in
            test_entity_type::"grandparent"

        "#,
        )
        .expect("parse fail");
        assert_eq!(
            evaluator
                .interpret_inline_policy(&expr)
                .expect("interpret fail"),
            ast::Value::Lit(ast::Literal::Bool(true))
        );
    }

    #[test]
    fn interpret_relation() {
        let request = eval::test::basic_request();
        let entities = eval::test::basic_entities();
        let exts = Extensions::none();
        let evaluator = eval::Evaluator::new(request, &entities, &exts);

        let expr = parse_expr(
            r#"

            3 < 2 || 2 > 3

        "#,
        )
        .expect("parse fail");
        assert_eq!(
            evaluator
                .interpret_inline_policy(&expr)
                .expect("interpret fail"),
            ast::Value::Lit(ast::Literal::Bool(false))
        );
        let expr = parse_expr(
            r#"

            7 <= 7 && 4 != 5

        "#,
        )
        .expect("parse fail");
        assert_eq!(
            evaluator
                .interpret_inline_policy(&expr)
                .expect("interpret fail"),
            ast::Value::Lit(ast::Literal::Bool(true))
        );
    }
}

#[cfg(test)]
mod parse_tests {
    use super::test_utils::*;
    use super::*;
    use cool_asserts::assert_matches;

    #[test]
    fn parse_exists() {
        let result = parse_policyset(
            r#"
            permit(principal, action, resource)
            when{ true };
        "#,
        );
        assert!(!result.expect("parse error").is_empty());
    }

    #[test]
    fn test_parse_policyset() {
        use crate::ast::PolicyID;
        let multiple_policies = r#"
            permit(principal, action, resource)
            when { principal == resource.owner };

            forbid(principal, action == Action::"modify", resource) // a comment
            when { resource . highSecurity }; // intentionally not conforming to our formatter
        "#;
        let pset = parse_policyset(multiple_policies).expect("Should parse");
        assert_eq!(pset.policies().count(), 2);
        assert_eq!(pset.static_policies().count(), 2);
        let (texts, pset) =
            parse_policyset_and_also_return_policy_text(multiple_policies).expect("Should parse");
        assert_eq!(pset.policies().count(), 2);
        assert_eq!(pset.static_policies().count(), 2);
        assert_eq!(texts.len(), 2);
        assert_eq!(
            texts.get(&PolicyID::from_string("policy0")),
            Some(
                &r#"permit(principal, action, resource)
            when { principal == resource.owner };"#
            )
        );
        assert_eq!(
            texts.get(&PolicyID::from_string("policy1")),
            Some(
                &r#"forbid(principal, action == Action::"modify", resource) // a comment
            when { resource . highSecurity };"#
            )
        );
    }

    #[test]
    fn test_parse_string() {
        // test idempotence
        assert_eq!(
            ast::Eid::new(parse_internal_string(r"a\nblock\nid").expect("should parse"))
                .to_string(),
            r"a\nblock\nid",
        );
        parse_internal_string(r#"oh, no, a '! "#).expect("single quote should be fine");
        parse_internal_string(r#"oh, no, a "! "#).expect_err("double quote not allowed");
        parse_internal_string(r#"oh, no, a \"! and a \'! "#).expect("escaped quotes should parse");
    }

    #[test]
    fn good_cst_bad_ast() {
        let src = r#"
            permit(principal, action, resource) when { principal.name.like == "3" };
            "#;
        let p = parse_policyset_to_ests_and_pset(src);
        assert_matches!(p, Err(e) => expect_err(src, &e, &ExpectedErrorMessage::error("this identifier is reserved and cannot be used: `like`")));
    }

    #[test]
    fn no_slots_in_condition() {
        let src = r#"
            permit(principal, action, resource) when {
                resource == ?resource
            };
            "#;
        let slot_in_when_clause = ExpectedErrorMessage::error_and_help(
            "found template slot ?resource in a `when` clause",
            "slots are currently unsupported in `when` clauses",
        );
        let unexpected_template = ExpectedErrorMessage::error_and_help(
            "expected a static policy, got a template containing the slot ?resource",
            "try removing the template slot(s) from this policy",
        );
        assert_matches!(parse_policy(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
            expect_some_error_matches(src, &e, &unexpected_template);
        });
        assert_matches!(parse_policy_template(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
        });
        assert_matches!(parse_policy_to_est_and_ast(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
            expect_some_error_matches(src, &e, &unexpected_template);
        });
        assert_matches!(parse_policy_template_to_est_and_ast(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
        });
        assert_matches!(parse_policyset(src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
        });
        assert_matches!(parse_policyset_to_ests_and_pset(src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
        });

        let src = r#"
            permit(principal, action, resource) when {
                resource == ?principal
            };
            "#;
        let slot_in_when_clause = ExpectedErrorMessage::error_and_help(
            "found template slot ?principal in a `when` clause",
            "slots are currently unsupported in `when` clauses",
        );
        let unexpected_template = ExpectedErrorMessage::error_and_help(
            "expected a static policy, got a template containing the slot ?principal",
            "try removing the template slot(s) from this policy",
        );
        assert_matches!(parse_policy(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
            expect_some_error_matches(src, &e, &unexpected_template);
        });
        assert_matches!(parse_policy_template(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
        });
        assert_matches!(parse_policy_to_est_and_ast(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
            expect_some_error_matches(src, &e, &unexpected_template);
        });
        assert_matches!(parse_policy_template_to_est_and_ast(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
        });
        assert_matches!(parse_policyset(src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
        });
        assert_matches!(parse_policyset_to_ests_and_pset(src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
        });

        let src = r#"
            permit(principal, action, resource) when {
                resource == ?blah
            };
            "#;
        // TODO(#451): improve these errors
        let error = ExpectedErrorMessage::error("invalid token");
        assert_matches!(parse_policy(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &error);
        });
        assert_matches!(parse_policy_template(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &error);
        });
        assert_matches!(parse_policy_to_est_and_ast(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &error);
        });
        assert_matches!(parse_policy_template_to_est_and_ast(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &error);
        });
        assert_matches!(parse_policyset(src), Err(e) => {
            expect_some_error_matches(src, &e, &error);
        });
        assert_matches!(parse_policyset_to_ests_and_pset(src), Err(e) => {
            expect_some_error_matches(src, &e, &error);
        });

        let src = r#"
            permit(principal, action, resource) unless {
                resource == ?resource
            };
            "#;
        let slot_in_unless_clause = ExpectedErrorMessage::error_and_help(
            "found template slot ?resource in a `unless` clause",
            "slots are currently unsupported in `unless` clauses",
        );
        let unexpected_template = ExpectedErrorMessage::error_and_help(
            "expected a static policy, got a template containing the slot ?resource",
            "try removing the template slot(s) from this policy",
        );
        assert_matches!(parse_policy(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
            expect_some_error_matches(src, &e, &unexpected_template);
        });
        assert_matches!(parse_policy_template(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
        });
        assert_matches!(parse_policy_to_est_and_ast(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
            expect_some_error_matches(src, &e, &unexpected_template);
        });
        assert_matches!(parse_policy_template_to_est_and_ast(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
        });
        assert_matches!(parse_policyset(src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
        });
        assert_matches!(parse_policyset_to_ests_and_pset(src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
        });

        let src = r#"
            permit(principal, action, resource) unless {
                resource == ?principal
            };
            "#;
        let slot_in_unless_clause = ExpectedErrorMessage::error_and_help(
            "found template slot ?principal in a `unless` clause",
            "slots are currently unsupported in `unless` clauses",
        );
        let unexpected_template = ExpectedErrorMessage::error_and_help(
            "expected a static policy, got a template containing the slot ?principal",
            "try removing the template slot(s) from this policy",
        );
        assert_matches!(parse_policy(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
            expect_some_error_matches(src, &e, &unexpected_template);
        });
        assert_matches!(parse_policy_template(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
        });
        assert_matches!(parse_policy_to_est_and_ast(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
            expect_some_error_matches(src, &e, &unexpected_template);
        });
        assert_matches!(parse_policy_template_to_est_and_ast(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
        });
        assert_matches!(parse_policyset(src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
        });
        assert_matches!(parse_policyset_to_ests_and_pset(src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
        });

        let src = r#"
            permit(principal, action, resource) unless {
                resource == ?blah
            };
            "#;
        // TODO(#451): improve these errors
        let error = ExpectedErrorMessage::error("invalid token");
        assert_matches!(parse_policy(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &error);
        });
        assert_matches!(parse_policy_template(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &error);
        });
        assert_matches!(parse_policy_to_est_and_ast(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &error);
        });
        assert_matches!(parse_policy_template_to_est_and_ast(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &error);
        });
        assert_matches!(parse_policyset(src), Err(e) => {
            expect_some_error_matches(src, &e, &error);
        });
        assert_matches!(parse_policyset_to_ests_and_pset(src), Err(e) => {
            expect_some_error_matches(src, &e, &error);
        });

        let src = r#"
            permit(principal, action, resource) unless {
                resource == ?resource
            } when {
                resource == ?resource
            };
            "#;
        let slot_in_when_clause = ExpectedErrorMessage::error_and_help(
            "found template slot ?resource in a `when` clause",
            "slots are currently unsupported in `when` clauses",
        );
        let slot_in_unless_clause = ExpectedErrorMessage::error_and_help(
            "found template slot ?resource in a `unless` clause",
            "slots are currently unsupported in `unless` clauses",
        );
        let unexpected_template = ExpectedErrorMessage::error_and_help(
            "expected a static policy, got a template containing the slot ?resource",
            "try removing the template slot(s) from this policy",
        );
        assert_matches!(parse_policy(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
            expect_some_error_matches(src, &e, &unexpected_template);
        });
        assert_matches!(parse_policy_template(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
        });
        assert_matches!(parse_policy_to_est_and_ast(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
            expect_some_error_matches(src, &e, &unexpected_template);
        });
        assert_matches!(parse_policy_template_to_est_and_ast(None, src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
        });
        assert_matches!(parse_policyset(src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
        });
        assert_matches!(parse_policyset_to_ests_and_pset(src), Err(e) => {
            expect_some_error_matches(src, &e, &slot_in_when_clause);
            expect_some_error_matches(src, &e, &slot_in_unless_clause);
        });
    }

    #[test]
    fn record_literals() {
        // unquoted keys
        let src = r#"permit(principal, action, resource) when { context.foo == { foo: 2, bar: "baz" } };"#;
        assert_matches!(parse_policy(None, src), Ok(_));
        // quoted keys
        let src = r#"permit(principal, action, resource) when { context.foo == { "foo": 2, "hi mom it's 🦀": "baz" } };"#;
        assert_matches!(parse_policy(None, src), Ok(_));
        // duplicate key
        let src = r#"permit(principal, action, resource) when { context.foo == { "spam": -341, foo: 2, "🦀": true, foo: "baz" } };"#;
        assert_matches!(parse_policy(None, src), Err(e) => {
            assert_eq!(e.len(), 1);
            expect_some_error_matches(src, &e, &ExpectedErrorMessage::error("duplicate key `foo` in record literal"));
        });
    }
}
