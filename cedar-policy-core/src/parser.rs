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
use crate::est;

/// simple main function for parsing policies
/// generates numbered ids
pub fn parse_policyset(text: &str) -> Result<ast::PolicySet, Vec<err::ParseError>> {
    let mut errs = Vec::new();
    text_to_cst::parse_policies(text)?
        .to_policyset(&mut errs)
        .ok_or(errs)
}

/// Like `parse_policyset()`, but also returns the (lossless) original text of
/// each individual policy.
pub fn parse_policyset_and_also_return_policy_text(
    text: &str,
) -> Result<(HashMap<ast::PolicyID, &str>, ast::PolicySet), err::ParseErrors> {
    let mut errs = Vec::new();
    let cst = text_to_cst::parse_policies(text).map_err(err::ParseErrors)?;
    let pset = cst
        .to_policyset(&mut errs)
        .ok_or_else(|| err::ParseErrors(errs.clone()))?;
    // PANIC SAFETY Shouldn't be `none` since `parse_policies()` and `to_policyset()` didn't return `Err`
    #[allow(clippy::expect_used)]
    // PANIC SAFETY Indexing is safe because of how `SourceInfo` is constructed
    #[allow(clippy::indexing_slicing)]
    let texts = cst
        .with_generated_policyids()
        .expect("shouldn't be None since parse_policies() and to_policyset() didn't return Err")
        .map(|(id, policy)| (id, &text[policy.info.0.clone()]))
        .collect::<HashMap<ast::PolicyID, &str>>();
    if errs.is_empty() {
        Ok((texts, pset))
    } else {
        Err(err::ParseErrors(errs))
    }
}

/// Like `parse_policyset()`, but also returns the (lossless) ESTs -- that is,
/// the ESTs of the original policies without any of the lossy transforms
/// involved in converting to AST.
pub fn parse_policyset_to_ests_and_pset(
    text: &str,
) -> Result<(HashMap<ast::PolicyID, est::Policy>, ast::PolicySet), err::ParseErrors> {
    let mut errs = Vec::new();
    let cst = text_to_cst::parse_policies(text).map_err(err::ParseErrors)?;
    let pset = cst
        .to_policyset(&mut errs)
        .ok_or_else(|| err::ParseErrors(errs.clone()))?;
    // PANIC SAFETY Shouldn't be `none` since `parse_policies()` and `to_policyset()` didn't return `Err`
    #[allow(clippy::expect_used)]
    let ests = cst
        .with_generated_policyids()
        .expect("shouldn't be None since parse_policies() and to_policyset() didn't return Err")
        .map(|(id, policy)| match &policy.node {
            Some(p) => Ok(Some((id, p.clone().try_into()?))),
            None => Ok(None),
        })
        .collect::<Result<Option<HashMap<ast::PolicyID, est::Policy>>, err::ParseErrors>>()?;
    match (errs.is_empty(), ests) {
        (true, Some(ests)) => Ok((ests, pset)),
        (_, _) => Err(err::ParseErrors(errs)),
    }
}

/// Simple main function for parsing a policy template.
/// If `id` is Some, then the resulting template will have that `id`.
/// If the `id` is None, the parser will use "policy0".
pub fn parse_policy_template(
    id: Option<String>,
    text: &str,
) -> Result<ast::Template, Vec<err::ParseError>> {
    let mut errs = Vec::new();
    let id = match id {
        Some(id) => ast::PolicyID::from_string(id),
        None => ast::PolicyID::from_string("policy0"),
    };
    let r = text_to_cst::parse_policy(text)?.to_policy_template(id, &mut errs);
    if errs.is_empty() {
        r.ok_or(errs).map(ast::Template::from)
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
    let mut errs = Vec::new();
    let id = match id {
        Some(id) => ast::PolicyID::from_string(id),
        None => ast::PolicyID::from_string("policy0"),
    };
    let cst = text_to_cst::parse_policy(text).map_err(err::ParseErrors)?;
    let ast = cst
        .to_policy_template(id, &mut errs)
        .ok_or_else(|| err::ParseErrors(errs.clone()))?;
    let est = cst.node.map(TryInto::try_into).transpose()?;
    match (errs.is_empty(), est) {
        (true, Some(est)) => Ok((est, ast)),
        (_, _) => Err(err::ParseErrors(errs)),
    }
}

/// simple main function for parsing a policy.
/// If `id` is Some, then the resulting policy will have that `id`.
/// If the `id` is None, the parser will use "policy0".
pub fn parse_policy(
    id: Option<String>,
    text: &str,
) -> Result<ast::StaticPolicy, Vec<err::ParseError>> {
    let mut errs = Vec::new();
    let id = match id {
        Some(id) => ast::PolicyID::from_string(id),
        None => ast::PolicyID::from_string("policy0"),
    };
    let r = text_to_cst::parse_policy(text)?.to_policy(id, &mut errs);

    if errs.is_empty() {
        r.ok_or(errs)
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
    let mut errs = Vec::new();
    let id = match id {
        Some(id) => ast::PolicyID::from_string(id),
        None => ast::PolicyID::from_string("policy0"),
    };
    let cst = text_to_cst::parse_policy(text).map_err(err::ParseErrors)?;
    let ast = cst
        .to_policy(id, &mut errs)
        .ok_or_else(|| err::ParseErrors(errs.clone()))?;

    let est = cst.node.map(TryInto::try_into).transpose()?;
    match (errs.is_empty(), est) {
        (true, Some(est)) => Ok((est, ast)),
        (_, _) => Err(err::ParseErrors(errs)),
    }
}

/// Parse a policy or template (either one works) to its EST representation
pub fn parse_policy_or_template_to_est(text: &str) -> Result<est::Policy, err::ParseErrors> {
    let cst = text_to_cst::parse_policy(text).map_err(err::ParseErrors)?;
    let est = cst.node.map(TryInto::try_into).transpose()?;
    match est {
        Some(est) => Ok(est),
        None => Err(err::ParseErrors(vec![])), // theoretically this shouldn't happen if the `?`s above didn't already fail us out
    }
}

/// parse an Expr
///
/// Private to this crate. Users outside Core should use `Expr`'s `FromStr` impl
/// or its constructors
pub(crate) fn parse_expr(ptext: &str) -> Result<ast::Expr, Vec<err::ParseError>> {
    let mut errs = Vec::new();
    text_to_cst::parse_expr(ptext)?
        .to_expr(&mut errs)
        .ok_or(errs)
}

/// parse a RestrictedExpr
///
/// Private to this crate. Users outside Core should use `RestrictedExpr`'s
/// `FromStr` impl or its constructors
pub(crate) fn parse_restrictedexpr(
    ptext: &str,
) -> Result<ast::RestrictedExpr, Vec<err::ParseError>> {
    parse_expr(ptext)
        .and_then(|expr| ast::RestrictedExpr::new(expr).map_err(|err| vec![err.into()]))
}

/// parse an EntityUID
///
/// Private to this crate. Users outside Core should use `EntityUID`'s `FromStr`
/// impl or its constructors
pub(crate) fn parse_euid(euid: &str) -> Result<ast::EntityUID, Vec<err::ParseError>> {
    let mut errs = Vec::new();
    text_to_cst::parse_ref(euid)?.to_ref(&mut errs).ok_or(errs)
}

/// parse a Name
///
/// Private to this crate. Users outside Core should use `Name`'s `FromStr` impl
/// or its constructors
pub(crate) fn parse_name(name: &str) -> Result<ast::Name, Vec<err::ParseError>> {
    let mut errs = Vec::new();
    text_to_cst::parse_name(name)?
        .to_name(&mut errs)
        .ok_or(errs)
}

/// parse a string into an ast::Literal (does not support expressions)
///
/// Private to this crate. Users outside Core should use `Literal`'s `FromStr` impl
/// or its constructors
pub(crate) fn parse_literal(val: &str) -> Result<ast::Literal, Vec<err::ParseError>> {
    let mut errs = Vec::new();
    match text_to_cst::parse_primary(val)?
        .to_expr(&mut errs)
        .ok_or(errs)?
        .into_expr_kind()
    {
        ast::ExprKind::Lit(v) => Ok(v),
        _ => Err(vec![err::ParseError::ToAST(
            "text is not a literal".to_string(),
        )]),
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
pub fn parse_internal_string(val: &str) -> Result<SmolStr, Vec<err::ParseError>> {
    let mut errs = Vec::new();
    // we need to add quotes for this to be a valid string literal
    text_to_cst::parse_primary(&format!(r#""{val}""#))?
        .to_string_literal(&mut errs)
        .ok_or(errs)
}

/// parse an identifier
///
/// Private to this crate. Users outside Core should use `Id`'s `FromStr` impl
/// or its constructors
pub(crate) fn parse_ident(id: &str) -> Result<ast::Id, Vec<err::ParseError>> {
    let mut errs = Vec::new();
    text_to_cst::parse_ident(id)?
        .to_valid_ident(&mut errs)
        .ok_or(errs)
}

/// parse into a `Request`
pub fn parse_request(
    principal: impl AsRef<str>,      // should be a "Type::EID" string
    action: impl AsRef<str>,         // should be a "Type::EID" string
    resource: impl AsRef<str>,       // should be a "Type::EID" string
    context_json: serde_json::Value, // JSON object mapping Strings to ast::RestrictedExpr
) -> Result<ast::Request, Vec<err::ParseError>> {
    let mut errs = vec![];
    // Parse principal, action, resource
    let mut parse_par = |s, name| {
        parse_euid(s)
            .map_err(|e| {
                errs.push(err::ParseError::WithContext {
                    context: format!("trying to parse {}", name),
                    errs: e.into(),
                })
            })
            .ok()
    };

    let (principal, action, resource) = (
        parse_par(principal.as_ref(), "principal"),
        parse_par(action.as_ref(), "action"),
        parse_par(resource.as_ref(), "resource"),
    );

    let context = match ast::Context::from_json_value(context_json) {
        Ok(ctx) => Some(ctx),
        Err(e) => {
            errs.push(err::ParseError::ToAST(format!(
                "failed to parse context JSON: {}",
                err::ParseErrors(vec![err::ParseError::ToAST(e.to_string())])
            )));
            None
        }
    };
    match (principal, action, resource, errs.as_slice()) {
        (Some(p), Some(a), Some(r), &[]) => Ok(ast::Request {
            principal: ast::EntityUIDEntry::concrete(p),
            action: ast::EntityUIDEntry::concrete(a),
            resource: ast::EntityUIDEntry::concrete(r),
            context,
        }),
        _ => Err(errs),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ast::{test_generators::*, Template};
    use itertools::Itertools;
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
                Err(e) => panic!(
                    "Failed to parse {src}, {}",
                    e.into_iter().map(|e| format!("{e}")).join("\n")
                ),
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
        println!("{:?}", errors);
        assert!(errors.len() >= 3);
    }
}

#[cfg(test)]
mod eval_tests {
    use super::*;
    use crate::evaluator as eval;
    use crate::extensions::Extensions;

    #[test]
    fn interpret_exprs() {
        let request = eval::test::basic_request();
        let entities = eval::test::basic_entities();
        let exts = Extensions::none();
        let evaluator = eval::Evaluator::new(&request, &entities, &exts).unwrap();

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
        let evaluator = eval::Evaluator::new(&request, &entities, &exts).unwrap();

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
        let evaluator = eval::Evaluator::new(&request, &entities, &exts).unwrap();

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
    use super::*;

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
            ast::Eid::new(parse_internal_string(r#"a\nblock\nid"#).expect("should parse"))
                .to_string(),
            r#"a\nblock\nid"#,
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
        let _ = parse_policyset_to_ests_and_pset(src);
    }

    #[test]
    fn no_slots_in_condition() {
        let srcs = [
            r#"
            permit(principal, action, resource) when {
                resource == ?resource
            };
            "#,
            r#"
            permit(principal, action, resource) when {
                resource == ?principal
            };
            "#,
            r#"
            permit(principal, action, resource) when {
                resource == ?blah
            };
            "#,
            r#"
            permit(principal, action, resource) unless {
                resource == ?resource
            };
            "#,
            r#"
            permit(principal, action, resource) unless {
                resource == ?principal
            };
            "#,
            r#"
            permit(principal, action, resource) unless {
                resource == ?blah
            };
            "#,
            r#"
            permit(principal, action, resource) unless {
                resource == ?resource
            } when {
                resource == ?resource
            }
            "#,
        ];

        for src in srcs {
            let p = parse_policy(None, src);
            assert!(p.is_err());
            let p = parse_policy_template(None, src);
            assert!(p.is_err());
            let p = parse_policy_to_est_and_ast(None, src);
            assert!(p.is_err());
            let p = parse_policy_template_to_est_and_ast(None, src);
            assert!(p.is_err());
            let p = parse_policyset(src);
            assert!(p.is_err());
            let p = parse_policyset_to_ests_and_pset(src);
            assert!(p.is_err());
        }
    }
}
