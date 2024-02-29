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

//! This module contains the External Syntax Tree (EST)

mod err;
pub use err::*;
mod expr;
pub use expr::*;
mod head_constraints;
pub use head_constraints::*;

use crate::ast;
use crate::entities::EntityUidJson;
use crate::parser::cst;
use crate::parser::err::{ParseErrors, ToASTError, ToASTErrorKind};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashMap};

#[cfg(feature = "wasm")]
extern crate tsify;

/// Serde JSON structure for policies and templates in the EST format
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct Policy {
    /// `Effect` of the policy or template
    effect: ast::Effect,
    /// Principal head constraint
    principal: PrincipalConstraint,
    /// Action head constraint
    action: ActionConstraint,
    /// Resource head constraint
    resource: ResourceConstraint,
    /// `when` and/or `unless` clauses
    conditions: Vec<Clause>,
    /// annotations
    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde_as(as = "serde_with::MapPreventDuplicates<_,_>")]
    #[cfg_attr(feature = "wasm", tsify(type = "Record<string, string>"))]
    annotations: BTreeMap<ast::AnyId, SmolStr>,
}

/// Serde JSON structure for a `when` or `unless` clause in the EST format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "body")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum Clause {
    /// A `when` clause
    #[serde(rename = "when")]
    When(Expr),
    /// An `unless` clause
    #[serde(rename = "unless")]
    Unless(Expr),
}

impl Policy {
    /// Fill in any slots in the policy using the values in `vals`. Throws an
    /// error if `vals` doesn't contain a necessary mapping, but does not throw
    /// an error if `vals` contains unused mappings -- and in particular if
    /// `self` is an inline policy (in which case it is returned unchanged).
    pub fn link(
        self,
        vals: &HashMap<ast::SlotId, EntityUidJson>,
    ) -> Result<Self, InstantiationError> {
        Ok(Policy {
            effect: self.effect,
            principal: self.principal.instantiate(vals)?,
            action: self.action.instantiate(vals)?,
            resource: self.resource.instantiate(vals)?,
            conditions: self
                .conditions
                .into_iter()
                .map(|clause| clause.instantiate(vals))
                .collect::<Result<Vec<_>, _>>()?,
            annotations: self.annotations,
        })
    }
}

impl Clause {
    /// Fill in any slots in the clause using the values in `vals`. Throws an
    /// error if `vals` doesn't contain a necessary mapping, but does not throw
    /// an error if `vals` contains unused mappings.
    pub fn instantiate(
        self,
        _vals: &HashMap<ast::SlotId, EntityUidJson>,
    ) -> Result<Self, InstantiationError> {
        // currently, slots are not allowed in clauses
        Ok(self)
    }
}

impl TryFrom<cst::Policy> for Policy {
    type Error = ParseErrors;
    fn try_from(policy: cst::Policy) -> Result<Policy, ParseErrors> {
        let mut errs = ParseErrors::new();
        let effect = policy.effect.to_effect(&mut errs);
        let (principal, action, resource) = policy.extract_head(&mut errs);
        let (annot_success, annotations) = policy.get_ast_annotations(&mut errs);
        let conditions = match policy
            .conds
            .into_iter()
            .map(|node| {
                let (cond, loc) = node.into_inner();
                let cond = cond.ok_or_else(|| {
                    ParseErrors(vec![ToASTError::new(
                        ToASTErrorKind::EmptyClause(None),
                        loc,
                    )
                    .into()])
                })?;
                cond.try_into()
            })
            .collect::<Result<Vec<_>, ParseErrors>>()
        {
            Ok(conds) => Some(conds),
            Err(e) => {
                errs.extend(e);
                None
            }
        };

        match (
            effect,
            principal,
            action,
            resource,
            conditions,
            annot_success,
            errs.is_empty(),
        ) {
            (
                Some(effect),
                Some(principal),
                Some(action),
                Some(resource),
                Some(conditions),
                true,
                true,
            ) => Ok(Policy {
                effect,
                principal: principal.into(),
                action: action.into(),
                resource: resource.into(),
                conditions,
                annotations: annotations.into_iter().map(|(k, v)| (k, v.val)).collect(),
            }),
            _ => Err(errs),
        }
    }
}

impl TryFrom<cst::Cond> for Clause {
    type Error = ParseErrors;
    fn try_from(cond: cst::Cond) -> Result<Clause, ParseErrors> {
        let mut errs = ParseErrors::new();
        let is_when = cond.cond.to_cond_is_when(&mut errs);
        let expr: Result<Expr, ParseErrors> = match cond.expr {
            None => {
                let ident = is_when.map(|is_when| {
                    cst::Ident::Ident(if is_when { "when" } else { "unless" }.into())
                });
                Err(cond
                    .cond
                    .to_ast_err(ToASTErrorKind::EmptyClause(ident))
                    .into())
            }
            Some(ref e) => e.try_into(),
        };
        let expr = match expr {
            Ok(expr) => Some(expr),
            Err(expr_errs) => {
                errs.extend(expr_errs.0);
                None
            }
        };

        if let (Some(expr), true) = (expr, errs.is_empty()) {
            Ok(match is_when {
                // PANIC SAFETY errs should be non empty if is_when is None
                #[allow(clippy::unreachable)]
                None => unreachable!("should have had an err in this case"),
                Some(true) => Clause::When(expr),
                Some(false) => Clause::Unless(expr),
            })
        } else {
            Err(errs)
        }
    }
}

impl Policy {
    /// Try to convert EST Policy into AST Policy.
    ///
    /// This process requires a policy ID. If not supplied, this method will
    /// fill it in as "JSON policy".
    pub fn try_into_ast_policy(
        self,
        id: Option<ast::PolicyID>,
    ) -> Result<ast::Policy, FromJsonError> {
        let template: ast::Template = self.try_into_ast_template(id)?;
        ast::StaticPolicy::try_from(template)
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Try to convert EST Policy into AST Template.
    ///
    /// This process requires a policy ID. If not supplied, this method will
    /// fill it in as "JSON policy".
    pub fn try_into_ast_template(
        self,
        id: Option<ast::PolicyID>,
    ) -> Result<ast::Template, FromJsonError> {
        let id = id.unwrap_or(ast::PolicyID::from_string("JSON policy"));
        let mut conditions_iter = self
            .conditions
            .into_iter()
            .map(|cond| cond.try_into_ast(id.clone()));
        let conditions = match conditions_iter.next() {
            None => ast::Expr::val(true),
            Some(first) => ast::ExprBuilder::with_data(())
                .and_nary(first?, conditions_iter.collect::<Result<Vec<_>, _>>()?),
        };
        Ok(ast::Template::new(
            id,
            self.annotations
                .into_iter()
                .map(|(key, val)| (key, ast::Annotation { val, loc: None }))
                .collect(),
            self.effect,
            self.principal.try_into()?,
            self.action.try_into()?,
            self.resource.try_into()?,
            conditions,
        ))
    }
}

impl Clause {
    fn filter_slots(e: ast::Expr, is_when: bool) -> Result<ast::Expr, FromJsonError> {
        let first_slot = e.slots().next().cloned();
        if let Some(slot) = first_slot {
            Err(FromJsonError::SlotsInConditionClause {
                slot,
                clausetype: if is_when { "when" } else { "unless" },
            })
        } else {
            Ok(e)
        }
    }
    /// `id` is the ID of the policy the clause belongs to, used only for reporting errors
    fn try_into_ast(self, id: ast::PolicyID) -> Result<ast::Expr, FromJsonError> {
        match self {
            Clause::When(expr) => Self::filter_slots(expr.try_into_ast(id)?, true),
            Clause::Unless(expr) => {
                Self::filter_slots(ast::Expr::not(expr.try_into_ast(id)?), false)
            }
        }
    }
}

/// Convert AST to EST
impl From<ast::Policy> for Policy {
    fn from(ast: ast::Policy) -> Policy {
        Policy {
            effect: ast.effect(),
            principal: ast.principal_constraint().into(),
            action: ast.action_constraint().clone().into(),
            resource: ast.resource_constraint().into(),
            conditions: vec![ast.non_head_constraints().clone().into()],
            annotations: ast
                .annotations()
                .map(|(k, v)| (k.clone(), v.val.clone()))
                .collect(),
        }
    }
}

/// Convert AST to EST
impl From<ast::Template> for Policy {
    fn from(ast: ast::Template) -> Policy {
        Policy {
            effect: ast.effect(),
            principal: ast.principal_constraint().clone().into(),
            action: ast.action_constraint().clone().into(),
            resource: ast.resource_constraint().clone().into(),
            conditions: vec![ast.non_head_constraints().clone().into()],
            annotations: ast
                .annotations()
                .map(|(k, v)| (k.clone(), v.val.clone()))
                .collect(),
        }
    }
}

impl From<ast::Expr> for Clause {
    fn from(expr: ast::Expr) -> Clause {
        Clause::When(expr.into())
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (k, v) in self.annotations.iter() {
            writeln!(f, "@{k}(\"{}\") ", v.escape_debug())?;
        }
        write!(
            f,
            "{}({}, {}, {})",
            self.effect, self.principal, self.action, self.resource
        )?;
        for condition in &self.conditions {
            write!(f, " {condition}")?;
        }
        write!(f, ";")
    }
}

impl std::fmt::Display for Clause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::When(expr) => write!(f, "when {{ {expr} }}"),
            Self::Unless(expr) => write!(f, "unless {{ {expr} }}"),
        }
    }
}

// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
// PANIC SAFETY: Unit Test Code
#[allow(clippy::indexing_slicing)]
#[cfg(test)]
mod test {
    use super::*;
    use crate::parser;
    use crate::test_utils::ExpectedErrorMessage;
    use cool_asserts::assert_matches;
    use miette::Diagnostic;
    use serde_json::json;

    /// helper function to just do EST data structure --> JSON --> EST data structure.
    /// This roundtrip should be lossless for all policies.
    fn est_roundtrip(est: Policy) -> Policy {
        let json = serde_json::to_value(est).expect("failed to serialize to JSON");
        serde_json::from_value(json.clone()).unwrap_or_else(|e| {
            panic!(
                "failed to deserialize from JSON: {e}\n\nJSON was:\n{}",
                serde_json::to_string_pretty(&json).expect("failed to convert JSON to string")
            )
        })
    }

    /// helper function to take EST-->text-->CST-->EST, which directly tests the Display impl for EST.
    /// This roundtrip should be lossless for all policies.
    fn text_roundtrip(est: &Policy) -> Policy {
        let text = est.to_string();
        let cst = parser::text_to_cst::parse_policy(&text)
            .expect("Failed to convert to CST")
            .node
            .expect("Node should not be empty");
        cst.try_into().expect("Failed to convert to EST")
    }

    /// helper function to take EST-->AST-->EST for inline policies.
    /// This roundtrip is not always lossless, because EST-->AST can be lossy.
    fn ast_roundtrip(est: Policy) -> Policy {
        let ast = est
            .try_into_ast_policy(None)
            .expect("Failed to convert to AST");
        ast.into()
    }

    /// helper function to take EST-->AST-->EST for templates.
    /// This roundtrip is not always lossless, because EST-->AST can be lossy.
    fn ast_roundtrip_template(est: Policy) -> Policy {
        let ast = est
            .try_into_ast_template(None)
            .expect("Failed to convert to AST");
        ast.into()
    }

    /// helper function to take EST-->AST-->text-->CST-->EST for inline policies.
    /// This roundtrip is not always lossless, because EST-->AST can be lossy.
    fn circular_roundtrip(est: Policy) -> Policy {
        let ast = est
            .try_into_ast_policy(None)
            .expect("Failed to convert to AST");
        let text = ast.to_string();
        let cst = parser::text_to_cst::parse_policy(&text)
            .expect("Failed to convert to CST")
            .node
            .expect("Node should not be empty");
        cst.try_into().expect("Failed to convert to EST")
    }

    /// helper function to take EST-->AST-->text-->CST-->EST for templates.
    /// This roundtrip is not always lossless, because EST-->AST can be lossy.
    fn circular_roundtrip_template(est: Policy) -> Policy {
        let ast = est
            .try_into_ast_template(None)
            .expect("Failed to convert to AST");
        let text = ast.to_string();
        let cst = parser::text_to_cst::parse_policy(&text)
            .expect("Failed to convert to CST")
            .node
            .expect("Node should not be empty");
        cst.try_into().expect("Failed to convert to EST")
    }

    #[test]
    fn empty_policy() {
        let policy = "permit(principal, action, resource);";
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [],
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        // during the lossy transform to AST, the only difference for this policy is that
        // a `when { true }` is added
        let expected_json_after_roundtrip = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "Value": true
                        }
                    }
                ],
            }
        );
        let roundtripped = serde_json::to_value(ast_roundtrip(est.clone())).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
        let roundtripped = serde_json::to_value(circular_roundtrip(est)).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
    }

    #[test]
    fn annotated_policy() {
        let policy = r#"
            @foo("bar")
            @this1is2a3valid_identifier("any arbitrary ! string \" is @ allowed in 🦀 here_")
            permit(principal, action, resource);
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [],
                "annotations": {
                    "foo": "bar",
                    "this1is2a3valid_identifier": "any arbitrary ! string \" is @ allowed in 🦀 here_",
                }
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        // during the lossy transform to AST, the only difference for this policy is that
        // a `when { true }` is added
        let expected_json_after_roundtrip = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "Value": true
                        }
                    }
                ],
                "annotations": {
                    "foo": "bar",
                    "this1is2a3valid_identifier": "any arbitrary ! string \" is @ allowed in 🦀 here_",
                }
            }
        );
        let roundtripped = serde_json::to_value(ast_roundtrip(est.clone())).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
        let roundtripped = serde_json::to_value(circular_roundtrip(est)).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
    }

    /// Test that we can use Cedar reserved words like `if` and `has` as annotation keys
    #[test]
    fn reserved_words_as_annotations() {
        let policy = r#"
            @if("this is the annotation for `if`")
            @then("this is the annotation for `then`")
            @else("this is the annotation for `else`")
            @true("this is the annotation for `true`")
            @false("this is the annotation for `false`")
            @in("this is the annotation for `in`")
            @is("this is the annotation for `is`")
            @like("this is the annotation for `like`")
            @has("this is the annotation for `has`")
            @principal("this is the annotation for `principal`") // not reserved at time of this writing, but we test it anyway
            permit(principal, action, resource) when { 2 == 2 };
        "#;

        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "==": {
                                "left": { "Value": 2 },
                                "right": { "Value": 2 },
                            }
                        }
                    }
                ],
                "annotations": {
                    "if": "this is the annotation for `if`",
                    "then": "this is the annotation for `then`",
                    "else": "this is the annotation for `else`",
                    "true": "this is the annotation for `true`",
                    "false": "this is the annotation for `false`",
                    "in": "this is the annotation for `in`",
                    "is": "this is the annotation for `is`",
                    "like": "this is the annotation for `like`",
                    "has": "this is the annotation for `has`",
                    "principal": "this is the annotation for `principal`",
                }
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        assert_eq!(ast_roundtrip(est.clone()), est);
        assert_eq!(circular_roundtrip(est.clone()), est);
    }

    #[test]
    fn annotation_errors() {
        let policy = r#"
            @foo("1")
            @foo("2")
            permit(principal, action, resource);
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        assert_matches!(Policy::try_from(cst), Err(e) => {
            parser::test_utils::expect_exactly_one_error(policy, &e, &ExpectedErrorMessage::error("duplicate annotation: @foo"));
            let expected_span = 35..44;
            assert_eq!(&policy[expected_span.clone()], r#"@foo("2")"#);
            itertools::assert_equal(e.labels().expect("should have labels"), [miette::LabeledSpan::underline(expected_span)]);
        });

        let policy = r#"
            @foo("1")
            @foo("1")
            permit(principal, action, resource);
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        assert_matches!(Policy::try_from(cst), Err(e) => {
            parser::test_utils::expect_exactly_one_error(policy, &e, &ExpectedErrorMessage::error("duplicate annotation: @foo"));
            let expected_span = 35..44;
            assert_eq!(&policy[expected_span.clone()], r#"@foo("1")"#);
            itertools::assert_equal(e.labels().expect("should have labels"), [miette::LabeledSpan::underline(expected_span)]);
        });

        let policy = r#"
            @foo("1")
            @bar("yellow")
            @foo("abc")
            @hello("goodbye")
            @bar("123")
            @foo("def")
            permit(principal, action, resource);
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        assert_matches!(Policy::try_from(cst), Err(e) => {
            assert_eq!(e.len(), 3); // two errors for @foo and one for @bar
            parser::test_utils::expect_some_error_matches(policy, &e, &ExpectedErrorMessage::error("duplicate annotation: @foo"));
            parser::test_utils::expect_some_error_matches(policy, &e, &ExpectedErrorMessage::error("duplicate annotation: @bar"));
            for ((err, expected_span), expected_snippet) in e.iter().zip([62..73, 116..127, 140..151]).zip([r#"@foo("abc")"#, r#"@bar("123")"#, r#"@foo("def")"#]) {
                assert_eq!(&policy[expected_span.clone()], expected_snippet);
                itertools::assert_equal(err.labels().expect("should have labels"), [miette::LabeledSpan::underline(expected_span)]);
            }
        });

        // the above tests ensure that we give the correct errors for CSTs
        // containing duplicate annotations.
        // This test ensures that we give the correct errors for JSON text
        // containing duplicate annotations.
        // Note that we have to use a string here as input (and not
        // serde_json::Value) because serde_json::Value would already remove
        // duplicates
        let est = r#"
            {
                "effect": "permit",
                "principal": {
                    "op": "All"
                },
                "action": {
                    "op": "All"
                },
                "resource": {
                    "op": "All"
                },
                "conditions": [],
                "annotations": {
                    "foo": "1",
                    "foo": "2"
                }
            }
        "#;
        assert_matches!(serde_json::from_str::<Policy>(est), Err(e) => {
            assert_eq!(e.to_string(), "invalid entry: found duplicate key at line 17 column 17");
        });
    }

    #[test]
    fn rbac_policy() {
        let policy = r#"
            permit(
                principal == User::"12UA45",
                action == Action::"view",
                resource in Folder::"abc"
            );
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "==",
                    "entity": { "type": "User", "id": "12UA45" },
                },
                "action": {
                    "op": "==",
                    "entity": { "type": "Action", "id": "view" },
                },
                "resource": {
                    "op": "in",
                    "entity": { "type": "Folder", "id": "abc" },
                },
                "conditions": []
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        // during the lossy transform to AST, the only difference for this policy is that
        // a `when { true }` is added
        let expected_json_after_roundtrip = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "==",
                    "entity": { "type": "User", "id": "12UA45" },
                },
                "action": {
                    "op": "==",
                    "entity": { "type": "Action", "id": "view" },
                },
                "resource": {
                    "op": "in",
                    "entity": { "type": "Folder", "id": "abc" },
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "Value": true
                        }
                    }
                ]
            }
        );
        let roundtripped = serde_json::to_value(ast_roundtrip(est.clone())).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
        let roundtripped = serde_json::to_value(circular_roundtrip(est)).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
    }

    #[test]
    fn rbac_template() {
        let template = r#"
            permit(
                principal == ?principal,
                action == Action::"view",
                resource in ?resource
            );
        "#;
        let cst = parser::text_to_cst::parse_policy(template)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "==",
                    "slot": "?principal",
                },
                "action": {
                    "op": "==",
                    "entity": { "type": "Action", "id": "view" },
                },
                "resource": {
                    "op": "in",
                    "slot": "?resource",
                },
                "conditions": []
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        // during the lossy transform to AST, the only difference for this policy is that
        // a `when { true }` is added
        let expected_json_after_roundtrip = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "==",
                    "slot": "?principal",
                },
                "action": {
                    "op": "==",
                    "entity": { "type": "Action", "id": "view" },
                },
                "resource": {
                    "op": "in",
                    "slot": "?resource",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "Value": true
                        }
                    }
                ]
            }
        );
        let roundtripped = serde_json::to_value(ast_roundtrip_template(est.clone())).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
        let roundtripped = serde_json::to_value(circular_roundtrip_template(est)).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
    }

    #[test]
    fn abac_policy() {
        let policy = r#"
            permit(
                principal == User::"12UA45",
                action == Action::"view",
                resource in Folder::"abc"
            ) when {
                context.tls_version == "1.3"
            };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "==",
                    "entity": { "type": "User", "id": "12UA45" },
                },
                "action": {
                    "op": "==",
                    "entity": { "type": "Action", "id": "view" },
                },
                "resource": {
                    "op": "in",
                    "entity": { "type": "Folder", "id": "abc" },
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "==": {
                                "left": {
                                    ".": {
                                        "left": { "Var": "context" },
                                        "attr": "tls_version",
                                    },
                                },
                                "right": {
                                    "Value": "1.3"
                                }
                            }
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        assert_eq!(ast_roundtrip(est.clone()), est);
        assert_eq!(circular_roundtrip(est.clone()), est);
    }

    #[test]
    fn action_list() {
        let policy = r#"
            permit(
                principal == User::"12UA45",
                action in [Action::"read", Action::"write"],
                resource
            );
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "==",
                    "entity": { "type": "User", "id": "12UA45" },
                },
                "action": {
                    "op": "in",
                    "entities": [
                        { "type": "Action", "id": "read" },
                        { "type": "Action", "id": "write" },
                    ]
                },
                "resource": {
                    "op": "All",
                },
                "conditions": []
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        // during the lossy transform to AST, the only difference for this policy is that
        // a `when { true }` is added
        let expected_json_after_roundtrip = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "==",
                    "entity": { "type": "User", "id": "12UA45" },
                },
                "action": {
                    "op": "in",
                    "entities": [
                        { "type": "Action", "id": "read" },
                        { "type": "Action", "id": "write" },
                    ]
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "Value": true
                        }
                    }
                ]
            }
        );
        let roundtripped = serde_json::to_value(ast_roundtrip(est.clone())).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
        let roundtripped = serde_json::to_value(circular_roundtrip(est)).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
    }

    #[test]
    fn num_literals() {
        let policy = r#"
            permit(principal, action, resource)
            when { 1 == 2 };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "==": {
                                "left": {
                                    "Value": 1
                                },
                                "right": {
                                    "Value": 2
                                }
                            }
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        assert_eq!(ast_roundtrip(est.clone()), est);
        assert_eq!(circular_roundtrip(est.clone()), est);
    }

    #[test]
    fn entity_literals() {
        let policy = r#"
            permit(principal, action, resource)
            when { User::"alice" == Namespace::Type::"foo" };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "==": {
                                "left": {
                                    "Value": {
                                        "__entity": {
                                            "type": "User",
                                            "id": "alice"
                                        }
                                    }
                                },
                                "right": {
                                    "Value": {
                                        "__entity": {
                                            "type": "Namespace::Type",
                                            "id": "foo"
                                        }
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        assert_eq!(ast_roundtrip(est.clone()), est);
        assert_eq!(circular_roundtrip(est.clone()), est);
    }

    #[test]
    fn bool_literals() {
        let policy = r#"
            permit(principal, action, resource)
            when { false == true };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "==": {
                                "left": {
                                    "Value": false
                                },
                                "right": {
                                    "Value": true
                                }
                            }
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        assert_eq!(ast_roundtrip(est.clone()), est);
        assert_eq!(circular_roundtrip(est.clone()), est);
    }

    #[test]
    fn string_literals() {
        let policy = r#"
            permit(principal, action, resource)
            when { "spam" == "eggs" };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "==": {
                                "left": {
                                    "Value": "spam"
                                },
                                "right": {
                                    "Value": "eggs"
                                }
                            }
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        assert_eq!(ast_roundtrip(est.clone()), est);
        assert_eq!(circular_roundtrip(est.clone()), est);
    }

    #[test]
    fn set_literals() {
        let policy = r#"
            permit(principal, action, resource)
            when { [1, 2, "foo"] == [4, 5, "spam"] };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "==": {
                                "left": {
                                    "Set": [
                                        { "Value": 1 },
                                        { "Value": 2 },
                                        { "Value": "foo" },
                                    ]
                                },
                                "right": {
                                    "Set": [
                                        { "Value": 4 },
                                        { "Value": 5 },
                                        { "Value": "spam" },
                                    ]
                                }
                            }
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        assert_eq!(ast_roundtrip(est.clone()), est);
        assert_eq!(circular_roundtrip(est.clone()), est);
    }

    #[test]
    fn record_literals() {
        let policy = r#"
            permit(principal, action, resource)
            when { {foo: "spam", bar: false} == {} };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "==": {
                                "left": {
                                    "Record": {
                                        "foo": { "Value": "spam" },
                                        "bar": { "Value": false },
                                    }
                                },
                                "right": {
                                    "Record": {}
                                }
                            }
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        assert_eq!(ast_roundtrip(est.clone()), est);
        assert_eq!(circular_roundtrip(est.clone()), est);
    }

    #[test]
    fn policy_variables() {
        let policy = r#"
            permit(principal, action, resource)
            when { principal == action && resource == context };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "&&": {
                                "left": {
                                    "==": {
                                        "left": {
                                            "Var": "principal"
                                        },
                                        "right": {
                                            "Var": "action"
                                        }
                                    }
                                },
                                "right": {
                                    "==": {
                                        "left": {
                                            "Var": "resource"
                                        },
                                        "right": {
                                            "Var": "context"
                                        }
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        assert_eq!(ast_roundtrip(est.clone()), est);
        assert_eq!(circular_roundtrip(est.clone()), est);
    }

    #[test]
    fn not() {
        let policy = r#"
            permit(principal, action, resource)
            when { !context.foo && principal != context.bar };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "&&": {
                                "left": {
                                    "!": {
                                        "arg": {
                                            ".": {
                                                "left": {
                                                    "Var": "context"
                                                },
                                                "attr": "foo"
                                            }
                                        }
                                    }
                                },
                                "right": {
                                    "!=": {
                                        "left": {
                                            "Var": "principal"
                                        },
                                        "right": {
                                            ".": {
                                                "left": {
                                                    "Var": "context"
                                                },
                                                "attr": "bar"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        // during the lossy transform to AST, the only difference for this policy is that
        // `!=` is expanded to `!(==)`
        let expected_json_after_roundtrip = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "&&": {
                                "left": {
                                    "!": {
                                        "arg": {
                                            ".": {
                                                "left": {
                                                    "Var": "context"
                                                },
                                                "attr": "foo"
                                            }
                                        }
                                    }
                                },
                                "right": {
                                    "!": {
                                        "arg": {
                                            "==": {
                                                "left": {
                                                    "Var": "principal"
                                                },
                                                "right": {
                                                    ".": {
                                                        "left": {
                                                            "Var": "context"
                                                        },
                                                        "attr": "bar"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        );
        let roundtripped = serde_json::to_value(ast_roundtrip(est.clone())).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
        let roundtripped = serde_json::to_value(circular_roundtrip(est)).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
    }

    #[test]
    fn hierarchy_in() {
        let policy = r#"
            permit(principal, action, resource)
            when { resource in principal.department };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "in": {
                                "left": {
                                    "Var": "resource"
                                },
                                "right": {
                                    ".": {
                                        "left": {
                                            "Var": "principal"
                                        },
                                        "attr": "department"
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        assert_eq!(ast_roundtrip(est.clone()), est);
        assert_eq!(circular_roundtrip(est.clone()), est);
    }

    #[test]
    fn nested_records() {
        let policy = r#"
            permit(principal, action, resource)
            when { context.something1.something2.something3 };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            ".": {
                                "left": {
                                    ".": {
                                        "left": {
                                            ".": {
                                                "left": {
                                                    "Var": "context"
                                                },
                                                "attr": "something1"
                                            }
                                        },
                                        "attr": "something2"
                                    }
                                },
                                "attr": "something3"
                            }
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        assert_eq!(ast_roundtrip(est.clone()), est);
        assert_eq!(circular_roundtrip(est.clone()), est);
    }

    #[test]
    fn neg_less_and_greater() {
        let policy = r#"
            permit(principal, action, resource)
            when { -3 < 2 && 4 > -(23 - 1) || 0 <= 0 && 7 >= 1};
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "||": {
                                "left": {
                                    "&&": {
                                        "left": {
                                            "<": {
                                                "left": {
                                                    "Value": -3
                                                },
                                                "right": {
                                                    "Value": 2
                                                }
                                            }
                                        },
                                        "right": {
                                            ">": {
                                                "left": {
                                                    "Value": 4
                                                },
                                                "right": {
                                                    "neg": {
                                                        "arg": {
                                                            "-": {
                                                                "left": {
                                                                    "Value": 23
                                                                },
                                                                "right": {
                                                                    "Value": 1
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                "right": {
                                    "&&": {
                                        "left": {
                                            "<=": {
                                                "left": {
                                                    "Value": 0
                                                },
                                                "right": {
                                                    "Value": 0
                                                }
                                            }
                                        },
                                        "right": {
                                            ">=": {
                                                "left": {
                                                    "Value": 7
                                                },
                                                "right": {
                                                    "Value": 1
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        // during the lossy transform to AST, the `>` and `>=` ops are desugared to `<` and
        // `<=` ops with the operands flipped
        let expected_json_after_roundtrip = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "||": {
                                "left": {
                                    "&&": {
                                        "left": {
                                            "<": {
                                                "left": {
                                                    "Value": -3
                                                },
                                                "right": {
                                                    "Value": 2
                                                }
                                            }
                                        },
                                        "right": {
                                            "!": {
                                                "arg":{
                                                    "<=": {
                                                        "left": {
                                                            "Value": 4
                                                        },
                                                        "right": {
                                                            "neg": {
                                                                "arg": {
                                                                    "-": {
                                                                        "left": {
                                                                            "Value": 23
                                                                        },
                                                                        "right": {
                                                                            "Value": 1
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                "right": {
                                    "&&": {
                                        "left": {
                                            "<=": {
                                                "left": {
                                                    "Value": 0
                                                },
                                                "right": {
                                                    "Value": 0
                                                }
                                            }
                                        },
                                        "right": {
                                            "!": {
                                                "arg": {
                                                    "<": {
                                                        "left": {
                                                            "Value": 7
                                                        },
                                                        "right": {
                                                            "Value": 1
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        );
        let roundtripped = serde_json::to_value(ast_roundtrip(est.clone())).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
        let roundtripped = serde_json::to_value(circular_roundtrip(est)).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
    }

    #[test]
    fn add_sub_and_mul() {
        let policy = r#"
            permit(principal, action, resource)
            when { 2 + 3 - principal.numFoos * (-10) == 7 };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "==": {
                                "left": {
                                    "-": {
                                        "left": {
                                            "+": {
                                                "left": {
                                                    "Value": 2
                                                },
                                                "right": {
                                                    "Value": 3
                                                }
                                            }
                                        },
                                        "right": {
                                            "*": {
                                                "left": {
                                                    ".": {
                                                        "left": {
                                                            "Var": "principal"
                                                        },
                                                        "attr": "numFoos"
                                                    }
                                                },
                                                "right": {
                                                    "Value": -10
                                                }
                                            }
                                        }
                                    }
                                },
                                "right": {
                                    "Value": 7
                                }
                            }
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        assert_eq!(ast_roundtrip(est.clone()), est);
        assert_eq!(circular_roundtrip(est.clone()), est);
    }

    #[test]
    fn contains_all_any() {
        let policy = r#"
            permit(principal, action, resource)
            when {
                principal.owners.contains("foo")
                && principal.owners.containsAny([1, Linux::Group::"sudoers"])
                && [2+3, "spam"].containsAll(resource.foos)
            };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "&&": {
                                "left": {
                                    "&&": {
                                        "left": {
                                            "contains": {
                                                "left": {
                                                    ".": {
                                                        "left": {
                                                            "Var": "principal"
                                                        },
                                                        "attr": "owners"
                                                    }
                                                },
                                                "right": {
                                                    "Value": "foo"
                                                }
                                            }
                                        },
                                        "right": {
                                            "containsAny": {
                                                "left": {
                                                    ".": {
                                                        "left": {
                                                            "Var": "principal"
                                                        },
                                                        "attr": "owners"
                                                    }
                                                },
                                                "right": {
                                                    "Set": [
                                                        { "Value": 1 },
                                                        { "Value": {
                                                            "__entity": {
                                                                "type": "Linux::Group",
                                                                "id": "sudoers"
                                                            }
                                                        } }
                                                    ]
                                                }
                                            }
                                        }
                                    }
                                },
                                "right": {
                                    "containsAll": {
                                        "left": {
                                            "Set": [
                                                { "+": {
                                                    "left": {
                                                        "Value": 2
                                                    },
                                                    "right": {
                                                        "Value": 3
                                                    }
                                                } },
                                                { "Value": "spam" },
                                            ]
                                        },
                                        "right": {
                                            ".": {
                                                "left": {
                                                    "Var": "resource"
                                                },
                                                "attr": "foos"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        assert_eq!(ast_roundtrip(est.clone()), est);
        assert_eq!(circular_roundtrip(est.clone()), est);
    }

    #[test]
    fn has_like_and_if() {
        let policy = r#"
            permit(principal, action, resource)
            when {
                if context.foo
                then principal has "-78/%$!"
                else resource.email like "*@amazon.com"
            };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "if-then-else": {
                                "if": {
                                    ".": {
                                        "left": {
                                            "Var": "context"
                                        },
                                        "attr": "foo"
                                    }
                                },
                                "then": {
                                    "has": {
                                        "left": {
                                            "Var": "principal"
                                        },
                                        "attr": "-78/%$!"
                                    }
                                },
                                "else": {
                                    "like": {
                                        "left": {
                                            ".": {
                                                "left": {
                                                    "Var": "resource"
                                                },
                                                "attr": "email"
                                            }
                                        },
                                        "pattern": "*@amazon.com"
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        assert_eq!(ast_roundtrip(est.clone()), est);
        assert_eq!(circular_roundtrip(est.clone()), est);
    }

    #[test]
    fn decimal() {
        let policy = r#"
            permit(principal, action, resource)
            when {
                context.confidenceScore.greaterThan(decimal("10.0"))
            };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "greaterThan": [
                                {
                                    ".": {
                                        "left": {
                                            "Var": "context"
                                        },
                                        "attr": "confidenceScore"
                                    }
                                },
                                {
                                    "decimal": [
                                        {
                                            "Value": "10.0"
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        assert_eq!(ast_roundtrip(est.clone()), est);
        assert_eq!(circular_roundtrip(est.clone()), est);
    }

    #[test]
    fn ip() {
        let policy = r#"
            permit(principal, action, resource)
            when {
                context.source_ip.isInRange(ip("222.222.222.0/24"))
            };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "isInRange": [
                                {
                                    ".": {
                                        "left": {
                                            "Var": "context"
                                        },
                                        "attr": "source_ip"
                                    }
                                },
                                {
                                    "ip": [
                                        {
                                            "Value": "222.222.222.0/24"
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        assert_eq!(ast_roundtrip(est.clone()), est);
        assert_eq!(circular_roundtrip(est.clone()), est);
    }

    #[test]
    fn multiple_clauses() {
        let policy = r#"
            permit(principal, action, resource)
            when { context.foo }
            unless { context.bar }
            when { principal.eggs };
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            ".": {
                                "left": {
                                    "Var": "context"
                                },
                                "attr": "foo"
                            }
                        }
                    },
                    {
                        "kind": "unless",
                        "body": {
                            ".": {
                                "left": {
                                    "Var": "context"
                                },
                                "attr": "bar"
                            }
                        }
                    },
                    {
                        "kind": "when",
                        "body": {
                            ".": {
                                "left": {
                                    "Var": "principal"
                                },
                                "attr": "eggs"
                            }
                        }
                    }
                ]
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        // during the lossy transform to AST, the multiple clauses on this policy are
        // combined into a single `when` clause
        let expected_json_after_roundtrip = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All",
                },
                "action": {
                    "op": "All",
                },
                "resource": {
                    "op": "All",
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "&&": {
                                "left": {
                                    "&&": {
                                        "left": {
                                            ".": {
                                                "left": {
                                                    "Var": "context"
                                                },
                                                "attr": "foo"
                                            }
                                        },
                                        "right": {
                                            "!": {
                                                "arg": {
                                                    ".": {
                                                        "left": {
                                                            "Var": "context"
                                                        },
                                                        "attr": "bar"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                "right": {
                                    ".": {
                                        "left": {
                                            "Var": "principal"
                                        },
                                        "attr": "eggs"
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        );
        let roundtripped = serde_json::to_value(ast_roundtrip(est.clone())).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
        let roundtripped = serde_json::to_value(circular_roundtrip(est)).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
    }

    #[test]
    fn instantiate() {
        let template = r#"
            permit(
                principal == ?principal,
                action == Action::"view",
                resource in ?resource
            ) when {
                principal in resource.owners
            };
        "#;
        let cst = parser::text_to_cst::parse_policy(template)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let err = est
            .clone()
            .link(&HashMap::from_iter([]))
            .expect_err("didn't fill all the slots");
        assert_eq!(
            err,
            InstantiationError::MissedSlot {
                slot: ast::SlotId::principal()
            }
        );
        let err = est
            .clone()
            .link(&HashMap::from_iter([(
                ast::SlotId::principal(),
                EntityUidJson::new("XYZCorp::User", "12UA45"),
            )]))
            .expect_err("didn't fill all the slots");
        assert_eq!(
            err,
            InstantiationError::MissedSlot {
                slot: ast::SlotId::resource()
            }
        );
        let linked = est
            .link(&HashMap::from_iter([
                (
                    ast::SlotId::principal(),
                    EntityUidJson::new("XYZCorp::User", "12UA45"),
                ),
                (ast::SlotId::resource(), EntityUidJson::new("Folder", "abc")),
            ]))
            .expect("did fill all the slots");
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "==",
                    "entity": { "type": "XYZCorp::User", "id": "12UA45" },
                },
                "action": {
                    "op": "==",
                    "entity": { "type": "Action", "id": "view" },
                },
                "resource": {
                    "op": "in",
                    "entity": { "type": "Folder", "id": "abc" },
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "in": {
                                "left": {
                                    "Var": "principal"
                                },
                                "right": {
                                    ".": {
                                        "left": {
                                            "Var": "resource"
                                        },
                                        "attr": "owners"
                                    }
                                }
                            }
                        }
                    }
                ],
            }
        );
        let linked_json = serde_json::to_value(linked).unwrap();
        assert_eq!(
            linked_json,
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&linked_json).unwrap(),
        );
    }

    #[test]
    fn eid_with_nulls() {
        let policy = r#"
            permit(
                principal == a::"\0\0\0J",
                action == Action::"view",
                resource
            );
        "#;
        let cst = parser::text_to_cst::parse_policy(policy)
            .unwrap()
            .node
            .unwrap();
        let est: Policy = cst.try_into().unwrap();
        let expected_json = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "==",
                    "entity": {
                        "type": "a",
                        "id": "\0\0\0J",
                    }
                },
                "action": {
                    "op": "==",
                    "entity": {
                        "type": "Action",
                        "id": "view",
                    }
                },
                "resource": {
                    "op": "All"
                },
                "conditions": []
            }
        );
        assert_eq!(
            serde_json::to_value(&est).unwrap(),
            expected_json,
            "\nExpected:\n{}\n\nActual:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json).unwrap(),
            serde_json::to_string_pretty(&est).unwrap()
        );
        let old_est = est.clone();
        let roundtripped = est_roundtrip(est);
        assert_eq!(&old_est, &roundtripped);
        let est = text_roundtrip(&old_est);
        assert_eq!(&old_est, &est);

        // during the lossy transform to AST, the only difference for this policy is that
        // a `when { true }` is added
        let expected_json_after_roundtrip = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "==",
                    "entity": {
                        "type": "a",
                        "id": "\0\0\0J",
                    }
                },
                "action": {
                    "op": "==",
                    "entity": {
                        "type": "Action",
                        "id": "view",
                    }
                },
                "resource": {
                    "op": "All"
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "Value": true
                        }
                    }
                ]
            }
        );
        let roundtripped = serde_json::to_value(ast_roundtrip(est.clone())).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
        let roundtripped = serde_json::to_value(circular_roundtrip(est)).unwrap();
        assert_eq!(
            roundtripped,
            expected_json_after_roundtrip,
            "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
            serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
            serde_json::to_string_pretty(&roundtripped).unwrap()
        );
    }

    #[test]
    fn invalid_json_ests() {
        let bad = json!(
            {
                "effect": "Permit",
                "principal": {
                    "op": "All"
                },
                "action": {
                    "op": "All"
                },
                "resource": {
                    "op": "All"
                },
                "conditions": []
            }
        );
        let est: Result<Policy, _> = serde_json::from_value(bad);
        assert_matches!(est, Err(_)); // `Permit` cannot be capitalized

        let bad = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All"
                },
                "action": {
                    "op": "All"
                },
                "resource": {
                    "op": "All"
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {}
                    }
                ]
            }
        );
        let est: Policy = serde_json::from_value(bad).unwrap();
        let ast: Result<ast::Policy, _> = est.try_into_ast_policy(None);
        assert_matches!(ast, Err(FromJsonError::MissingOperator));

        let bad = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "All"
                },
                "action": {
                    "op": "All"
                },
                "resource": {
                    "op": "All"
                },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "+": {
                                "left": {
                                    "Value": 3
                                },
                                "right": {
                                    "Value": 4
                                }
                            },
                            "-": {
                                "left": {
                                    "Value": 2
                                },
                                "right": {
                                    "Value": 8
                                }
                            }
                        }
                    }
                ]
            }
        );
        let est: Result<Policy, _> = serde_json::from_value(bad);
        assert_matches!(est, Err(_)); // two expressions in body, not connected

        let template = json!(
            {
                "effect": "permit",
                "principal": {
                    "op": "==",
                    "slot": "?principal",
                },
                "action": {
                    "op": "All"
                },
                "resource": {
                    "op": "All"
                },
                "conditions": []
            }
        );
        let est: Policy = serde_json::from_value(template).unwrap();
        let ast: Result<ast::Policy, _> = est.try_into_ast_policy(None);
        assert_matches!(
            ast,
            Err(FromJsonError::TemplateToPolicy(
                ast::UnexpectedSlotError::FoundSlot(s)
            )) => assert_eq!(s, ast::SlotId::principal())
        );
    }

    #[test]
    fn record_duplicate_key() {
        let bad = r#"
            {
                "effect": "permit",
                "principal": { "op": "All" },
                "action": { "op": "All" },
                "resource": { "op": "All" },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "Record": {
                                "foo": {"Value": 0},
                                "foo": {"Value": 1}
                            }
                        }
                    }
                ]
            }
        "#;
        let est: Result<Policy, _> = serde_json::from_str(bad);
        assert_matches!(est, Err(_));
    }

    #[test]
    fn value_record_duplicate_key() {
        let bad = r#"
            {
                "effect": "permit",
                "principal": { "op": "All" },
                "action": { "op": "All" },
                "resource": { "op": "All" },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "Value": {
                                "foo": 0,
                                "foo": 1
                            }
                        }
                    }
                ]
            }
        "#;
        let est: Result<Policy, _> = serde_json::from_str(bad);
        assert_matches!(est, Err(_));
    }

    #[test]
    fn duplicate_annotations() {
        let bad = r#"
            {
                "effect": "permit",
                "principal": { "op": "All" },
                "action": { "op": "All" },
                "resource": { "op": "All" },
                "conditions": [],
                "annotations": {
                    "foo": "bar",
                    "foo": "baz"
                }
            }
        "#;
        let est: Result<Policy, _> = serde_json::from_str(bad);
        assert_matches!(est, Err(_));
    }

    #[test]
    fn extension_duplicate_keys() {
        let bad = r#"
            {
                "effect": "permit",
                "principal": { "op": "All" },
                "action": { "op": "All" },
                "resource": { "op": "All" },
                "conditions": [
                    {
                        "kind": "when",
                        "body": {
                            "ip": [
                                {
                                    "Value": "222.222.222.0/24"
                                }
                            ],
                            "ip": [
                                {
                                    "Value": "111.111.111.0/24"
                                }
                            ]
                        }
                    }
                ]
            }
        "#;
        let est: Result<Policy, _> = serde_json::from_str(bad);
        assert_matches!(est, Err(_));
    }

    mod is_type {
        use cool_asserts::assert_panics;

        use super::*;

        #[test]
        fn principal() {
            let policy = r"permit(principal is User, action, resource);";
            let cst = parser::text_to_cst::parse_policy(policy)
                .unwrap()
                .node
                .unwrap();
            let est: Policy = cst.try_into().unwrap();
            let expected_json = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "is",
                        "entity_type": "User"
                    },
                    "action": {
                        "op": "All",
                    },
                    "resource": {
                        "op": "All",
                    },
                    "conditions": [ ]
                }
            );
            assert_eq!(
                serde_json::to_value(&est).unwrap(),
                expected_json,
                "\nExpected:\n{}\n\nActual:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json).unwrap(),
                serde_json::to_string_pretty(&est).unwrap()
            );
            let old_est = est.clone();
            let roundtripped = est_roundtrip(est);
            assert_eq!(&old_est, &roundtripped);
            let est = text_roundtrip(&old_est);
            assert_eq!(&old_est, &est);

            let expected_json_after_roundtrip = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "is",
                        "entity_type": "User"
                    },
                    "action": {
                        "op": "All",
                    },
                    "resource": {
                        "op": "All",
                    },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "Value": true
                            }
                        }
                    ],
                }
            );
            let roundtripped = serde_json::to_value(ast_roundtrip(est.clone())).unwrap();
            assert_eq!(
                roundtripped,
                expected_json_after_roundtrip,
                "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
                serde_json::to_string_pretty(&roundtripped).unwrap()
            );
            let roundtripped = serde_json::to_value(circular_roundtrip(est)).unwrap();
            assert_eq!(
                roundtripped,
                expected_json_after_roundtrip,
                "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
                serde_json::to_string_pretty(&roundtripped).unwrap()
            );
        }

        #[test]
        fn resource() {
            let policy = r"permit(principal, action, resource is Log);";
            let cst = parser::text_to_cst::parse_policy(policy)
                .unwrap()
                .node
                .unwrap();
            let est: Policy = cst.try_into().unwrap();
            let expected_json = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "All",
                    },
                    "action": {
                        "op": "All",
                    },
                    "resource": {
                        "op": "is",
                        "entity_type": "Log"
                    },
                    "conditions": [ ]
                }
            );
            assert_eq!(
                serde_json::to_value(&est).unwrap(),
                expected_json,
                "\nExpected:\n{}\n\nActual:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json).unwrap(),
                serde_json::to_string_pretty(&est).unwrap()
            );
            let old_est = est.clone();
            let roundtripped = est_roundtrip(est);
            assert_eq!(&old_est, &roundtripped);
            let est = text_roundtrip(&old_est);
            assert_eq!(&old_est, &est);

            let expected_json_after_roundtrip = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "All",
                    },
                    "action": {
                        "op": "All",
                    },
                    "resource": {
                        "op": "is",
                        "entity_type": "Log"
                    },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "Value": true
                            }
                        }
                    ],
                }
            );
            let roundtripped = serde_json::to_value(ast_roundtrip(est.clone())).unwrap();
            assert_eq!(
                roundtripped,
                expected_json_after_roundtrip,
                "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
                serde_json::to_string_pretty(&roundtripped).unwrap()
            );
            let roundtripped = serde_json::to_value(circular_roundtrip(est)).unwrap();
            assert_eq!(
                roundtripped,
                expected_json_after_roundtrip,
                "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
                serde_json::to_string_pretty(&roundtripped).unwrap()
            );
        }

        #[test]
        fn principal_in_entity() {
            let policy = r#"permit(principal is User in Group::"admin", action, resource);"#;
            let cst = parser::text_to_cst::parse_policy(policy)
                .unwrap()
                .node
                .unwrap();
            let est: Policy = cst.try_into().unwrap();
            let expected_json = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "is",
                        "entity_type": "User",
                        "in": { "entity": { "type": "Group", "id": "admin" } }
                    },
                    "action": {
                        "op": "All",
                    },
                    "resource": {
                        "op": "All",
                    },
                    "conditions": [ ]
                }
            );
            assert_eq!(
                serde_json::to_value(&est).unwrap(),
                expected_json,
                "\nExpected:\n{}\n\nActual:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json).unwrap(),
                serde_json::to_string_pretty(&est).unwrap()
            );
            let old_est = est.clone();
            let roundtripped = est_roundtrip(est);
            assert_eq!(&old_est, &roundtripped);
            let est = text_roundtrip(&old_est);
            assert_eq!(&old_est, &est);

            let expected_json_after_roundtrip = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "is",
                        "entity_type": "User",
                        "in": { "entity": { "type": "Group", "id": "admin" } }
                    },
                    "action": {
                        "op": "All",
                    },
                    "resource": {
                        "op": "All",
                    },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "Value": true
                            }
                        }
                    ],
                }
            );
            let roundtripped = serde_json::to_value(ast_roundtrip(est.clone())).unwrap();
            assert_eq!(
                roundtripped,
                expected_json_after_roundtrip,
                "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
                serde_json::to_string_pretty(&roundtripped).unwrap()
            );
            let roundtripped = serde_json::to_value(circular_roundtrip(est)).unwrap();
            assert_eq!(
                roundtripped,
                expected_json_after_roundtrip,
                "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
                serde_json::to_string_pretty(&roundtripped).unwrap()
            );
        }

        #[test]
        fn principal_in_slot() {
            let policy = r#"permit(principal is User in ?principal, action, resource);"#;
            let cst = parser::text_to_cst::parse_policy(policy)
                .unwrap()
                .node
                .unwrap();
            let est: Policy = cst.try_into().unwrap();
            let expected_json = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "is",
                        "entity_type": "User",
                        "in": { "slot": "?principal" }
                    },
                    "action": {
                        "op": "All",
                    },
                    "resource": {
                        "op": "All",
                    },
                    "conditions": [ ]
                }
            );
            assert_eq!(
                serde_json::to_value(&est).unwrap(),
                expected_json,
                "\nExpected:\n{}\n\nActual:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json).unwrap(),
                serde_json::to_string_pretty(&est).unwrap()
            );
            let old_est = est.clone();
            let roundtripped = est_roundtrip(est);
            assert_eq!(&old_est, &roundtripped);
            let est = text_roundtrip(&old_est);
            assert_eq!(&old_est, &est);

            let expected_json_after_roundtrip = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "is",
                        "entity_type": "User",
                        "in": { "slot": "?principal" }
                    },
                    "action": {
                        "op": "All",
                    },
                    "resource": {
                        "op": "All",
                    },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "Value": true
                            }
                        }
                    ],
                }
            );
            let roundtripped = serde_json::to_value(ast_roundtrip_template(est.clone())).unwrap();
            assert_eq!(
                roundtripped,
                expected_json_after_roundtrip,
                "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
                serde_json::to_string_pretty(&roundtripped).unwrap()
            );
            let roundtripped = serde_json::to_value(circular_roundtrip_template(est)).unwrap();
            assert_eq!(
                roundtripped,
                expected_json_after_roundtrip,
                "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
                serde_json::to_string_pretty(&roundtripped).unwrap()
            );
        }

        #[test]
        fn condition() {
            let policy = r#"
            permit(principal, action, resource)
            when { principal is User };"#;
            let cst = parser::text_to_cst::parse_policy(policy)
                .unwrap()
                .node
                .unwrap();
            let est: Policy = cst.try_into().unwrap();
            let expected_json = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "All",
                    },
                    "action": {
                        "op": "All",
                    },
                    "resource": {
                        "op": "All",
                    },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "is": {
                                    "left": {
                                        "Var": "principal"
                                    },
                                    "entity_type": "User",
                                }
                            }
                        }
                    ]
                }
            );
            assert_eq!(
                serde_json::to_value(&est).unwrap(),
                expected_json,
                "\nExpected:\n{}\n\nActual:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json).unwrap(),
                serde_json::to_string_pretty(&est).unwrap()
            );
            let old_est = est.clone();
            let roundtripped = est_roundtrip(est);
            assert_eq!(&old_est, &roundtripped);
            let est = text_roundtrip(&old_est);
            assert_eq!(&old_est, &est);

            assert_eq!(ast_roundtrip(est.clone()), est);
            assert_eq!(circular_roundtrip(est.clone()), est);
        }

        #[test]
        fn condition_in() {
            let policy = r#"
            permit(principal, action, resource)
            when { principal is User in 1 };"#;
            let cst = parser::text_to_cst::parse_policy(policy)
                .unwrap()
                .node
                .unwrap();
            let est: Policy = cst.try_into().unwrap();
            let expected_json = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "All",
                    },
                    "action": {
                        "op": "All",
                    },
                    "resource": {
                        "op": "All",
                    },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "is": {
                                    "left": { "Var": "principal" },
                                    "entity_type": "User",
                                    "in": {"Value": 1}
                                }
                            }
                        }
                    ]
                }
            );
            assert_eq!(
                serde_json::to_value(&est).unwrap(),
                expected_json,
                "\nExpected:\n{}\n\nActual:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json).unwrap(),
                serde_json::to_string_pretty(&est).unwrap()
            );
            let old_est = est.clone();
            let roundtripped = est_roundtrip(est);
            assert_eq!(&old_est, &roundtripped);
            let est = text_roundtrip(&old_est);
            assert_eq!(&old_est, &est);

            let expected_json_after_roundtrip = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "All",
                    },
                    "action": {
                        "op": "All",
                    },
                    "resource": {
                        "op": "All",
                    },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "&&": {
                                    "left": {
                                        "is": {
                                            "left": { "Var": "principal" },
                                            "entity_type": "User",
                                        }
                                    },
                                    "right": {
                                        "in": {
                                            "left": { "Var": "principal" },
                                            "right": { "Value": 1}
                                        }
                                    }
                                }
                            }
                        }
                    ],
                }
            );
            let roundtripped = serde_json::to_value(ast_roundtrip_template(est.clone())).unwrap();
            assert_eq!(
                roundtripped,
                expected_json_after_roundtrip,
                "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
                serde_json::to_string_pretty(&roundtripped).unwrap()
            );
            let roundtripped = serde_json::to_value(circular_roundtrip_template(est)).unwrap();
            assert_eq!(
                roundtripped,
                expected_json_after_roundtrip,
                "\nExpected after roundtrip:\n{}\n\nActual after roundtrip:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json_after_roundtrip).unwrap(),
                serde_json::to_string_pretty(&roundtripped).unwrap()
            );
        }

        #[test]
        fn invalid() {
            let bad = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "is"
                    },
                    "action": {
                        "op": "All"
                    },
                    "resource": {
                        "op": "All"
                    },
                    "conditions": []
                }
            );
            assert_panics!(
                serde_json::from_value::<Policy>(bad).unwrap(),
                includes("missing field `entity_type`"),
            );

            let bad = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "is",
                        "entity_type": "!"
                    },
                    "action": {
                        "op": "All"
                    },
                    "resource": {
                        "op": "All"
                    },
                    "conditions": []
                }
            );
            assert_matches!(
                serde_json::from_value::<Policy>(bad)
                    .unwrap()
                    .try_into_ast_policy(None),
                Err(FromJsonError::InvalidEntityType(_)),
            );

            let bad = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "is",
                        "entity_type": "User",
                        "==": {"entity": { "type": "User", "id": "alice"}}
                    },
                    "action": {
                        "op": "All"
                    },
                    "resource": {
                        "op": "All"
                    },
                    "conditions": []
                }
            );
            assert_panics!(
                serde_json::from_value::<Policy>(bad).unwrap(),
                includes("unknown field `==`, expected `entity_type` or `in`"),
            );

            let bad = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "All",
                    },
                    "action": {
                        "op": "is",
                        "entity_type": "Action"
                    },
                    "resource": {
                        "op": "All"
                    },
                    "conditions": []
                }
            );
            assert_panics!(
                serde_json::from_value::<Policy>(bad).unwrap(),
                includes("unknown variant `is`, expected one of `All`, `==`, `in`"),
            );
        }

        #[test]
        fn instantiate() {
            let template = r#"
            permit(
                principal is User in ?principal,
                action,
                resource is Doc in ?resource
            );
        "#;
            let cst = parser::text_to_cst::parse_policy(template)
                .unwrap()
                .node
                .unwrap();
            let est: Policy = cst.try_into().unwrap();
            let err = est.clone().link(&HashMap::from_iter([]));
            assert_eq!(
                err,
                Err(InstantiationError::MissedSlot {
                    slot: ast::SlotId::principal()
                })
            );
            let err = est.clone().link(&HashMap::from_iter([(
                ast::SlotId::principal(),
                EntityUidJson::new("User", "alice"),
            )]));
            assert_eq!(
                err,
                Err(InstantiationError::MissedSlot {
                    slot: ast::SlotId::resource()
                })
            );
            let linked = est
                .link(&HashMap::from_iter([
                    (
                        ast::SlotId::principal(),
                        EntityUidJson::new("User", "alice"),
                    ),
                    (ast::SlotId::resource(), EntityUidJson::new("Folder", "abc")),
                ]))
                .expect("did fill all the slots");
            let expected_json = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "is",
                        "entity_type": "User",
                        "in": { "entity": { "type": "User", "id": "alice" } }
                    },
                    "action": {
                        "op": "All"
                    },
                    "resource": {
                        "op": "is",
                        "entity_type": "Doc",
                        "in": { "entity": { "type": "Folder", "id": "abc" } }
                    },
                    "conditions": [ ],
                }
            );
            let linked_json = serde_json::to_value(linked).unwrap();
            assert_eq!(
                linked_json,
                expected_json,
                "\nExpected:\n{}\n\nActual:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json).unwrap(),
                serde_json::to_string_pretty(&linked_json).unwrap(),
            );
        }

        #[test]
        fn instantiate_no_slot() {
            let template = r#"permit(principal is User, action, resource is Doc);"#;
            let cst = parser::text_to_cst::parse_policy(template)
                .unwrap()
                .node
                .unwrap();
            let est: Policy = cst.try_into().unwrap();
            let linked = est.link(&HashMap::new()).unwrap();
            let expected_json = json!(
                {
                    "effect": "permit",
                    "principal": {
                        "op": "is",
                        "entity_type": "User",
                    },
                    "action": {
                        "op": "All"
                    },
                    "resource": {
                        "op": "is",
                        "entity_type": "Doc",
                    },
                    "conditions": [ ],
                }
            );
            let linked_json = serde_json::to_value(linked).unwrap();
            assert_eq!(
                linked_json,
                expected_json,
                "\nExpected:\n{}\n\nActual:\n{}\n\n",
                serde_json::to_string_pretty(&expected_json).unwrap(),
                serde_json::to_string_pretty(&linked_json).unwrap(),
            );
        }
    }
}
