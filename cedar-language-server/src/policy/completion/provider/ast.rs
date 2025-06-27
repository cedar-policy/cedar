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

use std::sync::Arc;

use cedar_policy_core::{
    ast::{BinaryOp, EntityType, Expr, ExprVisitor, Literal, Pattern},
    parser::Loc,
};
use smol_str::SmolStr;

use crate::{
    policy::{
        context::{
            AttrContext, AttrContextKind, BinaryOpContext, InKind, IsContext, Op, ReceiverContext,
        },
        CompletionContextKind, DocumentContext,
    },
    utils::is_cursor_in_condition_braces,
};

/// A visitor implementation for gathering completion information from Cedar policy expressions.
///
/// This visitor traverses the Cedar AST to identify the expression context at the cursor position
/// within policy condition blocks(the `when/unless {...}` section of a policy) and determines what kind
/// of completions should be offered to the user.
pub(crate) struct ConditionCompletionVisitor<'a> {
    cx: &'a DocumentContext<'a>,
}

impl<'a> ConditionCompletionVisitor<'a> {
    /// Creates a new completion visitor with the given document context.
    fn new(document_context: &'a DocumentContext<'_>) -> Self {
        Self {
            cx: document_context,
        }
    }

    /// Analyzes the current policy and cursor position to determine the appropriate completion context.
    ///
    /// This is the main entry point for obtaining completion suggestions based on where the
    /// cursor is positioned within a Cedar policy's conditions.
    pub(crate) fn get_completion_context(
        document_context: &DocumentContext<'_>,
    ) -> CompletionContextKind {
        let expr = document_context.policy.non_scope_constraints();
        if !is_cursor_in_condition_braces(
            document_context.cursor_position,
            document_context.policy_text,
        ) {
            return CompletionContextKind::None;
        }

        let mut visitor = ConditionCompletionVisitor::new(document_context);
        let kind = visitor
            .visit_expr(expr)
            .unwrap_or(CompletionContextKind::Unknown);

        let word = document_context
            .get_word_under_cursor()
            // Filters out the typing of entity euid literals as to not provide suggestions for it
            .filter(|w| !w.contains(':'));

        match kind {
            // Must type a character to get suggestions within empty when blocks or after a completion
            CompletionContextKind::Unknown if word.is_some() => {
                CompletionContextKind::ConditionDefault
            }
            kind => kind,
        }
    }

    fn visit_attr(
        &mut self,
        expr: &Arc<Expr>,
        attr: &SmolStr,
        loc: Option<&Loc>,
        context: AttrContextKind,
    ) -> Option<<Self as ExprVisitor>::Output> {
        self.visit_expr(expr).or_else(|| {
            let word = self.cx.get_word_under_cursor();
            // If cursor is within attribute and matches the current attribute name (or empty attribute)
            if self.cx.is_cursor_over_loc(loc) && (attr.is_empty() || word == Some(attr)) {
                return CompletionContextKind::Attr(AttrContext::new(
                    ReceiverContext::new(expr.clone()),
                    context,
                ))
                .into();
            }
            None
        })
    }
}

impl ExprVisitor for ConditionCompletionVisitor<'_> {
    type Output = CompletionContextKind;

    fn visit_literal(
        &mut self,
        lit: &cedar_policy_core::ast::Literal,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        if let Some(loc) = loc {
            // Check if cursor is within the literal
            if self.cx.is_cursor_over_loc(loc) {
                // We're specifically interested in EntityUID literals for action completions
                if let Literal::EntityUID(entity_uid) = lit {
                    let word = self.cx.get_word_under_cursor();
                    if word == Some(entity_uid.eid().escaped().as_str()) {
                        return CompletionContextKind::EntityLiteral {
                            entity_uid: entity_uid.clone(),
                        }
                        .into();
                    }
                }

                if let Literal::String(..) = lit {
                    return CompletionContextKind::None.into();
                }
            }
        } else {
            // Fall back to entity ID location for action completion in policy scope
            if let Literal::EntityUID(entity_uid) = lit {
                return self
                    .visit_literal(&Literal::EntityUID(entity_uid.clone()), entity_uid.loc());
            }
        }
        None
    }

    fn visit_is(
        &mut self,
        expr: &Arc<Expr>,
        entity_type: &EntityType,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        self.visit_expr(expr).or_else(|| {
            if let Some(loc) = loc {
                if self.cx.is_cursor_over_loc(loc) {
                    let word = self.cx.get_word_under_cursor();
                    if word == Some(&entity_type.to_string()) {
                        return CompletionContextKind::Is(IsContext::new(ReceiverContext::new(
                            expr.clone(),
                        )))
                        .into();
                    }
                }
            }
            None
        })
    }

    fn visit_binary_op(
        &mut self,
        op: cedar_policy_core::ast::BinaryOp,
        arg1: &Arc<Expr>,
        arg2: &Arc<Expr>,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        // Try to get completions from either operand first
        self.visit_expr(arg1)
            .or_else(|| self.visit_expr(arg2))
            .or_else(|| {
                if let Some(loc) = loc {
                    // Determine which side needs completion
                    let complete_right_side = !arg1
                        .source_loc()
                        .is_some_and(|loc| self.cx.is_cursor_over_loc(loc));

                    let (other_side_expr, complete_side_expr) = if complete_right_side {
                        (arg1.clone(), arg2.clone())
                    } else {
                        (arg2.clone(), arg1.clone())
                    };

                    if self.cx.is_cursor_over_loc(loc) {
                        match op {
                            BinaryOp::In => {
                                let kind = if complete_side_expr
                                    .source_loc()
                                    .and_then(|loc| loc.snippet())
                                    .is_some_and(|snip| snip.contains('[') && snip.contains(']'))
                                {
                                    InKind::ArrayLiteral
                                } else {
                                    InKind::Entity
                                };
                                return CompletionContextKind::BinaryOp(BinaryOpContext {
                                    op: Op::In(kind),
                                    other_side_expr,
                                    complete_side_expr,
                                })
                                .into();
                            }
                            BinaryOp::Eq => {
                                return CompletionContextKind::BinaryOp(BinaryOpContext {
                                    op: Op::Eq,
                                    other_side_expr,
                                    complete_side_expr,
                                })
                                .into()
                            }
                            _ => (),
                        }
                    }
                }

                None
            })
    }

    fn visit_has_attr(
        &mut self,
        expr: &Arc<Expr>,
        attr: &SmolStr,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        self.visit_attr(expr, attr, loc, AttrContextKind::Has)
    }

    fn visit_get_attr(
        &mut self,
        expr: &Arc<Expr>,
        attr: &SmolStr,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        self.visit_attr(expr, attr, loc, AttrContextKind::Get)
    }

    fn visit_like(
        &mut self,
        expr: &Arc<Expr>,
        pattern: &Pattern,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        self.visit_expr(expr).or_else(|| {
            let word = self.cx.get_word_under_cursor();
            let pat = pattern.to_string();
            if self.cx.is_cursor_over_loc(loc)
                && (word == Some(pat.as_str()) || word.is_none() && pat.is_empty())
            {
                return CompletionContextKind::None.into();
            }
            None
        })
    }
}
