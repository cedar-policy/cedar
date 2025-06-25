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
    ast::{BinaryOp, EntityType, Expr, ExprKind, ExprVisitor, Literal, Pattern, UnaryOp, Var},
    parser::Loc,
};
use lsp_types::Hover;
use smol_str::SmolStr;

use crate::{
    documentation::{
        ActionDocumentation, AndDocumentation, ContextDocumentation, ExtensionName,
        GreaterThanDocumentation, GreaterThanOrEqualsDocumentation, HasDocumentation,
        IfDocumentation, IsDocumentation, LikeDocumentation, NotEqualsDocumentation,
        OrDocumentation, PrincipalDocumentation, ResourceDocumentation,
    },
    policy::{
        types::{
            cedar::{CedarTypeKind, EntityTypeKind},
            DocumentContext, Token,
        },
        GetType,
    },
};

use super::ToHover;

/// Provides hover documentation for Cedar policy expressions.
///
/// The `HoverVisitor` traverses the Cedar AST to find the expression under the cursor
/// and generate appropriate hover documentation based on the expression type, operator,
/// or keyword. It implements the visitor pattern to analyze different expression types
/// and determine what documentation to display.
pub(crate) struct HoverVisitor<'a> {
    token_under_cursor: Token<'a>,
    doc_context: &'a DocumentContext<'a>,
}

impl<'a> HoverVisitor<'a> {
    pub(crate) fn new(cx: &'a DocumentContext<'_>) -> Self {
        HoverVisitor {
            token_under_cursor: cx.get_token_under_cursor().unwrap_or_else(|| {
                Token::Word(cx.get_char_at_position().unwrap_or_default().to_string())
            }),
            doc_context: cx,
        }
    }
}

impl ExprVisitor for HoverVisitor<'_> {
    type Output = Hover;

    fn visit_literal(&mut self, lit: &Literal, loc: Option<&Loc>) -> Option<Self::Output> {
        if self.doc_context.is_cursor_over_loc(loc) {
            let cedar_type = match lit {
                Literal::Bool(bool) if bool.to_string() == self.token_under_cursor => {
                    CedarTypeKind::Bool
                }
                Literal::Long(l) if l.to_string() == self.token_under_cursor => CedarTypeKind::Long,
                Literal::String(str)
                    if str.to_string().contains(self.token_under_cursor.inner()) =>
                {
                    CedarTypeKind::String
                }
                Literal::EntityUID(euid)
                    if euid.to_string().contains(self.token_under_cursor.inner()) =>
                {
                    euid.as_ref().into()
                }
                _ => return None,
            };
            return cedar_type.to_hover(self.doc_context);
        }
        None
    }

    fn visit_var(&mut self, var: Var, loc: Option<&Loc>) -> Option<Self::Output> {
        if self.doc_context.is_cursor_over_loc(loc) && self.token_under_cursor == var.to_string() {
            return match var {
                Var::Principal => {
                    PrincipalDocumentation::new(self.doc_context.resolve_principal_type())
                        .to_hover(self.doc_context)
                }
                Var::Action => {
                    ActionDocumentation::new(Some(self.doc_context.policy.action_constraint()))
                        .to_hover(self.doc_context)
                }
                Var::Resource => {
                    ResourceDocumentation::new(self.doc_context.resolve_resource_type())
                        .to_hover(self.doc_context)
                }
                Var::Context => {
                    ContextDocumentation::from(self.doc_context).to_hover(self.doc_context)
                }
            };
        }

        None
    }

    fn visit_get_attr(
        &mut self,
        expr: &Arc<Expr>,
        attr: &SmolStr,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        // First, check if we're within the overall expression's range
        // Get the word at the cursor position
        // If the cursor word matches the current attribute
        if self.doc_context.is_cursor_over_loc(loc) && self.token_under_cursor == attr.as_str() {
            return expr
                .expr_kind()
                .get_type(self.doc_context)
                .and_then(|ty| ty.attribute_type(attr, self.doc_context.schema()))
                .and_then(|ty| ty.to_hover(self.doc_context));
        }

        // Continue traversing the left side of the expression
        self.visit_expr(expr)
    }

    fn visit_unary_app(
        &mut self,
        op: UnaryOp,
        arg: &Arc<Expr>,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        if op == UnaryOp::Not {
            if let ExprKind::BinaryApp { op: bin_op, .. } = arg.expr_kind() {
                if self.doc_context.is_cursor_over_loc(arg.source_loc()) {
                    match bin_op {
                        BinaryOp::Less if self.token_under_cursor == ">=" => {
                            return GreaterThanOrEqualsDocumentation.to_hover(self.doc_context)
                        }
                        BinaryOp::LessEq if self.token_under_cursor == ">" => {
                            return GreaterThanDocumentation.to_hover(self.doc_context)
                        }
                        BinaryOp::Eq if self.token_under_cursor == "!=" => {
                            return NotEqualsDocumentation.to_hover(self.doc_context)
                        }
                        _ => {}
                    }
                }
            }
        }

        if self.doc_context.is_cursor_over_loc(loc) && self.token_under_cursor == op.to_string() {
            return op.to_hover(self.doc_context);
        }

        self.visit_expr(arg)
    }

    fn visit_binary_op(
        &mut self,
        op: BinaryOp,
        arg1: &Arc<Expr>,
        arg2: &Arc<Expr>,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        if self.doc_context.is_cursor_over_loc(loc) && self.token_under_cursor == op.to_string() {
            return op.to_hover(self.doc_context);
        }
        self.visit_expr(arg1).or_else(|| self.visit_expr(arg2))
    }

    fn visit_is(
        &mut self,
        expr: &Arc<Expr>,
        entity_type: &EntityType,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        if self.doc_context.is_cursor_over_loc(entity_type.loc())
            && self.token_under_cursor == entity_type.to_string()
        {
            return CedarTypeKind::EntityType(EntityTypeKind::Concrete(entity_type.clone().into()))
                .to_hover(self.doc_context);
        }

        if self.doc_context.is_cursor_over_loc(loc) && self.token_under_cursor == "is" {
            return IsDocumentation.to_hover(self.doc_context);
        }

        self.visit_expr(expr)
    }

    fn visit_extension_function(
        &mut self,
        fn_name: &cedar_policy_core::ast::Name,
        args: &Arc<Vec<Expr>>,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        if self.doc_context.is_cursor_over_loc(loc)
            && self.token_under_cursor == fn_name.to_string()
        {
            return ExtensionName(&fn_name.to_string()).to_hover(self.doc_context);
        }

        for arg in args.iter() {
            if let Some(output) = self.visit_expr(arg) {
                return Some(output);
            }
        }
        None
    }

    fn visit_has_attr(
        &mut self,
        expr: &Arc<Expr>,
        attr: &SmolStr,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        if self.doc_context.is_cursor_over_loc(loc)
            && !self.doc_context.is_cursor_over_loc(expr.source_loc())
            && self.token_under_cursor == "has"
        {
            return HasDocumentation.to_hover(self.doc_context);
        }

        if self.doc_context.is_cursor_over_loc(loc) && self.token_under_cursor == attr.as_str() {
            return expr
                .expr_kind()
                .get_type(self.doc_context)
                .and_then(|ty| ty.attribute_type(attr, self.doc_context.schema()))
                .and_then(|ty| ty.to_hover(self.doc_context));
        }

        self.visit_expr(expr)
    }

    fn visit_and(
        &mut self,
        left: &Arc<Expr>,
        right: &Arc<Expr>,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        if self.doc_context.is_cursor_over_loc(loc)
            && !self.doc_context.is_cursor_over_loc(left.source_loc())
            && !self.doc_context.is_cursor_over_loc(right.source_loc())
            && self.token_under_cursor == "&&"
        {
            return AndDocumentation.to_hover(self.doc_context);
        }

        self.visit_expr(left).or_else(|| self.visit_expr(right))
    }

    fn visit_or(
        &mut self,
        left: &Arc<Expr>,
        right: &Arc<Expr>,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        if self.doc_context.is_cursor_over_loc(loc)
            && !self.doc_context.is_cursor_over_loc(left.source_loc())
            && !self.doc_context.is_cursor_over_loc(right.source_loc())
            && self.token_under_cursor == "||"
        {
            return OrDocumentation.to_hover(self.doc_context);
        }

        self.visit_expr(left).or_else(|| self.visit_expr(right))
    }

    fn visit_if(
        &mut self,
        test_expr: &Arc<Expr>,
        then_expr: &Arc<Expr>,
        else_expr: &Arc<Expr>,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        let is_if_keyword = self.token_under_cursor == "if"
            || self.token_under_cursor == "then"
            || self.token_under_cursor == "else";
        if self.doc_context.is_cursor_over_loc(loc)
            && !self.doc_context.is_cursor_over_loc(test_expr.source_loc())
            && !self.doc_context.is_cursor_over_loc(then_expr.source_loc())
            && !self.doc_context.is_cursor_over_loc(else_expr.source_loc())
            && is_if_keyword
        {
            return IfDocumentation.to_hover(self.doc_context);
        }
        self.visit_expr(test_expr)
            .or_else(|| self.visit_expr(then_expr))
            .or_else(|| self.visit_expr(else_expr))
    }

    fn visit_like(
        &mut self,
        expr: &Arc<Expr>,
        _pattern: &Pattern,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        self.visit_expr(expr).or_else(|| {
            if self.doc_context.is_cursor_over_loc(loc) && self.token_under_cursor == "like" {
                return LikeDocumentation.to_hover(self.doc_context);
            }
            None
        })
    }
}
