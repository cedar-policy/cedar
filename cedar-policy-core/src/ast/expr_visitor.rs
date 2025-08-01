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

use std::{collections::BTreeMap, sync::Arc};

use crate::{
    ast::{
        BinaryOp, EntityType, Expr, ExprKind, Literal, Name, Pattern, SlotId, UnaryOp, Unknown, Var,
    },
    parser::Loc,
};
use smol_str::SmolStr;

/// A visitor trait for traversing Cedar Policy Abstract Syntax Trees (ASTs).
///
/// This trait enables type-safe traversal of Cedar policy expressions in the language server.
/// Implementers can selectively override methods to process specific expression types
/// while inheriting default behavior for others.
///
/// # Usage
///
/// Implement this trait and override the methods for the expression types you want to process.
///
/// # Traversal Behavior
///
/// By default, the visitor will traverse the expression tree depth-first, stopping and
/// returning the first non-None result. Implementers can override this behavior by
/// providing custom implementations for specific visit methods.
pub trait ExprVisitor {
    /// The output type for this visitor.
    ///
    /// By default, one a `visit_*` function returns `Some`, this visitor will
    /// return that value from `visit_expr`.
    type Output;

    /// Entry point for visiting an expression.
    ///
    /// This is typically called to begin traversal and dispatches to the
    /// relevant `visit_*` functions based on the expression kind.
    fn visit_expr(&mut self, expr: &Expr) -> Option<Self::Output> {
        let loc = expr.source_loc();
        match expr.expr_kind() {
            ExprKind::Lit(lit) => self.visit_literal(lit, loc),
            ExprKind::Var(var) => self.visit_var(*var, loc),
            ExprKind::Slot(slot) => self.visit_slot(slot.clone(), loc),
            ExprKind::Unknown(unknown) => self.visit_unknown(unknown, loc),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => self.visit_if(test_expr, then_expr, else_expr, loc),
            ExprKind::And { left, right } => self.visit_and(left, right, loc),
            ExprKind::Or { left, right } => self.visit_or(left, right, loc),
            ExprKind::UnaryApp { op, arg } => self.visit_unary_app(*op, arg, loc),
            ExprKind::BinaryApp { op, arg1, arg2 } => self.visit_binary_op(*op, arg1, arg2, loc),
            ExprKind::ExtensionFunctionApp { fn_name, args } => {
                self.visit_extension_function(fn_name, args, loc)
            }
            ExprKind::GetAttr { expr, attr } => self.visit_get_attr(expr, attr, loc),
            ExprKind::HasAttr { expr, attr } => self.visit_has_attr(expr, attr, loc),
            ExprKind::Like { expr, pattern } => self.visit_like(expr, pattern, loc),
            ExprKind::Is { expr, entity_type } => self.visit_is(expr, entity_type, loc),
            ExprKind::Set(elements) => self.visit_set(elements, loc),
            ExprKind::Record(fields) => self.visit_record(fields, loc),
            #[cfg(feature = "tolerant-ast")]
            ExprKind::Error { error_kind } => self.visit_error(error_kind),
        }
    }

    /// Visits a literal expression (string, number, boolean, etc.).
    fn visit_literal(&mut self, _lit: &Literal, _loc: Option<&Loc>) -> Option<Self::Output> {
        None
    }

    /// Visits a variable reference (principal, resource, action, context).
    fn visit_var(&mut self, _var: Var, _loc: Option<&Loc>) -> Option<Self::Output> {
        None
    }

    /// Visits a slot reference in a policy template.
    fn visit_slot(&mut self, _slot: SlotId, _loc: Option<&Loc>) -> Option<Self::Output> {
        None
    }

    /// Visits an unknown value for partial evaluation
    fn visit_unknown(&mut self, _unknown: &Unknown, _loc: Option<&Loc>) -> Option<Self::Output> {
        None
    }

    /// Visits an if-then-else conditional expression.
    ///
    /// Recursively visits the condition, then branch, and else branch.
    fn visit_if(
        &mut self,
        test_expr: &Arc<Expr>,
        then_expr: &Arc<Expr>,
        else_expr: &Arc<Expr>,
        _loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        self.visit_expr(test_expr)
            .or_else(|| self.visit_expr(then_expr))
            .or_else(|| self.visit_expr(else_expr))
    }

    /// Visits a logical AND expression.
    ///
    /// Recursively visits the left and right operands.
    fn visit_and(
        &mut self,
        left: &Arc<Expr>,
        right: &Arc<Expr>,
        _loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        self.visit_expr(left).or_else(|| self.visit_expr(right))
    }

    /// Visits a logical OR expression.
    ///
    /// Recursively visits the left and right operands.
    fn visit_or(
        &mut self,
        left: &Arc<Expr>,
        right: &Arc<Expr>,
        _loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        self.visit_expr(left).or_else(|| self.visit_expr(right))
    }

    /// Visits a unary operation (like negation).
    ///
    /// Recursively visits the operand.
    fn visit_unary_app(
        &mut self,
        _op: UnaryOp,
        arg: &Arc<Expr>,
        _loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        self.visit_expr(arg)
    }

    /// Visits a binary operation (like comparison or arithmetic).
    ///
    /// Recursively visits both operands.
    fn visit_binary_op(
        &mut self,
        _op: BinaryOp,
        arg1: &Arc<Expr>,
        arg2: &Arc<Expr>,
        _loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        self.visit_expr(arg1).or_else(|| self.visit_expr(arg2))
    }

    /// Visits an extension function call (like `ip()`).
    ///
    /// Recursively visits each argument.
    fn visit_extension_function(
        &mut self,
        _fn_name: &Name,
        args: &Arc<Vec<Expr>>,
        _loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        for arg in args.iter() {
            if let Some(output) = self.visit_expr(arg) {
                return Some(output);
            }
        }
        None
    }

    /// Visits an attribute access expression (e.g., `expr.attr`).
    ///
    /// Recursively visits the target expression.
    fn visit_get_attr(
        &mut self,
        expr: &Arc<Expr>,
        _attr: &SmolStr,
        _loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        self.visit_expr(expr)
    }

    /// Visits an attribute existence check (e.g., `expr has attr`).
    ///
    /// Recursively visits the target expression.
    fn visit_has_attr(
        &mut self,
        expr: &Arc<Expr>,
        _attr: &SmolStr,
        _loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        self.visit_expr(expr)
    }

    /// Visits a pattern-matching expression (e.g., `expr like "pat"`).
    ///
    /// Recursively visits the target expression.
    fn visit_like(
        &mut self,
        expr: &Arc<Expr>,
        _pattern: &Pattern,
        _loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        self.visit_expr(expr)
    }

    /// Visits a type-checking expression (e.g., `principal is User`).
    ///
    /// Recursively visits the target expression.
    fn visit_is(
        &mut self,
        expr: &Arc<Expr>,
        _entity_type: &EntityType,
        _loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        self.visit_expr(expr)
    }

    /// Visits a set literal expression (e.g., `[1, 2, 3]`).
    ///
    /// Recursively visits each element in the set.
    fn visit_set(&mut self, elements: &Arc<Vec<Expr>>, _loc: Option<&Loc>) -> Option<Self::Output> {
        for element in elements.iter() {
            if let Some(output) = self.visit_expr(element) {
                return Some(output);
            }
        }
        None
    }

    /// Visits a record literal expression (e.g., `{ "key": value }`).
    ///
    /// Recursively visits the value of each field in the record.
    fn visit_record(
        &mut self,
        fields: &Arc<BTreeMap<SmolStr, Expr>>,
        _loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        for expr in fields.values() {
            if let Some(output) = self.visit_expr(expr) {
                return Some(output);
            }
        }
        None
    }

    /// Visits the AST node representing a parse error.
    #[cfg(feature = "tolerant-ast")]
    fn visit_error(
        &mut self,
        _error_kind: &crate::ast::expr_allows_errors::AstExprErrorKind,
    ) -> Option<Self::Output> {
        None
    }
}

#[cfg(test)]
mod test {
    use crate::ast::{Expr, ExprVisitor};

    /// Simple implementation of `ExprVisitor` to test the default trait
    /// function implementations.
    struct VarLitCountingVisitor {
        count_var: u32,
        count_lit: u32,
    }

    impl VarLitCountingVisitor {
        fn new() -> Self {
            Self {
                count_var: 0,
                count_lit: 0,
            }
        }
    }

    impl ExprVisitor for VarLitCountingVisitor {
        type Output = ();

        fn visit_var(
            &mut self,
            _var: crate::ast::Var,
            _loc: Option<&crate::parser::Loc>,
        ) -> Option<Self::Output> {
            self.count_var += 1;
            None
        }

        fn visit_literal(
            &mut self,
            _lit: &crate::ast::Literal,
            _loc: Option<&crate::parser::Loc>,
        ) -> Option<Self::Output> {
            self.count_lit += 1;
            None
        }
    }

    #[test]
    fn visits_if() {
        let e: Expr = "if true then principal else false".parse().unwrap();
        let mut v = VarLitCountingVisitor::new();
        v.visit_expr(&e);
        assert_eq!(v.count_lit, 2);
        assert_eq!(v.count_var, 1);
    }

    #[test]
    fn visits_and() {
        let e: Expr = "principal && 1".parse().unwrap();
        let mut v = VarLitCountingVisitor::new();
        v.visit_expr(&e);
        assert_eq!(v.count_lit, 1);
        assert_eq!(v.count_var, 1);
    }

    #[test]
    fn visits_or() {
        let e: Expr = "principal || 1".parse().unwrap();
        let mut v = VarLitCountingVisitor::new();
        v.visit_expr(&e);
        assert_eq!(v.count_lit, 1);
        assert_eq!(v.count_var, 1);
    }

    #[test]
    fn visits_unary() {
        let e: Expr = "! 1".parse().unwrap();
        let mut v = VarLitCountingVisitor::new();
        v.visit_expr(&e);
        assert_eq!(v.count_lit, 1);
        assert_eq!(v.count_var, 0);
    }

    #[test]
    fn visits_binary() {
        let e: Expr = "1 + principal".parse().unwrap();
        let mut v = VarLitCountingVisitor::new();
        v.visit_expr(&e);
        assert_eq!(v.count_lit, 1);
        assert_eq!(v.count_var, 1);
    }

    #[test]
    fn visits_extension() {
        let e: Expr = r#"ip("192.168.1.1")"#.parse().unwrap();
        let mut v = VarLitCountingVisitor::new();
        v.visit_expr(&e);
        assert_eq!(v.count_lit, 1);
        assert_eq!(v.count_var, 0);
    }

    #[test]
    fn visits_get_attr() {
        let e: Expr = "principal.foo".parse().unwrap();
        let mut v = VarLitCountingVisitor::new();
        v.visit_expr(&e);
        assert_eq!(v.count_lit, 0);
        assert_eq!(v.count_var, 1);
    }

    #[test]
    fn visits_has_attr() {
        let e: Expr = "principal has foo".parse().unwrap();
        let mut v = VarLitCountingVisitor::new();
        v.visit_expr(&e);
        assert_eq!(v.count_lit, 0);
        assert_eq!(v.count_var, 1);
    }

    #[test]
    fn visits_like() {
        let e: Expr = r#""foo" like "*""#.parse().unwrap();
        let mut v = VarLitCountingVisitor::new();
        v.visit_expr(&e);
        assert_eq!(v.count_lit, 1);
        assert_eq!(v.count_var, 0);
    }

    #[test]
    fn visits_is() {
        let e: Expr = "principal is User".parse().unwrap();
        let mut v = VarLitCountingVisitor::new();
        v.visit_expr(&e);
        assert_eq!(v.count_lit, 0);
        assert_eq!(v.count_var, 1);
    }

    #[test]
    fn visits_set() {
        let e: Expr = "[1,principal,false,context]".parse().unwrap();
        let mut v = VarLitCountingVisitor::new();
        v.visit_expr(&e);
        assert_eq!(v.count_lit, 2);
        assert_eq!(v.count_var, 2);
    }

    #[test]
    fn visits_record() {
        let e: Expr = "{a: principal, b: false, c: 100, d: context}"
            .parse()
            .unwrap();
        let mut v = VarLitCountingVisitor::new();
        v.visit_expr(&e);
        assert_eq!(v.count_lit, 2);
        assert_eq!(v.count_var, 2);
    }
}
