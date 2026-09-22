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

//! Helpers shared by more than one linter pass.

use crate::ast::{BinaryOp, Expr, ExprKind, Literal, UnaryOp};
use crate::linter::findings::Finding;

/// Scan every subexpression of `expr`, map each through `check`, and return the
/// findings it produced in source order.
///
/// This is the shape almost every schema-free expression lint has: walk the whole
/// AST, decide at each node whether it is a finding, and report in the order the
/// policy reads. [`Expr::subexpressions`](crate::ast::Expr::subexpressions) yields
/// in reverse source order and includes `expr` itself, so this collects then sorts
/// by source offset. A lint only has to supply the per-node predicate, free of the
/// walk-collect-sort boilerplate.
pub(crate) fn scan(expr: &Expr, check: impl Fn(&Expr) -> Option<Finding>) -> Vec<Finding> {
    scan_many(expr, |e| check(e).into_iter().collect())
}

/// Like [`scan`], but for the passes where one node can yield *several* findings
/// (e.g. every duplicated element of a set literal). Each subexpression maps to a
/// `Vec<Finding>`; all are flattened and sorted by source order.
pub(crate) fn scan_many(expr: &Expr, check: impl Fn(&Expr) -> Vec<Finding>) -> Vec<Finding> {
    let mut findings: Vec<Finding> = expr.subexpressions().flat_map(|e| check(e)).collect();
    findings.sort_by_key(|f| f.source_loc().map(|l| l.span.offset()));
    findings
}

/// The immediate sub-expressions of `expr` — one step down, not recursive.
///
/// Shared by the passes that walk the AST by hand (rather than via
/// [`Expr::subexpressions`](crate::ast::Expr::subexpressions)) because they must
/// treat some node kinds specially, e.g. tracking `&&` capabilities.
pub(crate) fn direct_children(expr: &Expr) -> Box<dyn Iterator<Item = &Expr> + '_> {
    match expr.expr_kind() {
        ExprKind::If {
            test_expr,
            then_expr,
            else_expr,
        } => Box::new([test_expr.as_ref(), then_expr.as_ref(), else_expr.as_ref()].into_iter()),
        ExprKind::And { left, right } | ExprKind::Or { left, right } => {
            Box::new([left.as_ref(), right.as_ref()].into_iter())
        }
        ExprKind::UnaryApp { arg, .. } => Box::new(std::iter::once(arg.as_ref())),
        ExprKind::BinaryApp { arg1, arg2, .. } => {
            Box::new([arg1.as_ref(), arg2.as_ref()].into_iter())
        }
        ExprKind::GetAttr { expr, .. } | ExprKind::HasAttr { expr, .. } => {
            Box::new(std::iter::once(expr.as_ref()))
        }
        ExprKind::Like { expr, .. } | ExprKind::Is { expr, .. } => {
            Box::new(std::iter::once(expr.as_ref()))
        }
        ExprKind::ExtensionFunctionApp { args, .. } => Box::new(args.iter()),
        ExprKind::Set(elems) => Box::new(elems.iter()),
        ExprKind::Record(map) => Box::new(map.values()),
        _ => Box::new(std::iter::empty()),
    }
}

/// Is `expr` a constant, i.e. does its value not depend on the request or entity
/// store?
///
/// This is purely syntactic and deliberately conservative: it recognizes
/// literals and operators applied to constants, so `1 + 1`, `[true, false]`, and
/// `"a" == "b"` are constant, but `context.n - context.n` is not (even though it
/// is mathematically fixed). A `false` answer never means "definitely varies", it
/// means "not recognized as constant".
///
/// Extension calls and record/set construction over constants could in principle
/// be constant too, but they are excluded: an extension constructor can fail
/// (`ip("bad")`), and a record's *value* being constant is rarely what a lint
/// cares about.
///
/// Generic over the AST annotation `T` so it works on both a bare
/// [`Expr`](crate::ast::Expr) and a type-annotated `Expr<Option<Type>>` — it only
/// inspects `expr_kind()`, which does not depend on the annotation.
pub(crate) fn is_constant<T: Clone>(expr: &crate::ast::Expr<T>) -> bool {
    match expr.expr_kind() {
        ExprKind::Lit(_) => true,
        // A set of constants is a constant, so `x in [A, B]` with constant
        // elements has a constant right operand.
        ExprKind::Set(elems) => elems.iter().all(is_constant),
        // Operators are constant exactly when all their operands are.
        ExprKind::UnaryApp { arg, .. } => is_constant(arg),
        ExprKind::BinaryApp { arg1, arg2, .. } => is_constant(arg1) && is_constant(arg2),
        ExprKind::And { left, right } | ExprKind::Or { left, right } => {
            is_constant(left) && is_constant(right)
        }
        ExprKind::If {
            test_expr,
            then_expr,
            else_expr,
        } => is_constant(test_expr) && is_constant(then_expr) && is_constant(else_expr),
        // `like` and `is` against a constant target are constant.
        ExprKind::Like { expr, .. } | ExprKind::Is { expr, .. } => is_constant(expr),
        // Everything else — variables, slots, attribute access, extension calls,
        // records, unknowns — is not recognized as constant.
        _ => false,
    }
}

/// Is `expr` a constant integer expression, i.e. one whose value doesn't depend
/// on the request or entity store?
///
/// Note this is purely syntactic: `context.n - context.n` is mathematically
/// constant but not recognized as such.
pub(crate) fn is_constant_arithmetic(expr: &Expr) -> bool {
    match expr.expr_kind() {
        ExprKind::Lit(Literal::Long(_)) => true,
        // `-5` parses as a negation of a literal rather than a negative literal.
        ExprKind::UnaryApp {
            op: UnaryOp::Neg,
            arg,
        } => is_constant_arithmetic(arg),
        // Arithmetic over constants is itself constant.
        ExprKind::BinaryApp {
            op: BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul,
            arg1,
            arg2,
        } => is_constant_arithmetic(arg1) && is_constant_arithmetic(arg2),
        _ => false,
    }
}
