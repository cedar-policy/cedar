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

//! Stack-safe computation of AST expression depth.
//!
//! We need this in addition to CST depth to limit the depth of polices parsed
//! form JSON via the EST. `serde_json` applies it own depth limit by default,
//! but multiple `when` clauses which we encode as a flat JSON array are
//! deserialized as `&&` expressions which could exceed available stack space.

use super::{Expr, ExprKind};

impl<T> Expr<T> {
    /// The number of edges on the longest path to a leaf
    pub fn depth(&self) -> usize {
        let mut max = 0;
        let mut stack = vec![(self, 0)];
        while let Some((expr, depth)) = stack.pop() {
            max = max.max(depth);
            expr.push_children(depth + 1, &mut stack);
        }
        max
    }

    /// Push the immediate subexpressions of `self` onto `stack` with `depth`
    fn push_children<'a>(&'a self, depth: usize, stack: &mut Vec<(&'a Self, usize)>) {
        match self.expr_kind() {
            ExprKind::Lit(_) | ExprKind::Var(_) | ExprKind::Slot(_) | ExprKind::Unknown(_) => {}
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => stack.extend([
                (test_expr.as_ref(), depth),
                (then_expr.as_ref(), depth),
                (else_expr.as_ref(), depth),
            ]),
            ExprKind::And { left, right } | ExprKind::Or { left, right } => {
                stack.extend([(left.as_ref(), depth), (right.as_ref(), depth)])
            }
            ExprKind::UnaryApp { arg, .. } => stack.push((arg, depth)),
            ExprKind::BinaryApp { arg1, arg2, .. } => {
                stack.extend([(arg1.as_ref(), depth), (arg2.as_ref(), depth)])
            }
            ExprKind::GetAttr { expr, .. }
            | ExprKind::HasAttr { expr, .. }
            | ExprKind::ExtHasAttr { expr, .. }
            | ExprKind::Like { expr, .. }
            | ExprKind::Is { expr, .. } => stack.push((expr, depth)),
            ExprKind::ExtensionFunctionApp { args, .. } | ExprKind::Set(args) => {
                stack.extend(args.iter().map(|arg| (arg, depth)))
            }
            ExprKind::Record(fields) => stack.extend(fields.values().map(|v| (v, depth))),
            #[cfg(feature = "tolerant-ast")]
            ExprKind::Error { .. } => {}
        }
    }
}

/// The depth of `c1 && (c2 && (...))`, given the depths of each `ci`, which is
/// how a policy's conditions are combined. `None` if there are no conditions.
pub(crate) fn conjunction_depth(depths: &[usize]) -> Option<usize> {
    depths
        .iter()
        .enumerate()
        .map(|(i, depth)| {
            let assoc_depth = if i + 1 == depths.len() { i } else { i + 1 };
            depth + assoc_depth
        })
        .max()
}

#[cfg(test)]
mod tests {
    use crate::parser::parse_expr;

    #[test]
    fn depth() {
        assert_eq!(parse_expr("1").unwrap().depth(), 0);
        assert_eq!(parse_expr("1 + 2").unwrap().depth(), 1);
        assert_eq!(parse_expr("[1, [2]]").unwrap().depth(), 2);
        assert_eq!(parse_expr("{a: {b: 1}}").unwrap().depth(), 2);
        assert_eq!(parse_expr("1 != 2").unwrap().depth(), 2);
    }
}
