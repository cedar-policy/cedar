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

use yaspar_macros::stack_safe;

use super::{Expr, ExprKind};

impl<T> Expr<T> {
    /// The number of edges on the longest path to a leaf
    ///
    /// This doesn't necessarily need to be `stack_safe` because it runs after
    /// `serde_json` imposes its depth limit.
    #[stack_safe]
    pub fn depth(&self) -> usize {
        let mut d = 0;
        for child in Self::children(self) {
            d = d.max(1 + child.depth());
        }
        d
    }

    /// The immediate subexpressions of `expr`
    fn children(&self) -> Vec<&Expr<T>> {
        match self.expr_kind() {
            ExprKind::Lit(_) | ExprKind::Var(_) | ExprKind::Slot(_) | ExprKind::Unknown(_) => {
                vec![]
            }
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => vec![&test_expr, &then_expr, &else_expr],
            ExprKind::And { left, right } | ExprKind::Or { left, right } => vec![&left, &right],
            ExprKind::UnaryApp { arg, .. } => vec![&arg],
            ExprKind::BinaryApp { arg1, arg2, .. } => vec![&arg1, &arg2],
            ExprKind::GetAttr { expr, .. }
            | ExprKind::HasAttr { expr, .. }
            | ExprKind::ExtHasAttr { expr, .. }
            | ExprKind::Like { expr, .. }
            | ExprKind::Is { expr, .. } => vec![&expr],
            ExprKind::ExtensionFunctionApp { args, .. } | ExprKind::Set(args) => {
                args.iter().collect()
            }
            ExprKind::Record(fields) => fields.values().collect(),
            #[cfg(feature = "tolerant-ast")]
            ExprKind::Error { .. } => vec![],
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
