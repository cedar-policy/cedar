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

//! A capability-propagating traversal shared by the lints that reason about what a
//! `has`/`hasTag` guard establishes at each point in a condition.
//!
//! Several lints — attribute-guard checks, tag-guard checks, and the
//! disjunction-split soundness check — walk a condition threading a
//! [`CapabilitySet`] down the boolean structure: `&&` makes its left's positive
//! capabilities hold for its right, `||` makes its left's *negative* capabilities
//! hold for its right (so `!(e has a) || e.a` is guarded), `if` splits the test's
//! capabilities across the branches, and `!` swaps positive and negative. That
//! plumbing is identical across the lints and is exactly what the validator's
//! capability analysis does; only what each *node* establishes and checks differs.
//!
//! [`walk_capabilities`] owns the plumbing. A lint supplies one closure,
//! `on_node`, called at every non-boolean node with the capabilities in force
//! there; it reports whatever it wants (by side effect) and returns the
//! capabilities that node establishes (its positive half; [`CapabilitySet::negate`]
//! reads the negative half). The boolean connectives (`&&`, `||`, `if`, `!`) are
//! handled here and do not call `on_node` — their established capabilities come
//! from folding their operands'.

use crate::ast::{Expr, ExprKind, UnaryOp};
use crate::linter::util::direct_children;
use crate::validator::types::CapabilitySet;

/// Walk `expr` under the capabilities `caps` already establishes, threading
/// capabilities through the boolean structure and calling `on_node` at every other
/// node. Returns the capabilities `expr` itself establishes.
///
/// See the [module docs](self) for the short-circuiting rules. `on_node` receives
/// each non-boolean node and the capabilities in force when it is evaluated, and
/// returns what that node establishes (a `has`/`hasTag` yields its capability;
/// everything else yields [`CapabilitySet::new`]).
pub(crate) fn walk_capabilities<'a>(
    expr: &'a Expr,
    caps: &CapabilitySet<'a>,
    on_node: &mut impl FnMut(&'a Expr, &CapabilitySet<'a>) -> CapabilitySet<'a>,
) -> CapabilitySet<'a> {
    match expr.expr_kind() {
        ExprKind::And { left, right } => {
            let l = walk_capabilities(left, caps, on_node);
            // `&&` short-circuits: the right is reached only when the left is true,
            // so under the left's positive capabilities.
            let r = walk_capabilities(right, &caps.clone().and(&l), on_node);
            l.and(&r)
        }
        ExprKind::Or { left, right } => {
            let l = walk_capabilities(left, caps, on_node);
            // `||` short-circuits the other way: the right is reached only when the
            // left is false, so under the left's *negation*.
            let r = walk_capabilities(right, &caps.clone().and(&l.clone().negate()), on_node);
            l.or(&r)
        }
        ExprKind::If {
            test_expr,
            then_expr,
            else_expr,
        } => {
            let test = walk_capabilities(test_expr, caps, on_node);
            // Each branch is reached only for one value of the test.
            let then = walk_capabilities(then_expr, &caps.clone().and(&test), on_node);
            let els = walk_capabilities(
                else_expr,
                &caps.clone().and(&test.clone().negate()),
                on_node,
            );
            test.clone().and(&then).or(&test.negate().and(&els))
        }
        ExprKind::UnaryApp {
            op: UnaryOp::Not,
            arg,
        } => walk_capabilities(arg, caps, on_node).negate(),
        // Every other node: its children are all evaluated under the same
        // capabilities (no short-circuiting establishes anything between them), so
        // recurse into each for its side effects — a child's *established*
        // capabilities are usable only by a boolean connective, so they are
        // discarded here — then ask this node what it establishes.
        _ => {
            for child in direct_children(expr) {
                walk_capabilities(child, caps, on_node);
            }
            on_node(expr, caps)
        }
    }
}
