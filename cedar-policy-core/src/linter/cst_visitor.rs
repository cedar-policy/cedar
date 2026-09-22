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

//! A traversal for the CST, so that lints reading it don't each re-implement one.
//!
//! Some lints have to read the CST rather than the AST, because the parser
//! desugars: `a != b` becomes `!(a == b)`, `a > b` becomes `!(a <= b)`. The CST is
//! the only place the author's actual spelling survives.
//!
//! The cost is that the CST is shaped by the grammar's precedence layers rather
//! than by meaning. A single comparison is an [`Or`] holding an [`And`] holding a
//! [`Relation`] holding an [`Add`] holding a [`Mult`] holding a [`Unary`] holding
//! a [`Member`] holding a [`Primary`] — eight levels, each of which a lint has to
//! walk through to reach anything, and each of which is a
//! [`Node<Option<T>>`](Node) that may be absent when the parse partially failed.
//!
//! [`CstVisitor`] does that walk once. A lint implements the handful of methods
//! for nodes it cares about and calls the matching `walk_*` free function to keep
//! descending — or doesn't, to prune. Every method has a default that just
//! descends, so a lint interested in one node kind writes one method.
//!
//! # Example
//!
//! A lint that counts parenthesized expressions:
//!
//! ```ignore
//! struct CountParens(usize);
//!
//! impl CstVisitor for CountParens {
//!     fn visit_primary(&mut self, p: &Node<Option<Primary>>) {
//!         if matches!(p.as_inner(), Some(Primary::Expr(_))) {
//!             self.0 += 1;
//!         }
//!         walk_primary(self, p); // keep descending
//!     }
//! }
//! ```
//!
//! # What the traversal covers
//!
//! One policy's `when`/`unless` clauses, via [`CstVisitor::visit_policy`]. A lint
//! over a whole policy set drives it per policy, since findings are tagged with
//! the policy they came from. The
//! scope is deliberately excluded: it holds constraints, not arbitrary
//! expressions, and a lint that wants it can read
//! [`PolicyImpl::variables`](crate::parser::cst::PolicyImpl) directly.
//!
//! Absent (`None`) nodes terminate that branch rather than being reported: a
//! partial parse is the parser's error to report, not a lint's.

use crate::parser::{
    cst::{
        Add, And, Cond, Expr, ExprData, MemAccess, Member, Mult, Or, Policy, Primary, RecInit,
        Relation, Unary,
    },
    Node,
};

/// A visitor over the expression part of a policy CST.
///
/// Every method defaults to descending via the corresponding `walk_*` function,
/// so an implementor overrides only what it needs. To keep descending from an
/// override, call that `walk_*`; to prune, don't.
#[allow(unused_variables)]
pub(crate) trait CstVisitor: Sized {
    /// Visit one policy. The default visits its `when`/`unless` clauses.
    fn visit_policy(&mut self, policy: &Node<Option<Policy>>) {
        walk_policy(self, policy);
    }

    /// Visit one `when` or `unless` clause.
    ///
    /// `is_when` distinguishes them, since `unless` negates its expression and a
    /// lint may care.
    fn visit_cond(&mut self, cond: &Node<Option<Cond>>, is_when: bool) {
        walk_cond(self, cond, is_when);
    }

    fn visit_expr(&mut self, expr: &Node<Option<Expr>>) {
        walk_expr(self, expr);
    }

    /// Visit an `if`/`then`/`else`. Called in addition to
    /// [`CstVisitor::visit_expr`] for the same node, so a lint can match on the
    /// shape without unpacking [`ExprData`] itself.
    fn visit_if(
        &mut self,
        expr: &Node<Option<Expr>>,
        cond: &Node<Option<Expr>>,
        then_expr: &Node<Option<Expr>>,
        else_expr: &Node<Option<Expr>>,
    ) {
        walk_if(self, cond, then_expr, else_expr);
    }

    fn visit_or(&mut self, or: &Node<Option<Or>>) {
        walk_or(self, or);
    }

    fn visit_and(&mut self, and: &Node<Option<And>>) {
        walk_and(self, and);
    }

    fn visit_relation(&mut self, rel: &Node<Option<Relation>>) {
        walk_relation(self, rel);
    }

    fn visit_add(&mut self, add: &Node<Option<Add>>) {
        walk_add(self, add);
    }

    fn visit_mult(&mut self, mult: &Node<Option<Mult>>) {
        walk_mult(self, mult);
    }

    fn visit_unary(&mut self, unary: &Node<Option<Unary>>) {
        walk_unary(self, unary);
    }

    fn visit_member(&mut self, member: &Node<Option<Member>>) {
        walk_member(self, member);
    }

    fn visit_primary(&mut self, primary: &Node<Option<Primary>>) {
        walk_primary(self, primary);
    }
}

pub(crate) fn walk_policy<V: CstVisitor>(v: &mut V, policy: &Node<Option<Policy>>) {
    let Some(Policy::Policy(policy)) = policy.as_inner() else {
        return;
    };
    for cond in &policy.conds {
        // The keyword is `when` or `unless`; anything else is a parse error the
        // parser reports, and defaulting to `when` keeps the traversal going.
        let is_when = cond
            .as_inner()
            .and_then(|c| c.cond.as_inner())
            .map(|i| i.to_string() != "unless")
            .unwrap_or(true);
        v.visit_cond(cond, is_when);
    }
}

pub(crate) fn walk_cond<V: CstVisitor>(v: &mut V, cond: &Node<Option<Cond>>, _is_when: bool) {
    // `expr` is `None` only for an empty body, as in `when {}`.
    if let Some(Cond { expr: Some(e), .. }) = cond.as_inner() {
        v.visit_expr(e);
    }
}

pub(crate) fn walk_expr<V: CstVisitor>(v: &mut V, expr: &Node<Option<Expr>>) {
    let Some(Expr::Expr(inner)) = expr.as_inner() else {
        return;
    };
    match &*inner.expr {
        ExprData::Or(or) => v.visit_or(or),
        ExprData::If(cond, then_expr, else_expr) => v.visit_if(expr, cond, then_expr, else_expr),
    }
}

pub(crate) fn walk_if<V: CstVisitor>(
    v: &mut V,
    cond: &Node<Option<Expr>>,
    then_expr: &Node<Option<Expr>>,
    else_expr: &Node<Option<Expr>>,
) {
    v.visit_expr(cond);
    v.visit_expr(then_expr);
    v.visit_expr(else_expr);
}

pub(crate) fn walk_or<V: CstVisitor>(v: &mut V, or: &Node<Option<Or>>) {
    let Some(Or { initial, extended }) = or.as_inner() else {
        return;
    };
    v.visit_and(initial);
    for a in extended {
        v.visit_and(a);
    }
}

pub(crate) fn walk_and<V: CstVisitor>(v: &mut V, and: &Node<Option<And>>) {
    let Some(And { initial, extended }) = and.as_inner() else {
        return;
    };
    v.visit_relation(initial);
    for r in extended {
        v.visit_relation(r);
    }
}

pub(crate) fn walk_relation<V: CstVisitor>(v: &mut V, rel: &Node<Option<Relation>>) {
    match rel.as_inner() {
        Some(Relation::Common { initial, extended }) => {
            v.visit_add(initial);
            for (_, a) in extended {
                v.visit_add(a);
            }
        }
        Some(Relation::Has { target, field }) => {
            v.visit_add(target);
            v.visit_add(field);
        }
        Some(Relation::Like { target, pattern }) => {
            v.visit_add(target);
            v.visit_add(pattern);
        }
        Some(Relation::IsIn {
            target,
            entity_type,
            in_entity,
        }) => {
            v.visit_add(target);
            v.visit_add(entity_type);
            if let Some(e) = in_entity {
                v.visit_add(e);
            }
        }
        None => {}
    }
}

pub(crate) fn walk_add<V: CstVisitor>(v: &mut V, add: &Node<Option<Add>>) {
    let Some(Add { initial, extended }) = add.as_inner() else {
        return;
    };
    v.visit_mult(initial);
    for (_, m) in extended {
        v.visit_mult(m);
    }
}

pub(crate) fn walk_mult<V: CstVisitor>(v: &mut V, mult: &Node<Option<Mult>>) {
    let Some(Mult { initial, extended }) = mult.as_inner() else {
        return;
    };
    v.visit_unary(initial);
    for (_, u) in extended {
        v.visit_unary(u);
    }
}

pub(crate) fn walk_unary<V: CstVisitor>(v: &mut V, unary: &Node<Option<Unary>>) {
    if let Some(Unary { item, .. }) = unary.as_inner() {
        v.visit_member(item);
    }
}

pub(crate) fn walk_member<V: CstVisitor>(v: &mut V, member: &Node<Option<Member>>) {
    let Some(Member { item, access }) = member.as_inner() else {
        return;
    };
    v.visit_primary(item);
    for a in access {
        match a.as_inner() {
            // A method's arguments are expressions; its name is not.
            Some(MemAccess::Call(args)) => {
                for arg in args {
                    v.visit_expr(arg);
                }
            }
            Some(MemAccess::Index(e)) => v.visit_expr(e),
            Some(MemAccess::Field(_)) | None => {}
        }
    }
}

pub(crate) fn walk_primary<V: CstVisitor>(v: &mut V, primary: &Node<Option<Primary>>) {
    match primary.as_inner() {
        // Parentheses are where a nested expression re-enters the grammar.
        Some(Primary::Expr(e)) => v.visit_expr(e),
        Some(Primary::EList(items)) => {
            for i in items {
                v.visit_expr(i);
            }
        }
        Some(Primary::RInits(inits)) => {
            for i in inits {
                if let Some(RecInit(k, val)) = i.as_inner() {
                    v.visit_expr(k);
                    v.visit_expr(val);
                }
            }
        }
        Some(Primary::Literal(_) | Primary::Ref(_) | Primary::Name(_) | Primary::Slot(_))
        | None => {}
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::parser::text_to_cst;

    /// Counts every node kind the traversal reaches, so that a node added to the
    /// CST without a corresponding `walk_*` arm shows up as a gap here.
    #[derive(Default)]
    struct Counts {
        exprs: usize,
        relations: usize,
        primaries: usize,
        conds: usize,
        unless: usize,
    }

    impl CstVisitor for Counts {
        fn visit_cond(&mut self, cond: &Node<Option<Cond>>, is_when: bool) {
            self.conds += 1;
            if !is_when {
                self.unless += 1;
            }
            walk_cond(self, cond, is_when);
        }
        fn visit_expr(&mut self, e: &Node<Option<Expr>>) {
            self.exprs += 1;
            walk_expr(self, e);
        }
        fn visit_relation(&mut self, r: &Node<Option<Relation>>) {
            self.relations += 1;
            walk_relation(self, r);
        }
        fn visit_primary(&mut self, p: &Node<Option<Primary>>) {
            self.primaries += 1;
            walk_primary(self, p);
        }
    }

    #[track_caller]
    fn count(src: &str) -> Counts {
        let cst = text_to_cst::parse_policy(src).expect("failed to parse");
        let mut c = Counts::default();
        c.visit_policy(&cst);
        c
    }

    #[test]
    fn visits_a_simple_condition() {
        let c = count(r#"permit(principal, action, resource) when { context.a };"#);
        assert_eq!(c.conds, 1);
        assert_eq!(c.unless, 0);
        assert_eq!(c.exprs, 1);
        assert_eq!(c.relations, 1);
        assert_eq!(c.primaries, 1);
    }

    /// `unless` is reported as such, which a lint may need since it negates.
    #[test]
    fn distinguishes_when_from_unless() {
        let c = count(r#"permit(principal, action, resource) unless { context.a };"#);
        assert_eq!(c.conds, 1);
        assert_eq!(c.unless, 1);
    }

    #[test]
    fn visits_every_clause() {
        let c = count(
            r#"permit(principal, action, resource) when { context.a } unless { context.b };"#,
        );
        assert_eq!(c.conds, 2);
        assert_eq!(c.unless, 1);
    }

    /// Both operands of `&&` and `||` are reached.
    #[test]
    fn visits_both_sides_of_connectives() {
        let c = count(r#"permit(principal, action, resource) when { context.a && context.b };"#);
        assert_eq!(c.relations, 2);
        let c = count(r#"permit(principal, action, resource) when { context.a || context.b };"#);
        assert_eq!(c.relations, 2);
    }

    /// Parentheses re-enter the grammar, so the inner expression is visited.
    #[test]
    fn descends_into_parentheses() {
        let c = count(r#"permit(principal, action, resource) when { !(context.a == 1) };"#);
        // The outer condition, plus the parenthesized expression.
        assert_eq!(c.exprs, 2);
    }

    /// All three branches of an `if` are visited.
    #[test]
    fn descends_into_if() {
        let c = count(
            r#"permit(principal, action, resource) when { if context.a then context.b else context.c };"#,
        );
        assert_eq!(c.exprs, 4, "the `if` itself plus three branches");
    }

    /// Set and record elements, method arguments, and indexes are all reached.
    #[test]
    fn descends_into_containers_and_calls() {
        let c =
            count(r#"permit(principal, action, resource) when { [context.a, context.b] == [] };"#);
        assert!(c.exprs >= 3, "each element is an expression: {}", c.exprs);

        let c = count(r#"permit(principal, action, resource) when { {x: context.a}.x };"#);
        assert!(c.exprs >= 3, "record key and value: {}", c.exprs);

        let c =
            count(r#"permit(principal, action, resource) when { context.s.contains(context.a) };"#);
        assert!(c.exprs >= 2, "the call argument: {}", c.exprs);
    }

    /// A `has`, `like`, and `is .. in ..` all have their operands visited.
    #[test]
    fn descends_into_relation_forms() {
        let c = count(r#"permit(principal, action, resource) when { context has a };"#);
        assert_eq!(c.relations, 1);
        let c = count(r#"permit(principal, action, resource) when { context.a like "x*" };"#);
        assert_eq!(c.relations, 1);
        let c = count(
            r#"permit(principal, action, resource) when { principal is User in Group::"g" };"#,
        );
        assert_eq!(c.relations, 1);
    }

    /// The scope is not traversed: it holds constraints, not arbitrary
    /// expressions.
    #[test]
    fn does_not_visit_the_scope() {
        let c = count(r#"permit(principal == User::"alice", action, resource);"#);
        assert_eq!(c.conds, 0);
        assert_eq!(c.exprs, 0);
    }

    /// An empty condition body is not a node to visit.
    #[test]
    fn empty_condition_body() {
        let cst = text_to_cst::parse_policy(r#"permit(principal, action, resource) when {};"#);
        // Whether this parses is the parser's business; if it does, the
        // traversal must not panic on the absent expression.
        if let Ok(cst) = cst {
            let mut c = Counts::default();
            c.visit_policy(&cst);
            assert_eq!(c.exprs, 0);
        }
    }

    /// Pruning works: an override that doesn't call `walk_*` stops the descent.
    #[test]
    fn override_can_prune() {
        struct Prune(usize);
        impl CstVisitor for Prune {
            fn visit_expr(&mut self, _: &Node<Option<Expr>>) {
                self.0 += 1;
                // deliberately not descending
            }
        }
        let cst = text_to_cst::parse_policy(
            r#"permit(principal, action, resource) when { !(context.a == 1) };"#,
        )
        .expect("failed to parse");
        let mut p = Prune(0);
        p.visit_policy(&cst);
        assert_eq!(p.0, 1, "should stop at the outermost expression");
    }
}
