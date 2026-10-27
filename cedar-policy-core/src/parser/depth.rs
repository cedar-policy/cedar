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

//! Stack-safe depth computation for CST expressions.

use crate::ast::conjunction_depth;
use crate::parser::{err, Loc};

use super::cst;
use super::node::Node;
use yaspar_macros::stack_safe;

/// Check depth of all condition expressions in a policies CST node.
pub(crate) fn check_policies_depth(
    cst: &Node<Option<cst::Policies>>,
    depth_limit: usize,
) -> Result<(), err::ParseErrors> {
    let Some(policies) = cst.node.as_ref() else {
        return Ok(());
    };
    for policy_node in &policies.0 {
        check_policy_depth(policy_node, depth_limit)?;
    }
    Ok(())
}

/// Check depth of all expressions in a CST policy
pub(crate) fn check_policy_depth(
    cst: &Node<Option<cst::Policy>>,
    depth_limit: usize,
) -> Result<(), err::ParseErrors> {
    let Some(policy) = cst.node.as_ref() else {
        return Ok(());
    };
    let policy_impl = match policy {
        cst::Policy::Policy(p) => p,
        #[cfg(feature = "tolerant-ast")]
        cst::Policy::PolicyError => return Ok(()),
    };
    let mut depths = Vec::new();
    for var in &policy_impl.variables {
        let Some(var) = var.node.as_ref() else {
            continue;
        };
        if let Some(entity_type) = var.entity_type.as_ref() {
            check_depth(add_depth(entity_type), depth_limit, entity_type.loc())?;
        }
        if let Some((_, ineq)) = &var.ineq {
            check_depth(expr_depth(ineq), depth_limit, ineq.loc())?;
        }
        depths.push(scope_depth(var));
    }
    // The policy is converted to `principal && (action && (resource && conditions))`
    depths.push(conds_effective_depth(policy_impl).unwrap_or(0));
    if let Some(depth) = conjunction_depth(&depths) {
        check_depth(depth, depth_limit, cst.loc())?;
    }

    Ok(())
}

/// Depth of the expression a scope constraint is converted to, e.g.,
/// `principal is T in e` becomes `principal is T && principal in e`.
fn scope_depth(var: &cst::VariableDef) -> usize {
    match (&var.entity_type, &var.ineq) {
        (None, None) => 0,
        (Some(_), Some(_)) => 2,
        // `action in e` becomes `action in [e]`
        (None, Some(_)) if matches!(var.variable.node, Some(cst::Ident::Action)) => 2,
        _ => 1,
    }
}

/// Return an error if `depth` exceeds `depth_limit`.
pub(crate) fn check_depth(
    depth: usize,
    depth_limit: usize,
    loc: Option<&Loc>,
) -> Result<(), err::ParseErrors> {
    if depth > depth_limit {
        Err(err::ToASTError::new(
            err::ToASTErrorKind::ExpressionTooDeep {
                depth,
                limit: depth_limit,
            },
            loc.cloned(),
        )
        .into())
    } else {
        Ok(())
    }
}

/// Depth of the expression combining a policy's conditions, or `None` if it has none.
fn conds_effective_depth(policy: &cst::PolicyImpl) -> Option<usize> {
    let cond_depths: Vec<usize> = policy
        .conds
        .iter()
        .filter_map(|cond_node| {
            let cond = cond_node.node.as_ref()?;
            let expr = cond.expr.as_ref()?;
            let depth = expr_depth(expr);
            // `unless { e }` is converted to `!e`
            if matches!(cond.cond.node, Some(cst::Ident::Unless)) {
                Some(depth + 1)
            } else {
                Some(depth)
            }
        })
        .collect();
    conjunction_depth(&cond_depths)
}

/// Same as `node.node.as_ref()`, which fails type inference inside `#[stack_safe]`
fn inner<T>(node: &Node<Option<T>>) -> Option<&T> {
    node.node.as_ref()
}

/// Upper bound on the depth of both the CST and the AST it converts to, which
/// may be deeper (e.g., `a || b || c` becomes `(a || b) || c`).
#[stack_safe]
mod effective_depth {
    use super::{cst, inner, Node};

    pub(crate) fn expr_depth(expr_node: &Node<Option<cst::Expr>>) -> usize {
        let Some(expr) = expr_node.node.as_ref() else {
            return 0;
        };
        let expr_impl = match expr {
            cst::Expr::Expr(e) => e,
            #[cfg(feature = "tolerant-ast")]
            cst::Expr::ErrorExpr => return 0,
        };
        match &*expr_impl.expr {
            cst::ExprData::Or(or) => or_depth(or),
            cst::ExprData::If(cond, then_expr, else_expr) => {
                let cond_depth = expr_depth(cond);
                let then_depth = expr_depth(then_expr);
                let else_depth = expr_depth(else_expr);
                1 + cond_depth.max(then_depth).max(else_depth)
            }
        }
    }

    // Chained `||`, `&&`, relation, `+`, and `*` operators are left
    // associative, so `a || b || c` becomes `(a || b) || c`. The initial
    // operand is nested under every operator, and each extended operand is
    // nested under one fewer operator than the operand before it.

    fn or_depth(or_node: &Node<Option<cst::Or>>) -> usize {
        let Some(or) = or_node.node.as_ref() else {
            return 0;
        };
        let len = or.extended.len();
        let mut depth = len + and_depth(&or.initial);
        for (i, ext) in or.extended.iter().enumerate() {
            let ext_depth = and_depth(ext);
            depth = depth.max(len - i + ext_depth);
        }
        depth
    }

    fn and_depth(and_node: &Node<Option<cst::And>>) -> usize {
        let Some(and) = and_node.node.as_ref() else {
            return 0;
        };
        let len = and.extended.len();
        let mut depth = len + relation_depth(&and.initial);
        for (i, ext) in and.extended.iter().enumerate() {
            let ext_depth = relation_depth(ext);
            depth = depth.max(len - i + ext_depth);
        }
        depth
    }

    fn relation_depth(rel_node: &Node<Option<cst::Relation>>) -> usize {
        let Some(rel) = rel_node.node.as_ref() else {
            return 0;
        };
        match rel {
            cst::Relation::Common { initial, extended } => {
                // `!=`, `>`, and `>=` are converted to the negation of `==`,
                // `<=`, and `<`, adding a level of nesting.
                let negated = extended.iter().any(|(op, _)| {
                    matches!(
                        op,
                        cst::RelOp::NotEq | cst::RelOp::Greater | cst::RelOp::GreaterEq
                    )
                });
                let len = extended.len() + usize::from(negated);
                let mut depth = len + add_depth(initial);
                for (i, ext) in extended.iter().map(|(_, ext)| ext).enumerate() {
                    let ext_depth = add_depth(ext);
                    depth = depth.max(len - i + ext_depth);
                }
                depth
            }
            cst::Relation::Has { target, field } => {
                // `e has a.b.c` becomes a single `has` node. The depth of
                // `a.b.c` bounds the length of its attribute path.
                let target_depth = add_depth(target);
                let field_depth = add_depth(field);
                1 + target_depth.max(field_depth)
            }
            cst::Relation::Like { target, pattern } => {
                let target_depth = add_depth(target);
                let pattern_depth = add_depth(pattern);
                1 + target_depth.max(pattern_depth)
            }
            cst::Relation::IsIn {
                target,
                entity_type,
                in_entity,
            } => {
                let target_depth = add_depth(target);
                let entity_type_depth = add_depth(entity_type);
                match in_entity {
                    // `e is T in e2` expands to `e is T && e in e2`
                    Some(in_entity) => {
                        let in_entity_depth = add_depth(in_entity);
                        2 + target_depth.max(entity_type_depth).max(in_entity_depth)
                    }
                    None => 1 + target_depth.max(entity_type_depth),
                }
            }
        }
    }

    pub(crate) fn add_depth(add_node: &Node<Option<cst::Add>>) -> usize {
        let Some(add) = add_node.node.as_ref() else {
            return 0;
        };
        let len = add.extended.len();
        let mut depth = len + mult_depth(&add.initial);
        for (i, ext) in add.extended.iter().map(|(_, ext)| ext).enumerate() {
            let ext_depth = mult_depth(ext);
            depth = depth.max(len - i + ext_depth);
        }
        depth
    }

    fn mult_depth(mult_node: &Node<Option<cst::Mult>>) -> usize {
        let Some(mult) = mult_node.node.as_ref() else {
            return 0;
        };
        let len = mult.extended.len();
        let mut depth = len + unary_depth(&mult.initial);
        for (i, ext) in mult.extended.iter().map(|(_, ext)| ext).enumerate() {
            let ext_depth = unary_depth(ext);
            depth = depth.max(len - i + ext_depth);
        }
        depth
    }

    fn unary_depth(unary_node: &Node<Option<cst::Unary>>) -> usize {
        let Some(unary) = unary_node.node.as_ref() else {
            return 0;
        };
        let neg_depth = match unary.op {
            Some(cst::NegOp::Bang(n)) | Some(cst::NegOp::Dash(n)) => n as usize,
            Some(cst::NegOp::OverBang) | Some(cst::NegOp::OverDash) => 0,
            None => 0,
        };
        neg_depth + member_depth(&unary.item)
    }

    fn member_depth(mem_node: &Node<Option<cst::Member>>) -> usize {
        let Some(mem) = mem_node.node.as_ref() else {
            return 0;
        };
        // Member accesses are left associative, so `e.a.b` becomes `(e.a).b`.
        // The item is nested under every access, and the arguments of each
        // access are nested under one fewer access than the access before it.
        let len = mem.access.len();
        let mut depth = len + primary_depth(&mem.item);
        for (i, acc_node) in mem.access.iter().enumerate() {
            let Some(acc) = inner(acc_node) else {
                continue;
            };
            match acc {
                cst::MemAccess::Field(_) => {}
                cst::MemAccess::Call(args) => {
                    for arg in args {
                        let arg_depth = expr_depth(arg);
                        depth = depth.max(len - i + arg_depth);
                    }
                }
                cst::MemAccess::Index(idx) => {
                    let idx_depth = expr_depth(idx);
                    depth = depth.max(len - i + idx_depth);
                }
            }
        }
        depth
    }

    fn primary_depth(prim_node: &Node<Option<cst::Primary>>) -> usize {
        let Some(prim) = prim_node.node.as_ref() else {
            return 0;
        };
        match prim {
            cst::Primary::Literal(_)
            | cst::Primary::Ref(_)
            | cst::Primary::Name(_)
            | cst::Primary::Slot(_) => 0,
            // Parentheses don't add depth to the AST, but they do add depth to
            // the CST, which we recurse on when converting to an AST.
            cst::Primary::Expr(inner) => 1 + expr_depth(inner),
            cst::Primary::EList(elts) => {
                let mut depth = 0;
                for elt in elts {
                    let elt_depth = expr_depth(elt);
                    depth = depth.max(1 + elt_depth);
                }
                depth
            }
            cst::Primary::RInits(inits) => {
                let mut depth = 0;
                for init in inits {
                    let Some(rec_init) = init.node.as_ref() else {
                        continue;
                    };
                    let key_depth = expr_depth(&rec_init.0);
                    let value_depth = expr_depth(&rec_init.1);
                    depth = depth.max(1 + key_depth.max(value_depth));
                }
                depth
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast;
    use crate::parser::text_to_cst;
    use rstest::rstest;

    fn depth_of(src: &str) -> usize {
        let cst = text_to_cst::parse_expr(src).expect("parse failed");
        expr_depth(&cst)
    }

    #[rstest]
    #[case("1", 0)]
    #[case("principal", 0)]
    #[case("1 + 2", 1)]
    #[case("true || false || true", 2)]
    #[case("true && false && true", 2)]
    #[case("1 + 2 + 3 + 4", 3)]
    #[case("1 * 2 * 3 * 4", 3)]
    #[case("((1))", 2)]
    #[case("(1 + 2) + 3", 3)]
    #[case("1 + 2 + 3 + (5 * 5)", 3)]
    #[case("1 + (1 + 1) + 1 + 1", 5)]
    #[case("1 * (1 * 1) * 1 * 1", 5)]
    #[case("true || (true || true) || true", 4)]
    #[case("true && (true && true) && true", 4)]
    #[case("if true then 1 else 2", 1)]
    #[case("if if true then true else false then 1 else 2", 2)]
    #[case("principal.a.b.c", 3)]
    #[case(r#"principal["a"]["b"]["c"]"#, 3)]
    #[case(r#"principal["a"].b["c"].d"#, 4)]
    #[case("[1,2,3].contains(1)", 3)]
    #[case("principal.a.contains(1)", 3)]
    #[case("principal.contains(principal.a.b).contains(1)", 5)]
    #[case("!!true", 2)]
    #[case("--1", 2)]
    #[case("[[1]]", 2)]
    #[case("{\"a\": {\"b\": 1}}", 2)]
    #[case("1 == 2", 1)]
    #[case("1 != 2", 2)]
    #[case("1 > 2", 2)]
    #[case("1 >= 2", 2)]
    #[case("principal has foo", 1)]
    #[case("principal has foo.bar.baz", 3)]
    #[case("principal.a.b has foo.bar.baz", 3)]
    #[case("(principal has a.b) has c.d", 4)]
    #[case("principal is User", 1)]
    #[case("principal is User in Group::\"admin\"", 2)]
    #[case("\"abc\" like \"a*\"", 1)]
    #[case("if 1 + 2 + 3 > 4 then [1,2].contains(3) else principal.a.b", 5)]
    fn effective_expr_depth(#[case] src: &str, #[case] expected: usize) {
        assert_eq!(depth_of(src), expected, "depth mismatch for: {src:?}");
        let ast: ast::Expr = src.parse().expect("conversion failed");
        assert!(
            ast.depth() <= expected,
            "AST depth {} exceeds effective depth for: {src:?}",
            ast.depth()
        );
    }

    fn policy_depth_of(src: &str) -> Option<usize> {
        let cst = text_to_cst::parse_policy(src).ok()?;
        let policy = cst.node.as_ref()?;
        let policy_impl = match policy {
            cst::Policy::Policy(p) => p,
            #[cfg(feature = "tolerant-ast")]
            cst::Policy::PolicyError => return None,
        };
        conds_effective_depth(policy_impl)
    }

    #[rstest]
    #[case("permit(principal, action, resource) when { true };", Some(0))]
    #[case(
        "permit(principal, action, resource) when { true } when { true } when { true };",
        Some(2)
    )]
    #[case(
        "permit(principal, action, resource) when { true } when { 1 + 2 + 3 };",
        Some(3)
    )]
    #[case(
        "permit(principal, action, resource) when { 1 + 2 + 3 } when { true };",
        Some(3)
    )]
    #[case("permit(principal, action, resource) unless { 1 + 2 };", Some(2))]
    #[case(
        "permit(principal, action, resource) when { true } unless { 1 + 2 };",
        Some(3)
    )]
    #[case("permit(principal, action, resource);", None)]
    fn policy_cond_depth(#[case] src: &str, #[case] expected: Option<usize>) {
        assert_eq!(
            policy_depth_of(src),
            expected,
            "depth mismatch for: {src:?}"
        );
        let policy = crate::parser::parse_policy(None, src).expect("conversion failed");
        assert!(
            policy.non_scope_constraints().map(ast::Expr::depth) <= expected,
            "AST depth exceeds effective depth for: {src:?}"
        );
    }

    #[rstest]
    #[case("permit(principal, action, resource);", 3)]
    #[case("permit(principal, action, resource) when { 1 + 2 };", 4)]
    #[case("permit(principal is User in Group::\"g\", action, resource);", 3)]
    #[case(
        "permit(principal, action in [Action::\"a\"], resource) when { true };",
        4
    )]
    #[case("permit(principal, action, resource is T in Group::\"g\");", 5)]
    fn policy_depth_includes_scope(#[case] src: &str, #[case] expected: usize) {
        let cst = text_to_cst::parse_policy(src).expect("parse failed");
        assert!(check_policy_depth(&cst, expected).is_ok(), "for: {src:?}");
        assert!(
            check_policy_depth(&cst, expected - 1).is_err(),
            "for: {src:?}"
        );
        let policy = crate::parser::parse_policy(None, src).expect("conversion failed");
        assert!(policy.condition().depth() <= expected, "for: {src:?}");
    }

    /// Deep CSTs don't overflow the stack when computing depth.
    #[test]
    fn deep_cst_depth() {
        let depth = 100_000;
        let src = "[(".repeat(depth) + "1" + &")]".repeat(depth);
        assert_eq!(depth_of(&src), 2 * depth);
    }
}
