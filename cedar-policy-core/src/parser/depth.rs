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

//! Iterative depth computation for CST expressions.
//!
//! This module provides [`cst_effective_depth`], which computes the depth of
//! the AST that would result from converting a CST expression, accounting for
//! the amplification introduced by nary left-folds (Or, And, Add, Mult) and
//! member access chains.

use crate::parser::{err, Loc};

use super::cst;
use super::node::Node;

/// Work item for the iterative depth computation.
struct WorkItem<'a> {
    node: CstNode<'a>,
    depth: usize,
}

/// The different CST node types we need to visit.
#[derive(Debug, Copy, Clone)]
pub(crate) enum CstNode<'a> {
    Expr(&'a Node<Option<cst::Expr>>),
    Or(&'a Node<Option<cst::Or>>),
    And(&'a Node<Option<cst::And>>),
    Relation(&'a Node<Option<cst::Relation>>),
    Add(&'a Node<Option<cst::Add>>),
    Mult(&'a Node<Option<cst::Mult>>),
    Unary(&'a Node<Option<cst::Unary>>),
    Member(&'a Node<Option<cst::Member>>),
    Primary(&'a Node<Option<cst::Primary>>),
}

impl<'a> Into<CstNode<'a>> for &'a Node<Option<cst::Expr>> {
    fn into(self) -> CstNode<'a> {
        CstNode::Expr(self)
    }
}

impl<'a> Into<CstNode<'a>> for &'a Node<Option<cst::Add>> {
    fn into(self) -> CstNode<'a> {
        CstNode::Add(self)
    }
}

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

/// Compute the maximum effective depth of a list of cst expressions that are
/// used to build a right associated ast expression. As we progress the list
/// each is at a progressively deeper depth due to association being explicitly
/// imposed by nesting AST nodes.
fn effective_depth_right_assoc<'a>(
    exprs: impl Iterator<Item = &'a Node<Option<cst::Expr>>>,
) -> Option<usize> {
    exprs
        .enumerate()
        .map(|(assoc_depth, e)| cst_effective_depth(e.into()) + assoc_depth)
        .max()
}

/// Return an error if `depth` exceeds `depth_limit`.
fn check_depth(
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
    for var in &policy_impl.variables {
        let Some(var) = var.node.as_ref() else {
            continue;
        };
        if let Some(entity_type) = var.entity_type.as_ref() {
            check_depth(
                cst_effective_depth(entity_type.into()),
                depth_limit,
                entity_type.loc(),
            )?;
        }
        if let Some((_, ineq)) = &var.ineq {
            check_depth(cst_effective_depth(ineq.into()), depth_limit, ineq.loc())?;
        }
    }
    let cond_exprs: Vec<_> = policy_impl
        .conds
        .iter()
        .filter_map(|cond_node| cond_node.node.as_ref()?.expr.as_ref())
        .collect();
    if let Some(depth) = effective_depth_right_assoc(cond_exprs.into_iter()) {
        check_depth(depth, depth_limit, cst.loc())?;
    }

    Ok(())
}

/// Iteratively compute a conservative depth bound for this CST expression.
/// Accounts for both CST nesting (parenthesized sub-expressions, list/record
/// elements, method args) and AST amplification (nary left-folds, member
/// access chains, unary operators). A single limit applied against this
/// value guards against stack overflow in both the CST-to-AST converter
/// and the evaluator/validator.
pub(crate) fn cst_effective_depth(root: CstNode<'_>) -> usize {
    let mut stack: Vec<WorkItem<'_>> = vec![WorkItem {
        node: root,
        depth: 0,
    }];
    let mut max_depth: usize = 0;

    while let Some(WorkItem { node, depth }) = stack.pop() {
        max_depth = max_depth.max(depth);

        match node {
            CstNode::Expr(expr_node) => {
                let Some(expr) = expr_node.node.as_ref() else {
                    continue;
                };
                let expr_impl = match expr {
                    cst::Expr::Expr(e) => e,
                    #[cfg(feature = "tolerant-ast")]
                    cst::Expr::ErrorExpr => continue,
                };
                match &*expr_impl.expr {
                    cst::ExprData::Or(or) => {
                        stack.push(WorkItem {
                            node: CstNode::Or(or),
                            depth,
                        });
                    }
                    cst::ExprData::If(cond, then_expr, else_expr) => {
                        let child_depth = depth + 1;
                        stack.push(WorkItem {
                            node: CstNode::Expr(cond),
                            depth: child_depth,
                        });
                        stack.push(WorkItem {
                            node: CstNode::Expr(then_expr),
                            depth: child_depth,
                        });
                        stack.push(WorkItem {
                            node: CstNode::Expr(else_expr),
                            depth: child_depth,
                        });
                    }
                }
            }

            CstNode::Or(or_node) => {
                let Some(or) = or_node.node.as_ref() else {
                    continue;
                };
                push_left_assoc_exprs(
                    &mut stack,
                    depth,
                    CstNode::And(&or.initial),
                    or.extended.iter().map(|ext| CstNode::And(ext)),
                    or.extended.len(),
                );
            }

            CstNode::And(and_node) => {
                let Some(and) = and_node.node.as_ref() else {
                    continue;
                };
                push_left_assoc_exprs(
                    &mut stack,
                    depth,
                    CstNode::Relation(&and.initial),
                    and.extended.iter().map(|ext| CstNode::Relation(ext)),
                    and.extended.len(),
                );
            }

            CstNode::Relation(rel_node) => {
                let Some(rel) = rel_node.node.as_ref() else {
                    continue;
                };
                match rel {
                    cst::Relation::Common { initial, extended } => {
                        push_left_assoc_exprs(
                            &mut stack,
                            depth,
                            CstNode::Add(initial),
                            extended.iter().map(|(_, ext)| CstNode::Add(ext)),
                            extended.len(),
                        );
                    }
                    cst::Relation::Has { target, field } => {
                        let child_depth = depth + 1;
                        stack.push(WorkItem {
                            node: CstNode::Add(target),
                            depth: child_depth,
                        });
                        stack.push(WorkItem {
                            node: CstNode::Add(field),
                            depth: child_depth,
                        });
                    }
                    cst::Relation::Like { target, pattern } => {
                        let child_depth = depth + 1;
                        stack.push(WorkItem {
                            node: CstNode::Add(target),
                            depth: child_depth,
                        });
                        stack.push(WorkItem {
                            node: CstNode::Add(pattern),
                            depth: child_depth,
                        });
                    }
                    cst::Relation::IsIn {
                        target,
                        entity_type,
                        in_entity,
                    } => {
                        // is_in_entity_type produces and(is(target, type), in(target, in_entity))
                        let child_depth = depth + 2;
                        stack.push(WorkItem {
                            node: CstNode::Add(target),
                            depth: child_depth,
                        });
                        stack.push(WorkItem {
                            node: CstNode::Add(entity_type),
                            depth: child_depth,
                        });
                        if let Some(in_e) = in_entity {
                            stack.push(WorkItem {
                                node: CstNode::Add(in_e),
                                depth: child_depth,
                            });
                        }
                    }
                }
            }

            CstNode::Add(add_node) => {
                let Some(add) = add_node.node.as_ref() else {
                    continue;
                };
                push_left_assoc_exprs(
                    &mut stack,
                    depth,
                    CstNode::Mult(&add.initial),
                    add.extended.iter().map(|(_, ext)| CstNode::Mult(ext)),
                    add.extended.len(),
                );
            }

            CstNode::Mult(mult_node) => {
                let Some(mult) = mult_node.node.as_ref() else {
                    continue;
                };
                push_left_assoc_exprs(
                    &mut stack,
                    depth,
                    CstNode::Unary(&mult.initial),
                    mult.extended.iter().map(|(_, ext)| CstNode::Unary(ext)),
                    mult.extended.len(),
                );
            }

            CstNode::Unary(unary_node) => {
                let Some(unary) = unary_node.node.as_ref() else {
                    continue;
                };
                let neg_depth = match unary.op {
                    Some(cst::NegOp::Bang(n)) | Some(cst::NegOp::Dash(n)) => n as usize,
                    Some(cst::NegOp::OverBang) | Some(cst::NegOp::OverDash) => 5,
                    None => 0,
                };
                stack.push(WorkItem {
                    node: CstNode::Member(&unary.item),
                    depth: depth + neg_depth,
                });
            }

            CstNode::Member(mem_node) => {
                let Some(mem) = mem_node.node.as_ref() else {
                    continue;
                };
                let access_depth = mem.access.len();
                let item_depth = depth + access_depth;
                stack.push(WorkItem {
                    node: CstNode::Primary(&mem.item),
                    depth: item_depth,
                });
                for acc_node in &mem.access {
                    let Some(acc) = acc_node.node.as_ref() else {
                        continue;
                    };
                    match acc {
                        cst::MemAccess::Field(_) => {}
                        cst::MemAccess::Call(args) => {
                            for arg in args {
                                stack.push(WorkItem {
                                    node: CstNode::Expr(arg),
                                    depth: depth + 1,
                                });
                            }
                        }
                        cst::MemAccess::Index(idx) => {
                            stack.push(WorkItem {
                                node: CstNode::Expr(idx),
                                depth: depth + 1,
                            });
                        }
                    }
                }
            }

            CstNode::Primary(prim_node) => {
                let Some(prim) = prim_node.node.as_ref() else {
                    continue;
                };
                match prim {
                    cst::Primary::Literal(_)
                    | cst::Primary::Ref(_)
                    | cst::Primary::Name(_)
                    | cst::Primary::Slot(_) => {}
                    cst::Primary::Expr(inner) => {
                        stack.push(WorkItem {
                            node: CstNode::Expr(inner),
                            depth: depth + 1,
                        });
                    }
                    cst::Primary::EList(elts) => {
                        let child_depth = depth + 1;
                        for elt in elts {
                            stack.push(WorkItem {
                                node: CstNode::Expr(elt),
                                depth: child_depth,
                            });
                        }
                    }
                    cst::Primary::RInits(inits) => {
                        let child_depth = depth + 1;
                        for init in inits {
                            let Some(rec_init) = init.node.as_ref() else {
                                continue;
                            };
                            stack.push(WorkItem {
                                node: CstNode::Expr(&rec_init.0),
                                depth: child_depth,
                            });
                            stack.push(WorkItem {
                                node: CstNode::Expr(&rec_init.1),
                                depth: child_depth,
                            });
                        }
                    }
                }
            }
        }
    }

    max_depth
}

/// Push work items for a left-associative nary operator. The initial element
/// sits at the deepest point of the fold; each extended element is a right
/// child at its fold level.
fn push_left_assoc_exprs<'a>(
    stack: &mut Vec<WorkItem<'a>>,
    depth: usize,
    initial: CstNode<'a>,
    extended: impl Iterator<Item = CstNode<'a>>,
    extended_len: usize,
) {
    stack.push(WorkItem {
        node: initial,
        depth: depth + extended_len,
    });
    for (i, ext) in extended.enumerate() {
        stack.push(WorkItem {
            node: ext,
            depth: depth + i + 1,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::text_to_cst;
    use rstest::rstest;

    fn depth_of(src: &str) -> usize {
        let cst = text_to_cst::parse_expr(src).expect("parse failed");
        cst_effective_depth(CstNode::Expr(&cst))
    }

    #[rstest]
    // Literals
    #[case("1", 0)]
    #[case("true", 0)]
    #[case("\"hello\"", 0)]
    #[case("principal", 0)]
    // Binary ops
    #[case("1 + 2", 1)]
    #[case("1 * 2", 1)]
    #[case("1 - 2", 1)]
    // Left-fold amplification
    #[case("true || false || true", 2)]
    #[case("true && false && true", 2)]
    #[case("1 + 2 + 3 + 4", 3)]
    #[case("1 * 2 * 3 * 4", 3)]
    // Parens add CST recursion depth
    #[case("((1))", 2)]
    #[case("(((1)))", 3)]
    #[case("(1 + 2) + 3", 3)]
    #[case("1 + 2 + 3 + (5 * 5)", 5)]
    // If-then-else
    #[case("if true then 1 else 2", 1)]
    #[case("if if true then true else false then 1 else 2", 2)]
    // Member access chains
    #[case("principal.a", 1)]
    #[case("principal.a.b.c", 3)]
    // Method calls
    #[case("[1,2,3].contains(1)", 3)]
    #[case("principal.a.contains(1)", 3)]
    // Negation
    #[case("!true", 1)]
    #[case("!!true", 2)]
    #[case("-1", 1)]
    #[case("--1", 2)]
    // Set and record literals
    #[case("[1, 2, 3]", 1)]
    #[case("[[1]]", 2)]
    #[case("{\"a\": 1}", 1)]
    #[case("{\"a\": {\"b\": 1}}", 2)]
    // Relation operators
    #[case("1 < 2", 1)]
    #[case("1 == 2", 1)]
    // `has` with extended path
    #[case("principal has foo", 1)]
    #[case("principal has foo.bar", 2)]
    #[case("principal has foo.bar.baz", 3)]
    // `is` and `is in`
    #[case("principal is User", 2)]
    #[case("principal is User in Group::\"admin\"", 2)]
    // `like`
    #[case("\"abc\" like \"a*\"", 1)]
    // Combined depth
    #[case("if 1 + 2 + 3 > 4 then [1,2].contains(3) else principal.a.b", 4)]
    fn expr_depth(#[case] src: &str, #[case] expected: usize) {
        assert_eq!(depth_of(src), expected, "depth mismatch for: {src:?}");
    }

    fn policy_depth_of(src: &str) -> Option<usize> {
        let cst = text_to_cst::parse_policy(src).ok()?;
        let policy = cst.node.as_ref()?;
        let policy_impl = match policy {
            cst::Policy::Policy(p) => p,
            #[cfg(feature = "tolerant-ast")]
            cst::Policy::PolicyError => return None,
        };
        let cond_exprs: Vec<_> = policy_impl
            .conds
            .iter()
            .filter_map(|cond_node| cond_node.node.as_ref()?.expr.as_ref())
            .collect();
        effective_depth_right_assoc(cond_exprs.into_iter())
    }

    #[rstest]
    #[case("permit(principal, action, resource) when { true };", Some(0))]
    #[case(
        "permit(principal, action, resource) when { true } when { true };",
        Some(1)
    )]
    #[case(
        "permit(principal, action, resource) when { true } when { true } when { true };",
        Some(2)
    )]
    #[case(
        "permit(principal, action, resource) when { true } when { 1 + 2 + 3 };",
        Some(3)
    )]
    #[case("permit(principal, action, resource);", None)]
    fn policy_cond_depth(#[case] src: &str, #[case] expected: Option<usize>) {
        assert_eq!(
            policy_depth_of(src),
            expected,
            "depth mismatch for: {src:?}"
        );
    }

    #[rstest]
    #[case("permit(principal, action, resource) when { 1 + 2 }; forbid(principal, action, resource) when { true };", 1, true)]
    #[case("permit(principal, action, resource) when { true }; forbid(principal, action, resource) when { 1 + 2 + 3 };", 1, false)]
    fn check_policyset_depth_limit(
        #[case] src: &str,
        #[case] limit: usize,
        #[case] should_pass: bool,
    ) {
        use crate::parser::parse_policyset_with_depth_limit;
        let result = parse_policyset_with_depth_limit(src, limit);
        assert_eq!(
            result.is_ok(),
            should_pass,
            "for policyset: {src:?} with limit {limit}"
        );
    }
}
