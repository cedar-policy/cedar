/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

use super::utils::*;
use super::Context;
use cedar_policy_core::parser::{cst::*, ASTNode};
use pretty::RcDoc;

use super::token::Comment;

/// The trait to convert a CST to a RcDoc
pub trait Doc {
    /// Convert a type implementing this trait to a `RcDoc`.
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_>;
}

impl Doc for Ident {
    // An Ident's doc is itself.
    fn to_doc(&self, _context: &mut Context<'_>) -> RcDoc<'_> {
        RcDoc::as_string(self)
    }
}

impl Doc for ASTNode<Option<VariableDef>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        let vd = self.as_inner().unwrap();
        let start_comment = get_comment_at_start(self.info.0.start, &mut context.tokens);
        let end_comment = get_comment_at_end(self.info.0.end, &mut context.tokens);
        let var_doc = vd.variable.as_inner().unwrap().to_doc(context);

        match &vd.ineq {
            Some((op, rhs)) => get_leading_comment_doc_from_str(&start_comment.leading_comment)
                .append(
                    var_doc
                        .append(get_trailing_comment_doc_from_str(
                            &start_comment.trailing_comment,
                        ))
                        .append(RcDoc::line())
                        .append(add_comment(
                            RcDoc::as_string(op),
                            get_comment_after_end(vd.variable.info.0.end, &mut context.tokens),
                            RcDoc::nil(),
                        ))
                        .group()
                        .append(
                            RcDoc::line()
                                .append(get_leading_comment_doc_from_str(
                                    &end_comment.leading_comment,
                                ))
                                .append(rhs.to_doc(context))
                                .nest(context.config.indent_width),
                        )
                        .group()
                        .append(get_trailing_comment_doc_from_str(
                            &end_comment.trailing_comment,
                        )),
                ),
            None => add_comment(var_doc, start_comment, RcDoc::nil()),
        }
    }
}

impl Doc for ASTNode<Option<Cond>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        let cond = self.as_inner().unwrap();
        let lb_comment = get_comment_after_end(cond.cond.info.0.end, &mut context.tokens);
        let rb_comment = get_comment_at_end(self.info.0.end, &mut context.tokens);
        let cond_comment = get_comment_at_start(cond.cond.info.0.start, &mut context.tokens);

        let rb_doc = add_comment(RcDoc::text("}"), rb_comment, RcDoc::nil());
        let cond_doc = cond.cond.to_doc(context);
        match cond.expr.as_ref() {
            Some(expr) => {
                let expr_leading_comment =
                    get_leading_comment_at_start(expr.info.0.start, &mut context.tokens);
                let expr_doc = expr.to_doc(context);
                get_leading_comment_doc_from_str(&cond_comment.leading_comment).append(
                    cond_doc
                        .append(get_trailing_comment_doc_from_str(
                            &cond_comment.trailing_comment,
                        ))
                        .append(RcDoc::line())
                        .append(
                            get_leading_comment_doc_from_str(&lb_comment.leading_comment).append(
                                RcDoc::text("{").append(
                                    get_trailing_comment_doc_from_str(&lb_comment.trailing_comment)
                                        .append(RcDoc::line())
                                        .append(
                                            get_leading_comment_doc_from_str(&expr_leading_comment)
                                                .append(expr_doc.group()),
                                        )
                                        .nest(context.config.indent_width)
                                        .append(RcDoc::line())
                                        .append(rb_doc)
                                        .group(),
                                ),
                            ),
                        )
                        .group(),
                )
            }
            None => get_leading_comment_doc_from_str(&cond_comment.leading_comment).append(
                cond_doc
                    .append(get_trailing_comment_doc_from_str(
                        &cond_comment.trailing_comment,
                    ))
                    .append(RcDoc::line())
                    .append(
                        get_leading_comment_doc_from_str(&lb_comment.leading_comment).append(
                            RcDoc::text("{")
                                .append(get_trailing_comment_doc_from_str(
                                    &lb_comment.trailing_comment,
                                ))
                                .append(RcDoc::line())
                                .append(rb_doc)
                                .group(),
                        ),
                    )
                    .group(),
            ),
        }
    }
}

impl Doc for ASTNode<Option<Expr>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        match self.as_inner().unwrap().expr.as_ref() {
            ExprData::If(c, t, e) => {
                fn pp_group<'n>(
                    s: &str,
                    c: Comment,
                    e: &'n ASTNode<Option<Expr>>,
                    context: &mut Context<'_>,
                ) -> RcDoc<'n> {
                    add_comment(RcDoc::as_string(s), c, RcDoc::nil()).append(
                        RcDoc::line()
                            .append(e.to_doc(context))
                            .nest(context.config.indent_width),
                    )
                }
                let if_comment = get_comment_at_start(self.info.0.start, &mut context.tokens);
                let else_comment = get_comment_after_end(c.info.0.end, &mut context.tokens);
                let then_comment = get_comment_after_end(t.info.0.end, &mut context.tokens);
                pp_group("if", if_comment, c, context)
                    .append(RcDoc::line())
                    .append(pp_group("then", then_comment, t, context))
                    .append(RcDoc::line())
                    .append(pp_group("else", else_comment, e, context))
                    .group()
            }
            ExprData::Or(e) => e.to_doc(context),
        }
    }
}

impl Doc for ASTNode<Option<Or>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        let e = self.as_inner().unwrap();
        let initial = &e.initial;
        let extended = &e.extended;
        // Convert a list of and/or expressions `(,initial ,@extended) to a doc separated by the operator.
        // We want to make each subexpression on an individual line and put the operator on the right
        let es: Vec<_> = std::iter::once(initial).chain(extended.iter()).collect();
        let mut d: RcDoc<'_> = RcDoc::nil();
        for e in es.iter().take(es.len() - 1) {
            let op_comment = get_comment_after_end(e.info.0.end, &mut context.tokens);
            d = d
                .append(e.to_doc(context))
                .append(RcDoc::space())
                .append(add_comment(RcDoc::text("||"), op_comment, RcDoc::line()));
        }
        d.append(es.last().unwrap().to_doc(context))
    }
}

impl Doc for ASTNode<Option<And>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        let e = self.as_inner().unwrap();
        let initial = &e.initial;
        let extended = &e.extended;
        // Convert a list of and/or expressions `(,initial ,@extended) to a doc separated by the operator.
        // We want to make each subexpression on an individual line and put the operator on the right
        let es: Vec<_> = std::iter::once(initial).chain(extended.iter()).collect();
        let mut d: RcDoc<'_> = RcDoc::nil();
        for e in es.iter().take(es.len() - 1) {
            let op_comment = get_comment_after_end(e.info.0.end, &mut context.tokens);
            d = d
                .append(e.to_doc(context))
                .append(RcDoc::space())
                .append(add_comment(RcDoc::text("&&"), op_comment, RcDoc::line()));
        }
        d.append(es.last().unwrap().to_doc(context))
    }
}

impl Doc for ASTNode<Option<Relation>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        let e = self.as_inner().unwrap();
        match e {
            Relation::Common { initial, extended } => {
                match extended.as_slice() {
                    [] => initial.to_doc(context),
                    [(op, n)] =>
                    // do not group due to the limitation of current design
                    {
                        initial
                            .to_doc(context)
                            .append(RcDoc::space())
                            .append(add_comment(
                                RcDoc::as_string(op),
                                get_comment_after_end(initial.info.0.end, &mut context.tokens),
                                RcDoc::nil(),
                            ))
                            .append(RcDoc::space())
                            .append(n.to_doc(context))
                    }
                    _ => unreachable!("chained relation disallowed!"),
                }
            }
            Relation::Has { target, field } => target
                .to_doc(context)
                .append(RcDoc::line())
                .append(add_comment(
                    RcDoc::text("has"),
                    get_comment_after_end(target.info.0.end, &mut context.tokens),
                    RcDoc::nil(),
                ))
                .append(RcDoc::line())
                .append(field.to_doc(context).nest(context.config.indent_width))
                .group(),
            Relation::Like { target, pattern } => target
                .to_doc(context)
                .append(RcDoc::line())
                .append(add_comment(
                    RcDoc::text("like"),
                    get_comment_after_end(target.info.0.end, &mut context.tokens),
                    RcDoc::nil(),
                ))
                .append(RcDoc::line())
                .append(pattern.to_doc(context).nest(context.config.indent_width))
                .group(),
        }
    }
}

impl Doc for AddOp {
    fn to_doc(&self, _: &mut Context<'_>) -> RcDoc<'_> {
        RcDoc::text(self.to_string())
    }
}

impl Doc for ASTNode<Option<Add>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        let e = self.as_inner().unwrap();
        let initial = &e.initial;
        let extended = &e.extended;
        // Convert a list of arithmetic expressions to a doc separated by the operators
        // We keep the convention that operators are on the right but do not put a subexpression on a single line.
        extended
            .iter()
            .fold((initial.to_doc(context), initial), |doc, (op, e)| {
                (
                    doc.0
                        .append(RcDoc::space())
                        .append(add_comment(
                            op.to_doc(context),
                            get_comment_after_end(doc.1.info.0.end, &mut context.tokens),
                            RcDoc::nil(),
                        ))
                        .append(RcDoc::line())
                        .append(e.to_doc(context)),
                    e,
                )
            })
            .0
            .group()
    }
}

impl Doc for MultOp {
    fn to_doc(&self, _: &mut Context<'_>) -> RcDoc<'_> {
        RcDoc::text(self.to_string())
    }
}

impl Doc for ASTNode<Option<Mult>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        let e = self.as_inner().unwrap();
        let initial = &e.initial;
        let extended = &e.extended;
        // Convert a list of arithmetic expressions to a doc separated by the operators
        // We keep the convention that operators are on the right but do not put a subexpression on a single line.
        extended
            .iter()
            .fold((initial.to_doc(context), initial), |doc, (op, e)| {
                (
                    doc.0
                        .append(RcDoc::space())
                        .append(add_comment(
                            op.to_doc(context),
                            get_comment_after_end(doc.1.info.0.end, &mut context.tokens),
                            RcDoc::nil(),
                        ))
                        .append(RcDoc::line())
                        .append(e.to_doc(context)),
                    e,
                )
            })
            .0
            .group()
    }
}

impl Doc for ASTNode<Option<Unary>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        let e = self.as_inner().unwrap();
        if let Some(op) = e.op {
            match op {
                NegOp::OverBang | NegOp::OverDash => unreachable!("invalid policy!"),
                NegOp::Bang(n) | NegOp::Dash(n) => {
                    let comment = get_comment_in_range(
                        self.info.0.start,
                        e.item.info.0.start,
                        &mut context.tokens,
                    );
                    assert!(
                        comment.len() == n as usize,
                        "comment number {} should match operator number {}!",
                        comment.len(),
                        n
                    );
                    RcDoc::intersperse(
                        (0..n).map(|i| {
                            add_comment(
                                if matches!(op, NegOp::Bang(_)) {
                                    RcDoc::as_string("!")
                                } else {
                                    RcDoc::as_string("-")
                                },
                                comment[i as usize].clone(),
                                RcDoc::nil(),
                            )
                        }),
                        RcDoc::nil(),
                    )
                    .append(e.item.as_inner().unwrap().to_doc(context))
                }
            }
        } else {
            e.item.as_inner().unwrap().to_doc(context)
        }
    }
}

impl Doc for Member {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        let item_doc = self.item.to_doc(context);
        item_doc
            .append(
                RcDoc::intersperse(
                    self.access.iter().map(|ac| ac.to_doc(context)),
                    RcDoc::line_(),
                )
                .nest(context.config.indent_width),
            )
            .group()
    }
}

impl Doc for ASTNode<Option<RecInit>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        let e = self.as_inner().unwrap();
        let key_doc = e.0.to_doc(context);
        let value_doc = e.1.to_doc(context);
        key_doc
            .append(RcDoc::line_())
            .append(add_comment(
                RcDoc::text(":"),
                Comment::default(),
                RcDoc::nil(),
            ))
            .append(value_doc)
    }
}

impl Doc for ASTNode<Option<Name>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        let e = self.as_inner().unwrap();
        let path = &e.path;
        let n = &e.name;
        if path.is_empty() {
            n.to_doc(context)
        } else {
            path[1..]
                .iter()
                .fold((path[0].to_doc(context), &path[0]), |(d, e), p| {
                    (
                        d.append(add_comment(
                            RcDoc::as_string("::"),
                            get_comment_after_end(e.info.0.end, &mut context.tokens),
                            RcDoc::nil(),
                        ))
                        .append(p.to_doc(context)),
                        p,
                    )
                })
                .0
                .append(add_comment(
                    RcDoc::as_string("::"),
                    get_comment_after_end(path.last().unwrap().info.0.end, &mut context.tokens),
                    RcDoc::nil(),
                ))
                .append(n.to_doc(context))
        }
    }
}

impl Doc for ASTNode<Option<Str>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        let e = self.as_inner().unwrap();
        add_comment(
            RcDoc::as_string(e),
            get_comment_at_start(self.info.0.start, &mut context.tokens),
            RcDoc::nil(),
        )
    }
}

impl Doc for ASTNode<Option<Ref>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        match self.as_inner().unwrap() {
            Ref::Uid { path, eid } => path
                .to_doc(context)
                .append(add_comment(
                    RcDoc::text("::"),
                    get_comment_after_end(path.info.0.end, &mut context.tokens),
                    RcDoc::nil(),
                ))
                .append(eid.to_doc(context)),
            Ref::Ref { path: _, rinits: _ } => unreachable!("unsupported feature"),
        }
    }
}

impl Doc for ASTNode<Option<Literal>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        add_comment(
            RcDoc::as_string(self.as_inner().unwrap()),
            get_comment_at_start(self.info.0.start, &mut context.tokens),
            RcDoc::nil(),
        )
    }
}

impl Doc for ASTNode<Option<Slot>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        add_comment(
            RcDoc::as_string(self.as_inner().unwrap()),
            get_comment_at_start(self.info.0.start, &mut context.tokens),
            RcDoc::nil(),
        )
    }
}

impl Doc for ASTNode<Option<Primary>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        let e = self.as_inner().unwrap();
        match e {
            Primary::Literal(l) => l.to_doc(context),
            Primary::Ref(r) => r.to_doc(context),
            Primary::Name(n) => n.to_doc(context),
            Primary::Expr(e) => add_comment(
                RcDoc::text("("),
                get_comment_at_start(self.info.0.start, &mut context.tokens),
                RcDoc::nil(),
            )
            .append(RcDoc::nil())
            .append(e.to_doc(context).nest(1))
            .append(RcDoc::nil())
            .append(add_comment(
                RcDoc::text(")"),
                get_comment_at_end(self.info.0.end, &mut context.tokens),
                RcDoc::nil(),
            ))
            .group(),
            Primary::EList(el) => add_brackets(
                if el.is_empty() {
                    RcDoc::nil()
                } else {
                    el[1..]
                        .iter()
                        .fold((el[0].to_doc(context), &el[0]), |(d, e), v| {
                            (
                                d.append(add_comment(
                                    RcDoc::as_string(","),
                                    get_comment_after_end(e.info.0.end, &mut context.tokens),
                                    RcDoc::nil(),
                                ))
                                .append(RcDoc::line())
                                .append(v.to_doc(context)),
                                v,
                            )
                        })
                        .0
                },
                add_comment(
                    RcDoc::text("["),
                    get_comment_at_start(self.info.0.start, &mut context.tokens),
                    RcDoc::nil(),
                ),
                add_comment(
                    RcDoc::text("]"),
                    get_comment_at_end(self.info.0.end, &mut context.tokens),
                    RcDoc::nil(),
                ),
            ),
            Primary::RInits(ri) => add_brackets(
                if ri.is_empty() {
                    RcDoc::nil()
                } else {
                    ri[1..]
                        .iter()
                        .fold((ri[0].to_doc(context), &ri[0]), |(d, e), v| {
                            (
                                d.append(add_comment(
                                    RcDoc::as_string(","),
                                    get_comment_after_end(e.info.0.end, &mut context.tokens),
                                    RcDoc::nil(),
                                ))
                                .append(RcDoc::line())
                                .append(v.to_doc(context)),
                                v,
                            )
                        })
                        .0
                },
                add_comment(
                    RcDoc::text("{"),
                    get_comment_at_start(self.info.0.start, &mut context.tokens),
                    RcDoc::nil(),
                ),
                add_comment(
                    RcDoc::text("}"),
                    get_comment_at_end(self.info.0.end, &mut context.tokens),
                    RcDoc::nil(),
                ),
            ),
            Primary::Slot(slot) => slot.to_doc(context),
        }
    }
}

impl Doc for ASTNode<Option<MemAccess>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        let e = self.as_inner().unwrap();
        match e {
            MemAccess::Field(f) => add_comment(
                RcDoc::text("."),
                get_comment_at_start(self.info.0.start, &mut context.tokens),
                RcDoc::nil(),
            )
            .append(f.to_doc(context)),
            MemAccess::Call(args) => add_comment(
                RcDoc::text("("),
                get_comment_at_start(self.info.0.start, &mut context.tokens),
                RcDoc::nil(),
            )
            .append(RcDoc::line_())
            .append(if args.is_empty() {
                RcDoc::nil()
            } else {
                args[1..]
                    .iter()
                    .fold((args[0].to_doc(context), &args[0]), |(d, e), arg| {
                        (
                            d.append(add_comment(
                                RcDoc::as_string(","),
                                get_comment_after_end(e.info.0.end, &mut context.tokens),
                                RcDoc::nil(),
                            ))
                            .append(RcDoc::line())
                            .append(arg.to_doc(context)),
                            arg,
                        )
                    })
                    .0
            })
            .nest(context.config.indent_width)
            .append(RcDoc::line_())
            .append(add_comment(
                RcDoc::text(")"),
                get_comment_at_end(self.info.0.end, &mut context.tokens),
                RcDoc::nil(),
            )),
            MemAccess::Index(idx) => add_comment(
                RcDoc::text("["),
                get_comment_at_start(self.info.0.start, &mut context.tokens),
                RcDoc::nil(),
            )
            .append(RcDoc::line_())
            .append(idx.to_doc(context))
            .append(RcDoc::line_())
            .append(add_comment(
                RcDoc::text("]"),
                get_comment_at_end(self.info.0.end, &mut context.tokens),
                RcDoc::nil(),
            )),
        }
    }
}

impl Doc for ASTNode<Option<Annotation>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        let annotation = self.as_inner().unwrap();
        let id_doc = annotation.key.to_doc(context);
        let val_doc = annotation.value.to_doc(context);
        let at_doc = add_comment(
            RcDoc::text("@"),
            get_comment_at_start(self.info.0.start, &mut context.tokens),
            RcDoc::nil(),
        );
        let lp_doc = add_comment(
            RcDoc::text("("),
            get_comment_after_end(annotation.key.info.0.end, &mut context.tokens),
            RcDoc::nil(),
        );
        let rp_doc = add_comment(
            RcDoc::text(")"),
            get_comment_at_end(self.info.0.end, &mut context.tokens),
            RcDoc::hardline(),
        );
        at_doc
            .append(id_doc)
            .append(lp_doc)
            .append(val_doc)
            .append(rp_doc)
    }
}

impl Doc for ASTNode<Option<Ident>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        add_comment(
            self.as_inner().unwrap().to_doc(context),
            get_comment_at_start(self.info.0.start, &mut context.tokens),
            RcDoc::nil(),
        )
    }
}

impl Doc for ASTNode<Option<Policy>> {
    fn to_doc(&self, context: &mut Context<'_>) -> RcDoc<'_> {
        let policy = self.as_inner().unwrap();

        let anno_doc = RcDoc::intersperse(
            policy.annotations.iter().map(|a| a.to_doc(context)),
            RcDoc::nil(),
        );
        let eff_leading_comment =
            get_leading_comment_at_start(policy.effect.info.0.start, &mut context.tokens);
        let eff_doc = policy.effect.to_doc(context);
        let vars = &policy.variables;
        let principal_doc = vars[0].to_doc(context);
        let action_doc = vars[1].to_doc(context);
        let resource_doc = vars[2].to_doc(context);
        let vars_doc = if vars.iter().all(|v| v.as_inner().unwrap().ineq.is_none()) {
            principal_doc
                .append(add_comment(
                    RcDoc::text(","),
                    get_comment_after_end(vars[0].info.0.end, &mut context.tokens),
                    RcDoc::space(),
                ))
                .append(action_doc)
                .append(add_comment(
                    RcDoc::text(","),
                    get_comment_after_end(vars[1].info.0.end, &mut context.tokens),
                    RcDoc::space(),
                ))
                .append(resource_doc)
                .nest(context.config.indent_width)
                .group()
        } else {
            RcDoc::hardline()
                .append(
                    principal_doc
                        .append(add_comment(
                            RcDoc::text(","),
                            get_comment_after_end(vars[0].info.0.end, &mut context.tokens),
                            RcDoc::hardline(),
                        ))
                        .append(action_doc)
                        .append(add_comment(
                            RcDoc::text(","),
                            get_comment_after_end(vars[1].info.0.end, &mut context.tokens),
                            RcDoc::hardline(),
                        ))
                        .append(resource_doc),
                )
                .nest(context.config.indent_width)
                .append(RcDoc::hardline())
        };
        let conds = &policy.conds;
        let cond_doc =
            RcDoc::intersperse(conds.iter().map(|c| c.to_doc(context)), RcDoc::hardline());
        anno_doc
            .append(
                get_leading_comment_doc_from_str(&eff_leading_comment).append(
                    eff_doc
                        .append(RcDoc::line())
                        .append(add_comment(
                            RcDoc::text("("),
                            get_comment_after_end(policy.effect.info.0.end, &mut context.tokens),
                            RcDoc::nil(),
                        ))
                        .group(),
                ),
            )
            .append(vars_doc)
            .append(add_comment(
                RcDoc::text(")"),
                get_comment_after_end(vars[2].info.0.end, &mut context.tokens),
                if conds.is_empty() {
                    RcDoc::nil()
                } else {
                    RcDoc::hardline()
                },
            ))
            .append(cond_doc)
            .append(add_comment(
                RcDoc::text(";"),
                get_comment_at_end(self.info.0.end, &mut context.tokens),
                RcDoc::nil(),
            ))
    }
}
