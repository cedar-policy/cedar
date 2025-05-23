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

use super::utils::*;
use super::Context;
use cedar_policy_core::parser::AsLocRef;
use cedar_policy_core::parser::{cst::*, Node};
use pretty::RcDoc;

use super::token::Comment;

/// The trait to convert a CST to a RcDoc
pub trait Doc {
    /// Convert a type implementing this trait to a `RcDoc`.
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>>;
}

impl Doc for Ident {
    // An Ident's doc is itself.
    fn to_doc<'src>(&self, _context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        Some(RcDoc::as_string(self))
    }
}

impl Doc for Node<Option<VariableDef>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        let vd = self.as_inner()?;

        let start_comment = get_comment_at_start(
            self.loc.as_loc_ref().map(|loc| loc.span),
            &mut context.tokens,
        )?;
        let var_doc = vd.variable.as_inner()?.to_doc(context)?;

        let is_doc = match &vd.entity_type {
            Some(entity_type) => Some(
                RcDoc::line()
                    .append(add_comment(
                        RcDoc::text("is"),
                        get_comment_after_end(
                            vd.variable.loc.as_loc_ref().map(|loc| loc.span),
                            &mut context.tokens,
                        )?,
                        RcDoc::nil(),
                    ))
                    .group()
                    .append(RcDoc::line().append(add_comment(
                        entity_type.to_doc(context)?,
                        get_comment_at_start(
                            entity_type.loc.as_loc_ref().map(|loc| loc.span),
                            &mut context.tokens,
                        )?,
                        RcDoc::nil(),
                    )))
                    .nest(context.config.indent_width)
                    .group(),
            ),
            None => Some(RcDoc::nil()),
        }?;

        Some(match &vd.ineq {
            Some((op, rhs)) => {
                let op_comment = match &vd.entity_type {
                    Some(entity_type) => get_comment_after_end(
                        entity_type.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    None => get_comment_after_end(
                        vd.variable.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                };
                get_leading_comment_doc_from_str(start_comment.leading_comment()).append(
                    var_doc
                        .append(get_trailing_comment_doc_from_str(
                            start_comment.trailing_comment(),
                            RcDoc::nil(),
                        ))
                        .append(is_doc)
                        .append(RcDoc::line())
                        .append(add_comment(RcDoc::as_string(op), op_comment, RcDoc::nil()))
                        .group()
                        .append(
                            RcDoc::line()
                                .append(rhs.to_doc(context))
                                .nest(context.config.indent_width),
                        )
                        .group(),
                )
            }
            None => add_comment(var_doc, start_comment, RcDoc::nil()).append(is_doc),
        })
    }
}

impl Doc for Node<Option<Cond>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        let cond = self.as_inner()?;
        let lb_comment = get_comment_after_end(
            cond.cond.loc.as_loc_ref().map(|loc| loc.span),
            &mut context.tokens,
        )?;
        let rb_comment = get_comment_at_end(
            self.loc.as_loc_ref().map(|loc| loc.span),
            &mut context.tokens,
        )?;
        let cond_comment = get_comment_at_start(
            cond.cond.loc.as_loc_ref().map(|loc| loc.span),
            &mut context.tokens,
        )?;

        let rb_doc = add_comment(RcDoc::text("}"), rb_comment, RcDoc::nil());
        let cond_doc = cond.cond.to_doc(context)?;
        Some(match cond.expr.as_ref() {
            Some(expr) => {
                let expr_leading_comment = get_leading_comment_at_start(
                    expr.loc.as_loc_ref().map(|loc| loc.span),
                    &mut context.tokens,
                )?;
                let expr_doc = expr.to_doc(context)?;
                get_leading_comment_doc_from_str(cond_comment.leading_comment()).append(
                    cond_doc
                        .append(get_trailing_comment_doc_from_str(
                            cond_comment.trailing_comment(),
                            RcDoc::line(),
                        ))
                        .append(
                            get_leading_comment_doc_from_str(lb_comment.leading_comment()).append(
                                RcDoc::text("{").append(
                                    get_trailing_comment_doc_from_str(
                                        lb_comment.trailing_comment(),
                                        RcDoc::line(),
                                    )
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
            None => get_leading_comment_doc_from_str(cond_comment.leading_comment()).append(
                cond_doc
                    .append(get_trailing_comment_doc_from_str(
                        cond_comment.trailing_comment(),
                        RcDoc::line(),
                    ))
                    .append(
                        get_leading_comment_doc_from_str(lb_comment.leading_comment()).append(
                            RcDoc::text("{")
                                .append(get_trailing_comment_doc_from_str(
                                    lb_comment.trailing_comment(),
                                    RcDoc::line(),
                                ))
                                .append(rb_doc)
                                .group(),
                        ),
                    )
                    .group(),
            ),
        })
    }
}

impl Doc for Node<Option<Expr>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        match self.as_inner()? {
            Expr::Expr(expr_impl) => match expr_impl.expr.as_ref() {
                ExprData::If(c, t, e) => {
                    fn pp_group<'src>(
                        s: &'src str,
                        c: Comment<'src>,
                        e: &Node<Option<Expr>>,
                        context: &mut Context<'_, 'src>,
                    ) -> RcDoc<'src> {
                        add_comment(RcDoc::text(s), c, RcDoc::nil()).append(
                            RcDoc::line()
                                .append(e.to_doc(context))
                                .nest(context.config.indent_width),
                        )
                    }
                    let if_comment = get_comment_at_start(
                        self.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?;
                    let then_comment = get_comment_after_end(
                        c.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?;
                    let else_comment = get_comment_after_end(
                        t.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?;
                    Some(
                        pp_group("if", if_comment, c, context)
                            .append(RcDoc::line())
                            .append(pp_group("then", then_comment, t, context))
                            .append(RcDoc::line())
                            .append(pp_group("else", else_comment, e, context))
                            .group(),
                    )
                }
                ExprData::Or(e) => e.to_doc(context),
            },
            #[cfg(feature = "tolerant-ast")]
            Expr::ErrorExpr => None,
        }
    }
}

impl Doc for Node<Option<Or>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        let e = self.as_inner()?;
        let initial = &e.initial;
        let extended = &e.extended;
        // Convert a list of and/or expressions `(,initial ,@extended) to a doc separated by the operator.
        // We want to make each subexpression on an individual line and put the operator on the right
        let es: Vec<_> = std::iter::once(initial).chain(extended.iter()).collect();
        let mut d: RcDoc<'_> = RcDoc::nil();
        for e in es.iter().take(es.len() - 1) {
            let op_comment =
                get_comment_after_end(e.loc.as_loc_ref().map(|loc| loc.span), &mut context.tokens)?;
            d = d
                .append(e.to_doc(context))
                .append(RcDoc::space())
                .append(add_comment(RcDoc::text("||"), op_comment, RcDoc::line()));
        }
        Some(d.append(es.last()?.to_doc(context)))
    }
}

impl Doc for Node<Option<And>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        let e = self.as_inner()?;
        let initial = &e.initial;
        let extended = &e.extended;
        // Convert a list of and/or expressions `(,initial ,@extended) to a doc separated by the operator.
        // We want to make each subexpression on an individual line and put the operator on the right
        let es: Vec<_> = std::iter::once(initial).chain(extended.iter()).collect();
        let mut d: RcDoc<'_> = RcDoc::nil();
        for e in es.iter().take(es.len() - 1) {
            let op_comment =
                get_comment_after_end(e.loc.as_loc_ref().map(|loc| loc.span), &mut context.tokens)?;
            d = d
                .append(e.to_doc(context))
                .append(RcDoc::space())
                .append(add_comment(RcDoc::text("&&"), op_comment, RcDoc::line()));
        }
        Some(d.append(es.last()?.to_doc(context)))
    }
}

impl Doc for Node<Option<Relation>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        let e = self.as_inner()?;
        match e {
            Relation::Common { initial, extended } => {
                match extended.as_slice() {
                    [] => initial.to_doc(context),
                    [(op, n)] =>
                    // do not group due to the limitation of current design
                    {
                        Some(
                            initial
                                .to_doc(context)?
                                .append(RcDoc::space())
                                .append(add_comment(
                                    RcDoc::as_string(op),
                                    get_comment_after_end(
                                        initial.loc.as_loc_ref().map(|loc| loc.span),
                                        &mut context.tokens,
                                    )?,
                                    RcDoc::nil(),
                                ))
                                .append(RcDoc::space())
                                .append(n.to_doc(context)),
                        )
                    }
                    _ => None,
                }
            }
            Relation::Has { target, field } => Some(
                target
                    .to_doc(context)?
                    .append(RcDoc::line())
                    .append(add_comment(
                        RcDoc::text("has"),
                        get_comment_after_end(
                            target.loc.as_loc_ref().map(|loc| loc.span),
                            &mut context.tokens,
                        )?,
                        RcDoc::nil(),
                    ))
                    .append(RcDoc::line())
                    .append(field.to_doc(context)?.nest(context.config.indent_width))
                    .group(),
            ),
            Relation::Like { target, pattern } => Some(
                target
                    .to_doc(context)?
                    .append(RcDoc::line())
                    .append(add_comment(
                        RcDoc::text("like"),
                        get_comment_after_end(
                            target.loc.as_loc_ref().map(|loc| loc.span),
                            &mut context.tokens,
                        )?,
                        RcDoc::nil(),
                    ))
                    .append(RcDoc::line())
                    .append(pattern.to_doc(context)?.nest(context.config.indent_width))
                    .group(),
            ),
            Relation::IsIn {
                target,
                entity_type,
                in_entity,
            } => {
                let doc_is = target
                    .to_doc(context)?
                    .append(RcDoc::space())
                    .append(add_comment(
                        RcDoc::text("is"),
                        get_comment_after_end(
                            target.loc.as_loc_ref().map(|loc| loc.span),
                            &mut context.tokens,
                        )?,
                        RcDoc::nil(),
                    ))
                    .append(RcDoc::space())
                    .append(
                        entity_type
                            .to_doc(context)?
                            .nest(context.config.indent_width),
                    );
                Some(
                    match in_entity {
                        Some(in_entity) => doc_is
                            .append(RcDoc::line())
                            .append(add_comment(
                                RcDoc::text("in"),
                                get_comment_after_end(
                                    entity_type.loc.as_loc_ref().map(|loc| loc.span),
                                    &mut context.tokens,
                                )?,
                                RcDoc::nil(),
                            ))
                            .append(RcDoc::space())
                            .append(in_entity.to_doc(context)?.nest(context.config.indent_width)),
                        None => doc_is,
                    }
                    .group(),
                )
            }
        }
    }
}

impl Doc for AddOp {
    fn to_doc<'src>(&self, _context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        Some(RcDoc::as_string(self))
    }
}

impl Doc for Node<Option<Add>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        let e = self.as_inner()?;
        let initial = &e.initial;
        let extended = &e.extended;
        // Convert a list of arithmetic expressions to a doc separated by the operators
        // We keep the convention that operators are on the right but do not put a subexpression on a single line.
        Some(
            extended
                .iter()
                .try_fold((initial.to_doc(context)?, initial), |pair, (op, e)| {
                    Some((
                        pair.0
                            .append(RcDoc::space())
                            .append(add_comment(
                                op.to_doc(context)?,
                                get_comment_after_end(
                                    pair.1.loc.as_loc_ref().map(|loc| loc.span),
                                    &mut context.tokens,
                                )?,
                                RcDoc::nil(),
                            ))
                            .append(RcDoc::line())
                            .append(e.to_doc(context)),
                        e,
                    ))
                })?
                .0
                .group(),
        )
    }
}

impl Doc for MultOp {
    fn to_doc<'src>(&self, __context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        Some(RcDoc::as_string(self))
    }
}

impl Doc for Node<Option<Mult>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        let e = self.as_inner()?;
        let initial = &e.initial;
        let extended = &e.extended;
        // Convert a list of arithmetic expressions to a doc separated by the operators
        // We keep the convention that operators are on the right but do not put a subexpression on a single line.
        Some(
            extended
                .iter()
                .try_fold((initial.to_doc(context)?, initial), |pair, (op, e)| {
                    Some((
                        pair.0
                            .append(RcDoc::space())
                            .append(add_comment(
                                op.to_doc(context)?,
                                get_comment_after_end(
                                    pair.1.loc.as_loc_ref().map(|loc| loc.span),
                                    &mut context.tokens,
                                )?,
                                RcDoc::nil(),
                            ))
                            .append(RcDoc::line())
                            .append(e.to_doc(context)),
                        e,
                    ))
                })?
                .0
                .group(),
        )
    }
}

impl Doc for Node<Option<Unary>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        let e = self.as_inner()?;
        if let Some(op) = e.op {
            match op {
                NegOp::OverBang | NegOp::OverDash => None,
                NegOp::Bang(n) | NegOp::Dash(n) => {
                    let sloc = self.loc.as_loc_ref()?;
                    let eloc = e.item.loc.as_loc_ref()?;
                    let comment = get_comment_in_range(
                        Some((sloc.start()..eloc.start()).into()),
                        &mut context.tokens,
                    )?;
                    if comment.len() != n as usize {
                        return None;
                    }
                    Some(
                        RcDoc::intersperse(
                            (0..n)
                                .map(|i| {
                                    Some(add_comment(
                                        if matches!(op, NegOp::Bang(_)) {
                                            RcDoc::text("!")
                                        } else {
                                            RcDoc::text("-")
                                        },
                                        comment.get(i as usize)?,
                                        RcDoc::nil(),
                                    ))
                                })
                                .collect::<Option<Vec<RcDoc<'_>>>>()?,
                            RcDoc::nil(),
                        )
                        .append(e.item.as_inner()?.to_doc(context)?),
                    )
                }
            }
        } else {
            e.item.as_inner()?.to_doc(context)
        }
    }
}

impl Doc for Member {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        let item_doc = self.item.to_doc(context)?;
        Some(
            item_doc
                .append(
                    RcDoc::intersperse(
                        self.access.iter().map(|ac| ac.to_doc(context)),
                        RcDoc::line_(),
                    )
                    .nest(context.config.indent_width),
                )
                .group(),
        )
    }
}

impl Doc for Node<Option<RecInit>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        let e = self.as_inner()?;
        let key_doc = e.0.to_doc(context)?;
        let value_doc = e.1.to_doc(context)?;
        Some(
            key_doc
                .append(RcDoc::line_())
                .append(add_comment(
                    RcDoc::text(":"),
                    get_comment_after_end(
                        e.0.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    RcDoc::nil(),
                ))
                .append(value_doc),
        )
    }
}

impl Doc for Node<Option<Name>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        let e = self.as_inner()?;
        let path = &e.path;
        let n = &e.name;
        if path.is_empty() {
            n.to_doc(context)
        } else {
            Some(
                path.get(1..)?
                    .iter()
                    .try_fold(
                        (path.first()?.to_doc(context)?, path.first()?),
                        |pair, p| {
                            let (d, e) = pair;
                            Some((
                                d.append(add_comment(
                                    RcDoc::text("::"),
                                    get_comment_after_end(
                                        e.loc.as_loc_ref().map(|loc| loc.span),
                                        &mut context.tokens,
                                    )?,
                                    RcDoc::nil(),
                                ))
                                .append(p.to_doc(context)?),
                                p,
                            ))
                        },
                    )?
                    .0
                    .append(add_comment(
                        RcDoc::text("::"),
                        get_comment_after_end(
                            path.last()?.loc.as_loc_ref().map(|loc| loc.span),
                            &mut context.tokens,
                        )?,
                        RcDoc::nil(),
                    ))
                    .append(n.to_doc(context)),
            )
        }
    }
}

impl Doc for Node<Option<Str>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        let e = self.as_inner()?;
        // Note: the input string may contain newlines, but `utils::create_multiline_doc`
        // _cannot_ be used here because this function will change indentation
        // on newlines, which may alter the string content.
        Some(add_comment(
            RcDoc::as_string(e),
            get_comment_at_start(
                self.loc.as_loc_ref().map(|loc| loc.span),
                &mut context.tokens,
            )?,
            RcDoc::nil(),
        ))
    }
}

impl Doc for Node<Option<Ref>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        match self.as_inner()? {
            Ref::Uid { path, eid } => Some(
                path.to_doc(context)?
                    .append(add_comment(
                        RcDoc::text("::"),
                        get_comment_after_end(
                            path.loc.as_loc_ref().map(|loc| loc.span),
                            &mut context.tokens,
                        )?,
                        RcDoc::nil(),
                    ))
                    .append(eid.to_doc(context)?),
            ),
            Ref::Ref { path: _, rinits: _ } => None,
        }
    }
}

impl Doc for Node<Option<Literal>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        Some(add_comment(
            RcDoc::as_string(self.as_inner()?),
            get_comment_at_start(
                self.loc.as_loc_ref().map(|loc| loc.span),
                &mut context.tokens,
            )?,
            RcDoc::nil(),
        ))
    }
}

impl Doc for Node<Option<Slot>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        Some(add_comment(
            RcDoc::as_string(self.as_inner()?),
            get_comment_at_start(
                self.loc.as_loc_ref().map(|loc| loc.span),
                &mut context.tokens,
            )?,
            RcDoc::nil(),
        ))
    }
}

impl Doc for Node<Option<Primary>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        let e = self.as_inner()?;
        match e {
            Primary::Literal(lit) => lit.to_doc(context),
            Primary::Ref(r) => r.to_doc(context),
            Primary::Name(n) => n.to_doc(context),
            Primary::Expr(e) => Some(
                add_comment(
                    RcDoc::text("("),
                    get_comment_at_start(
                        self.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    RcDoc::nil(),
                )
                .append(RcDoc::nil())
                .append(e.to_doc(context)?.nest(1))
                .append(RcDoc::nil())
                .append(add_comment(
                    RcDoc::text(")"),
                    get_comment_at_end(
                        self.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    RcDoc::nil(),
                ))
                .group(),
            ),
            Primary::EList(el) => Some(add_brackets(
                if el.is_empty() {
                    RcDoc::nil()
                } else {
                    el.get(1..)?
                        .iter()
                        .try_fold((el.first()?.to_doc(context)?, el.first()?), |pair, v| {
                            let (d, e) = pair;
                            Some((
                                d.append(add_comment(
                                    RcDoc::text(","),
                                    get_comment_after_end(
                                        e.loc.as_loc_ref().map(|loc| loc.span),
                                        &mut context.tokens,
                                    )?,
                                    RcDoc::nil(),
                                ))
                                .append(RcDoc::line())
                                .append(v.to_doc(context)),
                                v,
                            ))
                        })?
                        .0
                },
                add_comment(
                    RcDoc::text("["),
                    get_comment_at_start(
                        self.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    RcDoc::nil(),
                ),
                add_comment(
                    RcDoc::text("]"),
                    get_comment_at_end(
                        self.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    RcDoc::nil(),
                ),
            )),
            Primary::RInits(ri) => Some(add_brackets(
                if ri.is_empty() {
                    RcDoc::nil()
                } else {
                    ri.get(1..)?
                        .iter()
                        .try_fold((ri.first()?.to_doc(context)?, ri.first()?), |pair, v| {
                            let (d, e) = pair;
                            Some((
                                d.append(add_comment(
                                    RcDoc::text(","),
                                    get_comment_after_end(
                                        e.loc.as_loc_ref().map(|loc| loc.span),
                                        &mut context.tokens,
                                    )?,
                                    RcDoc::nil(),
                                ))
                                .append(RcDoc::line())
                                .append(v.to_doc(context)),
                                v,
                            ))
                        })?
                        .0
                },
                add_comment(
                    RcDoc::text("{"),
                    get_comment_at_start(
                        self.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    RcDoc::nil(),
                ),
                add_comment(
                    RcDoc::text("}"),
                    get_comment_at_end(
                        self.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    RcDoc::nil(),
                ),
            )),
            Primary::Slot(slot) => slot.to_doc(context),
        }
    }
}

impl Doc for Node<Option<MemAccess>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        let e = self.as_inner()?;
        match e {
            MemAccess::Field(f) => Some(
                add_comment(
                    RcDoc::text("."),
                    get_comment_at_start(
                        self.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    RcDoc::nil(),
                )
                .append(f.to_doc(context)),
            ),
            MemAccess::Call(args) => Some(
                add_comment(
                    RcDoc::text("("),
                    get_comment_at_start(
                        self.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    RcDoc::nil(),
                )
                .append(RcDoc::line_())
                .append(if args.is_empty() {
                    RcDoc::nil()
                } else {
                    args.get(1..)?
                        .iter()
                        .try_fold(
                            (args.first()?.to_doc(context)?, args.first()?),
                            |pair, arg| {
                                let (d, e) = pair;
                                Some((
                                    d.append(add_comment(
                                        RcDoc::text(","),
                                        get_comment_after_end(
                                            e.loc.as_loc_ref().map(|loc| loc.span),
                                            &mut context.tokens,
                                        )?,
                                        RcDoc::nil(),
                                    ))
                                    .append(RcDoc::line())
                                    .append(arg.to_doc(context)),
                                    arg,
                                ))
                            },
                        )?
                        .0
                })
                .nest(context.config.indent_width)
                .append(RcDoc::line_())
                .append(add_comment(
                    RcDoc::text(")"),
                    get_comment_at_end(
                        self.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    RcDoc::nil(),
                )),
            ),
            MemAccess::Index(idx) => Some(
                add_comment(
                    RcDoc::text("["),
                    get_comment_at_start(
                        self.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    RcDoc::nil(),
                )
                .append(RcDoc::line_())
                .append(idx.to_doc(context))
                .append(RcDoc::line_())
                .append(add_comment(
                    RcDoc::text("]"),
                    get_comment_at_end(
                        self.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    RcDoc::nil(),
                )),
            ),
        }
    }
}

impl Doc for Node<Option<Annotation>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        let annotation = self.as_inner()?;
        let id_doc = annotation.key.to_doc(context);
        let at_doc = add_comment(
            RcDoc::text("@"),
            get_comment_at_start(
                self.loc.as_loc_ref().map(|loc| loc.span),
                &mut context.tokens,
            )?,
            RcDoc::nil(),
        );
        let val_doc = match annotation.value.as_ref() {
            Some(value) => {
                let lp_doc = add_comment(
                    RcDoc::text("("),
                    get_comment_after_end(
                        annotation.key.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    RcDoc::nil(),
                );
                let val_doc = value.to_doc(context);
                let rp_doc = add_comment(
                    RcDoc::text(")"),
                    get_comment_at_end(
                        self.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    RcDoc::hardline(),
                );
                lp_doc.append(val_doc).append(rp_doc)
            }
            None => RcDoc::hardline(),
        };

        Some(at_doc.append(id_doc).append(val_doc))
    }
}

impl Doc for Node<Option<Ident>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        Some(add_comment(
            self.as_inner()?.to_doc(context)?,
            get_comment_at_start(
                self.loc.as_loc_ref().map(|loc| loc.span),
                &mut context.tokens,
            )?,
            RcDoc::nil(),
        ))
    }
}

impl Doc for Node<Option<Policy>> {
    fn to_doc<'src>(&self, context: &mut Context<'_, 'src>) -> Option<RcDoc<'src>> {
        let policy = self.as_inner()?;
        let policy = match policy {
            Policy::Policy(policy_impl) => policy_impl,
            #[cfg(feature = "tolerant-ast")]
            Policy::PolicyError => return None,
        };

        let anno_doc = RcDoc::intersperse(
            policy.annotations.iter().map(|a| a.to_doc(context)),
            RcDoc::nil(),
        );
        let eff_leading_comment = get_leading_comment_at_start(
            policy.effect.loc.as_loc_ref().map(|loc| loc.span),
            &mut context.tokens,
        )?;
        let eff_doc = policy.effect.to_doc(context)?;
        let vars = &policy.variables;
        let principal_doc = vars.first()?.to_doc(context)?;
        let action_doc = vars.get(1)?.to_doc(context)?;
        let resource_doc = vars.get(2)?.to_doc(context)?;
        let vars_doc = if vars.get(0..3)?.iter().all(|v| {
            if let Some(v) = v.as_inner() {
                v.ineq.is_none() && v.entity_type.is_none()
            } else {
                false
            }
        }) {
            principal_doc
                .append(add_comment(
                    RcDoc::text(","),
                    get_comment_after_end(
                        vars.first()?.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    RcDoc::space(),
                ))
                .append(action_doc)
                .append(add_comment(
                    RcDoc::text(","),
                    get_comment_after_end(
                        vars.get(1)?.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
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
                            get_comment_after_end(
                                vars.first()?.loc.as_loc_ref().map(|loc| loc.span),
                                &mut context.tokens,
                            )?,
                            RcDoc::hardline(),
                        ))
                        .append(action_doc)
                        .append(add_comment(
                            RcDoc::text(","),
                            get_comment_after_end(
                                vars.get(1)?.loc.as_loc_ref().map(|loc| loc.span),
                                &mut context.tokens,
                            )?,
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
        Some(
            anno_doc
                .append(
                    get_leading_comment_doc_from_str(&eff_leading_comment).append(
                        eff_doc
                            .append(RcDoc::line())
                            .append(add_comment(
                                RcDoc::text("("),
                                get_comment_after_end(
                                    policy.effect.loc.as_loc_ref().map(|loc| loc.span),
                                    &mut context.tokens,
                                )?,
                                RcDoc::nil(),
                            ))
                            .group(),
                    ),
                )
                .append(vars_doc)
                .append(add_comment(
                    RcDoc::text(")"),
                    get_comment_after_end(
                        vars.get(2)?.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    if conds.is_empty() {
                        RcDoc::nil()
                    } else {
                        RcDoc::hardline()
                    },
                ))
                .append(cond_doc)
                .append(add_comment(
                    RcDoc::text(";"),
                    get_comment_at_end(
                        self.loc.as_loc_ref().map(|loc| loc.span),
                        &mut context.tokens,
                    )?,
                    RcDoc::nil(),
                )),
        )
    }
}
