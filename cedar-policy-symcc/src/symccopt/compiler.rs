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

use std::sync::Arc;

use cedar_policy_core::ast::{BinaryOp, Expr, ExprKind, UnaryOp, Var};

pub use crate::symcc::compiler::Result;
use crate::{
    err::{CompileError, ExtError},
    ext::Ext,
    symcc::{
        compiler::{
            compile_attrs_of, compile_get_tag, compile_has_tag, compile_in_ent, compile_in_set,
            extract_first, extract_first2, reducible_eq,
        },
        env::{SymEntities, SymEnv, SymRequest},
        extfun,
    },
    term::{Term, TermPrim},
    term_factory::{
        bvadd, bvmul, bvneg, bvnego, bvsaddo, bvsle, bvslt, bvsmulo, bvssubo, bvsub, eq,
        ext_datetime_val, ext_duration_val, if_all_some, if_false, if_some, is_some, ite, not,
        option_get, record_get, record_of, set_intersects, set_is_empty, set_member, set_of,
        set_subset, some_of, string_like,
    },
    term_type::TermType,
    type_abbrevs::*,
};

/// Not present in the Lean, but serves Rust-specific performance optimizations;
/// see notes where this is used
pub struct Footprint {
    terms: Arc<dyn Iterator<Item = Term>>,
}

impl Iterator for Footprint {
    type Item = Term;

    fn next(&mut self) -> Option<Term> {
        // Since `Footprint` does not implement `Clone`, and `terms` is a
        // private field, there is no way that anyone else could have cloned
        // the inner `Arc` and gotten a reference to it.
        // So, we know we definitively have the only reference to this `Arc`,
        // and `get_mut()` will succeed.
        let terms = Arc::get_mut(&mut self.terms);
        debug_assert!(terms.is_some());
        // When debug assertions are disabled, we avoid panicking if the `get_mut()`
        // assumption is violated, and instead just return `None`.
        terms?.next()
    }
}

impl Footprint {
    pub fn empty() -> Self {
        Self {
            terms: Arc::new(std::iter::empty()),
        }
    }

    pub fn singleton(term: Term) -> Self {
        Self {
            terms: Arc::new(std::iter::once(term)),
        }
    }

    pub fn from_iter(it: impl Iterator<Item = Term> + 'static) -> Self {
        Self {
            terms: Arc::new(it),
        }
    }
}

/// Structure returned by the optimized compiler, as opposed to the unoptimized
/// compiler which just produces a `Term`
pub struct CompileResult {
    /// Well-formed term of the appropriate type, representing the compiled expression
    pub term: Term,
    /// The "footprint" of the compiled expression.
    ///
    /// This is the terms corresponding to subexpressions of the compiled expression
    /// of the following form:
    ///
    /// * A variable term with an entity type
    /// * An entity reference literal
    /// * An attribute access expression with an entity type
    /// * A binary (`getTag`) expression with an entity type
    ///
    /// These are the only basic expressions in Cedar that may evaluate to an entity.
    /// All other expressions that evaluate to an entity are built up from the above
    /// basic expressions.
    ///
    /// All terms in the `footprint` are of type `TermType::Option(TermType::Entity)`.
    ///
    /// In the Lean, this is a Set. In Rust, we avoid repeatedly collecting into
    /// a `BTreeSet` for each compiled subexpression, by using a `dyn Iterator`
    /// internally rather than `BTreeSet` here. Ultimately, the caller of
    /// `compile` will collect into a `BTreeSet` to remove duplicates.
    pub footprint: Footprint,
}

impl CompileResult {
    /// Map on the `Term`, leaving the `footprint` unchanged
    fn map_term(self, f: impl FnOnce(Term) -> Term) -> Self {
        Self {
            term: f(self.term),
            ..self
        }
    }
}

/// Return the footprint of this compiled term _itself_ (not counting its subexpressions).
/// Only terms of option-entity type have any direct footprint.
///
/// This corresponds to `of_entity` in the `footprint` function in `symcc/enforcer.rs`,
/// except that we only call it when compiling to `Term` was successful, so it takes a
/// `Term` argument rather than `Result<Term>`.
///
/// In Lean, this returns a `Set` that is either singleton or empty.
/// In Rust, we further optimize by just returning an `Option`, taking advantage
/// of the fact that we never return a `Set` with multiple elements.
fn direct_footprint(term: Term) -> Option<Term> {
    if term.type_of().is_option_entity_type() {
        Some(term)
    } else {
        None
    }
}

fn compile_prim(p: &Prim, es: &SymEntities) -> Result<CompileResult> {
    match p {
        Prim::Bool(b) => Ok(CompileResult {
            term: some_of((*b).into()),
            footprint: Footprint::empty(),
        }),
        Prim::Long(i) => Ok(CompileResult {
            term: some_of((*i).into()),
            footprint: Footprint::empty(),
        }),
        Prim::String(s) => Ok(CompileResult {
            term: some_of(s.clone().into()),
            footprint: Footprint::empty(),
        }),
        Prim::EntityUID(uid) => {
            let uid = core_uid_into_uid(uid);
            if es.is_valid_entity_uid(uid) {
                let term = some_of(uid.clone().into());
                Ok(CompileResult {
                    footprint: Footprint::singleton(term.clone()),
                    term,
                })
            } else {
                Err(CompileError::TypeError)
            }
        }
    }
}

fn compile_var(v: &Var, req: &SymRequest) -> Result<CompileResult> {
    match v {
        Var::Principal => {
            if req.principal.type_of().is_entity_type() {
                let term = some_of(req.principal.clone());
                Ok(CompileResult {
                    footprint: Footprint::singleton(term.clone()),
                    term,
                })
            } else {
                Err(CompileError::TypeError)
            }
        }
        Var::Action => {
            if req.action.type_of().is_entity_type() {
                let term = some_of(req.action.clone());
                Ok(CompileResult {
                    footprint: Footprint::singleton(term.clone()),
                    term,
                })
            } else {
                Err(CompileError::TypeError)
            }
        }
        Var::Resource => {
            if req.resource.type_of().is_entity_type() {
                let term = some_of(req.resource.clone());
                Ok(CompileResult {
                    footprint: Footprint::singleton(term.clone()),
                    term,
                })
            } else {
                Err(CompileError::TypeError)
            }
        }
        Var::Context => {
            if req.context.type_of().is_record_type() {
                Ok(CompileResult {
                    term: some_of(req.context.clone()),
                    footprint: Footprint::empty(),
                })
            } else {
                Err(CompileError::TypeError)
            }
        }
    }
}

fn compile_app1(op1: UnaryOp, arg: CompileResult) -> Result<CompileResult> {
    match (op1, arg.term.type_of()) {
        (UnaryOp::Not, TermType::Bool) => Ok(arg.map_term(|term| some_of(not(term)))),
        (UnaryOp::Neg, TermType::Bitvec { n: SIXTY_FOUR }) => {
            Ok(arg.map_term(|term| if_false(bvnego(term.clone()), bvneg(term))))
        }
        (UnaryOp::IsEmpty, TermType::Set { .. }) => {
            Ok(arg.map_term(|term| some_of(set_is_empty(term))))
        }
        // No `like` or `is` cases here, because in Rust those are not
        // `UnaryOp`s, so we can't fully match the Lean.
        // In Rust we handle those in `compile_like()` and `compile_is()`.
        (_, _) => Err(CompileError::TypeError),
    }
}

/// In Lean, `compileApp₁` handles this case, but in Rust, `Like` is a separate
/// `Expr` variant and not part of `UnaryApp`.
fn compile_like(arg: CompileResult, pat: OrdPattern) -> Result<CompileResult> {
    match arg.term.type_of() {
        TermType::String => Ok(arg.map_term(|term| some_of(string_like(term, pat)))),
        _ => Err(CompileError::TypeError),
    }
}

/// In Lean, `compileApp₁` handles this case, but in Rust, `Is` is a separate
/// `Expr` variant and not part of `UnaryApp`.
fn compile_is(arg: CompileResult, ety1: &EntityType) -> Result<CompileResult> {
    match arg.term.type_of() {
        TermType::Entity { ety: ety2 } => Ok(arg.map_term(|_| some_of((ety1 == &ety2).into()))),
        _ => Err(CompileError::TypeError),
    }
}

fn compile_app2(
    op2: BinaryOp,
    arg1: CompileResult,
    arg2: CompileResult,
    es: &SymEntities,
) -> Result<CompileResult> {
    use BinaryOp::*;
    use ExtType::*;
    use TermType::*;
    // compute the footprint of the arguments, not counting the contribution of the `direct_footprint` of the
    // `BinaryOp` term (if any) (particularly relevant for `getTag`)
    let args_footprint = arg1.footprint.chain(arg2.footprint);
    // mimicking the behavior of the unoptimized compiler in how the direct footprint for the binaryOp term
    // itself is computed
    let binary_op_footprint =
        |term| direct_footprint(if_some(arg1.term.clone(), if_some(arg2.term.clone(), term)));
    // for the rest of this function, we consider only the `option_get`-ed args.
    // see detailed note in the toplevel optimized `compile()` function below.
    let t1 = option_get(arg1.term.clone());
    let t2 = option_get(arg2.term.clone());
    match (op2, t1.type_of(), t2.type_of()) {
        (Eq, ty1, ty2) => {
            let term = if reducible_eq(&ty1, &ty2)? {
                some_of(eq(t1, t2))
            } else {
                some_of(false.into())
            };
            Ok(CompileResult {
                // assuming everything is well-typed, the `binary_op_footprint()` here will be `None`,
                // but: (1) we want the two compilers to agree even on non-well-typed inputs,
                // for ease of proofs in the Lean; and (2) the unoptimized compiler adds this term
                footprint: Footprint::from_iter(
                    args_footprint.chain(binary_op_footprint(term.clone())),
                ),
                term,
            })
        }
        (Less, Bitvec { n: SIXTY_FOUR }, Bitvec { n: SIXTY_FOUR }) => {
            let term = some_of(bvslt(t1, t2));
            Ok(CompileResult {
                // assuming everything is well-typed, the `binary_op_footprint()` here will be `None`,
                // but: (1) we want the two compilers to agree even on non-well-typed inputs,
                // for ease of proofs in the Lean; and (2) the unoptimized compiler adds this term
                footprint: Footprint::from_iter(
                    args_footprint.chain(binary_op_footprint(term.clone())),
                ),
                term,
            })
        }
        (Less, Ext { xty: DateTime }, Ext { xty: DateTime }) => {
            let term = some_of(bvslt(ext_datetime_val(t1), ext_datetime_val(t2)));
            Ok(CompileResult {
                // assuming everything is well-typed, the `binary_op_footprint()` here will be `None`,
                // but: (1) we want the two compilers to agree even on non-well-typed inputs,
                // for ease of proofs in the Lean; and (2) the unoptimized compiler adds this term
                footprint: Footprint::from_iter(
                    args_footprint.chain(binary_op_footprint(term.clone())),
                ),
                term,
            })
        }
        (Less, Ext { xty: Duration }, Ext { xty: Duration }) => {
            let term = some_of(bvslt(ext_duration_val(t1), ext_duration_val(t2)));
            Ok(CompileResult {
                // assuming everything is well-typed, the `binary_op_footprint()` here will be `None`,
                // but: (1) we want the two compilers to agree even on non-well-typed inputs,
                // for ease of proofs in the Lean; and (2) the unoptimized compiler adds this term
                footprint: Footprint::from_iter(
                    args_footprint.chain(binary_op_footprint(term.clone())),
                ),
                term,
            })
        }
        (LessEq, Bitvec { n: SIXTY_FOUR }, Bitvec { n: SIXTY_FOUR }) => {
            let term = some_of(bvsle(t1, t2));
            Ok(CompileResult {
                // assuming everything is well-typed, the `binary_op_footprint()` here will be `None`,
                // but: (1) we want the two compilers to agree even on non-well-typed inputs,
                // for ease of proofs in the Lean; and (2) the unoptimized compiler adds this term
                footprint: Footprint::from_iter(
                    args_footprint.chain(binary_op_footprint(term.clone())),
                ),
                term,
            })
        }
        (LessEq, Ext { xty: DateTime }, Ext { xty: DateTime }) => {
            let term = some_of(bvsle(ext_datetime_val(t1), ext_datetime_val(t2)));
            Ok(CompileResult {
                // assuming everything is well-typed, the `binary_op_footprint()` here will be `None`,
                // but: (1) we want the two compilers to agree even on non-well-typed inputs,
                // for ease of proofs in the Lean; and (2) the unoptimized compiler adds this term
                footprint: Footprint::from_iter(
                    args_footprint.chain(binary_op_footprint(term.clone())),
                ),
                term,
            })
        }
        (LessEq, Ext { xty: Duration }, Ext { xty: Duration }) => {
            let term = some_of(bvsle(ext_duration_val(t1), ext_duration_val(t2)));
            Ok(CompileResult {
                // assuming everything is well-typed, the `binary_op_footprint()` here will be `None`,
                // but: (1) we want the two compilers to agree even on non-well-typed inputs,
                // for ease of proofs in the Lean; and (2) the unoptimized compiler adds this term
                footprint: Footprint::from_iter(
                    args_footprint.chain(binary_op_footprint(term.clone())),
                ),
                term,
            })
        }
        (Add, Bitvec { n: SIXTY_FOUR }, Bitvec { n: SIXTY_FOUR }) => {
            let term = if_false(bvsaddo(t1.clone(), t2.clone()), bvadd(t1, t2));
            Ok(CompileResult {
                // assuming everything is well-typed, the `binary_op_footprint()` here will be `None`,
                // but: (1) we want the two compilers to agree even on non-well-typed inputs,
                // for ease of proofs in the Lean; and (2) the unoptimized compiler adds this term
                footprint: Footprint::from_iter(
                    args_footprint.chain(binary_op_footprint(term.clone())),
                ),
                term,
            })
        }
        (Sub, Bitvec { n: SIXTY_FOUR }, Bitvec { n: SIXTY_FOUR }) => {
            let term = if_false(bvssubo(t1.clone(), t2.clone()), bvsub(t1, t2));
            Ok(CompileResult {
                // assuming everything is well-typed, the `binary_op_footprint()` here will be `None`,
                // but: (1) we want the two compilers to agree even on non-well-typed inputs,
                // for ease of proofs in the Lean; and (2) the unoptimized compiler adds this term
                footprint: Footprint::from_iter(
                    args_footprint.chain(binary_op_footprint(term.clone())),
                ),
                term,
            })
        }
        (Mul, Bitvec { n: SIXTY_FOUR }, Bitvec { n: SIXTY_FOUR }) => {
            let term = if_false(bvsmulo(t1.clone(), t2.clone()), bvmul(t1, t2));
            Ok(CompileResult {
                // assuming everything is well-typed, the `binary_op_footprint()` here will be `None`,
                // but: (1) we want the two compilers to agree even on non-well-typed inputs,
                // for ease of proofs in the Lean; and (2) the unoptimized compiler adds this term
                footprint: Footprint::from_iter(
                    args_footprint.chain(binary_op_footprint(term.clone())),
                ),
                term,
            })
        }
        (Contains, Set { ty: ty1 }, ty2) => {
            if *ty1 == ty2 {
                let term = some_of(set_member(t2, t1));
                Ok(CompileResult {
                    // assuming everything is well-typed, the `binary_op_footprint()` here will be `None`,
                    // but: (1) we want the two compilers to agree even on non-well-typed inputs,
                    // for ease of proofs in the Lean; and (2) the unoptimized compiler adds this term
                    footprint: Footprint::from_iter(
                        args_footprint.chain(binary_op_footprint(term.clone())),
                    ),
                    term,
                })
            } else {
                Err(CompileError::TypeError)
            }
        }
        (ContainsAll, Set { ty: ty1 }, Set { ty: ty2 }) => {
            if *ty1 == *ty2 {
                let term = some_of(set_subset(t2, t1));
                Ok(CompileResult {
                    // assuming everything is well-typed, the `binary_op_footprint()` here will be `None`,
                    // but: (1) we want the two compilers to agree even on non-well-typed inputs,
                    // for ease of proofs in the Lean; and (2) the unoptimized compiler adds this term
                    footprint: Footprint::from_iter(
                        args_footprint.chain(binary_op_footprint(term.clone())),
                    ),
                    term,
                })
            } else {
                Err(CompileError::TypeError)
            }
        }
        (ContainsAny, Set { ty: ty1 }, Set { ty: ty2 }) => {
            if *ty1 == *ty2 {
                let term = some_of(set_intersects(t1, t2));
                Ok(CompileResult {
                    // assuming everything is well-typed, the `binary_op_footprint()` here will be `None`,
                    // but: (1) we want the two compilers to agree even on non-well-typed inputs,
                    // for ease of proofs in the Lean; and (2) the unoptimized compiler adds this term
                    footprint: Footprint::from_iter(
                        args_footprint.chain(binary_op_footprint(term.clone())),
                    ),
                    term,
                })
            } else {
                Err(CompileError::TypeError)
            }
        }
        (In, Entity { ety: ety1 }, Entity { ety: ety2 }) => {
            let term = some_of(compile_in_ent(
                t1,
                t2,
                es.ancestors_of_type(&ety1, &ety2).cloned(),
            ));
            Ok(CompileResult {
                // assuming everything is well-typed, the `binary_op_footprint()` here will be `None`,
                // but: (1) we want the two compilers to agree even on non-well-typed inputs,
                // for ease of proofs in the Lean; and (2) the unoptimized compiler adds this term
                footprint: Footprint::from_iter(
                    args_footprint.chain(binary_op_footprint(term.clone())),
                ),
                term,
            })
        }
        (In, Entity { ety: ety1 }, Set { ty }) if matches!(*ty, Entity { .. }) => {
            match Arc::unwrap_or_clone(ty) {
                Entity { ety: ety2 } => {
                    let term = some_of(compile_in_set(
                        t1,
                        t2,
                        es.ancestors_of_type(&ety1, &ety2).cloned(),
                    ));
                    Ok(CompileResult {
                        // assuming everything is well-typed, the `binary_op_footprint()` here will be `None`,
                        // but: (1) we want the two compilers to agree even on non-well-typed inputs,
                        // for ease of proofs in the Lean; and (2) the unoptimized compiler adds this term
                        footprint: Footprint::from_iter(
                            args_footprint.chain(binary_op_footprint(term.clone())),
                        ),
                        term,
                    })
                }
                #[expect(
                    clippy::unreachable,
                    reason = "Code is unreachable due to above match that type must be an Entity"
                )]
                _ => unreachable!("We just matched with entity type above"),
            }
        }
        (HasTag, Entity { ety }, String) => {
            let term = compile_has_tag(t1, t2, es.tags(&ety), &ety)?;
            Ok(CompileResult {
                // assuming everything is well-typed, the `binary_op_footprint()` here will be `None`,
                // but: (1) we want the two compilers to agree even on non-well-typed inputs,
                // for ease of proofs in the Lean; and (2) the unoptimized compiler adds this term
                footprint: Footprint::from_iter(
                    args_footprint.chain(binary_op_footprint(term.clone())),
                ),
                term,
            })
        }
        (GetTag, Entity { ety }, String) => {
            let term = compile_get_tag(t1, t2, es.tags(&ety), &ety)?;
            Ok(CompileResult {
                // in this `GetTag` case, the `binary_op_footprint` term could actually be nonempty,
                // in the case where the tags are entity-typed
                footprint: Footprint::from_iter(
                    args_footprint.chain(binary_op_footprint(term.clone())),
                ),
                term,
            })
        }
        (_, _, _) => Err(CompileError::TypeError),
    }
}

pub fn compile_has_attr(arg: CompileResult, a: &Attr, es: &SymEntities) -> Result<CompileResult> {
    let attrs = compile_attrs_of(arg.term, es)?;
    match attrs.type_of() {
        TermType::Record { rty } => match rty.get(a) {
            Some(ty) if ty.is_option_type() => Ok(CompileResult {
                term: some_of(is_some(record_get(attrs, a))),
                footprint: arg.footprint,
            }),
            Some(_) => Ok(CompileResult {
                term: some_of(true.into()),
                footprint: arg.footprint,
            }),
            None => Ok(CompileResult {
                term: some_of(false.into()),
                footprint: arg.footprint,
            }),
        },
        _ => Err(CompileError::TypeError),
    }
}

pub fn compile_get_attr(arg: CompileResult, a: &Attr, es: &SymEntities) -> Result<CompileResult> {
    // miimicking the behavior of the unoptimized compiler in how the direct
    // footprint for the `GetAttr` term itself is computed
    let get_attr_footprint = |term| direct_footprint(if_some(arg.term.clone(), term));
    // for the rest of this function, we consider only the `option_get`-ed args.
    // see detailed note in the toplevel optimized `compile()` function below.
    let term = option_get(arg.term.clone());
    let attrs = compile_attrs_of(term, es)?;
    match attrs.type_of() {
        TermType::Record { rty } => {
            let term = match rty.get(a) {
                Some(ty) if ty.is_option_type() => Ok(record_get(attrs, a)),
                Some(_) => Ok(some_of(record_get(attrs, a))),
                None => Err(CompileError::NoSuchAttribute(a.to_string())),
            }?;
            Ok(CompileResult {
                footprint: Footprint::from_iter(
                    get_attr_footprint(term.clone())
                        .into_iter()
                        .chain(arg.footprint),
                ),
                term,
            })
        }
        _ => Err(CompileError::TypeError),
    }
}

pub fn compile_if(
    arg1: CompileResult,
    arg2: Result<CompileResult>,
    arg3: Result<CompileResult>,
) -> Result<CompileResult> {
    match (&arg1.term, arg1.term.type_of()) {
        (Term::Some(it), _) if matches!(**it, Term::Prim(TermPrim::Bool(true))) => arg2, // omitting arg1.footprint is sound: unoptimized `symcc::footprint()` does that in this case, and our Lean proofs show it's sound
        (Term::Some(it), _) if matches!(**it, Term::Prim(TermPrim::Bool(false))) => arg3, // omitting arg1.footprint is sound: unoptimized `symcc::footprint()` does that in this case, and our Lean proofs show it's sound
        (_, TermType::Option { ty }) if matches!(*ty, TermType::Bool) => {
            let arg2 = arg2?;
            let arg3 = arg3?;
            if arg2.term.type_of() == arg3.term.type_of() {
                Ok(CompileResult {
                    term: if_some(
                        arg1.term.clone(),
                        ite(option_get(arg1.term), arg2.term, arg3.term),
                    ),
                    footprint: Footprint::from_iter(
                        arg1.footprint.chain(arg2.footprint).chain(arg3.footprint),
                    ),
                })
            } else {
                Err(CompileError::TypeError)
            }
        }
        (_, _) => Err(CompileError::TypeError),
    }
}

pub fn compile_and(arg1: CompileResult, arg2: Result<CompileResult>) -> Result<CompileResult> {
    match (&arg1.term, arg1.term.type_of()) {
        (Term::Some(it), _) if matches!(**it, Term::Prim(TermPrim::Bool(false))) => {
            // we could just do `Ok(arg1)`, but the unoptimized `symcc::footprint()` returns an empty
            // footprint in this case, which is also sound (as our Lean proofs show)
            Ok(CompileResult {
                term: arg1.term,
                footprint: Footprint::empty(),
            })
        }
        (_, TermType::Option { ty: ity }) if matches!(*ity, TermType::Bool) => {
            let arg2 = arg2?;
            if matches!(arg2.term.type_of(), TermType::Option { ty } if matches!(*ty, TermType::Bool))
            {
                let footprint = if matches!(&arg1.term, Term::Some(t) if matches!(**t, Term::Prim(TermPrim::Bool(true))))
                {
                    // omitting arg1.footprint is sound: unoptimized `symcc::footprint()` does that in this case,
                    // and our Lean proofs show it's sound
                    arg2.footprint
                } else {
                    Footprint::from_iter(arg1.footprint.chain(arg2.footprint))
                };
                Ok(CompileResult {
                    term: if_some(
                        arg1.term.clone(),
                        ite(option_get(arg1.term), arg2.term, some_of(false.into())),
                    ),
                    footprint,
                })
            } else {
                Err(CompileError::TypeError)
            }
        }
        (_, _) => Err(CompileError::TypeError),
    }
}

pub fn compile_or(arg1: CompileResult, arg2: Result<CompileResult>) -> Result<CompileResult> {
    match (&arg1.term, arg1.term.type_of()) {
        (Term::Some(it), _) if matches!(**it, Term::Prim(TermPrim::Bool(true))) => {
            // we could just do `Ok(arg1)`, but the unoptimized `symcc::footprint()` returns an empty
            // footprint in this case, which is also sound (as our Lean proofs show)
            Ok(CompileResult {
                term: arg1.term,
                footprint: Footprint::empty(),
            })
        }
        (_, TermType::Option { ty: ity }) if matches!(*ity, TermType::Bool) => {
            let arg2 = arg2?;
            if matches!(arg2.term.type_of(), TermType::Option { ty } if matches!(*ty, TermType::Bool))
            {
                let footprint = if matches!(&arg1.term, Term::Some(t) if matches!(**t, Term::Prim(TermPrim::Bool(false))))
                {
                    // omitting arg1.footprint is sound: unoptimized `symcc::footprint()` does that in this case,
                    // and our Lean proofs show it's sound
                    arg2.footprint
                } else {
                    Footprint::from_iter(arg1.footprint.chain(arg2.footprint))
                };
                Ok(CompileResult {
                    term: if_some(
                        arg1.term.clone(),
                        ite(option_get(arg1.term), some_of(true.into()), arg2.term),
                    ),
                    footprint,
                })
            } else {
                Err(CompileError::TypeError)
            }
        }
        (_, _) => Err(CompileError::TypeError),
    }
}

pub fn compile_set(args: Vec<CompileResult>) -> Result<CompileResult> {
    if args.is_empty() {
        Err(CompileError::UnsupportedFeature(
            "empty set literals are not supported".to_string(),
        ))
    } else {
        #[expect(
            clippy::indexing_slicing,
            reason = "args must be non-empty and thus indexing by 0 should not panic"
        )]
        match &args[0].term.type_of() {
            ty @ TermType::Option { ty: ity } => {
                if args.iter().all(|it| &it.term.type_of() == ty) {
                    let terms = args.iter().map(|arg| arg.term.clone());
                    Ok(CompileResult {
                        term: if_all_some(
                            terms.clone(),
                            some_of(set_of(terms.map(option_get), TermType::clone(ity))),
                        ),
                        footprint: Footprint::from_iter(
                            args.into_iter().flat_map(|arg| arg.footprint),
                        ),
                    })
                } else {
                    Err(CompileError::TypeError)
                }
            }
            _ => Err(CompileError::TypeError),
        }
    }
}

pub fn compile_record(ats: Vec<(Attr, CompileResult)>) -> CompileResult {
    let terms = ats.iter().map(|(_, res)| res.term.clone());
    #[expect(
        clippy::needless_collect,
        reason = "collect allows ats to be moved later"
    )]
    CompileResult {
        term: if_all_some(
            terms.collect::<Vec<_>>(),
            some_of(record_of(
                ats.iter()
                    .map(|(a, res)| (a.clone(), option_get(res.term.clone()))),
            )),
        ),
        footprint: Footprint::from_iter(ats.into_iter().flat_map(|(_, res)| res.footprint)),
    }
}

pub fn compile_call0(
    mk: impl Fn(&str) -> std::result::Result<Ext, ExtError>,
    arg: CompileResult,
) -> Result<CompileResult> {
    match arg {
        CompileResult {
            term: Term::Some(t),
            footprint,
        } => match t.as_ref() {
            Term::Prim(TermPrim::String(s)) => match mk(s.as_ref()) {
                Ok(v) => Ok(CompileResult {
                    term: some_of(v.into()),
                    footprint,
                }),
                Err(err) => Err(CompileError::ExtError(err)),
            },
            _ => Err(CompileError::TypeError),
        },
        _ => Err(CompileError::TypeError),
    }
}

// Use directly for encoding calls that can error
pub fn compile_call1_error(
    xty: ExtType,
    enc: impl Fn(Term) -> Term,
    arg1: CompileResult,
) -> Result<CompileResult> {
    if matches!(arg1.term.type_of(), TermType::Option { ty } if matches!(&*ty, TermType::Ext { xty: other } if xty == *other))
    {
        Ok(CompileResult {
            term: if_some(arg1.term.clone(), enc(option_get(arg1.term))),
            footprint: arg1.footprint,
        })
    } else {
        Err(CompileError::TypeError)
    }
}

// Use directly for encoding calls that cannot error
pub fn compile_call1(
    xty: ExtType,
    enc: impl Fn(Term) -> Term,
    arg1: CompileResult,
) -> Result<CompileResult> {
    compile_call1_error(xty, |t1| some_of(enc(t1)), arg1)
}

// Use directly for encoding calls that can error
pub fn compile_call2_error(
    xty1: ExtType,
    xty2: ExtType,
    enc: impl Fn(Term, Term) -> Term,
    arg1: CompileResult,
    arg2: CompileResult,
) -> Result<CompileResult> {
    let ty1 = TermType::option_of(TermType::Ext { xty: xty1 });
    let ty2 = TermType::option_of(TermType::Ext { xty: xty2 });
    if arg1.term.type_of() == ty1 && arg2.term.type_of() == ty2 {
        Ok(CompileResult {
            term: if_some(
                arg1.term.clone(),
                if_some(
                    arg2.term.clone(),
                    enc(option_get(arg1.term), option_get(arg2.term)),
                ),
            ),
            footprint: Footprint::from_iter(arg1.footprint.chain(arg2.footprint)),
        })
    } else {
        Err(CompileError::TypeError)
    }
}

// Use directly for encoding calls that cannot error
pub fn compile_call2(
    xty: ExtType,
    enc: impl Fn(Term, Term) -> Term,
    arg1: CompileResult,
    arg2: CompileResult,
) -> Result<CompileResult> {
    compile_call2_error(xty, xty, |t1, t2| some_of(enc(t1, t2)), arg1, arg2)
}

#[cfg(feature = "variadic-is-in-range")]
// Use directly for encoding calls that can error with n arguments
pub fn compile_call_n_error(
    xty: ExtType,
    xtys: Vec<ExtType>,
    enc: impl Fn(Term, Vec<Term>) -> Term,
    arg: CompileResult,
    args: Vec<CompileResult>,
) -> Result<CompileResult> {
    let ty = TermType::option_of(TermType::Ext { xty });
    if arg.term.type_of() != ty {
        return Err(CompileError::TypeError);
    }
    if args.len() != xtys.len() {
        return Err(CompileError::TypeError);
    }

    let expected_types = xtys
        .iter()
        .map(|xty| TermType::option_of(TermType::Ext { xty: *xty }));

    // Check all types match
    if args
        .iter()
        .zip(expected_types)
        .all(|(arg, ty)| arg.term.type_of() == ty)
    {
        // Build nested if_some calls
        let mut result = enc(
            option_get(arg.term.clone()),
            args.iter()
                .map(|arg| option_get(arg.term.clone()))
                .collect(),
        );
        for arg in args.iter().rev() {
            result = if_some(arg.term.clone(), result);
        }
        result = if_some(arg.term.clone(), result);

        // Combine all footprints
        let footprint = Footprint::from_iter(
            arg.footprint
                .chain(args.into_iter().flat_map(|arg| arg.footprint)),
        );

        Ok(CompileResult {
            term: result,
            footprint,
        })
    } else {
        Err(CompileError::TypeError)
    }
}

#[cfg(feature = "variadic-is-in-range")]
// Use directly for encoding calls that cannot error with n arguments
pub fn compile_call_n(
    xty: ExtType,
    n: usize,
    enc: impl Fn(Term, Vec<Term>) -> Term,
    arg: CompileResult,
    args: Vec<CompileResult>,
) -> Result<CompileResult> {
    let enc = |t: Term, ts: Vec<Term>| -> Term { some_of(enc(t, ts)) };
    compile_call_n_error(xty, vec![xty; n], enc, arg, args)
}

pub fn compile_call(
    xfn: &cedar_policy_core::ast::Name,
    args: Vec<CompileResult>,
) -> Result<CompileResult> {
    match (xfn.to_string().as_str(), args.len()) {
        ("decimal", 1) => {
            let t1 = extract_first(args);
            compile_call0(Ext::parse_decimal, t1)
        }
        ("lessThan", 2) => {
            let (t1, t2) = extract_first2(args);
            compile_call2(ExtType::Decimal, extfun::less_than, t1, t2)
        }
        ("lessThanOrEqual", 2) => {
            let (t1, t2) = extract_first2(args);
            compile_call2(ExtType::Decimal, extfun::less_than_or_equal, t1, t2)
        }
        ("greaterThan", 2) => {
            let (t1, t2) = extract_first2(args);
            compile_call2(ExtType::Decimal, extfun::greater_than, t1, t2)
        }
        ("greaterThanOrEqual", 2) => {
            let (t1, t2) = extract_first2(args);
            compile_call2(ExtType::Decimal, extfun::greater_than_or_equal, t1, t2)
        }
        ("ip", 1) => {
            let t1 = extract_first(args);
            compile_call0(Ext::parse_ip, t1)
        }
        ("isIpv4", 1) => {
            let t1 = extract_first(args);
            compile_call1(ExtType::IpAddr, extfun::is_ipv4, t1)
        }
        ("isIpv6", 1) => {
            let t1 = extract_first(args);
            compile_call1(ExtType::IpAddr, extfun::is_ipv6, t1)
        }
        ("isLoopback", 1) => {
            let t1 = extract_first(args);
            compile_call1(ExtType::IpAddr, extfun::is_loopback, t1)
        }
        ("isMulticast", 1) => {
            let t1 = extract_first(args);
            compile_call1(ExtType::IpAddr, extfun::is_multicast, t1)
        }
        ("isInRange", n) => {
            #[cfg(feature = "variadic-is-in-range")]
            if n < 2 {
                Err(CompileError::TypeError)
            } else {
                let mut args = args;
                let t = args.remove(0);
                compile_call_n(ExtType::IpAddr, n - 1, extfun::is_in_range, t, args)
            }

            #[cfg(not(feature = "variadic-is-in-range"))]
            if n != 2 {
                Err(CompileError::TypeError)
            } else {
                let (t1, t2) = extract_first2(args);
                compile_call2(
                    ExtType::IpAddr,
                    |t1, t2| extfun::is_in_range(t1, vec![t2]),
                    t1,
                    t2,
                )
            }
        }
        ("datetime", 1) => {
            let t1 = extract_first(args);
            compile_call0(Ext::parse_datetime, t1)
        }
        ("duration", 1) => {
            let t1 = extract_first(args);
            compile_call0(Ext::parse_duration, t1)
        }
        ("offset", 2) => {
            let (t1, t2) = extract_first2(args);
            compile_call2_error(ExtType::DateTime, ExtType::Duration, extfun::offset, t1, t2)
        }
        ("durationSince", 2) => {
            let (t1, t2) = extract_first2(args);
            compile_call2_error(
                ExtType::DateTime,
                ExtType::DateTime,
                extfun::duration_since,
                t1,
                t2,
            )
        }
        ("toDate", 1) => {
            let t1 = extract_first(args);
            compile_call1_error(ExtType::DateTime, extfun::to_date, t1)
        }
        ("toTime", 1) => {
            let t1 = extract_first(args);
            compile_call1(ExtType::DateTime, extfun::to_time, t1)
        }
        ("toMilliseconds", 1) => {
            let t1 = extract_first(args);
            compile_call1(ExtType::Duration, extfun::to_milliseconds, t1)
        }
        ("toSeconds", 1) => {
            let t1 = extract_first(args);
            compile_call1(ExtType::Duration, extfun::to_seconds, t1)
        }
        ("toMinutes", 1) => {
            let t1 = extract_first(args);
            compile_call1(ExtType::Duration, extfun::to_minutes, t1)
        }
        ("toHours", 1) => {
            let t1 = extract_first(args);
            compile_call1(ExtType::Duration, extfun::to_hours, t1)
        }
        ("toDays", 1) => {
            let t1 = extract_first(args);
            compile_call1(ExtType::Duration, extfun::to_days, t1)
        }
        (_, _) => Err(CompileError::TypeError),
    }
}

/// Given an expression `x` that has type `τ` with respect to a type environment
/// `Γ`, and given a well-formed symbolic environment `env` that conforms to `Γ`,
/// `compile x env` succeeds and produces a well-formed term of type `.option τ.toTermType`.
pub fn compile(x: &Expr, env: &SymEnv) -> Result<CompileResult> {
    match x.expr_kind() {
        ExprKind::Lit(l) => compile_prim(l, &env.entities),
        ExprKind::Var(v) => compile_var(v, &env.request),
        ExprKind::If {
            test_expr: x1,
            then_expr: x2,
            else_expr: x3,
        } => compile_if(compile(x1, env)?, compile(x2, env), compile(x3, env)),
        ExprKind::And {
            left: x1,
            right: x2,
        } => compile_and(compile(x1, env)?, compile(x2, env)),
        ExprKind::Or {
            left: x1,
            right: x2,
        } => compile_or(compile(x1, env)?, compile(x2, env)),
        ExprKind::UnaryApp { op, arg } => {
            let res1 = compile(arg, env)?;
            let res1_term = res1.term.clone();
            let res = compile_app1(*op, res1.map_term(option_get))?;
            Ok(res.map_term(|term| if_some(res1_term, term)))
        }
        ExprKind::BinaryApp { op, arg1, arg2 } => {
            let res1 = compile(arg1, env)?;
            let res2 = compile(arg2, env)?;
            let res1_term = res1.term.clone();
            let res2_term = res2.term.clone();
            // subtlety:
            // the unoptimized _compiler_ calls `option_get()` on the terms passed to `compile_app2`,
            // similar to how it's done for `compile_app1`, `compile_has_attr`, etc.
            // However, for _footprint_ purposes, the unoptimized `footprint` function expresses
            // the footprint in terms of the original terms, without the `option_get`.
            // In order to give our optimized `compile_app2` easy access to both the original and
            // `option_get` terms, we pass the original ones here.
            let res = compile_app2(*op, res1, res2, &env.entities)?;
            Ok(res.map_term(|term| if_some(res1_term, if_some(res2_term, term))))
        }
        ExprKind::HasAttr { expr, attr } => {
            let res1 = compile(expr, env)?;
            let res1_term = res1.term.clone();
            let res = compile_has_attr(res1.map_term(option_get), attr, &env.entities)?;
            Ok(res.map_term(|term| if_some(res1_term, term)))
        }
        ExprKind::GetAttr { expr, attr } => {
            // subtlety:
            // similar to the comment above in the `BinaryApp` case
            let res1 = compile(expr, env)?;
            let res1_term = res1.term.clone();
            let res = compile_get_attr(res1, attr, &env.entities)?;
            Ok(res.map_term(|term| if_some(res1_term, term)))
        }
        ExprKind::Like { expr, pattern } => {
            let res1 = compile(expr, env)?;
            let res1_term = res1.term.clone();
            let res = compile_like(res1.map_term(option_get), pattern.clone().into())?;
            Ok(res.map_term(|term| if_some(res1_term, term)))
        }
        ExprKind::Is { expr, entity_type } => {
            let res1 = compile(expr, env)?;
            let res1_term = res1.term.clone();
            let res = compile_is(
                res1.map_term(option_get),
                core_entity_type_into_entity_type(entity_type),
            )?;
            Ok(res.map_term(|term| if_some(res1_term, term)))
        }
        ExprKind::Set(xs) => {
            let ress = xs
                .iter()
                .map(|x1| compile(x1, env))
                .collect::<Result<Vec<_>>>()?;
            compile_set(ress)
        }
        ExprKind::Record(axs) => {
            let ats = axs
                .iter()
                .map(|(a1, x1)| Ok((a1.clone(), compile(x1, env)?)))
                .collect::<Result<Vec<_>>>()?;
            Ok(compile_record(ats))
        }
        ExprKind::ExtensionFunctionApp { fn_name, args } => {
            let ress = args
                .iter()
                .map(|x1| compile(x1, env))
                .collect::<Result<Vec<_>>>()?;
            compile_call(fn_name, ress)
        }
        ExprKind::Slot(_) => Err(CompileError::UnsupportedFeature(
            "templates/slots are not supported".to_string(),
        )),
        ExprKind::Unknown(_) => Err(CompileError::UnsupportedFeature(
            "partial evaluation is not supported".to_string(),
        )),
        _ => Err(CompileError::UnsupportedFeature(format!(
            "symbolic compilation of `{}` is not supported",
            x
        ))),
    }
}
