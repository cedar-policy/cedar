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

//! This module defines Interpretation and how
//! can SymRequest/SymEntities be interpreted with
//! an Interpretation.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use super::env::{SymEntities, SymEntityData, SymRequest};
use super::function::{Udf, UnaryFunction};
use super::op::{ExtOp, Op, Uuf};
use super::tags::SymTags;
use super::term::{Term, TermVar};
use super::{factory, SymEnv};

/// An interpretation extracted from an SMT model consists of
/// - A map from variables (principal, action, resource, context) to literals
/// - A map from UUF to UDFs
#[derive(Debug)]
pub struct Interpretation<'a> {
    pub(super) vars: BTreeMap<TermVar, Term>,
    pub(super) funs: BTreeMap<Uuf, Udf>,
    pub(super) env: &'a SymEnv,
}

impl<'a> Interpretation<'a> {
    /// Returns a literal symbolic environments with default terms.
    pub fn default(env: &'a SymEnv) -> Self {
        Self {
            vars: BTreeMap::new(),
            funs: BTreeMap::new(),
            env,
        }
    }
}

impl Interpretation<'_> {
    /// Interprets variables as terms, and use the default literal if not found.
    pub fn interpret_var(&self, var: &TermVar) -> Term {
        self.vars
            .get(var)
            .cloned()
            .unwrap_or_else(|| var.ty.default_literal(self.env))
    }

    /// Interprets uninterpreted functions as interpreted functions, and use the
    /// default UDF if not found.
    pub fn interpret_fun(&self, fun: &Uuf) -> Udf {
        self.funs
            .get(fun)
            .cloned()
            .unwrap_or_else(|| fun.default_udf(self.env))
    }
}

impl Term {
    /// Recursively interprets a term, substituting variables with
    /// their interpretations.
    pub fn interpret(&self, interp: &Interpretation<'_>) -> Term {
        let mut cache: HashMap<*const Term, Term> = HashMap::new();
        self.interpret_memoized(interp, &mut cache)
    }

    /// Memoized worker for [`Term::interpret`].
    ///
    /// Keyed on the address of each subterm (not structural equality) so that
    /// shared subterms in the `Term` DAG collapse to one cache entry without
    /// paying the exponential cost of structural key comparison.
    //
    // The memoization based on pointer is safe under the invariants:
    // - we only hold &self and not a mutable reference,
    // - the cache is never shared across calls to the `interpret` caller,
    // - all cache entries correspond to subterms of term, never temporary values
    fn interpret_memoized(
        &self,
        interp: &Interpretation<'_>,
        cache: &mut HashMap<*const Term, Term>,
    ) -> Term {
        let key: *const Term = self;
        if let Some(cached) = cache.get(&key) {
            return cached.clone();
        }
        let result = self.interpret_uncached(interp, cache);
        cache.insert(key, result.clone());
        result
    }

    /// Computes the interpretation of `self` without consulting the cache for
    /// `self` itself, recursing through [`Self::interpret_memoized`] so that
    /// shared subterms are only interpreted once.
    fn interpret_uncached(
        &self,
        interp: &Interpretation<'_>,
        cache: &mut HashMap<*const Term, Term>,
    ) -> Term {
        match self {
            Term::Prim(..) | Term::None(..) => self.clone(),
            Term::Var(var) => interp.interpret_var(var),
            // `t: &Arc<Term>` is borrowed from `self`, not a temporary.
            Term::Some(t) => Term::Some(Arc::new(t.interpret_memoized(interp, cache))),

            // Each `t` yielded by `elts.iter()` borrows from `self`'s `Arc<BTreeSet<Term>>`
            Term::Set { elts, elts_ty } => Term::Set {
                elts: Arc::new(
                    elts.iter()
                        .map(|t| t.interpret_memoized(interp, cache))
                        .collect(),
                ),
                elts_ty: elts_ty.clone(),
            },

            // Each value `v` borrows from `self`'s `Arc<BTreeMap<Attr, Term>>`
            Term::Record(rec) => Term::Record(Arc::new(
                rec.iter()
                    .map(|(k, v)| (k.clone(), v.interpret_memoized(interp, cache)))
                    .collect(),
            )),

            // Every `arg`/`argN` below is an element of `args.as_slice()`, i.e.
            // a borrow into `self`'s `Arc<Vec<Term>>`.
            Term::App { op, args, ret_ty } => match (op, args.as_slice()) {
                (Op::Not, [arg]) => factory::not(arg.interpret_memoized(interp, cache)),
                (Op::And, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::and(a1, a2)
                }

                (Op::Or, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::or(a1, a2)
                }

                (Op::Eq, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::eq(a1, a2)
                }

                (Op::Ite, [arg1, arg2, arg3]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    let a3 = arg3.interpret_memoized(interp, cache);
                    factory::ite(a1, a2, a3)
                }

                (Op::Uuf(uuf), [arg]) => factory::app(
                    UnaryFunction::Udf(Arc::new(interp.interpret_fun(uuf))),
                    arg.interpret_memoized(interp, cache),
                ),

                (Op::Bvneg, [arg]) => factory::bvneg(arg.interpret_memoized(interp, cache)),

                (Op::Bvadd, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvadd(a1, a2)
                }

                (Op::Bvsub, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvsub(a1, a2)
                }

                (Op::Bvmul, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvmul(a1, a2)
                }

                (Op::Bvsdiv, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvsdiv(a1, a2)
                }

                (Op::Bvsrem, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvsrem(a1, a2)
                }

                (Op::Bvudiv, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvudiv(a1, a2)
                }

                (Op::Bvsmod, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvsmod(a1, a2)
                }

                (Op::Bvurem, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvurem(a1, a2)
                }

                (Op::Bvshl, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvshl(a1, a2)
                }

                (Op::Bvlshr, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvlshr(a1, a2)
                }

                (Op::Bvslt, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvslt(a1, a2)
                }

                (Op::Bvsle, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvsle(a1, a2)
                }

                (Op::Bvult, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvult(a1, a2)
                }

                (Op::Bvule, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvule(a1, a2)
                }

                (Op::Bvnego, [arg]) => factory::bvnego(arg.interpret_memoized(interp, cache)),

                (Op::Bvsaddo, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvsaddo(a1, a2)
                }

                (Op::Bvsmulo, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvsmulo(a1, a2)
                }

                (Op::Bvssubo, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::bvssubo(a1, a2)
                }

                (Op::ZeroExtend(n), [arg]) => {
                    factory::zero_extend(*n, arg.interpret_memoized(interp, cache))
                }

                (Op::SetMember, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::set_member(a1, a2)
                }

                (Op::SetSubset, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::set_subset(a1, a2)
                }

                (Op::SetInter, [arg1, arg2]) => {
                    let a1 = arg1.interpret_memoized(interp, cache);
                    let a2 = arg2.interpret_memoized(interp, cache);
                    factory::set_inter(a1, a2)
                }

                // Factory.option.get' in the Lean version
                (Op::OptionGet, [arg]) => {
                    let arg = arg.interpret_memoized(interp, cache);

                    if let Term::None(ty) = arg {
                        ty.default_literal(interp.env)
                    } else {
                        factory::option_get(arg)
                    }
                }

                (Op::RecordGet(smol_str), [arg]) => {
                    factory::record_get(arg.interpret_memoized(interp, cache), smol_str)
                }

                (Op::StringLike(ord_pattern), [arg]) => {
                    factory::string_like(arg.interpret_memoized(interp, cache), ord_pattern.clone())
                }

                (Op::Ext(ext_op), [arg]) => {
                    let arg = arg.interpret_memoized(interp, cache);
                    match ext_op {
                        ExtOp::DecimalVal => factory::ext_decimal_val(arg),
                        ExtOp::IpaddrIsV4 => factory::ext_ipaddr_is_v4(arg),
                        ExtOp::IpaddrAddrV4 => factory::ext_ipaddr_addr_v4(arg),
                        ExtOp::IpaddrPrefixV4 => factory::ext_ipaddr_prefix_v4(arg),
                        ExtOp::IpaddrAddrV6 => factory::ext_ipaddr_addr_v6(arg),
                        ExtOp::IpaddrPrefixV6 => factory::ext_ipaddr_prefix_v6(arg),
                        ExtOp::DatetimeVal => factory::ext_datetime_val(arg),
                        ExtOp::DatetimeOfBitVec => factory::ext_datetime_of_bitvec(arg),
                        ExtOp::DurationVal => factory::ext_duration_val(arg),
                        ExtOp::DurationOfBitVec => factory::ext_duration_of_bitvec(arg),
                    }
                }

                // Otherwise leave the application as it but
                // interpret the arguments
                (op, args) => {
                    debug_assert!(
                        false,
                        "This should never happen. The above match should be exhaustive."
                    );
                    Term::App {
                        op: op.clone(),
                        args: Arc::new(
                            // `t` borrows from `self`'s `args`, not a temporary.
                            args.iter()
                                .map(|t| t.interpret_memoized(interp, cache))
                                .collect(),
                        ),
                        ret_ty: ret_ty.clone(),
                    }
                }
            },
        }
    }
}

impl SymRequest {
    /// Interprets a [`SymRequest`] with the given interpretation.
    pub fn interpret(&self, interp: &Interpretation<'_>) -> SymRequest {
        SymRequest {
            principal: self.principal.interpret(interp),
            action: self.action.interpret(interp),
            resource: self.resource.interpret(interp),
            context: self.context.interpret(interp),
        }
    }
}

impl UnaryFunction {
    /// Interprets a [`UnaryFunction`] with the given interpretation.
    pub fn interpret(&self, interp: &Interpretation<'_>) -> UnaryFunction {
        match self {
            UnaryFunction::Udf(..) => self.clone(),
            UnaryFunction::Uuf(uuf) => UnaryFunction::Udf(Arc::new(interp.interpret_fun(uuf))),
        }
    }
}

impl SymTags {
    /// Interprets a [`SymTags`] with the given interpretation.
    pub fn interpret(&self, interp: &Interpretation<'_>) -> SymTags {
        SymTags {
            keys: self.keys.interpret(interp),
            vals: self.vals.interpret(interp),
        }
    }
}

impl SymEntityData {
    /// Interpret a [`SymEntityData`] with the given interpretation.
    pub fn interpret(&self, interp: &Interpretation<'_>) -> SymEntityData {
        SymEntityData {
            attrs: self.attrs.interpret(interp),
            ancestors: self
                .ancestors
                .iter()
                .map(|(ent, fun)| (ent.clone(), fun.interpret(interp)))
                .collect(),
            members: self.members.clone(),
            tags: self.tags.as_ref().map(|tags| tags.interpret(interp)),
        }
    }
}

impl SymEntities {
    /// Interpret a [`SymEntities`] with the given interpretation.
    pub fn interpret(&self, interp: &Interpretation<'_>) -> SymEntities {
        SymEntities(
            self.0
                .iter()
                .map(|(ent, data)| (ent.clone(), data.interpret(interp)))
                .collect(),
        )
    }
}

impl SymEnv {
    /// Interpret a [`SymEnv`] with the given interpretation.
    pub fn interpret(&self, interp: &Interpretation<'_>) -> SymEnv {
        SymEnv {
            entities: Arc::new(self.entities.interpret(interp)),
            request: self.request.interpret(interp),
        }
    }
}

#[cfg(test)]
#[expect(clippy::panic, reason = "unit tests")]
mod interpret_test {
    use std::str::FromStr;

    use cedar_policy::{RequestEnv, Schema};
    use cedar_policy_core::ast::Expr;

    use crate::{
        bitvec::BitVec,
        symcc::{
            compiler::compile,
            test_utils::{deep_chain_sym_env, deep_has_chain_expr},
        },
        term::TermPrim,
        term_type::TermType,
        type_abbrevs::Width,
    };

    use super::*;

    #[track_caller]
    pub fn pretty_panic<T>(e: impl miette::Diagnostic + Send + Sync + 'static) -> T {
        panic!("{:?}", miette::Report::new(e))
    }

    fn test_schema() -> Schema {
        let schema = r#"
            entity Thing;
            entity User in [User];
            action View appliesTo {
                principal: [User],
                resource: [Thing],
                context: {
                    x: Long,
                    y: Long,
                    a: Bool,
                    b: Bool,
                    dt1: datetime,
                    dt2: datetime,
                    d1: duration,
                    d2: duration,
                    ip1: ipaddr,
                    ip2: ipaddr,
                    ip3: ipaddr,
                    s1: Set<Long>,
                    s2: Set<Long>,
                    dc1: decimal,
                    dc2: decimal,
                    str: String,
                }
            };
        "#;
        Schema::from_cedarschema_str(schema)
            .unwrap_or_else(pretty_panic)
            .0
    }

    fn request_env() -> RequestEnv {
        RequestEnv::new(
            "User".parse().unwrap(),
            "Action::\"View\"".parse().unwrap(),
            "Thing".parse().unwrap(),
        )
    }

    fn sym_env() -> SymEnv {
        SymEnv::new(&test_schema(), &request_env()).expect("Malformed sym env.")
    }

    #[track_caller]
    fn parse_expr(str: &str) -> Expr {
        Expr::from_str(str).unwrap_or_else(|e| panic!("Could not parse expression: {str}: {e}"))
    }

    #[track_caller]
    fn test_valid_bool_interp_expr(str: &str, interp: &Interpretation<'_>, res: bool) {
        let term = compile(&parse_expr(str), &sym_env()).unwrap();
        let term_interp = term.interpret(interp);
        assert_eq!(
            term_interp,
            Term::Some(Arc::new(Term::Prim(TermPrim::Bool(res)))),
            "{str}"
        );
        // Check idempotency
        assert_eq!(term_interp, term_interp.interpret(interp));
    }

    #[test]
    fn test_interp_term_builtin() {
        let symenv = sym_env();
        let interp = Interpretation::default(&symenv);
        test_valid_bool_interp_expr(
            "context.x + context.y == context.y + context.x",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            "context.x + context.y == context.y + context.x",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            "context.x < context.y || context.x == context.y || context.x > context.y",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            "context.x * context.y == context.y * context.x",
            &interp,
            true,
        );
        test_valid_bool_interp_expr("--context.x == context.x", &interp, true);
        test_valid_bool_interp_expr(
            "(!context.a && !context.b) == !(context.a || context.b)",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            "(if context.a then context.x else context.y) == (if !context.a then context.y else context.x)",
            &interp,
            true,
        );
        test_valid_bool_interp_expr("context.x + 1 == context.x", &interp, false);
        test_valid_bool_interp_expr(r#"context.str like "*""#, &interp, true);
    }

    #[test]
    fn test_interp_term_set() {
        let symenv = sym_env();
        let interp = Interpretation::default(&symenv);
        test_valid_bool_interp_expr(
            "!(context.s1.containsAll(context.s2) && context.s2.containsAll(context.s1)) || context.s1 == context.s2",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            "!(context.s1.containsAll(context.s2) && context.s2.contains(10)) || context.s1.contains(10)",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            "!(context.s1.contains(10) && context.s2.contains(10)) || context.s1.containsAny(context.s2)",
            &interp,
            true,
        );
    }

    #[test]
    fn test_interp_term_decimal() {
        let symenv = sym_env();
        let interp = Interpretation::default(&symenv);
        test_valid_bool_interp_expr(
            "context.dc1.lessThan(context.dc2) || context.dc1 == context.dc2 || context.dc1.greaterThan(context.dc2)",
            &interp,
            true,
        );
    }

    #[test]
    fn test_interp_term_datetime() {
        let symenv = sym_env();
        let interp = Interpretation::default(&symenv);
        test_valid_bool_interp_expr(
            "context.dt1.offset(context.d1).offset(context.d2) == context.dt1.offset(context.d2).offset(context.d1)",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            r#"
            !(context.dt1 >= context.dt2 && context.dt2 >= datetime("1970-01-01")) ||
            context.dt1.durationSince(context.dt2) >= duration("0ms")
            "#,
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            r#"!(context.d1 >= duration("0ms")) || context.d1.toDays() <= context.d1.toMilliseconds()"#,
            &interp,
            true,
        );
    }

    #[test]
    fn test_interp_term_ipaddr() {
        let symenv = sym_env();
        let interp = Interpretation::default(&symenv);
        test_valid_bool_interp_expr(
            "context.ip1.isIpv4() || context.ip1.isIpv6()",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            "!(context.ip1.isIpv4() && context.ip1.isIpv6())",
            &interp,
            true,
        );
        test_valid_bool_interp_expr(
            "!(context.ip1.isInRange(context.ip2) && context.ip2.isInRange(context.ip3)) || context.ip1.isInRange(context.ip3)",
            &interp,
            true,
        );
    }

    #[test]
    fn test_interp_misc_bitvec() {
        let symenv = sym_env();
        let interp = Interpretation::default(&symenv);
        let t1 = Term::Prim(TermPrim::Bitvec(BitVec::of_u128(
            Width::new(64).unwrap(),
            10,
        )));
        let t2 = Term::Prim(TermPrim::Bitvec(BitVec::of_u128(
            Width::new(64).unwrap(),
            3,
        )));

        // This test exists to test `Term::interpret` for these operations, so I
        // don't want to use the factory functions which would fold constants before interpration.
        fn bv_app_without_folding(op: Op, t1: &Term, t2: &Term, ret_ty: TermType) -> Term {
            Term::App {
                op,
                args: Arc::new(vec![t1.clone(), t2.clone()]),
                ret_ty,
            }
        }

        assert_eq!(
            bv_app_without_folding(Op::Bvult, &t1, &t2, TermType::Bool).interpret(&interp),
            Term::Prim(TermPrim::Bool(false))
        );
        assert_eq!(
            bv_app_without_folding(Op::Bvudiv, &t1, &t2, t1.type_of()).interpret(&interp),
            Term::Prim(TermPrim::Bitvec(BitVec::of_u128(
                Width::new(64).unwrap(),
                3
            )))
        );
        assert_eq!(
            bv_app_without_folding(Op::Bvsmod, &t1, &t2, t1.type_of()).interpret(&interp),
            Term::Prim(TermPrim::Bitvec(BitVec::of_u128(
                Width::new(64).unwrap(),
                1
            )))
        );
        assert_eq!(
            bv_app_without_folding(Op::Bvurem, &t1, &t2, t1.type_of()).interpret(&interp),
            Term::Prim(TermPrim::Bitvec(BitVec::of_u128(
                Width::new(64).unwrap(),
                1
            )))
        );
    }

    #[test]
    fn interpret_deep_chain_is_tractable() {
        let depth = 20;
        let term = compile(&deep_has_chain_expr(depth), &deep_chain_sym_env(depth))
            .expect("expression should compile");
        let symenv = deep_chain_sym_env(depth);
        let interp = Interpretation::default(&symenv);

        // we're just testing this returns here; values don't matter
        let result = term.interpret(&interp);
        assert!(
            matches!(
                &result,
                Term::Some(inner) if matches!(inner.as_ref(), Term::Prim(TermPrim::Bool(_)))
            ),
            "expected an interpreted boolean, got {result}"
        );
    }
}
