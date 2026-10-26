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

//! Policies in the model. A production policy (template + slot environment)
//! is abstracted to a linked policy (`abs_linked_policy`). `body_cond_rel`
//! relates `TemplateBody::condition` to the model's `policy_to_expr`.

use vstd::prelude::*;

use super::abs::*;
use super::model as m;
use super::model_lemmas::*;
use super::model::policy as mp;
use super::trusted::*;
use super::value_abs::*;
use super::expr_abs::*;
use super::map_entries::*;
use crate::ast::*;
use crate::ast::lemma_slot_id_cases;
use std::sync::Arc;

verus! {

broadcast use group_model_eq, group_trusted;

// ---------------------------------------------------------------------------
// The copying functions of the model return their input.
// ---------------------------------------------------------------------------

pub broadcast proof fn lemma_clone_effect(e: m::authorizer::Effect)
    ensures
        #[trigger] mp::clone_effect(&e) == e,
{
}

pub broadcast proof fn lemma_clone_pattern(p: m::value::List<m::expr::PatElem>)
    ensures
        #[trigger] mp::clone_pattern(&p) == p,
    decreases p,
{
    if let m::value::List::Cons(_, rest) = p {
        lemma_clone_pattern(*rest);
    }
}

pub broadcast proof fn lemma_clone_expr(x: m::expr::Expr)
    ensures
        #[trigger] mp::clone_expr(&x) == x,
    decreases x,
{
    broadcast use lemma_clone_prim, lemma_clone_str, lemma_clone_strs, lemma_clone_name, lemma_clone_pattern;

    match x {
        m::expr::Expr::Ite(a1, a2, a3) => {
            lemma_clone_expr(*a1);
            lemma_clone_expr(*a2);
            lemma_clone_expr(*a3);
        },
        m::expr::Expr::And(a1, a2) => {
            lemma_clone_expr(*a1);
            lemma_clone_expr(*a2);
        },
        m::expr::Expr::Or(a1, a2) => {
            lemma_clone_expr(*a1);
            lemma_clone_expr(*a2);
        },
        m::expr::Expr::UnaryApp(_, a1) => lemma_clone_expr(*a1),
        m::expr::Expr::BinaryApp(_, a1, a2) => {
            lemma_clone_expr(*a1);
            lemma_clone_expr(*a2);
        },
        m::expr::Expr::GetAttr(a1, _) => lemma_clone_expr(*a1),
        m::expr::Expr::HasAttr(a1, _) => lemma_clone_expr(*a1),
        m::expr::Expr::ExtHasAttr(a1, _, _) => lemma_clone_expr(*a1),
        m::expr::Expr::Set(xs) => lemma_clone_exprs(*xs),
        m::expr::Expr::Record(xs) => lemma_clone_attr_exprs(*xs),
        m::expr::Expr::Call(f, xs) => {
            lemma_clone_extfun(f);
            lemma_clone_exprs(*xs);
        },
        _ => {},
    }
}

pub broadcast proof fn lemma_clone_exprs(xs: m::value::List<m::expr::Expr>)
    ensures
        #[trigger] mp::clone_exprs(&xs) == xs,
    decreases xs,
{
    match xs {
        m::value::List::Cons(x, rest) => {
            lemma_clone_expr(x);
            lemma_clone_exprs(*rest);
        },
        _ => {},
    }
}

pub broadcast proof fn lemma_clone_attr_exprs(xs: m::value::List<(m::value::Str, m::expr::Expr)>)
    ensures
        #[trigger] mp::clone_attr_exprs(&xs) == xs,
    decreases xs,
{
    match xs {
        m::value::List::Cons((k, x), rest) => {
            lemma_clone_str(k);
            lemma_clone_expr(x);
            lemma_clone_attr_exprs(*rest);
        },
        _ => {},
    }
}

pub broadcast group group_linked_clone {
    lemma_clone_effect,
    lemma_clone_pattern,
    lemma_clone_expr,
    lemma_clone_exprs,
    lemma_clone_attr_exprs,
}

// ---------------------------------------------------------------------------
// Slots
// ---------------------------------------------------------------------------

pub open spec fn principal_slot() -> SlotId {
    SlotId::spec_principal()
}

pub open spec fn resource_slot() -> SlotId {
    SlotId::spec_resource()
}

// ---------------------------------------------------------------------------
// Policies and template bodies
// ---------------------------------------------------------------------------

/// The ID of a template body (`TemplateBody::id`)
pub open spec fn tbody_id(b: TemplateBody) -> PolicyID {
    match b {
        TemplateBody::TemplateBody(i) => i.spec_id(),
    }
}

/// The effect of a template body (`TemplateBody::effect`)
pub open spec fn tbody_effect(b: TemplateBody) -> Effect {
    match b {
        TemplateBody::TemplateBody(i) => i.spec_effect(),
    }
}

/// The body of the template of a policy
pub open spec fn policy_body(p: Policy) -> TemplateBody {
    p.spec_template().spec_body()
}

/// The ID of a policy (`Policy::id`): the ID of the link, or that of the
/// template for a static policy
pub open spec fn policy_id(p: Policy) -> PolicyID {
    match p.spec_link() {
        Some(id) => id,
        None => tbody_id(policy_body(p)),
    }
}

/// The effect of a policy (`Policy::effect`)
pub open spec fn policy_effect(p: Policy) -> Effect {
    tbody_effect(policy_body(p))
}

/// The slot environment of a policy (`Policy::env`)
pub open spec fn policy_env(p: Policy) -> SlotEnv {
    p.spec_values()
}

// ---------------------------------------------------------------------------
// Scope constraints, in the model
// ---------------------------------------------------------------------------

/// The entity of an entity reference, with the slot `slot` filled in from
/// `env`
pub open spec fn abs_entity_ref(x: EntityReference, slot: SlotId, env: SlotEnv) -> m::value::EntityUID {
    match x {
        EntityReference::EUID(u) => abs_uid(*u),
        EntityReference::Slot(_) => abs_uid(env@[slot]),
    }
}

/// The slot of an entity reference, if it is one, is bound in `env`.
pub open spec fn entity_ref_bound(x: EntityReference, slot: SlotId, env: SlotEnv) -> bool {
    x is Slot ==> env@.contains_key(slot)
}

/// A principal or resource constraint, as a model scope
pub open spec fn abs_por(c: PrincipalOrResourceConstraint, slot: SlotId, env: SlotEnv) -> mp::Scope {
    match c {
        PrincipalOrResourceConstraint::Any => mp::Scope::Any,
        PrincipalOrResourceConstraint::In(x) => mp::Scope::Mem(abs_entity_ref(x, slot, env)),
        PrincipalOrResourceConstraint::Eq(x) => mp::Scope::Eq(abs_entity_ref(x, slot, env)),
        PrincipalOrResourceConstraint::Is(t) => mp::Scope::Is(abs_entity_type(*t)),
        PrincipalOrResourceConstraint::IsIn(t, x) => mp::Scope::IsMem(abs_entity_type(*t), abs_entity_ref(x, slot, env)),
    }
}

/// The slot of a principal or resource constraint, if it has one, is bound
/// in `env`.
pub open spec fn por_bound(c: PrincipalOrResourceConstraint, slot: SlotId, env: SlotEnv) -> bool {
    match c {
        PrincipalOrResourceConstraint::In(x) => entity_ref_bound(x, slot, env),
        PrincipalOrResourceConstraint::Eq(x) => entity_ref_bound(x, slot, env),
        PrincipalOrResourceConstraint::IsIn(_, x) => entity_ref_bound(x, slot, env),
        _ => true,
    }
}

/// An action constraint, as a model action scope
pub open spec fn abs_action_constraint(c: ActionConstraint) -> mp::ActionScope {
    match c {
        ActionConstraint::Any => mp::ActionScope::ActionScope(mp::Scope::Any),
        ActionConstraint::Eq(u) => mp::ActionScope::ActionScope(mp::Scope::Eq(abs_uid(*u))),
        ActionConstraint::In(us) => mp::ActionScope::ActionInAny(
            seq_to_list(us@.map_values(|u: Arc<EntityUID>| abs_uid(*u))),
        ),
    }
}

/// The template's non-scope constraint as a single `when` condition. (Slots
/// in it, which the parser rejects, are filled from `env`.)
pub open spec fn abs_conditions(nsc: Option<Arc<Expr>>, env: SlotEnv) -> m::value::List<mp::Condition> {
    match nsc {
        None => m::value::List::Nil,
        Some(e) => m::value::List::Cons(
            mp::Condition { kind: mp::ConditionKind::When, body: abs_expr(*e, env) },
            Box::new(m::value::List::Nil),
        ),
    }
}

/// A template body with the slot environment `env`, as a linked policy with
/// the ID `id`
pub open spec fn abs_tbody(b: TemplateBody, id: m::value::Str, env: SlotEnv) -> mp::LinkedPolicy {
    match b {
        TemplateBody::TemplateBody(i) => mp::LinkedPolicy {
            id,
            effect: abs_effect(i.spec_effect()),
            principal_scope: abs_por(i.spec_principal_constraint().spec_constraint(), principal_slot(), env),
            action_scope: abs_action_constraint(i.spec_action_constraint()),
            resource_scope: abs_por(i.spec_resource_constraint().spec_constraint(), resource_slot(), env),
            condition: abs_conditions(i.spec_non_scope_constraints(), env),
        },
    }
}

/// The scope's slots are bound in `env` and the non-scope constraint is modeled
pub open spec fn tbody_modeled(b: TemplateBody, env: SlotEnv, calls: bool) -> bool {
    match b {
        TemplateBody::TemplateBody(i) => {
            &&& por_bound(i.spec_principal_constraint().spec_constraint(), principal_slot(), env)
            &&& por_bound(i.spec_resource_constraint().spec_constraint(), resource_slot(), env)
            &&& match i.spec_non_scope_constraints() {
                Some(e) => expr_modeled(*e, env, calls),
                None => true,
            }
        },
    }
}

/// The linked policy of a production policy (Lean's `Cedar.Spec.Policy`)
pub open spec fn abs_linked_policy(p: Policy) -> mp::LinkedPolicy {
    abs_tbody(policy_body(p), abs_policy_id(policy_id(p)), policy_env(p))
}

/// The policy is modeled (with extension calls if `calls`)
pub open spec fn policy_modeled(p: Policy, calls: bool) -> bool {
    tbody_modeled(policy_body(p), policy_env(p), calls)
}

// ---------------------------------------------------------------------------
// The expressions built by `TemplateBody::condition`
// ---------------------------------------------------------------------------

/// `r` is the expression of the entity reference `x` (`EntityReference::into_expr`)
pub open spec fn entity_ref_rel(r: Expr, x: EntityReference, slot: SlotId) -> bool {
    match x {
        EntityReference::EUID(u) => r.spec_kind() == ExprKind::<()>::Lit(Literal::EntityUID(u)),
        EntityReference::Slot(_) => r.spec_kind() == ExprKind::<()>::Slot(slot),
    }
}

/// `r` is `v op x` for the variable `v` and the entity reference `x`
pub open spec fn var_op_ref_rel(r: Expr, op: BinaryOp, v: Var, x: EntityReference, slot: SlotId) -> bool {
    r.spec_kind() matches ExprKind::BinaryApp { op: o, arg1, arg2 } && o == op
        && arg1.spec_kind() == ExprKind::<()>::Var(v) && entity_ref_rel(*arg2, x, slot)
}

/// `r` is `v is t`
pub open spec fn var_is_rel(r: Expr, v: Var, t: EntityType) -> bool {
    r.spec_kind() matches ExprKind::Is { expr, entity_type } && entity_type == t
        && expr.spec_kind() == ExprKind::<()>::Var(v)
}

pub open spec fn var_of(v: PrincipalOrResource) -> Var {
    match v {
        PrincipalOrResource::Principal => Var::Principal,
        PrincipalOrResource::Resource => Var::Resource,
    }
}

pub open spec fn slot_of(v: PrincipalOrResource) -> SlotId {
    match v {
        PrincipalOrResource::Principal => principal_slot(),
        PrincipalOrResource::Resource => resource_slot(),
    }
}

/// `r` is the expression of the principal or resource constraint `c`
/// (`PrincipalOrResourceConstraint::as_expr`)
pub open spec fn por_expr_rel(r: Expr, c: PrincipalOrResourceConstraint, v: PrincipalOrResource) -> bool {
    match c {
        PrincipalOrResourceConstraint::Any => r.spec_kind() == ExprKind::<()>::Lit(Literal::Bool(true)),
        PrincipalOrResourceConstraint::Eq(x) => var_op_ref_rel(r, BinaryOp::Eq, var_of(v), x, slot_of(v)),
        PrincipalOrResourceConstraint::In(x) => var_op_ref_rel(r, BinaryOp::In, var_of(v), x, slot_of(v)),
        PrincipalOrResourceConstraint::Is(t) => var_is_rel(r, var_of(v), *t),
        PrincipalOrResourceConstraint::IsIn(t, x) => r.spec_kind() matches ExprKind::And { left, right }
            && var_is_rel(*left, var_of(v), *t) && var_op_ref_rel(*right, BinaryOp::In, var_of(v), x, slot_of(v)),
    }
}

/// `r` is the expression of the action constraint `c` (`ActionConstraint::as_expr`)
pub open spec fn action_expr_rel(r: Expr, c: ActionConstraint) -> bool {
    match c {
        ActionConstraint::Any => r.spec_kind() == ExprKind::<()>::Lit(Literal::Bool(true)),
        ActionConstraint::Eq(u) => r.spec_kind() matches ExprKind::BinaryApp { op, arg1, arg2 }
            && op == BinaryOp::Eq && arg1.spec_kind() == ExprKind::<()>::Var(Var::Action)
            && arg2.spec_kind() == ExprKind::<()>::Lit(Literal::EntityUID(u)),
        ActionConstraint::In(us) => r.spec_kind() matches ExprKind::BinaryApp { op, arg1, arg2 }
            && op == BinaryOp::In && arg1.spec_kind() == ExprKind::<()>::Var(Var::Action)
            && (arg2.spec_kind() matches ExprKind::Set(xs) && euid_lits_rel(xs@, us@)),
    }
}

/// `xs` are the entity literals `us`
pub open spec fn euid_lits_rel(xs: Seq<Expr>, us: Seq<Arc<EntityUID>>) -> bool {
    &&& xs.len() == us.len()
    &&& forall|i: int| 0 <= i < xs.len() ==> #[trigger] xs[i].spec_kind() == ExprKind::<()>::Lit(Literal::EntityUID(us[i]))
}

/// `r` is `Expr::and(a, b)`, which folds a conjunction of two boolean literals
pub open spec fn and_rel(r: Expr, a: Expr, b: Expr) -> bool {
    match (a.spec_kind(), b.spec_kind()) {
        (ExprKind::Lit(Literal::Bool(b1)), ExprKind::Lit(Literal::Bool(b2))) =>
            r.spec_kind() == ExprKind::<()>::Lit(Literal::Bool(b1 && b2)),
        _ => r.spec_kind() matches ExprKind::And { left, right } && *left == a && *right == b,
    }
}

/// `r` is `TemplateBody::condition` of `b`: in every slot environment where
/// `b` is modeled, `r` abstracts to the linked policy's `policy_to_expr`.
pub open spec fn body_cond_rel(r: Expr, b: TemplateBody) -> bool {
    forall|env: SlotEnv, calls: bool| #[trigger] tbody_modeled(b, env, calls) ==> {
        &&& expr_modeled(r, env, calls)
        &&& abs_expr(r, env) == mp::policy_to_expr(&abs_tbody(b, m::value::List::Nil, env))
    }
}

// ---------------------------------------------------------------------------
// Lemmas
// ---------------------------------------------------------------------------

/// A modeled expression abstracts to a boolean literal iff it is one.
pub proof fn lemma_abs_bool_lit(e: Expr, env: SlotEnv, calls: bool)
    requires
        expr_modeled(e, env, calls),
    ensures
        (abs_expr(e, env) matches m::expr::Expr::Lit(m::value::Prim::Bool(_))) == (e.spec_kind() matches ExprKind::Lit(
            Literal::Bool(_),
        )),
        e.spec_kind() matches ExprKind::Lit(Literal::Bool(b)) ==> abs_expr(e, env) == m::expr::Expr::Lit(m::value::Prim::Bool(b)),
{
    lemma_abs_expr(e, env);
    lemma_expr_modeled(e, env, calls);
}

/// `Expr::and` in the model
pub proof fn lemma_and_abs(r: Expr, a: Expr, b: Expr, env: SlotEnv, calls: bool)
    requires
        and_rel(r, a, b),
        expr_modeled(a, env, calls),
        expr_modeled(b, env, calls),
    ensures
        expr_modeled(r, env, calls),
        abs_expr(r, env) == mp::mk_and(abs_expr(a, env), abs_expr(b, env)),
{
    lemma_abs_expr(r, env);
    lemma_expr_modeled(r, env, calls);
    lemma_abs_bool_lit(a, env, calls);
    lemma_abs_bool_lit(b, env, calls);
}

pub proof fn lemma_entity_ref_abs(r: Expr, x: EntityReference, slot: SlotId, env: SlotEnv, calls: bool)
    requires
        entity_ref_rel(r, x, slot),
        entity_ref_bound(x, slot, env),
    ensures
        expr_modeled(r, env, calls),
        abs_expr(r, env) == m::expr::Expr::Lit(m::value::Prim::EntityUID(abs_entity_ref(x, slot, env))),
{
    lemma_abs_expr(r, env);
    lemma_expr_modeled(r, env, calls);
}

pub proof fn lemma_var_op_ref_abs(r: Expr, op: BinaryOp, v: Var, x: EntityReference, slot: SlotId, env: SlotEnv, calls: bool)
    requires
        var_op_ref_rel(r, op, v, x, slot),
        entity_ref_bound(x, slot, env),
    ensures
        expr_modeled(r, env, calls),
        abs_expr(r, env) == m::expr::Expr::BinaryApp(
            abs_binary_op(op),
            Box::new(m::expr::Expr::Var(abs_var(v))),
            Box::new(m::expr::Expr::Lit(m::value::Prim::EntityUID(abs_entity_ref(x, slot, env)))),
        ),
{
    lemma_abs_expr(r, env);
    lemma_expr_modeled(r, env, calls);
    if let ExprKind::BinaryApp { op: _, arg1, arg2 } = r.spec_kind() {
        lemma_abs_expr(*arg1, env);
        lemma_expr_modeled(*arg1, env, calls);
        lemma_entity_ref_abs(*arg2, x, slot, env, calls);
    }
}

pub proof fn lemma_var_is_abs(r: Expr, v: Var, t: EntityType, env: SlotEnv, calls: bool)
    requires
        var_is_rel(r, v, t),
    ensures
        expr_modeled(r, env, calls),
        abs_expr(r, env) == m::expr::Expr::UnaryApp(m::expr::UnaryOp::Is(abs_entity_type(t)), Box::new(m::expr::Expr::Var(abs_var(v)))),
{
    lemma_abs_expr(r, env);
    lemma_expr_modeled(r, env, calls);
    if let ExprKind::Is { expr, entity_type: _ } = r.spec_kind() {
        lemma_abs_expr(*expr, env);
        lemma_expr_modeled(*expr, env, calls);
    }
}

/// The expression of a principal or resource constraint, in the model
pub proof fn lemma_por_abs(r: Expr, c: PrincipalOrResourceConstraint, v: PrincipalOrResource, env: SlotEnv, calls: bool)
    requires
        por_expr_rel(r, c, v),
        por_bound(c, slot_of(v), env),
    ensures
        expr_modeled(r, env, calls),
        abs_expr(r, env) == mp::scope_to_expr(&abs_por(c, slot_of(v), env), &abs_var(var_of(v))),
{
    broadcast use lemma_clone_uid, lemma_clone_name;

    match c {
        PrincipalOrResourceConstraint::Any => {
            lemma_abs_expr(r, env);
            lemma_expr_modeled(r, env, calls);
        },
        PrincipalOrResourceConstraint::Eq(x) => {
            lemma_var_op_ref_abs(r, BinaryOp::Eq, var_of(v), x, slot_of(v), env, calls);
        },
        PrincipalOrResourceConstraint::In(x) => {
            lemma_var_op_ref_abs(r, BinaryOp::In, var_of(v), x, slot_of(v), env, calls);
        },
        PrincipalOrResourceConstraint::Is(t) => {
            lemma_var_is_abs(r, var_of(v), *t, env, calls);
        },
        PrincipalOrResourceConstraint::IsIn(t, x) => {
            lemma_abs_expr(r, env);
            lemma_expr_modeled(r, env, calls);
            if let ExprKind::And { left, right } = r.spec_kind() {
                lemma_var_is_abs(*left, var_of(v), *t, env, calls);
                lemma_var_op_ref_abs(*right, BinaryOp::In, var_of(v), x, slot_of(v), env, calls);
            }
        },
    }
}

proof fn lemma_uid_lits(xs: Seq<Expr>, us: Seq<Arc<EntityUID>>, env: SlotEnv, calls: bool)
    requires
        euid_lits_rel(xs, us),
    ensures
        forall|i: int| 0 <= i < xs.len() ==> #[trigger] expr_modeled(xs[i], env, calls),
        seq_to_list(xs.map_values(|x: Expr| abs_expr(x, env))) == mp::uid_lits(
            &seq_to_list(us.map_values(|u: Arc<EntityUID>| abs_uid(*u))),
        ),
    decreases xs.len(),
{
    broadcast use lemma_clone_uid;

    assert forall|i: int| 0 <= i < xs.len() implies #[trigger] expr_modeled(xs[i], env, calls) by {
        lemma_expr_modeled(xs[i], env, calls);
    }
    if xs.len() > 0 {
        let xs1 = xs.subrange(1, xs.len() as int);
        let us1 = us.subrange(1, us.len() as int);
        assert forall|i: int| 0 <= i < xs1.len() implies #[trigger] xs1[i].spec_kind()
            == ExprKind::<()>::Lit(Literal::EntityUID(us1[i])) by {
            assert(xs1[i] == xs[i + 1]);
        }
        lemma_uid_lits(xs1, us1, env, calls);
        lemma_abs_expr(xs[0], env);
        assert(xs.map_values(|x: Expr| abs_expr(x, env)).subrange(1, xs.len() as int) =~= xs1.map_values(
            |x: Expr| abs_expr(x, env),
        ));
        assert(us.map_values(|u: Arc<EntityUID>| abs_uid(*u)).subrange(1, us.len() as int) =~= us1.map_values(
            |u: Arc<EntityUID>| abs_uid(*u),
        ));
    }
}

/// The expression of an action constraint, in the model
pub proof fn lemma_action_abs(r: Expr, c: ActionConstraint, env: SlotEnv, calls: bool)
    requires
        action_expr_rel(r, c),
    ensures
        expr_modeled(r, env, calls),
        abs_expr(r, env) == mp::action_scope_to_expr(&abs_action_constraint(c)),
{
    broadcast use lemma_clone_uid;

    lemma_abs_expr(r, env);
    lemma_expr_modeled(r, env, calls);
    match c {
        ActionConstraint::Any => {},
        ActionConstraint::Eq(u) => {
            if let ExprKind::BinaryApp { op: _, arg1, arg2 } = r.spec_kind() {
                lemma_abs_expr(*arg1, env);
                lemma_expr_modeled(*arg1, env, calls);
                lemma_abs_expr(*arg2, env);
                lemma_expr_modeled(*arg2, env, calls);
            }
        },
        ActionConstraint::In(us) => {
            if let ExprKind::BinaryApp { op: _, arg1, arg2 } = r.spec_kind() {
                lemma_abs_expr(*arg1, env);
                lemma_expr_modeled(*arg1, env, calls);
                lemma_abs_expr(*arg2, env);
                lemma_expr_modeled(*arg2, env, calls);
                if let ExprKind::Set(xs) = arg2.spec_kind() {
                    lemma_uid_lits(xs@, us@, env, calls);
                    lemma_seq_to_list_list_view(abs_exprs(*xs, env));
                }
            }
        },
    }
}

/// The condition of a template body, in the model, for one slot environment
pub proof fn lemma_body_cond(
    r: Expr,
    b: TemplateBody,
    pe: Expr,
    ae: Expr,
    re: Expr,
    ne: Expr,
    x2: Expr,
    x1: Expr,
    env: SlotEnv,
    calls: bool,
)
    requires
        b matches TemplateBody::TemplateBody(i) && {
            &&& por_expr_rel(pe, i.spec_principal_constraint().spec_constraint(), PrincipalOrResource::Principal)
            &&& action_expr_rel(ae, i.spec_action_constraint())
            &&& por_expr_rel(re, i.spec_resource_constraint().spec_constraint(), PrincipalOrResource::Resource)
            &&& match i.spec_non_scope_constraints() {
                Some(e) => ne == *e,
                None => ne.spec_kind() == ExprKind::<()>::Lit(Literal::Bool(true)),
            }
        },
        and_rel(x2, re, ne),
        and_rel(x1, ae, x2),
        and_rel(r, pe, x1),
        tbody_modeled(b, env, calls),
    ensures
        expr_modeled(r, env, calls),
        abs_expr(r, env) == mp::policy_to_expr(&abs_tbody(b, m::value::List::Nil, env)),
{
    broadcast use group_linked_clone;

    let TemplateBody::TemplateBody(i) = b;
    lemma_por_abs(pe, i.spec_principal_constraint().spec_constraint(), PrincipalOrResource::Principal, env, calls);
    lemma_por_abs(re, i.spec_resource_constraint().spec_constraint(), PrincipalOrResource::Resource, env, calls);
    lemma_action_abs(ae, i.spec_action_constraint(), env, calls);
    match i.spec_non_scope_constraints() {
        Some(e) => {},
        None => {
            lemma_abs_expr(ne, env);
            lemma_expr_modeled(ne, env, calls);
        },
    }
    lemma_and_abs(x2, re, ne, env, calls);
    lemma_and_abs(x1, ae, x2, env, calls);
    lemma_and_abs(r, pe, x1, env, calls);
    let t = abs_tbody(b, m::value::List::Nil, env);
    match i.spec_non_scope_constraints() {
        Some(e) => {
            if let m::value::List::Cons(c, rest) = t.condition {
                assert(mp::condition_to_expr(&c) == abs_expr(ne, env));
                assert(*rest is Nil);
            }
            assert(mp::conditions_to_expr(&t.condition) == abs_expr(ne, env));
        },
        None => {},
    }
}

/// The model condition of a linked policy does not depend on its ID.
pub proof fn lemma_policy_to_expr_id(b: TemplateBody, id: m::value::Str, env: SlotEnv)
    ensures
        mp::policy_to_expr(&abs_tbody(b, id, env)) == mp::policy_to_expr(&abs_tbody(b, m::value::List::Nil, env)),
{
    let TemplateBody::TemplateBody(i) = b;
    let lp = abs_tbody(b, id, env);
    let lp0 = abs_tbody(b, m::value::List::Nil, env);
    assert(lp == mp::LinkedPolicy { id, ..lp0 });
}

} // verus!
