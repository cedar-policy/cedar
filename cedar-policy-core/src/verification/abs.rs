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

//! Abstraction functions from production types to model types.

use vstd::prelude::*;

use super::model as m;
use super::trusted::*;
use super::value_abs::*;
use crate::ast::*;
use crate::ast::{Integer, Set};
use crate::authorizer::{AuthorizationError, Decision, Response};
use crate::evaluator::EvaluationError;
use smol_str::SmolStr;

verus! {

pub open spec fn seq_to_list<T>(s: Seq<T>) -> m::value::List<T>
    decreases s.len(),
{
    if s.len() == 0 {
        m::value::List::Nil
    } else {
        m::value::List::Cons(s[0], Box::new(seq_to_list(s.subrange(1, s.len() as int))))
    }
}

pub open spec fn list_view<T>(l: m::value::List<T>) -> Seq<T>
    decreases l,
{
    match l {
        m::value::List::Nil => Seq::empty(),
        m::value::List::Cons(x, rest) => seq![x] + list_view(*rest),
    }
}

pub open spec fn abs_str(s: SmolStr) -> m::value::Str {
    seq_to_list(smol_view(s))
}

pub open spec fn abs_id(i: Id) -> m::value::Str {
    abs_str(i.spec_smolstr())
}

pub open spec fn abs_name(n: Name) -> m::value::Name {
    m::value::Name {
        id: abs_id(n.spec_internal().spec_id()),
        path: seq_to_list(n.spec_internal().spec_path().map_values(|i: Id| abs_id(i))),
    }
}

pub open spec fn abs_entity_type(t: EntityType) -> m::value::Name {
    match t {
        EntityType::EntityType(n) => abs_name(n),
    }
}

pub open spec fn abs_eid(e: Eid) -> m::value::Str {
    match e {
        Eid::Eid(s) => abs_str(s),
    }
}

pub open spec fn abs_uid(u: EntityUID) -> m::value::EntityUID {
    match u {
        EntityUID::EntityUID(i) => m::value::EntityUID {
            ty: abs_entity_type(i.spec_ty()),
            eid: abs_eid(i.spec_eid()),
        },
    }
}

pub open spec fn abs_lit(l: Literal) -> m::value::Prim {
    match l {
        Literal::Bool(b) => m::value::Prim::Bool(b),
        Literal::Long(i) => m::value::Prim::Int(i),
        Literal::String(s) => m::value::Prim::String(abs_str(s)),
        Literal::EntityUID(u) => m::value::Prim::EntityUID(abs_uid(*u)),
    }
}

pub open spec fn abs_var(v: Var) -> m::expr::Var {
    match v {
        Var::Principal => m::expr::Var::Principal,
        Var::Action => m::expr::Var::Action,
        Var::Resource => m::expr::Var::Resource,
        Var::Context => m::expr::Var::Context,
    }
}

pub open spec fn abs_pattern_elem(e: PatternElem) -> m::expr::PatElem {
    match e {
        PatternElem::Char(c) => m::expr::PatElem::JustChar(c),
        PatternElem::Wildcard => m::expr::PatElem::Star,
    }
}

pub open spec fn abs_pattern(p: Pattern) -> m::value::List<m::expr::PatElem> {
    seq_to_list(p.spec_elems().map_values(|e: PatternElem| abs_pattern_elem(e)))
}

/// The attribute path of `x has a.b.c`
pub open spec fn abs_attr_path(attrs: nonempty::NonEmpty<SmolStr>) -> m::value::List<m::value::Str> {
    m::value::List::Cons(
        abs_str(attrs.head),
        Box::new(seq_to_list(attrs.tail@.map_values(|a: SmolStr| abs_str(a)))),
    )
}

/// The attribute path of `x has a.b.c`, as a sequence
pub open spec fn attr_path_seq(attrs: nonempty::NonEmpty<SmolStr>) -> Seq<m::value::Str> {
    seq![abs_str(attrs.head)] + attrs.tail@.map_values(|a: SmolStr| abs_str(a))
}

pub open spec fn abs_unary_op(op: UnaryOp) -> Option<m::expr::UnaryOp> {
    match op {
        UnaryOp::Not => Some(m::expr::UnaryOp::Not),
        UnaryOp::Neg => Some(m::expr::UnaryOp::Neg),
        UnaryOp::IsEmpty => Some(m::expr::UnaryOp::IsEmpty),
    }
}

pub open spec fn abs_binary_op(op: BinaryOp) -> m::expr::BinaryOp {
    match op {
        BinaryOp::Eq => m::expr::BinaryOp::Eq,
        BinaryOp::Less => m::expr::BinaryOp::Less,
        BinaryOp::LessEq => m::expr::BinaryOp::LessEq,
        BinaryOp::Add => m::expr::BinaryOp::Add,
        BinaryOp::Sub => m::expr::BinaryOp::Sub,
        BinaryOp::Mul => m::expr::BinaryOp::Mul,
        BinaryOp::In => m::expr::BinaryOp::Mem,
        BinaryOp::Contains => m::expr::BinaryOp::Contains,
        BinaryOp::ContainsAll => m::expr::BinaryOp::ContainsAll,
        BinaryOp::ContainsAny => m::expr::BinaryOp::ContainsAny,
        BinaryOp::GetTag => m::expr::BinaryOp::GetTag,
        BinaryOp::HasTag => m::expr::BinaryOp::HasTag,
    }
}

pub open spec fn abs_entry(e: EntityUIDEntry) -> m::value::EntityUID {
    match e {
        EntityUIDEntry::Known { euid, .. } => abs_uid(*euid),
        _ => arbitrary(),
    }
}

pub open spec fn abs_policy_id(id: PolicyID) -> m::value::Str {
    abs_str(policy_id_str(id))
}

pub open spec fn abs_effect(e: Effect) -> m::authorizer::Effect {
    match e {
        Effect::Permit => m::authorizer::Effect::Permit,
        Effect::Forbid => m::authorizer::Effect::Forbid,
    }
}

/// The authorizer's policy of a policy: `to_policy` of its linked
/// policy (`policy_abs::abs_linked_policy`)
pub open spec fn abs_policy(p: Policy) -> m::authorizer::Policy {
    super::model::policy::to_policy(&super::policy_abs::abs_linked_policy(p))
}

/// The policies of a policy set, in the model
pub open spec fn abs_policy_set(ps: PolicySet) -> m::value::List<m::authorizer::Policy> {
    seq_to_list(pset_policies(ps).map_values(|p: Policy| abs_policy(p)))
}

/// All policies of the set are modeled (with extension calls if `calls`)
pub open spec fn policy_set_modeled(ps: PolicySet, calls: bool) -> bool {
    forall|i: int| 0 <= i < pset_policies(ps).len() ==> #[trigger] super::policy_abs::policy_modeled(pset_policies(ps)[i], calls)
}

/// A production response agrees with a model response: same decision, and
/// the same sets of determining and erroring policies.
pub open spec fn response_rel(r: Response, mr: m::authorizer::Response) -> bool {
    &&& (r.decision is Allow) == (mr.decision is Allow)
    &&& r.diagnostics.reason@.map(|id: PolicyID| abs_policy_id(id)) == list_view(mr.determining_policies).to_set()
    &&& error_ids(r.diagnostics.errors@).map(|id: PolicyID| abs_policy_id(id)) == list_view(mr.erroring_policies).to_set()
}

/// The request is concrete and its context is a modeled record
pub open spec fn request_wf(q: Request) -> bool {
    &&& q.spec_principal() is Known
    &&& q.spec_action() is Known
    &&& q.spec_resource() is Known
    &&& q.spec_context() matches Some(Context::Value(r)) && modeled_kind(ValueKind::Record(r))
}

pub open spec fn abs_request(q: Request) -> m::request::Request {
    m::request::Request {
        principal: abs_entry(q.spec_principal()),
        action: abs_entry(q.spec_action()),
        resource: abs_entry(q.spec_resource()),
        context: match q.spec_context() {
            Some(Context::Value(r)) => abs_record(*r),
            _ => m::value::List::Nil,
        },
    }
}

/// A production (partial-evaluation) result agrees with a model result: both
/// succeed with corresponding (non-residual) values, or both fail (with any
/// error).
pub open spec fn pv_result_rel(r: Result<PartialValue, EvaluationError>, mr: Result<m::value::Value, m::value::Error>) -> bool {
    match (r, mr) {
        (Ok(PartialValue::Value(v)), Ok(mv)) => modeled(v) && abs_value(v) == mv,
        (Err(_), Err(_)) => true,
        _ => false,
    }
}

/// A production result agrees with a model result: both succeed with
/// corresponding values, or both fail (with any error).
pub open spec fn result_rel(r: Result<Value, EvaluationError>, mr: Result<m::value::Value, m::value::Error>) -> bool {
    match (r, mr) {
        (Ok(v), Ok(mv)) => modeled(v) && abs_value(v) == mv,
        (Err(_), Err(_)) => true,
        _ => false,
    }
}

} // verus!
