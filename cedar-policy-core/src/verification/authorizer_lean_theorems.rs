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

//! TRUSTED: transcriptions of the Lean theorems about the Aeneas-extracted
//! model (`cedar-rust-model/lean/CedarRustModel/Theorems/Authorization.lean`),
//! assumed as axioms. Each names the Lean theorem or definition it transcribes.
//!
//! Conventions (Lean => Verus):
//! * `f x = ok r` => `f(x) == r`; `∃ r, f x = ok r ∧ P r` => `P(f(x))`
//! * `satisfied p req es = ok true` / `ok false` => `satisfied(..)` / `!satisfied(..)`
//!   (likewise `has_error`)
//! * `x ∈ List.toList l` => `list_view(l).contains(x)`

use vstd::prelude::*;

use super::abs::list_view;
use super::model as m;
use super::model::policy as mp;

verus! {

/// Lean: `Thm.IsLinked`
pub open spec fn is_linked(p: m::authorizer::Policy) -> bool {
    exists|lp: mp::LinkedPolicy| #[trigger] mp::to_policy(&lp) == p
}

/// Lean: `Thm.Linked`
pub open spec fn linked(ps: m::value::List<m::authorizer::Policy>) -> bool {
    forall|p: m::authorizer::Policy| #[trigger] list_view(ps).contains(p) ==> is_linked(p)
}

/// Lean: `Thm.HasSatisfiedEffect`
pub open spec fn has_satisfied_effect(eff: m::authorizer::Effect, req: m::request::Request, es: m::entities::Entities, ps: m::value::List<m::authorizer::Policy>) -> bool {
    exists|p: m::authorizer::Policy| #[trigger] list_view(ps).contains(p) && p.effect == eff && m::authorizer::satisfied(&p, &req, &es)
}

/// Lean: `Thm.IsExplicitlyForbidden`
pub open spec fn is_explicitly_forbidden(req: m::request::Request, es: m::entities::Entities, ps: m::value::List<m::authorizer::Policy>) -> bool {
    has_satisfied_effect(m::authorizer::Effect::Forbid, req, es, ps)
}

/// Lean: `Thm.IsExplicitlyPermitted`
pub open spec fn is_explicitly_permitted(req: m::request::Request, es: m::entities::Entities, ps: m::value::List<m::authorizer::Policy>) -> bool {
    has_satisfied_effect(m::authorizer::Effect::Permit, req, es, ps)
}

/// Lean: `Thm.decisionEffect`
pub open spec fn decision_effect(d: m::authorizer::Decision) -> m::authorizer::Effect {
    match d {
        m::authorizer::Decision::Allow => m::authorizer::Effect::Permit,
        m::authorizer::Decision::Deny => m::authorizer::Effect::Forbid,
    }
}

/// Lean: `Thm.IsSoundPolicySlice`
pub open spec fn is_sound_policy_slice(req: m::request::Request, es: m::entities::Entities, slice: m::value::List<m::authorizer::Policy>, ps: m::value::List<m::authorizer::Policy>) -> bool {
    &&& forall|p: m::authorizer::Policy| #[trigger] list_view(slice).contains(p) ==> list_view(ps).contains(p)
    &&& forall|p: m::authorizer::Policy| #[trigger] list_view(ps).contains(p) && !list_view(slice).contains(p) ==>
            !m::authorizer::satisfied(&p, &req, &es) && !m::authorizer::has_error(&p, &req, &es)
}

/// Lean: `Thm.forbid_trumps_permit`
pub axiom fn forbid_trumps_permit(req: m::request::Request, es: m::entities::Entities, ps: m::value::List<m::authorizer::Policy>)
    requires
        linked(ps),
        is_explicitly_forbidden(req, es, ps),
    ensures
        m::authorizer::is_authorized(&req, &es, &ps).decision is Deny,
;

/// Lean: `Thm.allowed_only_if_explicitly_permitted`
pub axiom fn allowed_only_if_explicitly_permitted(req: m::request::Request, es: m::entities::Entities, ps: m::value::List<m::authorizer::Policy>)
    requires
        linked(ps),
    ensures
        m::authorizer::is_authorized(&req, &es, &ps).decision is Allow ==> is_explicitly_permitted(req, es, ps),
;

/// Lean: `Thm.default_deny`
pub axiom fn default_deny(req: m::request::Request, es: m::entities::Entities, ps: m::value::List<m::authorizer::Policy>)
    requires
        linked(ps),
        !is_explicitly_permitted(req, es, ps),
    ensures
        m::authorizer::is_authorized(&req, &es, &ps).decision is Deny,
;

/// Lean: `Thm.allowed_iff_explicitly_permitted_and_not_denied`
pub axiom fn allowed_iff_explicitly_permitted_and_not_denied(req: m::request::Request, es: m::entities::Entities, ps: m::value::List<m::authorizer::Policy>)
    requires
        linked(ps),
    ensures
        (is_explicitly_permitted(req, es, ps) && !is_explicitly_forbidden(req, es, ps))
            <==> m::authorizer::is_authorized(&req, &es, &ps).decision is Allow,
;

/// Lean: `Thm.denied_iff_explicitly_denied_or_not_permitted`
pub axiom fn denied_iff_explicitly_denied_or_not_permitted(req: m::request::Request, es: m::entities::Entities, ps: m::value::List<m::authorizer::Policy>)
    requires
        linked(ps),
    ensures
        (is_explicitly_forbidden(req, es, ps) || !is_explicitly_permitted(req, es, ps))
            <==> m::authorizer::is_authorized(&req, &es, &ps).decision is Deny,
;

/// Lean: `Thm.order_and_dup_independent`
pub axiom fn order_and_dup_independent(req: m::request::Request, es: m::entities::Entities, ps1: m::value::List<m::authorizer::Policy>, ps2: m::value::List<m::authorizer::Policy>)
    requires
        linked(ps1),
        linked(ps2),
        forall|p: m::authorizer::Policy| list_view(ps1).contains(p) <==> list_view(ps2).contains(p),
    ensures
        m::authorizer::is_authorized(&req, &es, &ps1) == m::authorizer::is_authorized(&req, &es, &ps2),
;

/// Lean: `Thm.unchanged_allow_when_add_permit`
pub axiom fn unchanged_allow_when_add_permit(req: m::request::Request, es: m::entities::Entities, ps: m::value::List<m::authorizer::Policy>, p: m::authorizer::Policy)
    requires
        linked(ps),
        is_linked(p),
        p.effect is Permit,
    ensures
        m::authorizer::is_authorized(&req, &es, &ps).decision is Allow
            ==> m::authorizer::is_authorized(&req, &es, &m::value::List::Cons(p, Box::new(ps))).decision is Allow,
;

/// Lean: `Thm.unchanged_deny_when_add_forbid`
pub axiom fn unchanged_deny_when_add_forbid(req: m::request::Request, es: m::entities::Entities, ps: m::value::List<m::authorizer::Policy>, p: m::authorizer::Policy)
    requires
        linked(ps),
        is_linked(p),
        p.effect is Forbid,
    ensures
        m::authorizer::is_authorized(&req, &es, &ps).decision is Deny
            ==> m::authorizer::is_authorized(&req, &es, &m::value::List::Cons(p, Box::new(ps))).decision is Deny,
;

/// Lean: `Thm.is_authorized_eq_for_sound_policy_slice`
pub axiom fn is_authorized_eq_for_sound_policy_slice(req: m::request::Request, es: m::entities::Entities, slice: m::value::List<m::authorizer::Policy>, ps: m::value::List<m::authorizer::Policy>)
    requires
        linked(ps),
        is_sound_policy_slice(req, es, slice, ps),
    ensures
        m::authorizer::is_authorized(&req, &es, &slice) == m::authorizer::is_authorized(&req, &es, &ps),
;

/// Lean: `Thm.determining_policies_of`
pub axiom fn determining_policies_of(req: m::request::Request, es: m::entities::Entities, ps: m::value::List<m::authorizer::Policy>)
    requires
        linked(ps),
    ensures
        forall|id: m::value::Str| #[trigger] list_view(m::authorizer::is_authorized(&req, &es, &ps).determining_policies).contains(id)
            <==> exists|p: m::authorizer::Policy| #[trigger] list_view(ps).contains(p) && p.id == id
                && p.effect == decision_effect(m::authorizer::is_authorized(&req, &es, &ps).decision)
                && m::authorizer::satisfied(&p, &req, &es),
;

/// Lean: `Thm.erroring_policies_of`
pub axiom fn erroring_policies_of(req: m::request::Request, es: m::entities::Entities, ps: m::value::List<m::authorizer::Policy>)
    requires
        linked(ps),
    ensures
        forall|id: m::value::Str| #[trigger] list_view(m::authorizer::is_authorized(&req, &es, &ps).erroring_policies).contains(id)
            <==> exists|p: m::authorizer::Policy| #[trigger] list_view(ps).contains(p) && p.id == id && m::authorizer::has_error(&p, &req, &es),
;

} // verus!
