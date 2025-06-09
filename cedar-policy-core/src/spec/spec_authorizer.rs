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

//! This module contains a spec of the Cedar authorizer, translated to Verus spec code
//! from the Lean spec in cedar-spec/cedar-lean/Cedar/Spec/Authorizer.lean.

#![allow(missing_debug_implementations)] // vstd types Seq/Set/Map don't impl Debug
#![allow(missing_docs)] // just for now
#![allow(unused_imports)]

pub use crate::spec::{spec_ast::*, spec_evaluator::*};
pub use crate::verus_utils::*;
#[cfg(verus_keep_ghost)]
pub use vstd::{map::*, prelude::*, seq::*, set::*};

verus! {

#[verifier::opaque]
pub open spec fn satisfied(p: Policy, req: Request, entities: Entities) -> bool {
    &&& evaluate(p.to_expr(), req, entities) matches Ok(v)
    &&& v is Prim &&& v->p is Bool &&& v->p->b == true
}

#[verifier::opaque]
pub open spec fn satisfied_with_effect(effect: Effect, policy: Policy, req: Request, entities: Entities) -> Option<PolicyID> {
    if policy.effect == effect && satisfied(policy, req, entities) {
        Some(policy.id)
    } else {
        None
    }
}

#[verifier::opaque]
pub open spec fn satisfied_policies(effect: Effect, policies: Policies, req: Request, entities: Entities) -> Set<PolicyID> {
    seq_filter_map_option(policies, |p: Policy| satisfied_with_effect(effect, p, req, entities)).to_set()
}

#[verifier::opaque]
pub open spec fn has_error(policy: Policy, req: Request, entities: Entities) -> bool {
    evaluate(policy.to_expr(), req, entities) is Err
}

// This function is analogous to `satisfiedWithEffect` in that it returns
// `Option PolicyID`, but not analogous to `satisfiedWithEffect` in that it does
// not consider the policy's effect.
#[verifier::opaque]
pub open spec fn errored(policy: Policy, req: Request, entities: Entities) -> Option<PolicyID> {
    if has_error(policy, req, entities) {
        Some(policy.id)
    } else {
        None
    }
}

#[verifier::opaque]
pub open spec fn error_policies(policies: Policies, req: Request, entities: Entities) -> Set<PolicyID> {
    seq_filter_map_option(policies, |p: Policy| errored(p, req, entities)).to_set()
}

#[verifier::opaque]
pub open spec fn is_authorized(req: Request, entities: Entities, policies: Policies) -> Response {
    let forbids = satisfied_policies(Effect::Forbid, policies, req, entities);
    let permits = satisfied_policies(Effect::Permit, policies, req, entities);
    let erroring_policies = error_policies(policies, req, entities);
    if forbids.is_empty() && !permits.is_empty() {
        Response {
            decision: Decision::Allow,
            determining_policies: permits,
            erroring_policies
        }
    } else {
        Response {
            decision: Decision::Deny,
            determining_policies: forbids,
            erroring_policies
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Alternate version of authorizer using Set<Policy>, instead of Seq<Policy> //
///////////////////////////////////////////////////////////////////////////////

#[verifier::opaque]
pub open spec fn satisfied_policies_from_set(effect: Effect, policy_set: Set<Policy>, req: Request, entities: Entities) -> Set<PolicyID> {
    policy_set.filter_map(|p: Policy| satisfied_with_effect(effect, p, req, entities))
}

#[verifier::opaque]
pub open spec fn error_policies_from_set(policy_set: Set<Policy>, req: Request, entities: Entities) -> Set<PolicyID> {
    policy_set.filter_map(|p: Policy| errored(p, req, entities))
}

#[verifier::opaque]
pub open spec fn is_authorized_from_set(req: Request, entities: Entities, policy_set: Set<Policy>) -> Response {
    let forbids = satisfied_policies_from_set(Effect::Forbid, policy_set, req, entities);
    let permits = satisfied_policies_from_set(Effect::Permit, policy_set, req, entities);
    let erroring_policies = error_policies_from_set(policy_set, req, entities);
    if forbids.is_empty() && !permits.is_empty() {
        Response {
            decision: Decision::Allow,
            determining_policies: permits,
            erroring_policies
        }
    } else {
        Response {
            decision: Decision::Deny,
            determining_policies: forbids,
            erroring_policies
        }
    }
}


}

////////////////////////////////////////////////////////
// Helper definitions and lemmas about the authorizer //
////////////////////////////////////////////////////////

verus! {

// Lemmas connecting the main specs to the `_from_set` specs

pub proof fn lemma_satisfied_policies_from_set(effect: Effect, policy_set: Set<Policy>, req: Request, entities: Entities)
    requires policy_set.finite()
    ensures satisfied_policies_from_set(effect, policy_set, req, entities) == satisfied_policies(effect, policy_set.to_seq(), req, entities)
{
    reveal(satisfied_policies);
    reveal(satisfied_policies_from_set);
    lemma_set_seq_filter_map_option(policy_set, |p: Policy| satisfied_with_effect(effect, p, req, entities))
}

pub proof fn lemma_error_policies_from_set(policy_set: Set<Policy>, req: Request, entities: Entities)
    requires policy_set.finite()
    ensures error_policies_from_set(policy_set, req, entities) == error_policies(policy_set.to_seq(), req, entities)
{
    reveal(error_policies);
    reveal(error_policies_from_set);
    lemma_set_seq_filter_map_option(policy_set, |p: Policy| errored(p, req, entities))
}

pub proof fn lemma_is_authorized_from_set(req: Request, entities: Entities, policy_set: Set<Policy>)
    requires policy_set.finite()
    ensures is_authorized_from_set(req, entities, policy_set) == is_authorized(req, entities, policy_set.to_seq())
{
    reveal(is_authorized);
    reveal(is_authorized_from_set);
    lemma_satisfied_policies_from_set(Effect::Forbid, policy_set, req, entities);
    lemma_satisfied_policies_from_set(Effect::Permit, policy_set, req, entities);
    lemma_error_policies_from_set(policy_set, req, entities);
}


// Helper lemmas for `is_authorized` proof

pub proof fn lemma_satisfied_policies_from_set_empty(effect: Effect, req: Request, entities: Entities)
    ensures satisfied_policies_from_set(effect, Set::<Policy>::empty(), req, entities).is_empty()
{
    reveal(satisfied_policies_from_set);
    // lemma_set_filter_map_empty(|p: Policy| satisfied_with_effect(effect, p, req, entities))
}


pub proof fn lemma_satisfied_policies_from_set_insert_some(effect: Effect, policy_set: Set<Policy>, req: Request, entities: Entities, new_policy: Policy, new_id: PolicyID)
    requires
        policy_set.finite(),
        satisfied_with_effect(effect, new_policy, req, entities) matches Some(new_id_) && new_id_ == new_id,
    ensures
        satisfied_policies_from_set(effect, policy_set.insert(new_policy), req, entities) == satisfied_policies_from_set(effect, policy_set, req, entities).insert(new_id)
{
    reveal(satisfied_policies_from_set);
    lemma_set_filter_map_insert_some(policy_set, |p: Policy| satisfied_with_effect(effect, p, req, entities), new_policy, new_id)
}

pub proof fn lemma_satisfied_policies_from_set_insert_none(effect: Effect, policy_set: Set<Policy>, req: Request, entities: Entities, new_policy: Policy)
    requires
        policy_set.finite(),
        satisfied_with_effect(effect, new_policy, req, entities) is None
    ensures
        satisfied_policies_from_set(effect, policy_set.insert(new_policy), req, entities) == satisfied_policies_from_set(effect, policy_set, req, entities)
{
    reveal(satisfied_policies_from_set);
    lemma_set_filter_map_insert_none(policy_set, |p: Policy| satisfied_with_effect(effect, p, req, entities), new_policy)
}


pub proof fn lemma_erroring_policy_cannot_be_satisfied(policy: Policy, req: Request, entities: Entities)
    requires
        has_error(policy, req, entities)
    ensures
        forall |effect: Effect| (#[trigger] satisfied_with_effect(effect, policy, req, entities)) is None
{
    reveal(has_error);
    reveal(satisfied_with_effect);
    reveal(satisfied);
}

}
