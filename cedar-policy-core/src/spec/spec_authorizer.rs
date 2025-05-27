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

}
