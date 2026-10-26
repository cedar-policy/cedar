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
//! Relations between the public API types and the core types.
#![allow(unused_imports)]

use vstd::prelude::*;

use crate::api::*;
use cedar_policy_core::ast;
use cedar_policy_core::authorizer;
use cedar_policy_core::verification::abs as ca;
use cedar_policy_core::verification::authorizer_theorems as th;
use cedar_policy_core::verification::trusted as ct;
use vstd::seq::Seq;
use vstd::set::Set;

verus! {

/// The preconditions of the public `Authorizer::is_authorized`: those of the core one.
pub open spec fn authorization_hyps(a: Authorizer, r: Request, p: PolicySet, e: Entities) -> bool {
    &&& th::authorization_hyps(a.spec_ast(), r.spec_ast(), p.spec_ast(), e.spec_ast())
    &&& !ct::stack_exhausted()
}

/// `r` has the decision, determining policies and erroring policies of `r0`.
pub open spec fn response_lift(r: Response, r0: authorizer::Response) -> bool {
    &&& r.spec_decision() == r0.decision
    &&& r.spec_reason().map(|id: PolicyId| id.spec_ast()) == r0.diagnostics.reason@
    &&& r.spec_errors().map_values(|e: AuthorizationError| e.spec_policy_id()).to_set() == ct::error_ids(r0.diagnostics.errors@)
}

/// `r` lifts a response of the core `Authorizer::is_authorized` on the same arguments.
pub open spec fn is_authorized_lift(a: Authorizer, q: Request, p: PolicySet, e: Entities, r: Response) -> bool {
    exists|r0: authorizer::Response| #[trigger] th::authorized(a.spec_ast(), q.spec_ast(), p.spec_ast(), e.spec_ast(), r0)
        && response_lift(r, r0)
}

/// For `From<authorizer::Response> for Response`
pub proof fn lemma_response_lift(r0: authorizer::Response, r: Response)
    requires
        r.spec_decision() == r0.decision,
        r.spec_reason().map(|id: PolicyId| id.spec_ast()) == r0.diagnostics.reason@,
        r.spec_errors().map_values(|e: AuthorizationError| e.spec_policy_id())
            == r0.diagnostics.errors@.map_values(|e: authorizer::AuthorizationError| ct::error_policy_id(e)),
    ensures
        response_lift(r, r0),
{
}

} // verus!
