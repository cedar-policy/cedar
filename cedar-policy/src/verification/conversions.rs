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

//! `FromSpecImpl`s for the public API's `From` impls, which have their own
//! specifications (so `obeys_from_spec` is `false`).

use vstd::prelude::*;
use vstd::std_specs::convert::FromSpecImpl;

use crate::api::*;
use cedar_policy_core::authorizer;

verus! {

impl FromSpecImpl<authorizer::AuthorizationError> for crate::api::authorization_errors::PolicyEvaluationError {
    open spec fn obeys_from_spec() -> bool {
        false
    }

    open spec fn from_spec(v: authorizer::AuthorizationError) -> Self {
        arbitrary()
    }
}

impl FromSpecImpl<authorizer::AuthorizationError> for AuthorizationError {
    open spec fn obeys_from_spec() -> bool {
        false
    }

    open spec fn from_spec(v: authorizer::AuthorizationError) -> Self {
        arbitrary()
    }
}

impl FromSpecImpl<authorizer::Diagnostics> for Diagnostics {
    open spec fn obeys_from_spec() -> bool {
        false
    }

    open spec fn from_spec(v: authorizer::Diagnostics) -> Self {
        arbitrary()
    }
}

impl FromSpecImpl<authorizer::Response> for Response {
    open spec fn obeys_from_spec() -> bool {
        false
    }

    open spec fn from_spec(v: authorizer::Response) -> Self {
        arbitrary()
    }
}

} // verus!
