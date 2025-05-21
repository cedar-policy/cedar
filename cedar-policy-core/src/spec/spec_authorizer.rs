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

pub use crate::spec::spec_ast::*;
pub use crate::verus_utils::*;
#[cfg(verus_keep_ghost)]
pub use vstd::{map::*, prelude::*, seq::*, set::*};

verus! {

// def satisfied (policy : Policy) (req : Request) (entities : Entities) : Bool :=
//   (evaluate policy.toExpr req entities) = .ok true

// def satisfiedWithEffect (effect : Effect) (policy : Policy) (req : Request) (entities : Entities) : Option PolicyID :=
//   if policy.effect == effect && satisfied policy req entities
//   then some policy.id
//   else none

// def satisfiedPolicies (effect : Effect) (policies : Policies) (req : Request) (entities : Entities) : Set PolicyID :=
//   Set.make (policies.filterMap (satisfiedWithEffect effect · req entities))

// def hasError (policy : Policy) (req : Request) (entities : Entities) : Bool :=
//   match (evaluate policy.toExpr req entities) with
//   | .ok _ => false
//   | .error _ => true

// /--
//   This function is analogous to `satisfiedWithEffect` in that it returns
//   `Option PolicyID`, but not analogous to `satisfiedWithEffect` in that it does
//   not consider the policy's effect.
// -/
// def errored (policy : Policy) (req : Request) (entities : Entities) : Option PolicyID :=
//   if hasError policy req entities then some policy.id else none

// def errorPolicies (policies : Policies) (req : Request) (entities : Entities) : Set PolicyID :=
//   Set.make (policies.filterMap (errored · req entities))

// def isAuthorized (req : Request) (entities : Entities) (policies : Policies) : Response :=
//   let forbids := satisfiedPolicies .forbid policies req entities
//   let permits := satisfiedPolicies .permit policies req entities
//   let erroringPolicies := errorPolicies policies req entities
//   if forbids.isEmpty && !permits.isEmpty
//   then { decision := .allow, determiningPolicies := permits, erroringPolicies }
//   else { decision := .deny,  determiningPolicies := forbids, erroringPolicies }

}
