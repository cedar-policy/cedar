/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

use cedar_policy_core::ast;
use cedar_policy_core::authorizer::{Authorizer, Diagnostics};
use cedar_policy_core::entities::Entities;
use cedar_policy_core::parser;
use arbitrary::Arbitrary;

 #[derive(Arbitrary, Debug, Clone)]
 struct AuthorizerInputAbstractEvaluator {
     /// Set of AbstractPolicy objects
     policies: Vec<AbstractPolicy>,
 }
 
 #[derive(Arbitrary, Debug, PartialEq, Eq, Clone)]
 enum AbstractPolicy {
     /// Permit policy that evaluates 'true'
     PermitTrue,
     /// Permit policy that evaluates 'false'
     PermitFalse,
     /// Permit policy that errors
     PermitError,
     /// Forbid policy that evaluates 'true'
     ForbidTrue,
     /// Forbid policy that evaluates 'false'
     ForbidFalse,
     /// Forbid policy that evaluates 'error'
     ForbidError,
 }
 
 impl AbstractPolicy {
     fn into_policy(self, id: String) -> ast::StaticPolicy {
         match self {
             AbstractPolicy::PermitTrue => {
                 parser::parse_policy(Some(id), "permit(principal, action, resource);")
                     .expect("should be a valid policy")
             }
             AbstractPolicy::PermitFalse => parser::parse_policy(
                 Some(id),
                 "permit(principal, action, resource) when { 1 == 0 };",
             )
             .expect("should be a valid policy"),
             AbstractPolicy::PermitError => parser::parse_policy(
                 Some(id),
                 "permit(principal, action, resource) when { 1 < \"hello\" };",
             )
             .expect("should be a valid policy"),
             AbstractPolicy::ForbidTrue => {
                 parser::parse_policy(Some(id), "forbid(principal, action, resource);")
                     .expect("should be a valid policy")
             }
             AbstractPolicy::ForbidFalse => parser::parse_policy(
                 Some(id),
                 "forbid(principal, action, resource) when { 1 == 0 };",
             )
             .expect("should be a valid policy"),
             AbstractPolicy::ForbidError => parser::parse_policy(
                 Some(id),
                 "forbid(principal, action, resource) when { 1 < \"hello\" };",
             )
             .expect("should be a valid policy"),
         }
     }
 }

 // This fuzz target is for differential-testing the `is_authorized()`
 // functionality _assuming the correctness of the evaluator_.  We use only
 // trivial policies and requests, and focus on how the authorizer combines the
 // results.

 #[test]
 #[cfg_attr(kani, kani::proof)]
 #[cfg_attr(kani, kani::unwind(5))]
pub fn check_rbac() {
    bolero::check!()
     .with_arbitrary::<AuthorizerInputAbstractEvaluator>()
     .cloned()
     .for_each(|input: AuthorizerInputAbstractEvaluator| {
        let entities = Entities::new();
        let authorizer = Authorizer::new();
        let q = parser::parse_request(
            "User::\"alice\"",
            "Action::\"read\"",
            "Resource::\"foo\"",
            serde_json::Value::Object(serde_json::Map::new()),
        )
        .expect("should be a valid request");
        
        let policies = input
            .policies
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, p)| p.into_policy(format!("policy{i}")));
        let mut policyset = ast::PolicySet::new();
        for policy in policies {
            policyset.add_static(policy).unwrap();
        }
        assert_eq!(policyset.policies().count(), input.policies.len());
        let rust_res = authorizer.is_authorized(&q, &policyset, &entities);
    
        // check property: there should be an error reported iff we had either PermitError or ForbidError
        let should_error = input
            .policies
            .iter()
            .any(|p| p == &AbstractPolicy::PermitError || p == &AbstractPolicy::ForbidError);
        if should_error {
            assert!(!rust_res.diagnostics.errors.is_empty());
        } else {
            // doing the assertion this way, rather than assert!(.is_empty()), gives
            // us a better assertion-failure message (showing what items were
            // present on the LHS)
            assert_eq!(rust_res.diagnostics.errors, Vec::<String>::new());
        }
    
        // TODO: add code to run the definitional engine

        //  // check agreement with definitional engine
        //  // for now, we expect never to receive errors from the definitional engine,
        //  // and we otherwise ignore errors in the comparison
        //  let definitional_engine =
        //      DefinitionalEngine::new().expect("failed to create definitional engine");
        //  let definitional_res = definitional_engine.is_authorized(&q, &policyset, &entities);
        //  assert_eq!(definitional_res.diagnostics.errors, Vec::<String>::new());
        //  let rust_res_for_comparison = Response {
        //      diagnostics: Diagnostics {
        //          errors: Vec::new(),
        //          ..rust_res.diagnostics
        //      },
        //      ..rust_res
        //  };
        //  assert_eq!(
        //      rust_res_for_comparison, definitional_res,
        //      "Mismatch for {q}\nPolicies:\n{}\nEntities:\n{}",
        //      &policyset, &entities
        //  );
    });
}
