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

//! Tests SymCC on policy sets from the cedar-examples repo.

mod utils;

use cedar_policy::{PolicySet, Validator};
use cedar_policy_symcc::{solver::LocalSolver, CedarSymCompiler};
use rstest::rstest;

use crate::utils::{
    assert_always_allows_ok, assert_always_denies_ok, assert_disjoint_ok, assert_equivalent,
    assert_equivalent_ok, assert_implies, assert_implies_ok, assert_never_errors_ok, Environments,
    Pathway,
};

#[rstest]
#[case::document_cloud(
    include_str!("data/cedar-examples/document_cloud/policies.cedar"),
    include_str!("data/cedar-examples/document_cloud/policies.cedarschema"),
)]
#[case::github_example(
    include_str!("data/cedar-examples/github_example/policies.cedar"),
    include_str!("data/cedar-examples/github_example/policies.cedarschema"),
)]
#[case::hotel_chains(
    include_str!("data/cedar-examples/hotel_chains/policies.cedar"),
    include_str!("data/cedar-examples/hotel_chains/policies.cedarschema"),
)]
#[case::sales_orgs(
    include_str!("data/cedar-examples/sales_orgs/policies.cedar"),
    include_str!("data/cedar-examples/sales_orgs/policies.cedarschema"),
)]
#[case::streaming_service(
    include_str!("data/cedar-examples/streaming_service/policies.cedar"),
    include_str!("data/cedar-examples/streaming_service/policies.cedarschema"),
)]
#[case::tags_n_roles(
    include_str!("data/cedar-examples/tags_n_roles/policies.cedar"),
    include_str!("data/cedar-examples/tags_n_roles/policies.cedarschema"),
)]
#[case::tax_preparer(
    include_str!("data/cedar-examples/tax_preparer/policies.cedar"),
    include_str!("data/cedar-examples/tax_preparer/policies.cedarschema"),
)]
#[case::tinytodo(
    include_str!("data/cedar-examples/tinytodo/policies.cedar"),
    include_str!("data/cedar-examples/tinytodo/policies.cedarschema"),
)]
#[tokio::test]
async fn test_cedar_examples(#[case] policy_set_src: &str, #[case] schema_src: &str) {
    let schema = utils::schema_from_cedarstr(schema_src);
    let validator = Validator::new(schema.clone());
    let pset = utils::pset_from_text(policy_set_src, &validator);
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::get_all_from_schema(validator.schema());

    for env in &envs {
        // Sanity checks to make sure various verification tasks do not error
        // and produce valid counterexamples if they exist.

        assert_always_allows_ok(&mut compiler, &pset, env, Pathway::Both).await;
        assert_always_denies_ok(&mut compiler, &pset, env, Pathway::Both).await;
        assert_implies(&mut compiler, &pset, &pset, env).await;
        assert_equivalent(&mut compiler, &pset, &pset, env).await;

        for policy1 in pset.policies() {
            let pset1 = PolicySet::from_policies(std::iter::once(policy1.clone())).unwrap();
            assert_never_errors_ok(&mut compiler, &policy1, env, Pathway::Both).await;
            assert_always_allows_ok(&mut compiler, &pset1, env, Pathway::Both).await;
            assert_always_denies_ok(&mut compiler, &pset1, env, Pathway::Both).await;
            assert_implies(&mut compiler, &pset1, &pset1, env).await;
            assert_equivalent(&mut compiler, &pset1, &pset1, env).await;

            for policy2 in pset.policies() {
                let pset2 = PolicySet::from_policies(std::iter::once(policy2.clone())).unwrap();
                assert_implies_ok(&mut compiler, &pset1, &pset2, env, Pathway::Both).await;
                assert_equivalent_ok(&mut compiler, &pset1, &pset2, env, Pathway::Both).await;
                assert_disjoint_ok(&mut compiler, &pset1, &pset2, env, Pathway::Both).await;
            }
        }
    }
}
