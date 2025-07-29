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
use cedar_policy::{Authorizer, Decision, Policy, PolicySet, Schema, Validator};
use cedar_policy_symcc::{
    solver::{LocalSolver, Solver},
    CedarSymCompiler, WellTypedPolicies, WellTypedPolicy,
};

mod utils;
use utils::Environments;

fn sample_schema() -> Schema {
    utils::schema_from_cedarstr(
        r#"
        entity Account;
        entity Identity {
            account: Account
        };
        entity Thing in Account {
            owner: Identity,
            description: String,
            private: Bool
        };
        action view appliesTo {
          principal: [Identity],
          resource: [Thing],
          context: {
            n1: String
          }
        };
    "#,
    )
}

fn envs_for_sample_schema(schema: &Schema) -> Environments<'_> {
    Environments::new(schema, "Identity", "Action::\"view\"", "Thing")
}

fn action_groups_schema() -> Schema {
    utils::schema_from_cedarstr(
        r#"
        entity P, R;
        action Group1, Group2;
        action Group3 in Group1;
        action view in Group3 appliesTo {
            principal: [P],
            resource: [R]
        };
    "#,
    )
}

fn attributes_schema() -> Schema {
    utils::schema_from_cedarstr(
        r#"
        entity User in User;
        entity Dept in Dept;
        action view appliesTo {
            principal: [User],
            resource: [Dept],
            context: {
                s1: String,
                n1: Long,
                n2: Long,
                n3: Long,
                ns: Set<Long>,
                dept: Dept,
                dept1: Dept,
                dept2: Dept,
                dept3: Dept,
                depts: Set<Dept>,
                depts1: Set<Dept>,
                depts2: Set<Dept>
            }
        };
    "#,
    )
}

fn pset_empty() -> PolicySet {
    PolicySet::new()
}

fn pset_permit_all(validator: &Validator) -> PolicySet {
    utils::pset_from_text("permit(principal, action, resource);", validator)
}

fn policy_permit_all(validator: &Validator) -> Policy {
    utils::policy_from_text(
        "permit_all",
        "permit(principal, action, resource);",
        validator,
    )
}

async fn assert_never_errors<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    policy: &Policy,
    envs: &Environments<'_>,
) {
    let policy = WellTypedPolicy::from_policy(policy, &envs.req_env, envs.schema).unwrap();
    match compiler.check_never_errors(&policy, &envs.symenv).await {
        Ok(true) => (),
        Ok(false) => panic!("assert_never_errors failed for:\n{policy}"),
        Err(e) => panic!("{e}"),
    }
    assert!(
        compiler.check_never_errors_with_counterexample(&policy, &envs.symenv).await.unwrap().is_none(),
        "check_never_errors is true, but check_never_errors_with_counterexample returned a counterexample",
    );
}

async fn assert_always_allows<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) {
    let pset = WellTypedPolicies::from_policies(pset, &envs.req_env, envs.schema).unwrap();
    match compiler.check_always_allows(&pset, &envs.symenv).await {
        Ok(true) => (),
        Ok(false) => panic!("assert_always_allows failed for:\n{pset}"),
        Err(e) => panic!("{e}"),
    }
    assert!(
        compiler.check_always_allows_with_counterexample(&pset, &envs.symenv).await.unwrap().is_none(),
        "check_always_allows is true, but check_always_allows_with_counterexample returned a counterexample",
    );
}

async fn assert_does_not_always_allow<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) {
    let typed_pset = WellTypedPolicies::from_policies(pset, &envs.req_env, envs.schema).unwrap();
    match compiler.check_always_allows(&typed_pset, &envs.symenv).await {
        Ok(true) => panic!("assert_does_not_always_allow failed for:\n{pset}"),
        Ok(false) => (),
        Err(e) => panic!("{e}"),
    }
    match compiler.check_always_allows_with_counterexample(&typed_pset, &envs.symenv).await.unwrap() {
        Some((request, entities)) => {
            // Check that the counterexample is correct
            let resp1 = Authorizer::new().is_authorized(&request, pset, &entities);
            assert!(resp1.decision() == Decision::Deny,
                "check_always_allows_with_counterexample returned an invalid counterexample");
        }
        _ => panic!("check_always_allows is false, but check_always_allows_with_counterexample returned no counterexample"),
    }
}

async fn assert_always_denies<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) {
    let pset = WellTypedPolicies::from_policies(pset, &envs.req_env, envs.schema).unwrap();
    match compiler.check_always_denies(&pset, &envs.symenv).await {
        Ok(true) => (),
        Ok(false) => panic!("assert_always_denies failed for:\n{pset}"),
        Err(e) => panic!("{e}"),
    }
    assert!(
        compiler.check_always_denies_with_counterexample(&pset, &envs.symenv).await.unwrap().is_none(),
        "check_always_denies is true, but check_always_denies_with_counterexample returned a counterexample",
    );
}

async fn assert_does_not_always_deny<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset: &PolicySet,
    envs: &Environments<'_>,
) {
    let typed_pset = WellTypedPolicies::from_policies(pset, &envs.req_env, envs.schema).unwrap();
    match compiler.check_always_denies(&typed_pset, &envs.symenv).await {
        Ok(true) => panic!("assert_does_not_always_deny failed for:\n{pset}"),
        Ok(false) => (),
        Err(e) => panic!("{e}"),
    }
    println!("{}", typed_pset);
    match compiler.check_always_denies_with_counterexample(&typed_pset, &envs.symenv).await.unwrap() {
        Some((request, entities)) => {
            // Check that the counterexample is correct
            let resp1 = Authorizer::new().is_authorized(&request, pset, &entities);
            eprintln!("{request} {}: {resp1:?}", entities.as_ref().to_json_value().unwrap());
            assert!(resp1.decision() == Decision::Allow,
                "check_always_denies_with_counterexample returned an invalid counterexample");
        }
        _ => panic!("check_always_denies is false, but check_always_denies_with_counterexample returned no counterexample"),
    }
}

async fn assert_equivalent<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    let pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    match compiler
        .check_equivalent(&pset1, &pset2, &envs.symenv)
        .await
    {
        Ok(true) => (),
        Ok(false) => panic!("assert_equivalent failed for:\n{pset1}\n{pset2}"),
        Err(e) => panic!("{e}"),
    }
    assert!(
        compiler.check_equivalent_with_counterexample(&pset1, &pset2, &envs.symenv).await.unwrap().is_none(),
        "check_equivalent is true, but check_equivalent_with_counterexample returned a counterexample",
    );
}

async fn assert_not_equivalent<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    let typed_pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let typed_pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    match compiler
        .check_equivalent(&typed_pset1, &typed_pset2, &envs.symenv)
        .await
    {
        Ok(true) => panic!("assert_not_equivalent failed for:\n{pset1}\n{pset2}"),
        Ok(false) => (),
        Err(e) => panic!("{e}"),
    }
    match compiler.check_equivalent_with_counterexample(&typed_pset1, &typed_pset2, &envs.symenv).await.unwrap() {
        Some((request, entities)) => {
            // Check that the counterexample is correct
            let resp1 = Authorizer::new().is_authorized(&request, pset1, &entities);
            let resp2 = Authorizer::new().is_authorized(&request, pset2, &entities);
            assert!(resp1.decision() != resp2.decision(),
                "check_equivalent_with_counterexample returned an invalid counterexample");
        }
        _ => panic!("check_equivalent is false, but check_equivalent_with_counterexample returned no counterexample"),
    }
}

async fn assert_implies<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    let pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    match compiler.check_implies(&pset1, &pset2, &envs.symenv).await {
        Ok(true) => (),
        Ok(false) => panic!("assert_implies failed for:\n{pset1}\n{pset2}"),
        Err(e) => panic!("{e}"),
    }
    assert!(
        compiler.check_implies_with_counterexample(&pset1, &pset2, &envs.symenv).await.unwrap().is_none(),
        "check_implies is true, but check_implies_with_counterexample returned a counterexample",
    );
}

async fn assert_does_not_imply<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    let typed_pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let typed_pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    match compiler.check_implies(&typed_pset1, &typed_pset2, &envs.symenv).await {
        Ok(true) => panic!("assert_does_not_imply failed for:\n{pset1}\n{pset2}"),
        Ok(false) => (),
        Err(e) => panic!("{e}"),
    }
    match compiler.check_implies_with_counterexample(&typed_pset1, &typed_pset2, &envs.symenv).await.unwrap() {
        Some((request, entities)) => {
            // Check that the counterexample is correct
            let resp1 = Authorizer::new().is_authorized(&request, pset1, &entities);
            let resp2 = Authorizer::new().is_authorized(&request, pset2, &entities);
            assert!(resp1.decision() == Decision::Allow && resp2.decision() == Decision::Deny,
                "check_implies_with_counterexample returned an invalid counterexample");
        }
        _ => panic!("check_implies is false, but check_implies_with_counterexample returned no counterexample"),
    }
}

async fn assert_disjoint<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    let pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    match compiler.check_disjoint(&pset1, &pset2, &envs.symenv).await {
        Ok(true) => (),
        Ok(false) => panic!("assert_disjoint failed for:\n{pset1}\n{pset2}"),
        Err(e) => panic!("{e}"),
    }
    assert!(
        compiler.check_disjoint_with_counterexample(&pset1, &pset2, &envs.symenv).await.unwrap().is_none(),
        "check_disjoint is true, but check_disjoint_with_counterexample returned a counterexample",
    );
}

async fn assert_not_disjoint<S: Solver>(
    compiler: &mut CedarSymCompiler<S>,
    pset1: &PolicySet,
    pset2: &PolicySet,
    envs: &Environments<'_>,
) {
    let typed_pset1 = WellTypedPolicies::from_policies(pset1, &envs.req_env, envs.schema).unwrap();
    let typed_pset2 = WellTypedPolicies::from_policies(pset2, &envs.req_env, envs.schema).unwrap();
    match compiler.check_disjoint(&typed_pset1, &typed_pset2, &envs.symenv).await {
        Ok(true) => panic!("assert_not_disjoint failed for:\n{pset1}\n{pset2}"),
        Ok(false) => (),
        Err(e) => panic!("{e}"),
    }
    match compiler.check_disjoint_with_counterexample(&typed_pset1, &typed_pset2, &envs.symenv).await.unwrap() {
        Some((request, entities)) => {
            // Check that the counterexample is correct
            let resp1 = Authorizer::new().is_authorized(&request, pset1, &entities);
            let resp2 = Authorizer::new().is_authorized(&request, pset2, &entities);
            assert!(resp1.decision() == Decision::Allow && resp2.decision() == Decision::Allow,
                "check_disjoint_with_counterexample returned an invalid counterexample");
        }
        _ => panic!("check_disjoint is false, but check_disjoint_with_counterexample returned no counterexample"),
    }
}

/// analysis results about the trivial permit-all policy
#[tokio::test]
async fn simplest_permit() {
    let validator = Validator::new(sample_schema());
    let policy = policy_permit_all(&validator);
    let pset = pset_permit_all(&validator);

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = envs_for_sample_schema(validator.schema());

    assert_never_errors(&mut compiler, &policy, &envs).await;
    assert_always_allows(&mut compiler, &pset, &envs).await;
    assert_does_not_always_deny(&mut compiler, &pset, &envs).await;
    assert_equivalent(&mut compiler, &pset, &pset, &envs).await;
    assert_not_disjoint(&mut compiler, &pset, &pset, &envs).await;
    assert_implies(&mut compiler, &pset, &pset, &envs).await;
}

/// a vacuous permit (that can never fire) is equivalent to an empty policy set,
/// or to a policy set that forbids-all
#[tokio::test]
async fn vacuous() {
    let validator = Validator::new(sample_schema());
    let pset_forbid_all = utils::pset_from_text(
        r#"
        forbid(principal, action, resource);
    "#,
        &validator,
    );

    let psets_vacuous = [
        utils::pset_from_text(
            r#"
            permit(principal, action, resource)
            when {
                context.n1 != "a" &&
                context.n1 like "a"
            };
        "#,
            &validator,
        ),
        utils::pset_from_text(
            r#"
            permit(principal, action, resource)
            when {
                {a : true} has b
            };
        "#,
            &validator,
        ),
        // a single forbid with no permits
        utils::pset_from_text(
            r#"
            forbid(principal, action, resource)
            when {
                resource in Account::"mine"
            };
        "#,
            &validator,
        ),
        // less-trivially the case that this one is vacuous
        utils::pset_from_text(
            r#"
            permit(principal, action, resource)
            when {
                if resource.owner == principal then
                    principal != resource.owner
                else
                    !(context has n1)
            };
        "#,
            &validator,
        ),
        // this one is vacuous because `principal` and `resource` must be
        // different types. (Note that this policy does validate, because Cedar
        // `==` does not require its arguments to be the same type)
        utils::pset_from_text(
            r#"
            permit(principal, action, resource)
            when {
                principal == resource
            };
        "#,
            &validator,
        ),
    ];

    let psets_not_vacuous = [
        utils::pset_from_text(
            r#"
            permit(principal, action, resource)
            when {
                context.n1 != "a"
            };
        "#,
            &validator,
        ),
        utils::pset_from_text(
            r#"
            permit(principal, action, resource)
            when {
                context.n1 == resource.description
            };
        "#,
            &validator,
        ),
        utils::pset_from_text(
            r#"
            permit(
                principal,
                action == Action::"view",
                resource in Account::"mine"
            );
        "#,
            &validator,
        ),
    ];

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = envs_for_sample_schema(validator.schema());

    assert_always_denies(&mut compiler, &pset_empty(), &envs).await;
    assert_always_denies(&mut compiler, &pset_forbid_all, &envs).await;

    for pset in psets_vacuous {
        assert_does_not_always_allow(&mut compiler, &pset, &envs).await;
        assert_always_denies(&mut compiler, &pset, &envs).await;
        assert_equivalent(&mut compiler, &pset, &pset_empty(), &envs).await;
        assert_equivalent(&mut compiler, &pset, &pset_forbid_all, &envs).await;
        assert_implies(&mut compiler, &pset, &pset_empty(), &envs).await;
        assert_implies(&mut compiler, &pset, &pset_forbid_all, &envs).await;
    }

    for pset in psets_not_vacuous {
        assert_does_not_always_allow(&mut compiler, &pset, &envs).await;
        assert_does_not_always_deny(&mut compiler, &pset, &envs).await;
        assert_not_equivalent(&mut compiler, &pset, &pset_empty(), &envs).await;
    }
}

/// analysis results about some nontrivial permit policies
#[tokio::test]
async fn nontrivial_permit() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 != "a"
        };
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 != "a" && context.n1 != "b"
        };
    "#,
        &validator,
    );
    let pset_permit_all = pset_permit_all(&validator);

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = envs_for_sample_schema(validator.schema());

    assert_does_not_always_allow(&mut compiler, &pset1, &envs).await;
    assert_does_not_always_allow(&mut compiler, &pset2, &envs).await;
    assert_does_not_always_deny(&mut compiler, &pset1, &envs).await;
    assert_does_not_always_deny(&mut compiler, &pset2, &envs).await;
    assert_equivalent(&mut compiler, &pset1, &pset1, &envs).await;
    assert_not_equivalent(&mut compiler, &pset1, &pset2, &envs).await;
    assert_not_equivalent(&mut compiler, &pset1, &pset_empty(), &envs).await;
    assert_not_equivalent(&mut compiler, &pset1, &pset_permit_all, &envs).await;
    assert_does_not_imply(&mut compiler, &pset1, &pset2, &envs).await;
    assert_implies(&mut compiler, &pset2, &pset1, &envs).await;
    assert_does_not_imply(&mut compiler, &pset1, &pset_empty(), &envs).await;
    assert_does_not_imply(&mut compiler, &pset2, &pset_empty(), &envs).await;
    assert_implies(&mut compiler, &pset_empty(), &pset1, &envs).await;
    assert_implies(&mut compiler, &pset_empty(), &pset2, &envs).await;
    assert_implies(&mut compiler, &pset1, &pset_permit_all, &envs).await;
    assert_implies(&mut compiler, &pset2, &pset_permit_all, &envs).await;
    assert_does_not_imply(&mut compiler, &pset_permit_all, &pset1, &envs).await;
    assert_does_not_imply(&mut compiler, &pset_permit_all, &pset2, &envs).await;
    assert_not_disjoint(&mut compiler, &pset1, &pset2, &envs).await;
    assert_disjoint(&mut compiler, &pset1, &pset_empty(), &envs).await;
}

/// analysis results about a multi-policy set
#[tokio::test]
async fn multi_policy_set() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "a*"
        };
        permit(principal, action, resource)
        when {
            context.n1 like "b*"
        };
        forbid(principal, action, resource)
        when {
            context.n1 like "bc*"
        };
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "ab*"
        };
        permit(principal, action, resource)
        when {
            context.n1 like "bd*"
        };
    "#,
        &validator,
    );
    let pset_permit_all = pset_permit_all(&validator);

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = envs_for_sample_schema(validator.schema());

    assert_does_not_always_allow(&mut compiler, &pset1, &envs).await;
    assert_does_not_always_allow(&mut compiler, &pset2, &envs).await;
    assert_does_not_always_deny(&mut compiler, &pset1, &envs).await;
    assert_does_not_always_deny(&mut compiler, &pset2, &envs).await;
    assert_equivalent(&mut compiler, &pset1, &pset1, &envs).await;
    assert_equivalent(&mut compiler, &pset2, &pset2, &envs).await;
    assert_not_equivalent(&mut compiler, &pset1, &pset2, &envs).await;
    assert_not_disjoint(&mut compiler, &pset1, &pset2, &envs).await;
    assert_does_not_imply(&mut compiler, &pset1, &pset2, &envs).await;
    assert_implies(&mut compiler, &pset2, &pset1, &envs).await;
    assert_does_not_imply(&mut compiler, &pset1, &pset_empty(), &envs).await;
    assert_does_not_imply(&mut compiler, &pset_permit_all, &pset1, &envs).await;
}

/// analysis results using scopes and entities (RBAC policies)
#[tokio::test]
async fn scopes_and_entities_rbac() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(
            principal == Identity::"raymond",
            action,
            resource
        );
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(
            principal,
            action,
            resource == Thing::"widget"
        );
    "#,
        &validator,
    );
    let pset3 = utils::pset_from_text(
        r#"
        permit(
            principal == Identity::"raymond",
            action,
            resource == Thing::"widget"
        );
    "#,
        &validator,
    );
    let pset4 = utils::pset_from_text(
        r#"
        permit(
            principal,
            action,
            resource in Account::"mine"
        );
    "#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = envs_for_sample_schema(validator.schema());

    assert_implies(&mut compiler, &pset3, &pset1, &envs).await;
    assert_implies(&mut compiler, &pset3, &pset2, &envs).await;
    assert_does_not_imply(&mut compiler, &pset1, &pset2, &envs).await;
    assert_does_not_imply(&mut compiler, &pset1, &pset3, &envs).await;
    assert_does_not_imply(&mut compiler, &pset1, &pset4, &envs).await;
    assert_does_not_imply(&mut compiler, &pset2, &pset4, &envs).await;
    assert_does_not_imply(&mut compiler, &pset4, &pset2, &envs).await;
}

/// analysis results about globs
#[tokio::test]
async fn globs() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "a*"
        };
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "a**"
        };
    "#,
        &validator,
    );
    let pset3 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "aa*"
        };
    "#,
        &validator,
    );
    let pset4 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 != "a" && context.n1 like "a*"
        };
    "#,
        &validator,
    );
    let pset5 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "*a"
        };
    "#,
        &validator,
    );
    let pset6 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "*b"
        };
    "#,
        &validator,
    );
    let pset7 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "*a" && context.n1 like "*b"
        };
    "#,
        &validator,
    );
    let pset8 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 != "a*Cd" && context.n1 like "a\*Cd"
        };
    "#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = envs_for_sample_schema(validator.schema());

    assert_equivalent(&mut compiler, &pset1, &pset2, &envs).await;
    assert_not_equivalent(&mut compiler, &pset1, &pset3, &envs).await;
    assert_not_equivalent(&mut compiler, &pset1, &pset4, &envs).await;
    assert_not_equivalent(&mut compiler, &pset1, &pset5, &envs).await;
    assert_implies(&mut compiler, &pset3, &pset1, &envs).await;
    assert_implies(&mut compiler, &pset4, &pset1, &envs).await;
    assert_implies(&mut compiler, &pset3, &pset4, &envs).await;
    assert_does_not_imply(&mut compiler, &pset4, &pset3, &envs).await;
    assert_does_not_imply(&mut compiler, &pset1, &pset5, &envs).await;
    assert_does_not_imply(&mut compiler, &pset5, &pset1, &envs).await;
    assert_not_disjoint(&mut compiler, &pset1, &pset3, &envs).await;
    assert_disjoint(&mut compiler, &pset5, &pset6, &envs).await;
    assert_always_denies(&mut compiler, &pset7, &envs).await;
    assert_always_denies(&mut compiler, &pset8, &envs).await;
}

/// policy sets where the forbid totally overrides the permit
#[tokio::test]
async fn forbid_overrides_permit() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "aa*"
        };
        forbid(principal, action, resource)
        when {
            context.n1 like "a*"
        };
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(
            principal == Identity::"jane",
            action,
            resource == Thing::"box"
        ) when {
            !(resource in Identity::"jane".account)
        };
        forbid(principal, action, resource)
        when {
            !(resource in principal.account)
        };
        "#,
        &validator,
    );
    let pset_empty = PolicySet::new();

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = envs_for_sample_schema(validator.schema());

    assert_always_denies(&mut compiler, &pset1, &envs).await;
    assert_equivalent(&mut compiler, &pset1, &pset_empty, &envs).await;
    assert_always_denies(&mut compiler, &pset2, &envs).await;
    assert_equivalent(&mut compiler, &pset2, &pset_empty, &envs).await;
}

/// policy sets where the forbid does not totally override the permit
#[tokio::test]
async fn forbid_does_not_override_permit() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "a*"
        };
        forbid(principal, action, resource)
        when {
            context.n1 like "aa*"
        };
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "a*"
        };
    "#,
        &validator,
    );
    let pset3 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "*b"
        };
        forbid(principal, action, resource)
        when {
            context.n1 like "*bb"
        };
    "#,
        &validator,
    );
    let pset4 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "aaa*"
        };
    "#,
        &validator,
    );
    let pset_empty = PolicySet::new();

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = envs_for_sample_schema(validator.schema());

    assert_does_not_always_deny(&mut compiler, &pset1, &envs).await;
    assert_does_not_always_deny(&mut compiler, &pset3, &envs).await;
    assert_not_equivalent(&mut compiler, &pset1, &pset_empty, &envs).await;
    assert_not_equivalent(&mut compiler, &pset1, &pset2, &envs).await;
    assert_implies(&mut compiler, &pset_empty, &pset1, &envs).await;
    assert_implies(&mut compiler, &pset1, &pset2, &envs).await;
    assert_not_disjoint(&mut compiler, &pset1, &pset3, &envs).await;
    assert_disjoint(&mut compiler, &pset1, &pset4, &envs).await;
}

/// comparing policy sets with differently-permissive forbids
#[tokio::test]
async fn psets_with_different_forbids() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "a*"
        };
        permit(principal, action, resource)
        when {
            context.n1 like "b*"
        };
        forbid(principal, action, resource)
        when {
            context.n1 like "bb*"
        };
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "a*"
        };
        permit(principal, action, resource)
        when {
            context.n1 like "b*"
        };
        forbid(principal, action, resource)
        when {
            context.n1 like "bbb*"
        };
    "#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = envs_for_sample_schema(validator.schema());

    assert_not_equivalent(&mut compiler, &pset1, &pset2, &envs).await;
    assert_implies(&mut compiler, &pset1, &pset2, &envs).await;
}

/// these two policies are equivalent in this `symenv`
#[tokio::test]
async fn equivalent_specifying_action() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "a*"
        };
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action == Action::"view", resource)
        when {
            context.n1 like "a*"
        };
    "#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = envs_for_sample_schema(validator.schema());

    assert_equivalent(&mut compiler, &pset1, &pset2, &envs).await;
}

/// policysets with the same policies in a different order are equivalent
#[tokio::test]
async fn equivalent_different_order() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "a*"
        };
        permit(principal, action, resource)
        when {
            context.n1 like "b*"
        };
        permit(
            principal == Identity::"jane",
            action,
            resource == Thing::"box"
        );
        forbid(principal, action, resource == Thing::"box")
        when {
            context.n1 like "b*"
        };
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(
            principal == Identity::"jane",
            action,
            resource == Thing::"box"
        );
        forbid(principal, action, resource == Thing::"box")
        when {
            context.n1 like "b*"
        };
        permit(principal, action, resource)
        when {
            context.n1 like "b*"
        };
        permit(principal, action, resource)
        when {
            context.n1 like "a*"
        };
    "#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = envs_for_sample_schema(validator.schema());

    assert_equivalent(&mut compiler, &pset1, &pset2, &envs).await;
}

/// Comparing a policyset, to the same policyset with another permit added, or
/// the same policyset with another forbid added
#[tokio::test]
async fn add_permit_or_forbid() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "a*"
        };
        permit(principal, action, resource)
        when {
            context.n1 like "b*"
        };
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "a*"
        };
        permit(principal, action, resource)
        when {
            context.n1 like "b*"
        };
        permit(principal, action, resource)
        when {
            context.n1 like "*def"
        };
    "#,
        &validator,
    );
    let pset3 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.n1 like "a*"
        };
        permit(principal, action, resource)
        when {
            context.n1 like "b*"
        };
        forbid(principal, action, resource)
        when {
            context.n1 like "*def"
        };
    "#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = envs_for_sample_schema(validator.schema());

    assert_implies(&mut compiler, &pset1, &pset2, &envs).await;
    assert_implies(&mut compiler, &pset3, &pset1, &envs).await;
    assert_not_equivalent(&mut compiler, &pset1, &pset2, &envs).await;
    assert_not_equivalent(&mut compiler, &pset1, &pset3, &envs).await;
}

/// Two policies that are equivalent to a single policy
#[tokio::test]
async fn two_policies_equivalent_to_one() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal == resource.owner || (
            (context.n1 like "*.png" || context.n1 like "*.jpg")
            && !resource.private
            )
        };
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal == resource.owner
        };
        permit(principal, action, resource)
        when {
            context.n1 like "*.png" || context.n1 like "*.jpg"
        } unless {
            resource.private
        };
    "#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = envs_for_sample_schema(validator.schema());

    assert_equivalent(&mut compiler, &pset1, &pset2, &envs).await;
}

/// Tests involving action groups
#[tokio::test]
async fn action_groups() {
    let validator = Validator::new(action_groups_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            Action::"view" in Action::"Group1"
        };
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            Action::"view" in Action::"Group2"
        };
    "#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::new(validator.schema(), "P", "Action::\"view\"", "R");

    // Analysis should identify this policy is always-true
    // because of the transitive action-group-membership in the schema
    assert_always_allows(&mut compiler, &pset1, &envs).await;
    // Analysis should identify this policy is always-false
    // because the action is not in the action-group in the schema
    assert_always_denies(&mut compiler, &pset2, &envs).await;
}

/// Some regression tests from previous iterations of CedarSymCompiler
#[tokio::test]
async fn historical_regression_tests() {
    let schema = utils::schema_from_cedarstr(
        r#"
        entity a {
            my_set: Set<String>
        };
        action action appliesTo {
            principal: [a],
            resource: [a]
        };
    "#,
    );
    let validator = Validator::new(schema);
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            true && (a::"" in [resource, resource, principal])
        };
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            [a::"A"["my_set"]].containsAll([a::"B"["my_set"]])
        };
    "#,
        &validator,
    );
    let pset3 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            [a::"A"["my_set"]].containsAny([a::"B"["my_set"]])
        };
    "#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::new(validator.schema(), "a", "Action::\"action\"", "a");

    assert_does_not_always_allow(&mut compiler, &pset1, &envs).await;
    assert_does_not_always_deny(&mut compiler, &pset1, &envs).await;
    assert_does_not_always_allow(&mut compiler, &pset2, &envs).await;
    assert_does_not_always_deny(&mut compiler, &pset2, &envs).await;
    // assert_does_not_always_allow(&mut compiler, &pset3, &envs).await;
    // assert_does_not_always_deny(&mut compiler, &pset3, &envs).await;
}

/// Regression test for a bug discovered 2025-03-24.
/// (The bug resulted in a solver error, not a wrong result)
#[tokio::test]
async fn regression_test_2025_03_24() {
    let schema = utils::schema_from_cedarstr(
        r#"
        entity Account;
        entity User {
            account: Account
        };
        entity Thing, Box in [Box, Account] {
            owner: User,
            description: String,
            private: Bool
        };
        action view appliesTo {
          principal: [User],
          resource: [Thing, Box],
          context: {
            n1: String
          }
        };
    "#,
    );
    let validator = Validator::new(schema);
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal == User::"amelia", action, resource);
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource == Thing::"widget");
    "#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::new(validator.schema(), "User", "Action::\"view\"", "Box");

    assert_does_not_imply(&mut compiler, &pset1, &pset2, &envs).await;
}

/// Test with a larger policy and schema
#[tokio::test]
async fn larger_policy_and_schema() {
    let schema = utils::schema_from_cedarstr(
        r#"
        entity User in UserGroup {
            department: String,
            jobLevel: Long
        };
        entity UserGroup, Administrator;
        entity Photo in [Account, Album] {
            private: Bool,
            account: Account,
            admins: Set<User>
        };
        entity Album in [Account, Album] {
            private: Bool,
            account: Account,
            admins: Set<User>
        };
        entity Account {
            private: Bool,
            owner: User,
            admins: Set<User>
        };
        entity AccountGroup {
            owner: User
        };
        action view, comment, edit, delete appliesTo {
            principal: [User],
            resource: [Photo],
            context: {
                authenticated: Bool
            }
        };
        action listAlbums appliesTo {
            principal: [User],
            resource: [Account],
            context: {
                authenticated: Bool
            }
        };
        action listPhotos appliesTo {
            principal: [User],
            resource: [Album],
            context: {
                authenticated: Bool
            }
        };
        action addPhoto appliesTo {
            principal: [User],
            resource: [Album],
            context: {
                authenticated: Bool,
                photo: {
                    filesize_mb: Long,
                    filetype: String
                }
            }
        };
    "#,
    );
    let validator = Validator::new(schema);
    let pset1 = utils::pset_from_text(
        r#"
        permit(
            principal,
            action == Action::"addPhoto",
            resource in Account::"alice"
        )
        when {
            (["JPEG", "PNG"].contains(context.photo.filetype) &&
                context.photo.filesize_mb <= 1)
            ||
            (context.photo.filetype == "RAW" &&
                context.photo.filesize_mb <= 100 &&
                principal in UserGroup::"AVTeam")
        };
    "#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::new(validator.schema(), "User", "Action::\"addPhoto\"", "Album");

    assert_does_not_always_allow(&mut compiler, &pset1, &envs).await;
    assert_does_not_always_deny(&mut compiler, &pset1, &envs).await;
}

/// analysis results about `decimal`
#[tokio::test]
async fn decimal() {
    let schema = utils::schema_from_cedarstr(
        r#"
        entity User {
            score: decimal
        };
        entity File {
            name: String,
            owner: User,
            private: Bool,
            is_photo: Bool
        };
        action action appliesTo {
            principal: [User],
            resource: [File]
        };
    "#,
    );
    let validator = Validator::new(schema);

    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal.score.lessThan(decimal("3.14")) &&
            principal.score.greaterThan(decimal("3.14"))
        };
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal.score.lessThanOrEqual(decimal("3.14")) &&
            principal.score.greaterThanOrEqual(decimal("3.14"))
        };
    "#,
        &validator,
    );
    let pset3 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal.score == decimal("3.1400")
        };
    "#,
        &validator,
    );
    let pset4 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal.score.lessThanOrEqual(decimal("4.56")) &&
            principal.score.greaterThanOrEqual(decimal("2.34"))
        };
    "#,
        &validator,
    );
    let pset5 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal.score.lessThanOrEqual(decimal("5.67")) &&
            principal.score.greaterThanOrEqual(decimal("4.56"))
        };
    "#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::new(validator.schema(), "User", "Action::\"action\"", "File");

    assert_always_denies(&mut compiler, &pset1, &envs).await;
    assert_equivalent(&mut compiler, &pset2, &pset3, &envs).await;
    assert_not_equivalent(&mut compiler, &pset3, &pset4, &envs).await;
    assert_implies(&mut compiler, &pset3, &pset4, &envs).await;
    assert_does_not_imply(&mut compiler, &pset4, &pset5, &envs).await;
    assert_does_not_imply(&mut compiler, &pset5, &pset4, &envs).await;
    assert_not_disjoint(&mut compiler, &pset4, &pset5, &envs).await;
    assert_disjoint(&mut compiler, &pset3, &pset5, &envs).await;
}

/// Tests that the analyzer understands transitivity and `in`
#[tokio::test]
async fn transitivity_and_in() {
    let validator = Validator::new(attributes_schema());
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::new(validator.schema(), "User", "Action::\"view\"", "Dept");

    // always denies because the hierarchy is transitive
    let pset = utils::pset_from_text(
        r#"
        permit(
            principal == User::"bob",
            action,
            resource in Dept::"dept1"
        ) when {
            context.dept1 in context.dept2 &&
            context.dept2 in context.dept3 &&
            !(context.dept1 in context.dept3)
        };
    "#,
        &validator,
    );
    assert_always_denies(&mut compiler, &pset, &envs).await;

    // always allows because the hierarchy is transitive
    let pset = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            if (context.dept1 in context.dept2 && context.dept2 in context.dept3)
            then context.dept1 in context.dept3
            else 1 < 2
        };
    "#,
        &validator,
    );
    assert_always_allows(&mut compiler, &pset, &envs).await;

    // trickier example that always denies because the hierarchy is transitive
    let pset = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.dept1 in context.dept2 &&
            context.dept2 in context.depts &&
            !(context.dept1 in context.depts)
        };
    "#,
        &validator,
    );
    assert_always_denies(&mut compiler, &pset, &envs).await;

    // always allows because of how `in` is defined
    let pset = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            !context.depts.contains(context.dept1) ||
            context.dept1 in context.depts
        };
    "#,
        &validator,
    );
    assert_always_allows(&mut compiler, &pset, &envs).await;

    // pset1 implies pset2, but not vice versa, because of how `in` is defined
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource == Dept::"finance");
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource in Dept::"finance");
    "#,
        &validator,
    );
    assert_implies(&mut compiler, &pset1, &pset2, &envs).await;
    assert_does_not_imply(&mut compiler, &pset2, &pset1, &envs).await;

    // always allows because of how `in` and `containsAll` interact
    let pset = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.dept in context.depts2
        };
        permit(principal, action, resource)
        unless {
            context.depts2.containsAll(context.depts1) &&
            context.dept in context.depts1
        };
    "#,
        &validator,
    );
    assert_always_allows(&mut compiler, &pset, &envs).await;

    // always allows because of how `contains` and `containsAny` interact
    let pset = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.depts1.containsAny(context.depts2)
        };
        permit(principal, action, resource)
        unless {
            context.depts1.contains(context.dept) &&
            context.depts2.contains(context.dept)
        };
    "#,
        &validator,
    );
    assert_always_allows(&mut compiler, &pset, &envs).await;

    // always allows because the analyzer understands how get-attr and sets work
    let pset = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        unless {
            context.n1 == 1 && context.n2 == 2 && context.n3 == 3 &&
            context.ns == [context.n1, context.n2, context.n3, 3, 2, 1, context.n2]
        };
        permit(principal, action, resource)
        when {
            context.ns == [1, 2, 3]
        };
    "#,
        &validator,
    );
    assert_always_allows(&mut compiler, &pset, &envs).await;
}

/// Tests that the analyzer understands simple arithmetic
#[tokio::test]
async fn arithmetic() {
    let schema = utils::schema_from_cedarstr(
        r#"
        entity User {
            score: Long
        };
        entity File {
            score: Long
        };
        action action appliesTo {
            principal: [User],
            resource: [File],
            context: {
                score: Long
            }
        };
    "#,
    );
    let validator = Validator::new(schema);

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::new(validator.schema(), "User", "Action::\"action\"", "File");

    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal.score > 4
        };
        // to exclude overflow
        forbid(principal, action, resource)
        when {
            principal.score < -10000 ||
            resource.score < -10000 ||
            principal.score > 10000 ||
            resource.score > 10000
        };
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal.score + 2 > 6
        };
        // to exclude overflow
        forbid(principal, action, resource)
        when {
            principal.score < -10000 ||
            resource.score < -10000 ||
            principal.score > 10000 ||
            resource.score > 10000
        };
    "#,
        &validator,
    );
    assert_equivalent(&mut compiler, &pset1, &pset2, &envs).await;

    let permit_p_gt_r = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal.score > resource.score
        };
    "#,
        &validator,
    );
    let permit_r_gt_p = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            resource.score > principal.score
        };
    "#,
        &validator,
    );
    assert_disjoint(&mut compiler, &permit_p_gt_r, &permit_r_gt_p, &envs).await;

    let permit_impossible = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal.score + principal.score + principal.score + principal.score
            !=
            principal.score * 4
        };
    "#,
        &validator,
    );
    assert_always_denies(&mut compiler, &permit_impossible, &envs).await;

    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal.score + resource.score - (2 * resource.score) > context.score + 234
        };
        // to exclude overflow
        forbid(principal, action, resource)
        when {
            principal.score < -10000 ||
            resource.score < -10000 ||
            principal.score > 10000 ||
            resource.score > 10000
        };
    "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal.score - resource.score - 234 > context.score
        };
        // to exclude overflow
        forbid(principal, action, resource)
        when {
            principal.score < -10000 ||
            resource.score < -10000 ||
            principal.score > 10000 ||
            resource.score > 10000
        };
    "#,
        &validator,
    );
    assert_equivalent(&mut compiler, &pset1, &pset2, &envs).await;
}

/// Tests that the analyzer understands integer overflow
#[tokio::test]
async fn overflow() {
    let schema = utils::schema_from_cedarstr(
        r#"
        entity User {
            score: Long
        };
        entity File {
            score: Long
        };
        action action appliesTo {
            principal: [User],
            resource: [File]
        };
    "#,
    );
    let validator = Validator::new(schema);

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::new(validator.schema(), "User", "Action::\"action\"", "File");

    // neither of these imply each other:
    //   first does not allow p.score == 1, while the second does
    //   second does not allow p.score == INT_MIN (due to integer overflow), while the first does
    let permit_lt_0 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal.score < 0
        };
    "#,
        &validator,
    );
    let permit_lt_2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal.score - 2 < 0
        };
    "#,
        &validator,
    );
    assert_does_not_imply(&mut compiler, &permit_lt_0, &permit_lt_2, &envs).await;
    assert_does_not_imply(&mut compiler, &permit_lt_2, &permit_lt_0, &envs).await;

    // these should be equivalent.
    // note that if p.score == INT_MIN, the negation overflows in the second policy
    // so it does not allow, but the first policy also cannot allow, because -INT_MIN
    // is not a possible 64-bit signed value
    let permit_p_minus_r = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal.score == -resource.score
        };
    "#,
        &validator,
    );
    let permit_r_minus_p = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            resource.score == -principal.score
        };
    "#,
        &validator,
    );
    assert_equivalent(&mut compiler, &permit_p_minus_r, &permit_r_minus_p, &envs).await;

    // this should not be possible. No values other than 0 are equal to their negations,
    // in particular INT_MIN, because its negation overflows
    let permit_impossible = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            principal.score != 0 &&
            principal.score == -principal.score
        };
    "#,
        &validator,
    );
    assert_always_denies(&mut compiler, &permit_impossible, &envs).await;
}

/// Tests that involve short-circuiting (or not) for && and ||
///
/// Among other things, this is a regression test for a bug in an early version
/// of CedarSymCompiler (discovered 2025-04-25). The bug resulted in failure to
/// generate a solver query, not a wrong result. Specifically, `compile_and()`
/// was returning `false` instead of `Some(false)` in one case, and likewise
/// `compile_or()` was returning `true` instead of `Some(true)` in one case.
#[tokio::test]
async fn regression_test_and_or() {
    let schema = utils::schema_from_cedarstr(
        r#"
        entity P1, P2 in P2;
        entity R1, R2 in R2;
        action view, edit appliesTo {
            principal: [P1, P2],
            resource: [R1, R2]
        };
    "#,
    );
    let validator = Validator::new(schema);
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();

    let p1_view_r1 = Environments::new(validator.schema(), "P1", "Action::\"view\"", "R1");
    let p1_edit_r1 = Environments::new(validator.schema(), "P1", "Action::\"edit\"", "R1");
    let p1_view_r2 = Environments::new(validator.schema(), "P1", "Action::\"view\"", "R2");
    let p1_edit_r2 = Environments::new(validator.schema(), "P1", "Action::\"edit\"", "R2");
    let p2_view_r1 = Environments::new(validator.schema(), "P2", "Action::\"view\"", "R1");
    let p2_edit_r1 = Environments::new(validator.schema(), "P2", "Action::\"edit\"", "R1");
    let p2_view_r2 = Environments::new(validator.schema(), "P2", "Action::\"view\"", "R2");
    let p2_edit_r2 = Environments::new(validator.schema(), "P2", "Action::\"edit\"", "R2");

    // this policy allows nothing in any of the p2_* sigs, and some (but not
    // all) requests in each of the p1_* sigs
    let pset = utils::pset_from_text(
        r#"permit(principal == P1::"A", action, resource);"#,
        &validator,
    );
    assert_does_not_always_deny(&mut compiler, &pset, &p1_view_r1).await;
    assert_does_not_always_allow(&mut compiler, &pset, &p1_view_r1).await;
    assert_does_not_always_deny(&mut compiler, &pset, &p1_edit_r1).await;
    assert_does_not_always_allow(&mut compiler, &pset, &p1_edit_r1).await;
    assert_does_not_always_deny(&mut compiler, &pset, &p1_view_r2).await;
    assert_does_not_always_allow(&mut compiler, &pset, &p1_view_r2).await;
    assert_does_not_always_deny(&mut compiler, &pset, &p1_edit_r2).await;
    assert_does_not_always_allow(&mut compiler, &pset, &p1_edit_r2).await;
    assert_always_denies(&mut compiler, &pset, &p2_view_r1).await;
    assert_always_denies(&mut compiler, &pset, &p2_edit_r1).await;
    assert_always_denies(&mut compiler, &pset, &p2_view_r2).await;
    assert_always_denies(&mut compiler, &pset, &p2_edit_r2).await;

    // this policy allows nothing in any of the *_r1 sigs or the *_view_* sigs;
    // but it allows all requests in p1_edit_r2 and p2_edit_r2
    let pset = utils::pset_from_text(
        r#"permit(principal, action == Action::"edit", resource is R2);"#,
        &validator,
    );
    assert_always_denies(&mut compiler, &pset, &p1_view_r1).await;
    assert_always_denies(&mut compiler, &pset, &p1_edit_r1).await;
    assert_always_denies(&mut compiler, &pset, &p2_view_r1).await;
    assert_always_denies(&mut compiler, &pset, &p2_edit_r1).await;
    assert_always_denies(&mut compiler, &pset, &p1_view_r2).await;
    assert_always_denies(&mut compiler, &pset, &p2_view_r2).await;
    assert_always_allows(&mut compiler, &pset, &p1_edit_r2).await;
    assert_always_allows(&mut compiler, &pset, &p2_edit_r2).await;

    // this policy allows all requests in all of the p2_* sigs, some but not
    // all requests in the remaining *_r1 sigs, and nothing in p1_view_r2 or
    // p1_edit_r2
    let pset = utils::pset_from_text(
        r#"permit(principal, action, resource) when { principal is P2 || resource == R1::"A" };"#,
        &validator,
    );
    assert_always_allows(&mut compiler, &pset, &p2_view_r1).await;
    assert_always_allows(&mut compiler, &pset, &p2_edit_r1).await;
    assert_always_allows(&mut compiler, &pset, &p2_view_r2).await;
    assert_always_allows(&mut compiler, &pset, &p2_edit_r2).await;
    assert_does_not_always_allow(&mut compiler, &pset, &p1_view_r1).await;
    assert_does_not_always_deny(&mut compiler, &pset, &p1_view_r1).await;
    assert_does_not_always_allow(&mut compiler, &pset, &p1_edit_r1).await;
    assert_does_not_always_deny(&mut compiler, &pset, &p1_edit_r1).await;
    assert_always_denies(&mut compiler, &pset, &p1_view_r2).await;
    assert_always_denies(&mut compiler, &pset, &p1_edit_r2).await;

    // this policy allows all requests in p1_view_r1 and p1_edit_r1; some
    // requests in the p2_* sigs; and no requests in p1_view_r2 or p1_edit_r2
    let pset = utils::pset_from_text(
        r#"
        permit(principal, action, resource) when {
            (principal is P1 && resource is R1) ||
            (principal is P2 && resource in R2::"A")
        };
        "#,
        &validator,
    );
    assert_always_allows(&mut compiler, &pset, &p1_view_r1).await;
    assert_always_allows(&mut compiler, &pset, &p1_edit_r1).await;
    assert_does_not_always_allow(&mut compiler, &pset, &p2_view_r1).await;
    assert_does_not_always_allow(&mut compiler, &pset, &p2_edit_r1).await;
    assert_does_not_always_allow(&mut compiler, &pset, &p2_view_r2).await;
    assert_does_not_always_allow(&mut compiler, &pset, &p2_edit_r2).await;
    assert_always_denies(&mut compiler, &pset, &p1_view_r2).await;
    assert_always_denies(&mut compiler, &pset, &p1_edit_r2).await;
}

/// Ensure that running SymCC on the following policy post type-checking does
/// not result in a `NoSuchAttribute` error (see unit tests in tests/well_typed.rs for
/// a more detailed explanation). This test is based on a real DataZone policy.
#[tokio::test]
async fn well_typed_policy_test() {
    let schema = utils::schema_from_cedarstr(
        r#"
        entity P;
        entity R = {
            baz?: String,
        };
        type Context = {
            foo?: String,
        };
        action view appliesTo {
            principal: [P],
            resource: [R],
            context: Context
        };
        action delete appliesTo {
            principal: [P],
            resource: [R],
            context: Context
        };
    "#,
    );
    let validator = Validator::new(schema.clone());
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::new(validator.schema(), "P", "Action::\"view\"", "R");

    let policy = utils::policy_from_text(
        "policy",
        r#"permit (
            principal,
            action in [Action::"view"],
            resource)
        when
            {
            (context has foo && ["aa"].contains(context.foo) &&
            (resource has baz) &&
            ["bb"].contains(resource.baz))};"#,
        &validator,
    );
    assert_never_errors(&mut compiler, &policy, &envs).await;
    // Type-checking the second policy will return a `PolicyCheck::Irrelevant` for the given environment
    // since it does not apply to `Action::"view"`. This test ensures we still keep the first policy that
    // is valid.
    let pset = utils::pset_from_text(
        r#"
        permit(principal, action, resource);
        permit(principal, action in [Action::"delete"], resource);
        "#,
        &validator,
    );
    assert_always_allows(&mut compiler, &pset, &envs).await;
}

/// Tests that the encoding of tags is correct
#[tokio::test]
async fn tags_encoding() {
    let schema = utils::schema_from_cedarstr(
        r#"
        entity User tags Long;
        action talkTo appliesTo {
            principal: [User],
            resource: [User]
        };
    "#,
    );
    let validator = Validator::new(schema);
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::new(validator.schema(), "User", "Action::\"talkTo\"", "User");

    let pset = utils::pset_from_text(
        r#"
        permit(
            principal,
            action,
            resource
        ) when {
            principal.hasTag("a") &&
            principal.hasTag("b") &&
            principal.getTag("a") + principal.getTag("b") ==
            principal.getTag("b") + principal.getTag("a")
        };
    "#,
        &validator,
    );
    assert_does_not_always_allow(&mut compiler, &pset, &envs).await;
}

/// Tests that SMT string encoding is correct
#[tokio::test]
async fn encoder_string() {
    let validator = Validator::new(attributes_schema());
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::new(validator.schema(), "User", "Action::\"view\"", "Dept");

    // Tests that `User::"\""` is encoded correctly in SMT
    let pset = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when { principal == User::"\"" };
    "#,
        &validator,
    );
    assert_does_not_always_allow(&mut compiler, &pset, &envs).await;
}

/// Tests generation of simple models without ancestors
#[tokio::test]
async fn cex_test_simple_model() {
    let schema = utils::schema_from_cedarstr(
        r#"
        entity User;
        entity Snack {
            min_hungry_level: Long
        };
        action eat appliesTo {
            principal: [User],
            resource: [Snack],
            context: {
                hungry_level: Long,
            }
        };"#,
    );
    let validator = Validator::new(schema.clone());

    let pset = utils::pset_from_text(
        r#"permit(principal, action == Action::"eat", resource) when {
            context.hungry_level >= resource.min_hungry_level
        };
        
        forbid(principal == User::"alice", action == Action::"eat", resource);
        "#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::new(validator.schema(), "User", "Action::\"eat\"", "Snack");

    assert_does_not_always_deny(&mut compiler, &pset, &envs).await;
}

/// Tests generation of simple models with ancestors
#[tokio::test]
async fn cex_test_simple_model_ancestor() {
    let schema = utils::schema_from_cedarstr(
        r#"
        entity UserGroup;
        entity User in [UserGroup];
        entity Snack {
            min_hungry_level: Long
        };
        action eat appliesTo {
            principal: [User],
            resource: [Snack],
            context: {
                hungry_level: Long,
            }
        };"#,
    );
    let validator = Validator::new(schema.clone());

    let pset = utils::pset_from_text(
        r#"permit(principal in UserGroup::"chef", action == Action::"eat", resource) when {
            context.hungry_level >= resource.min_hungry_level
        };
        
        forbid(principal == User::"alice", action == Action::"eat", resource);
        "#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::new(validator.schema(), "User", "Action::\"eat\"", "Snack");

    assert_does_not_always_deny(&mut compiler, &pset, &envs).await;
}

/// Tests generation of simple models with tags
#[tokio::test]
async fn cex_test_simple_model_tags() {
    let schema = utils::schema_from_cedarstr(
        r#"
        entity User {
            hungry_level: Long
        } tags Bool;

        entity Snack {
            min_hungry_level: Long
        };

        action eat appliesTo {
            principal: [User],
            resource: [Snack]
        };"#,
    );
    let validator = Validator::new(schema.clone());

    let pset = utils::pset_from_text(
        r#"permit(principal, action, resource)
        when {
            principal.hungry_level >= resource.min_hungry_level &&
            principal.hasTag("can_eat") &&
            principal.getTag("can_eat")
        };"#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::new(validator.schema(), "User", "Action::\"eat\"", "Snack");

    assert_does_not_always_deny(&mut compiler, &pset, &envs).await;
}

/// Tests generation of ancestor functions with at least one ite
#[tokio::test]
async fn cex_test_simple_model_ancestor_ite() {
    let schema = utils::schema_from_cedarstr(
        r#"
        entity UserGroup;
        entity User in [UserGroup];
        entity Snack {
            min_hungry_level: Long
        };
        action eat appliesTo {
            principal: [User],
            resource: [Snack],
            context: {
                hungry_level: Long,
            }
        };"#,
    );
    let validator = Validator::new(schema.clone());

    let pset = utils::pset_from_text(
        r#"permit(principal in UserGroup::"chef", action == Action::"eat", resource) when {
            context.hungry_level >= resource.min_hungry_level
            && principal != User::"alice"
            && !(User::"alice" in UserGroup::"chef")
        };
        
        forbid(principal == User::"alice", action == Action::"eat", resource);
        "#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::new(validator.schema(), "User", "Action::\"eat\"", "Snack");

    assert_does_not_always_deny(&mut compiler, &pset, &envs).await;
}

/// Tests generation of trivial models
#[tokio::test]
async fn cex_test_simple_model_trivial() {
    let schema = utils::schema_from_cedarstr(
        r#"
        entity UserGroup;
        entity User in [UserGroup];
        entity Snack {
            min_hungry_level: Long
        };
        action eat appliesTo {
            principal: [User],
            resource: [Snack],
            context: {
                hungry_level: Long,
            }
        };"#,
    );
    let validator = Validator::new(schema.clone());

    let pset = utils::pset_from_text(r#"permit(principal, action, resource);"#, &validator);

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::new(validator.schema(), "User", "Action::\"eat\"", "Snack");

    assert_does_not_always_deny(&mut compiler, &pset, &envs).await;
}
