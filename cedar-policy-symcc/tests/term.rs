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

//! This module contains tests for the experimental `term` feature.

use std::{str::FromStr, sync::Arc};

use cedar_policy::{Authorizer, Schema, Validator};
use cedar_policy_symcc::{
    compile_always_allows, compile_always_denies, solver::LocalSolver, term::*, term_factory,
    term_type::*, CedarSymCompiler, SymEnv, WellFormedAsserts, WellTypedPolicies,
};

use crate::utils::{assert_always_allows, assert_does_not_always_deny, Environments};
mod utils;

fn sample_schema() -> Schema {
    utils::schema_from_cedarstr(
        r#"
        entity User;
        entity Thing;
        action View appliesTo {
          principal: [User],
          resource: [Thing],
          context: {
            x: Long,
            y: Long,
          }
        };
    "#,
    )
}

fn env_for_sample_schema<'a>(schema: &'a Schema) -> Environments<'a> {
    Environments::new(&schema, "User", "Action::\"View\"", "Thing")
}

#[tokio::test]
async fn term_basic_arith_unsat() {
    use hashconsing::{HConsign, HashConsign};
    let mut h = HConsign::empty();
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let schema = sample_schema();
    let envs = env_for_sample_schema(&schema);

    let bitvec_ty = TermType {
        inner: h.mk(TermTypeInner::Bitvec { n: 64 }),
    };
    assert_eq!(
        compiler
            .check_unsat(&WellFormedAsserts::from_asserts_unchecked(
                &envs.symenv,
                Arc::new(vec![term_factory::not(
                    term_factory::eq(
                        TermVar {
                            id: "x".into(),
                            ty: bitvec_ty.clone()
                        }
                        .into(),
                        TermVar {
                            id: "x".into(),
                            ty: bitvec_ty.clone()
                        }
                        .into(),
                        &mut h
                    ),
                    &mut h
                )]),
                std::iter::empty()
            ),)
            .await
            .unwrap(),
        true
    );
    assert_eq!(
        compiler
            .check_unsat(&WellFormedAsserts::from_asserts_unchecked(
                &envs.symenv,
                Arc::new(vec![term_factory::not(
                    term_factory::eq(
                        TermVar {
                            id: "x".into(),
                            ty: bitvec_ty.clone()
                        }
                        .into(),
                        TermVar {
                            id: "y".into(),
                            ty: bitvec_ty.clone()
                        }
                        .into(),
                        &mut h
                    ),
                    &mut h
                )]),
                std::iter::empty()
            ),)
            .await
            .unwrap(),
        false
    );
    assert_eq!(
        compiler
            .check_unsat(&WellFormedAsserts::from_asserts_unchecked(
                &envs.symenv,
                Arc::new(vec![term_factory::not(
                    term_factory::implies(
                        term_factory::and(
                            term_factory::bvsle(
                                TermVar {
                                    id: "x".into(),
                                    ty: bitvec_ty.clone()
                                }
                                .into(),
                                TermVar {
                                    id: "y".into(),
                                    ty: bitvec_ty.clone()
                                }
                                .into(),
                                &mut h
                            ),
                            term_factory::bvsle(
                                TermVar {
                                    id: "y".into(),
                                    ty: bitvec_ty.clone()
                                }
                                .into(),
                                TermVar {
                                    id: "z".into(),
                                    ty: bitvec_ty.clone()
                                }
                                .into(),
                                &mut h
                            ),
                            &mut h
                        ),
                        term_factory::bvsle(
                            TermVar {
                                id: "x".into(),
                                ty: bitvec_ty.clone()
                            }
                            .into(),
                            TermVar {
                                id: "z".into(),
                                ty: bitvec_ty.clone()
                            }
                            .into(),
                            &mut h
                        ),
                        &mut h
                    ),
                    &mut h
                )]),
                std::iter::empty(),
            ),)
            .await
            .unwrap(),
        true
    );
}

#[tokio::test]
async fn term_always_denies_cex() {
    let validator = Validator::new(sample_schema());
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let schema = sample_schema();
    let envs = env_for_sample_schema(&schema);
    let pset = utils::pset_from_text(
        r#"permit(principal, action, resource) when { context.x >= context.y };"#,
        &validator,
    );
    let typed_pset = WellTypedPolicies::from_policies(&pset, &envs.req_env, envs.schema).unwrap();
    let asserts = compile_always_denies(&typed_pset, &envs.symenv).unwrap();
    let cex = compiler.check_sat(&asserts).await.unwrap().unwrap();
    let resp = Authorizer::new().is_authorized(&cex.request, &pset, &cex.entities);
    assert_eq!(resp.decision(), cedar_policy::Decision::Allow);
}

/// Tests modifying some parts of SymEnv
#[tokio::test]
async fn term_cex_custom_symenv() {
    let schema = utils::schema_from_cedarstr(
        r#"
        entity User;
        entity Document;
        action view appliesTo {
            principal: [User],
            resource: [Document],
            context: {
                user: User
            }
        };
        "#,
    );
    let validator = Validator::new(schema.clone());
    let pset = utils::pset_from_text(
        r#"permit(principal, action, resource) when { principal == context.user };"#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let mut envs = Environments::new(validator.schema(), "User", "Action::\"view\"", "Document");

    // Fix `context.user` to be the same as `principal`
    envs.symenv.request.context = Term::Record(Arc::new(
        [("user".into(), envs.symenv.request.principal.clone())]
            .into_iter()
            .collect(),
    ));

    assert_does_not_always_deny(&mut compiler, &pset, &envs).await;
    assert_always_allows(&mut compiler, &pset, &envs).await;
}

/// Tests modifying some parts of SymEnv
#[tokio::test]
#[ignore]
async fn term_cex_custom_symenv_set() {
    let schema = utils::schema_from_cedarstr(
        r#"
        entity User;
        entity Document;
        action view appliesTo {
            principal: [User],
            resource: [Document],
            context: {
                users: Set<User>
            }
        };
        "#,
    );
    let validator = Validator::new(schema.clone());
    let pset = utils::pset_from_text(
        r#"permit(principal, action, resource) when { context.users.contains(principal) };"#,
        &validator,
    );

    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let mut envs = Environments::new(validator.schema(), "User", "Action::\"view\"", "Document");

    // Fix `context.users` to be `[principal]`
    let principal_ty = envs
        .symenv
        .request
        .principal
        .type_of(&mut *envs.symenv.h_mut());
    envs.symenv.request.context = Term::Record(Arc::new(
        [(
            "users".into(),
            Term::Set {
                elts: Arc::new(
                    [envs.symenv.request.principal.clone()]
                        .into_iter()
                        .collect(),
                ),
                elts_ty: principal_ty,
            },
        )]
        .into_iter()
        .collect(),
    ));

    assert_does_not_always_deny(&mut compiler, &pset, &envs).await;
    assert_always_allows(&mut compiler, &pset, &envs).await;
}

#[test]
fn duration() {
    let schema = Schema::from_str(
        r#"
        entity a;
        action "" appliesTo {
            principal: a,
            resource: a,
        };
    "#,
    )
    .unwrap();
    let policies = utils::pset_from_text(
        r#"
        forbid(
      principal,
      action in [Action::""],
      resource
    ) when {
      ((true && ((((duration("-0h0m09223372036854775808ms")).toHours()) - 0) <= 0)) && false) && false
    };
        "#,
        &Validator::new(schema.clone()),
    );

    for req_env in schema.request_envs() {
        let ps = WellTypedPolicies::from_policies(&policies, &req_env, &schema).unwrap();
        let sym_env = SymEnv::new(&schema, &req_env).unwrap();
        let terms = compile_always_allows(&ps, &sym_env);
        assert!(terms.is_ok(), "terms: {terms:?}");
    }
}
