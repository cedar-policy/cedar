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
    always_denies_asserts, solver::LocalSolver, term::*, term_factory, term_type::*,
    type_abbrevs::SIXTY_FOUR, CedarSymCompiler, CompiledPolicies,
};

use crate::utils::{assert_always_allows_ok, assert_always_denies_ok, Environments, Pathway};
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
    Environments::new(schema, "User", "Action::\"View\"", "Thing")
}

#[tokio::test]
#[expect(
    clippy::bool_assert_comparison,
    reason = "easier to read assert_eq with true/false than to look for presence/absence of `!`"
)]
async fn term_basic_arith_unsat() {
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let schema = sample_schema();
    let envs = env_for_sample_schema(&schema);

    assert_eq!(
        compiler
            .check_unsat_raw(
                Arc::new(vec![term_factory::not(term_factory::eq(
                    TermVar {
                        id: "x".into(),
                        ty: TermType::Bitvec { n: SIXTY_FOUR }
                    }
                    .into(),
                    TermVar {
                        id: "x".into(),
                        ty: TermType::Bitvec { n: SIXTY_FOUR }
                    }
                    .into(),
                ))]),
                &envs.symenv,
            )
            .await
            .unwrap(),
        true
    );
    assert_eq!(
        compiler
            .check_unsat_raw(
                Arc::new(vec![term_factory::not(term_factory::eq(
                    TermVar {
                        id: "x".into(),
                        ty: TermType::Bitvec { n: SIXTY_FOUR }
                    }
                    .into(),
                    TermVar {
                        id: "y".into(),
                        ty: TermType::Bitvec { n: SIXTY_FOUR }
                    }
                    .into(),
                ))]),
                &envs.symenv,
            )
            .await
            .unwrap(),
        false
    );
    assert_eq!(
        compiler
            .check_unsat_raw(
                Arc::new(vec![term_factory::not(term_factory::implies(
                    term_factory::and(
                        term_factory::bvsle(
                            TermVar {
                                id: "x".into(),
                                ty: TermType::Bitvec { n: SIXTY_FOUR }
                            }
                            .into(),
                            TermVar {
                                id: "y".into(),
                                ty: TermType::Bitvec { n: SIXTY_FOUR }
                            }
                            .into(),
                        ),
                        term_factory::bvsle(
                            TermVar {
                                id: "y".into(),
                                ty: TermType::Bitvec { n: SIXTY_FOUR }
                            }
                            .into(),
                            TermVar {
                                id: "z".into(),
                                ty: TermType::Bitvec { n: SIXTY_FOUR }
                            }
                            .into(),
                        ),
                    ),
                    term_factory::bvsle(
                        TermVar {
                            id: "x".into(),
                            ty: TermType::Bitvec { n: SIXTY_FOUR }
                        }
                        .into(),
                        TermVar {
                            id: "z".into(),
                            ty: TermType::Bitvec { n: SIXTY_FOUR }
                        }
                        .into(),
                    ),
                ))]),
                &envs.symenv,
            )
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
    let compiled_pset = CompiledPolicies::compile(&pset, &envs.req_env, envs.schema).unwrap();
    let asserts = always_denies_asserts(&compiled_pset);
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

    // Fix `context.user` to be the same as `principal`
    let default_envs =
        Environments::new(validator.schema(), "User", "Action::\"view\"", "Document");
    let mut symenv = default_envs.symenv.clone();
    symenv.request.context = Term::Record(Arc::new(
        std::iter::once(("user".into(), default_envs.symenv.request.principal.clone())).collect(),
    ));
    let envs = Environments::new_with_custom_symenv(
        validator.schema(),
        "User",
        "Action::\"view\"",
        "Document",
        symenv,
    );

    let always_denies =
        assert_always_denies_ok(&mut compiler, &pset, &envs, Pathway::default()).await;
    assert!(!always_denies);
    let always_allows =
        assert_always_allows_ok(&mut compiler, &pset, &envs, Pathway::default()).await;
    assert!(always_allows);
}

/// Tests modifying some parts of SymEnv
#[tokio::test]
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

    // Fix `context.users` to be `[principal]`
    let default_envs =
        Environments::new(validator.schema(), "User", "Action::\"view\"", "Document");
    let mut symenv = default_envs.symenv.clone();
    symenv.request.context = Term::Record(Arc::new(
        std::iter::once((
            "users".into(),
            Term::Set {
                elts: Arc::new(
                    std::iter::once(default_envs.symenv.request.principal.clone()).collect(),
                ),
                elts_ty: default_envs.symenv.request.principal.type_of(),
            },
        ))
        .collect(),
    ));
    let envs = Environments::new_with_custom_symenv(
        validator.schema(),
        "User",
        "Action::\"view\"",
        "Document",
        symenv,
    );

    let always_denies =
        assert_always_denies_ok(&mut compiler, &pset, &envs, Pathway::default()).await;
    assert!(!always_denies);
    let always_allows =
        assert_always_allows_ok(&mut compiler, &pset, &envs, Pathway::default()).await;
    assert!(always_allows);
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
        // just test that compiling works
        CompiledPolicies::compile(&policies, &req_env, &schema).unwrap();
    }
}
