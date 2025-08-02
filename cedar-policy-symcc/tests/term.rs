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

#![cfg(feature = "term")]

use cedar_policy::{Authorizer, Schema, Validator};
use cedar_policy_symcc::{
    solver::LocalSolver, term, CedarSymCompiler, TermType, TermVar, WellTypedPolicies,
};

use crate::utils::Environments;
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
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let schema = sample_schema();
    let envs = env_for_sample_schema(&schema);

    assert_eq!(
        compiler
            .check_unsat(
                vec![term::not(term::eq(
                    TermVar {
                        id: "x".to_string(),
                        ty: TermType::Bitvec { n: 64 }
                    }
                    .into(),
                    TermVar {
                        id: "x".to_string(),
                        ty: TermType::Bitvec { n: 64 }
                    }
                    .into(),
                ))],
                &envs.symenv,
            )
            .await
            .unwrap(),
        true
    );
    assert_eq!(
        compiler
            .check_unsat(
                vec![term::not(term::eq(
                    TermVar {
                        id: "x".to_string(),
                        ty: TermType::Bitvec { n: 64 }
                    }
                    .into(),
                    TermVar {
                        id: "y".to_string(),
                        ty: TermType::Bitvec { n: 64 }
                    }
                    .into(),
                ))],
                &envs.symenv,
            )
            .await
            .unwrap(),
        false
    );
    assert_eq!(
        compiler
            .check_unsat(
                vec![term::not(term::implies(
                    term::and(
                        term::bvsle(
                            TermVar {
                                id: "x".to_string(),
                                ty: TermType::Bitvec { n: 64 }
                            }
                            .into(),
                            TermVar {
                                id: "y".to_string(),
                                ty: TermType::Bitvec { n: 64 }
                            }
                            .into(),
                        ),
                        term::bvsle(
                            TermVar {
                                id: "y".to_string(),
                                ty: TermType::Bitvec { n: 64 }
                            }
                            .into(),
                            TermVar {
                                id: "z".to_string(),
                                ty: TermType::Bitvec { n: 64 }
                            }
                            .into(),
                        ),
                    ),
                    term::bvsle(
                        TermVar {
                            id: "x".to_string(),
                            ty: TermType::Bitvec { n: 64 }
                        }
                        .into(),
                        TermVar {
                            id: "z".to_string(),
                            ty: TermType::Bitvec { n: 64 }
                        }
                        .into(),
                    ),
                )),],
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
    let typed_pset = WellTypedPolicies::from_policies(&pset, &envs.req_env, envs.schema).unwrap();
    let asserts = compiler
        .compile_always_denies(&typed_pset, &envs.symenv)
        .unwrap();
    let cex = compiler
        .check_sat(asserts, &envs.symenv, typed_pset.policy_set().policies())
        .await
        .unwrap()
        .unwrap();
    let resp = Authorizer::new().is_authorized(&cex.request, &pset, &cex.entities);
    assert_eq!(resp.decision(), cedar_policy::Decision::Allow);
}
