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
use cedar_policy::{Schema, Validator};
use cedar_policy_symcc::{solver::LocalSolver, CedarSymCompiler};

use crate::utils::{assert_does_not_imply, assert_implies, Environments};
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
            x: datetime,
            y: datetime,
            d1: duration,
            d2: duration,
          }
        };
    "#,
    )
}

fn env_for_sample_schema<'a>(schema: &'a Schema) -> Environments<'a> {
    Environments::new(&schema, "User", "Action::\"View\"", "Thing")
}

#[tokio::test]
async fn x_max_offset() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {
            context.x >= datetime("1970-01-01") &&
            context.x.offset(duration("9223372036854775807ms")) == context.x.offset(duration("9223372036854775807ms"))};
        "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {context.x == datetime("1970-01-01")};"#,
        &validator,
    );
    let pset3 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {context.x != datetime("1970-01-01")};"#,
        &validator,
    );
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let schema = sample_schema();
    let envs = env_for_sample_schema(&schema);
    assert_implies(&mut compiler, &pset1, &pset2, &envs).await;
    assert_does_not_imply(&mut compiler, &pset1, &pset3, &envs).await;
}

#[tokio::test]
async fn x_min_offset() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {
            context.x <= datetime("1970-01-01") &&
            context.x.offset(duration("-9223372036854775808ms")) == context.x.offset(duration("-9223372036854775808ms"))};
        "#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {context.x == datetime("1970-01-01")};"#,
        &validator,
    );
    let pset3 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {context.x != datetime("1970-01-01")};"#,
        &validator,
    );
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let schema = sample_schema();
    let envs = env_for_sample_schema(&schema);
    assert_implies(&mut compiler, &pset1, &pset2, &envs).await;
    assert_does_not_imply(&mut compiler, &pset1, &pset3, &envs).await;
}
