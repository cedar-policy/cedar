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
use cedar_policy_symcc::{solver::LocalSolver, SymCompiler, SymEnv};
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
            x: decimal,
            y: decimal,
            z: decimal,
            s: String,
          }
        };
    "#,
    )
}

fn symenv_for_sample_schema() -> SymEnv {
    let schema = sample_schema();
    let req_env = utils::req_env_from_strs("User", "Action::\"View\"", "Thing");
    SymEnv::new(&schema, &req_env).unwrap()
}

#[tokio::test]
async fn x_lte_max() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {true};"#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {context.x.lessThanOrEqual(decimal("922337203685477.5807"))};"#,
        &validator,
    );

    let mut compiler = SymCompiler::new(LocalSolver::cvc5().unwrap());
    let symenv = symenv_for_sample_schema();

    assert!(
        compiler
            .check_equivalent(pset1.as_ref(), pset2.as_ref(), &symenv)
            .await
            .unwrap(),
        "True: x lessThanOrEqual 922337203685477.5807"
    );
}

#[tokio::test]
async fn max_gte_x() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {true};"#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {decimal("922337203685477.5807").greaterThanOrEqual(context.x)};"#,
        &validator,
    );

    let mut compiler = SymCompiler::new(LocalSolver::cvc5().unwrap());
    let symenv = symenv_for_sample_schema();

    assert!(
        compiler
            .check_equivalent(pset1.as_ref(), pset2.as_ref(), &symenv)
            .await
            .unwrap(),
        "True: 922337203685477.5807 greaterThanOrEqual x"
    );
}

#[tokio::test]
async fn x_gte_min() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {true};"#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {context.x.greaterThanOrEqual(decimal("-922337203685477.5808"))};"#,
        &validator,
    );

    let mut compiler = SymCompiler::new(LocalSolver::cvc5().unwrap());
    let symenv = symenv_for_sample_schema();

    assert!(
        compiler
            .check_equivalent(pset1.as_ref(), pset2.as_ref(), &symenv)
            .await
            .unwrap(),
        "True: x greaterThanOrEqual -922337203685477.5808"
    );
}

#[tokio::test]
async fn min_lte_x() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {true};"#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {decimal("-922337203685477.5808").lessThanOrEqual(context.x)};"#,
        &validator,
    );

    let mut compiler = SymCompiler::new(LocalSolver::cvc5().unwrap());
    let symenv = symenv_for_sample_schema();

    assert!(
        compiler
            .check_equivalent(pset1.as_ref(), pset2.as_ref(), &symenv)
            .await
            .unwrap(),
        "True: -922337203685477.5808 lessThanOrEqual x"
    );
}

#[tokio::test]
async fn x_ne_max_impl_x_lt_max() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.x != decimal("922337203685477.5807")
        };"#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.x.lessThan(decimal("922337203685477.5807"))
        };"#,
        &validator,
    );

    let mut compiler = SymCompiler::new(LocalSolver::cvc5().unwrap());
    let symenv = symenv_for_sample_schema();

    assert!(
        compiler
            .check_implies(pset1.as_ref(), pset2.as_ref(), &symenv)
            .await
            .unwrap(),
        "Implies: x != 922337203685477.5807 ==> x lessThan 922337203685477.5807"
    );
}

#[tokio::test]
async fn x_ne_min_impl_x_gt_min() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.x != decimal("-922337203685477.5808")
        };"#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.x.greaterThan(decimal("-922337203685477.5808"))
        };"#,
        &validator,
    );

    let mut compiler = SymCompiler::new(LocalSolver::cvc5().unwrap());
    let symenv = symenv_for_sample_schema();

    assert!(
        compiler
            .check_implies(pset1.as_ref(), pset2.as_ref(), &symenv)
            .await
            .unwrap(),
        "Implies: x != -922337203685477.5808 ==> x greaterThan -922337203685477.5808"
    );
}

#[tokio::test]
async fn x_lt_y_impl_y_gt_x() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.x.lessThan(context.y)
        };"#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.y.greaterThan(context.x)
        };"#,
        &validator,
    );

    let mut compiler = SymCompiler::new(LocalSolver::cvc5().unwrap());
    let symenv = symenv_for_sample_schema();

    assert!(
        compiler
            .check_implies(pset1.as_ref(), pset2.as_ref(), &symenv)
            .await
            .unwrap(),
        "Implies: x lessThan y ==> y greaterThan x"
    );
}

#[tokio::test]
async fn x_lte_y_impl_y_gte_x() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.x.lessThanOrEqual(context.y)
        };"#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.y.greaterThanOrEqual(context.x)
        };"#,
        &validator,
    );

    let mut compiler = SymCompiler::new(LocalSolver::cvc5().unwrap());
    let symenv = symenv_for_sample_schema();

    assert!(
        compiler
            .check_implies(pset1.as_ref(), pset2.as_ref(), &symenv)
            .await
            .unwrap(),
        "Implies: x lessThanOrEqual y ==> y greaterThanOrEqual x"
    );
}

#[tokio::test]
async fn x_lte_y_and_y_lte_x_impl_x_eq_y() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.x.lessThanOrEqual(context.y) &&
            context.y.lessThanOrEqual(context.x)
        };"#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.x == context.y
        };"#,
        &validator,
    );

    let mut compiler = SymCompiler::new(LocalSolver::cvc5().unwrap());
    let symenv = symenv_for_sample_schema();

    assert!(
        compiler
            .check_implies(pset1.as_ref(), pset2.as_ref(), &symenv)
            .await
            .unwrap(),
        "Implies: x lessThanOrEqual y && y lessThanOrEqual x ==> x = y"
    );
}

#[tokio::test]
async fn x_lt_y_and_y_lt_z_impl_z_gt_x() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.x.lessThan(context.y) &&
            context.y.lessThan(context.z)
        };"#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"
        permit(principal, action, resource)
        when {
            context.z.greaterThan(context.x)
        };"#,
        &validator,
    );

    let mut compiler = SymCompiler::new(LocalSolver::cvc5().unwrap());
    let symenv = symenv_for_sample_schema();

    assert!(
        compiler
            .check_implies(pset1.as_ref(), pset2.as_ref(), &symenv)
            .await
            .unwrap(),
        "Implies: x lessThan y && x lessThan z ==> z greaterThan x"
    );
}
