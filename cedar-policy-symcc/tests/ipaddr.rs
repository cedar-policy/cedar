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

use crate::utils::{assert_always_allows, assert_does_not_imply, assert_implies, Environments};
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
            x: ipaddr,
            y: ipaddr,
            z: ipaddr,
          }
        };
    "#,
    )
}

fn env_for_sample_schema<'a>(schema: &'a Schema) -> Environments<'a> {
    Environments::new(&schema, "User", "Action::\"View\"", "Thing")
}

#[tokio::test]
async fn ipaddr_constants() {
    let validator = Validator::new(sample_schema());
    let pset = utils::pset_from_text(
        r#"permit(principal, action, resource) when {
            ip("192.168.0.1").isInRange(ip("192.168.0.1/24")) == true &&
            ip("192.168.0.1").isInRange(ip("192.168.0.1/28")) == true &&
            ip("192.168.0.75").isInRange(ip("192.168.0.1/24")) == true &&
            ip("192.168.0.75").isInRange(ip("192.168.0.1/28")) == false &&
            ip("192.168.1.1/16").isInRange(ip("192.168.1.1/24")) == false &&
            ip("192.168.1.1/25").isInRange(ip("192.168.1.1/24")) == true &&
            ip("1:2:3:4::").isInRange(ip("1:2:3:4::/48")) == true &&
            ip("192.168.0.1").isInRange(ip("1:2:3:4::")) == false &&
            ip("192.168.1.1").isInRange(ip("192.168.0.1/24")) == false &&
            ip("127.0.0.1").isMulticast() == false &&
            ip("ff00::2").isMulticast() == true &&
            ip("127.0.0.2").isLoopback() == true &&
            ip("::1").isLoopback() == true &&
            ip("::2").isLoopback() == false &&
            ip("127.0.0.1/24").isIpv6() == false &&
            ip("ffee::/64").isIpv6() == true &&
            ip("::1").isIpv6() == true &&
            ip("127.0.0.1").isIpv4() == true &&
            ip("::1").isIpv4() == false &&
            ip("127.0.0.1/24").isIpv4() == true
        };"#,
        &validator,
    );
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let schema = sample_schema();
    let envs = env_for_sample_schema(&schema);
    assert_always_allows(&mut compiler, &pset, &envs).await;
}

#[tokio::test]
async fn ipaddr_in_range_antisymmetric_modulo_ip_funs() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {
            context.x.isInRange(context.y) &&
            context.y.isInRange(context.x)
        };"#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {
            context.x.isMulticast() == context.y.isMulticast() &&
            context.x.isLoopback() == context.y.isLoopback() &&
            context.x.isIpv4() == context.y.isIpv4() &&
            context.x.isIpv6() == context.y.isIpv6()
        };"#,
        &validator,
    );
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let schema = sample_schema();
    let envs = env_for_sample_schema(&schema);
    assert_implies(&mut compiler, &pset1, &pset2, &envs).await;
}

#[tokio::test]
async fn ipaddr_in_range_antisymmetric_cex_ipv4() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {
            context.x.isInRange(context.y) &&
            context.y.isInRange(context.x) &&
            context.x.isIpv4()
        };"#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {
            context.x == context.y
        };"#,
        &validator,
    );
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let schema = sample_schema();
    let envs = env_for_sample_schema(&schema);
    assert_does_not_imply(&mut compiler, &pset1, &pset2, &envs).await;
}

#[tokio::test]
async fn ipaddr_in_range_antisymmetric_cex_ipv6() {
    let validator = Validator::new(sample_schema());
    let pset1 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {
            context.x.isInRange(context.y) &&
            context.y.isInRange(context.x) &&
            context.x.isIpv6()
        };"#,
        &validator,
    );
    let pset2 = utils::pset_from_text(
        r#"permit(principal, action, resource) when {
            context.x == context.y
        };"#,
        &validator,
    );
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let schema = sample_schema();
    let envs = env_for_sample_schema(&schema);
    assert_does_not_imply(&mut compiler, &pset1, &pset2, &envs).await;
}
