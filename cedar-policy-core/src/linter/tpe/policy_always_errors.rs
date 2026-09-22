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

//! Flags every policy that errors for all requests in some reachable request
//! environment, so it is silently skipped there — a `forbid` fails open.

use crate::{
    ast::{EntityType, EntityUID, PolicySet},
    linter::findings::AlwaysErrors,
    validator::ValidatorSchema,
};

use super::shared::for_each_env;

/// Human description of a request environment, for a message.
fn describe_env(principal: &EntityType, action: &EntityUID, resource: &EntityType) -> String {
    format!("for principal `{principal}`, action `{action}`, resource `{resource}`")
}

/// For each environment, TPE on a fully-unknown request; any policy whose residual
/// is `error_permits`/`error_forbids` (an unconditional error with everything
/// unknown) errors for every request in that environment. One environment suffices
/// — an error reachable anywhere is a bug — so this does not require the error to
/// hold across all environments, unlike the redundancy findings.
pub(crate) fn lint(policies: &PolicySet, schema: &ValidatorSchema) -> Vec<AlwaysErrors> {
    let mut out = Vec::new();
    for_each_env(policies, schema, |p, a, r, response| {
        for residual in response.error_permits().chain(response.error_forbids()) {
            out.push(AlwaysErrors {
                policy_id: residual.get_policy_id().to_string(),
                env: describe_env(p, a, r),
            });
        }
    });
    out
}

#[cfg(test)]
mod test {
    use super::super::shared::test_support::schema;
    use crate::linter::test_util::render;
    use crate::parser::parse_policyset;

    #[track_caller]
    fn errors_report(src: &str) -> String {
        let policies = parse_policyset(src).expect("policy parse");
        let mut findings = lint(&policies, &schema());
        findings.sort_by_key(|f| f.to_string());
        render(&findings)
    }
    use super::lint;

    /// A policy that errors unconditionally (constant overflow) errors in every
    /// environment it applies to; each is reported.
    #[test]
    fn policy_always_errors() {
        insta::assert_snapshot!(errors_report(
            r#"permit(principal, action == Action::"edit", resource) when { 9223372036854775807 + 1 > 0 };"#), @r#"
        ⚠ policy `policy0` always errors for principal `User`, action `Action::"edit"`, resource `Photo`
        help: the policy errors for every request in this environment, so it is skipped there and has no effect; a skipped `forbid` fails open
        "#);
    }

    /// A policy that only errors on *some* inputs (the overflow depends on an
    /// unknown) is not reported: it does not error for every request.
    #[test]
    fn conditional_error_is_not_reported() {
        insta::assert_snapshot!(errors_report(
            r#"forbid(principal, action == Action::"edit", resource) when { context.n + 9223372036854775807 > 0 };"#),
            @"");
    }
}
