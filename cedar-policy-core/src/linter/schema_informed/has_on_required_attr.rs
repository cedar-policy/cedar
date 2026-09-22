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

//! Flags a `has` on an attribute the schema declares required on the operand's
//! type in every applicable request environment — so the test is always true.

use crate::{
    ast::ExprKind,
    validator::{types::Type, ValidatorSchema},
};

use super::super::findings::{Finding, HasOnRequiredAttr};
use super::PerEnv;

/// Report each `has` whose attribute the schema declares required on the operand's
/// type in every environment.
pub(super) fn lint(per_env: &PerEnv<'_>, schema: &ValidatorSchema, findings: &mut Vec<Finding>) {
    for i in 0..per_env.len() {
        let ExprKind::HasAttr { attr, .. } = per_env.first(i).expr_kind() else {
            continue;
        };
        if !per_env.in_clause(i) {
            continue;
        }
        // The `has` is redundant only if `attr` is *required* on the target's type
        // in every environment. If the target's type is unknown, or the attribute
        // is optional, in even one environment, the guard is doing real work there
        // and is not reported.
        let required_everywhere = per_env.all_envs(i, |node| {
            let ExprKind::HasAttr { expr: target, .. } = node.expr_kind() else {
                return false;
            };
            match target.data() {
                Some(ty) => {
                    Type::lookup_attribute_type(schema, ty, attr).is_some_and(|a| a.is_required)
                }
                None => false,
            }
        });
        if required_everywhere {
            findings.push(
                HasOnRequiredAttr {
                    loc: per_env.first(i).source_loc().cloned(),
                    attr: attr.clone(),
                }
                .into(),
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::test_support::report;
    use crate::linter::Lint;

    #[track_caller]
    fn lint_report(src: &str) -> String {
        report(Lint::HasOnRequiredAttr, src)
    }

    /// `name` is required on `User`, so `principal has name` is always true.
    #[test]
    fn has_on_required() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action == Action::"view", resource) when { principal has name };"#), @r#"
         ⚠ for policy `policy0`, `has name` is always true: the schema declares `name` required
          ╭────
        1 │ permit(principal, action == Action::"view", resource) when { principal has name };
          ·                                                              ──────────────────
          ╰────
         help: a required attribute is always present, so this test is always true; note that `has` also proves the entity exists, which a defensive policy may still want
        "#);
    }

    /// `manager` is optional, so the guard is doing real work.
    #[test]
    fn has_on_optional_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action == Action::"view", resource) when { principal has manager };"#),
            @"");
    }
}
