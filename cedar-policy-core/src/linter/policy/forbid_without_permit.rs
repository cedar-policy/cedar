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

//! Flags `forbid` policies in a set with no `permit` at all.
//!
//! Cedar denies by default, so a set with only `forbid`s never allows anything;
//! the `forbid`s cannot change that outcome, so they are almost certainly
//! incomplete (a missing `permit`) rather than wrong. Needs the whole policy set.

use crate::{
    ast::{Effect, PolicySet},
    linter::findings::{ForbidWithoutPermit, LintFinding},
};

/// Report every `forbid` when the set contains no `permit`.
pub(crate) fn lint(policy_set: &PolicySet) -> Vec<LintFinding> {
    if policy_set
        .all_templates()
        .any(|t| t.effect() == Effect::Permit)
    {
        return Vec::new();
    }
    policy_set
        .all_templates()
        .filter(|t| t.effect() == Effect::Forbid)
        .flat_map(|t| {
            LintFinding::tag_all(
                [ForbidWithoutPermit {
                    loc: t.loc().cloned(),
                }
                .into()],
                t.id(),
            )
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::lint;
    use crate::linter::test_util::render;
    use crate::parser::parse_policyset;

    #[track_caller]
    fn forbid_without_permit_report(src: &str) -> String {
        let policies = parse_policyset(src).expect("failed to parse");
        render(&lint(&policies))
    }

    /// A set with `forbid`s but no `permit` never allows anything.
    #[test]
    fn forbid_without_permit() {
        insta::assert_snapshot!(forbid_without_permit_report(
            r#"forbid(principal == User::"alice", action, resource);"#), @r#"
         ⚠ for policy `policy0`, this `forbid` is in a policy set with no `permit` policy
          ╭────
        1 │ forbid(principal == User::"alice", action, resource);
          · ─────────────────────────────────────────────────────
          ╰────
         help: Cedar denies by default, so every request is already denied and this `forbid` changes nothing; the policy set may be missing a `permit`
        "#);
    }

    /// Each `forbid` in such a set is reported.
    #[test]
    fn multiple_forbids_without_permit() {
        insta::assert_snapshot!(forbid_without_permit_report(
            r#"
            forbid(principal == User::"alice", action, resource);
            forbid(principal == User::"bob", action, resource);
        "#), @r#"
         ⚠ for policy `policy0`, this `forbid` is in a policy set with no `permit` policy
          ╭─[2:13]
        1 │ 
        2 │             forbid(principal == User::"alice", action, resource);
          ·             ─────────────────────────────────────────────────────
        3 │             forbid(principal == User::"bob", action, resource);
          ╰────
         help: Cedar denies by default, so every request is already denied and this `forbid` changes nothing; the policy set may be missing a `permit`

         ⚠ for policy `policy1`, this `forbid` is in a policy set with no `permit` policy
          ╭─[3:13]
        2 │             forbid(principal == User::"alice", action, resource);
        3 │             forbid(principal == User::"bob", action, resource);
          ·             ───────────────────────────────────────────────────
        4 │         
          ╰────
         help: Cedar denies by default, so every request is already denied and this `forbid` changes nothing; the policy set may be missing a `permit`
        "#);
    }

    /// One `permit` anywhere in the set is enough, even a constrained one.
    #[test]
    fn any_permit_suffices() {
        insta::assert_snapshot!(forbid_without_permit_report(
            r#"
            forbid(principal == User::"alice", action, resource);
            permit(principal == User::"bob", action, resource);
        "#), @"");
    }

    /// A set with no policies at all, and one with only `permit`s, are both fine.
    #[test]
    fn nothing_to_report() {
        insta::assert_snapshot!(forbid_without_permit_report(""), @"");
        insta::assert_snapshot!(forbid_without_permit_report(
            r#"permit(principal == User::"alice", action, resource);"#), @"");
    }
}
