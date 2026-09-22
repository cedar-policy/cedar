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

use crate::{
    ast::{BinaryOp, Expr, ExprKind},
    linter::{
        capability::walk_capabilities,
        findings::{Finding, TagError},
    },
    validator::types::{Capability, CapabilitySet},
};

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct TagLinter {
    errors: Vec<Finding>,
}

impl TagLinter {
    /// Lint `expr`, reporting every `getTag` not preceded by a corresponding
    /// `hasTag` guard.
    pub(crate) fn lint(&mut self, expr: &Expr) {
        let mut errors = std::mem::take(&mut self.errors);
        // The capability plumbing is shared; this only says what each node
        // establishes and checks. A `hasTag` establishes its tag; an unguarded
        // `getTag` errors at runtime, so it is reported.
        walk_capabilities(expr, &CapabilitySet::new(), &mut |expr, tags| {
            if let ExprKind::BinaryApp { op, arg1, arg2 } = expr.expr_kind() {
                match op {
                    BinaryOp::HasTag => {
                        return CapabilitySet::singleton(Capability::new_borrowed_tag(arg1, arg2));
                    }
                    BinaryOp::GetTag => {
                        if !tags.contains(&Capability::new_borrowed_tag(arg1, arg2)) {
                            errors.push(
                                TagError {
                                    loc: expr.source_loc().cloned(),
                                }
                                .into(),
                            );
                        }
                    }
                    _ => {}
                }
            }
            CapabilitySet::new()
        });
        self.errors = errors;
    }

    /// Consume this linter, returning the findings it accumulated.
    pub(crate) fn into_findings(self) -> Vec<Finding> {
        self.errors
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::test_util::render;
    use crate::parser::parse_expr;

    /// Lint `src` and return the pretty miette rendering of all findings,
    /// concatenated. Rendered without color so the snapshots stay readable.
    #[track_caller]
    fn lint_report(src: &str) -> String {
        let expr = parse_expr(src).expect("failed to parse");
        let mut linter = TagLinter::default();
        linter.lint(&expr);
        render(&linter.errors)
    }

    /// A `getTag` guarded by the corresponding `hasTag` is fine.
    #[test]
    fn guarded_by_has_tag() {
        insta::assert_snapshot!(
            lint_report(r#"principal.hasTag("x") && principal.getTag("x") == "y""#), @"");
    }

    #[test]
    fn unguarded() {
        insta::assert_snapshot!(lint_report(r#"principal.getTag("x") == "y""#), @r#"
         × `getTag` is not preceded by corresponding `hasTag
          ╭────
        1 │ principal.getTag("x") == "y"
          · ─────────────────────
          ╰────
        "#);
    }

    /// The guard must be for the same target and tag.
    #[test]
    fn guard_for_different_tag() {
        insta::assert_snapshot!(
            lint_report(r#"principal.hasTag("x") && principal.getTag("y") == "z""#), @r#"
         × `getTag` is not preceded by corresponding `hasTag
          ╭────
        1 │ principal.hasTag("x") && principal.getTag("y") == "z"
          ·                          ─────────────────────
          ╰────
        "#);
    }

    #[test]
    fn guard_for_different_target() {
        insta::assert_snapshot!(
            lint_report(r#"principal.hasTag("x") && resource.getTag("x") == "z""#), @r#"
         × `getTag` is not preceded by corresponding `hasTag
          ╭────
        1 │ principal.hasTag("x") && resource.getTag("x") == "z"
          ·                          ────────────────────
          ╰────
        "#);
    }

    /// `||` doesn't establish a capability for its right operand, since the
    /// right side is only evaluated when the left is false.
    #[test]
    fn or_does_not_guard() {
        insta::assert_snapshot!(
            lint_report(r#"principal.hasTag("x") || principal.getTag("x") == "y""#), @r#"
         × `getTag` is not preceded by corresponding `hasTag
          ╭────
        1 │ principal.hasTag("x") || principal.getTag("x") == "y"
          ·                          ─────────────────────
          ╰────
        "#);
    }

    /// A `hasTag` test guards the `then` branch but not the `else` branch.
    #[test]
    fn if_guards_then_but_not_else() {
        insta::assert_snapshot!(
            lint_report(r#"if principal.hasTag("x") then principal.getTag("x") == "y" else false"#),
            @"");
        insta::assert_snapshot!(
            lint_report(r#"if principal.hasTag("x") then false else principal.getTag("x") == "y""#),
            @r#"
         × `getTag` is not preceded by corresponding `hasTag
          ╭────
        1 │ if principal.hasTag("x") then false else principal.getTag("x") == "y"
          ·                                          ─────────────────────
          ╰────
        "#);
    }

    /// Multiple guards accumulate, and each `getTag` is checked.
    #[test]
    fn multiple_tags() {
        insta::assert_snapshot!(lint_report(
            r#"principal.hasTag("x") && principal.hasTag("y") && principal.getTag("x") == principal.getTag("y")"#),
            @"");
        insta::assert_snapshot!(lint_report(
            r#"principal.hasTag("x") && principal.getTag("x") == principal.getTag("y")"#),
            @r#"
         × `getTag` is not preceded by corresponding `hasTag
          ╭────
        1 │ principal.hasTag("x") && principal.getTag("x") == principal.getTag("y")
          ·                                                   ─────────────────────
          ╰────
        "#);
    }
}
