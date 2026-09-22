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

//! Flags `like` patterns that are almost certainly not what the author meant.
//!
//! Three cases, all decided by looking at the pattern alone:
//!
//! * A pattern with no wildcard, e.g. `x like "abc"`. This is just a string
//!   equality written the long way, and readers may reasonably expect it to
//!   match more than the one exact string.
//! * A pattern consisting only of wildcards, e.g. `x like "*"`. This matches
//!   every string, so the comparison contributes nothing. (It does still
//!   require the operand to be a string, but the `types` lint covers that.)
//! * A pattern with two or more *consecutive* wildcards, e.g. `x like "a**b"`. A
//!   run of `*`s matches exactly what a single `*` matches, so the extra ones are
//!   redundant. This is reported only for the mixed patterns the first two cases
//!   do not already cover — an all-wildcard pattern like `"**"` is reported as
//!   matching every string, not for its consecutive wildcards.
//!
//! All are warnings: they are legal, well-defined, and only suspicious.
//!
//! # Combining a prefix and a suffix pattern
//!
//! A fourth, cross-expression case looks at a *conjunction*: two `like`s on the
//! same operand, one a prefix constraint (`foo like "cs*"`) and one a suffix
//! constraint (`foo like "*p"`), combine into a single `foo like "cs*p"` — and the
//! symmetric `foo like "*cs" && foo like "p*"` into `foo like "p*cs"`.
//!
//! This is only sound when the prefix and suffix literals **cannot overlap**.
//! `"cs*p"` requires the `p`-match to sit *after* the whole `cs` prefix, whereas
//! the conjunction lets them overlap: `foo like "a*" && foo like "*a"` accepts
//! `"a"` (the one char is both prefix and suffix), but `foo like "a*a"` needs at
//! least `"aa"`. So the merge is offered *only* when no suffix of the prefix
//! literal equals a prefix of the suffix literal — the border check in
//! [`overlaps`] — which guarantees the two are exactly equivalent. Patterns whose
//! anchor is not a plain literal (an interior wildcard, e.g. `"a*b"`) are not
//! considered, since their overlap cannot be decided this cheaply.

use crate::{
    ast::{Expr, ExprKind, ExprShapeOnly, Pattern, PatternElem},
    linter::{
        findings::{
            CombinableLikePatterns, Finding, LikeWithConsecutiveWildcards, LikeWithOnlyWildcards,
            LikeWithoutWildcard,
        },
        util::{direct_children, scan},
    },
    parser::Loc,
};

/// Lint `expr`, reporting `like` patterns with no wildcard (just an equality),
/// only wildcards (matches anything), or consecutive wildcards (redundant `*`s),
/// plus prefix/suffix `like` pairs on one operand that combine into a single
/// pattern.
pub(crate) fn lint(expr: &Expr) -> Vec<Finding> {
    let mut findings = per_pattern(expr);
    combine_prefix_suffix(expr, &mut findings);
    findings
}

/// The per-`like` checks: each `like` node examined on its own.
fn per_pattern(expr: &Expr) -> Vec<Finding> {
    scan(expr, |e| {
        let ExprKind::Like { pattern, .. } = e.expr_kind() else {
            return None;
        };
        // An empty pattern only matches the empty string. That's unusual but
        // unambiguous, so leave it alone.
        if pattern.is_empty() {
            return None;
        }
        let len = pattern.len();
        let wildcards = pattern
            .iter()
            .filter(|e| matches!(e, PatternElem::Wildcard))
            .count();
        let loc = e.source_loc().cloned();
        let pattern_str = pattern.to_string();
        if wildcards == 0 {
            Some(
                LikeWithoutWildcard {
                    loc,
                    pattern: pattern_str,
                }
                .into(),
            )
        } else if wildcards == len {
            Some(
                LikeWithOnlyWildcards {
                    loc,
                    pattern: pattern_str,
                }
                .into(),
            )
        } else if has_consecutive_wildcards(pattern) {
            Some(
                LikeWithConsecutiveWildcards {
                    loc,
                    pattern: pattern_str,
                }
                .into(),
            )
        } else {
            None
        }
    })
}

/// Does `pattern` contain two wildcards in a row?
fn has_consecutive_wildcards(pattern: &Pattern) -> bool {
    pattern
        .iter()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|w| matches!(w, [PatternElem::Wildcard, PatternElem::Wildcard]))
}

/// A literal anchor a `like` pattern imposes on its operand: the operand's prefix
/// (`"cs*"`) or suffix (`"*cs"`) is exactly these characters. Patterns with an
/// interior wildcard, more than one wildcard, or no literal part are not anchors.
#[derive(Clone)]
enum Anchor {
    Prefix(Vec<char>),
    Suffix(Vec<char>),
}

/// The anchor `pattern` imposes, if it is a plain prefix or suffix literal.
fn anchor(pattern: &Pattern) -> Option<Anchor> {
    let elems = pattern.get_elems();
    if elems.len() < 2 {
        return None;
    }
    // The literal characters of `slice`, or `None` if any element is a wildcard.
    let literal = |slice: &[PatternElem]| -> Option<Vec<char>> {
        slice
            .iter()
            .map(|e| match e {
                PatternElem::Char(c) => Some(*c),
                PatternElem::Wildcard => None,
            })
            .collect()
    };
    // `cs*`: literal characters then a single trailing wildcard.
    if matches!(elems.last(), Some(PatternElem::Wildcard)) {
        if let Some(chars) = literal(&elems[..elems.len() - 1]) {
            return Some(Anchor::Prefix(chars));
        }
    }
    // `*cs`: a single leading wildcard then literal characters.
    if matches!(elems.first(), Some(PatternElem::Wildcard)) {
        if let Some(chars) = literal(&elems[1..]) {
            return Some(Anchor::Suffix(chars));
        }
    }
    None
}

/// Can a suffix of `prefix` equal a prefix of `suffix`? If so, a short string can
/// satisfy both anchors with the two literals overlapping (e.g. `"a"` satisfies
/// `"a*"` and `"*a"`), so merging into `prefix*suffix` — which forces them apart —
/// would wrongly exclude it. Absence of any overlap makes the merge exactly
/// equivalent.
fn overlaps(prefix: &[char], suffix: &[char]) -> bool {
    let max = prefix.len().min(suffix.len());
    (1..=max).any(|k| prefix[prefix.len() - k..] == suffix[..k])
}

/// One `like` prefix/suffix constraint that is known to hold at a point in the
/// condition, threaded through the boolean structure like an attribute capability.
#[derive(Clone)]
struct KnownAnchor<'a> {
    /// The operand it constrains, compared by shape so `principal.name` in two
    /// places is recognized as the same operand.
    operand: ExprShapeOnly<'a, ()>,
    anchor: Anchor,
    /// The pattern as written, and where, for the finding.
    pattern: String,
    loc: Option<Loc>,
}

/// Find prefix/suffix `like` pairs on the same operand that combine into one
/// pattern, threading the anchors that hold through the boolean structure so a
/// prefix and a suffix separated by other conjuncts are still paired.
///
/// Anchors propagate only through `&&` (where the left holds when the right is
/// evaluated); a `||`, `if`, or `!` is a barrier, so a prefix outside it is never
/// combined with a suffix inside — that would cross a disjunction, which the merge
/// cannot express. Nested conjunctions inside those are still searched on their own.
fn combine_prefix_suffix(expr: &Expr, findings: &mut Vec<Finding>) {
    walk(expr, &[], findings);
}

/// Walk `expr` under the anchors `incoming` already establishes, reporting any
/// combinable pair reached, and return the anchors `expr` itself establishes (for
/// the conjunct to its right).
fn walk<'a>(
    expr: &'a Expr,
    incoming: &[KnownAnchor<'a>],
    findings: &mut Vec<Finding>,
) -> Vec<KnownAnchor<'a>> {
    match expr.expr_kind() {
        // `&&` short-circuits: the right is reached only when the left is true, so
        // the left's anchors hold for it. Both sides' anchors hold when the `&&` is
        // true, so it establishes their union.
        ExprKind::And { left, right } => {
            let mut established = walk(left, incoming, findings);
            let mut scope = incoming.to_vec();
            scope.extend(established.iter().cloned());
            let right_established = walk(right, &scope, findings);
            established.extend(right_established);
            established
        }
        // A `like` on a plain prefix/suffix literal: pair it with any complementary
        // anchor already in scope, then contribute its own anchor to the right.
        ExprKind::Like {
            expr: operand,
            pattern,
        } => {
            let Some(anchor) = anchor(pattern) else {
                return Vec::new();
            };
            let operand_shape = ExprShapeOnly::new_from_borrowed(operand.as_ref());
            for known in incoming {
                if known.operand == operand_shape {
                    if let Some(finding) = combine(known, &anchor, pattern, expr.source_loc()) {
                        findings.push(finding);
                    }
                }
            }
            vec![KnownAnchor {
                operand: operand_shape,
                anchor,
                pattern: pattern.to_string(),
                loc: expr.source_loc().cloned(),
            }]
        }
        // Any other node (`||`, `if`, `!`, comparisons, …) is a barrier: anchors do
        // not carry across it, but nested conjunctions inside are still searched.
        _ => {
            for child in direct_children(expr) {
                walk(child, &[], findings);
            }
            Vec::new()
        }
    }
}

/// Combine an in-scope anchor `known` with the anchor `here` (from the `like` at
/// `here_loc`) if they are complementary (one prefix, one suffix) on the same
/// operand and their literals cannot overlap. Returns the finding, anchored at the
/// earlier of the two patterns.
fn combine(
    known: &KnownAnchor<'_>,
    here: &Anchor,
    here_pattern: &Pattern,
    here_loc: Option<&Loc>,
) -> Option<Finding> {
    let (prefix, suffix) = match (&known.anchor, here) {
        (Anchor::Prefix(p), Anchor::Suffix(s)) | (Anchor::Suffix(s), Anchor::Prefix(p)) => (p, s),
        // Two prefixes or two suffixes do not combine into one pattern.
        _ => return None,
    };
    if overlaps(prefix, suffix) {
        return None;
    }
    let merged: Pattern = prefix
        .iter()
        .copied()
        .map(PatternElem::Char)
        .chain(std::iter::once(PatternElem::Wildcard))
        .chain(suffix.iter().copied().map(PatternElem::Char))
        .collect();
    // Name the prefix and suffix patterns by role, and anchor at whichever comes
    // first in the source.
    let (prefix_pat, suffix_pat) = match &known.anchor {
        Anchor::Prefix(_) => (known.pattern.clone(), here_pattern.to_string()),
        Anchor::Suffix(_) => (here_pattern.to_string(), known.pattern.clone()),
    };
    let loc = earlier(known.loc.as_ref(), here_loc).cloned();
    Some(
        CombinableLikePatterns {
            loc,
            prefix: prefix_pat,
            suffix: suffix_pat,
            merged: merged.to_string(),
        }
        .into(),
    )
}

/// The location with the smaller source offset (the one written first).
fn earlier<'a>(a: Option<&'a Loc>, b: Option<&'a Loc>) -> Option<&'a Loc> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if x.span.offset() <= y.span.offset() {
            x
        } else {
            y
        }),
        (x, y) => x.or(y),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::test_util::render;
    use crate::parser::parse_expr;

    /// Lint `src` and return the pretty miette rendering of all findings.
    #[track_caller]
    fn lint_report(src: &str) -> String {
        let expr = parse_expr(src).expect("failed to parse");
        render(&lint(&expr))
    }

    /// A pattern with no wildcard is just an equality check.
    #[test]
    fn no_wildcard() {
        insta::assert_snapshot!(lint_report(r#"principal.name like "abc""#), @r#"
         ⚠ `like` pattern `"abc"` contains no wildcard
          ╭────
        1 │ principal.name like "abc"
          · ─────────────────────────
          ╰────
         help: this matches only the one exact string; use `==` to compare strings, or add a `*` wildcard
        "#);
    }

    /// A pattern of only wildcards matches everything.
    #[test]
    fn only_wildcards() {
        insta::assert_snapshot!(lint_report(r#"principal.name like "*""#), @r#"
         ⚠ `like` pattern `"*"` matches every string
          ╭────
        1 │ principal.name like "*"
          · ───────────────────────
          ╰────
         help: this comparison is always true for a string operand, so it has no effect
        "#);
        insta::assert_snapshot!(lint_report(r#"principal.name like "**""#), @r#"
         ⚠ `like` pattern `"**"` matches every string
          ╭────
        1 │ principal.name like "**"
          · ────────────────────────
          ╰────
         help: this comparison is always true for a string operand, so it has no effect
        "#);
    }

    /// A pattern mixing wildcards and characters is the normal case.
    #[test]
    fn mixed_pattern_is_fine() {
        insta::assert_snapshot!(lint_report(r#"principal.name like "a*""#), @"");
        insta::assert_snapshot!(lint_report(r#"principal.name like "*@example.com""#), @"");
        insta::assert_snapshot!(lint_report(r#"principal.name like "a*b*c""#), @"");
    }

    /// Two consecutive wildcards in a mixed pattern are redundant.
    #[test]
    fn consecutive_wildcards() {
        insta::assert_snapshot!(lint_report(r#"principal.name like "a**b""#), @r#"
         ⚠ `like` pattern `"a**b"` has consecutive wildcards
          ╭────
        1 │ principal.name like "a**b"
          · ──────────────────────────
          ╰────
         help: a run of `*`s matches the same as a single `*`; collapse each run to one wildcard
        "#);
    }

    /// A run of three wildcards is reported once.
    #[test]
    fn three_consecutive_wildcards() {
        insta::assert_snapshot!(lint_report(r#"principal.name like "a***b""#), @r#"
         ⚠ `like` pattern `"a***b"` has consecutive wildcards
          ╭────
        1 │ principal.name like "a***b"
          · ───────────────────────────
          ╰────
         help: a run of `*`s matches the same as a single `*`; collapse each run to one wildcard
        "#);
    }

    /// Consecutive wildcards separated by a literal are not consecutive, so a
    /// pattern like `a*b*c` is fine (already covered by `mixed_pattern_is_fine`,
    /// asserted here explicitly for the boundary).
    #[test]
    fn non_adjacent_wildcards_are_fine() {
        insta::assert_snapshot!(lint_report(r#"principal.name like "a*b*""#), @"");
    }

    /// An all-wildcard pattern is reported as matching every string, not for its
    /// consecutive wildcards — the earlier case takes precedence.
    #[test]
    fn all_wildcards_takes_precedence_over_consecutive() {
        insta::assert_snapshot!(lint_report(r#"principal.name like "**""#), @r#"
         ⚠ `like` pattern `"**"` matches every string
          ╭────
        1 │ principal.name like "**"
          · ────────────────────────
          ╰────
         help: this comparison is always true for a string operand, so it has no effect
        "#);
    }

    /// A wildcard next to an escaped star is not two wildcards: `\*` is a literal.
    #[test]
    fn wildcard_next_to_escaped_star_is_fine() {
        insta::assert_snapshot!(lint_report(r#"principal.name like "a*\*b""#), @"");
    }

    /// An escaped `\*` is a literal asterisk, not a wildcard, so a pattern of
    /// only escaped stars has no wildcard.
    #[test]
    fn escaped_star_is_not_a_wildcard() {
        insta::assert_snapshot!(lint_report(r#"principal.name like "\*""#), @r#"
         ⚠ `like` pattern `"\*"` contains no wildcard
          ╭────
        1 │ principal.name like "\*"
          · ────────────────────────
          ╰────
         help: this matches only the one exact string; use `==` to compare strings, or add a `*` wildcard
        "#);
    }

    /// The empty pattern is unusual but unambiguous, so it isn't flagged.
    #[test]
    fn empty_pattern_is_not_flagged() {
        insta::assert_snapshot!(lint_report(r#"principal.name like """#), @"");
    }

    /// Each `like` in an expression is checked, in source order.
    #[test]
    fn multiple_likes() {
        insta::assert_snapshot!(
            lint_report(r#"principal.a like "x" && principal.b like "*""#), @r#"
         ⚠ `like` pattern `"x"` contains no wildcard
          ╭────
        1 │ principal.a like "x" && principal.b like "*"
          · ────────────────────
          ╰────
         help: this matches only the one exact string; use `==` to compare strings, or add a `*` wildcard

         ⚠ `like` pattern `"*"` matches every string
          ╭────
        1 │ principal.a like "x" && principal.b like "*"
          ·                         ────────────────────
          ╰────
         help: this comparison is always true for a string operand, so it has no effect
        "#);
    }

    /// A `like` nested inside a larger expression is still found.
    #[test]
    fn nested() {
        insta::assert_snapshot!(lint_report(r#"if principal.a like "x" then 1 else 2"#), @r#"
         ⚠ `like` pattern `"x"` contains no wildcard
          ╭────
        1 │ if principal.a like "x" then 1 else 2
          ·    ────────────────────
          ╰────
         help: this matches only the one exact string; use `==` to compare strings, or add a `*` wildcard
        "#);
    }

    // --- combining a prefix and a suffix pattern on the same operand ---

    /// A prefix and a suffix constraint on one operand combine into one pattern.
    #[test]
    fn prefix_and_suffix_combine() {
        insta::assert_snapshot!(
            lint_report(r#"principal.name like "cs*" && principal.name like "*p""#), @r#"
         ⚠ `like` patterns `"cs*"` and `"*p"` on the same operand combine into one
          ╭────
        1 │ principal.name like "cs*" && principal.name like "*p"
          · ─────────────────────────
          ╰────
         help: the prefix and suffix cannot overlap, so together they are exactly `like "cs*p"`; use that single pattern
        "#);
    }

    /// The order does not matter: suffix first, prefix second.
    #[test]
    fn suffix_first_combines() {
        insta::assert_snapshot!(
            lint_report(r#"principal.name like "*cs" && principal.name like "p*""#), @r#"
         ⚠ `like` patterns `"p*"` and `"*cs"` on the same operand combine into one
          ╭────
        1 │ principal.name like "*cs" && principal.name like "p*"
          · ─────────────────────────
          ╰────
         help: the prefix and suffix cannot overlap, so together they are exactly `like "p*cs"`; use that single pattern
        "#);
    }

    /// The pair is found even with other conjuncts between the two `like`s.
    #[test]
    fn combine_at_a_distance() {
        insta::assert_snapshot!(
            lint_report(r#"principal.name like "a*" && context.ok && principal.name like "*b""#), @r#"
         ⚠ `like` patterns `"a*"` and `"*b"` on the same operand combine into one
          ╭────
        1 │ principal.name like "a*" && context.ok && principal.name like "*b"
          · ────────────────────────
          ╰────
         help: the prefix and suffix cannot overlap, so together they are exactly `like "a*b"`; use that single pattern
        "#);
    }

    /// When the prefix and suffix literals can overlap, the merge would change
    /// meaning (`"a"` matches `"a*" && "*a"` but not `"a*a"`), so nothing is
    /// suggested.
    #[test]
    fn overlapping_literals_do_not_combine() {
        insta::assert_snapshot!(
            lint_report(r#"principal.name like "a*" && principal.name like "*a""#), @"");
        // A shared border also blocks it: `ab` is a suffix of the prefix `ab` and a
        // prefix of the suffix `ab`.
        insta::assert_snapshot!(
            lint_report(r#"principal.name like "ab*" && principal.name like "*ab""#), @"");
    }

    /// Patterns on *different* operands do not combine.
    #[test]
    fn different_operands_do_not_combine() {
        insta::assert_snapshot!(
            lint_report(r#"principal.name like "a*" && principal.email like "*b""#), @"");
    }

    /// Two prefix constraints (or two suffixes) do not combine into one pattern.
    #[test]
    fn two_prefixes_do_not_combine() {
        insta::assert_snapshot!(
            lint_report(r#"principal.name like "a*" && principal.name like "b*""#), @"");
    }

    /// A prefix and a suffix in different disjuncts are not combined — the merge
    /// cannot cross an `||`.
    #[test]
    fn across_disjunction_does_not_combine() {
        insta::assert_snapshot!(
            lint_report(r#"principal.name like "a*" || principal.name like "*b""#), @"");
    }

    /// An anchor with an interior wildcard (`"a*b"`) is not a plain prefix/suffix,
    /// so it is not eligible to combine.
    #[test]
    fn interior_wildcard_anchor_does_not_combine() {
        insta::assert_snapshot!(
            lint_report(r#"principal.name like "a*b" && principal.name like "*c""#), @"");
    }
}
