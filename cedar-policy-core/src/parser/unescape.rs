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

use crate::ast::PatternElem;
use itertools::Itertools;
use miette::Diagnostic;
use nonempty::NonEmpty;
use rustc_literal_escaper::{unescape_str, EscapeError};
use smol_str::{SmolStr, SmolStrBuilder};
use std::ops::Range;
use thiserror::Error;

/// Unescape a string following Cedar's string escape rules
pub fn to_unescaped_string(s: &str) -> Result<SmolStr, NonEmpty<UnescapeError>> {
    let mut unescaped_str = SmolStrBuilder::new();
    let mut errs = Vec::new();
    let mut callback = |range, r: Result<char, EscapeError>| match r {
        Ok(c) => unescaped_str.push(c),
        // `EscapeError` includes two not-fatal warnings: `UnskippedWhitespaceWarning` and `MultipleSkippedLinesWarning`
        Err(err) if err.is_fatal() => errs.push(UnescapeError {
            err,
            input: s.to_owned(),
            range,
        }),
        Err(_) => (),
    };
    unescape_str(s, &mut callback);
    if let Some((head, tails)) = errs.split_first() {
        Err(NonEmpty {
            head: head.clone(),
            tail: tails.iter().cloned().collect_vec(),
        })
    } else {
        Ok(unescaped_str.finish())
    }
}

pub(crate) fn to_pattern(s: &str) -> Result<Vec<PatternElem>, NonEmpty<UnescapeError>> {
    let mut unescaped_str = Vec::new();
    let mut errs = Vec::new();
    let bytes = s.as_bytes(); // to inspect string element in O(1) time
    let mut callback = |range: Range<usize>, r| match r {
        Ok(c) => unescaped_str.push(if c == '*' { PatternElem::Wildcard }else { PatternElem::Char(c) }),
        #[expect(clippy::indexing_slicing, reason = "By invariant, all passed in ranges must be in range")]
        Err(EscapeError::InvalidEscape)
        // note that the range argument refers to the *byte* offset into the string.
        // so we can compare the byte slice against the bytes of the ``star'' escape sequence.
        if &bytes[range.clone()] == br"\*"
            =>
        {
            unescaped_str.push(PatternElem::Char('*'))
        }
        // `EscapeError` includes two not-fatal warnings: `UnskippedWhitespaceWarning` and `MultipleSkippedLinesWarning`
        Err(err) if err.is_fatal() => errs.push(UnescapeError { err, input: s.to_owned(), range }),
        Err(_) => (),
    };
    unescape_str(s, &mut callback);
    if let Some((head, tails)) = errs.split_first() {
        Err(NonEmpty {
            head: head.clone(),
            tail: tails.iter().cloned().collect_vec(),
        })
    } else {
        Ok(unescaped_str)
    }
}

/// Parse a pattern for the *delimited* `like(pattern, delim)` form.
///
/// Same as [`to_pattern`], but afterwards pairs runs of consecutive `Wildcard`s
/// into `MultiWildcard` elements left-to-right: every pair of adjacent `*`s
/// becomes one `**` (`MultiWildcard`); a leftover trailing `*` stays
/// `Wildcard`.  The source form is preserved byte-for-byte through
/// parse → display → parse (every `**` round-trips as `**`, every `*` as `*`,
/// every escaped `\*` as `\*`).
///
/// Semantically all three parses of `***` under delimited matching
/// (`[Wildcard, MultiWildcard]`, `[MultiWildcard, Wildcard]`, or
/// `[MultiWildcard]`) denote the same regular language `.*` for any delimiter,
/// so the left-to-right pairing is a deliberate choice between
/// equivalent-regex ASTs that keeps source round-trip exact.
///
/// Because `\*` lowers to `Char('*')` in [`to_pattern`], escaped asterisks
/// break a wildcard run — `*\**` stays `[Wildcard, Char('*'), Wildcard]`.
pub(crate) fn to_pattern_delimited(s: &str) -> Result<Vec<PatternElem>, NonEmpty<UnescapeError>> {
    let raw = to_pattern(s)?;
    let mut out: Vec<PatternElem> = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        #[expect(clippy::indexing_slicing, reason = "i < raw.len() by loop condition")]
        let elem = raw[i];
        if matches!(elem, PatternElem::Wildcard) {
            // Count consecutive Wildcards starting at i, then emit
            // `MultiWildcard` for each adjacent pair and one `Wildcard` for a
            // trailing leftover.  E.g. `***` → `[MultiWildcard, Wildcard]`,
            // `****` → `[MultiWildcard, MultiWildcard]`.
            let mut count = 1;
            #[expect(clippy::indexing_slicing, reason = "index checked in the guard")]
            while i + count < raw.len() && matches!(raw[i + count], PatternElem::Wildcard) {
                count += 1;
            }
            for _ in 0..(count / 2) {
                out.push(PatternElem::MultiWildcard);
            }
            if count % 2 == 1 {
                out.push(PatternElem::Wildcard);
            }
            i += count;
        } else {
            out.push(elem);
            i += 1;
        }
    }
    Ok(out)
}

/// Errors generated when processing escapes
#[derive(Debug, Diagnostic, Error, PartialEq, Eq)]
pub struct UnescapeError {
    /// underlying EscapeError
    err: EscapeError,
    /// copy of the input string which had the error
    #[source_code]
    input: String,
    /// Range of the input string where the error occurred
    /// This range must be within the length of `input`
    #[label]
    range: Range<usize>,
}

impl Clone for UnescapeError {
    fn clone(&self) -> Self {
        Self {
            err: clone_escape_error(&self.err),
            input: self.input.clone(),
            range: self.range.clone(),
        }
    }
}

/// [`EscapeError`] doesn't implement clone or copy
fn clone_escape_error(e: &EscapeError) -> EscapeError {
    match e {
        EscapeError::ZeroChars => EscapeError::ZeroChars,
        EscapeError::MoreThanOneChar => EscapeError::MoreThanOneChar,
        EscapeError::LoneSlash => EscapeError::LoneSlash,
        EscapeError::InvalidEscape => EscapeError::InvalidEscape,
        EscapeError::BareCarriageReturn => EscapeError::BareCarriageReturn,
        EscapeError::BareCarriageReturnInRawString => EscapeError::BareCarriageReturnInRawString,
        EscapeError::EscapeOnlyChar => EscapeError::EscapeOnlyChar,
        EscapeError::TooShortHexEscape => EscapeError::TooShortHexEscape,
        EscapeError::InvalidCharInHexEscape => EscapeError::InvalidCharInHexEscape,
        EscapeError::OutOfRangeHexEscape => EscapeError::OutOfRangeHexEscape,
        EscapeError::NoBraceInUnicodeEscape => EscapeError::NoBraceInUnicodeEscape,
        EscapeError::InvalidCharInUnicodeEscape => EscapeError::InvalidCharInUnicodeEscape,
        EscapeError::EmptyUnicodeEscape => EscapeError::EmptyUnicodeEscape,
        EscapeError::UnclosedUnicodeEscape => EscapeError::UnclosedUnicodeEscape,
        EscapeError::LeadingUnderscoreUnicodeEscape => EscapeError::LeadingUnderscoreUnicodeEscape,
        EscapeError::OverlongUnicodeEscape => EscapeError::OverlongUnicodeEscape,
        EscapeError::LoneSurrogateUnicodeEscape => EscapeError::LoneSurrogateUnicodeEscape,
        EscapeError::OutOfRangeUnicodeEscape => EscapeError::OutOfRangeUnicodeEscape,
        EscapeError::UnicodeEscapeInByte => EscapeError::UnicodeEscapeInByte,
        EscapeError::NonAsciiCharInByte => EscapeError::NonAsciiCharInByte,
        EscapeError::NulInCStr => EscapeError::NulInCStr,
        EscapeError::UnskippedWhitespaceWarning => EscapeError::UnskippedWhitespaceWarning,
        EscapeError::MultipleSkippedLinesWarning => EscapeError::MultipleSkippedLinesWarning,
    }
}

impl std::fmt::Display for UnescapeError {
    #[expect(
        clippy::string_slice,
        reason = "By invariant, the range will always be within the bounds of `input`"
    )]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the input `{}` is not a valid escape",
            &self.input[self.range.clone()],
        )
    }
}

#[cfg(test)]
#[expect(clippy::indexing_slicing, reason = "testing")]
mod test {
    use cool_asserts::assert_matches;
    use rustc_literal_escaper::{unescape_str, EscapeError};

    use super::to_unescaped_string;
    use crate::ast;
    use crate::parser::err::{ParseError, ToASTErrorKind};
    use crate::parser::text_to_cst;
    use crate::parser::unescape::to_pattern;

    #[test]
    fn test_string_escape() {
        // refer to this doc for Rust string escapes: http://web.mit.edu/rust-lang_v1.25/arch/amd64_ubuntu1404/share/doc/rust/html/reference/tokens.html

        // valid ASCII escapes
        assert_eq!(
            to_unescaped_string(r"\t\r\n\\\0\x42").expect("valid string"),
            "\t\r\n\\\0\x42"
        );

        // invalid ASCII escapes
        let errs = to_unescaped_string(r"abc\xFFdef").expect_err("should be an invalid escape");
        assert_eq!(errs.len(), 1);

        // valid unicode escapes
        assert_eq!(
            to_unescaped_string(r"\u{0}\u{1}\u{1234}\u{12345}\u{054321}\u{123}\u{42}",)
                .expect("valid string"),
            "\u{000000}\u{001}\u{001234}\u{012345}\u{054321}\u{123}\u{00042}"
        );

        // invalid unicode escapes
        let errs = to_unescaped_string(r"abc\u{1111111}\u{222222222}FFdef")
            .expect_err("should be invalid escapes");
        assert_eq!(errs.len(), 2);

        // invalid escapes
        let errs = to_unescaped_string(r"abc\*\bdef").expect_err("should be invalid escapes");
        assert_eq!(errs.len(), 2);
    }

    #[test]
    fn multiple_skipped_warning() {
        let str = r"lines\


skipped";

        let mut saw_warning = false;
        unescape_str(str, |_, r: Result<char, EscapeError>| match r {
            Err(EscapeError::MultipleSkippedLinesWarning) => {
                saw_warning = true;
            }
            _ => (),
        });
        assert!(saw_warning, "test string should warning");

        assert_eq!(
            to_unescaped_string(str).expect("valid string"),
            r"linesskipped"
        );
        to_pattern(str).unwrap();
    }

    #[test]
    fn unskipped_whitespace_warning() {
        let str = "unicode space\\\n\u{2001}\nnot skipped";
        let mut saw_warning = false;
        unescape_str(str, |_, r: Result<char, EscapeError>| match r {
            Err(EscapeError::UnskippedWhitespaceWarning) => {
                saw_warning = true;
            }
            _ => (),
        });
        assert!(saw_warning, "test string should trigger warning");

        assert_eq!(
            to_unescaped_string(str).expect("valid string"),
            "unicode space\u{2001}\nnot skipped",
        );
        to_pattern(str).unwrap();
    }

    #[test]
    fn test_pattern_escape() {
        // valid ASCII escapes
        assert!(
            matches!(text_to_cst::parse_expr(r#""aa" like "\t\r\n\\\0\x42\*""#)
            .expect("failed parsing")
            .to_expr::<ast::ExprBuilder<()>>()
            .expect("failed conversion").expr_kind(),
            ast::ExprKind::Like {
                expr: _,
                pattern,
            ..
            } if
                pattern.to_string() ==
                format!("{}{}", "\t\r\n\\\0\x42".escape_debug(), r"\*")
            )
        );

        // invalid ASCII escapes
        let errs = text_to_cst::parse_expr(r#""abc" like "abc\xFF\xFEdef""#)
            .expect("failed parsing")
            .to_expr::<ast::ExprBuilder<()>>()
            .unwrap_err();
        assert_eq!(errs.len(), 2);
        assert_matches!(&errs[0], ParseError::ToAST(e) => assert_matches!(e.kind(), ToASTErrorKind::Unescape(_)));
        assert_matches!(&errs[1], ParseError::ToAST(e) => assert_matches!(e.kind(), ToASTErrorKind::Unescape(_)));

        // valid `\*` surrounded by chars
        assert!(
            matches!(text_to_cst::parse_expr(r#""aaa" like "👀👀\*🤞🤞\*🤝""#)
            .expect("failed parsing")
            .to_expr::<ast::ExprBuilder<()>>()
            .expect("failed conversion").expr_kind(),
            ast::ExprKind::Like { expr: _, pattern, .. } if pattern.to_string() == *r"👀👀\*🤞🤞\*🤝")
        );

        // invalid escapes
        let errs = text_to_cst::parse_expr(r#""aaa" like "abc\d\bdef""#)
            .expect("failed parsing")
            .to_expr::<ast::ExprBuilder<()>>()
            .unwrap_err();
        assert_eq!(errs.len(), 2);
        assert_matches!(&errs[0], ParseError::ToAST(e) => assert_matches!(e.kind(), ToASTErrorKind::Unescape(_)));
        assert_matches!(&errs[1], ParseError::ToAST(e) => assert_matches!(e.kind(), ToASTErrorKind::Unescape(_)));
    }

    // Grammar tests for `like(pattern, delim)` syntax (Checkpoint 1).
    // The stub treats delimited like as plain like — delimiter is validated but discarded.
    // These tests will be extended in Checkpoint 2 when the delimiter reaches the evaluator.
    #[test]
    fn test_like_delimited_parses() {
        // Basic: valid delimiter and pattern
        assert!(
            matches!(
                text_to_cst::parse_expr(r#""api.example.com" like("*.example.com", ".")"#)
                    .expect("failed parsing")
                    .to_expr::<ast::ExprBuilder<()>>()
                    .expect("failed conversion")
                    .expr_kind(),
                ast::ExprKind::LikeDelimited {
                    expr: _,
                    pattern: _,
                    ..
                }
            ),
            "like(pattern, delim) should parse and lower to ExprKind::Like"
        );
    }

    #[test]
    fn test_like_delimited_slash_delimiter() {
        assert!(matches!(
            text_to_cst::parse_expr(r#""/v1/chat" like("/v1/*", "/")"#)
                .expect("failed parsing")
                .to_expr::<ast::ExprBuilder<()>>()
                .expect("failed conversion")
                .expr_kind(),
            ast::ExprKind::LikeDelimited {
                expr: _,
                pattern: _,
                ..
            }
        ));
    }

    #[test]
    fn test_like_delimited_escaped_delimiter() {
        // Escape sequences in the delimiter literal are valid
        assert!(matches!(
            text_to_cst::parse_expr(r#""a\tb" like("a\tb", "\t")"#)
                .expect("failed parsing")
                .to_expr::<ast::ExprBuilder<()>>()
                .expect("failed conversion")
                .expr_kind(),
            ast::ExprKind::LikeDelimited {
                expr: _,
                pattern: _,
                ..
            }
        ));
    }

    #[test]
    fn test_like_delimited_double_star_pattern() {
        // ** in a delimited pattern is valid syntax
        assert!(matches!(
            text_to_cst::parse_expr(r#""deep.api.example.com" like("**.example.com", ".")"#)
                .expect("failed parsing")
                .to_expr::<ast::ExprBuilder<()>>()
                .expect("failed conversion")
                .expr_kind(),
            ast::ExprKind::LikeDelimited {
                expr: _,
                pattern: _,
                ..
            }
        ));
    }

    /// Consecutive star runs: `to_pattern_delimited` pairs them left-to-right.
    /// `**` → one `MultiWildcard`.
    /// `***` → `MultiWildcard` + leftover `Wildcard`.
    /// `****` → two `MultiWildcard`.
    /// This keeps source round-trip exact: `Display` emits two chars per
    /// `MultiWildcard` and one per `Wildcard`.
    #[test]
    fn test_like_delimited_star_runs_left_assoc() {
        use super::to_pattern_delimited;
        use crate::ast::{Pattern, PatternElem};

        // `**` → [MultiWildcard]
        let p = to_pattern_delimited("**").unwrap();
        assert_eq!(p, vec![PatternElem::MultiWildcard]);
        assert_eq!(Pattern::from(p).to_string(), "**");

        // `***` → [MultiWildcard, Wildcard]
        let p = to_pattern_delimited("***").unwrap();
        assert_eq!(p, vec![PatternElem::MultiWildcard, PatternElem::Wildcard]);
        assert_eq!(Pattern::from(p).to_string(), "***");

        // `****` → [MultiWildcard, MultiWildcard]
        let p = to_pattern_delimited("****").unwrap();
        assert_eq!(
            p,
            vec![PatternElem::MultiWildcard, PatternElem::MultiWildcard]
        );
        assert_eq!(Pattern::from(p).to_string(), "****");

        // `*****` → [MultiWildcard, MultiWildcard, Wildcard]
        let p = to_pattern_delimited("*****").unwrap();
        assert_eq!(
            p,
            vec![
                PatternElem::MultiWildcard,
                PatternElem::MultiWildcard,
                PatternElem::Wildcard
            ]
        );
        assert_eq!(Pattern::from(p).to_string(), "*****");

        // Escaped star breaks a run: `*\**` → [Wildcard, Char('*'), Wildcard]
        let p = to_pattern_delimited(r"*\**").unwrap();
        assert_eq!(
            p,
            vec![
                PatternElem::Wildcard,
                PatternElem::Char('*'),
                PatternElem::Wildcard
            ]
        );
        // Note: Display re-escapes literal `*` as `\*`.
        assert_eq!(Pattern::from(p).to_string(), r"*\**");

        // `a***b` → [Char('a'), MultiWildcard, Wildcard, Char('b')]
        let p = to_pattern_delimited("a***b").unwrap();
        assert_eq!(
            p,
            vec![
                PatternElem::Char('a'),
                PatternElem::MultiWildcard,
                PatternElem::Wildcard,
                PatternElem::Char('b')
            ]
        );
        assert_eq!(Pattern::from(p).to_string(), "a***b");
    }

    /// All three parses of `a***b` under delimited matching admit the same
    /// strings (cvc5-verified for the SMT encoding; this test verifies the
    /// runtime DP matcher agrees).
    #[test]
    fn test_like_delimited_star_run_equivalence() {
        use crate::ast::{Pattern, PatternElem};

        // Three ASTs that would arise from the three possible parses of `a***b`:
        //   A = a ** b             (one MultiWildcard)
        //   B = a *  ** b           (left-assoc parse: Wildcard + MultiWildcard)
        //   C = a ** *  b           (right-assoc parse: MultiWildcard + Wildcard)
        //
        // Our current parser produces B (left-assoc).  All three should match
        // the same strings — the regex language is `a .* b` in every case.
        let a_pat = Pattern::from(vec![
            PatternElem::Char('a'),
            PatternElem::MultiWildcard,
            PatternElem::Char('b'),
        ]);
        let b_pat = Pattern::from(vec![
            PatternElem::Char('a'),
            PatternElem::Wildcard,
            PatternElem::MultiWildcard,
            PatternElem::Char('b'),
        ]);
        let c_pat = Pattern::from(vec![
            PatternElem::Char('a'),
            PatternElem::MultiWildcard,
            PatternElem::Wildcard,
            PatternElem::Char('b'),
        ]);

        let inputs = [
            "ab", "axb", "a.b", "a.x.b", "a..b", "ax.y.zb", "a....b", "aab", "abb", "axbb", "a",
            "b", "ab.", ".ab",
        ];
        for s in inputs {
            let a = a_pat.wildcard_match_delimited(s, '.');
            let b = b_pat.wildcard_match_delimited(s, '.');
            let c = c_pat.wildcard_match_delimited(s, '.');
            assert_eq!(a, b, "A vs B disagree on {s:?}: a={a}, b={b}");
            assert_eq!(a, c, "A vs C disagree on {s:?}: a={a}, c={c}");
        }
    }

    /// RFC #115: `**` is allowed in any position, not just at the end
    /// (unlike Envoy / OpenAPI / Istio).  Envoy's "`**` must be last" rule
    /// exists for capture disambiguation; Cedar's `like` returns a Boolean
    /// with no capture, so the restriction doesn't apply.  These tests
    /// pin membership answers for interleaved patterns across every
    /// combination of `*` and `**` with literals and delimiters.
    #[test]
    fn test_like_delimited_interleaved_wildcards() {
        use crate::ast::{Pattern, PatternElem};

        // Helper to build a pattern from a mnemonic string: `s` = Wildcard,
        // `S` = MultiWildcard, any other char = literal.
        fn mkpat(mnemonic: &str) -> Pattern {
            Pattern::from(
                mnemonic
                    .chars()
                    .map(|c| match c {
                        's' => PatternElem::Wildcard,
                        'S' => PatternElem::MultiWildcard,
                        c => PatternElem::Char(c),
                    })
                    .collect::<Vec<_>>(),
            )
        }

        // (pattern, delim, text, expected)
        let cases: &[(&str, char, &str, bool)] = &[
            // `**X**` on `aXbXc` — multiple valid decompositions, membership answer still yes.
            ("SXS", '.', "aXbXc", true),
            // `**X**` on `aYb` — no X, no match.
            ("SXS", '.', "aYb", false),
            // `**X**` on `aX.b.c` — `**` crosses delim, so X in middle is fine.
            ("SXS", '.', "aX.b.c", true),
            // `**foo**bar**` with `/`.
            ("SfooSbarS", '/', "/a/foo/b/c/bar/d", true),
            // Missing bar after foo — no match.
            ("SfooSbarS", '/', "/a/foo", false),
            // Empty between `**` and literals.
            ("SfooSbarS", '/', "foobar", true),
            // `*foo**bar*` — leading/trailing non-delim-crossing stars.
            ("sfooSbars", '/', "xfoo/a/b/baryz", true),
            // Leading `*` can't cross `/`, so `/foo...` fails.
            ("sfooSbars", '/', "x/foo/a/bar/y", false),
            // Trailing `*` can't cross `/`.
            ("sfooSbars", '/', "foo/bar/x", false),
            // `**X*Y**` — `*` between X and Y can't cross delim.
            ("SXsYS", '.', "aXYb", true),
            ("SXsYS", '.', "a.X.Y.b", false), // `*` between X and Y can't eat `.`
            ("SXsYS", '.', "aXZYb", true),    // `*` consumes Z
            // Multiple `**`s interleaved with `*`s and literals.
            // `**x*y*z**` with delim `.`:
            // regex `.* x [^.]* y [^.]* z .*`
            ("SxsyszS", '.', "xyz", true), // all empty between literals
            ("SxsyszS", '.', "AxByCzD", true), // non-delim content
            ("SxsyszS", '.', "A.xByCzD", true), // delim before x crossed by **
            ("SxsyszS", '.', "x.y.z", false), // `*` between letters can't cross `.`
            // `**` only in the middle, not at end.
            ("fooSbar", '/', "foo/a/b/bar", true),
            ("fooSbar", '/', "foo/bar", true),
            ("fooSbar", '/', "foobar", true),
            ("fooSbar", '/', "foo/a/b", false), // Missing bar at end
            // `**` at the start only.
            ("Sfoo", '/', "/a/foo", true),
            ("Sfoo", '/', "a/b/foo", true),
            ("Sfoo", '/', "foo/a", false), // Must end with foo
            // Three `**`s interleaved with single literals.
            ("SaSbSc", '/', "x/a/y/b/z/c", true),
            ("SaSbSc", '/', "abc", true),
            ("SaSbSc", '/', "x/a/b/c", true),
            ("SaSbSc", '/', "a/b", false), // Missing c
            // `*` after `**`-crossing: distinguishes from `**` only.
            ("Sfoos", '.', "a.b.foox", true),
            ("Sfoos", '.', "a.b.foo.x", false), // Trailing `*` can't cross `.`
            // `*` before `**`-crossing: leading `*` restricted to one segment.
            ("sfooS", '.', "xfoo.a.b", true),
            ("sfooS", '.', "x.foo.a", false), // Leading `*` can't cross `.`
            // The example that would be ambiguous for a capturing matcher:
            // `**foo**` on `/a/foo/b/foo/c` — multiple decompositions, still yes.
            ("SfooS", '/', "/a/foo/b/foo/c", true),
            ("SfooS", '/', "/a/b/c", false),
        ];

        for (pat_mn, delim, text, expected) in cases {
            let p = mkpat(pat_mn);
            let got = p.wildcard_match_delimited(text, *delim);
            assert_eq!(
                got, *expected,
                "pattern `{pat_mn}` delim `{delim}` on `{text}`: expected {expected}, got {got}"
            );
        }
    }

    #[test]
    fn test_like_delimited_empty_delimiter_error() {
        // Empty delimiter must be rejected
        let errs = text_to_cst::parse_expr(r#""a" like("*", "")"#)
            .expect("failed parsing")
            .to_expr::<ast::ExprBuilder<()>>()
            .unwrap_err();
        assert_eq!(errs.len(), 1);
        assert_matches!(&errs[0], ParseError::ToAST(e) => assert_matches!(e.kind(), ToASTErrorKind::InvalidLikeDelimiter(_)));
    }

    #[test]
    fn test_like_delimited_multi_char_delimiter_error() {
        // Multi-character delimiter must be rejected
        let errs = text_to_cst::parse_expr(r#""a" like("*", "..")"#)
            .expect("failed parsing")
            .to_expr::<ast::ExprBuilder<()>>()
            .unwrap_err();
        assert_eq!(errs.len(), 1);
        assert_matches!(&errs[0], ParseError::ToAST(e) => assert_matches!(e.kind(), ToASTErrorKind::InvalidLikeDelimiter(_)));
    }

    #[test]
    fn test_like_delimited_star_delimiter_error() {
        // `*` is explicitly rejected as a delimiter
        let errs = text_to_cst::parse_expr(r#""a" like("*", "*")"#)
            .expect("failed parsing")
            .to_expr::<ast::ExprBuilder<()>>()
            .unwrap_err();
        assert_eq!(errs.len(), 1);
        assert_matches!(&errs[0], ParseError::ToAST(e) => assert_matches!(e.kind(), ToASTErrorKind::InvalidLikeDelimiter(_)));
    }

    #[test]
    fn test_like_delimited_out_of_range_delimiter_error() {
        // RFC #115: delimiters above U+2FFFF (SMT_LIB_MAX_CODE_POINT) are rejected.
        let errs = text_to_cst::parse_expr(r#""a" like("*", "\u{30000}")"#)
            .expect("failed parsing")
            .to_expr::<ast::ExprBuilder<()>>()
            .unwrap_err();
        assert_eq!(errs.len(), 1);
        assert_matches!(&errs[0], ParseError::ToAST(e) => assert_matches!(e.kind(), ToASTErrorKind::InvalidLikeDelimiter(_)));
    }

    #[test]
    fn test_like_delimited_boundary_delimiter_ok() {
        // The exact boundary U+2FFFF must be accepted.
        assert!(matches!(
            text_to_cst::parse_expr(r#""a" like("*", "\u{2FFFF}")"#)
                .expect("failed parsing")
                .to_expr::<ast::ExprBuilder<()>>()
                .expect("failed conversion")
                .expr_kind(),
            ast::ExprKind::LikeDelimited { .. }
        ));
    }

    #[test]
    fn test_like_delimited_non_string_delimiter_error() {
        // The grammar requires the delimiter to be a string literal token.
        // A boolean, an integer, or an identifier at the delimiter position
        // should all be parse errors.
        let bad_forms = [
            r#""a" like("*", true)"#,
            r#""a" like("*", 1)"#,
            r#""a" like("*", principal)"#,
            r#""a" like("*", context.d)"#,
        ];
        for src in bad_forms {
            let res = text_to_cst::parse_expr(src);
            // Either the CST parse fails, or the CST->AST lowering fails.
            match res {
                Err(_) => {}
                Ok(cst) => {
                    let ast_res = cst.to_expr::<ast::ExprBuilder<()>>();
                    assert!(
                        ast_res.is_err(),
                        "expected parse or lowering error for `{src}`, got ok"
                    );
                }
            }
        }
    }

    #[test]
    fn test_like_delimited_non_string_pattern_error() {
        // The pattern (first argument) must also be a string literal.
        // A non-literal pattern is rejected during CST->AST lowering
        // (into_pattern_delimited returns InvalidPattern).
        let bad_forms = [
            r#""a" like(principal, ".")"#,
            r#""a" like(context.p, ".")"#,
            r#""a" like(true, ".")"#,
            r#""a" like(1, ".")"#,
        ];
        for src in bad_forms {
            let res = text_to_cst::parse_expr(src);
            match res {
                Err(_) => {}
                Ok(cst) => {
                    let ast_res = cst.to_expr::<ast::ExprBuilder<()>>();
                    assert!(
                        ast_res.is_err(),
                        "expected parse or lowering error for `{src}`, got ok"
                    );
                }
            }
        }
    }

    /// Evaluator tests for delimited `like` — check that matching produces the right Boolean.
    ///
    /// Uses `text_to_cst::parse_policyset` + evaluate to reach the full evaluator path.
    #[test]
    fn test_like_delimited_evaluator_hostname() {
        use crate::ast::{Expr, Value};
        use crate::entities::Entities;
        use crate::evaluator::Evaluator;
        use crate::extensions::Extensions;

        // Helper: parse a Cedar expression, evaluate it in an empty environment.
        fn eval_bool(src: &str) -> bool {
            let expr: Expr = text_to_cst::parse_expr(src)
                .expect("failed parsing")
                .to_expr::<ast::ExprBuilder<()>>()
                .expect("failed conversion");
            let ext = Extensions::all_available();
            let entities = Entities::new();
            let request = crate::ast::Request::new_unchecked(
                crate::ast::EntityUIDEntry::unknown(),
                crate::ast::EntityUIDEntry::unknown(),
                crate::ast::EntityUIDEntry::unknown(),
                None,
            );
            let eval = Evaluator::new(request, &entities, ext);
            match eval.interpret(&expr, &std::collections::HashMap::new()) {
                Ok(Value {
                    value: crate::ast::ValueKind::Lit(crate::ast::Literal::Bool(b)),
                    ..
                }) => b,
                Ok(v) => panic!("expected Bool, got {v:?}"),
                Err(e) => panic!("evaluation error: {e:?}"),
            }
        }

        // Hostname table from the RFC
        assert!(
            eval_bool(r#""api.example.com" like("*.example.com", ".")"#),
            "one subdomain should match"
        );
        assert!(
            !eval_bool(r#""example.com" like("*.example.com", ".")"#),
            "bare host should not match (literal `.` needs a char)"
        );
        assert!(
            !eval_bool(r#""deep.api.example.com" like("*.example.com", ".")"#),
            "multi-level should not match `*`"
        );
        assert!(
            eval_bool(r#""deep.api.example.com" like("**.example.com", ".")"#),
            "multi-level should match `**`"
        );
        assert!(
            !eval_bool(r#""example.com" like("**.example.com", ".")"#),
            "`**` still needs a leading segment"
        );
        assert!(
            eval_bool(r#""tenant-api.example.com" like("*-api.example.com", ".")"#),
            "wildcard inside label"
        );
        assert!(
            !eval_bool(r#""deep.api.example.com" like("*", ".")"#),
            "`*` alone cannot cross delimiter"
        );
        assert!(
            eval_bool(r#""deep.api.example.com" like("**", ".")"#),
            "`**` alone matches everything"
        );
        // api.**.com pattern
        assert!(
            eval_bool(r#""api.x.y.com" like("api.**.com", ".")"#),
            "middle `**` matches multi-segment"
        );
        assert!(
            !eval_bool(r#""api.com" like("api.**.com", ".")"#),
            "middle `**` requires at least one segment"
        );
    }

    #[test]
    fn test_like_delimited_evaluator_paths() {
        use crate::ast::{Expr, Value};
        use crate::entities::Entities;
        use crate::evaluator::Evaluator;
        use crate::extensions::Extensions;

        fn eval_bool(src: &str) -> bool {
            let expr: Expr = text_to_cst::parse_expr(src)
                .expect("failed parsing")
                .to_expr::<ast::ExprBuilder<()>>()
                .expect("failed conversion");
            let ext = Extensions::all_available();
            let entities = Entities::new();
            let request = crate::ast::Request::new_unchecked(
                crate::ast::EntityUIDEntry::unknown(),
                crate::ast::EntityUIDEntry::unknown(),
                crate::ast::EntityUIDEntry::unknown(),
                None,
            );
            let eval = Evaluator::new(request, &entities, ext);
            match eval.interpret(&expr, &std::collections::HashMap::new()) {
                Ok(Value {
                    value: crate::ast::ValueKind::Lit(crate::ast::Literal::Bool(b)),
                    ..
                }) => b,
                Ok(v) => panic!("expected Bool, got {v:?}"),
                Err(e) => panic!("evaluation error: {e:?}"),
            }
        }

        // URL path table
        assert!(eval_bool(
            r#""/repos/o/pulls/1/reviews" like("/repos/*/pulls/*/reviews", "/")"#
        ));
        assert!(!eval_bool(
            r#""/repos/o/sub/pulls/1/reviews" like("/repos/*/pulls/*/reviews", "/")"#
        ));
        assert!(eval_bool(r#""a/b/error.log" like("**/error.log", "/")"#));
        assert!(eval_bool(r#""/v1/chat" like("/v1/**", "/")"#));
        assert!(!eval_bool(r#""/v1" like("/v1/**", "/")"#));
        // Zero-or-more: `/api/*/admin` admits `/api//admin`
        assert!(eval_bool(r#""/api//admin" like("/api/*/admin", "/")"#));
    }

    #[test]
    fn test_like_undelimited_still_works() {
        // Original `like` syntax is unchanged
        assert!(matches!(
            text_to_cst::parse_expr(r#""x.y" like "*""#)
                .expect("failed parsing")
                .to_expr::<ast::ExprBuilder<()>>()
                .expect("failed conversion")
                .expr_kind(),
            ast::ExprKind::Like {
                expr: _,
                pattern: _,
                ..
            }
        ));
    }
}
