/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
use rustc_lexer::unescape::{unescape_str, EscapeError};
use smol_str::SmolStr;
use std::ops::Range;
use thiserror::Error;

/// Unescape a string following Cedar's string escape rules
pub fn to_unescaped_string(s: &str) -> Result<SmolStr, NonEmpty<UnescapeError>> {
    let mut unescaped_str = String::new();
    let mut errs = Vec::new();
    let mut callback = |range, r| match r {
        Ok(c) => unescaped_str.push(c),
        Err(err) => errs.push(UnescapeError {
            err,
            input: s.to_owned(),
            range,
        }),
    };
    unescape_str(s, &mut callback);
    if let Some((head, tails)) = errs.split_first() {
        Err(NonEmpty {
            head: head.clone(),
            tail: tails.iter().cloned().collect_vec(),
        })
    } else {
        Ok(unescaped_str.into())
    }
}

pub(crate) fn to_pattern(s: &str) -> Result<Vec<PatternElem>, NonEmpty<UnescapeError>> {
    let mut unescaped_str = Vec::new();
    let mut errs = Vec::new();
    let bytes = s.as_bytes(); // to inspect string element in O(1) time
    let mut callback = |range: Range<usize>, r| match r {
        Ok(c) => unescaped_str.push(if c == '*' { PatternElem::Wildcard }else { PatternElem::Char(c) }),
        // PANIC SAFETY By invariant, all passed in ranges must be in range
        #[allow(clippy::indexing_slicing)]
        Err(EscapeError::InvalidEscape)
        // note that the range argument refers to the *byte* offset into the string.
        // so we can compare the byte slice against the bytes of the ``star'' escape sequence.
        if &bytes[range.start..range.end] == r"\*".as_bytes()
            =>
        {
            unescaped_str.push(PatternElem::Char('*'))
        }
        Err(err) => errs.push(UnescapeError { err, input: s.to_owned(), range }),
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
        EscapeError::NonAsciiCharInByteString => EscapeError::NonAsciiCharInByteString,
    }
}

impl std::fmt::Display for UnescapeError {
    // PANIC SAFETY By invariant, the range will always be within the bounds of `input`
    #[allow(clippy::indexing_slicing)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the input `{}` is not a valid escape: {:?}",
            &self.input[self.range.clone()],
            &self.err
        )
    }
}

#[cfg(test)]
mod test {
    use super::to_unescaped_string;
    use crate::ast;
    use crate::parser::{
        err::{ParseError, ParseErrors},
        text_to_cst,
    };

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
    fn test_pattern_escape() {
        // valid ASCII escapes
        let mut errs = ParseErrors::new();
        assert!(
            matches!(text_to_cst::parse_expr(r#""aa" like "\t\r\n\\\0\x42\*""#)
            .expect("failed parsing")
            .to_expr(&mut errs)
            .expect("failed conversion").expr_kind(),
            ast::ExprKind::Like {
                expr: _,
                pattern,
            } if
                pattern.to_string() ==
                format!("{}{}", "\t\r\n\\\0\x42".escape_debug(), r"\*")
            )
        );

        // invalid ASCII escapes
        let mut errs = ParseErrors::new();
        assert!(text_to_cst::parse_expr(r#""abc" like "abc\xFF\xFEdef""#)
            .expect("failed parsing")
            .to_expr(&mut errs)
            .is_none());
        assert!(matches!(
            errs.as_slice(),
            [ParseError::ToAST(_), ParseError::ToAST(_)]
        ));

        // valid `\*` surrounded by chars
        let mut errs = ParseErrors::new();
        assert!(
            matches!(text_to_cst::parse_expr(r#""aaa" like "👀👀\*🤞🤞\*🤝""#)
            .expect("failed parsing")
            .to_expr(&mut errs)
            .expect("failed conversion").expr_kind(),
            ast::ExprKind::Like { expr: _, pattern} if pattern.to_string() == *r"👀👀\*🤞🤞\*🤝")
        );

        // invalid escapes
        let mut errs = ParseErrors::new();
        assert!(text_to_cst::parse_expr(r#""aaa" like "abc\d\bdef""#)
            .expect("failed parsing")
            .to_expr(&mut errs)
            .is_none());
        assert!(matches!(
            errs.as_slice(),
            [ParseError::ToAST(_), ParseError::ToAST(_)]
        ));
    }
}
