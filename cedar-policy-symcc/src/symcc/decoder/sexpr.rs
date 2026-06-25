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

//! S-expression tokenizer and parser for SMT-LIB 2.

use std::collections::VecDeque;

use itertools::Itertools;
use miette::Diagnostic;
use smol_str::{SmolStr, SmolStrBuilder};
use thiserror::Error;

use crate::{bitvec::BitVec, symcc::encoder::SMT_LIB_MAX_CODE_POINT, type_abbrevs::Width};

/// Errors during s-expression parsing
#[derive(Debug, Diagnostic, Error)]
pub enum SExprParseError {
    /// Unexpected end of input.
    #[error("Unexpected end of input")]
    UnexpectedEnd,
    /// UTF-8 decoding error.
    #[error("Invalid UTF-8 sequence: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    /// Failed to parse an SMT string.
    #[error("Failed to parse string: {0:?}")]
    StringParseError(Vec<u8>),
    /// Failed to parse an SMT numeral.
    #[error("Invalid numeric token: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    /// Unclosed S-expression.
    #[error("Unclosed S-expression")]
    UnclosedSExpr,
    /// Trailing unparsed tokens.
    #[error("Trailing tokens")]
    TrailingTokens,
    /// Integer overflow.
    #[error("Integer overflow")]
    IntegerOverflow,
    /// Bitvector of a zero width, which we do not support.
    #[error("Bitvector of zero width")]
    ZeroWidthBitVec,
}

// Types of tokens
#[derive(Debug)]
enum Token {
    LeftParen,
    RightParen,
    Atom(SExpr),
}

/// S-expressions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SExpr {
    BitVec(BitVec),
    Numeral(u128),
    String(SmolStr),
    Symbol(SmolStr),
    App(Vec<SExpr>),
}

/// This function decodes a string encoded in SMT-LIB 2 format
/// as a Rust string.
///
/// It handles two escape sequences:
/// - Parser-level escape sequence `""` (which represents `"`)
///   (per https://smt-lib.org/papers/smt-lib-reference-v2.7-r2025-07-07.pdf)
/// - Theory-level escape sequence for Unicode characters:
///   convert any of the following to the corresponding Unicode character
///   (see https://smt-lib.org/theories-UnicodeStrings.shtml):
///   - \ud₃d₂d₁d₀
///   - \u{d₀}
///   - \u{d₁d₀}
///   - \u{d₂d₁d₀}
///   - \u{d₃d₂d₁d₀}
///   - \u{d₄d₃d₂d₁d₀}
///
/// See also:
/// - The (right) inverse: `encode_string`
/// - The concrete C++ implementation in cvc5, which this function mimics
///   https://github.com/cvc5/cvc5/blob/b78e7ed23348659db52a32765ad181ae0c26bbd5/src/util/string.cpp#L136
fn decode_string(s: &[u8]) -> Option<SmolStr> {
    let mut out = SmolStrBuilder::new();

    // Helper function to read the byte as a hexadecimal digit
    let as_hex = |c: u8| {
        if c.is_ascii_digit() {
            Some(u32::from(c - b'0'))
        } else if (b'a'..=b'f').contains(&c) {
            Some(u32::from(c - b'a' + 10))
        } else if (b'A'..=b'F').contains(&c) {
            Some(u32::from(c - b'A' + 10))
        } else {
            None
        }
    };

    let mut i: usize = 0;

    while i < s.len() {
        #[expect(
            clippy::indexing_slicing,
            reason = "i < s.len() thus indexing by i should not panic"
        )]
        let c = s[i];

        if c != b'\\' {
            if c != b'"' {
                out.push(c as char);
                i += 1;
            } else {
                out.push('"');

                #[expect(
                    clippy::indexing_slicing,
                    reason = "i + 1 < s.len() thus indexing by i + 1 should not panic"
                )]
                if i + 1 < s.len() && s[i + 1] == b'"' {
                    // `""` is interpreted as `"` (per SMT-LIB 2.7 standard).
                    //
                    // NOTE: In cvc5, this happens in a separate parser pass, but
                    // we merge it with the theory-level escape sequence handling.
                    // This is ok because `"` should not occur in any valid
                    // theory-level escape sequence.
                    i += 2;
                } else {
                    // This case is technically not allowed by the lexer,
                    // but we silently accept it anyway.
                    i += 1;
                }
            }
            continue;
        }

        let esc_start = i;
        let mut is_esc = false;

        #[expect(
            clippy::indexing_slicing,
            reason = "i + 1 < s.len() thus indexing by i + 1 should not panic"
        )]
        if i + 1 < s.len() && s[i + 1] == b'u' {
            i += 2;
            #[expect(
                clippy::indexing_slicing,
                reason = "i < s.len() thus indexing by i should not panic"
            )]
            if i < s.len() && s[i] == b'{' {
                i += 1;

                // Code point value
                let mut v: u32 = 0;

                // Find the closing brace in range [i + 1, i + 5]
                let mut j = i;
                let mut failed = false;

                #[expect(
                    clippy::indexing_slicing,
                    reason = "j < s.len() thus indexing by j should not panic"
                )]
                while j < s.len() && s[j] != b'}' && j <= i + 5 {
                    if let Some(d) = as_hex(s[j]) {
                        v = (v << 4) | d;
                        j += 1;
                    } else {
                        failed = true;
                        break;
                    }
                }

                // At least one digit is required
                if j > i && !failed {
                    #[expect(
                        clippy::indexing_slicing,
                        reason = "j < s.len() thus indexing by j should not panic"
                    )]
                    if j < s.len() && s[j] == b'}' && v <= SMT_LIB_MAX_CODE_POINT {
                        // Found the closing brace
                        out.push(char::from_u32(v)?);
                        is_esc = true;
                        i = j + 1;
                    }
                }
            } else {
                // No brace, we expect exactly 4 hex digits
                if i + 3 < s.len() {
                    #[expect(
                        clippy::indexing_slicing,
                        reason = "i + 3 < s.len() thus indexing by i .. i + 3 should not panic"
                    )]
                    if let (Some(d1), Some(d2), Some(d3), Some(d4)) = (
                        as_hex(s[i]),
                        as_hex(s[i + 1]),
                        as_hex(s[i + 2]),
                        as_hex(s[i + 3]),
                    ) {
                        out.push(char::from_u32(d1 << 12 | d2 << 8 | d3 << 4 | d4)?);
                        is_esc = true;
                        i += 4;
                    }
                }
            }
        }

        // If we fail to parse the escape sequence,
        // treat `\` as a normal character
        if !is_esc {
            out.push(c as char);
            i = esc_start + 1;
        }
    }

    Some(out.finish())
}

/// Tokenizes a string of SMT-LIB 2 S-expressions
/// Reference: https://smtlib.github.io/jSMTLIB/SMTLIBTutorial.pdf, Table 3.1
fn tokenize(src: &[u8]) -> Result<Vec<Token>, SExprParseError> {
    let mut i = 0;

    let mut in_str = false;
    let mut str_start = 0;

    let mut tokens = Vec::new();

    while i < src.len() {
        #[expect(
            clippy::indexing_slicing,
            reason = "i < src.len() thus indexing by i should not panic"
        )]
        let c = src[i];

        if in_str {
            match c {
                b'"' => {
                    #[expect(
                        clippy::indexing_slicing,
                        reason = "i + 1 < src.len() thus indexing by i + 1 should not panic"
                    )]
                    if i + 1 < src.len() && src[i + 1] == b'"' {
                        // Two double quotes ("") is an escape sequence
                        // or a single double quote (") per SMT-LIB 2 spec
                        i += 2;
                    } else {
                        // String is terminated
                        #[expect(
                            clippy::indexing_slicing,
                            reason = "invariant str_start <= i and i <= src.len() thus slicing should not panic"
                        )]
                        let lit = decode_string(&src[str_start..i]).ok_or_else(|| {
                            SExprParseError::StringParseError(src[str_start..i].to_vec())
                        })?;
                        tokens.push(Token::Atom(SExpr::String(lit)));
                        in_str = false;
                        i += 1;
                    }
                }

                _ => i += 1,
            }
        } else {
            match c {
                b'"' => {
                    in_str = true;
                    str_start = i + 1;
                    i += 1;
                }

                b'(' => {
                    tokens.push(Token::LeftParen);
                    i += 1;
                }

                b')' => {
                    tokens.push(Token::RightParen);
                    i += 1;
                }

                // Bit vector literal (#b or #x)
                b'#' => {
                    if i + 1 < src.len() {
                        #[expect(
                            clippy::indexing_slicing,
                            reason = "i + 1 < src.len() thus indexing by i + 1 should not panic"
                        )]
                        let (radix, bits_per_digit, is_digit): (
                            u32,
                            usize,
                            fn(u8) -> bool,
                        ) = match src[i + 1] {
                            // Binary representation
                            b'b' => (2, 1, |c| c == b'0' || c == b'1'),
                            // Hex representation
                            b'x' => (16, 4, |c| c.is_ascii_hexdigit()),
                            _ => return Err(SExprParseError::UnexpectedEnd),
                        };

                        i += 2;
                        let start = i;
                        #[expect(
                            clippy::indexing_slicing,
                            reason = "i < src.len() thus indexing by i should not panic"
                        )]
                        while i < src.len() && is_digit(src[i]) {
                            i += 1;
                        }

                        let width: usize = (i - start) * bits_per_digit;
                        #[expect(
                            clippy::indexing_slicing,
                            reason = "start <= i <= src.len() thus slicing should not panic"
                        )]
                        let num = str::from_utf8(&src[start..i])?;
                        let num = u128::from_str_radix(num, radix)?;

                        // Do a sign-extension from i<width> to i<128>
                        let num = if width != 0 && width < 128 && (1u128 << (width - 1)) & num != 0
                        {
                            ((u128::MAX << width) | num) as i128
                        } else {
                            num as i128
                        };

                        let width =
                            u32::try_from(width).map_err(|_| SExprParseError::IntegerOverflow)?;
                        let width = Width::new(width).ok_or(SExprParseError::ZeroWidthBitVec)?;

                        tokens.push(Token::Atom(SExpr::BitVec(BitVec::of_int(
                            width,
                            num.into(),
                        ))));
                    } else {
                        return Err(SExprParseError::UnexpectedEnd);
                    }
                }

                // Numeral
                c if c.is_ascii_digit() => {
                    // Read until a non-digit
                    let start = i;
                    #[expect(
                        clippy::indexing_slicing,
                        reason = "i < src.len() thus indexing by i should not panic"
                    )]
                    while i < src.len() && src[i].is_ascii_digit() {
                        i += 1;
                    }

                    #[expect(
                        clippy::indexing_slicing,
                        reason = "start <= i <= src.len() ===> slicing should not panic"
                    )]
                    let num = str::from_utf8(&src[start..i])?;
                    let num = num.parse::<u128>()?;

                    tokens.push(Token::Atom(SExpr::Numeral(num)));
                }

                // Comment
                b';' =>
                {
                    #[expect(
                        clippy::indexing_slicing,
                        reason = "i < src.len() thus indexing src by i should not panic"
                    )]
                    while i < src.len() && src[i] != b'\n' {
                        i += 1;
                    }
                }

                c if c.is_ascii_whitespace() => i += 1,

                // Symbol
                // TODO: this doesn't quite align with the SMT-LIB 2 spec
                // e.g. we don't allow whitespaces in quoted symbols
                // but it should suffice for (get-model)
                _ => {
                    // Take until (, ), or whitespace
                    let start = i;
                    #[expect(
                        clippy::indexing_slicing,
                        reason = "i < src.len() thus indexing by I should not panic"
                    )]
                    while i < src.len()
                        && src[i] != b'('
                        && src[i] != b')'
                        && src[i] != b';'
                        && src[i] != b'"'
                        && src[i] != b'#'
                        && !src[i].is_ascii_whitespace()
                    {
                        i += 1;
                    }
                    #[expect(
                        clippy::indexing_slicing,
                        reason = "start <= i and i <= src.len ==> slicing should not panic"
                    )]
                    let symbol = str::from_utf8(&src[start..i])?;

                    tokens.push(Token::Atom(SExpr::Symbol(symbol.into())));
                }
            }
        }
    }

    if in_str {
        return Err(SExprParseError::UnexpectedEnd);
    }

    Ok(tokens)
}

/// Parses the input source as an S-expression
pub fn parse_sexpr(src: &[u8]) -> Result<SExpr, SExprParseError> {
    let mut stack = VecDeque::new();

    let tokens = tokenize(src)?;
    let token_count = tokens.len();

    for (i, token) in tokens.into_iter().enumerate() {
        match token {
            Token::LeftParen => stack.push_back(Vec::new()),
            Token::RightParen => {
                let Some(exprs) = stack.pop_back() else {
                    return Err(SExprParseError::UnclosedSExpr);
                };

                if let Some(last) = stack.back_mut() {
                    last.push(SExpr::App(exprs));
                } else {
                    // Succeed if there is no trailing tokens
                    if i + 1 == token_count {
                        return Ok(SExpr::App(exprs));
                    } else {
                        return Err(SExprParseError::TrailingTokens);
                    }
                }
            }
            Token::Atom(s) => {
                if let Some(last) = stack.back_mut() {
                    last.push(s);
                } else {
                    // Succeed if there is no trailing tokens
                    if i + 1 == token_count {
                        return Ok(s);
                    } else {
                        return Err(SExprParseError::TrailingTokens);
                    }
                }
            }
        }
    }

    Err(SExprParseError::UnexpectedEnd)
}

impl std::fmt::Display for SExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SExpr::BitVec(bv) => write!(f, "{:?}", bv),
            SExpr::Numeral(n) => write!(f, "{}", n),
            SExpr::String(s) => write!(f, "\"{}\"", s),
            SExpr::Symbol(s) => write!(f, "{}", s),
            SExpr::App(exprs) => write!(f, "({})", exprs.iter().map(|e| e.to_string()).join(" ")),
        }
    }
}

#[cfg(test)]
mod string_encode_decode_test {
    use crate::symcc::encoder::encode_string;

    use super::*;

    #[test]
    fn test_string_decode() {
        assert_eq!(decode_string(b"").unwrap(), "");
        assert_eq!(decode_string(b"hello").unwrap(), "hello");
        assert_eq!(decode_string(b"\"\"hello\"\"").unwrap(), "\"hello\"");
        // Invalid unicode escape sequences with braces
        assert_eq!(decode_string(b"\\u").unwrap(), "\\u");
        assert_eq!(decode_string(b"\\u{").unwrap(), "\\u{");
        assert_eq!(decode_string(b"\\u{1").unwrap(), "\\u{1");
        assert_eq!(decode_string(b"\\u{1d").unwrap(), "\\u{1d");
        assert_eq!(decode_string(b"\\u{1dc").unwrap(), "\\u{1dc");
        assert_eq!(decode_string(b"\\u{1dce").unwrap(), "\\u{1dce");
        assert_eq!(decode_string(b"\\u{1dcx}").unwrap(), "\\u{1dcx}");
        assert_eq!(decode_string(b"\\u{1dcef").unwrap(), "\\u{1dcef");
        assert_eq!(decode_string(b"\\u\"\"").unwrap(), "\\u\"");
        assert_eq!(decode_string(b"\\u{32344}").unwrap(), "\\u{32344}");
        // Invalid unicode escape sequences without braces
        assert_eq!(decode_string(b"\\u123").unwrap(), "\\u123");
        assert_eq!(decode_string(b"\\u12").unwrap(), "\\u12");
        assert_eq!(decode_string(b"\\u**").unwrap(), "\\u**");
        assert_eq!(decode_string(b"\\u****").unwrap(), "\\u****");
        assert_eq!(decode_string(b"\\u0").unwrap(), "\\u0");
        // Other invalid escape sequences
        assert_eq!(decode_string(b"\\x").unwrap(), "\\x");
        assert_eq!(decode_string(b"\\n").unwrap(), "\\n");
        assert_eq!(decode_string(b"\\t\\n\\u").unwrap(), "\\t\\n\\u");
        // Valid escape sequences
        assert_eq!(decode_string(b"\\u{1dcef}").unwrap(), "\u{1dcef}");
        assert_eq!(decode_string(b"\\u{1DcEf}").unwrap(), "\u{1dcef}");
        assert_eq!(decode_string(b"\\u{1dce}").unwrap(), "\u{1dce}");
        assert_eq!(decode_string(b"\\\\u{1dce}").unwrap(), "\\\u{1dce}");
        assert_eq!(decode_string(b"\\u1234").unwrap(), "\u{1234}");
        assert_eq!(decode_string(b"\\uffff").unwrap(), "\u{ffff}");
        assert_eq!(decode_string(b"\\u{0}").unwrap(), "\u{0}");
        assert_eq!(decode_string(b"\\u{01}").unwrap(), "\u{01}");
        assert_eq!(decode_string(b"\\u{a01}").unwrap(), "\u{a01}");
        assert_eq!(decode_string(b"\\u{a01b}").unwrap(), "\u{a01b}");
    }

    #[test]
    fn test_string_encode() {
        let strs = [
            "",
            "hello",
            "\"hello\"",
            "\\u",
            "\\u{",
            "\\u{1",
            "\\u{1d",
            "\\u{1dc",
            "\\u{1dce",
            "\\u{1dcx}",
            "\\u{1dcef",
            "\\u\"\"",
            "\\u{32344}",
            "\\u123",
            "\\u12",
            "\\u**",
            "\\u0",
            "\\x",
            "\\n",
            "\\t\\n\\u",
            "\\u{1dcef}",
            "\\u{1DcEf}",
            "\\u{1dce}",
            "\\\\u{1dce}",
            "\\u1234",
            "\\uffff",
            "\\u{0}",
            "\\u{01}",
            "\\u{a01}",
            "\\u{a01b}",
            "\u{1dcef}",
            "\u{1dce}",
            "\u{ffff}",
            "\u{0}",
            "\u{a01b}",
            "abc\u{29999}d",
        ];

        assert_eq!(encode_string("\u{33333}"), None);
        assert_eq!(encode_string("abc\u{30000}d"), None);

        for s in strs {
            let enc = encode_string(s).unwrap();
            assert_eq!(decode_string(enc.as_bytes()).unwrap(), s);
        }
    }
}

#[cfg(test)]
mod test_sexpr_parse {
    use std::num::IntErrorKind;

    use crate::type_abbrevs::Width;

    use super::*;
    use cool_asserts::assert_matches;

    #[test]
    fn numeral() {
        assert_eq!(parse_sexpr(b"0").unwrap(), SExpr::Numeral(0));
        assert_eq!(parse_sexpr(b"00").unwrap(), SExpr::Numeral(0));
        assert_eq!(parse_sexpr(b"01").unwrap(), SExpr::Numeral(1));
        assert_eq!(parse_sexpr(b"42").unwrap(), SExpr::Numeral(42));
        assert_eq!(parse_sexpr(b"999").unwrap(), SExpr::Numeral(999));
    }

    #[test]
    fn string() {
        assert_eq!(parse_sexpr(b"\"\"").unwrap(), SExpr::String("".into()));
        assert_eq!(
            parse_sexpr(b"\"hello\"").unwrap(),
            SExpr::String("hello".into())
        );
        assert_eq!(
            parse_sexpr(b"\"a b c\"").unwrap(),
            SExpr::String("a b c".into())
        );
        assert_eq!(
            parse_sexpr(b"\"\"\"\"").unwrap(),
            SExpr::String("\"".into())
        );
    }

    #[test]
    fn symbol() {
        assert_eq!(parse_sexpr(b"foo").unwrap(), SExpr::Symbol("foo".into()));
        assert_eq!(
            parse_sexpr(b"bar123").unwrap(),
            SExpr::Symbol("bar123".into())
        );
        assert_eq!(parse_sexpr(b"a+b").unwrap(), SExpr::Symbol("a+b".into()));
    }

    #[test]
    fn app() {
        assert_eq!(parse_sexpr(b"()").unwrap(), SExpr::App(vec![]));
        assert_eq!(
            parse_sexpr(b"(foo)").unwrap(),
            SExpr::App(vec![SExpr::Symbol("foo".into())])
        );
        assert_eq!(
            parse_sexpr(b"(add 1 2)").unwrap(),
            SExpr::App(vec![
                SExpr::Symbol("add".into()),
                SExpr::Numeral(1),
                SExpr::Numeral(2)
            ])
        );
        assert_eq!(
            parse_sexpr(b"(() (() ()) (()))").unwrap(),
            SExpr::App(vec![
                SExpr::App(vec![]),
                SExpr::App(vec![SExpr::App(vec![]), SExpr::App(vec![])]),
                SExpr::App(vec![SExpr::App(vec![])]),
            ])
        );
    }

    #[test]
    fn bitvec() {
        assert_eq!(
            parse_sexpr(b"#b0").unwrap(),
            SExpr::BitVec(BitVec::of_u128(Width::new(1).unwrap(), 0))
        );
        assert_eq!(
            parse_sexpr(b"#b1").unwrap(),
            SExpr::BitVec(BitVec::of_u128(Width::new(1).unwrap(), 1))
        );
        assert_eq!(
            parse_sexpr(b"#b01").unwrap(),
            SExpr::BitVec(BitVec::of_u128(Width::new(2).unwrap(), 1))
        );
        assert_eq!(
            parse_sexpr(b"#b11").unwrap(),
            SExpr::BitVec(BitVec::of_int(Width::new(2).unwrap(), (-1).into()))
        );
    }

    #[test]
    fn bitvec_hex() {
        assert_eq!(
            parse_sexpr(b"#x0").unwrap(),
            SExpr::BitVec(BitVec::of_u128(Width::new(4).unwrap(), 0))
        );
        assert_eq!(
            parse_sexpr(b"#xF").unwrap(),
            SExpr::BitVec(BitVec::of_int(Width::new(4).unwrap(), (-1).into()))
        );
        assert_eq!(
            parse_sexpr(b"#xff").unwrap(),
            SExpr::BitVec(BitVec::of_int(Width::new(8).unwrap(), (-1).into()))
        );
        assert_eq!(
            parse_sexpr(b"#x0A").unwrap(),
            SExpr::BitVec(BitVec::of_u128(Width::new(8).unwrap(), 10))
        );
        assert_eq!(
            parse_sexpr(b"#xDEAD").unwrap(),
            SExpr::BitVec(BitVec::of_u128(Width::new(16).unwrap(), 0xDEAD))
        );
    }

    #[test]
    fn bitvec_indexed() {
        assert_eq!(
            parse_sexpr(b"(_ bv0 8)").unwrap(),
            SExpr::App(vec![
                SExpr::Symbol("_".into()),
                SExpr::Symbol("bv0".into()),
                SExpr::Numeral(8),
            ])
        );
    }

    #[test]
    fn whitespace() {
        let expected = SExpr::App(vec![SExpr::Symbol("a".into()), SExpr::Symbol("b".into())]);
        assert_eq!(parse_sexpr(b"(a b)").unwrap(), expected);
        assert_eq!(parse_sexpr(b"(a  b)").unwrap(), expected);
        assert_eq!(parse_sexpr(b"(a\nb)").unwrap(), expected);
        assert_eq!(parse_sexpr(b"(a\tb)").unwrap(), expected);
        assert_eq!(parse_sexpr(b"  (a b)  ").unwrap(), expected);
    }

    #[test]
    fn comments() {
        let expected = SExpr::App(vec![SExpr::Symbol("foo".into())]);
        assert_eq!(parse_sexpr(b"; comment\n(foo)").unwrap(), expected);
        assert_eq!(parse_sexpr(b"(foo); comment").unwrap(), expected);
        assert_eq!(parse_sexpr(b"; c1\n(foo); c2\n").unwrap(), expected);
        assert_eq!(
            parse_sexpr(b"foo; c2").unwrap(),
            SExpr::Symbol("foo".into())
        );
    }

    #[test]
    fn errors() {
        assert_matches!(
            parse_sexpr(b"\"unclosed"),
            Err(SExprParseError::UnexpectedEnd)
        );
        assert_matches!(
            parse_sexpr(b"(unclosed"),
            Err(SExprParseError::UnexpectedEnd)
        );
        assert_matches!(parse_sexpr(b")"), Err(SExprParseError::UnclosedSExpr));
        assert_matches!(parse_sexpr(b"a b"), Err(SExprParseError::TrailingTokens));
        assert_matches!(
            parse_sexpr(b"(a) (b)"),
            Err(SExprParseError::TrailingTokens)
        );
        assert_matches!(parse_sexpr(b"#"), Err(SExprParseError::UnexpectedEnd));
        assert_matches!(
            parse_sexpr(b"#b"),
            Err(SExprParseError::ParseIntError(e)) if e.kind() == &IntErrorKind::Empty
        );
        assert_matches!(
            parse_sexpr(b"#b111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"),
            Err(SExprParseError::ParseIntError(e)) if e.kind() == &IntErrorKind::PosOverflow
        );
        assert_matches!(
            parse_sexpr(b"#x"),
            Err(SExprParseError::ParseIntError(e)) if e.kind() == &IntErrorKind::Empty
        );
        assert_matches!(
            parse_sexpr(b"#xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1"),
            Err(SExprParseError::ParseIntError(e)) if e.kind() == &IntErrorKind::PosOverflow
        );
        assert_matches!(parse_sexpr(b"#y"), Err(SExprParseError::UnexpectedEnd));
        assert_matches!(parse_sexpr(b""), Err(SExprParseError::UnexpectedEnd));
        assert_matches!(parse_sexpr(b"  "), Err(SExprParseError::UnexpectedEnd));
        assert_matches!(
            parse_sexpr(b"; comment\n"),
            Err(SExprParseError::UnexpectedEnd)
        );
    }
}
