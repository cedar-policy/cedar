use crate::parser::err::{ParseError, ParseErrors, ToASTError, ToASTErrorKind};
use crate::parser::Loc;
use std::fmt::Display;
use std::str::FromStr;

/// Trait for parsing "normalized" strings only, throwing an error if a
/// non-normalized string is encountered. See docs on the
/// [`FromNormalizedStr::from_normalized_str`] trait function.
pub trait FromNormalizedStr: FromStr<Err = ParseErrors> + Display {
    /// Create a `Self` by parsing a string, which is required to be normalized.
    /// That is, the input is required to roundtrip with the `Display` impl on `Self`:
    /// `Self::from_normalized_str(x).to_string() == x` must hold.
    ///
    /// In Cedar's context, that means that `from_normalized_str()` will not
    /// accept strings with spurious whitespace (e.g. `A :: B :: C::"foo"`),
    /// Cedar comments (e.g. `A::B::"bar" // comment`), etc. See
    /// [RFC 9](https://github.com/cedar-policy/rfcs/blob/main/text/0009-disallow-whitespace-in-entityuid.md)
    /// for more details and justification.
    ///
    /// For the version that accepts whitespace and Cedar comments, use the
    /// actual `FromStr` implementations.
    fn from_normalized_str(s: &str) -> Result<Self, ParseErrors> {
        let parsed = Self::from_str(s)?;
        let normalized_src = parsed.to_string();
        if normalized_src == s {
            // the normalized representation is indeed the one that was provided
            Ok(parsed)
        } else {
            let diff_byte = s
                .bytes()
                .zip(normalized_src.bytes())
                .enumerate()
                .find(|(_, (b0, b1))| b0 != b1)
                .map(|(idx, _)| idx)
                .unwrap_or(s.len().min(normalized_src.len()));

            Err(ParseError::ToAST(ToASTError::new(
                ToASTErrorKind::NonNormalizedString {
                    kind: Self::describe_self(),
                    src: s.to_string(),
                    normalized_src,
                },
                Loc::new(diff_byte, s.into()),
            ))
            .into())
        }
    }

    /// Short string description of the `Self` type, to be used in error messages.
    /// What are we trying to parse?
    fn describe_self() -> &'static str;
}
