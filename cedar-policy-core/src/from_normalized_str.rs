use crate::parser::err::{ParseError, ParseErrors};
use std::fmt::Display;
use std::str::FromStr;

/// Trait for parsing "normalized" strings only, throwing an error if a
/// non-normalized string is encountered. See docs on the
/// [`from_normalized_str`] trait function.
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
        let normalized = parsed.to_string();
        if normalized == s {
            // the normalized representation is indeed the one that was provided
            Ok(parsed)
        } else {
            Err(ParseError::ToAST(format!(
                "{} needs to be normalized (e.g., whitespace removed): {s} The normalized form is {normalized}",
                Self::describe_self()
            )).into())
        }
    }

    /// Short string description of the `Self` type, to be used in error messages.
    /// What are we trying to parse?
    fn describe_self() -> &'static str;
}
