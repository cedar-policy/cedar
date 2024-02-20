use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::{parser::err::ParseErrors, FromNormalizedStr};

/// Identifiers. Anything in `Id` should be a valid identifier, this means it
/// does not contain, for instance, spaces or characters like '+'; and also is
/// not one of the Cedar reserved identifiers (at time of writing,
/// `true | false | if | then | else | in | is | like | has`).
//
// For now, internally, `Id`s are just owned `SmolString`s.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Hash, PartialOrd, Ord)]
pub struct Id(SmolStr);

impl Id {
    /// Create a new `Id` from a `String`, where it is the caller's
    /// responsibility to ensure that the string is indeed a valid identifier.
    ///
    /// When possible, callers should not use this, and instead use `s.parse()`,
    /// which checks that `s` is a valid identifier, and returns a parse error
    /// if not.
    ///
    /// This method was created for the `From<cst::Ident> for Id` impl to use.
    /// Since `parser::parse_ident()` implicitly uses that `From` impl itself,
    /// if we tried to make that `From` impl go through `.parse()` like everyone
    /// else, we'd get infinite recursion.  And, we assert that `cst::Ident` is
    /// always already checked to contain a valid identifier, otherwise it would
    /// never have been created.
    pub(crate) fn new_unchecked(s: impl Into<SmolStr>) -> Id {
        Id(s.into())
    }

    /// Get the underlying string
    pub fn into_smolstr(self) -> SmolStr {
        self.0
    }
}

impl AsRef<str> for Id {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.0)
    }
}

// allow `.parse()` on a string to make an `Id`
impl std::str::FromStr for Id {
    type Err = ParseErrors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::parser::parse_ident(s)
    }
}

impl FromNormalizedStr for Id {
    fn describe_self() -> &'static str {
        "Id"
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Id {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // identifier syntax:
        // IDENT     := ['_''a'-'z''A'-'Z']['_''a'-'z''A'-'Z''0'-'9']* - RESERVED
        // BOOL      := 'true' | 'false'
        // RESERVED  := BOOL | 'if' | 'then' | 'else' | 'in' | 'is' | 'like' | 'has'

        let construct_list = |s: &str| s.chars().collect::<Vec<char>>();
        let list_concat = |s1: &[char], s2: &[char]| [s1, s2].concat();
        // the set of the first character of an identifier
        let head_letters = construct_list("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_");
        // the set of the remaining characters of an identifier
        let tail_letters = list_concat(&construct_list("0123456789"), &head_letters);
        // identifier character count minus 1
        let remaining_length = u.int_in_range(0..=16)?;
        let mut cs = vec![*u.choose(&head_letters)?];
        cs.extend(
            (0..remaining_length)
                .map(|_| u.choose(&tail_letters))
                .collect::<Result<Vec<&char>, _>>()?,
        );
        let mut s: String = cs.into_iter().collect();
        // Should the parsing fails, the string should be reserved word.
        // Append a `_` to create a valid Id.
        if crate::parser::parse_ident(&s).is_err() {
            s.push('_');
        }
        Ok(Self::new_unchecked(s))
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        arbitrary::size_hint::and_all(&[
            // for arbitrary length
            <usize as arbitrary::Arbitrary>::size_hint(depth),
            // for arbitrary choices
            // we use the size hint of a vector of `u8` to get an underestimate of bytes required by the sequence of choices.
            <Vec<u8> as arbitrary::Arbitrary>::size_hint(depth),
        ])
    }
}

/// Like `Id`, except this specifically _can_ contain Cedar reserved identifiers.
/// (It still can't contain, for instance, spaces or characters like '+'.)
//
// For now, internally, `AnyId`s are just owned `SmolString`s.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Hash, PartialOrd, Ord)]
pub struct AnyId(SmolStr);

impl AnyId {
    /// Create a new `AnyId` from a `String`, where it is the caller's
    /// responsibility to ensure that the string is indeed a valid `AnyId`.
    ///
    /// When possible, callers should not use this, and instead use `s.parse()`,
    /// which checks that `s` is a valid `AnyId`, and returns a parse error
    /// if not.
    ///
    /// This method was created for the `From<cst::Ident> for AnyId` impl to use.
    /// See notes on `Id::new_unchecked()`.
    pub(crate) fn new_unchecked(s: impl Into<SmolStr>) -> AnyId {
        AnyId(s.into())
    }

    /// Get the underlying string
    pub fn into_smolstr(self) -> SmolStr {
        self.0
    }
}

impl AsRef<str> for AnyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AnyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.0)
    }
}

// allow `.parse()` on a string to make an `AnyId`
impl std::str::FromStr for AnyId {
    type Err = ParseErrors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::parser::parse_anyid(s)
    }
}

impl FromNormalizedStr for AnyId {
    fn describe_self() -> &'static str {
        "AnyId"
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for AnyId {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // AnyId syntax:
        // ['_''a'-'z''A'-'Z']['_''a'-'z''A'-'Z''0'-'9']*

        let construct_list = |s: &str| s.chars().collect::<Vec<char>>();
        let list_concat = |s1: &[char], s2: &[char]| [s1, s2].concat();
        // the set of the first character of an AnyId
        let head_letters = construct_list("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_");
        // the set of the remaining characters of an AnyId
        let tail_letters = list_concat(&construct_list("0123456789"), &head_letters);
        // identifier character count minus 1
        let remaining_length = u.int_in_range(0..=16)?;
        let mut cs = vec![*u.choose(&head_letters)?];
        cs.extend(
            (0..remaining_length)
                .map(|_| u.choose(&tail_letters))
                .collect::<Result<Vec<&char>, _>>()?,
        );
        let s: String = cs.into_iter().collect();
        debug_assert!(
            crate::parser::parse_anyid(&s).is_ok(),
            "all strings constructed this way should be valid AnyIds, but this one is not: {s:?}"
        );
        Ok(Self::new_unchecked(s))
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        arbitrary::size_hint::and_all(&[
            // for arbitrary length
            <usize as arbitrary::Arbitrary>::size_hint(depth),
            // for arbitrary choices
            // we use the size hint of a vector of `u8` to get an underestimate of bytes required by the sequence of choices.
            <Vec<u8> as arbitrary::Arbitrary>::size_hint(depth),
        ])
    }
}

// PANIC SAFETY: unit-test code
#[allow(clippy::panic)]
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn normalized_id() {
        Id::from_normalized_str("foo").expect("should be OK");
        Id::from_normalized_str("foo::bar").expect_err("shouldn't be OK");
        Id::from_normalized_str(r#"foo::"bar""#).expect_err("shouldn't be OK");
        Id::from_normalized_str(" foo").expect_err("shouldn't be OK");
        Id::from_normalized_str("foo ").expect_err("shouldn't be OK");
        Id::from_normalized_str("foo\n").expect_err("shouldn't be OK");
        Id::from_normalized_str("foo//comment").expect_err("shouldn't be OK");
    }
}
