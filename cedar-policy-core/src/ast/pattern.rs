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

use std::sync::Arc;

/// Represent an element in a pattern literal (the RHS of the like operation)
#[derive(Hash, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum PatternElem {
    /// A character literal
    Char(char),
    /// The wildcard `*`
    Wildcard,
}

/// Represent a pattern literal (the RHS of the like operator)
/// Also provides an implementation of the Display trait as well as a wildcard matching method.
#[derive(Debug, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct Pattern {
    /// A vector of pattern elements
    elems: Arc<Vec<PatternElem>>,
}

impl Pattern {
    /// Explicitly create a pattern literal out of a shared vector of pattern elements
    fn new(elems: Arc<Vec<PatternElem>>) -> Self {
        Self { elems }
    }

    /// Getter to the wrapped vector
    pub fn get_elems(&self) -> &[PatternElem] {
        &self.elems
    }

    /// Iterate over pattern elements
    pub fn iter(&self) -> impl Iterator<Item = &PatternElem> {
        self.elems.iter()
    }

    /// Length of elems vector
    pub fn len(&self) -> usize {
        self.elems.len()
    }

    /// Is this an empty pattern
    pub fn is_empty(&self) -> bool {
        self.elems.is_empty()
    }
}

impl From<Arc<Vec<PatternElem>>> for Pattern {
    fn from(value: Arc<Vec<PatternElem>>) -> Self {
        Self::new(value)
    }
}

impl From<Vec<PatternElem>> for Pattern {
    fn from(value: Vec<PatternElem>) -> Self {
        Self::new(Arc::new(value))
    }
}

impl FromIterator<PatternElem> for Pattern {
    fn from_iter<T: IntoIterator<Item = PatternElem>>(iter: T) -> Self {
        Self::new(Arc::new(iter.into_iter().collect()))
    }
}

impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for pc in self.elems.as_ref() {
            match pc {
                PatternElem::Char('*') => write!(f, r#"\*"#)?,
                PatternElem::Char(c) => write!(f, "{}", c.escape_debug())?,
                PatternElem::Wildcard => write!(f, r#"*"#)?,
            }
        }
        Ok(())
    }
}

impl PatternElem {
    fn match_char(self, text_char: char) -> bool {
        match self {
            PatternElem::Char(c) => text_char == c,
            PatternElem::Wildcard => true,
        }
    }
    fn is_wildcard(self) -> bool {
        matches!(self, PatternElem::Wildcard)
    }
}

impl Pattern {
    /// Find if the argument text matches the pattern
    pub fn wildcard_match(&self, text: &str) -> bool {
        let pattern = self.get_elems();
        if pattern.is_empty() {
            return text.is_empty();
        }

        // Copying the strings into vectors requires extra space, but has two benefits:
        // 1. It makes accessing elements more efficient. The alternative (i.e.,
        //    chars().nth()) needs to re-scan the string for each invocation. Note
        //    that a simple iterator will not work here since we move both forward
        //    and backward through the string.
        // 2. It provides an unambiguous length. In general for a string s,
        //    s.len() is not the same as s.chars().count(). The length of these
        //    created vectors will match .chars().count()
        let text: Vec<char> = text.chars().collect();

        let mut i: usize = 0; // index into text
        let mut j: usize = 0; // index into pattern
        let mut star_idx: usize = 0; // index in pattern (j) of the most recent *
        let mut tmp_idx: usize = 0; // index in text (i) of the most recent *
        let mut contains_star: bool = false; // does the pattern contain *?

        let text_len = text.len();
        let pattern_len = pattern.len();

        while i < text_len && (!contains_star || star_idx != pattern_len - 1) {
            #[expect(
                clippy::indexing_slicing,
                reason = "`j` is checked to be less than length"
            )]
            if j < pattern_len && pattern[j].is_wildcard() {
                contains_star = true;
                star_idx = j;
                tmp_idx = i;
                j += 1;
            } else if j < pattern_len && pattern[j].match_char(text[i]) {
                i += 1;
                j += 1;
            } else if contains_star {
                j = star_idx + 1;
                i = tmp_idx + 1;
                tmp_idx = i;
            } else {
                return false;
            }
        }

        #[expect(
            clippy::indexing_slicing,
            reason = "`j` is checked to be less than length"
        )]
        while j < pattern_len && pattern[j].is_wildcard() {
            j += 1;
        }

        j == pattern_len
    }
}

#[cfg(feature = "extended-like")]
mod delim_pattern {
    use std::sync::Arc;

    /// Represent an element in a delimited pattern literal (the pattern
    /// argument of `like(pattern, delim)`)
    #[derive(Hash, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub enum DelimPatternElem {
        /// A character literal
        Char(char),
        /// The wildcard `*`. Matches any run of non-delimiter characters.
        Wildcard,
        /// The double wildcard `**`. Matches any run of characters.
        MultiWildcard,
    }

    /// Represent a delimited pattern literal (the pattern argument of
    /// `like(pattern, delim)`). The delimiter itself is not stored here.
    #[derive(Debug, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
    pub struct DelimPattern {
        /// A vector of pattern elements
        elems: Arc<Vec<DelimPatternElem>>,
    }

    impl DelimPattern {
        /// Explicitly create a pattern literal out of a shared vector of pattern elements
        fn new(elems: Arc<Vec<DelimPatternElem>>) -> Self {
            Self { elems }
        }

        /// Getter to the wrapped vector
        pub fn get_elems(&self) -> &[DelimPatternElem] {
            &self.elems
        }

        /// Iterate over pattern elements
        pub fn iter(&self) -> impl Iterator<Item = &DelimPatternElem> {
            self.elems.iter()
        }

        /// Length of elems vector
        pub fn len(&self) -> usize {
            self.elems.len()
        }

        /// Is this an empty pattern
        pub fn is_empty(&self) -> bool {
            self.elems.is_empty()
        }

        /// Find if the argument text matches the pattern under a delimiter.
        /// `*` matches any run of non-delimiter characters, `**` matches any
        /// run of characters.
        ///
        /// This is more expensive than [`super::Pattern::wildcard_match`], which is a
        /// greedy scan using constant extra memory. Here every (text index,
        /// pattern index) pair is memoised, so time and memory are
        /// O(text length * pattern length), and the recursion can go
        /// text length + pattern length deep.
        // TODO: replace with a non-recursive matcher closer to `wildcard_match`.
        pub fn wildcard_match_delimited(&self, text: &str, delim: char) -> bool {
            let pattern = self.get_elems();
            let text: Vec<char> = text.chars().collect();
            let mut cache: std::collections::HashMap<(usize, usize), bool> =
                std::collections::HashMap::new();
            wildcard_match_delimited_idx(&text, pattern, 0, 0, delim, &mut cache)
        }
    }

    /// Largest code point allowed as a `like` delimiter. Delimiters above
    /// SMT-LIB's max code point can't be encoded by the symbolic compiler.
    pub const MAX_LIKE_DELIMITER: char = '\u{2FFFF}';

    /// A delimiter for `like(pattern, delim)`: one Unicode scalar value, not
    /// `*`, at most U+2FFFF ([`MAX_LIKE_DELIMITER`]).
    ///
    /// The only way to create a `LikeDelimiter` is through
    /// [`LikeDelimiter::new()`] or [`LikeDelimiter::parse()`], both of which
    /// enforce these restrictions.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct LikeDelimiter(char);

    impl LikeDelimiter {
        /// Create a new `LikeDelimiter`, checking that `c` is not `*` and is
        /// at most U+2FFFF.
        pub fn new(c: char) -> Result<Self, InvalidLikeDelimiterError> {
            if c == '*' {
                Err(InvalidLikeDelimiterError::new(
                    c.to_string(),
                    InvalidLikeDelimiterReason::Wildcard,
                ))
            } else if c > MAX_LIKE_DELIMITER {
                Err(InvalidLikeDelimiterError::new(
                    c.to_string(),
                    InvalidLikeDelimiterReason::TooLarge,
                ))
            } else {
                Ok(Self(c))
            }
        }

        /// Parse the (already unescaped) delimiter string of a
        /// `like(pattern, delim)` expression. `s` must be exactly one
        /// Unicode scalar value satisfying the restrictions of
        /// [`LikeDelimiter::new()`].
        pub fn parse(s: &str) -> Result<Self, InvalidLikeDelimiterError> {
            let mut chars = s.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => Self::new(c),
                _ => Err(InvalidLikeDelimiterError::new(
                    s,
                    InvalidLikeDelimiterReason::NotSingleChar,
                )),
            }
        }

        /// Get the delimiter character
        pub fn as_char(self) -> char {
            self.0
        }
    }

    impl std::fmt::Display for LikeDelimiter {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl From<LikeDelimiter> for char {
        fn from(d: LikeDelimiter) -> Self {
            d.0
        }
    }

    #[cfg(feature = "arbitrary")]
    impl<'a> arbitrary::Arbitrary<'a> for LikeDelimiter {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            let c: char = u.arbitrary()?;
            // Map invalid delimiters deterministically to valid ones.
            let c = if c == '*' {
                '.'
            } else if c > MAX_LIKE_DELIMITER {
                // Fold the out-of-range code point into U+0..=U+2FFFF,
                // falling back to `.` if the result is a surrogate or `*`.
                char::from_u32((c as u32) % (MAX_LIKE_DELIMITER as u32 + 1))
                    .filter(|c| *c != '*')
                    .unwrap_or('.')
            } else {
                c
            };
            Ok(Self(c))
        }

        fn size_hint(depth: usize) -> (usize, Option<usize>) {
            <char as arbitrary::Arbitrary<'a>>::size_hint(depth)
        }
    }

    /// Why a delimiter was rejected by [`LikeDelimiter`]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum InvalidLikeDelimiterReason {
        /// The input was empty or had more than one Unicode scalar value
        NotSingleChar,
        /// The input was `*`
        Wildcard,
        /// The input was greater than U+2FFFF
        TooLarge,
    }

    impl std::fmt::Display for InvalidLikeDelimiterReason {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NotSingleChar => write!(f, "it must be exactly one Unicode scalar value"),
                Self::Wildcard => write!(f, "it must not be `*`"),
                Self::TooLarge => write!(f, "it must be no greater than U+2FFFF"),
            }
        }
    }

    /// Error returned when constructing an invalid [`LikeDelimiter`]
    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
    #[error("invalid delimiter `{}` for a `like` expression: {reason}", input.escape_debug())]
    #[diagnostic(help(
        "the delimiter must be exactly one Unicode scalar value, other than `*`, no greater than U+2FFFF"
    ))]
    pub struct InvalidLikeDelimiterError {
        input: String,
        reason: InvalidLikeDelimiterReason,
    }

    impl InvalidLikeDelimiterError {
        fn new(input: impl Into<String>, reason: InvalidLikeDelimiterReason) -> Self {
            Self {
                input: input.into(),
                reason,
            }
        }

        /// The rejected input
        pub fn input(&self) -> &str {
            &self.input
        }

        /// Why the input was rejected
        pub fn reason(&self) -> InvalidLikeDelimiterReason {
            self.reason
        }
    }

    impl From<Arc<Vec<DelimPatternElem>>> for DelimPattern {
        fn from(value: Arc<Vec<DelimPatternElem>>) -> Self {
            Self::new(value)
        }
    }

    impl From<Vec<DelimPatternElem>> for DelimPattern {
        fn from(value: Vec<DelimPatternElem>) -> Self {
            Self::new(Arc::new(value))
        }
    }

    impl FromIterator<DelimPatternElem> for DelimPattern {
        fn from_iter<T: IntoIterator<Item = DelimPatternElem>>(iter: T) -> Self {
            Self::new(Arc::new(iter.into_iter().collect()))
        }
    }

    /// Note that two adjacent `Wildcard`s are printed as a single `*`, since
    /// printing them as `**` would re-parse as `MultiWildcard` (which matches
    /// the delimiter). A run of `Wildcard`s matches exactly what a single
    /// `Wildcard` matches, so this preserves semantics.
    impl std::fmt::Display for DelimPattern {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let mut prev_wildcard = false;
            for pc in self.elems.as_ref() {
                match pc {
                    DelimPatternElem::Char('*') => write!(f, r#"\*"#)?,
                    DelimPatternElem::Char(c) => write!(f, "{}", c.escape_debug())?,
                    DelimPatternElem::Wildcard if prev_wildcard => {}
                    DelimPatternElem::Wildcard => write!(f, r#"*"#)?,
                    DelimPatternElem::MultiWildcard => write!(f, r#"**"#)?,
                }
                prev_wildcard = matches!(pc, DelimPatternElem::Wildcard);
            }
            Ok(())
        }
    }

    /// Memoised DP for delimiter-aware wildcard matching.
    fn wildcard_match_delimited_idx(
        text: &[char],
        pattern: &[DelimPatternElem],
        i: usize,
        j: usize,
        delim: char,
        cache: &mut std::collections::HashMap<(usize, usize), bool>,
    ) -> bool {
        if let Some(&b) = cache.get(&(i, j)) {
            return b;
        }
        let result = if j == pattern.len() {
            i == text.len()
        } else if i == text.len() {
            #[expect(
                clippy::indexing_slicing,
                reason = "j < pattern.len() by the else branch above"
            )]
            match pattern[j] {
                DelimPatternElem::MultiWildcard | DelimPatternElem::Wildcard => {
                    wildcard_match_delimited_idx(text, pattern, i, j + 1, delim, cache)
                }
                DelimPatternElem::Char(_) => false,
            }
        } else {
            #[expect(
                clippy::indexing_slicing,
                reason = "i < text.len() and j < pattern.len()"
            )]
            match pattern[j] {
                DelimPatternElem::MultiWildcard => {
                    wildcard_match_delimited_idx(text, pattern, i, j + 1, delim, cache)
                        || wildcard_match_delimited_idx(text, pattern, i + 1, j, delim, cache)
                }
                DelimPatternElem::Wildcard => {
                    let c = text[i];
                    wildcard_match_delimited_idx(text, pattern, i, j + 1, delim, cache)
                        || (c != delim
                            && wildcard_match_delimited_idx(text, pattern, i + 1, j, delim, cache))
                }
                DelimPatternElem::Char(k) => {
                    text[i] == k
                        && wildcard_match_delimited_idx(text, pattern, i + 1, j + 1, delim, cache)
                }
            }
        };
        cache.insert((i, j), result);
        result
    }

    #[cfg(test)]
    mod test {
        use super::*;

        fn pat(s: &str) -> DelimPattern {
            // `!` stands for `**`, `*` for `*`; everything else is a literal.
            s.chars()
                .map(|c| match c {
                    '!' => DelimPatternElem::MultiWildcard,
                    '*' => DelimPatternElem::Wildcard,
                    c => DelimPatternElem::Char(c),
                })
                .collect()
        }

        #[test]
        fn delimited_match_basic() {
            assert!(pat("*.example.com").wildcard_match_delimited("a.example.com", '.'));
            assert!(!pat("*.example.com").wildcard_match_delimited("a.b.example.com", '.'));
            assert!(pat("!.example.com").wildcard_match_delimited("a.b.example.com", '.'));
            assert!(pat("*").wildcard_match_delimited("", '.'));
            assert!(pat("!").wildcard_match_delimited("", '.'));
            assert!(!pat("*").wildcard_match_delimited(".", '.'));
            assert!(pat("!").wildcard_match_delimited(".", '.'));
            assert!(pat("").wildcard_match_delimited("", '.'));
            assert!(!pat("").wildcard_match_delimited("a", '.'));
        }

        #[test]
        fn like_delimiter_validation() {
            for c in ['.', '/', '\\', '\u{0}', '\u{2FFFF}'] {
                assert_eq!(LikeDelimiter::new(c).map(LikeDelimiter::as_char), Ok(c));
                assert_eq!(LikeDelimiter::parse(&c.to_string()).map(char::from), Ok(c));
            }
            assert_eq!(
                LikeDelimiter::new('*').map_err(|e| e.reason()),
                Err(InvalidLikeDelimiterReason::Wildcard)
            );
            assert_eq!(
                LikeDelimiter::new('\u{30000}').map_err(|e| e.reason()),
                Err(InvalidLikeDelimiterReason::TooLarge)
            );
            for s in ["", "ab", ".."] {
                let err = LikeDelimiter::parse(s).unwrap_err();
                assert_eq!(err.reason(), InvalidLikeDelimiterReason::NotSingleChar);
                assert_eq!(err.input(), s);
            }
            assert!(LikeDelimiter::parse("*").is_err());
            assert!(LikeDelimiter::parse("\u{30000}").is_err());
            assert_eq!(LikeDelimiter::new('/').unwrap().to_string(), "/");
        }

        #[test]
        fn delimited_display() {
            let p = DelimPattern::from(vec![
                DelimPatternElem::MultiWildcard,
                DelimPatternElem::Char('*'),
                DelimPatternElem::Wildcard,
                DelimPatternElem::Char('.'),
            ]);
            assert_eq!(p.to_string(), r"**\**.");
            // Adjacent single wildcards must not print as `**`.
            let p = DelimPattern::from(vec![
                DelimPatternElem::Wildcard,
                DelimPatternElem::Wildcard,
                DelimPatternElem::Char('a'),
                DelimPatternElem::Wildcard,
                DelimPatternElem::Wildcard,
                DelimPatternElem::MultiWildcard,
            ]);
            assert_eq!(p.to_string(), "*a***");
            assert!(!p.wildcard_match_delimited("x.a", '.'));
        }
    }
}
#[cfg(feature = "extended-like")]
pub use delim_pattern::{
    DelimPattern, DelimPatternElem, InvalidLikeDelimiterError, InvalidLikeDelimiterReason,
    LikeDelimiter, MAX_LIKE_DELIMITER,
};

#[cfg(test)]
mod test {
    use super::*;

    impl std::ops::Add for Pattern {
        type Output = Pattern;
        fn add(self, rhs: Self) -> Self::Output {
            let elems = [self.get_elems(), rhs.get_elems()].concat();
            Pattern::from(elems)
        }
    }

    // Map a string into a pattern literal with `PatternElem::Char`
    fn string_map(text: &str) -> Pattern {
        text.chars().map(PatternElem::Char).collect()
    }

    // Create a star pattern literal
    fn star() -> Pattern {
        Pattern::from(vec![PatternElem::Wildcard])
    }

    // Create an empty pattern literal
    fn empty() -> Pattern {
        Pattern::from(vec![])
    }

    #[test]
    fn test_wildcard_match_basic() {
        // Patterns that match "foo bar"
        assert!((string_map("foo") + star()).wildcard_match("foo bar"));
        assert!((star() + string_map("bar")).wildcard_match("foo bar"));
        assert!((star() + string_map("o b") + star()).wildcard_match("foo bar"));
        assert!((string_map("f") + star() + string_map(" bar")).wildcard_match("foo bar"));
        assert!((string_map("f") + star() + star() + string_map("r")).wildcard_match("foo bar"));
        assert!((star() + string_map("f") + star() + star() + star()).wildcard_match("foo bar"));

        // Patterns that do not match "foo bar"
        assert!(!(star() + string_map("foo")).wildcard_match("foo bar"));
        assert!(!(string_map("bar") + star()).wildcard_match("foo bar"));
        assert!(!(star() + string_map("bo") + star()).wildcard_match("foo bar"));
        assert!(!(string_map("f") + star() + string_map("br")).wildcard_match("foo bar"));
        assert!(!(star() + string_map("x") + star() + star() + star()).wildcard_match("foo bar"));
        assert!(!empty().wildcard_match("foo bar"));

        // Patterns that match ""
        assert!(empty().wildcard_match(""));
        assert!(star().wildcard_match(""));

        // Patterns that do not match ""
        assert!(!string_map("foo bar").wildcard_match(""));

        // Patterns that match "*"
        assert!(string_map("*").wildcard_match("*"));
        assert!(star().wildcard_match("*"));

        // Patterns that do not match "*"
        assert!(!string_map("\u{0000}").wildcard_match("*"));
        assert!(!string_map(r"\u{0000}").wildcard_match("*"));
    }

    #[test]
    fn test_wildcard_match_unicode() {
        // Patterns that match "y̆"
        assert!((string_map("y") + star()).wildcard_match("y̆"));
        assert!(string_map("y̆").wildcard_match("y̆"));

        // Patterns that do not match "y̆"
        assert!(!(star() + string_map("p") + star()).wildcard_match("y̆"));

        // Patterns that match "ḛ̶͑͝x̶͔͛a̵̰̯͛m̴͉̋́p̷̠͂l̵͇̍̔ȩ̶̣͝"
        assert!((star() + string_map("p") + star()).wildcard_match("ḛ̶͑͝x̶͔͛a̵̰̯͛m̴͉̋́p̷̠͂l̵͇̍̔ȩ̶̣͝"));
        assert!((star() + string_map("a̵̰̯͛m̴͉̋́") + star()).wildcard_match("ḛ̶͑͝x̶͔͛a̵̰̯͛m̴͉̋́p̷̠͂l̵͇̍̔ȩ̶̣͝"));

        // Patterns that do not match "ḛ̶͑͝x̶͔͛a̵̰̯͛m̴͉̋́p̷̠͂l̵͇̍̔ȩ̶̣͝"
        assert!(!(string_map("y") + star()).wildcard_match("ḛ̶͑͝x̶͔͛a̵̰̯͛m̴͉̋́p̷̠͂l̵͇̍̔ȩ̶̣͝"));
    }
}
