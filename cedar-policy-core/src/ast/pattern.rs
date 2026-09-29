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
    ///
    /// In undelimited `like`, matches any run of characters.
    /// In delimited `like(pattern, delim)`, matches any run of characters
    /// that does not include the delimiter.
    Wildcard,
    /// The double wildcard `**`
    ///
    /// Only produced by the delimited parser. Matches any run of characters
    /// including the delimiter. In undelimited patterns, `**` remains two
    /// adjacent `Wildcard`s (the language is the same, so behaviour is
    /// preserved).
    MultiWildcard,
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
                PatternElem::MultiWildcard => write!(f, r#"**"#)?,
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
            // MultiWildcard is only produced by the delimited parser; when
            // encountered in an undelimited context (e.g. legacy `wildcard_match`
            // being called on a pattern that somehow contains one), treat as
            // any-character just like Wildcard.
            PatternElem::MultiWildcard => true,
        }
    }
    fn is_wildcard(self) -> bool {
        matches!(self, PatternElem::Wildcard | PatternElem::MultiWildcard)
    }
}

impl Pattern {
    /// Find if the argument text matches the pattern under a delimiter.
    ///
    /// Uses the same memoised dynamic-programming algorithm as the Lean spec
    /// `wildcardMatchDelimitedIdx` in
    /// `cedar-spec/cedar-lean/Cedar/Spec/WildcardDelimited.lean`.
    ///
    /// Semantics:
    /// - `PatternElem::MultiWildcard` (`**`) matches any run of characters,
    ///   including the delimiter.
    /// - `PatternElem::Wildcard` (`*`) matches any run of characters that does
    ///   *not* include the delimiter.
    /// - `PatternElem::Char(c)` matches exactly `c`.
    ///
    /// Complexity: O(|text| × |pattern|) time and space (each `(i, j)` cell
    /// is computed at most once).
    pub fn wildcard_match_delimited(&self, text: &str, delim: char) -> bool {
        let pattern = self.get_elems();
        let text: Vec<char> = text.chars().collect();
        let mut cache: std::collections::HashMap<(usize, usize), bool> =
            std::collections::HashMap::new();
        wildcard_match_delimited_idx(&text, pattern, 0, 0, delim, &mut cache)
    }

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

/// Memoised DP for delimiter-aware wildcard matching.
///
/// This is a direct port of `wildcardMatchDelimitedIdx` in the Lean spec
/// (`cedar-spec/cedar-lean/Cedar/Spec/WildcardDelimited.lean`). Each `(i, j)`
/// cell of the memo table is computed at most once.
fn wildcard_match_delimited_idx(
    text: &[char],
    pattern: &[PatternElem],
    i: usize,
    j: usize,
    delim: char,
    cache: &mut std::collections::HashMap<(usize, usize), bool>,
) -> bool {
    if let Some(&b) = cache.get(&(i, j)) {
        return b;
    }
    let result = if j == pattern.len() {
        // Pattern exhausted: match iff text is also exhausted.
        i == text.len()
    } else if i == text.len() {
        // Text exhausted, pattern non-empty: only wildcards may match empty tail.
        #[expect(
            clippy::indexing_slicing,
            reason = "j < pattern.len() by the else branch above"
        )]
        match pattern[j] {
            PatternElem::MultiWildcard | PatternElem::Wildcard => {
                wildcard_match_delimited_idx(text, pattern, i, j + 1, delim, cache)
            }
            PatternElem::Char(_) => false,
        }
    } else {
        // Both non-exhausted: case-split on pattern head.
        #[expect(
            clippy::indexing_slicing,
            reason = "i < text.len() and j < pattern.len()"
        )]
        match pattern[j] {
            PatternElem::MultiWildcard => {
                // `**`: skip pattern OR consume one arbitrary char.
                wildcard_match_delimited_idx(text, pattern, i, j + 1, delim, cache)
                    || wildcard_match_delimited_idx(text, pattern, i + 1, j, delim, cache)
            }
            PatternElem::Wildcard => {
                // `*`: skip pattern OR consume one non-delimiter char.
                let c = text[i];
                wildcard_match_delimited_idx(text, pattern, i, j + 1, delim, cache)
                    || (c != delim
                        && wildcard_match_delimited_idx(text, pattern, i + 1, j, delim, cache))
            }
            PatternElem::Char(k) => {
                // Literal: consume iff exact match.
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
