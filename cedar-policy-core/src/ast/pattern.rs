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

use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// Represent an element in a pattern literal (the RHS of the like operation)
#[derive(Deserialize, Hash, Debug, Clone, Copy, PartialEq, Eq)]
// We need special serialization for patterns because Rust's unicode escape
// sequences (e.g., `\u{1234}`) can appear in serialized strings and it's difficult
// to parse these into characters in the formal model. Instead we serialize the
// unicode values of Rust characters.
#[cfg_attr(not(feature = "arbitrary"), derive(Serialize))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum PatternElem {
    /// A character literal
    Char(char),
    /// The wildcard `*`
    Wildcard,
}

#[cfg(feature = "arbitrary")]
impl Serialize for PatternElem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Helper enum for serialization
        #[derive(Debug, Serialize)]
        enum PatternElemU32 {
            Char(u32),
            Wildcard,
        }
        match self {
            Self::Char(c) => PatternElemU32::Char(*c as u32).serialize(serializer),
            Self::Wildcard => PatternElemU32::Wildcard.serialize(serializer),
        }
    }
}

/// Represent a pattern literal (the RHS of the like operator)
/// Also provides an implementation of the Display trait as well as a wildcard matching method.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Pattern {
    /// A vector of pattern elements
    elems: Arc<Vec<PatternElem>>,
}

impl Pattern {
    /// Explicitly create a pattern literal out of a vector of pattern elements
    pub fn new(elems: impl IntoIterator<Item = PatternElem>) -> Self {
        Self {
            elems: Arc::new(elems.into_iter().collect()),
        }
    }

    /// Getter to the wrapped vector
    pub fn get_elems(&self) -> &[PatternElem] {
        &self.elems
    }

    /// Iterate over pattern elements
    pub fn iter(&self) -> impl Iterator<Item = &PatternElem> {
        self.elems.iter()
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
    fn match_char(&self, text_char: &char) -> bool {
        match self {
            PatternElem::Char(c) => text_char == c,
            PatternElem::Wildcard => true,
        }
    }
    fn is_wildcard(&self) -> bool {
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
            // PANIC SAFETY `j` is checked to be less than length
            #[allow(clippy::indexing_slicing)]
            if j < pattern_len && pattern[j].is_wildcard() {
                contains_star = true;
                star_idx = j;
                tmp_idx = i;
                j += 1;
            } else if j < pattern_len && pattern[j].match_char(&text[i]) {
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

        // PANIC SAFETY `j` is checked to be less than length
        #[allow(clippy::indexing_slicing)]
        while j < pattern_len && pattern[j].is_wildcard() {
            j += 1;
        }

        j == pattern_len
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    impl std::ops::Add for Pattern {
        type Output = Pattern;
        fn add(self, rhs: Self) -> Self::Output {
            let elems = [self.get_elems(), rhs.get_elems()].concat();
            Pattern::new(elems)
        }
    }

    // Map a string into a pattern literal with `PatternElem::Char`
    fn string_map(text: &str) -> Pattern {
        Pattern::new(text.chars().map(PatternElem::Char))
    }

    // Create a star pattern literal
    fn star() -> Pattern {
        Pattern::new(vec![PatternElem::Wildcard])
    }

    // Create an empty pattern literal
    fn empty() -> Pattern {
        Pattern::new(vec![])
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
