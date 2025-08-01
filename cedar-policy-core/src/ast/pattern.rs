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

use crate::spec::spec_pattern;
use crate::verus_utils::clone_spec_for;
use std::sync::Arc;
use vstd::prelude::*;

verus! {

/// Represent an element in a pattern literal (the RHS of the like operation)
#[derive(Hash, Debug, Clone, Copy, PartialEq, Eq)]
#[verifier::external_derive]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum PatternElem {
    /// A character literal
    Char(char),
    /// The wildcard `*`
    Wildcard,
}

impl View for PatternElem {
    type V = spec_pattern::PatElem;
    open spec fn view(&self) -> Self::V {
        match self {
            PatternElem::Char(c) => spec_pattern::PatElem::JustChar { c: *c },
            PatternElem::Wildcard => spec_pattern::PatElem::Star,
        }
    }
}

clone_spec_for!(PatternElem);

/// Represent a pattern literal (the RHS of the like operator)
/// Also provides an implementation of the Display trait as well as a wildcard matching method.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
#[verifier::external_derive]
pub struct Pattern {
    /// A vector of pattern elements
    elems: Arc<Vec<PatternElem>>,
}

impl View for Pattern {
    type V = spec_pattern::Pattern;
    closed spec fn view(&self) -> Self::V {
        self.elems@.map_values(|p: PatternElem| p@)
    }
}

clone_spec_for!(Pattern);

}

impl Pattern {
    /// Explicitly create a pattern literal out of a shared vector of pattern elements
    fn new(elems: Arc<Vec<PatternElem>>) -> Self {
        Self { elems }
    }

    verus! {

    /// Getter to the wrapped vector
    pub fn get_elems(&self) -> (elems: &[PatternElem])
        ensures elems@.map_values(|p: PatternElem| p@) == self@
    {
        &self.elems
    }

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

verus! {

impl PatternElem {
    fn match_char(self, text_char: char) -> (b: bool)
        ensures b == (spec_pattern::char_match(text_char, self@) || self@ is Star)
    {
        match self {
            PatternElem::Char(c) => text_char == c,
            PatternElem::Wildcard => true,
        }
    }

    fn is_wildcard(self) -> (b: bool)
        ensures b == (self@ is Star)
    {
        matches!(self, PatternElem::Wildcard)
    }
}

}

verus! {
// Wrappers for unsupported stdlib operations on strings

#[verifier::external_body]
fn str_is_empty(s: &str) -> (b: bool)
    ensures b == (s@.len() == 0)
{
    s.is_empty()
}

#[verifier::external_body]
fn collect_chars(s: &str) -> (v: Vec<char>)
    ensures v@ == s@
{
    s.chars().collect()
}

}

impl Pattern {
    verus! {

    /// Find if the argument text matches the pattern
    #[verifier::loop_isolation(false)]
    pub fn wildcard_match(&self, text: &str) -> (b: bool)
        ensures b == spec_pattern::wildcard_match(text@, self@)
    {
        let pattern = self.get_elems();
        // if pattern.is_empty() { // Verus doesn't support `is_empty`
        if pattern.len() == 0 {
            return str_is_empty(text); // text.is_empty();
        }

        // Copying the strings into vectors requires extra space, but has two benefits:
        // 1. It makes accessing elements more efficient. The alternative (i.e.,
        //    chars().nth()) needs to re-scan the string for each invocation. Note
        //    that a simple iterator will not work here since we move both forward
        //    and backward through the string.
        // 2. It provides an unambiguous length. In general for a string s,
        //    s.len() is not the same as s.chars().count(). The length of these
        //    created vectors will match .chars().count()
        let text: Vec<char> = collect_chars(text); // text.chars.collect();

        let mut i: usize = 0; // index into text
        let mut j: usize = 0; // index into pattern
        let mut star_idx: usize = 0; // index in pattern (j) of the most recent *
        let mut tmp_idx: usize = 0; // index in text (i) of the most recent *
        let mut contains_star: bool = false; // does the pattern contain *?

        let text_len = text.len();
        let pattern_len = pattern.len();

        reveal_with_fuel(spec_pattern::wildcard_match_rev_idx, 1);
        let ghost spec_pattern = pattern@.map_values(|p: PatternElem| p@);
        proof {
            spec_pattern::lemma_wildcard_match_idx_rev_idx_equiv(text@, spec_pattern);
        }

        while i < text_len && (!contains_star || star_idx != pattern_len - 1)
            invariant
                text_len == text@.len(),
                pattern_len == spec_pattern.len(),
                0 <= i <= text_len,
                0 <= j <= pattern_len,
                0 <= star_idx <= j,
                j > 0 ==> star_idx < j,
                0 <= tmp_idx <= i,
                contains_star ==> spec_pattern[star_idx as int] is Star,
                spec_pattern::wildcard_match_rev_idx(text@, spec_pattern, i as int, j as int),
            decreases text_len - tmp_idx, pattern_len - j, text_len - i
        {
            // PANIC SAFETY `j` is checked to be less than length
            #[allow(clippy::indexing_slicing)]
            if j < pattern_len && pattern[j].is_wildcard() {
                contains_star = true;
                star_idx = j;
                tmp_idx = i;
                j += 1;
                assert(spec_pattern::wildcard_match_rev_idx(text@, spec_pattern, i as int, j as int));
            } else if j < pattern_len && pattern[j].match_char(text[i]) {
                i += 1;
                j += 1;
                assert(spec_pattern::wildcard_match_rev_idx(text@, spec_pattern, i as int, j as int));
            } else if contains_star {
                j = star_idx + 1;
                i = tmp_idx + 1;
                tmp_idx = i;
                assert(spec_pattern::wildcard_match_rev_idx(text@, spec_pattern, i as int, j as int));
            } else {
                return false;
            }
        }

        assert(i == text_len || (contains_star && star_idx == pattern_len - 1));
        // Either we reached the end of the text (i == text_len),
        // or we have a star and it's at the end of the pattern (contains_star && star_idx == pattern_len - 1)

        // PANIC SAFETY `j` is checked to be less than length
        #[allow(clippy::indexing_slicing)]
        while j < pattern_len && pattern[j].is_wildcard()
            invariant
                0 <= j <= pattern_len,
                0 <= star_idx <= j,
                j > 0 ==> star_idx < j,
                contains_star ==> spec_pattern[star_idx as int] is Star,
                spec_pattern::wildcard_match_rev_idx(text@, spec_pattern, i as int, j as int),
            decreases pattern_len - j
        {
            j += 1;
        }

        j == pattern_len
    }

    } // verus!
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
