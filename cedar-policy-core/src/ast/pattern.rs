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

#[cfg(feature = "verus")]
use crate::verification::{abs::*, model as m, wildcard_lemmas::*};
use std::sync::Arc;
#[cfg(feature = "verus")]
#[allow(unused_imports)]
use vstd::prelude::*;

/// Represent an element in a pattern literal (the RHS of the like operation)
#[cfg_attr(feature = "verus", verus_verify(external_derive))]
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
#[cfg_attr(feature = "verus", verus_verify(external_derive))]
#[derive(Debug, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct Pattern {
    /// A vector of pattern elements
    elems: Arc<Vec<PatternElem>>,
}

#[cfg(feature = "verus")]
vstd::prelude::verus! {
impl Pattern {
    /// The pattern elements (for specifications)
    pub closed spec fn spec_elems(self) -> vstd::prelude::Seq<PatternElem> {
        vstd::prelude::View::view(&*self.elems)
    }
}
} // verus!

#[cfg_attr(feature = "verus", verus_verify)]
impl Pattern {
    /// Explicitly create a pattern literal out of a shared vector of pattern elements
    #[cfg_attr(feature = "verus", verus_verify(external))]
    fn new(elems: Arc<Vec<PatternElem>>) -> Self {
        Self { elems }
    }

    /// Getter to the wrapped vector
    #[cfg_attr(feature = "verus", verus_spec(r => ensures r@ == self.spec_elems()))]
    pub fn get_elems(&self) -> &[PatternElem] {
        &self.elems
    }

    /// Iterate over pattern elements
    #[cfg_attr(feature = "verus", verus_verify(external))]
    pub fn iter(&self) -> impl Iterator<Item = &PatternElem> {
        self.elems.iter()
    }

    /// Length of elems vector
    #[cfg_attr(feature = "verus", verus_verify(external))]
    pub fn len(&self) -> usize {
        self.elems.len()
    }

    /// Is this an empty pattern
    #[cfg_attr(feature = "verus", verus_verify(external))]
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

#[cfg_attr(feature = "verus", verus_verify)]
impl PatternElem {
    #[cfg_attr(feature = "verus", verus_spec(r =>
        ensures r == match self {
            PatternElem::Char(c) => text_char == c,
            PatternElem::Wildcard => true,
        }
    ))]
    fn match_char(self, text_char: char) -> bool {
        match self {
            PatternElem::Char(c) => text_char == c,
            PatternElem::Wildcard => true,
        }
    }
    #[cfg_attr(feature = "verus", verus_spec(r => ensures r == self is Wildcard))]
    fn is_wildcard(self) -> bool {
        matches!(self, PatternElem::Wildcard)
    }
}

#[cfg_attr(feature = "verus", verus_verify)]
impl Pattern {
    /// Find if the argument text matches the pattern
    #[cfg_attr(feature = "verus", verus_spec(r =>
        ensures r == m::evaluator::wildcard_match(&seq_to_list(text@), &abs_pattern(*self))
    ))]
    pub fn wildcard_match(&self, text: &str) -> bool {
        let pattern = self.get_elems();
        if pattern.is_empty() {
            proof! {
                assert(abs_elems(pattern@) =~= vstd::prelude::Seq::empty());
            }
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

        proof! {
            lemma_seq_to_list_full(text@);
            lemma_seq_to_list_full(abs_elems(pattern@));
        }
        #[cfg_attr(feature = "verus", verus_spec(
            invariant
                text_len == text@.len(),
                pattern_len == pattern@.len(),
                pattern_len > 0,
                pattern@ == self.spec_elems(),
                greedy_inv(text@, abs_elems(pattern@), wm_at(text@, abs_elems(pattern@), 0, 0),
                    i as int, j as int, star_idx as int, tmp_idx as int, contains_star),
            decreases text_len - tmp_idx, (text_len - i) + (pattern_len - j)
        ))]
        // the early `return false` needs facts about the shadowed `text: &str`
        #[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
        while i < text_len && (!contains_star || star_idx != pattern_len - 1) {
            #[expect(
                clippy::indexing_slicing,
                reason = "`j` is checked to be less than length"
            )]
            if j < pattern_len && pattern[j].is_wildcard() {
                proof! {
                    if contains_star {
                        lemma_wm_new_star(text@, abs_elems(pattern@), tmp_idx as int,
                            star_idx as int, i as int, j as int);
                    }
                }
                contains_star = true;
                star_idx = j;
                tmp_idx = i;
                j += 1;
            } else if j < pattern_len && pattern[j].match_char(text[i]) {
                proof! {
                    let p = abs_elems(pattern@);
                    if !contains_star {
                        lemma_wm_step(text@, p, i as int, j as int);
                    } else {
                        let ghost s1 = star_idx + 1;
                        assert forall|q: int| 0 <= q < j + 1 - s1 implies #[trigger] p[s1 + q]
                            == m::expr::PatElem::JustChar(text@[tmp_idx + q]) by {
                            if q < j - s1 {
                                assert(p[s1 + q] == m::expr::PatElem::JustChar(text@[tmp_idx + q]));
                            }
                        }
                    }
                }
                i += 1;
                j += 1;
            } else if contains_star {
                proof! {
                    lemma_wm_mismatch(text@, abs_elems(pattern@), tmp_idx as int,
                        star_idx as int, i as int, j as int);
                }
                j = star_idx + 1;
                i = tmp_idx + 1;
                tmp_idx = i;
            } else {
                proof! {
                    lemma_wm_step(text@, abs_elems(pattern@), i as int, j as int);
                }
                return false;
            }
        }

        proof! {
            let p = abs_elems(pattern@);
            if contains_star && star_idx == pattern_len - 1 {
                lemma_wm_star_end(text@, p, tmp_idx as int);
                lemma_wm_step(text@, p, text_len as int, pattern_len as int);
            } else if contains_star {
                lemma_wm_text_end(text@, p, tmp_idx as int, star_idx as int, j as int);
            }
        }

        #[expect(
            clippy::indexing_slicing,
            reason = "`j` is checked to be less than length"
        )]
        #[cfg_attr(feature = "verus", verus_spec(
            invariant
                text_len == text@.len(),
                pattern_len == pattern@.len(),
                pattern@ == self.spec_elems(),
                j <= pattern_len,
                wm_at(text@, abs_elems(pattern@), 0, 0)
                    == wm_at(text@, abs_elems(pattern@), text_len as int, j as int),
            decreases pattern_len - j
        ))]
        while j < pattern_len && pattern[j].is_wildcard() {
            proof! {
                lemma_wm_step(text@, abs_elems(pattern@), text_len as int, j as int);
            }
            j += 1;
        }
        proof! {
            lemma_wm_step(text@, abs_elems(pattern@), text_len as int, j as int);
        }

        j == pattern_len
    }
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
