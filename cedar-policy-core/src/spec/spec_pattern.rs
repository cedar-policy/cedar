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

//! This module contains spec data structures modeling the Cedar AST

#![allow(missing_debug_implementations)] // vstd types Seq/Set/Map don't impl Debug
#![allow(missing_docs)] // just for now

pub use crate::verus_utils::*;
pub use vstd::{map::*, prelude::*, seq::*, set::*};

verus! {

pub enum PatElem {
    Star,
    JustChar { c: char }
}

pub type Pattern = Seq<PatElem>;

pub open spec fn char_match(text_char: char, pat_elem: PatElem) -> bool {
    match pat_elem {
        PatElem::JustChar { c } => text_char == c,
        _ => false,
    }
}

pub open spec fn wildcard(pat_elem: PatElem) -> bool {
    match pat_elem {
        PatElem::Star => true,
        _ => false,
    }
}

// The Lean version of this function uses a dynamic programming cache for efficiency (since the Lean code actually is run)
// Verus specs are never run, so we don't bother with the cache
// i = text index, j = pattern index
// wildcard_match_idx(text, pattern, i, j) means that text[i..] matches pattern[j..]
pub open spec fn wildcard_match_idx(text: Seq<char>, pattern: Pattern, i: int, j: int) -> bool
    decreases text.len() - i, pattern.len() - j
{
    if i < 0 || i > text.len() || j < 0 || j > pattern.len() {
        arbitrary()
    } else if j == pattern.len() {
        // if we've reached the end of the pattern, there can't be any characters left to match
        i == text.len()
    } else if i == text.len() {
        // if we've reached the end of the text, we must have a wildcard in the pattern
        wildcard(pattern[j]) && wildcard_match_idx(text, pattern, i, j+1)
    } else if wildcard(pattern[j]) {
        // if we have a wildcard now, we can either use it to match zero characters (increase j by 1),
        // or use it to match one character (increase i by 1) and continue using it
        wildcard_match_idx(text, pattern, i, j+1) || wildcard_match_idx(text, pattern, i+1, j)
    } else {
        // if we have a non-wildcard character, we must match it exactly,
        // in which case we consume that character from the pattern and from the text
        char_match(text[i], pattern[j]) && wildcard_match_idx(text, pattern, i+1, j+1)
    }
}


pub open spec fn wildcard_match(text: Seq<char>, pattern: Pattern) -> bool {
    wildcard_match_idx(text, pattern, 0, 0)
}

// Alternative version of `wildcard_match` that takes subranges instead of indexing
pub open spec fn wildcard_match_alt(text: Seq<char>, pattern: Pattern) -> bool
    decreases text.len(), pattern.len()
{
    if pattern.len() == 0 && text.len() == 0 {
        true
    } else if pattern.len() == 0 {
        false
    } else if text.len() == 0 {
       wildcard(pattern[0]) && wildcard_match_alt(text, pattern.skip(1))
    } else if wildcard(pattern[0]) {
        wildcard_match_alt(text, pattern.skip(1)) || wildcard_match_alt(text.skip(1), pattern)
    } else {
        char_match(text[0], pattern[0]) && wildcard_match_alt(text.skip(1), pattern.skip(1))
    }
}


}

////////////////////////////////////////////////
// Helper definitions and lemmas for patterns //
////////////////////////////////////////////////
verus! {

// Alternative version of `wildcard_match` recursing from the end, rather than the beginning

// pub open spec fn wildcard_match_rev_idx(text: Seq<char>, pattern: Pattern, i: int, j: int) -> bool
//     decreases i, j
// {
//     if i < 0 || i > text.len() || j < 0 || j > pattern.len() {
//         arbitrary()
//     } else if i == 0 && j == 0 {
//         // empty pattern matches empty string
//         true
//     } else if i == 0 {
//         // all of the pattern should be wildcards
//         wildcard(pattern[j-1]) && wildcard_match_rev_idx(text, pattern, i, j-1)
//     } else if j == 0 {
//         // the pattern is empty and there are still some text characters to match
//         false
//     } else if wildcard(pattern[j-1]) {
//         // either we can match zero characters with the wildcard (decrement j),
//         // or we can match one character with the wildcard (decrement i) and continue using it
//         wildcard_match_rev_idx(text, pattern, i, j-1) || wildcard_match_rev_idx(text, pattern, i-1, j)
//     } else {
//         // we must match the character exactly and continue
//         char_match(text[i-1], pattern[j-1]) && wildcard_match_rev_idx(text, pattern, i-1, j-1)
//     }
// }

// pub proof fn lemma_wildcard_match_idx_rev_idx_equiv_aux(text: Seq<char>, pattern: Pattern, i: int, j: int)
//     requires
//         0 <= i <= text.len(),
//         0 <= j <= pattern.len(),
//     ensures wildcard_match_idx(text.subrange(0,i), pattern.subrange(0,j), 0, 0) == wildcard_match_rev_idx(text, pattern, i, j)
//     decreases i, j
// {
//     reveal_with_fuel(wildcard_match_idx, 2);
//     reveal_with_fuel(wildcard_match_rev_idx, 2);
//     if i == 0 && j == 0 {
//         // empty pattern matches empty string
//         assert(wildcard_match_rev_idx(text, pattern, i, j));
//         assert(wildcard_match_idx(text.subrange(0,i), pattern.subrange(0,j), 0, 0));
//     } else if i == 0 {
//         // all of the pattern should be wildcards
//         lemma_wildcard_match_idx_rev_idx_equiv_aux(text, pattern, i, j-1);
//         assert(wildcard_match_idx(text.subrange(0,i), pattern.subrange(0,j), 0, 0) == wildcard_match_rev_idx(text, pattern, i, j));
//     } else if j == 0 {
//         // the pattern is empty and there are still some text characters to match
//         assert(wildcard_match_idx(text.subrange(0,i), pattern.subrange(0,j), 0, 0) == wildcard_match_rev_idx(text, pattern, i, j));
//     } else if wildcard(pattern[j-1]) {
//         // either we can match zero characters with the wildcard (decrement j),
//         // or we can match one character with the wildcard (decrement i) and continue using it
//         lemma_wildcard_match_idx_rev_idx_equiv_aux(text, pattern, i, j-1);
//         lemma_wildcard_match_idx_rev_idx_equiv_aux(text, pattern, i-1, j);
//         assert(wildcard_match_idx(text.subrange(0,i), pattern.subrange(0,j), 0, 0) == wildcard_match_rev_idx(text, pattern, i, j));
//     } else {
//         // we must match the character exactly and continue
//         lemma_wildcard_match_idx_rev_idx_equiv_aux(text, pattern, i-1, j-1);
//         assert(wildcard_match_idx(text.subrange(0,i), pattern.subrange(0,j), 0, 0) == wildcard_match_rev_idx(text, pattern, i, j));
//     }
// }

// pub proof fn lemma_wildcard_match_idx_rev_idx_equiv(text: Seq<char>, pattern: Pattern)
//     ensures wildcard_match_idx(text, pattern, 0, 0) == wildcard_match_rev_idx(text, pattern, text.len() as int, pattern.len() as int)
// {
//     assert(text.subrange(0, text.len() as int) =~= text);
//     assert(pattern.subrange(0, pattern.len() as int) =~= pattern);
//     lemma_wildcard_match_idx_rev_idx_equiv_aux(text, pattern, text.len() as int, pattern.len() as int);
// }

proof fn lemma_wildcard_match_pattern_append_star(text: Seq<char>, pattern: Pattern)
    requires wildcard_match_alt(text, pattern)
    ensures wildcard_match_alt(text, pattern.push(PatElem::Star))
    decreases text.len(), pattern.len()
{
    reveal_with_fuel(wildcard_match_alt, 2);
    if pattern.len() == 0 && text.len() == 0 {
    } else if pattern.len() == 0 {
    } else {
        assert(pattern.push(PatElem::Star).skip(1) =~= pattern.skip(1).push(PatElem::Star));
        if text.len() == 0 {
            lemma_wildcard_match_pattern_append_star(text, pattern.skip(1));
        } else if wildcard(pattern[0]) {
            if wildcard_match_alt(text, pattern.skip(1)) {
                lemma_wildcard_match_pattern_append_star(text, pattern.skip(1));
            } else {
                lemma_wildcard_match_pattern_append_star(text.skip(1), pattern);
            }
        } else {
            lemma_wildcard_match_pattern_append_star(text.skip(1), pattern.skip(1));
        }
    }
}

proof fn lemma_wildcard_match_pattern_append_star_char(text: Seq<char>, pattern: Pattern, text_c: char, pattern_c: PatElem)
    requires
        wildcard_match_alt(text, pattern),
        wildcard(pattern_c),
    ensures wildcard_match_alt(text.push(text_c), pattern.push(pattern_c))
    decreases text.len(), pattern.len()
{
    reveal_with_fuel(wildcard_match_alt, 2);
    if pattern.len() == 0 && text.len() == 0 {
        assert(text.push(text_c) =~= seq![text_c]);
        assert(pattern.push(pattern_c) =~= seq![pattern_c]);
        assert(text.push(text_c).skip(1).len() == 0);
        assert(wildcard_match_alt(text.push(text_c).skip(1), pattern.push(pattern_c)));
    } else if pattern.len() == 0 {
    } else {
        assert(pattern.push(pattern_c).skip(1) =~= pattern.skip(1).push(pattern_c));
        if text.len() == 0 {
            lemma_wildcard_match_pattern_append_star_char(text, pattern.skip(1), text_c, pattern_c);
        } else {
            assert(text.push(text_c).skip(1) =~= text.skip(1).push(text_c));
            if wildcard(pattern[0]) {
                if wildcard_match_alt(text, pattern.skip(1)) {
                    lemma_wildcard_match_pattern_append_star_char(text, pattern.skip(1), text_c, pattern_c);
                } else {
                    lemma_wildcard_match_pattern_append_star_char(text.skip(1), pattern, text_c, pattern_c);
                }
            } else {
                lemma_wildcard_match_pattern_append_star_char(text.skip(1), pattern.skip(1), text_c, pattern_c);
            }
        }
    }
}


proof fn lemma_wildcard_match_pattern_append_matching_chars(text: Seq<char>, pattern: Pattern, text_c: char, pattern_c: PatElem)
    requires
        wildcard_match_alt(text, pattern),
        char_match(text_c, pattern_c)
    ensures wildcard_match_alt(text.push(text_c), pattern.push(pattern_c))
    decreases text.len(), pattern.len()
{
    reveal_with_fuel(wildcard_match_alt, 2);
    if pattern.len() == 0 && text.len() == 0 {
    } else if pattern.len() == 0 {
    } else {
        assert(pattern.push(pattern_c).skip(1) =~= pattern.skip(1).push(pattern_c));
        if text.len() == 0 {
            lemma_wildcard_match_pattern_append_matching_chars(text, pattern.skip(1), text_c, pattern_c);
        } else {
            assert(text.push(text_c).skip(1) =~= text.skip(1).push(text_c));
            if wildcard(pattern[0]) {
                if wildcard_match_alt(text, pattern.skip(1)) {
                    lemma_wildcard_match_pattern_append_matching_chars(text, pattern.skip(1), text_c, pattern_c);
                } else {
                    lemma_wildcard_match_pattern_append_matching_chars(text.skip(1), pattern, text_c, pattern_c);
                }
            } else {
                lemma_wildcard_match_pattern_append_matching_chars(text.skip(1), pattern.skip(1), text_c, pattern_c);
            }
        }
    }
}

proof fn lemma_wildcard_match_pattern_append_last_wildcard(text: Seq<char>, pattern: Pattern, text_c: char)
    requires
        pattern.len() > 0,
        wildcard(pattern.last()),
        wildcard_match_alt(text, pattern),
    ensures wildcard_match_alt(text.push(text_c), pattern)
    decreases text.len(), pattern.len()
{
    reveal_with_fuel(wildcard_match_alt, 2);
    if pattern.len() == 0 && text.len() == 0 {
    } else if pattern.len() == 0 {
    } else {
        if text.len() == 0 {
            if pattern.skip(1).len() > 0 {
                lemma_wildcard_match_pattern_append_last_wildcard(text, pattern.skip(1), text_c);
            } else {
                assert(pattern =~= seq![PatElem::Star]);
                assert(text.push(text_c).skip(1) =~= Seq::empty());
                assert(wildcard_match_alt(text.push(text_c).skip(1), pattern));
            }
        } else {
            assert(text.push(text_c).skip(1) =~= text.skip(1).push(text_c));
            if wildcard(pattern[0]) {
                if wildcard_match_alt(text, pattern.skip(1)) {
                    lemma_wildcard_match_pattern_append_last_wildcard(text, pattern.skip(1), text_c);
                } else {
                    lemma_wildcard_match_pattern_append_last_wildcard(text.skip(1), pattern, text_c);
                }
            } else {
                lemma_wildcard_match_pattern_append_last_wildcard(text.skip(1), pattern.skip(1), text_c);
            }
        }
    }
}

proof fn lemma_empty_pattern_only_matches_empty_text(text: Seq<char>, pattern: Pattern)
    requires
        pattern.len() == 0,
        wildcard_match_alt(text, pattern),
    ensures text.len() == 0
{}

proof fn lemma_merge_adjacent_stars_aux(text: Seq<char>, pattern: Pattern)
    requires
        pattern.len() >= 2,
        wildcard_match_alt(text, pattern),
        wildcard(pattern[0]),
        wildcard(pattern[1]),
    ensures
        wildcard_match_alt(text, pattern.skip(1))
    decreases text.len()
{
    reveal_with_fuel(wildcard_match_alt, 2);
    if text.len() == 0 {
    } else {
        if !wildcard_match_alt(text, pattern.skip(1)) {
            lemma_merge_adjacent_stars_aux(text.skip(1), pattern);
        }
    }
}

// proof fn lemma_merge_adjacent_stars(text: Seq<char>, pattern: Pattern, j: int)
//     requires
//         pattern.len() >= j + 2,
//         wildcard_match_alt(text, pattern),
//         wildcard(pattern[j]),
//         wildcard(pattern[j+1]),
//     ensures
//         wildcard_match_alt(text, pattern.take(j + 1) + pattern.skip(j + 2))
// {
//     admit()
// }


// proof fn lemma_merge_adjacent_stars_join(text1: Seq<char>, pattern1: Pattern, text2: Seq<char>, pattern2: Pattern)
//     requires
//         pattern1.len() > 0, pattern2.len() > 0,
//         wildcard(pattern1.last()),
//         wildcard(pattern2[0]),
//         wildcard_match_alt(text1, pattern1),
//         wildcard_match_alt(text2, pattern2),
//     ensures
//         wildcard_match_alt(text1 + text2, pattern1 + pattern2.skip(1))
// {
//     assert(pattern1 + pattern2 =~= pattern1.drop_last() + seq![pattern1.last()] + seq![pattern2[0]] + pattern2.skip(1));
//     let j = pattern1.len() - 1;
//     assert(pattern1.last() == pattern1[j]);
//     assert((pattern1 + pattern2).take(j + 1) =~= pattern1);
//     assert((pattern1 + pattern2).skip(j + 2) =~= pattern2.skip(1));
//     lemma_merge_adjacent_stars(text1 + text2, pattern1 + pattern2, j);
// }




pub proof fn lemma_wildcard_match_skip_take(text: Seq<char>, pattern: Pattern, i: int, j: int)
    requires
        0 <= i <= text.len(),
        0 <= j <= pattern.len(),
        wildcard_match_alt(text.take(i), pattern.take(j)),
        wildcard_match_alt(text.skip(i), pattern.skip(j)),
    ensures
        wildcard_match_alt(text, pattern)
    decreases text.len() - i, pattern.len() - j
{
    reveal_with_fuel(wildcard_match_alt, 2);
    if j == pattern.len() && i == text.len() {
        assert(text.take(i) =~= text);
        assert(pattern.take(j) =~= pattern);
    } else if j == pattern.len() {
        assert(pattern.take(j) =~= pattern);
        assert(false);
    } else {
        assert(pattern[j] == pattern.skip(j)[0]);
        assert(pattern.skip(j+1) =~= pattern.skip(j).skip(1));
        assert(pattern.take(j+1) =~= pattern.take(j).push(pattern[j]));
        if i == text.len() {
            assert(text.take(i) =~= text);
            assert(wildcard(pattern[j]));
            lemma_wildcard_match_pattern_append_star(text.take(i), pattern.take(j));
            lemma_wildcard_match_skip_take(text, pattern, i, j+1);
        } else {
            assert(text[i] == text.skip(i)[0]);
            assert(text.skip(i+1) =~= text.skip(i).skip(1));
            assert(text.take(i+1) =~= text.take(i).push(text[i]));
            if wildcard(pattern[j]) {
                if wildcard_match_alt(text.skip(i), pattern.skip(j+1)) {
                    lemma_wildcard_match_pattern_append_star(text.take(i), pattern.take(j));
                    lemma_wildcard_match_skip_take(text, pattern, i, j+1);
                } else {
                    assert(wildcard_match_alt(text.skip(i+1), pattern.skip(j)));
                    lemma_wildcard_match_pattern_append_star_char(text.take(i), pattern.take(j), text[i], pattern[j]);
                    assert(wildcard_match_alt(text.take(i+1), pattern.take(j+1)));

                    // This, plus something like lemma_merge_adjacent_stars above, would be sufficient
                    // but we can't prove termination on this call
                    // lemma_wildcard_match_skip_take(text, pattern.take(j+1) + pattern.skip(j), i+1, j+1);

                    admit(); // need star-condensing lemma
                }
            } else {
                assert(char_match(text[i], pattern[j]));
                lemma_wildcard_match_pattern_append_matching_chars(text.take(i), pattern.take(j), text[i], pattern[j]);
                lemma_wildcard_match_skip_take(text, pattern, i+1, j+1);
            }
        }
    }
}

}
