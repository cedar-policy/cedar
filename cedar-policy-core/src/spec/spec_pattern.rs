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

}

////////////////////////////////////////////////
// Helper definitions and lemmas for patterns //
////////////////////////////////////////////////
verus! {

// Alternative version of `wildcard_match` recursing from the end, rather than the beginning

pub open spec fn wildcard_match_rev_idx(text: Seq<char>, pattern: Pattern, i: int, j: int) -> bool
    decreases i, j
{
    if i < 0 || i > text.len() || j < 0 || j > pattern.len() {
        arbitrary()
    } else if i == 0 && j == 0 {
        // empty pattern matches empty string
        true
    } else if i == 0 {
        // all of the pattern should be wildcards
        wildcard(pattern[j]) && wildcard_match_rev_idx(text, pattern, i, j-1)
    } else if j == 0 {
        // the pattern is empty and there are still some text characters to match
        false
    } else if wildcard(pattern[j]) {
        // either we can match zero characters with the wildcard (decrement j),
        // or we can match one character with the wildcard (decrement i) and continue using it
        wildcard_match_rev_idx(text, pattern, i, j-1) || wildcard_match_rev_idx(text, pattern, i-1, j)
    } else {
        // we must match the character exactly and continue
        char_match(text[i], pattern[j]) && wildcard_match_rev_idx(text, pattern, i-1, j-1)
    }
}

pub proof fn lemma_wildcard_match_idx_rev_idx_equiv_aux(text: Seq<char>, pattern: Pattern, i: int, j: int)
    ensures wildcard_match_idx(text.subrange(0,i), pattern.subrange(0,j), 0, 0) == wildcard_match_rev_idx(text, pattern, i, j)
    decreases i, j
{
    admit()
    // reveal_with_fuel(wildcard_match_idx, 2);
    // reveal_with_fuel(wildcard_match_rev_idx, 2);
    // if i == 0 && j == 0 {
    //     // empty pattern matches empty string
    //     assert(wildcard_match_rev_idx(text, pattern, i, j));
    //     assert(wildcard_match_idx(text, pattern, 0, 0));
    // } else if i == 0 {
    //     // all of the pattern should be wildcards
    //     assert(wildcard_match_idx(text.subrange(0,i), pattern.subrange(0,j), 0, 0) == wildcard_match_rev_idx(text, pattern, i, j));
    // } else if j == 0 {
    //     // the pattern is empty and there are still some text characters to match
    //     assert(wildcard_match_idx(text.subrange(0,i), pattern.subrange(0,j), 0, 0) == wildcard_match_rev_idx(text, pattern, i, j));
    // } else if wildcard(pattern[j]) {
    //     // either we can match zero characters with the wildcard (decrement j),
    //     // or we can match one character with the wildcard (decrement i) and continue using it
    //     assert(wildcard_match_idx(text.subrange(0,i), pattern.subrange(0,j), 0, 0) == wildcard_match_rev_idx(text, pattern, i, j));
    // } else {
    //     // we must match the character exactly and continue
    //     assert(wildcard_match_idx(text.subrange(0,i), pattern.subrange(0,j), 0, 0) == wildcard_match_rev_idx(text, pattern, i, j));
    // }
}

pub proof fn lemma_wildcard_match_idx_rev_idx_equiv(text: Seq<char>, pattern: Pattern)
    ensures wildcard_match_idx(text, pattern, 0, 0) == wildcard_match_rev_idx(text, pattern, text.len() as int, pattern.len() as int)
{
    assert(text.subrange(0, text.len() as int) =~= text);
    assert(pattern.subrange(0, pattern.len() as int) =~= pattern);
    lemma_wildcard_match_idx_rev_idx_equiv_aux(text, pattern, text.len() as int, pattern.len() as int);
}

}
