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
