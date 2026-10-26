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

//! Lemmas relating the greedy two-pointer algorithm in
//! `Pattern::wildcard_match` to the model's recursive `wildcard_match`.
//!
//! `wm_at(t, p, i, j)` is the model matcher applied to the suffixes `t[i..]`
//! and `p[j..]`. The production loop maintains (writing `k` for `tmp_idx` and
//! `s` for `star_idx`):
//!
//! * before any `*` was seen: `wm_at(t, p, 0, 0) == wm_at(t, p, i, j)`;
//! * after: `p[s]` is a `*`, `p[s+1..j]` are characters equal to `t[k..i]`, and
//!   `wm_at(t, p, 0, 0) == wm_at(t, p, k, s)`.

use vstd::prelude::*;

use super::abs::*;
use super::model as m;
use crate::ast::PatternElem;

verus! {

/// The model pattern elements of production pattern elements.
pub open spec fn abs_elems(s: Seq<PatternElem>) -> Seq<m::expr::PatElem> {
    s.map_values(|e: PatternElem| abs_pattern_elem(e))
}

/// The invariant of the main loop of `Pattern::wildcard_match`: `res` is the
/// result of matching the whole text against the whole pattern.
pub open spec fn greedy_inv(
    t: Seq<char>,
    p: Seq<m::expr::PatElem>,
    res: bool,
    i: int,
    j: int,
    star_idx: int,
    tmp_idx: int,
    contains_star: bool,
) -> bool {
    &&& 0 <= i <= t.len()
    &&& 0 <= j <= p.len()
    &&& !contains_star ==> tmp_idx == 0 && res == wm_at(t, p, i, j)
    &&& contains_star ==> {
        &&& 0 <= star_idx < j
        &&& 0 <= tmp_idx <= i
        &&& i - tmp_idx == j - star_idx - 1
        &&& p[star_idx] is Star
        &&& seg_match(t, p, tmp_idx, star_idx + 1, j - star_idx - 1)
        &&& res == wm_at(t, p, tmp_idx, star_idx)
    }
}

/// The model matcher on the suffixes `t[i..]` and `p[j..]`.
pub open spec fn wm_at(t: Seq<char>, p: Seq<m::expr::PatElem>, i: int, j: int) -> bool {
    m::evaluator::wildcard_match(
        &seq_to_list(t.subrange(i, t.len() as int)),
        &seq_to_list(p.subrange(j, p.len() as int)),
    )
}

/// `p[j..j+len]` consists of the characters `t[i..i+len]`.
pub open spec fn seg_match(t: Seq<char>, p: Seq<m::expr::PatElem>, i: int, j: int, len: int) -> bool {
    forall|q: int| 0 <= q < len ==> #[trigger] p[j + q] == m::expr::PatElem::JustChar(t[i + q])
}

/// `p[j..j+len]` contains no `*`.
pub open spec fn no_star(p: Seq<m::expr::PatElem>, j: int, len: int) -> bool {
    forall|q: int| 0 <= q < len ==> #[trigger] p[j + q] is JustChar
}

pub proof fn lemma_seq_to_list_suffix<T>(s: Seq<T>, i: int)
    requires
        0 <= i <= s.len(),
    ensures
        i == s.len() ==> seq_to_list(s.subrange(i, s.len() as int)) == m::value::List::<T>::Nil,
        i < s.len() ==> seq_to_list(s.subrange(i, s.len() as int)) == m::value::List::Cons(
            s[i],
            Box::new(seq_to_list(s.subrange(i + 1, s.len() as int))),
        ),
{
    let sub = s.subrange(i, s.len() as int);
    if i < s.len() {
        assert(sub.subrange(1, sub.len() as int) =~= s.subrange(i + 1, s.len() as int));
    }
}

pub proof fn lemma_seq_to_list_full<T>(s: Seq<T>)
    ensures
        seq_to_list(s.subrange(0, s.len() as int)) == seq_to_list(s),
{
    assert(s.subrange(0, s.len() as int) =~= s);
}

/// One step of the model matcher.
pub proof fn lemma_wm_step(t: Seq<char>, p: Seq<m::expr::PatElem>, i: int, j: int)
    requires
        0 <= i <= t.len(),
        0 <= j <= p.len(),
    ensures
        j == p.len() ==> (wm_at(t, p, i, j) == (i == t.len())),
        j < p.len() && p[j] is Star ==> (wm_at(t, p, i, j) == (wm_at(t, p, i, j + 1) || (i
            < t.len() && wm_at(t, p, i + 1, j)))),
        j < p.len() && p[j] is JustChar ==> (wm_at(t, p, i, j) == (i < t.len() && p[j]
            == m::expr::PatElem::JustChar(t[i]) && wm_at(t, p, i + 1, j + 1))),
{
    lemma_seq_to_list_suffix(t, i);
    lemma_seq_to_list_suffix(p, j);
}

/// Matching a segment of characters.
pub proof fn lemma_wm_chars(t: Seq<char>, p: Seq<m::expr::PatElem>, i: int, j: int, len: int)
    requires
        0 <= i,
        0 <= j,
        0 <= len,
        i + len <= t.len(),
        j + len <= p.len(),
        seg_match(t, p, i, j, len),
    ensures
        wm_at(t, p, i, j) == wm_at(t, p, i + len, j + len),
    decreases len,
{
    if len > 0 {
        assert(p[j + 0] == m::expr::PatElem::JustChar(t[i + 0]));
        lemma_wm_step(t, p, i, j);
        assert forall|q: int| 0 <= q < len - 1 implies #[trigger] p[(j + 1) + q]
            == m::expr::PatElem::JustChar(t[(i + 1) + q]) by {
            assert(p[j + (q + 1)] == m::expr::PatElem::JustChar(t[i + (q + 1)]));
        }
        lemma_wm_chars(t, p, i + 1, j + 1, len - 1);
    }
}

/// If `p[s]` is a `*` and `t[x..]` matches `p[s..]`, then the `*` consumes
/// some `t[x..y]` and `t[y..]` matches `p[s+1..]`.
pub proof fn lemma_wm_star_split(t: Seq<char>, p: Seq<m::expr::PatElem>, x: int, s: int) -> (y: int)
    requires
        0 <= x <= t.len(),
        0 <= s < p.len(),
        p[s] is Star,
        wm_at(t, p, x, s),
    ensures
        x <= y <= t.len(),
        wm_at(t, p, y, s + 1),
    decreases t.len() - x,
{
    lemma_wm_step(t, p, x, s);
    if wm_at(t, p, x, s + 1) {
        x
    } else {
        lemma_wm_star_split(t, p, x + 1, s)
    }
}

/// A match of `p[j..]` (which begins with `len` characters) consumes `len`
/// characters of the text.
pub proof fn lemma_wm_no_star(t: Seq<char>, p: Seq<m::expr::PatElem>, y: int, j: int, len: int)
    requires
        0 <= y <= t.len(),
        0 <= j,
        0 <= len,
        j + len <= p.len(),
        no_star(p, j, len),
        wm_at(t, p, y, j),
    ensures
        y + len <= t.len(),
        wm_at(t, p, y + len, j + len),
    decreases len,
{
    if len > 0 {
        assert(p[j + 0] is JustChar);
        lemma_wm_step(t, p, y, j);
        assert forall|q: int| 0 <= q < len - 1 implies #[trigger] p[(j + 1) + q] is JustChar by {
            assert(p[j + (q + 1)] is JustChar);
        }
        lemma_wm_no_star(t, p, y + 1, j + 1, len - 1);
    }
}

/// A `*` can absorb more text: if `t[y..]` matches `p[j..]` then so does
/// `t[x..]` for `x <= y`.
pub proof fn lemma_wm_star_mono(t: Seq<char>, p: Seq<m::expr::PatElem>, x: int, y: int, j: int)
    requires
        0 <= x <= y <= t.len(),
        0 <= j < p.len(),
        p[j] is Star,
        wm_at(t, p, y, j),
    ensures
        wm_at(t, p, x, j),
    decreases y - x,
{
    if x < y {
        lemma_wm_star_mono(t, p, x + 1, y, j);
        lemma_wm_step(t, p, x, j);
    }
}

proof fn lemma_seg_no_star(t: Seq<char>, p: Seq<m::expr::PatElem>, i: int, j: int, len: int)
    requires
        seg_match(t, p, i, j, len),
    ensures
        no_star(p, j, len),
{
    assert forall|q: int| 0 <= q < len implies #[trigger] p[j + q] is JustChar by {
        assert(p[j + q] == m::expr::PatElem::JustChar(t[i + q]));
    }
}

/// The greedy algorithm meets a new `*` at `j`: the previous `*` (at `s`) can
/// be forgotten.
pub proof fn lemma_wm_new_star(t: Seq<char>, p: Seq<m::expr::PatElem>, k: int, s: int, i: int, j: int)
    requires
        0 <= k <= i <= t.len(),
        0 <= s < j < p.len(),
        p[s] is Star,
        p[j] is Star,
        i - k == j - s - 1,
        seg_match(t, p, k, s + 1, j - s - 1),
    ensures
        wm_at(t, p, k, s) == wm_at(t, p, i, j),
{
    let len = j - s - 1;
    lemma_wm_step(t, p, k, s);
    lemma_wm_chars(t, p, k, s + 1, len);
    if k < t.len() && wm_at(t, p, k + 1, s) {
        let y = lemma_wm_star_split(t, p, k + 1, s);
        lemma_seg_no_star(t, p, k, s + 1, len);
        lemma_wm_no_star(t, p, y, s + 1, len);
        lemma_wm_star_mono(t, p, i, y + len, j);
    }
}

/// The greedy algorithm reached the end of the text.
pub proof fn lemma_wm_text_end(t: Seq<char>, p: Seq<m::expr::PatElem>, k: int, s: int, j: int)
    requires
        0 <= k <= t.len(),
        0 <= s < j <= p.len(),
        p[s] is Star,
        t.len() - k == j - s - 1,
        seg_match(t, p, k, s + 1, j - s - 1),
    ensures
        wm_at(t, p, k, s) == wm_at(t, p, t.len() as int, j),
{
    let len = j - s - 1;
    lemma_wm_step(t, p, k, s);
    lemma_wm_chars(t, p, k, s + 1, len);
    if k < t.len() && wm_at(t, p, k + 1, s) {
        let y = lemma_wm_star_split(t, p, k + 1, s);
        lemma_seg_no_star(t, p, k, s + 1, len);
        lemma_wm_no_star(t, p, y, s + 1, len);
        assert(false);
    }
}

/// The greedy algorithm hit a mismatch after the `*` at `s`: let the `*`
/// consume one more character.
pub proof fn lemma_wm_mismatch(t: Seq<char>, p: Seq<m::expr::PatElem>, k: int, s: int, i: int, j: int)
    requires
        0 <= k <= i < t.len(),
        0 <= s < j <= p.len(),
        p[s] is Star,
        i - k == j - s - 1,
        seg_match(t, p, k, s + 1, j - s - 1),
        j == p.len() || p[j] != m::expr::PatElem::JustChar(t[i]),
        j == p.len() || p[j] is JustChar,
    ensures
        wm_at(t, p, k, s) == wm_at(t, p, k + 1, s),
{
    lemma_wm_step(t, p, k, s);
    lemma_wm_chars(t, p, k, s + 1, j - s - 1);
    lemma_wm_step(t, p, i, j);
}

/// A trailing `*` matches any suffix.
pub proof fn lemma_wm_star_end(t: Seq<char>, p: Seq<m::expr::PatElem>, k: int)
    requires
        0 <= k <= t.len(),
        p.len() > 0,
        p[p.len() - 1] is Star,
    ensures
        wm_at(t, p, k, p.len() - 1),
{
    lemma_wm_step(t, p, t.len() as int, p.len() as int);
    lemma_wm_step(t, p, t.len() as int, p.len() - 1);
    lemma_wm_star_mono(t, p, k, t.len() as int, p.len() - 1);
}

} // verus!
