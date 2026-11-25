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

//! The spec fns for graphs and paths, and lemmas about paths. Everything
//! here is ghost, so the module is empty under Cargo.
//!
//! `reach` is defined through `reach_n`, a path of length 1 to `k`, and the
//! lemmas are proved by induction on `k`: transitivity
//! (`lemma_reach_trans`), the first step of a path (`lemma_reach_first`),
//! and the range of its endpoints.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
verus! {
/// Every target of every row is a node: below `g.len()`.
pub open spec fn wf(g: Seq<Vec<usize>>) -> bool {
    forall|u: int, j: int| 0 <= u < g.len() && 0 <= j < g[u]@.len() ==> (#[trigger] g[u]@[j] as int) < g.len()
}

/// `u` and `v` are nodes and `g[u]` contains `v`.
pub open spec fn edge(g: Seq<Vec<usize>>, u: int, v: int) -> bool {
    0 <= u < g.len() && 0 <= v < g.len() && g[u]@.contains(v as usize)
}

/// `g` has a path of length 1 to `k` from `u` to `v`.
pub open spec fn reach_n(g: Seq<Vec<usize>>, u: int, v: int, k: nat) -> bool
    decreases k,
{
    if k == 0 {
        false
    } else {
        edge(g, u, v) || exists|w: int| #[trigger] edge(g, u, w) && reach_n(g, w, v, (k - 1) as nat)
    }
}

/// `g` has a path of length at least 1 from `u` to `v`.
pub open spec fn reach(g: Seq<Vec<usize>>, u: int, v: int) -> bool {
    exists|k: nat| #[trigger] reach_n(g, u, v, k)
}

/// Some node reaches itself.
pub open spec fn has_cycle(g: Seq<Vec<usize>>) -> bool {
    exists|u: int| 0 <= u < g.len() && #[trigger] reach(g, u, u)
}

/// Row `u` of `h` contains exactly the nodes that `u` reaches in `g`.
pub open spec fn closed_at(g: Seq<Vec<usize>>, h: Seq<Vec<usize>>, u: int) -> bool {
    forall|v: int| 0 <= v < g.len() ==> (h[u]@.contains(v as usize) <==> #[trigger] reach(g, u, v))
}

pub proof fn lemma_reach_edge(g: Seq<Vec<usize>>, u: int, v: int)
    requires
        edge(g, u, v),
    ensures
        reach(g, u, v),
{
    assert(reach_n(g, u, v, 1));
}

pub proof fn lemma_edge_at(g: Seq<Vec<usize>>, u: int, j: int)
    requires
        wf(g),
        0 <= u < g.len(),
        0 <= j < g[u]@.len(),
    ensures
        edge(g, u, g[u]@[j] as int),
        reach(g, u, g[u]@[j] as int),
{
    assert((g[u]@[j] as int) < g.len());
    assert(g[u]@.contains(g[u]@[j]));
    lemma_reach_edge(g, u, g[u]@[j] as int);
}

pub proof fn lemma_reach_n_mono(g: Seq<Vec<usize>>, u: int, v: int, k: nat, k2: nat)
    requires
        k <= k2,
        reach_n(g, u, v, k),
    ensures
        reach_n(g, u, v, k2),
    decreases k,
{
    if !edge(g, u, v) {
        let w = choose|w: int| #[trigger] edge(g, u, w) && reach_n(g, w, v, (k - 1) as nat);
        lemma_reach_n_mono(g, w, v, (k - 1) as nat, (k2 - 1) as nat);
        assert(reach_n(g, w, v, (k2 - 1) as nat));
    }
}

proof fn lemma_reach_n_trans(g: Seq<Vec<usize>>, u: int, w: int, v: int, k1: nat, k2: nat)
    requires
        reach_n(g, u, w, k1),
        reach_n(g, w, v, k2),
    ensures
        reach_n(g, u, v, k1 + k2),
    decreases k1,
{
    if edge(g, u, w) {
        assert(reach_n(g, u, v, k2 + 1));
        lemma_reach_n_mono(g, u, v, k2 + 1, k1 + k2);
    } else {
        let x = choose|x: int| #[trigger] edge(g, u, x) && reach_n(g, x, w, (k1 - 1) as nat);
        lemma_reach_n_trans(g, x, w, v, (k1 - 1) as nat, k2);
        assert(reach_n(g, x, v, (k1 + k2 - 1) as nat));
    }
}

pub proof fn lemma_reach_trans(g: Seq<Vec<usize>>, u: int, w: int, v: int)
    requires
        reach(g, u, w),
        reach(g, w, v),
    ensures
        reach(g, u, v),
{
    let k1 = choose|k: nat| #[trigger] reach_n(g, u, w, k);
    let k2 = choose|k: nat| #[trigger] reach_n(g, w, v, k);
    lemma_reach_n_trans(g, u, w, v, k1, k2);
}

/// The first step of a path.
pub proof fn lemma_reach_first(g: Seq<Vec<usize>>, u: int, v: int)
    requires
        reach(g, u, v),
    ensures
        exists|w: int| #[trigger] edge(g, u, w) && (w == v || reach(g, w, v)),
{
    let k = choose|k: nat| #[trigger] reach_n(g, u, v, k);
    if !edge(g, u, v) {
        let w = choose|w: int| #[trigger] edge(g, u, w) && reach_n(g, w, v, (k - 1) as nat);
        assert(reach(g, w, v));
    }
}

pub proof fn lemma_reach_tgt_in_range(g: Seq<Vec<usize>>, u: int, v: int)
    requires
        reach(g, u, v),
    ensures
        0 <= v < g.len(),
{
    let k = choose|k: nat| #[trigger] reach_n(g, u, v, k);
    lemma_reach_n_tgt_in_range(g, u, v, k);
}

proof fn lemma_reach_n_tgt_in_range(g: Seq<Vec<usize>>, u: int, v: int, k: nat)
    requires
        reach_n(g, u, v, k),
    ensures
        0 <= v < g.len(),
    decreases k,
{
    if !edge(g, u, v) {
        let w = choose|w: int| #[trigger] edge(g, u, w) && reach_n(g, w, v, (k - 1) as nat);
        lemma_reach_n_tgt_in_range(g, w, v, (k - 1) as nat);
    }
}

} // verus!
