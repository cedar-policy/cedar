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

//! The specification of graphs and paths (Verus only).
//!
//! `wf(g)`: every target is a node. `reach(g, u, v)`: `g` has a path of
//! length at least 1 from `u` to `v`. `has_cycle(g)`: some node reaches
//! itself. `closed_at(g, h, u)`: row `u` of `h` is exactly the set of nodes
//! `u` reaches in `g`.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
verus! {
/// Basic well-formedness: when a graph is repesented by its adjacency matrix, all the indices in the matrix
/// are smaller than the largest vertex's index.
pub open spec fn wf(g: Seq<Vec<usize>>) -> bool {
    forall|u: int, j: int| 0 <= u < g.len() && 0 <= j < g[u]@.len() ==> (#[trigger] g[u]@[j] as int) < g.len()
}

/// An edge between u and v means g[u] contains the index v
pub open spec fn edge(g: Seq<Vec<usize>>, u: int, v: int) -> bool {
    0 <= u < g.len() && 0 <= v < g.len() && g[u]@.contains(v as usize)
}

/// k-reachability: `v`` is reachable from `u`` iff there exists a path of length `1..=k` from `u` to `v`.
pub open spec fn reach_n(g: Seq<Vec<usize>>, u: int, v: int, k: nat) -> bool
    decreases k,
{
    if k == 0 {
        false
    } else {
        edge(g, u, v) || exists|w: int| #[trigger] edge(g, u, w) && reach_n(g, w, v, (k - 1) as nat)
    }
}

/// Reachability: `v` is reachable from `u` iff there exists `k` such that `v` is k-reachable from `u`
pub open spec fn reach(g: Seq<Vec<usize>>, u: int, v: int) -> bool {
    exists|k: nat| #[trigger] reach_n(g, u, v, k)
}

/// Cyclicity: a graph has a cycle iff there exists a vertex that is reachable from itself. Note
/// that reachable means there exists a path of length >= 1.
pub open spec fn has_cycle(g: Seq<Vec<usize>>) -> bool {
    exists|u: int| 0 <= u < g.len() && #[trigger] reach(g, u, u)
}

/// `h` is the closure of `g` at `u` if and edge between `u` and `v` exists in `h` iff `v` is reachable
/// from `u` in `g`.
pub open spec fn closed_at(g: Seq<Vec<usize>>, h: Seq<Vec<usize>>, u: int) -> bool {
    forall|v: int| 0 <= v < g.len() ==> (h[u]@.contains(v as usize) <==> #[trigger] reach(g, u, v))
}

/// An edge between `u` and `v` implies `v` is reachable from `u` (in one step)
pub proof fn lemma_reach_edge(g: Seq<Vec<usize>>, u: int, v: int)
    requires
        edge(g, u, v),
    ensures
        reach(g, u, v),
{
    assert(reach_n(g, u, v, 1));
}

/// `g[u][j]` is an edge.
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

/// A node with an out-path is a node with a nonempty row.
pub proof fn lemma_reach_src_in_range(g: Seq<Vec<usize>>, u: int, v: int)
    requires
        reach(g, u, v),
    ensures
        0 <= u < g.len(),
        g[u]@.len() > 0,
{
    lemma_reach_first(g, u, v);
    let w = choose|w: int| #[trigger] edge(g, u, w) && (w == v || reach(g, w, v));
    assert(g[u]@.contains(w as usize));
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

/// If every row of `g` is contained in the row of `h`, and every edge of `h`
/// is a path of `g`, then `h` and `g` have the same paths.
pub proof fn lemma_reach_super(g: Seq<Vec<usize>>, h: Seq<Vec<usize>>, u: int, v: int)
    requires
        h.len() == g.len(),
        forall|x: int, y: usize| 0 <= x < g.len() && #[trigger] g[x]@.contains(y) ==> h[x]@.contains(y),
        forall|x: int, y: int| 0 <= x < g.len() && 0 <= y < g.len() && #[trigger] h[x]@.contains(y as usize) ==> reach(g, x, y),
    ensures
        reach(h, u, v) <==> reach(g, u, v),
{
    if reach(g, u, v) {
        let k = choose|k: nat| #[trigger] reach_n(g, u, v, k);
        lemma_reach_n_sub(g, h, u, v, k);
    }
    if reach(h, u, v) {
        let k = choose|k: nat| #[trigger] reach_n(h, u, v, k);
        lemma_reach_n_super(g, h, u, v, k);
    }
}

proof fn lemma_reach_n_sub(g: Seq<Vec<usize>>, h: Seq<Vec<usize>>, u: int, v: int, k: nat)
    requires
        h.len() == g.len(),
        forall|x: int, y: usize| 0 <= x < g.len() && #[trigger] g[x]@.contains(y) ==> h[x]@.contains(y),
        reach_n(g, u, v, k),
    ensures
        reach_n(h, u, v, k),
    decreases k,
{
    if edge(g, u, v) {
        assert(h[u]@.contains(v as usize));
    } else {
        let w = choose|w: int| #[trigger] edge(g, u, w) && reach_n(g, w, v, (k - 1) as nat);
        lemma_reach_n_sub(g, h, w, v, (k - 1) as nat);
        assert(h[u]@.contains(w as usize));
        assert(edge(h, u, w));
    }
}

proof fn lemma_reach_n_super(g: Seq<Vec<usize>>, h: Seq<Vec<usize>>, u: int, v: int, k: nat)
    requires
        h.len() == g.len(),
        forall|x: int, y: int| 0 <= x < g.len() && 0 <= y < g.len() && #[trigger] h[x]@.contains(y as usize) ==> reach(g, x, y),
        reach_n(h, u, v, k),
    ensures
        reach(g, u, v),
    decreases k,
{
    if edge(h, u, v) {
        assert(h[u]@.contains(v as usize));
    } else {
        let w = choose|w: int| #[trigger] edge(h, u, w) && reach_n(h, w, v, (k - 1) as nat);
        lemma_reach_n_super(g, h, w, v, (k - 1) as nat);
        assert(h[u]@.contains(w as usize));
        lemma_reach_trans(g, u, w, v);
    }
}

} // verus!
