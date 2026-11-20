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

//! DAG checks on a transitive closure.
//!
//! [`first_self_loop`] returns the first node of `order` whose row contains
//! itself. `lemma_compute_dag_check` states that, on the result of
//! [`crate::transitive_closure`] and an order containing every node with a
//! nonempty row, it returns `None` iff the input has no cycle.
//! `lemma_repair_dag_check` states that, on the result of
//! [`crate::repair_closure`] and the order `fix`, `Some` implies that the
//! input has a cycle. The converse does not hold when no cycle goes through
//! `fix`.

#[cfg(verus_keep_ghost)]
use crate::graph::*;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// Whether `row` contains `u`.
#[cfg_attr(verus_keep_ghost, verus_spec(res =>
    ensures
        res == row@.contains(u),
))]
pub(crate) fn row_contains(row: &Vec<usize>, u: usize) -> bool {
    let mut j: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            j <= row.len(),
            forall|k: int| 0 <= k < j ==> #[trigger] row@[k] != u,
        decreases row.len() - j
    ))]
    while j < row.len() {
        if row[j] == u {
            return true;
        }
        j += 1;
    }
    false
}

/// The first node `u` of `order` whose row `r[u]` contains `u`.
#[cfg_attr(verus_keep_ghost, verus_spec(res =>
    requires
        forall|i: int| 0 <= i < order.len() ==> (#[trigger] order@[i] as int) < r.len(),
    ensures
        match res {
            None => forall|i: int| 0 <= i < order.len() ==>
                !r@[#[trigger] order@[i] as int]@.contains(order@[i]),
            Some(u) => exists|i: int| 0 <= i < order.len() && #[trigger] order@[i] == u
                && r@[u as int]@.contains(u)
                && forall|j: int| 0 <= j < i ==> !r@[#[trigger] order@[j] as int]@.contains(order@[j]),
        },
))]
pub fn first_self_loop(r: &Vec<Vec<usize>>, order: &Vec<usize>) -> Option<usize> {
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            i <= order.len(),
            forall|k: int| 0 <= k < order.len() ==> (#[trigger] order@[k] as int) < r.len(),
            forall|j: int| 0 <= j < i ==> !r@[#[trigger] order@[j] as int]@.contains(order@[j]),
        decreases order.len() - i
    ))]
    while i < order.len() {
        let u = order[i];
        if row_contains(&r[u], u) {
            proof! {
                assert(order@[i as int] == u);
            }
            return Some(u);
        }
        i += 1;
    }
    None
}

#[cfg(verus_keep_ghost)]
verus! {

/// The DAG check of `compute_tc`: if `r` is the closure of `g` (the theorem
/// of `transitive_closure`) and `order` contains every node with a nonempty
/// row, then `g` has a cycle iff some node has a self-edge in `r`, iff some
/// node of `order` has a self-edge in `r`.
pub proof fn lemma_compute_dag_check(g: Seq<Vec<usize>>, r: Seq<Vec<usize>>, order: Seq<usize>)
    requires
        wf(g),
        g.len() <= usize::MAX,
        r.len() == g.len(),
        forall|u: int, v: int| 0 <= u < g.len() && 0 <= v < g.len() ==>
            (r[u]@.contains(v as usize) <==> #[trigger] reach(g, u, v)),
        forall|i: int| 0 <= i < order.len() ==> (#[trigger] order[i] as int) < g.len(),
        forall|u: int| 0 <= u < g.len() && #[trigger] g[u]@.len() > 0 ==> order.contains(u as usize),
    ensures
        has_cycle(g) <==> exists|u: int| 0 <= u < r.len() && #[trigger] r[u]@.contains(u as usize),
        has_cycle(g) <==> exists|i: int| 0 <= i < order.len()
            && r[#[trigger] order[i] as int]@.contains(order[i]),
{
    if has_cycle(g) {
        let u = choose|u: int| 0 <= u < g.len() && #[trigger] reach(g, u, u);
        lemma_reach_src_in_range(g, u, u);
        assert(r[u]@.contains(u as usize));
        let i = choose|i: int| 0 <= i < order.len() && order[i] == u as usize;
        assert(r[order[i] as int]@.contains(order[i]));
    }
    if exists|u: int| 0 <= u < r.len() && #[trigger] r[u]@.contains(u as usize) {
        let u = choose|u: int| 0 <= u < r.len() && #[trigger] r[u]@.contains(u as usize);
        assert(reach(g, u, u));
    }
    if exists|i: int| 0 <= i < order.len() && r[#[trigger] order[i] as int]@.contains(order[i]) {
        let i = choose|i: int| 0 <= i < order.len() && r[#[trigger] order[i] as int]@.contains(order[i]);
        let u = order[i] as int;
        assert(r[u]@.contains(u as usize));
        assert(reach(g, u, u));
    }
}

/// The DAG check of `repair_tc`: if every edge of `g1` is a path of `g0`
/// (R3 of `repair_closure`), a self-edge in `g1` at a node of `fix` implies
/// that `g0` has a cycle (D1). Equivalently, if `g0` has no cycle, no node
/// of `fix` has a self-edge (D2).
pub proof fn lemma_repair_dag_check(g0: Seq<Vec<usize>>, g1: Seq<Vec<usize>>, fix: Seq<usize>)
    requires
        g1.len() == g0.len(),
        forall|u: int, v: usize| 0 <= u < g0.len() && #[trigger] g1[u]@.contains(v) ==> reach(g0, u, v as int),
        forall|i: int| 0 <= i < fix.len() ==> (#[trigger] fix[i] as int) < g0.len(),
    ensures
        (exists|i: int| 0 <= i < fix.len() && g1[#[trigger] fix[i] as int]@.contains(fix[i])) ==> has_cycle(g0),
        !has_cycle(g0) ==> forall|i: int| 0 <= i < fix.len() ==> !g1[#[trigger] fix[i] as int]@.contains(fix[i]),
{
    if exists|i: int| 0 <= i < fix.len() && g1[#[trigger] fix[i] as int]@.contains(fix[i]) {
        let i = choose|i: int| 0 <= i < fix.len() && g1[#[trigger] fix[i] as int]@.contains(fix[i]);
        let u = fix[i] as int;
        assert(g1[u]@.contains(u as usize));
        assert(reach(g0, u, u));
    }
}

} // verus!

#[cfg(test)]
mod tests {
    use super::first_self_loop;

    #[test]
    fn first_self_loop_order() {
        // 0 -> 1, 1 -> {1, 2}, 2 -> 2
        let r = vec![vec![1], vec![1, 2], vec![2]];
        assert_eq!(first_self_loop(&r, &vec![0, 1, 2]), Some(1));
        assert_eq!(first_self_loop(&r, &vec![2, 1, 0]), Some(2));
        assert_eq!(first_self_loop(&r, &vec![0]), None);
        assert_eq!(first_self_loop(&r, &vec![]), None);
    }

    #[test]
    fn first_self_loop_none() {
        let r = vec![vec![1, 2], vec![2], vec![]];
        assert_eq!(first_self_loop(&r, &vec![0, 1, 2]), None);
    }
}
