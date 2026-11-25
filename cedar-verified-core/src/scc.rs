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

//! Strongly connected components, by Tarjan's algorithm.
//!
//! `sccs` numbers the components in completion order and proves P1–P3
//! (`sccs_ok`): an edge never goes to a component with a larger id (P1), two
//! distinct nodes of one component reach each other (P2), and `members[c]`
//! is exactly the nodes of component `c` (P3). Maximality of the components
//! is not proved; the transitive closure does not need it.
//!
//! `strongconnect` is the Tarjan search from one node, as a loop over an
//! explicit stack of frames. The search state satisfies `inv` throughout.
//! The top frame satisfies `loop_inv`, the invariant of its edge loop. Each
//! suspended frame satisfies `frozen`: `loop_inv` from its entry state to the
//! entry state of the frame above it, which stays true while the frames
//! above run (`lemma_frozen_keep`). When the last frame finishes, `sc_post`,
//! the contract of the search, holds. The loop terminates by the
//! lexicographic decreases `(g.len() - st.next, fv.len(), sc_rem)`.

#[cfg(verus_keep_ghost)]
use crate::graph::*;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// Unvisited (in `index`) or not yet assigned (in `comp`).
#[cfg_attr(verus_keep_ghost, verus_spec)]
pub(crate) const NONE: usize = usize::MAX;

/// The components of a graph.
pub(crate) struct Sccs {
    /// `comp[u]`: the component id of node `u`.
    pub(crate) comp: Vec<usize>,
    /// `members[c]`: the nodes of component `c`.
    pub(crate) members: Vec<Vec<usize>>,
}

/// The Tarjan search state: the discovery `index` of each node (`NONE` if
/// unvisited), `on_stack`, the Tarjan `stack`, the component `comp` of each
/// node (`NONE` if unassigned), the next index and the number of components.
struct State {
    index: Vec<usize>,
    on_stack: Vec<bool>,
    stack: Vec<usize>,
    comp: Vec<usize>,
    next: usize,
    ncomp: usize,
}

#[cfg(verus_keep_ghost)]
verus! {

/// `s` gives every node of `g` a component, with P1–P3.
pub(crate) open spec fn sccs_ok(g: Seq<Vec<usize>>, s: Sccs) -> bool {
    let n = g.len();
    &&& s.comp.len() == n
    &&& forall|x: int| 0 <= x < n ==> (#[trigger] s.comp@[x] as int) < s.members.len()
    &&& forall|x: int, j: int| 0 <= x < n && 0 <= j < g[x]@.len() ==>
        s.comp@[#[trigger] g[x]@[j] as int] <= s.comp@[x]
    &&& forall|x: int, y: int| 0 <= x < n && 0 <= y < n && #[trigger] s.comp@[x] == #[trigger] s.comp@[y] && x != y ==>
        reach(g, x, y)
    &&& forall|c: int, k: int| 0 <= c < s.members.len() && 0 <= k < s.members@[c]@.len() ==>
        (#[trigger] s.members@[c]@[k] as int) < n && s.comp@[s.members@[c]@[k] as int] == c
    &&& forall|x: int| 0 <= x < n ==> #[trigger] s.members@[s.comp@[x] as int]@.contains(x as usize)
}

/// The number of visited entries (not `NONE`) among the first `k` of `s`.
spec fn count_vis(s: Seq<usize>, k: int) -> int
    decreases k,
{
    if k <= 0 {
        0
    } else {
        count_vis(s, k - 1) + if s[k - 1] != NONE { 1int } else { 0int }
    }
}

proof fn lemma_count_bound(s: Seq<usize>, k: int)
    requires
        0 <= k <= s.len(),
    ensures
        0 <= count_vis(s, k) <= k,
    decreases k,
{
    if k > 0 {
        lemma_count_bound(s, k - 1);
    }
}

proof fn lemma_count_eq(s: Seq<usize>, t: Seq<usize>, k: int)
    requires
        0 <= k <= s.len(),
        k <= t.len(),
        forall|j: int| 0 <= j < k ==> (s[j] != NONE) == (t[j] != NONE),
    ensures
        count_vis(s, k) == count_vis(t, k),
    decreases k,
{
    if k > 0 {
        lemma_count_eq(s, t, k - 1);
    }
}

proof fn lemma_count_zero(s: Seq<usize>, k: int)
    requires
        0 <= k <= s.len(),
        forall|j: int| 0 <= j < k ==> s[j] == NONE,
    ensures
        count_vis(s, k) == 0,
    decreases k,
{
    if k > 0 {
        lemma_count_zero(s, k - 1);
    }
}

proof fn lemma_count_set(s: Seq<usize>, k: int, u: int, x: usize)
    requires
        0 <= u < k <= s.len(),
        s[u] == NONE,
        x != NONE,
    ensures
        count_vis(s.update(u, x), k) == count_vis(s, k) + 1,
    decreases k,
{
    if k - 1 > u {
        lemma_count_set(s, k - 1, u, x);
    } else {
        lemma_count_eq(s, s.update(u, x), u);
    }
}

proof fn lemma_count_lt(s: Seq<usize>, k: int, u: int)
    requires
        0 <= u < k <= s.len(),
        s[u] == NONE,
    ensures
        count_vis(s, k) < k,
{
    lemma_count_set(s, k, u, 0);
    lemma_count_bound(s.update(u, 0), k);
}

/// The invariant of the search state: `wf(g)`, `lens` and `inv_q`.
spec fn inv(g: Seq<Vec<usize>>, st: State) -> bool {
    &&& wf(g)
    &&& lens(g, st)
    &&& inv_q(g, st)
}

/// The lengths of the state vectors, and bounds on `next`, `ncomp` and the
/// stack entries.
spec fn lens(g: Seq<Vec<usize>>, st: State) -> bool {
    &&& g.len() <= usize::MAX
    &&& st.index.len() == g.len()
    &&& st.on_stack.len() == g.len()
    &&& st.comp.len() == g.len()
    &&& st.next <= g.len()
    &&& st.ncomp + st.stack.len() <= st.next
    &&& forall|i: int| 0 <= i < st.stack.len() ==> (#[trigger] st.stack@[i] as int) < g.len()
}

/// The quantified part of `inv`: `next` counts the visited nodes, a node is
/// on the stack iff it is visited and unassigned, stack indices increase,
/// and the assigned nodes satisfy P1 and P2.
#[verifier::opaque]
spec fn inv_q(g: Seq<Vec<usize>>, st: State) -> bool {
    let n = g.len();
    &&& st.next == count_vis(st.index@, n as int)
    &&& forall|x: int| 0 <= x < n && #[trigger] st.index@[x] != NONE ==> st.index@[x] < st.next
    &&& forall|x: int| 0 <= x < n ==>
        (#[trigger] st.on_stack@[x] <==> (st.index@[x] != NONE && st.comp@[x] == NONE))
    &&& forall|x: int| 0 <= x < n && st.index@[x] == NONE ==> #[trigger] st.comp@[x] == NONE
    &&& forall|x: int| 0 <= x < n && #[trigger] st.comp@[x] != NONE ==> st.comp@[x] < st.ncomp
    &&& forall|i: int| 0 <= i < st.stack.len() ==> st.on_stack@[#[trigger] st.stack@[i] as int]
    &&& forall|x: int| 0 <= x < n && #[trigger] st.on_stack@[x] ==> st.stack@.contains(x as usize)
    &&& forall|i: int, j: int| 0 <= i < j < st.stack.len() ==>
        st.index@[#[trigger] st.stack@[i] as int] < st.index@[#[trigger] st.stack@[j] as int]
    &&& forall|x: int, j: int| 0 <= x < n && 0 <= j < g[x]@.len() && st.comp@[x] != NONE ==>
        st.comp@[#[trigger] g[x]@[j] as int] != NONE && st.comp@[g[x]@[j] as int] <= st.comp@[x]
    &&& forall|x: int, y: int| 0 <= x < n && 0 <= y < n && st.comp@[x] != NONE
        && #[trigger] st.comp@[x] == #[trigger] st.comp@[y] && x != y ==> reach(g, x, y)
}

/// An edge to `t` is either to an assigned component, or to a node on the
/// stack with an index at least `low`.
spec fn out_ok(st: State, t: int, low: int) -> bool {
    st.comp@[t] != NONE || (st.on_stack@[t] && st.index@[t] >= low)
}

/// Nodes visited before `s0` keep their index, assigned components and
/// stack entries.
spec fn frame(n: int, s0: State, s1: State) -> bool {
    &&& forall|x: int| 0 <= x < n && s0.index@[x] != NONE ==> #[trigger] s1.index@[x] == s0.index@[x]
    &&& forall|x: int| 0 <= x < n && s0.comp@[x] != NONE ==> #[trigger] s1.comp@[x] == s0.comp@[x]
    &&& forall|x: int| 0 <= x < n && s0.on_stack@[x] ==> #[trigger] s1.on_stack@[x]
    &&& s1.stack.len() >= s0.stack.len()
    &&& forall|i: int| 0 <= i < s0.stack.len() ==> #[trigger] s1.stack@[i] == s0.stack@[i]
}

/// The contract of a search `strongconnect(v)` from `s0` to `s1` that
/// returns the low-link `low`, besides `inv`.
spec fn sc_post(g: Seq<Vec<usize>>, s0: State, s1: State, v: int, low: int) -> bool {
    let b = s0.stack.len() as int;
    &&& s1.next > s0.next
    &&& s1.index@[v] == s0.next
    &&& frame(g.len() as int, s0, s1)
    &&& low <= s1.index@[v]
    &&& low == s1.index@[v] ==> s1.stack.len() == b && s1.comp@[v] != NONE
    &&& low < s1.index@[v] ==> {
        &&& s1.stack.len() > b
        &&& s1.stack@[b] == v
        &&& forall|i: int| b < i < s1.stack.len() ==> reach(g, #[trigger] s1.stack@[i] as int, v)
        &&& exists|i: int| 0 <= i < b && #[trigger] s1.index@[s0.stack@[i] as int] == low
            && reach(g, v, s0.stack@[i] as int)
    }
    &&& forall|i: int| b < i < s1.stack.len() ==> reach(g, v, #[trigger] s1.stack@[i] as int)
    &&& forall|i: int, j: int| b <= i < s1.stack.len() && 0 <= j < g[s1.stack@[i] as int]@.len() ==>
        out_ok(s1, #[trigger] g[s1.stack@[i] as int]@[j] as int, low)
}

/// The invariant of the edge loop of the frame of `v`, entered from `s0`,
/// after `i` edges, with the current low-link `low`.
#[verifier::opaque]
spec fn loop_inv(g: Seq<Vec<usize>>, s0: State, st: State, v: int, low: int, i: int) -> bool {
    let n = g.len();
    let b = s0.stack.len() as int;
    let idx = s0.next as int;
    &&& 0 <= v < n
    &&& 0 <= i <= g[v]@.len()
    &&& st.next > idx
    &&& st.index@[v] == idx
    &&& st.stack.len() > b
    &&& st.stack@[b] == v
    &&& frame(n as int, s0, st)
    &&& forall|k: int| 0 <= k < b ==> reach(g, #[trigger] s0.stack@[k] as int, v)
    &&& forall|k: int| b < k < st.stack.len() ==> reach(g, #[trigger] st.stack@[k] as int, v)
    &&& forall|k: int| b < k < st.stack.len() ==> reach(g, v, #[trigger] st.stack@[k] as int)
    &&& low <= idx
    &&& low < idx ==> exists|k: int| 0 <= k < b && #[trigger] st.index@[s0.stack@[k] as int] == low
        && reach(g, v, s0.stack@[k] as int)
    &&& forall|k: int, j: int| b <= k < st.stack.len() && 0 <= j < g[st.stack@[k] as int]@.len()
        && (k > b || j < i) ==> out_ok(st, #[trigger] g[st.stack@[k] as int]@[j] as int, low)
}

/// The popping loop, from `sb` (stack `sb.stack`) down to `st.stack.len()`;
/// popped nodes get component `c`.
spec fn pop_inv(g: Seq<Vec<usize>>, sb: State, st: State, c: usize) -> bool {
    let n = g.len();
    &&& st.stack.len() <= sb.stack.len()
    &&& st.stack@ == sb.stack@.subrange(0, st.stack.len() as int)
    &&& st.index@ == sb.index@
    &&& st.next == sb.next
    &&& st.comp.len() == n
    &&& st.on_stack.len() == n
    &&& st.index.len() == n
    &&& forall|x: int| 0 <= x < n && !sb.on_stack@[x] ==>
        #[trigger] st.comp@[x] == sb.comp@[x] && !st.on_stack@[x]
    &&& forall|k: int| 0 <= k < st.stack.len() ==>
        st.comp@[#[trigger] sb.stack@[k] as int] == NONE && st.on_stack@[sb.stack@[k] as int]
    &&& forall|k: int| st.stack.len() <= k < sb.stack.len() ==>
        st.comp@[#[trigger] sb.stack@[k] as int] == c && !st.on_stack@[sb.stack@[k] as int]
}

proof fn lemma_next_lt(g: Seq<Vec<usize>>, st: State, v: int)
    requires
        inv(g, st),
        0 <= v < g.len(),
        st.index@[v] == NONE,
    ensures
        st.next < g.len(),
{
    reveal(inv_q);
    lemma_count_lt(st.index@, g.len() as int, v);
}

proof fn lemma_push(g: Seq<Vec<usize>>, s0: State, st: State, v: int)
    requires
        inv(g, s0),
        0 <= v < g.len(),
        s0.index@[v] == NONE,
        s0.next < g.len(),
        st.index@ == s0.index@.update(v, s0.next),
        st.on_stack@ == s0.on_stack@.update(v, true),
        st.stack@ == s0.stack@.push(v as usize),
        st.comp@ == s0.comp@,
        st.next == s0.next + 1,
        st.ncomp == s0.ncomp,
        forall|i: int| 0 <= i < s0.stack.len() ==> reach(g, #[trigger] s0.stack@[i] as int, v),
    ensures
        inv(g, st),
        loop_inv(g, s0, st, v, s0.next as int, 0),
{
    reveal(inv_q);
    reveal(loop_inv);
    let n = g.len();
    let b = s0.stack.len() as int;
    lemma_count_set(s0.index@, n as int, v, s0.next);
    assert forall|i: int, j: int| 0 <= i < j < st.stack.len() implies
        st.index@[#[trigger] st.stack@[i] as int] < st.index@[#[trigger] st.stack@[j] as int] by {
        assert(st.stack@[i] == s0.stack@[i]);
        if j < b {
            assert(st.stack@[j] == s0.stack@[j]);
        }
    }
    assert forall|x: int| 0 <= x < n && #[trigger] st.on_stack@[x] implies st.stack@.contains(x as usize) by {
        if x == v {
            assert(st.stack@[b] == v as usize);
        } else {
            assert(s0.stack@.contains(x as usize));
            let k = choose|k: int| 0 <= k < s0.stack.len() && s0.stack@[k] == x as usize;
            assert(st.stack@[k] == x as usize);
        }
    }
    assert forall|i: int| 0 <= i < st.stack.len() implies st.on_stack@[#[trigger] st.stack@[i] as int] by {
        if i < b {
            assert(st.stack@[i] == s0.stack@[i]);
        }
    }
    assert forall|i: int| 0 <= i < st.stack.len() implies (#[trigger] st.stack@[i] as int) < g.len() by {
        if i < b {
            assert(st.stack@[i] == s0.stack@[i]);
        }
    }
    assert(frame(n as int, s0, st));
}

/// Every stack node reaches the target of edge `i` of `v`.
proof fn lemma_ctx_child(g: Seq<Vec<usize>>, s0: State, st: State, v: int, low: int, i: int)
    requires
        inv(g, st),
        loop_inv(g, s0, st, v, low, i),
        i < g[v]@.len(),
    ensures
        forall|k: int| 0 <= k < st.stack.len() ==> reach(g, #[trigger] st.stack@[k] as int, g[v]@[i] as int),
{
    reveal(loop_inv);
    let w = g[v]@[i] as int;
    let b = s0.stack.len() as int;
    lemma_edge_at(g, v, i);
    assert forall|k: int| 0 <= k < st.stack.len() implies reach(g, #[trigger] st.stack@[k] as int, w) by {
        if k < b {
            assert(st.stack@[k] == s0.stack@[k]);
            lemma_reach_trans(g, st.stack@[k] as int, v, w);
        } else if k > b {
            lemma_reach_trans(g, st.stack@[k] as int, v, w);
        }
    }
}

proof fn lemma_after_child(
    g: Seq<Vec<usize>>,
    s0: State,
    s1: State,
    st: State,
    v: int,
    low: int,
    lw: int,
    i: int,
)
    requires
        inv(g, s1),
        loop_inv(g, s0, s1, v, low, i),
        i < g[v]@.len(),
        s1.index@[g[v]@[i] as int] == NONE,
        inv(g, st),
        sc_post(g, s1, st, g[v]@[i] as int, lw),
    ensures
        loop_inv(g, s0, st, v, if lw < low { lw } else { low }, i + 1),
{
    reveal(loop_inv);
    let n = g.len() as int;
    let w = g[v]@[i] as int;
    let b = s0.stack.len() as int;
    let b1 = s1.stack.len() as int;
    let idx = s0.next as int;
    let nlow = if lw < low { lw } else { low };
    lemma_edge_at(g, v, i);
    assert(st.index@[w] == s1.next);
    assert(frame(n, s0, st)) by {
        assert forall|x: int| 0 <= x < n && s0.index@[x] != NONE implies #[trigger] st.index@[x] == s0.index@[x] by {
            assert(s1.index@[x] == s0.index@[x]);
        }
        assert forall|x: int| 0 <= x < n && s0.comp@[x] != NONE implies #[trigger] st.comp@[x] == s0.comp@[x] by {
            assert(s1.comp@[x] == s0.comp@[x]);
        }
        assert forall|x: int| 0 <= x < n && s0.on_stack@[x] implies #[trigger] st.on_stack@[x] by {
            assert(s1.on_stack@[x]);
        }
        assert forall|k: int| 0 <= k < s0.stack.len() implies #[trigger] st.stack@[k] == s0.stack@[k] by {
            assert(s1.stack@[k] == s0.stack@[k]);
        }
    }
    assert(st.stack@[b] == v) by {
        assert(st.stack@[b] == s1.stack@[b]);
    }
    assert(st.index@[v] == idx) by {
        assert(s1.index@[v] == idx);
    }
    // If the child left nodes on the stack, it reaches a node `y` below it,
    // and `y` reaches `v`.
    if lw < st.index@[w] {
        let ki = choose|ki: int| 0 <= ki < b1 && #[trigger] st.index@[s1.stack@[ki] as int] == lw
            && reach(g, w, s1.stack@[ki] as int);
        let y = s1.stack@[ki] as int;
        if ki < b {
            assert(s1.stack@[ki] == s0.stack@[ki]);
            lemma_reach_trans(g, w, y, v);
        } else if ki > b {
            lemma_reach_trans(g, w, y, v);
        }
        assert(reach(g, w, v));
    }
    assert forall|k: int| b < k < st.stack.len() implies reach(g, #[trigger] st.stack@[k] as int, v) by {
        if k < b1 {
            assert(st.stack@[k] == s1.stack@[k]);
        } else if k > b1 {
            lemma_reach_trans(g, st.stack@[k] as int, w, v);
        }
    }
    assert forall|k: int| b < k < st.stack.len() implies reach(g, v, #[trigger] st.stack@[k] as int) by {
        if k < b1 {
            assert(st.stack@[k] == s1.stack@[k]);
        } else if k > b1 {
            lemma_reach_trans(g, v, w, st.stack@[k] as int);
        }
    }
    if nlow < idx {
        if lw < low {
            let ki = choose|ki: int| 0 <= ki < b1 && #[trigger] st.index@[s1.stack@[ki] as int] == lw
                && reach(g, w, s1.stack@[ki] as int);
            reveal(inv_q);
            if ki >= b {
                assert(s1.stack@[b] == v);
                if ki > b {
                    assert(s1.index@[s1.stack@[b] as int] < s1.index@[s1.stack@[ki] as int]);
                }
                assert(st.index@[s1.stack@[ki] as int] == s1.index@[s1.stack@[ki] as int]);
            }
            assert(s1.stack@[ki] == s0.stack@[ki]);
            lemma_reach_trans(g, v, w, s0.stack@[ki] as int);
            assert(st.index@[s0.stack@[ki] as int] == nlow);
        } else {
            let k = choose|k: int| 0 <= k < b && #[trigger] s1.index@[s0.stack@[k] as int] == low
                && reach(g, v, s0.stack@[k] as int);
            assert(st.index@[s0.stack@[k] as int] == nlow);
        }
    }
    assert forall|k: int, j: int| b <= k < st.stack.len() && 0 <= j < g[st.stack@[k] as int]@.len()
        && (k > b || j < i + 1) implies out_ok(st, #[trigger] g[st.stack@[k] as int]@[j] as int, nlow) by {
        let t = g[st.stack@[k] as int]@[j] as int;
        if k < b1 {
            assert(st.stack@[k] == s1.stack@[k]);
            if k > b || j < i {
                assert(out_ok(s1, t, low));
                assert(0 <= t < n);
                if s1.comp@[t] != NONE {
                    assert(st.comp@[t] == s1.comp@[t]);
                } else {
                    reveal(inv_q);
                    assert(s1.index@[t] != NONE);
                    assert(st.index@[t] == s1.index@[t]);
                }
            } else {
                assert(t == w);
                if lw < st.index@[w] {
                    reveal(inv_q);
                    assert(st.stack@[b1] == w as usize);
                    assert(st.on_stack@[st.stack@[b1] as int]);
                }
            }
        }
    }
}

proof fn lemma_visited(g: Seq<Vec<usize>>, s0: State, st: State, v: int, low: int, i: int)
    requires
        inv(g, st),
        loop_inv(g, s0, st, v, low, i),
        i < g[v]@.len(),
        st.index@[g[v]@[i] as int] != NONE,
    ensures
        loop_inv(g, s0, st, v,
            if st.on_stack@[g[v]@[i] as int] && st.index@[g[v]@[i] as int] < low {
                st.index@[g[v]@[i] as int] as int
            } else {
                low
            }, i + 1),
{
    reveal(loop_inv);
    reveal(inv_q);
    let w = g[v]@[i] as int;
    let b = s0.stack.len() as int;
    let idx = s0.next as int;
    lemma_edge_at(g, v, i);
    let nlow = if st.on_stack@[w] && st.index@[w] < low { st.index@[w] as int } else { low };
    if st.on_stack@[w] && st.index@[w] < low {
        assert(st.stack@.contains(w as usize));
        let k = choose|k: int| 0 <= k < st.stack.len() && st.stack@[k] == w as usize;
        if k >= b {
            if k > b {
                assert(st.index@[st.stack@[b] as int] < st.index@[st.stack@[k] as int]);
            }
        }
        assert(st.stack@[k] == s0.stack@[k]);
        assert(st.index@[s0.stack@[k] as int] == nlow);
    } else if low < idx {
        let k = choose|k: int| 0 <= k < b && #[trigger] st.index@[s0.stack@[k] as int] == low
            && reach(g, v, s0.stack@[k] as int);
        assert(st.index@[s0.stack@[k] as int] == nlow);
    }
    assert forall|k: int, j: int| b <= k < st.stack.len() && 0 <= j < g[st.stack@[k] as int]@.len()
        && (k > b || j < i + 1) implies out_ok(st, #[trigger] g[st.stack@[k] as int]@[j] as int, nlow) by {
        if k > b || j < i {
        } else {
            assert(g[st.stack@[k] as int]@[j] as int == w);
        }
    }
}

proof fn lemma_no_pop(g: Seq<Vec<usize>>, s0: State, st: State, v: int, low: int)
    requires
        loop_inv(g, s0, st, v, low, g[v]@.len() as int),
        low != s0.next,
    ensures
        sc_post(g, s0, st, v, low),
{
    reveal(loop_inv);
    let b = s0.stack.len() as int;
    let k = choose|k: int| 0 <= k < b && #[trigger] st.index@[s0.stack@[k] as int] == low
        && reach(g, v, s0.stack@[k] as int);
    assert forall|i: int, j: int| b <= i < st.stack.len() && 0 <= j < g[st.stack@[i] as int]@.len() implies
        out_ok(st, #[trigger] g[st.stack@[i] as int]@[j] as int, low) by {
        if i == b {
            assert(st.stack@[i] == v);
        }
    }
}

proof fn lemma_pop_step(g: Seq<Vec<usize>>, sb: State, s1: State, st: State, c: usize, x: usize)
    requires
        inv(g, sb),
        pop_inv(g, sb, s1, c),
        s1.stack.len() > 0,
        x == s1.stack@.last(),
        st.stack@ == s1.stack@.drop_last(),
        st.on_stack@ == s1.on_stack@.update(x as int, false),
        st.comp@ == s1.comp@.update(x as int, c),
        st.index@ == s1.index@,
        st.next == s1.next,
    ensures
        pop_inv(g, sb, st, c),
{
    reveal(inv_q);
    let n = g.len() as int;
    let top = s1.stack.len() - 1;
    assert(x == sb.stack@[top]);
    assert forall|k: int| 0 <= k < top implies #[trigger] sb.stack@[k] != x by {
        assert(sb.index@[sb.stack@[k] as int] < sb.index@[sb.stack@[top] as int]);
    }
    assert(sb.on_stack@[sb.stack@[top] as int]);
    assert(st.stack@ == sb.stack@.subrange(0, st.stack.len() as int));
}

proof fn lemma_pop_init(g: Seq<Vec<usize>>, sb: State, c: usize)
    requires
        inv(g, sb),
    ensures
        pop_inv(g, sb, sb, c),
{
    reveal(inv_q);
    assert(sb.stack@ =~= sb.stack@.subrange(0, sb.stack.len() as int));
}

/// A node popped by the frame of `v` is `v` or on a cycle with `v`, and
/// its edges go to assigned components or to popped nodes.
proof fn lemma_popped_node(g: Seq<Vec<usize>>, s0: State, sb: State, v: int, x: int)
    requires
        inv(g, sb),
        loop_inv(g, s0, sb, v, s0.next as int, g[v]@.len() as int),
        0 <= x < g.len(),
        sb.on_stack@[x],
        sb.index@[x] >= s0.next,
    ensures
        x == v || (reach(g, x, v) && reach(g, v, x)),
        forall|j: int| 0 <= j < g[x]@.len() ==> out_ok(sb, #[trigger] g[x]@[j] as int, s0.next as int),
{
    reveal(inv_q);
    reveal(loop_inv);
    let base = s0.stack.len() as int;
    assert(sb.stack@.contains(x as usize));
    let k = choose|k: int| 0 <= k < sb.stack.len() && sb.stack@[k] == x as usize;
    if k < base {
        assert(sb.index@[sb.stack@[k] as int] < sb.index@[sb.stack@[base] as int]);
    }
    assert forall|j: int| 0 <= j < g[x]@.len() implies out_ok(sb, #[trigger] g[x]@[j] as int, s0.next as int) by {
        assert(out_ok(sb, g[sb.stack@[k] as int]@[j] as int, s0.next as int));
    }
}

/// Which nodes the popping loop changed: exactly the stack nodes with an
/// index at least `s0.next`.
proof fn lemma_pop_class(g: Seq<Vec<usize>>, s0: State, sb: State, st: State, v: int)
    requires
        inv(g, sb),
        loop_inv(g, s0, sb, v, s0.next as int, g[v]@.len() as int),
        pop_inv(g, sb, st, sb.ncomp),
        st.stack.len() == s0.stack.len(),
    ensures
        forall|x: int| 0 <= x < g.len() ==>
            (#[trigger] st.comp@[x] == sb.ncomp ==> sb.on_stack@[x])
            && (sb.on_stack@[x] ==> (st.comp@[x] == sb.ncomp <==> sb.index@[x] >= s0.next))
            && (sb.on_stack@[x] && sb.index@[x] < s0.next ==> st.on_stack@[x] && st.comp@[x] == NONE
                && st.stack@.contains(x as usize))
            && (sb.on_stack@[x] && sb.index@[x] >= s0.next ==> !st.on_stack@[x])
            && (!sb.on_stack@[x] ==> st.comp@[x] == sb.comp@[x] && !st.on_stack@[x]),
{
    reveal(inv_q);
    reveal(loop_inv);
    let n = g.len() as int;
    let base = s0.stack.len() as int;
    let m = sb.stack.len() as int;
    let c = sb.ncomp;
    assert forall|x: int| 0 <= x < n implies
        (#[trigger] st.comp@[x] == c ==> sb.on_stack@[x])
        && (sb.on_stack@[x] ==> (st.comp@[x] == c <==> sb.index@[x] >= s0.next))
        && (sb.on_stack@[x] && sb.index@[x] < s0.next ==> st.on_stack@[x] && st.comp@[x] == NONE
            && st.stack@.contains(x as usize))
        && (sb.on_stack@[x] && sb.index@[x] >= s0.next ==> !st.on_stack@[x])
        && (!sb.on_stack@[x] ==> st.comp@[x] == sb.comp@[x] && !st.on_stack@[x])
    by {
        assert(c < n);
        if sb.on_stack@[x] {
            assert(sb.stack@.contains(x as usize));
            let k = choose|k: int| 0 <= k < m && sb.stack@[k] == x as usize;
            if k < base {
                assert(sb.index@[sb.stack@[k] as int] < sb.index@[sb.stack@[base] as int]);
                assert(st.stack@[k] == sb.stack@[k]);
                assert(st.stack@[k] == x as usize);
                assert(st.on_stack@[x] && st.comp@[x] == NONE);
                assert(st.stack@.contains(x as usize));
            } else {
                if k > base {
                    assert(sb.index@[sb.stack@[base] as int] < sb.index@[sb.stack@[k] as int]);
                }
                assert(st.comp@[x] == c);
                assert(!st.on_stack@[x]);
                assert(sb.index@[x] >= s0.next);
            }
        } else {
            if sb.comp@[x] != NONE {
                assert(sb.comp@[x] < sb.ncomp);
            }
            assert(st.comp@[x] == sb.comp@[x]);
        }
    }
}

proof fn lemma_pop_done(g: Seq<Vec<usize>>, s0: State, sb: State, st: State, v: int)
    requires
        inv(g, s0),
        inv(g, sb),
        loop_inv(g, s0, sb, v, s0.next as int, g[v]@.len() as int),
        pop_inv(g, sb, st, sb.ncomp),
        st.stack.len() == s0.stack.len(),
        st.ncomp == sb.ncomp + 1,
    ensures
        inv(g, st),
        sc_post(g, s0, st, v, s0.next as int),
{
    let n = g.len() as int;
    let base = s0.stack.len() as int;
    let c = sb.ncomp;
    let idx = s0.next as int;
    lemma_pop_class(g, s0, sb, st, v);
    assert(0 <= v < n && sb.index@[v] == idx && sb.stack@[base] == v as usize && sb.next > idx
        && sb.stack.len() > base) by {
        reveal(loop_inv);
    }
    assert(sb.on_stack@[v]) by {
        reveal(inv_q);
    }
    assert forall|x: int, j: int| 0 <= x < n && 0 <= j < g[x]@.len() && st.comp@[x] != NONE implies
        st.comp@[#[trigger] g[x]@[j] as int] != NONE && st.comp@[g[x]@[j] as int] <= st.comp@[x] by {
        let t = g[x]@[j] as int;
        assert(0 <= t < n);
        reveal(inv_q);
        if st.comp@[x] == c {
            lemma_popped_node(g, s0, sb, v, x);
            assert(out_ok(sb, t, idx));
        }
        if sb.comp@[t] != NONE {
            assert(sb.comp@[t] < c);
        }
    }
    assert forall|x: int, y: int| 0 <= x < n && 0 <= y < n && st.comp@[x] != NONE
        && #[trigger] st.comp@[x] == #[trigger] st.comp@[y] && x != y implies reach(g, x, y) by {
        reveal(inv_q);
        if st.comp@[x] == c {
            lemma_popped_node(g, s0, sb, v, x);
            lemma_popped_node(g, s0, sb, v, y);
            if x != v && y != v {
                lemma_reach_trans(g, x, v, y);
            }
        } else {
            assert(sb.comp@[x] == st.comp@[x]);
            assert(sb.comp@[y] == st.comp@[y]);
        }
    }
    assert(frame(n, s0, st)) by {
        reveal(inv_q);
        reveal(loop_inv);
        assert forall|x: int| 0 <= x < n && s0.on_stack@[x] implies #[trigger] st.on_stack@[x] by {
            assert(sb.on_stack@[x]);
            assert(s0.stack@.contains(x as usize));
            let k = choose|k: int| 0 <= k < s0.stack.len() && s0.stack@[k] == x as usize;
            assert(sb.stack@[k] == x as usize);
            assert(sb.index@[sb.stack@[k] as int] < sb.index@[sb.stack@[base] as int]);
        }
        assert forall|x: int| 0 <= x < n && s0.comp@[x] != NONE implies #[trigger] st.comp@[x] == s0.comp@[x] by {
            assert(sb.comp@[x] == s0.comp@[x]);
        }
        assert forall|x: int| 0 <= x < n && s0.index@[x] != NONE implies #[trigger] st.index@[x] == s0.index@[x] by {
            assert(sb.index@[x] == s0.index@[x]);
        }
        assert forall|i: int| 0 <= i < base implies #[trigger] st.stack@[i] == s0.stack@[i] by {
            assert(sb.stack@[i] == s0.stack@[i]);
        }
    }
    lemma_pop_inv_rest(g, s0, sb, st, v);
}

/// The parts of `inv` after popping that do not involve edges.
proof fn lemma_pop_inv_rest(g: Seq<Vec<usize>>, s0: State, sb: State, st: State, v: int)
    requires
        inv(g, sb),
        loop_inv(g, s0, sb, v, s0.next as int, g[v]@.len() as int),
        pop_inv(g, sb, st, sb.ncomp),
        st.stack.len() == s0.stack.len(),
        st.ncomp == sb.ncomp + 1,
        forall|x: int, j: int| 0 <= x < g.len() && 0 <= j < g[x]@.len() && st.comp@[x] != NONE ==>
            st.comp@[#[trigger] g[x]@[j] as int] != NONE && st.comp@[g[x]@[j] as int] <= st.comp@[x],
        forall|x: int, y: int| 0 <= x < g.len() && 0 <= y < g.len() && st.comp@[x] != NONE
            && #[trigger] st.comp@[x] == #[trigger] st.comp@[y] && x != y ==> reach(g, x, y),
    ensures
        inv(g, st),
{
    lemma_pop_class(g, s0, sb, st, v);
    assert(st.stack.len() < sb.stack.len()) by {
        reveal(loop_inv);
    }
    reveal(inv_q);
    let n = g.len() as int;
    assert forall|i: int| 0 <= i < st.stack.len() implies st.on_stack@[#[trigger] st.stack@[i] as int] by {
        assert(st.stack@[i] == sb.stack@[i]);
    }
    assert forall|i: int| 0 <= i < st.stack.len() implies (#[trigger] st.stack@[i] as int) < n by {
        assert(st.stack@[i] == sb.stack@[i]);
    }
    assert forall|i: int, j: int| 0 <= i < j < st.stack.len() implies
        st.index@[#[trigger] st.stack@[i] as int] < st.index@[#[trigger] st.stack@[j] as int] by {
        assert(st.stack@[i] == sb.stack@[i] && st.stack@[j] == sb.stack@[j]);
    }
    assert(sb.ncomp < n);
    assert forall|x: int| 0 <= x < n implies
        (#[trigger] st.on_stack@[x] <==> (st.index@[x] != NONE && st.comp@[x] == NONE)) by {
        assert(st.index@[x] == sb.index@[x]);
        if sb.on_stack@[x] {
            assert(sb.index@[x] != NONE);
            if sb.index@[x] >= s0.next {
                assert(st.comp@[x] == sb.ncomp);
            }
        } else {
            assert(st.comp@[x] == sb.comp@[x]);
            assert(!(sb.index@[x] != NONE && sb.comp@[x] == NONE));
        }
    }
    assert forall|x: int| 0 <= x < n && #[trigger] st.on_stack@[x] implies st.stack@.contains(x as usize) by {}
    assert forall|x: int| 0 <= x < n && #[trigger] st.comp@[x] != NONE implies st.comp@[x] < st.ncomp by {
        if sb.comp@[x] != NONE {
            assert(sb.comp@[x] < sb.ncomp);
        }
    }
    assert forall|x: int| 0 <= x < n && st.index@[x] == NONE implies #[trigger] st.comp@[x] == NONE by {}
}

proof fn lemma_init(g: Seq<Vec<usize>>, st: State)
    requires
        wf(g),
        g.len() <= usize::MAX,
        st.index.len() == g.len(),
        st.on_stack.len() == g.len(),
        st.comp.len() == g.len(),
        forall|i: int| 0 <= i < g.len() ==> st.index@[i] == NONE,
        forall|i: int| 0 <= i < g.len() ==> st.comp@[i] == NONE,
        forall|i: int| 0 <= i < g.len() ==> !st.on_stack@[i],
        st.stack.len() == 0,
        st.next == 0,
        st.ncomp == 0,
    ensures
        inv(g, st),
{
    reveal(inv_q);
    lemma_count_zero(st.index@, g.len() as int);
}

/// After all nodes are visited and the stack is empty, every node has a
/// component, and P1 and P2 hold.
proof fn lemma_done(g: Seq<Vec<usize>>, st: State)
    requires
        inv(g, st),
        st.stack.len() == 0,
        forall|x: int| 0 <= x < g.len() ==> #[trigger] st.index@[x] != NONE,
    ensures
        forall|x: int| 0 <= x < g.len() ==> #[trigger] st.comp@[x] != NONE && st.comp@[x] < st.ncomp,
        forall|x: int, j: int| 0 <= x < g.len() && 0 <= j < g[x]@.len() ==>
            st.comp@[#[trigger] g[x]@[j] as int] <= st.comp@[x],
        forall|x: int, y: int| 0 <= x < g.len() && 0 <= y < g.len() && #[trigger] st.comp@[x] == #[trigger] st.comp@[y] && x != y ==>
            reach(g, x, y),
{
    reveal(inv_q);
    assert forall|x: int| 0 <= x < g.len() implies #[trigger] st.comp@[x] != NONE && st.comp@[x] < st.ncomp by {
        assert(st.index@[x] != NONE);
        if st.on_stack@[x] {
            assert(st.stack@.contains(x as usize));
        }
    }
    assert forall|x: int, j: int| 0 <= x < g.len() && 0 <= j < g[x]@.len() implies
        st.comp@[#[trigger] g[x]@[j] as int] <= st.comp@[x] by {
        assert(st.comp@[x] != NONE);
    }
    assert forall|x: int, y: int| 0 <= x < g.len() && 0 <= y < g.len() && #[trigger] st.comp@[x] == #[trigger] st.comp@[y] && x != y implies
        reach(g, x, y) by {
        assert(st.comp@[x] != NONE);
    }
}

/// Frame `k` is suspended at its edge `fi[k]`, whose target is the node of
/// frame `k + 1`, entered from `fs[k + 1]`.
spec fn frozen(g: Seq<Vec<usize>>, fs: Seq<State>, fv: Seq<usize>, fi: Seq<usize>, fl: Seq<usize>, k: int) -> bool {
    let v = fv[k] as int;
    let i = fi[k] as int;
    &&& loop_inv(g, fs[k], fs[k + 1], v, fl[k] as int, i)
    &&& i < g[v]@.len()
    &&& g[v]@[i] == fv[k + 1]
    &&& fs[k + 1].index@[fv[k + 1] as int] == NONE
}

/// The number of edges left in the top frame.
spec fn sc_rem(g: Seq<Vec<usize>>, fv: Seq<usize>, fi: Seq<usize>) -> int {
    if fv.len() > 0 {
        g[fv[fv.len() - 1] as int]@.len() - fi[fv.len() - 1]
    } else {
        0
    }
}

/// Frozen facts of frames below `m` depend only on entries `<= m` of `fs`
/// and `fv` and entries `< m` of `fi` and `fl`.
proof fn lemma_frozen_keep(
    g: Seq<Vec<usize>>,
    fs1: Seq<State>,
    fv1: Seq<usize>,
    fi1: Seq<usize>,
    fl1: Seq<usize>,
    fs2: Seq<State>,
    fv2: Seq<usize>,
    fi2: Seq<usize>,
    fl2: Seq<usize>,
    m: int,
)
    requires
        forall|k: int| 0 <= k < m ==> #[trigger] frozen(g, fs1, fv1, fi1, fl1, k),
        forall|k: int| 0 <= k <= m ==> fs2[k] == fs1[k] && fv2[k] == fv1[k],
        forall|k: int| 0 <= k < m ==> fi2[k] == fi1[k] && fl2[k] == fl1[k],
    ensures
        forall|k: int| 0 <= k < m ==> #[trigger] frozen(g, fs2, fv2, fi2, fl2, k),
{
    assert forall|k: int| 0 <= k < m implies #[trigger] frozen(g, fs2, fv2, fi2, fl2, k) by {
        assert(frozen(g, fs1, fv1, fi1, fl1, k));
        assert(fs2[k] == fs1[k] && fs2[k + 1] == fs1[k + 1] && fv2[k] == fv1[k] && fv2[k + 1] == fv1[k + 1]);
    }
}

} // verus!

/// `n` copies of `x`.
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r.len() == n,
        forall|i: int| 0 <= i < n ==> r@[i] == x,
))]
pub(crate) fn filled(n: usize, x: usize) -> Vec<usize> {
    let mut r: Vec<usize> = Vec::with_capacity(n);
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            r.len() <= n,
            forall|i: int| 0 <= i < r.len() ==> r@[i] == x,
        decreases n - r.len()
    ))]
    while r.len() < n {
        r.push(x);
    }
    r
}

/// `n` copies of `false`.
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r.len() == n,
        forall|i: int| 0 <= i < n ==> !r@[i],
))]
pub(crate) fn filled_false(n: usize) -> Vec<bool> {
    let mut r: Vec<bool> = Vec::with_capacity(n);
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            r.len() <= n,
            forall|i: int| 0 <= i < r.len() ==> !r@[i],
        decreases n - r.len()
    ))]
    while r.len() < n {
        r.push(false);
    }
    r
}

/// Visits `v`: gives it the index `next`, pushes it on the stack, and
/// returns the index.
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    with Ghost(g): Ghost<Seq<Vec<usize>>>
    requires
        inv(g, *old(st)),
        (v as int) < g.len(),
        old(st).index@[v as int] == NONE,
        forall|i: int| 0 <= i < old(st).stack.len() ==> reach(g, #[trigger] old(st).stack@[i] as int, v as int),
    ensures
        inv(g, *final(st)),
        loop_inv(g, *old(st), *final(st), v as int, r as int, 0),
        r == old(st).next,
        final(st).next == old(st).next + 1,
))]
fn enter_node(st: &mut State, v: usize) -> usize {
    proof_decl! {
        let ghost s0 = *st;
    }
    proof! {
        lemma_next_lt(g, s0, v as int);
    }
    let idx = st.next;
    st.index[v] = idx;
    st.next = idx + 1;
    st.stack.push(v);
    st.on_stack[v] = true;
    proof! {
        lemma_push(g, s0, *st, v as int);
    }
    idx
}

/// Finishes the frame of `v`, entered from `s0` with stack length `base`:
/// pops its component if `v` is a root.
#[cfg_attr(verus_keep_ghost, verus_spec(
    with Ghost(g): Ghost<Seq<Vec<usize>>>, Ghost(s0): Ghost<State>
    requires
        inv(g, s0),
        inv(g, *old(st)),
        (v as int) < g.len(),
        base == s0.stack.len(),
        loop_inv(g, s0, *old(st), v as int, low as int, g[v as int]@.len() as int),
    ensures
        inv(g, *final(st)),
        sc_post(g, s0, *final(st), v as int, low as int),
        final(st).next == old(st).next,
))]
fn leave_node(st: &mut State, v: usize, low: usize, base: usize) {
    proof! {
        assert(st.index@[v as int] == s0.next) by {
            reveal(loop_inv);
        }
    }
    if low == st.index[v] {
        let c = st.ncomp;
        proof_decl! {
            let ghost sb = *st;
        }
        proof! {
            assert(st.stack.len() > base) by {
                reveal(loop_inv);
            }
            lemma_pop_init(g, sb, c);
        }
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                inv(g, sb),
                pop_inv(g, sb, *st, c),
                base == s0.stack.len(),
                base <= st.stack.len(),
                st.ncomp == c,
                c == sb.ncomp,
            decreases st.stack.len()
        ))]
        while st.stack.len() > base {
            let top = st.stack.len() - 1;
            let x = st.stack[top];
            proof_decl! {
                let ghost s1 = *st;
            }
            st.stack.pop();
            st.on_stack[x] = false;
            st.comp[x] = c;
            proof! {
                lemma_pop_step(g, sb, s1, *st, c, x);
            }
        }
        proof! {
            assert(pop_inv(g, sb, *st, c));
        }
        st.ncomp = c + 1;
        proof! {
            assert(pop_inv(g, sb, *st, c));
            lemma_pop_done(g, s0, sb, *st, v as int);
        }
    } else {
        proof! {
            lemma_no_pop(g, s0, *st, v as int, low as int);
        }
    }
}

/// Tarjan's search from `v`, with an explicit stack of frames: frame `k`
/// has node `fv[k]`, next edge `fi[k]`, low-link `fl[k]` and entry stack
/// length `fb[k]`; the ghost `fs[k]` is the state at its entry. Returns the
/// low-link of `v`.
#[cfg_attr(verus_keep_ghost, verus_spec(ret =>
    requires
        inv(g@, *old(st)),
        (v as int) < g.len(),
        old(st).index@[v as int] == NONE,
        forall|i: int| 0 <= i < old(st).stack.len() ==> reach(g@, #[trigger] old(st).stack@[i] as int, v as int),
    ensures
        inv(g@, *final(st)),
        sc_post(g@, *old(st), *final(st), v as int, ret as int),
))]
fn strongconnect(g: &Vec<Vec<usize>>, st: &mut State, v: usize) -> usize {
    proof_decl! {
        let ghost s0 = *st;
    }
    let mut fv: Vec<usize> = Vec::new();
    let mut fi: Vec<usize> = Vec::new();
    let mut fl: Vec<usize> = Vec::new();
    let mut fb: Vec<usize> = Vec::new();
    let b0 = st.stack.len();
    proof_with!(Ghost(g@));
    let idx = enter_node(st, v);
    fv.push(v);
    fi.push(0);
    fl.push(idx);
    fb.push(b0);
    proof_decl! {
        let ghost mut fs: Seq<State> = seq![s0];
    }
    let mut ret: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            s0 == *old(st),
            (v as int) < g.len(),
            inv(g@, *st),
            fi.len() == fv.len(),
            fl.len() == fv.len(),
            fb.len() == fv.len(),
            fs.len() == fv.len(),
            fv.len() > 0 ==> fs[0] == s0 && fv@[0] == v,
            forall|k: int| 0 <= k < fv.len() ==> inv(g@, #[trigger] fs[k]),
            forall|k: int| 0 <= k < fv.len() ==> (#[trigger] fv@[k] as int) < g.len()
                && fi@[k] <= g@[fv@[k] as int]@.len() && fb@[k] == fs[k].stack.len(),
            fv.len() > 0 ==> loop_inv(g@, fs[fv.len() - 1], *st, fv@[fv.len() - 1] as int,
                fl@[fv.len() - 1] as int, fi@[fv.len() - 1] as int),
            forall|k: int| 0 <= k < fv.len() - 1 ==> #[trigger] frozen(g@, fs, fv@, fi@, fl@, k),
            fv.len() == 0 ==> sc_post(g@, s0, *st, v as int, ret as int),
        decreases g.len() - st.next, fv.len(), sc_rem(g@, fv@, fi@)
    ))]
    while fv.len() > 0 {
        proof_decl! {
            let ghost fs1 = fs;
            let ghost fv1 = fv@;
            let ghost fi1 = fi@;
            let ghost fl1 = fl@;
        }
        let t = fv.len() - 1;
        let u = fv[t];
        let i = fi[t];
        let low = fl[t];
        if i < g[u].len() {
            let w = g[u][i];
            proof! {
                lemma_edge_at(g@, u as int, i as int);
            }
            if st.index[w] == NONE {
                proof_decl! {
                    let ghost s1 = *st;
                }
                proof! {
                    lemma_ctx_child(g@, fs[t as int], s1, u as int, low as int, i as int);
                }
                let b = st.stack.len();
                proof_with!(Ghost(g@));
                let iw = enter_node(st, w);
                fv.push(w);
                fi.push(0);
                fl.push(iw);
                fb.push(b);
                proof! {
                    fs = fs.push(s1);
                    lemma_frozen_keep(g@, fs1, fv1, fi1, fl1, fs, fv@, fi@, fl@, t as int);
                    assert(frozen(g@, fs, fv@, fi@, fl@, t as int));
                }
            } else {
                proof! {
                    lemma_visited(g@, fs[t as int], *st, u as int, low as int, i as int);
                }
                let mut nl = low;
                if st.on_stack[w] {
                    let iw = st.index[w];
                    if iw < low {
                        nl = iw;
                    }
                }
                fi[t] = i + 1;
                fl[t] = nl;
                proof! {
                    lemma_frozen_keep(g@, fs1, fv1, fi1, fl1, fs, fv@, fi@, fl@, t as int);
                }
            }
        } else {
            let b = fb[t];
            proof_with!(Ghost(g@), Ghost(fs[t as int]));
            leave_node(st, u, low, b);
            fv.pop();
            fi.pop();
            fl.pop();
            fb.pop();
            proof! {
                fs = fs.drop_last();
            }
            if t > 0 {
                let p = t - 1;
                let ip = fi[p];
                let lp = fl[p];
                proof! {
                    assert(frozen(g@, fs1, fv1, fi1, fl1, p as int));
                    assert(ip == fi1[p as int]);
                    assert(ip < g@[fv1[p as int] as int]@.len() && g@[fv1[p as int] as int]@.len() == g@[fv1[p as int] as int].len());
                    lemma_after_child(g@, fs[p as int], fs1[t as int], *st, fv1[p as int] as int, lp as int, low as int, ip as int);
                }
                fi[p] = ip + 1;
                if low < lp {
                    fl[p] = low;
                }
                proof! {
                    lemma_frozen_keep(g@, fs1, fv1, fi1, fl1, fs, fv@, fi@, fl@, p as int);
                }
            } else {
                ret = low;
            }
        }
    }
    ret
}

/// The components of `g`, with P1-P3.
#[cfg_attr(verus_keep_ghost, verus_spec(s =>
    requires
        wf(g@),
    ensures
        sccs_ok(g@, s),
))]
pub(crate) fn sccs(g: &Vec<Vec<usize>>) -> Sccs {
    let n = g.len();
    let mut st = State {
        index: filled(n, NONE),
        on_stack: filled_false(n),
        stack: Vec::new(),
        comp: filled(n, NONE),
        next: 0,
        ncomp: 0,
    };
    proof! {
        lemma_init(g@, st);
    }
    let mut v: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            n == g.len(),
            v <= n,
            inv(g@, st),
            st.stack.len() == 0,
            forall|x: int| 0 <= x < v ==> #[trigger] st.index@[x] != NONE,
        decreases n - v
    ))]
    while v < n {
        if st.index[v] == NONE {
            proof_decl! {
                let ghost s0 = st;
            }
            let _low = strongconnect(g, &mut st, v);
            proof! {
                assert forall|x: int| 0 <= x < v implies #[trigger] st.index@[x] != NONE by {
                    assert(s0.index@[x] != NONE);
                }
            }
        }
        v += 1;
    }
    let ncomp = st.ncomp;
    proof! {
        lemma_done(g@, st);
    }
    let mut members: Vec<Vec<usize>> = Vec::with_capacity(ncomp);
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            members.len() <= ncomp,
            forall|c: int| 0 <= c < members.len() ==> #[trigger] members@[c]@.len() == 0,
        decreases ncomp - members.len()
    ))]
    while members.len() < ncomp {
        members.push(Vec::new());
    }
    let mut u: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            n == g.len(),
            u <= n,
            st.comp.len() == n,
            ncomp == st.ncomp,
            members.len() == ncomp,
            forall|x: int| 0 <= x < n ==> #[trigger] st.comp@[x] != NONE && st.comp@[x] < st.ncomp,
            forall|x: int, j: int| 0 <= x < g.len() && 0 <= j < g[x]@.len() ==>
                st.comp@[#[trigger] g[x]@[j] as int] <= st.comp@[x],
            forall|x: int, y: int| 0 <= x < g.len() && 0 <= y < g.len() && #[trigger] st.comp@[x] == #[trigger] st.comp@[y] && x != y ==>
                reach(g@, x, y),
            forall|c: int, k: int| 0 <= c < members.len() && 0 <= k < members@[c]@.len() ==>
                (#[trigger] members@[c]@[k] as int) < u && st.comp@[members@[c]@[k] as int] == c,
            forall|x: int| 0 <= x < u ==> #[trigger] members@[st.comp@[x] as int]@.contains(x as usize),
        decreases n - u
    ))]
    while u < n {
        let c = st.comp[u];
        proof_decl! {
            let ghost m0 = members@;
        }
        let mut row: Vec<usize> = Vec::new();
        std::mem::swap(&mut row, &mut members[c]);
        row.push(u);
        members[c] = row;
        proof! {
            assert(members@[c as int]@ == m0[c as int]@.push(u));
            assert forall|x: int| 0 <= x < u + 1 implies #[trigger] members@[st.comp@[x] as int]@.contains(x as usize) by {
                if x == u {
                    assert(members@[c as int]@[m0[c as int]@.len() as int] == u);
                } else {
                    let cx = st.comp@[x] as int;
                    assert(m0[cx]@.contains(x as usize));
                    let k = choose|k: int| 0 <= k < m0[cx]@.len() && m0[cx]@[k] == x as usize;
                    assert(members@[cx]@[k] == x as usize);
                }
            }
            assert forall|cc: int, k: int| 0 <= cc < members.len() && 0 <= k < members@[cc]@.len() implies
                (#[trigger] members@[cc]@[k] as int) < u + 1 && st.comp@[members@[cc]@[k] as int] == cc by {
                if cc == c as int && k == m0[cc]@.len() {
                } else {
                    assert(members@[cc]@[k] == m0[cc]@[k]);
                }
            }
        }
        u += 1;
    }
    Sccs {
        comp: st.comp,
        members,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same(s: &Sccs, a: usize, b: usize) -> bool {
        s.comp[a] == s.comp[b]
    }

    #[test]
    fn chain() {
        let g = vec![vec![1], vec![2], vec![]];
        let s = sccs(&g);
        assert_eq!(s.members.len(), 3);
        assert!(s.comp[2] < s.comp[1] && s.comp[1] < s.comp[0]);
    }

    #[test]
    fn three_cycle() {
        let g = vec![vec![1], vec![2], vec![0]];
        let s = sccs(&g);
        assert_eq!(s.members.len(), 1);
        assert_eq!(s.members[0].len(), 3);
    }

    #[test]
    fn two_sccs() {
        // {0, 1} -> {2, 3}
        let g = vec![vec![1], vec![0, 2], vec![3], vec![2]];
        let s = sccs(&g);
        assert_eq!(s.members.len(), 2);
        assert!(same(&s, 0, 1) && same(&s, 2, 3) && !same(&s, 0, 2));
        assert!(s.comp[2] < s.comp[0]);
    }

    #[test]
    fn dangling() {
        // Node 1 has an empty row.
        let g = vec![vec![1], vec![]];
        let s = sccs(&g);
        assert_eq!(s.members.len(), 2);
        assert!(s.comp[1] < s.comp[0]);
    }

    #[test]
    fn deep_chain_small_stack() {
        let n = 100_000;
        let h = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || {
                let mut g: Vec<Vec<usize>> = (1..n).map(|i| vec![i]).collect();
                g.push(vec![]);
                let s = sccs(&g);
                assert_eq!(s.members.len(), n);
                assert!(s.comp[n - 1] < s.comp[0]);
            })
            .unwrap();
        h.join().unwrap();
    }
}
