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

//! The transitive closure and its repair.
//!
//! [`transitive_closure`] computes the SCCs ([`crate::scc`]), then the
//! successor components of each component, in increasing id order: by P1 an
//! edge leaves component `c` only to a component `t < c`, whose successors
//! are already known (`succ_ok`). Row `u` of the result lists the members of
//! the successor components of `u`'s component that are not targets of
//! `g[u]` (`row_minus`).
//!
//! [`repair_closure`] is a port of `compute_tc_internal` and `add_ancestors`
//! in `cedar-policy-core`, with cycle detection on. `add_ancestors` is a
//! post-order DFS over an explicit stack of frames: a frame closes its row
//! (`close_row`) after all its targets are closed, and its parent then
//! appends that row to `buf` (`lemma_anc_after_child`, `lemma_anc_append`).
//! The top frame satisfies `anc_loop`, each suspended frame `anc_frozen`, and
//! a finished search `anc_post`. The ghost `dag` holds when the input has no
//! cycle and its rows outside `fix` are closed; under `dag`, `pending` and
//! `kept` give that every seen row that is not yet closed is the current
//! node's row or the row of a node that reaches it, which gives R4. The loop
//! terminates by the lexicographic decreases
//! `(n - count_seen(seen), fx.len(), anc_rem)`.
//!
//! `restricts` and `lemma_repair_restrict` relate a repair of a restricted
//! graph to a repair of the whole graph.

#[cfg(verus_keep_ghost)]
use crate::graph::*;
#[cfg(verus_keep_ghost)]
use crate::scc::sccs_ok;
use crate::scc::{filled, filled_false, sccs, Sccs, NONE};
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
verus! {

/// Some node of component `a` reaches some node of component `b`.
spec fn creach(g: Seq<Vec<usize>>, comp: Seq<usize>, a: int, b: int) -> bool {
    exists|x: int, y: int| 0 <= x < g.len() && 0 <= y < g.len() && comp[x] == a && comp[y] == b
        && #[trigger] reach(g, x, y)
}

/// `succ[c2]`, for `c2 < c`, is the set of components that `c2` reaches.
spec fn succ_ok(g: Seq<Vec<usize>>, s: Sccs, succ: Seq<Vec<usize>>, c: int) -> bool {
    &&& c <= succ.len()
    &&& forall|c2: int, k: int| 0 <= c2 < c && 0 <= k < succ[c2]@.len() ==>
        (#[trigger] succ[c2]@[k] as int) < s.members.len()
    &&& forall|c2: int, t: usize| 0 <= c2 < c && (t as int) < s.members.len() ==>
        (#[trigger] succ[c2]@.contains(t) <==> creach(g, s.comp@, c2, t as int))
}

/// `mark[t] == c` iff `t` is in `cur`.
spec fn sync(mark: Seq<usize>, cur: Seq<usize>, c: usize, ncomp: int) -> bool {
    &&& mark.len() == ncomp
    &&& ncomp <= usize::MAX
    &&& forall|k: int| 0 <= k < cur.len() ==> (#[trigger] cur[k] as int) < ncomp
    &&& forall|t: int| 0 <= t < ncomp ==> (#[trigger] mark[t] == c <==> cur.contains(t as usize))
}

/// Edge `j` of `x` has been processed for component `c`: its target
/// component, and that component's successors when it is not `c`, are
/// marked.
spec fn edge_done(g: Seq<Vec<usize>>, s: Sccs, succ: Seq<Vec<usize>>, mark: Seq<usize>, c: usize, x: int, j: int) -> bool {
    let t = s.comp@[g[x]@[j] as int] as int;
    &&& mark[t] == c
    &&& t != c ==> forall|k: int| 0 <= k < succ[t]@.len() ==> mark[#[trigger] succ[t]@[k] as int] == c
}

/// `mark` only gained marks `c` from `m0`.
spec fn grows(m0: Seq<usize>, mark: Seq<usize>, c: usize) -> bool {
    &&& mark.len() == m0.len()
    &&& forall|t: int| 0 <= t < m0.len() ==> #[trigger] mark[t] == m0[t] || mark[t] == c
}

proof fn lemma_push_contains(s: Seq<usize>, x: usize, v: usize)
    ensures
        s.push(x).contains(v) <==> (s.contains(v) || v == x),
{
    if s.contains(v) {
        let k = choose|k: int| 0 <= k < s.len() && s[k] == v;
        assert(s.push(x)[k] == v);
    }
    if v == x {
        assert(s.push(x)[s.len() as int] == v);
    }
    if s.push(x).contains(v) {
        let k = choose|k: int| 0 <= k < s.push(x).len() && s.push(x)[k] == v;
        if k < s.len() {
            assert(s[k] == v);
        }
    }
}

proof fn lemma_sync_push(mark: Seq<usize>, cur: Seq<usize>, c: usize, ncomp: int, t: usize)
    requires
        sync(mark, cur, c, ncomp),
        (t as int) < ncomp,
        mark[t as int] != c,
    ensures
        sync(mark.update(t as int, c), cur.push(t), c, ncomp),
{
    assert forall|t2: int| 0 <= t2 < ncomp implies
        (#[trigger] mark.update(t as int, c)[t2] == c <==> cur.push(t).contains(t2 as usize)) by {
        lemma_push_contains(cur, t, t2 as usize);
    }
}

/// Marks only grow, so processed edges stay processed.
proof fn lemma_done_mono(g: Seq<Vec<usize>>, s: Sccs, succ: Seq<Vec<usize>>, m1: Seq<usize>, m2: Seq<usize>, c: usize, x: int, j: int)
    requires
        edge_done(g, s, succ, m1, c, x, j),
        m2.len() == m1.len(),
        0 <= s.comp@[g[x]@[j] as int] < m1.len(),
        forall|t: int| 0 <= t < m1.len() && m1[t] == c ==> #[trigger] m2[t] == c,
        s.comp@[g[x]@[j] as int] != c ==> forall|k: int| 0 <= k < succ[s.comp@[g[x]@[j] as int] as int]@.len() ==>
            (#[trigger] succ[s.comp@[g[x]@[j] as int] as int]@[k] as int) < m1.len(),
    ensures
        edge_done(g, s, succ, m2, c, x, j),
{
    let t = s.comp@[g[x]@[j] as int] as int;
    if t != c {
        assert forall|k: int| 0 <= k < succ[t]@.len() implies m2[#[trigger] succ[t]@[k] as int] == c by {
            assert(m1[succ[t]@[k] as int] == c);
        }
    }
}

/// An edge `u -> v` extends the components reached from `v`'s component to
/// `u`'s component.
proof fn lemma_creach_step(g: Seq<Vec<usize>>, s: Sccs, u: int, j: int, t2: int)
    requires
        wf(g),
        sccs_ok(g, s),
        0 <= u < g.len(),
        0 <= j < g[u]@.len(),
        creach(g, s.comp@, s.comp@[g[u]@[j] as int] as int, t2),
    ensures
        creach(g, s.comp@, s.comp@[u] as int, t2),
{
    let v = g[u]@[j] as int;
    lemma_edge_at(g, u, j);
    let (x, y) = choose|x: int, y: int| 0 <= x < g.len() && 0 <= y < g.len() && s.comp@[x] == s.comp@[v]
        && s.comp@[y] == t2 && #[trigger] reach(g, x, y);
    if x != v {
        assert(s.comp@[v] == s.comp@[x]);
        lemma_reach_trans(g, v, x, y);
    }
    lemma_reach_trans(g, u, v, y);
}

proof fn lemma_creach_edge(g: Seq<Vec<usize>>, s: Sccs, u: int, j: int)
    requires
        wf(g),
        sccs_ok(g, s),
        0 <= u < g.len(),
        0 <= j < g[u]@.len(),
    ensures
        creach(g, s.comp@, s.comp@[u] as int, s.comp@[g[u]@[j] as int] as int),
{
    lemma_edge_at(g, u, j);
    assert(reach(g, u, g[u]@[j] as int));
}

/// If every edge out of component `c` is processed, every component that
/// `c` reaches is marked.
proof fn lemma_complete_n(g: Seq<Vec<usize>>, s: Sccs, succ: Seq<Vec<usize>>, mark: Seq<usize>, c: usize, x: int, y: int, k: nat)
    requires
        wf(g),
        sccs_ok(g, s),
        succ_ok(g, s, succ, c as int),
        mark.len() == s.members.len(),
        0 <= x < g.len(),
        s.comp@[x] == c,
        forall|x2: int, j: int| 0 <= x2 < g.len() && s.comp@[x2] == c && 0 <= j < g[x2]@.len() ==>
            #[trigger] edge_done(g, s, succ, mark, c, x2, j),
        reach_n(g, x, y, k),
    ensures
        mark[s.comp@[y] as int] == c,
    decreases k,
{
    lemma_reach_n_tgt(g, x, y, k);
    if edge(g, x, y) {
        let j = choose|j: int| 0 <= j < g[x]@.len() && g[x]@[j] == y as usize;
        assert(edge_done(g, s, succ, mark, c, x, j));
    } else {
        let w = choose|w: int| #[trigger] edge(g, x, w) && reach_n(g, w, y, (k - 1) as nat);
        let j = choose|j: int| 0 <= j < g[x]@.len() && g[x]@[j] == w as usize;
        assert(edge_done(g, s, succ, mark, c, x, j));
        let tw = s.comp@[w] as int;
        assert(tw <= c);
        if tw == c {
            lemma_complete_n(g, s, succ, mark, c, w, y, (k - 1) as nat);
        } else {
            assert(reach(g, w, y));
            assert(creach(g, s.comp@, tw, s.comp@[y] as int));
            let ty = s.comp@[y];
            assert(succ[tw]@.contains(ty));
            let kk = choose|kk: int| 0 <= kk < succ[tw]@.len() && succ[tw]@[kk] == ty;
            assert(mark[succ[tw]@[kk] as int] == c);
        }
    }
}

proof fn lemma_reach_n_tgt(g: Seq<Vec<usize>>, x: int, y: int, k: nat)
    requires
        reach_n(g, x, y, k),
    ensures
        0 <= y < g.len(),
{
    assert(reach(g, x, y));
    lemma_reach_tgt_in_range(g, x, y);
}

/// Two components reach each other iff any of their nodes do.
proof fn lemma_creach_reach(g: Seq<Vec<usize>>, s: Sccs, u: int, v: int)
    requires
        sccs_ok(g, s),
        0 <= u < g.len(),
        0 <= v < g.len(),
    ensures
        creach(g, s.comp@, s.comp@[u] as int, s.comp@[v] as int) <==> reach(g, u, v),
{
    if creach(g, s.comp@, s.comp@[u] as int, s.comp@[v] as int) {
        let (x, y) = choose|x: int, y: int| 0 <= x < g.len() && 0 <= y < g.len() && s.comp@[x] == s.comp@[u]
            && s.comp@[y] == s.comp@[v] && #[trigger] reach(g, x, y);
        if x != u {
            assert(s.comp@[u] == s.comp@[x]);
            lemma_reach_trans(g, u, x, y);
        }
        if y != v {
            assert(s.comp@[y] == s.comp@[v]);
            lemma_reach_trans(g, u, y, v);
        }
    }
}

proof fn lemma_prefix_contains(s: Seq<usize>, k: int, a: usize)
    requires
        0 <= k < s.len(),
    ensures
        s.subrange(0, k + 1).contains(a) <==> (s.subrange(0, k).contains(a) || s[k] == a),
{
    assert(s.subrange(0, k + 1) =~= s.subrange(0, k).push(s[k]));
    lemma_push_contains(s.subrange(0, k), s[k], a);
}

} // verus!

/// The successor components of component `c`.
#[cfg_attr(verus_keep_ghost, verus_spec(cur =>
    requires
        wf(g@),
        sccs_ok(g@, *s),
        (c as int) < s.members.len(),
        succ.len() == c,
        succ_ok(g@, *s, succ@, c as int),
        old(mark).len() == s.members.len(),
        forall|t: int| 0 <= t < s.members.len() ==> #[trigger] old(mark)@[t] != c,
    ensures
        grows(old(mark)@, final(mark)@, c),
        forall|k: int| 0 <= k < cur.len() ==> (#[trigger] cur@[k] as int) < s.members.len(),
        forall|t: usize| (t as int) < s.members.len() ==>
            (#[trigger] cur@.contains(t) <==> creach(g@, s.comp@, c as int, t as int)),
))]
fn component_succ(
    g: &Vec<Vec<usize>>,
    s: &Sccs,
    succ: &Vec<Vec<usize>>,
    mark: &mut Vec<usize>,
    c: usize,
) -> Vec<usize> {
    let ms = &s.members[c];
    let mut cur: Vec<usize> = Vec::new();
    proof_decl! {
        let ghost ncomp = s.members.len() as int;
        let ghost m0 = mark@;
    }
    proof! {
        assert forall|t: int| 0 <= t < ncomp implies (#[trigger] mark@[t] == c <==> cur@.contains(t as usize)) by {}
    }
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            wf(g@),
            sccs_ok(g@, *s),
            succ_ok(g@, *s, succ@, c as int),
            succ.len() == c,
            (c as int) < ncomp,
            ncomp == s.members.len(),
            ms == s.members@[c as int],
            m0 == old(mark)@,
            i <= ms.len(),
            grows(m0, mark@, c),
            sync(mark@, cur@, c, ncomp),
            forall|k: int| 0 <= k < cur.len() ==> creach(g@, s.comp@, c as int, #[trigger] cur@[k] as int),
            forall|i2: int, j: int| 0 <= i2 < i && 0 <= j < g[ms@[i2] as int]@.len() ==>
                #[trigger] edge_done(g@, *s, succ@, mark@, c, ms@[i2] as int, j),
        decreases ms.len() - i
    ))]
    while i < ms.len() {
        let u = ms[i];
        let row = &g[u];
        proof! {
            assert((u as int) < g.len() && s.comp@[u as int] == c);
        }
        let mut j: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                wf(g@),
                sccs_ok(g@, *s),
                succ_ok(g@, *s, succ@, c as int),
                succ.len() == c,
                (c as int) < ncomp,
                ncomp == s.members.len(),
                ms == s.members@[c as int],
                m0 == old(mark)@,
                i < ms.len(),
                u == ms@[i as int],
                (u as int) < g.len(),
                s.comp@[u as int] == c,
                *row == g@[u as int],
                j <= row.len(),
                grows(m0, mark@, c),
                sync(mark@, cur@, c, ncomp),
                forall|k: int| 0 <= k < cur.len() ==> creach(g@, s.comp@, c as int, #[trigger] cur@[k] as int),
                forall|i2: int, j2: int| 0 <= i2 < i && 0 <= j2 < g[ms@[i2] as int]@.len() ==>
                    #[trigger] edge_done(g@, *s, succ@, mark@, c, ms@[i2] as int, j2),
                forall|j2: int| 0 <= j2 < j ==> #[trigger] edge_done(g@, *s, succ@, mark@, c, u as int, j2),
            decreases row.len() - j
        ))]
        while j < row.len() {
            proof_decl! {
                let ghost mj = mark@;
            }
            proof! {
                lemma_edge_at(g@, u as int, j as int);
                lemma_creach_edge(g@, *s, u as int, j as int);
            }
            let t = s.comp[row[j]];
            if mark[t] != c {
                proof! {
                    lemma_sync_push(mark@, cur@, c, ncomp, t);
                }
                mark[t] = c;
                cur.push(t);
            }
            if t != c {
                let st = &succ[t];
                proof! {
                    assert((t as int) < c);
                }
                let mut k: usize = 0;
                #[cfg_attr(verus_keep_ghost, verus_spec(
                    invariant
                        wf(g@),
                        sccs_ok(g@, *s),
                        succ_ok(g@, *s, succ@, c as int),
                        (t as int) < c,
                        (c as int) < ncomp,
                        ncomp == s.members.len(),
                        *st == succ@[t as int],
                        k <= st.len(),
                        (u as int) < g.len(),
                        s.comp@[u as int] == c,
                        j < g@[u as int]@.len(),
                        t == s.comp@[g@[u as int]@[j as int] as int],
                        grows(m0, mark@, c),
                        sync(mark@, cur@, c, ncomp),
                        mark@[t as int] == c,
                        forall|q: int| 0 <= q < ncomp && mj[q] == c ==> #[trigger] mark@[q] == c,
                        forall|k2: int| 0 <= k2 < cur.len() ==> creach(g@, s.comp@, c as int, #[trigger] cur@[k2] as int),
                        forall|k2: int| 0 <= k2 < k ==> mark@[#[trigger] st@[k2] as int] == c,
                    decreases st.len() - k
                ))]
                while k < st.len() {
                    let t2 = st[k];
                    proof! {
                        assert(succ@[t as int]@[k as int] == t2);
                        assert(succ@[t as int]@.contains(t2));
                        assert(creach(g@, s.comp@, t as int, t2 as int));
                        lemma_creach_step(g@, *s, u as int, j as int, t2 as int);
                    }
                    if mark[t2] != c {
                        proof! {
                            lemma_sync_push(mark@, cur@, c, ncomp, t2);
                        }
                        mark[t2] = c;
                        cur.push(t2);
                    }
                    k += 1;
                }
            }
            proof! {
                assert(edge_done(g@, *s, succ@, mark@, c, u as int, j as int));
                assert forall|i2: int, j2: int| 0 <= i2 < i && 0 <= j2 < g[ms@[i2] as int]@.len() implies
                    #[trigger] edge_done(g@, *s, succ@, mark@, c, ms@[i2] as int, j2) by {
                    lemma_edge_at(g@, ms@[i2] as int, j2);
                    assert(edge_done(g@, *s, succ@, mj, c, ms@[i2] as int, j2));
                    lemma_done_mono(g@, *s, succ@, mj, mark@, c, ms@[i2] as int, j2);
                }
                assert forall|j2: int| 0 <= j2 < j implies #[trigger] edge_done(g@, *s, succ@, mark@, c, u as int, j2) by {
                    lemma_edge_at(g@, u as int, j2);
                    assert(edge_done(g@, *s, succ@, mj, c, u as int, j2));
                    lemma_done_mono(g@, *s, succ@, mj, mark@, c, u as int, j2);
                }
            }
            j += 1;
        }
        i += 1;
    }
    proof! {
        assert forall|x2: int, j: int| 0 <= x2 < g.len() && s.comp@[x2] == c && 0 <= j < g[x2]@.len() implies
            #[trigger] edge_done(g@, *s, succ@, mark@, c, x2, j) by {
            assert(s.members@[s.comp@[x2] as int]@.contains(x2 as usize));
            let i2 = choose|i2: int| 0 <= i2 < ms.len() && ms@[i2] == x2 as usize;
        }
        assert forall|t: usize| (t as int) < ncomp implies
            (#[trigger] cur@.contains(t) <==> creach(g@, s.comp@, c as int, t as int)) by {
            assert(mark@[t as int] == c <==> cur@.contains(t));
            if creach(g@, s.comp@, c as int, t as int) {
                let (x, y) = choose|x: int, y: int| 0 <= x < g.len() && 0 <= y < g.len() && s.comp@[x] == c
                    && s.comp@[y] == t as int && #[trigger] reach(g@, x, y);
                let kk = choose|kk: nat| #[trigger] reach_n(g@, x, y, kk);
                lemma_complete_n(g@, *s, succ@, mark@, c, x, y, kk);
            }
            if cur@.contains(t) {
                let k = choose|k: int| 0 <= k < cur.len() && cur@[k] == t;
                assert(creach(g@, s.comp@, c as int, cur@[k] as int));
            }
        }
    }
    cur
}

/// The members of the components in `cur`.
#[cfg_attr(verus_keep_ghost, verus_spec(row =>
    requires
        sccs_ok(g@, *s),
        forall|k: int| 0 <= k < cur.len() ==> (#[trigger] cur@[k] as int) < s.members.len(),
    ensures
        forall|k: int| 0 <= k < row.len() ==> (#[trigger] row@[k] as int) < g@.len(),
        forall|v: int| 0 <= v < g@.len() ==> (#[trigger] row@.contains(v as usize) <==> cur@.contains(s.comp@[v])),
))]
fn component_row(g: &Vec<Vec<usize>>, s: &Sccs, cur: &Vec<usize>) -> Vec<usize> {
    let _ = g;
    let mut row: Vec<usize> = Vec::new();
    let mut k: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            sccs_ok(g@, *s),
            forall|k2: int| 0 <= k2 < cur.len() ==> (#[trigger] cur@[k2] as int) < s.members.len(),
            k <= cur.len(),
            forall|q: int| 0 <= q < row.len() ==> (#[trigger] row@[q] as int) < g@.len(),
            forall|v: int| 0 <= v < g@.len() ==>
                (#[trigger] row@.contains(v as usize) <==> cur@.subrange(0, k as int).contains(s.comp@[v])),
        decreases cur.len() - k
    ))]
    while k < cur.len() {
        let ms = &s.members[cur[k]];
        let mut m: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                sccs_ok(g@, *s),
                forall|k2: int| 0 <= k2 < cur.len() ==> (#[trigger] cur@[k2] as int) < s.members.len(),
                k < cur.len(),
                *ms == s.members@[cur@[k as int] as int],
                m <= ms.len(),
                forall|q: int| 0 <= q < row.len() ==> (#[trigger] row@[q] as int) < g@.len(),
                forall|v: int| 0 <= v < g@.len() ==>
                    (#[trigger] row@.contains(v as usize) <==> (cur@.subrange(0, k as int).contains(s.comp@[v])
                        || (s.comp@[v] == cur@[k as int] && ms@.subrange(0, m as int).contains(v as usize)))),
            decreases ms.len() - m
        ))]
        while m < ms.len() {
            let x = ms[m];
            proof! {
                assert(ms@[m as int] == x);
                assert((x as int) < g@.len() && s.comp@[x as int] == cur@[k as int]);
                assert forall|v: int| 0 <= v < g@.len() implies
                    (#[trigger] row@.push(x).contains(v as usize) <==> (cur@.subrange(0, k as int).contains(s.comp@[v])
                        || (s.comp@[v] == cur@[k as int] && ms@.subrange(0, m as int + 1).contains(v as usize)))) by {
                    lemma_push_contains(row@, x, v as usize);
                    lemma_prefix_contains(ms@, m as int, v as usize);
                }
            }
            row.push(x);
            m += 1;
        }
        proof! {
            assert(ms@.subrange(0, ms.len() as int) =~= ms@);
            assert forall|v: int| 0 <= v < g@.len() implies
                (#[trigger] row@.contains(v as usize) <==> cur@.subrange(0, k as int + 1).contains(s.comp@[v])) by {
                lemma_prefix_contains(cur@, k as int, s.comp@[v]);
                assert(s.members@[s.comp@[v] as int]@.contains(v as usize));
            }
        }
        k += 1;
    }
    proof! {
        assert(cur@.subrange(0, cur.len() as int) =~= cur@);
    }
    row
}

/// The elements of `row` that are not in `out`, and whether `row` contains
/// `u`. `mark` is all false before and after.
#[cfg_attr(verus_keep_ghost, verus_spec(res =>
    requires
        forall|v: int| 0 <= v < old(mark).len() ==> !old(mark)@[v],
        forall|k: int| 0 <= k < row.len() ==> (#[trigger] row@[k] as int) < old(mark).len(),
        forall|k: int| 0 <= k < out.len() ==> (#[trigger] out@[k] as int) < old(mark).len(),
    ensures
        final(mark).len() == old(mark).len(),
        forall|v: int| 0 <= v < final(mark).len() ==> !final(mark)@[v],
        forall|k: int| 0 <= k < res.0.len() ==> (#[trigger] res.0@[k] as int) < old(mark).len(),
        forall|v: usize| #[trigger] res.0@.contains(v) <==> (row@.contains(v) && !out@.contains(v)),
        res.1 == row@.contains(u),
))]
fn row_minus(
    row: &Vec<usize>,
    out: &Vec<usize>,
    u: usize,
    mark: &mut Vec<bool>,
) -> (Vec<usize>, bool) {
    proof_decl! {
        let ghost n = mark.len() as int;
    }
    let mut q: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            mark.len() == n,
            q <= out.len(),
            forall|k: int| 0 <= k < out.len() ==> (#[trigger] out@[k] as int) < n,
            forall|v: int| 0 <= v < n ==> (#[trigger] mark@[v] <==> out@.subrange(0, q as int).contains(v as usize)),
        decreases out.len() - q
    ))]
    while q < out.len() {
        proof! {
            assert forall|v: int| 0 <= v < n implies
                (#[trigger] mark@.update(out@[q as int] as int, true)[v] <==> out@.subrange(0, q as int + 1).contains(v as usize)) by {
                lemma_prefix_contains(out@, q as int, v as usize);
            }
        }
        mark[out[q]] = true;
        q += 1;
    }
    proof! {
        assert(out@.subrange(0, out.len() as int) =~= out@);
    }
    let mut res: Vec<usize> = Vec::new();
    let mut found = false;
    let mut k: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            mark.len() == n,
            k <= row.len(),
            forall|kk: int| 0 <= kk < row.len() ==> (#[trigger] row@[kk] as int) < n,
            forall|kk: int| 0 <= kk < out.len() ==> (#[trigger] out@[kk] as int) < n,
            forall|v: int| 0 <= v < n ==> (#[trigger] mark@[v] <==> out@.contains(v as usize)),
            forall|qq: int| 0 <= qq < res.len() ==> (#[trigger] res@[qq] as int) < n,
            forall|v: usize| #[trigger] res@.contains(v) <==>
                (row@.subrange(0, k as int).contains(v) && !out@.contains(v)),
            found == row@.subrange(0, k as int).contains(u),
        decreases row.len() - k
    ))]
    while k < row.len() {
        let x = row[k];
        proof! {
            assert(row@[k as int] == x);
            lemma_prefix_contains(row@, k as int, u);
        }
        if x == u {
            found = true;
        }
        if !mark[x] {
            proof! {
                assert forall|v: usize| #[trigger] res@.push(x).contains(v) <==>
                    (row@.subrange(0, k as int + 1).contains(v) && !out@.contains(v)) by {
                    lemma_push_contains(res@, x, v);
                    lemma_prefix_contains(row@, k as int, v);
                }
            }
            res.push(x);
        } else {
            proof! {
                assert forall|v: usize| #[trigger] res@.contains(v) <==>
                    (row@.subrange(0, k as int + 1).contains(v) && !out@.contains(v)) by {
                    lemma_prefix_contains(row@, k as int, v);
                }
            }
        }
        k += 1;
    }
    proof! {
        assert(row@.subrange(0, row.len() as int) =~= row@);
    }
    let mut q: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            mark.len() == n,
            q <= out.len(),
            forall|kk: int| 0 <= kk < out.len() ==> (#[trigger] out@[kk] as int) < n,
            forall|v: int| 0 <= v < n && #[trigger] mark@[v] ==>
                exists|p: int| q <= p < out.len() && out@[p] == v as usize,
        decreases out.len() - q
    ))]
    while q < out.len() {
        proof_decl! {
            let ghost m0 = mark@;
        }
        mark[out[q]] = false;
        proof! {
            assert forall|v: int| 0 <= v < n && #[trigger] mark@[v] implies
                exists|p: int| q + 1 <= p < out.len() && out@[p] == v as usize by {
                assert(m0[v]);
                let p = choose|p: int| q <= p < out.len() && out@[p] == v as usize;
                assert(p != q);
            }
        }
        q += 1;
    }
    (res, found)
}

/// The transitive closure of `g`, without the edges of `g`: row `u` of the
/// first result contains `v` iff `g` has a path of length at least 1 from
/// `u` to `v` and `g[u]` does not contain `v`. The second result is the
/// first node on a cycle, `None` iff `g` has no cycle.
#[cfg_attr(verus_keep_ghost, verus_spec(res =>
    requires
        wf(g@),
    ensures
        res.0.len() == g.len(),
        wf(res.0@),
        forall|u: int, v: int| 0 <= u < g.len() && 0 <= v < g.len() ==>
            (res.0[u]@.contains(v as usize) <==> (reach(g@, u, v) && !g@[u]@.contains(v as usize))),
        match res.1 {
            None => !has_cycle(g@),
            Some(u) => (u as int) < g.len() && reach(g@, u as int, u as int)
                && forall|w: int| 0 <= w < u ==> !#[trigger] reach(g@, w, w),
        },
))]
pub fn transitive_closure(g: &Vec<Vec<usize>>) -> (Vec<Vec<usize>>, Option<usize>) {
    let n = g.len();
    let s = sccs(g);
    let ncomp = s.members.len();
    let mut mark = filled(ncomp, NONE);
    let mut inrow = filled_false(n);
    let mut best: Option<usize> = None;
    let mut succ: Vec<Vec<usize>> = Vec::with_capacity(ncomp);
    let mut r: Vec<Vec<usize>> = Vec::with_capacity(n);
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            r.len() <= n,
            forall|u: int| 0 <= u < r.len() ==> #[trigger] r@[u]@.len() == 0,
        decreases n - r.len()
    ))]
    while r.len() < n {
        r.push(Vec::new());
    }
    let mut c: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            wf(g@),
            n == g.len(),
            sccs_ok(g@, s),
            ncomp == s.members.len(),
            c <= ncomp,
            succ.len() == c,
            succ_ok(g@, s, succ@, c as int),
            mark.len() == ncomp,
            forall|t: int| 0 <= t < ncomp ==> #[trigger] mark@[t] == NONE || mark@[t] < c,
            r.len() == n,
            forall|u: int, q: int| 0 <= u < n && 0 <= q < r@[u]@.len() ==> (#[trigger] r@[u]@[q] as int) < n,
            forall|u: int, v: int| 0 <= u < n && 0 <= v < n && s.comp@[u] < c ==>
                (#[trigger] r@[u]@.contains(v as usize) <==>
                    (succ@[s.comp@[u] as int]@.contains(s.comp@[v]) && !g@[u]@.contains(v as usize))),
            inrow.len() == n,
            forall|v: int| 0 <= v < n ==> !inrow@[v],
            match best {
                None => forall|w: int| 0 <= w < n && s.comp@[w] < c ==> !#[trigger] reach(g@, w, w),
                Some(b) => (b as int) < n && s.comp@[b as int] < c && reach(g@, b as int, b as int)
                    && forall|w: int| 0 <= w < b && s.comp@[w] < c ==> !#[trigger] reach(g@, w, w),
            },
        decreases ncomp - c
    ))]
    while c < ncomp {
        proof_decl! {
            let ghost mk0 = mark@;
        }
        let cur = component_succ(g, &s, &succ, &mut mark, c);
        let row = component_row(g, &s, &cur);
        proof_decl! {
            let ghost succ0 = succ@;
        }
        succ.push(cur);
        proof! {
            assert(succ@[c as int] == cur);
            assert forall|c2: int, k: int| 0 <= c2 < c + 1 && 0 <= k < succ@[c2]@.len() implies
                (#[trigger] succ@[c2]@[k] as int) < ncomp by {
                if c2 < c {
                    assert(succ@[c2] == succ0[c2]);
                }
            }
            assert forall|c2: int, t: usize| 0 <= c2 < c + 1 && (t as int) < ncomp implies
                (#[trigger] succ@[c2]@.contains(t) <==> creach(g@, s.comp@, c2, t as int)) by {
                if c2 < c {
                    assert(succ@[c2] == succ0[c2]);
                }
            }
            assert forall|t: int| 0 <= t < ncomp implies #[trigger] mark@[t] == NONE || mark@[t] < c + 1 by {
                assert(mark@[t] == mk0[t] || mark@[t] == c);
            }
            assert(succ_ok(g@, s, succ@, c as int + 1));
        }
        let ms = &s.members[c];
        let mut m: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                wf(g@),
                n == g.len(),
                sccs_ok(g@, s),
                ncomp == s.members.len(),
                c < ncomp,
                succ.len() == c + 1,
                succ_ok(g@, s, succ@, c as int + 1),
                *ms == s.members@[c as int],
                m <= ms.len(),
                forall|q: int| 0 <= q < row.len() ==> (#[trigger] row@[q] as int) < n,
                forall|v: int| 0 <= v < n ==> (#[trigger] row@.contains(v as usize) <==> succ@[c as int]@.contains(s.comp@[v])),
                r.len() == n,
                forall|u: int, q: int| 0 <= u < n && 0 <= q < r@[u]@.len() ==> (#[trigger] r@[u]@[q] as int) < n,
                forall|u: int, v: int| 0 <= u < n && 0 <= v < n
                    && (s.comp@[u] < c || (s.comp@[u] == c && ms@.subrange(0, m as int).contains(u as usize))) ==>
                    (#[trigger] r@[u]@.contains(v as usize) <==>
                        (succ@[s.comp@[u] as int]@.contains(s.comp@[v]) && !g@[u]@.contains(v as usize))),
                inrow.len() == n,
                forall|v: int| 0 <= v < n ==> !inrow@[v],
                match best {
                    None => forall|w: int| 0 <= w < n
                        && (s.comp@[w] < c || (s.comp@[w] == c && ms@.subrange(0, m as int).contains(w as usize)))
                        ==> !#[trigger] reach(g@, w, w),
                    Some(b) => (b as int) < n
                        && (s.comp@[b as int] < c || (s.comp@[b as int] == c && ms@.subrange(0, m as int).contains(b)))
                        && reach(g@, b as int, b as int)
                        && forall|w: int| 0 <= w < b
                            && (s.comp@[w] < c || (s.comp@[w] == c && ms@.subrange(0, m as int).contains(w as usize)))
                            ==> !#[trigger] reach(g@, w, w),
                },
            decreases ms.len() - m
        ))]
        while m < ms.len() {
            let u = ms[m];
            proof_decl! {
                let ghost r0 = r@;
                let ghost b0 = best;
            }
            proof! {
                assert(ms@[m as int] == u);
                assert((u as int) < n && s.comp@[u as int] == c);
                lemma_creach_reach(g@, s, u as int, u as int);
                assert(row@.contains((u as int) as usize) <==> succ@[c as int]@.contains(s.comp@[u as int]));
                assert(succ@[c as int]@.contains(c) <==> creach(g@, s.comp@, c as int, c as int));
                assert(row@.contains(u) <==> reach(g@, u as int, u as int));
            }
            let (ru, selfloop) = row_minus(&row, &g[u], u, &mut inrow);
            r[u] = ru;
            if selfloop {
                match best {
                    None => {
                        best = Some(u);
                    }
                    Some(b) => {
                        if u < b {
                            best = Some(u);
                        }
                    }
                }
            }
            proof! {
                assert(r@[u as int]@ == ru@);
                assert forall|u2: int, q: int| 0 <= u2 < n && 0 <= q < r@[u2]@.len() implies
                    (#[trigger] r@[u2]@[q] as int) < n by {
                    if u2 != u {
                        assert(r@[u2] == r0[u2]);
                    }
                }
                assert forall|u2: int, v: int| 0 <= u2 < n && 0 <= v < n
                    && (s.comp@[u2] < c || (s.comp@[u2] == c && ms@.subrange(0, m as int + 1).contains(u2 as usize))) implies
                    (#[trigger] r@[u2]@.contains(v as usize) <==>
                        (succ@[s.comp@[u2] as int]@.contains(s.comp@[v]) && !g@[u2]@.contains(v as usize))) by {
                    lemma_prefix_contains(ms@, m as int, u2 as usize);
                    if u2 != u {
                        assert(r@[u2] == r0[u2]);
                    }
                }
                assert forall|w: int| 0 <= w < n implies
                    ((s.comp@[w] < c || (s.comp@[w] == c && ms@.subrange(0, m as int + 1).contains(w as usize)))
                    <==> (w == u || s.comp@[w] < c || (s.comp@[w] == c && ms@.subrange(0, m as int).contains(w as usize)))) by {
                    lemma_prefix_contains(ms@, m as int, w as usize);
                }
                match b0 {
                    Some(b) => {
                        lemma_prefix_contains(ms@, m as int, b);
                    }
                    None => {}
                }
            }
            m += 1;
        }
        proof! {
            assert forall|u: int, v: int| 0 <= u < n && 0 <= v < n && s.comp@[u] < c + 1 implies
                (#[trigger] r@[u]@.contains(v as usize) <==>
                    (succ@[s.comp@[u] as int]@.contains(s.comp@[v]) && !g@[u]@.contains(v as usize))) by {
                if s.comp@[u] == c {
                    assert(ms@.subrange(0, ms.len() as int) =~= ms@);
                    assert(s.members@[s.comp@[u] as int]@.contains(u as usize));
                }
            }
            assert(ms@.subrange(0, ms.len() as int) =~= ms@);
            assert forall|w: int| 0 <= w < n && s.comp@[w] < c + 1 implies
                (s.comp@[w] < c || (s.comp@[w] == c && ms@.subrange(0, ms.len() as int).contains(w as usize))) by {
                if s.comp@[w] == c {
                    assert(s.members@[s.comp@[w] as int]@.contains(w as usize));
                }
            }
        }
        c += 1;
    }
    proof! {
        assert forall|u: int, v: int| 0 <= u < g.len() && 0 <= v < g.len() implies
            (r[u]@.contains(v as usize) <==> (reach(g@, u, v) && !g@[u]@.contains(v as usize))) by {
            assert(succ@[s.comp@[u] as int]@.contains(s.comp@[v]) <==> creach(g@, s.comp@, s.comp@[u] as int, s.comp@[v] as int));
            lemma_creach_reach(g@, s, u, v);
        }
        assert forall|w: int| 0 <= w < n implies s.comp@[w] < c by {}
        match best {
            None => {
                assert forall|w: int| 0 <= w < n implies !#[trigger] reach(g@, w, w) by {}
                assert(!has_cycle(g@));
            }
            Some(b) => {}
        }
    }
    (r, best)
}

#[cfg(verus_keep_ghost)]
verus! {

/// Every edge of `g` is a path of `g0`.
spec fn sound(g0: Seq<Vec<usize>>, g: Seq<Vec<usize>>) -> bool {
    &&& g.len() == g0.len()
    &&& forall|u: int, j: int| 0 <= u < g.len() && 0 <= j < g[u]@.len() ==>
        (#[trigger] g[u]@[j] as int) < g.len() && reach(g0, u, g[u]@[j] as int)
}

/// Every row of `g1` is a prefix of the same row of `g2`.
spec fn grown(g1: Seq<Vec<usize>>, g2: Seq<Vec<usize>>) -> bool {
    &&& g2.len() == g1.len()
    &&& forall|u: int| 0 <= u < g1.len() ==> g1[u]@.len() <= (#[trigger] g2[u])@.len()
    &&& forall|u: int, j: int| 0 <= u < g1.len() && 0 <= j < g1[u]@.len() ==> #[trigger] g2[u]@[j] == g1[u]@[j]
}

/// Every seen node that is not closed is `x` or reaches `x`.
spec fn pending(g0: Seq<Vec<usize>>, g: Seq<Vec<usize>>, seen: Seq<bool>, x: int) -> bool {
    forall|u: int| 0 <= u < g.len() && seen[u] && !#[trigger] closed_at(g0, g, u) ==>
        u == x || reach(g0, u, x)
}

/// Every seen node of `(g2, seen2)` that is not closed was already seen and
/// not closed in `(g1, seen1)`.
spec fn kept(g0: Seq<Vec<usize>>, g1: Seq<Vec<usize>>, seen1: Seq<bool>, g2: Seq<Vec<usize>>, seen2: Seq<bool>) -> bool {
    forall|u: int| 0 <= u < g2.len() && seen2[u] && !#[trigger] closed_at(g0, g2, u) ==>
        seen1[u] && !closed_at(g0, g1, u)
}

/// `v` is in `buf[start..]`.
spec fn in_buf(buf: Seq<usize>, start: int, v: usize) -> bool {
    exists|k: int| start <= k < buf.len() && #[trigger] buf[k] == v
}

/// The number of `true` entries among the first `k` of `s`.
spec fn count_seen(s: Seq<bool>, k: int) -> int
    decreases k,
{
    if k <= 0 {
        0
    } else {
        count_seen(s, k - 1) + if s[k - 1] { 1int } else { 0int }
    }
}

proof fn lemma_count_seen_bound(s: Seq<bool>, k: int)
    requires
        0 <= k <= s.len(),
    ensures
        0 <= count_seen(s, k) <= k,
    decreases k,
{
    if k > 0 {
        lemma_count_seen_bound(s, k - 1);
    }
}

proof fn lemma_count_seen_mono(s: Seq<bool>, t: Seq<bool>, k: int)
    requires
        0 <= k <= s.len(),
        k <= t.len(),
        forall|j: int| 0 <= j < k && #[trigger] s[j] ==> t[j],
    ensures
        count_seen(s, k) <= count_seen(t, k),
    decreases k,
{
    if k > 0 {
        lemma_count_seen_mono(s, t, k - 1);
    }
}

proof fn lemma_count_seen_set(s: Seq<bool>, k: int, u: int)
    requires
        0 <= u < k <= s.len(),
        !s[u],
    ensures
        count_seen(s.update(u, true), k) == count_seen(s, k) + 1,
    decreases k,
{
    if k - 1 > u {
        lemma_count_seen_set(s, k - 1, u);
    } else {
        lemma_count_seen_mono(s, s.update(u, true), u);
        lemma_count_seen_mono(s.update(u, true), s, u);
    }
}

proof fn lemma_grown_trans(g1: Seq<Vec<usize>>, g2: Seq<Vec<usize>>, g3: Seq<Vec<usize>>)
    requires
        grown(g1, g2),
        grown(g2, g3),
    ensures
        grown(g1, g3),
{
    assert forall|u: int| 0 <= u < g1.len() implies g1[u]@.len() <= (#[trigger] g3[u])@.len() by {
        assert(g1[u]@.len() <= g2[u]@.len());
    }
    assert forall|u: int, j: int| 0 <= u < g1.len() && 0 <= j < g1[u]@.len() implies
        #[trigger] g3[u]@[j] == g1[u]@[j] by {
        assert(g1[u]@.len() <= g2[u]@.len());
        assert(g2[u]@[j] == g1[u]@[j]);
        assert(g3[u]@[j] == g2[u]@[j]);
    }
}

proof fn lemma_grown_contains(g1: Seq<Vec<usize>>, g2: Seq<Vec<usize>>, u: int, v: usize)
    requires
        grown(g1, g2),
        0 <= u < g1.len(),
        g1[u]@.contains(v),
    ensures
        g2[u]@.contains(v),
{
    let j = choose|j: int| 0 <= j < g1[u]@.len() && g1[u]@[j] == v;
    assert(g1[u]@.len() <= g2[u]@.len());
    assert(g2[u]@[j] == g1[u]@[j]);
}

proof fn lemma_closed_mono(g0: Seq<Vec<usize>>, g1: Seq<Vec<usize>>, g2: Seq<Vec<usize>>, u: int)
    requires
        sound(g0, g2),
        grown(g1, g2),
        0 <= u < g1.len(),
        closed_at(g0, g1, u),
    ensures
        closed_at(g0, g2, u),
{
    assert forall|v: int| 0 <= v < g0.len() implies
        (g2[u]@.contains(v as usize) <==> #[trigger] reach(g0, u, v)) by {
        if g2[u]@.contains(v as usize) {
            let j = choose|j: int| 0 <= j < g2[u]@.len() && g2[u]@[j] == v as usize;
            assert(reach(g0, u, g2[u]@[j] as int));
        }
        if reach(g0, u, v) {
            lemma_grown_contains(g1, g2, u, v as usize);
        }
    }
}

proof fn lemma_closed_same_row(g0: Seq<Vec<usize>>, h1: Seq<Vec<usize>>, h2: Seq<Vec<usize>>, u: int)
    requires
        h1[u]@ == h2[u]@,
    ensures
        closed_at(g0, h1, u) == closed_at(g0, h2, u),
{
}

proof fn lemma_sound_init(g: Seq<Vec<usize>>)
    requires
        wf(g),
    ensures
        sound(g, g),
        grown(g, g),
{
    assert forall|u: int, j: int| 0 <= u < g.len() && 0 <= j < g[u]@.len() implies
        (#[trigger] g[u]@[j] as int) < g.len() && reach(g, u, g[u]@[j] as int) by {
        lemma_edge_at(g, u, j);
    }
    assert forall|u: int| 0 <= u < g.len() implies g[u]@.len() <= (#[trigger] g[u])@.len() by {}
}

/// The precondition of a DFS frame at `x`.
spec fn anc_pre(g0: Seq<Vec<usize>>, dag: bool, g: Seq<Vec<usize>>, seen: Seq<bool>, buf: Seq<usize>, x: int) -> bool {
    &&& sound(g0, g)
    &&& grown(g0, g)
    &&& 0 <= x < g.len()
    &&& seen.len() == g.len()
    &&& forall|k: int| 0 <= k < buf.len() ==> (#[trigger] buf[k] as int) < g.len()
    &&& dag ==> !has_cycle(g0)
    &&& dag ==> pending(g0, g, seen, x)
}

/// What a finished DFS frame at `x` guarantees, from its entry state
/// `(g1, seen1, buf1)` to `(g, seen, buf)`: the ensures of `add_ancestors`
/// without `mark`.
spec fn anc_post(
    g0: Seq<Vec<usize>>,
    dag: bool,
    g1: Seq<Vec<usize>>,
    seen1: Seq<bool>,
    buf1: Seq<usize>,
    g: Seq<Vec<usize>>,
    seen: Seq<bool>,
    buf: Seq<usize>,
    x: int,
) -> bool {
    &&& sound(g0, g)
    &&& grown(g1, g)
    &&& forall|u: int| 0 <= u < g1.len() && #[trigger] g[u]@ != g1[u]@ ==> u == x || !seen1[u]
    &&& seen.len() == seen1.len()
    &&& forall|u: int| 0 <= u < seen1.len() && #[trigger] seen1[u] ==> seen[u]
    &&& buf == buf1
    &&& dag ==> closed_at(g0, g, x)
    &&& dag ==> kept(g0, g1, seen1, g, seen)
}

/// The invariant of the edge loop of the frame at `x` entered at
/// `(g1, seen1, buf1)`, after `j` edges.
#[verifier::opaque]
spec fn anc_loop(
    g0: Seq<Vec<usize>>,
    dag: bool,
    g1: Seq<Vec<usize>>,
    seen1: Seq<bool>,
    buf1: Seq<usize>,
    g: Seq<Vec<usize>>,
    seen: Seq<bool>,
    buf: Seq<usize>,
    x: int,
    j: int,
) -> bool {
    let n = g1.len();
    let start = buf1.len() as int;
    &&& anc_pre(g0, dag, g1, seen1, buf1, x)
    &&& 0 <= j <= g1[x]@.len()
    &&& sound(g0, g)
    &&& grown(g1, g)
    &&& grown(g0, g)
    &&& forall|u: int| 0 <= u < n && #[trigger] g[u]@ != g1[u]@ ==> u == x || !seen1[u]
    &&& seen.len() == n
    &&& forall|u: int| 0 <= u < n && #[trigger] seen1[u] ==> seen[u]
    &&& start <= buf.len()
    &&& forall|k: int| 0 <= k < start ==> #[trigger] buf[k] == buf1[k]
    &&& forall|k: int| 0 <= k < buf.len() ==> (#[trigger] buf[k] as int) < n
    &&& forall|k: int| start <= k < buf.len() ==> reach(g0, x, #[trigger] buf[k] as int)
    &&& dag ==> kept(g0, g1, seen1, g, seen)
    &&& dag ==> forall|j2: int, v: int| 0 <= j2 < j && 0 <= v < n && #[trigger] reach(g0, g1[x]@[j2] as int, v) ==>
        in_buf(buf, start, v as usize)
}

/// Frame `k` is suspended at its edge `fj[k]`, whose target is the node of
/// frame `k + 1`; `cs[k]` is `seen` when the frame above was pushed, before
/// its node was marked seen.
spec fn anc_frozen(
    g0: Seq<Vec<usize>>,
    dag: bool,
    eg: Seq<Seq<Vec<usize>>>,
    es: Seq<Seq<bool>>,
    eb: Seq<Seq<usize>>,
    cs: Seq<Seq<bool>>,
    fx: Seq<usize>,
    fj: Seq<usize>,
    k: int,
) -> bool {
    let x = fx[k] as int;
    let j = fj[k] as int;
    let a = fx[k + 1] as int;
    &&& anc_loop(g0, dag, eg[k], es[k], eb[k], eg[k + 1], cs[k], eb[k + 1], x, j)
    &&& j < eg[k][x]@.len()
    &&& eg[k][x]@[j] as int == a
    &&& !cs[k][a]
    &&& es[k + 1] == cs[k].update(a, true)
}

/// The number of edges left in the top frame.
spec fn anc_rem(flen: Seq<usize>, fj: Seq<usize>) -> int {
    if fj.len() > 0 && flen.len() == fj.len() {
        flen[fj.len() - 1] - fj[fj.len() - 1]
    } else {
        0
    }
}

proof fn lemma_anc_enter(g0: Seq<Vec<usize>>, dag: bool, g: Seq<Vec<usize>>, seen: Seq<bool>, buf: Seq<usize>, x: int)
    requires
        anc_pre(g0, dag, g, seen, buf, x),
    ensures
        anc_loop(g0, dag, g, seen, buf, g, seen, buf, x, 0),
{
    reveal(anc_loop);
    assert forall|u: int| 0 <= u < g.len() implies g[u]@.len() <= (#[trigger] g[u])@.len() by {}
    assert(grown(g, g));
}

proof fn lemma_anc_facts(
    g0: Seq<Vec<usize>>,
    dag: bool,
    g1: Seq<Vec<usize>>,
    seen1: Seq<bool>,
    buf1: Seq<usize>,
    g: Seq<Vec<usize>>,
    seen: Seq<bool>,
    buf: Seq<usize>,
    x: int,
    j: int,
)
    requires
        anc_loop(g0, dag, g1, seen1, buf1, g, seen, buf, x, j),
    ensures
        g.len() == g1.len(),
        g0.len() == g1.len(),
        seen.len() == g.len(),
        seen1.len() == g.len(),
        0 <= x < g.len(),
        0 <= j <= g1[x]@.len(),
        g1[x]@.len() <= g[x]@.len(),
        j < g1[x]@.len() ==> g[x]@[j] == g1[x]@[j] && (g1[x]@[j] as int) < g.len()
            && reach(g0, x, g1[x]@[j] as int),
        buf1.len() <= buf.len(),
        forall|k: int| 0 <= k < buf.len() ==> (#[trigger] buf[k] as int) < g.len(),
{
    reveal(anc_loop);
}

/// Before pushing a frame for an unseen target.
proof fn lemma_anc_child(
    g0: Seq<Vec<usize>>,
    dag: bool,
    g1: Seq<Vec<usize>>,
    seen1: Seq<bool>,
    buf1: Seq<usize>,
    g: Seq<Vec<usize>>,
    seen: Seq<bool>,
    buf: Seq<usize>,
    x: int,
    j: int,
)
    requires
        anc_loop(g0, dag, g1, seen1, buf1, g, seen, buf, x, j),
        j < g1[x]@.len(),
        !seen[g1[x]@[j] as int],
    ensures
        anc_pre(g0, dag, g, seen.update(g1[x]@[j] as int, true), buf, g1[x]@[j] as int),
{
    reveal(anc_loop);
    let n = g1.len();
    let a = g1[x]@[j] as int;
    assert(a < n && reach(g0, x, a));
    if dag {
        assert forall|u: int| 0 <= u < n && seen.update(a, true)[u] && !#[trigger] closed_at(g0, g, u) implies
            u == a || reach(g0, u, a) by {
            if u != a {
                assert(seen[u]);
                assert(seen1[u] && !closed_at(g0, g1, u));
                if u != x {
                    lemma_reach_trans(g0, u, x, a);
                }
            }
        }
    }
}

/// After the frame of the target `a` of edge `j` finishes.
proof fn lemma_anc_after_child(
    g0: Seq<Vec<usize>>,
    dag: bool,
    g1: Seq<Vec<usize>>,
    seen1: Seq<bool>,
    buf1: Seq<usize>,
    ga: Seq<Vec<usize>>,
    sa: Seq<bool>,
    buf: Seq<usize>,
    g2: Seq<Vec<usize>>,
    seen2: Seq<bool>,
    x: int,
    j: int,
)
    requires
        anc_loop(g0, dag, g1, seen1, buf1, ga, sa, buf, x, j),
        j < g1[x]@.len(),
        !sa[g1[x]@[j] as int],
        anc_post(g0, dag, ga, sa.update(g1[x]@[j] as int, true), buf, g2, seen2, buf, g1[x]@[j] as int),
    ensures
        anc_loop(g0, dag, g1, seen1, buf1, g2, seen2, buf, x, j),
        dag ==> closed_at(g0, g2, g1[x]@[j] as int),
{
    reveal(anc_loop);
    let n = g1.len();
    let a = g1[x]@[j] as int;
    assert(a < n);
    lemma_grown_trans(g1, ga, g2);
    lemma_grown_trans(g0, ga, g2);
    assert forall|u: int| 0 <= u < n && #[trigger] seen1[u] implies seen2[u] by {
        assert(sa.update(a, true)[u]);
    }
    assert forall|u: int| 0 <= u < n && #[trigger] g2[u]@ != g1[u]@ implies u == x || !seen1[u] by {
        if ga[u]@ == g1[u]@ {
            assert(u == a || !(sa.update(a, true))[u]);
        }
    }
    if dag {
        assert forall|u: int| 0 <= u < n && seen2[u] && !#[trigger] closed_at(g0, g2, u) implies
            seen1[u] && !closed_at(g0, g1, u) by {
            assert(sa.update(a, true)[u] && !closed_at(g0, ga, u));
        }
    }
}

/// A target that is already seen is closed when the graph is a DAG.
proof fn lemma_anc_seen(
    g0: Seq<Vec<usize>>,
    dag: bool,
    g1: Seq<Vec<usize>>,
    seen1: Seq<bool>,
    buf1: Seq<usize>,
    g: Seq<Vec<usize>>,
    seen: Seq<bool>,
    buf: Seq<usize>,
    x: int,
    j: int,
)
    requires
        anc_loop(g0, dag, g1, seen1, buf1, g, seen, buf, x, j),
        j < g1[x]@.len(),
        seen[g1[x]@[j] as int],
    ensures
        dag ==> closed_at(g0, g, g1[x]@[j] as int),
{
    reveal(anc_loop);
    let a = g1[x]@[j] as int;
    assert(a < g1.len() && reach(g0, x, a));
    if dag && !closed_at(g0, g, a) {
        assert(seen1[a] && !closed_at(g0, g1, a));
        if a == x {
            assert(reach(g0, x, x));
        } else {
            lemma_reach_trans(g0, a, x, a);
        }
        assert(has_cycle(g0));
    }
}

/// Appending the row of the target of edge `j` to `buf` finishes edge `j`.
proof fn lemma_anc_append(
    g0: Seq<Vec<usize>>,
    dag: bool,
    g1: Seq<Vec<usize>>,
    seen1: Seq<bool>,
    buf1: Seq<usize>,
    g: Seq<Vec<usize>>,
    seen: Seq<bool>,
    buf: Seq<usize>,
    buf2: Seq<usize>,
    x: int,
    j: int,
)
    requires
        anc_loop(g0, dag, g1, seen1, buf1, g, seen, buf, x, j),
        j < g1[x]@.len(),
        dag ==> closed_at(g0, g, g1[x]@[j] as int),
        buf2 == buf + g[g1[x]@[j] as int]@,
    ensures
        anc_loop(g0, dag, g1, seen1, buf1, g, seen, buf2, x, j + 1),
{
    reveal(anc_loop);
    let n = g1.len();
    let a = g1[x]@[j] as int;
    let start = buf1.len() as int;
    assert(a < n && reach(g0, x, a));
    assert forall|k: int| start <= k < buf2.len() implies reach(g0, x, #[trigger] buf2[k] as int) by {
        if k >= buf.len() {
            let m = k - buf.len();
            assert(buf2[k] == g[a]@[m]);
            lemma_reach_trans(g0, x, a, buf2[k] as int);
        } else {
            assert(buf2[k] == buf[k]);
        }
    }
    assert forall|k: int| 0 <= k < buf2.len() implies (#[trigger] buf2[k] as int) < n by {
        if k >= buf.len() {
            assert(buf2[k] == g[a]@[k - buf.len()]);
        } else {
            assert(buf2[k] == buf[k]);
        }
    }
    assert forall|k: int| 0 <= k < start implies #[trigger] buf2[k] == buf1[k] by {
        assert(buf2[k] == buf[k]);
    }
    if dag {
        assert forall|j2: int, v: int| 0 <= j2 < j + 1 && 0 <= v < n && #[trigger] reach(g0, g1[x]@[j2] as int, v) implies
            in_buf(buf2, start, v as usize) by {
            if j2 < j {
                assert(in_buf(buf, start, v as usize));
                let k = choose|k: int| start <= k < buf.len() && #[trigger] buf[k] == v as usize;
                assert(buf2[k] == buf[k]);
            } else {
                assert(g[a]@.contains(v as usize));
                let m = choose|m: int| 0 <= m < g[a]@.len() && g[a]@[m] == v as usize;
                assert(buf2[buf.len() + m] == g[a]@[m]);
            }
        }
    }
}

/// Frozen facts of frames below `m` depend only on entries `<= m` of `eg`,
/// `es`, `eb`, `fx` and entries `< m` of `cs`, `fj`.
proof fn lemma_anc_keep(
    g0: Seq<Vec<usize>>,
    dag: bool,
    eg1: Seq<Seq<Vec<usize>>>,
    es1: Seq<Seq<bool>>,
    eb1: Seq<Seq<usize>>,
    cs1: Seq<Seq<bool>>,
    fx1: Seq<usize>,
    fj1: Seq<usize>,
    eg2: Seq<Seq<Vec<usize>>>,
    es2: Seq<Seq<bool>>,
    eb2: Seq<Seq<usize>>,
    cs2: Seq<Seq<bool>>,
    fx2: Seq<usize>,
    fj2: Seq<usize>,
    m: int,
)
    requires
        forall|k: int| 0 <= k < m ==> #[trigger] anc_frozen(g0, dag, eg1, es1, eb1, cs1, fx1, fj1, k),
        forall|k: int| 0 <= k <= m ==> eg2[k] == eg1[k] && es2[k] == es1[k] && eb2[k] == eb1[k] && fx2[k] == fx1[k],
        forall|k: int| 0 <= k < m ==> cs2[k] == cs1[k] && fj2[k] == fj1[k],
    ensures
        forall|k: int| 0 <= k < m ==> #[trigger] anc_frozen(g0, dag, eg2, es2, eb2, cs2, fx2, fj2, k),
{
    assert forall|k: int| 0 <= k < m implies #[trigger] anc_frozen(g0, dag, eg2, es2, eb2, cs2, fx2, fj2, k) by {
        assert(anc_frozen(g0, dag, eg1, es1, eb1, cs1, fx1, fj1, k));
        assert(eg2[k] == eg1[k] && es2[k] == es1[k] && eb2[k] == eb1[k] && fx2[k] == fx1[k]);
        assert(eg2[k + 1] == eg1[k + 1] && es2[k + 1] == es1[k + 1] && eb2[k + 1] == eb1[k + 1]
            && fx2[k + 1] == fx1[k + 1]);
        assert(cs2[k] == cs1[k] && fj2[k] == fj1[k]);
    }
}

} // verus!

/// Appends `row` to `buf`.
#[cfg_attr(verus_keep_ghost, verus_spec(
    ensures
        final(buf)@ == old(buf)@ + row@,
))]
fn append_row(buf: &mut Vec<usize>, row: &Vec<usize>) {
    proof_decl! {
        let ghost b0 = buf@;
    }
    let mut m: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            m <= row.len(),
            buf@ == b0 + row@.subrange(0, m as int),
        decreases row.len() - m
    ))]
    while m < row.len() {
        proof! {
            assert(row@.subrange(0, m as int + 1) =~= row@.subrange(0, m as int).push(row@[m as int]));
        }
        buf.push(row[m]);
        m += 1;
    }
    proof! {
        assert(row@.subrange(0, row.len() as int) =~= row@);
    }
}

/// Appends to `row` each element of `buf[start..]` that is not in `row`.
/// `mark` is all false before and after.
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires
        start <= buf.len(),
        forall|v: int| 0 <= v < old(mark).len() ==> !old(mark)@[v],
        forall|k: int| 0 <= k < buf.len() ==> (#[trigger] buf@[k] as int) < old(mark).len(),
        forall|q: int| 0 <= q < old(row).len() ==> (#[trigger] old(row)@[q] as int) < old(mark).len(),
    ensures
        final(mark).len() == old(mark).len(),
        forall|v: int| 0 <= v < final(mark).len() ==> !final(mark)@[v],
        old(row).len() <= final(row).len(),
        forall|q: int| 0 <= q < old(row).len() ==> #[trigger] final(row)@[q] == old(row)@[q],
        forall|q: int| 0 <= q < final(row).len() ==> (#[trigger] final(row)@[q] as int) < old(mark).len(),
        forall|v: usize| #[trigger] final(row)@.contains(v) <==> (old(row)@.contains(v) || in_buf(buf@, start as int, v)),
))]
fn union_from(row: &mut Vec<usize>, buf: &Vec<usize>, start: usize, mark: &mut Vec<bool>) {
    proof_decl! {
        let ghost r0 = row@;
        let ghost n = mark.len() as int;
    }
    let mut q: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            row@ == r0,
            mark.len() == n,
            q <= row.len(),
            forall|qq: int| 0 <= qq < row.len() ==> (#[trigger] row@[qq] as int) < n,
            forall|v: int| 0 <= v < n ==> (#[trigger] mark@[v] <==> row@.subrange(0, q as int).contains(v as usize)),
        decreases row.len() - q
    ))]
    while q < row.len() {
        proof! {
            assert forall|v: int| 0 <= v < n implies
                (#[trigger] mark@.update(row@[q as int] as int, true)[v] <==> row@.subrange(0, q as int + 1).contains(v as usize)) by {
                lemma_prefix_contains(row@, q as int, v as usize);
            }
        }
        mark[row[q]] = true;
        q += 1;
    }
    proof! {
        assert(row@.subrange(0, row.len() as int) =~= row@);
    }
    let mut k: usize = start;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            start <= k <= buf.len(),
            mark.len() == n,
            forall|kk: int| 0 <= kk < buf.len() ==> (#[trigger] buf@[kk] as int) < n,
            r0.len() <= row.len(),
            forall|qq: int| 0 <= qq < r0.len() ==> #[trigger] row@[qq] == r0[qq],
            forall|qq: int| 0 <= qq < row.len() ==> (#[trigger] row@[qq] as int) < n,
            forall|v: int| 0 <= v < n ==> (#[trigger] mark@[v] <==> row@.contains(v as usize)),
            forall|v: usize| #[trigger] row@.contains(v) <==> (r0.contains(v) || in_buf(buf@.subrange(0, k as int), start as int, v)),
        decreases buf.len() - k
    ))]
    while k < buf.len() {
        let b = buf[k];
        proof! {
            assert forall|v: usize| #[trigger] in_buf(buf@.subrange(0, k as int + 1), start as int, v) <==>
                (in_buf(buf@.subrange(0, k as int), start as int, v) || v == b) by {
                if in_buf(buf@.subrange(0, k as int + 1), start as int, v) {
                    let kk = choose|kk: int| start <= kk < k + 1 && #[trigger] buf@.subrange(0, k as int + 1)[kk] == v;
                    if kk < k {
                        assert(buf@.subrange(0, k as int)[kk] == v);
                    }
                }
                if in_buf(buf@.subrange(0, k as int), start as int, v) {
                    let kk = choose|kk: int| start <= kk < k && #[trigger] buf@.subrange(0, k as int)[kk] == v;
                    assert(buf@.subrange(0, k as int + 1)[kk] == v);
                }
                if v == b {
                    assert(buf@.subrange(0, k as int + 1)[k as int] == v);
                }
            }
        }
        if !mark[b] {
            proof! {
                assert forall|v: usize| #[trigger] row@.push(b).contains(v) <==> (row@.contains(v) || v == b) by {
                    lemma_push_contains(row@, b, v);
                }
            }
            mark[b] = true;
            row.push(b);
        } else {
            proof! {
                assert(row@.contains(b));
            }
        }
        k += 1;
    }
    proof! {
        assert(buf@.subrange(0, buf.len() as int) =~= buf@);
    }
    let mut q: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            mark.len() == n,
            q <= row.len(),
            forall|qq: int| 0 <= qq < row.len() ==> (#[trigger] row@[qq] as int) < n,
            forall|v: int| 0 <= v < n && #[trigger] mark@[v] ==>
                exists|p: int| q <= p < row.len() && row@[p] == v as usize,
        decreases row.len() - q
    ))]
    while q < row.len() {
        proof_decl! {
            let ghost m0 = mark@;
        }
        mark[row[q]] = false;
        proof! {
            assert forall|v: int| 0 <= v < n && #[trigger] mark@[v] implies
                exists|p: int| q + 1 <= p < row.len() && row@[p] == v as usize by {
                assert(m0[v]);
                let p = choose|p: int| q <= p < row.len() && row@[p] == v as usize;
                assert(p != q);
            }
        }
        q += 1;
    }
}

/// Closes row `x`: adds `buf[start..]` to it, then truncates `buf` to
/// `start`.
#[cfg_attr(verus_keep_ghost, verus_spec(
    with Ghost(g0): Ghost<Seq<Vec<usize>>>, Ghost(dag): Ghost<bool>, Ghost(g1): Ghost<Seq<Vec<usize>>>,
        Ghost(seen1): Ghost<Seq<bool>>, Ghost(buf1): Ghost<Seq<usize>>, Ghost(seen): Ghost<Seq<bool>>
    requires
        anc_loop(g0, dag, g1, seen1, buf1, old(g)@, seen, old(buf)@, x as int, g1[x as int]@.len() as int),
        start == buf1.len(),
        old(mark).len() == old(g).len(),
        forall|v: int| 0 <= v < old(mark).len() ==> !old(mark)@[v],
    ensures
        anc_post(g0, dag, g1, seen1, buf1, final(g)@, seen, final(buf)@, x as int),
        final(g).len() == old(g).len(),
        final(mark).len() == old(mark).len(),
        forall|v: int| 0 <= v < final(mark).len() ==> !final(mark)@[v],
))]
fn close_row(
    g: &mut Vec<Vec<usize>>,
    x: usize,
    buf: &mut Vec<usize>,
    start: usize,
    mark: &mut Vec<bool>,
) {
    proof_decl! {
        let ghost gl = g@;
        let ghost bl = buf@;
        let ghost n = g.len() as int;
    }
    proof! {
        assert(sound(g0, gl) && g1.len() == n && (x as int) < n && start <= bl.len()
            && forall|k: int| 0 <= k < bl.len() ==> (#[trigger] bl[k] as int) < n) by {
            reveal(anc_loop);
        }
    }
    let mut row: Vec<usize> = Vec::new();
    std::mem::swap(&mut row, &mut g[x]);
    proof! {
        assert(row@ == gl[x as int]@);
    }
    union_from(&mut row, buf, start, mark);
    g[x] = row;
    buf.truncate(start);
    proof! {
        reveal(anc_loop);
        assert(buf@ =~= buf1);
        let gf = g@;
        assert forall|u: int| 0 <= u < n && u != x implies gf[u] == gl[u] by {}
        assert forall|u: int, q: int| 0 <= u < gf.len() && 0 <= q < gf[u]@.len() implies
            (#[trigger] gf[u]@[q] as int) < gf.len() && reach(g0, u, gf[u]@[q] as int) by {
            if u == x {
                let v = gf[u]@[q];
                assert(gf[u]@.contains(v));
                if in_buf(bl, start as int, v) {
                    let k = choose|k: int| start <= k < bl.len() && #[trigger] bl[k] == v;
                    assert(reach(g0, x as int, bl[k] as int));
                } else {
                    let p = choose|p: int| 0 <= p < gl[x as int]@.len() && gl[x as int]@[p] == v;
                    assert(reach(g0, x as int, gl[x as int]@[p] as int));
                }
            } else {
                assert(gf[u] == gl[u]);
            }
        }
        assert(sound(g0, gf));
        assert forall|u: int| 0 <= u < gl.len() implies gl[u]@.len() <= (#[trigger] gf[u])@.len() by {
            if u != x {
                assert(gf[u] == gl[u]);
            }
        }
        assert forall|u: int, q: int| 0 <= u < gl.len() && 0 <= q < gl[u]@.len() implies
            #[trigger] gf[u]@[q] == gl[u]@[q] by {
            if u != x {
                assert(gf[u] == gl[u]);
            }
        }
        assert(grown(gl, gf));
        lemma_grown_trans(g1, gl, gf);
        assert forall|u: int| 0 <= u < n && #[trigger] gf[u]@ != g1[u]@ implies u == x || !seen1[u] by {
            if u != x {
                assert(gf[u] == gl[u]);
            }
        }
        if dag {
            assert forall|v: int| 0 <= v < n implies
                (gf[x as int]@.contains(v as usize) <==> #[trigger] reach(g0, x as int, v)) by {
                if reach(g0, x as int, v) {
                    lemma_reach_first(g0, x as int, v);
                    let w = choose|w: int| #[trigger] edge(g0, x as int, w) && (w == v || reach(g0, w, v));
                    let i = choose|i: int| 0 <= i < g0[x as int]@.len() && g0[x as int]@[i] == w as usize;
                    assert(g1[x as int]@[i] == g0[x as int]@[i]);
                    assert(gl[x as int]@[i] == g1[x as int]@[i]);
                    if w == v {
                        assert(gl[x as int]@.contains(v as usize));
                    } else {
                        assert(reach(g0, g1[x as int]@[i] as int, v));
                        assert(in_buf(bl, start as int, v as usize));
                    }
                }
            }
            assert forall|u: int| 0 <= u < n && seen[u] && !#[trigger] closed_at(g0, gf, u) implies
                seen1[u] && !closed_at(g0, g1, u) by {
                if u != x {
                    lemma_closed_same_row(g0, gf, gl, u);
                }
            }
        }
    }
}

/// The port of `add_ancestors` in `cedar-policy-core`: closes row `x` by
/// visiting each target of `x` that is not seen, then adding the row of
/// each target to row `x`. `buf[start..]` of each frame collects the rows of
/// its targets. Frame `k` has node `fx[k]`, next edge `fj[k]`, entry buffer
/// length `fst[k]` and entry row length `flen[k]`; the ghost `eg[k]`,
/// `es[k]` and `eb[k]` are `g`, `seen` and `buf` at its entry.
#[cfg_attr(verus_keep_ghost, verus_spec(
    with Ghost(g0): Ghost<Seq<Vec<usize>>>, Ghost(dag): Ghost<bool>
    requires
        sound(g0, old(g)@),
        grown(g0, old(g)@),
        (x as int) < old(g).len(),
        old(seen).len() == old(g).len(),
        old(mark).len() == old(g).len(),
        forall|v: int| 0 <= v < old(mark).len() ==> !old(mark)@[v],
        forall|k: int| 0 <= k < old(buf).len() ==> (#[trigger] old(buf)@[k] as int) < old(g).len(),
        dag ==> !has_cycle(g0),
        dag ==> pending(g0, old(g)@, old(seen)@, x as int),
    ensures
        sound(g0, final(g)@),
        grown(old(g)@, final(g)@),
        forall|u: int| 0 <= u < old(g).len() && #[trigger] final(g)@[u]@ != old(g)@[u]@ ==>
            u == x || !old(seen)@[u],
        final(seen).len() == old(seen).len(),
        forall|u: int| 0 <= u < old(seen).len() && #[trigger] old(seen)@[u] ==> final(seen)@[u],
        final(mark).len() == old(mark).len(),
        forall|v: int| 0 <= v < final(mark).len() ==> !final(mark)@[v],
        final(buf)@ == old(buf)@,
        dag ==> closed_at(g0, final(g)@, x as int),
        dag ==> kept(g0, old(g)@, old(seen)@, final(g)@, final(seen)@),
))]
fn add_ancestors(
    g: &mut Vec<Vec<usize>>,
    x: usize,
    seen: &mut Vec<bool>,
    buf: &mut Vec<usize>,
    mark: &mut Vec<bool>,
) {
    proof_decl! {
        let ghost gi = g@;
        let ghost si = seen@;
        let ghost bi = buf@;
        let ghost n = g.len() as int;
    }
    proof! {
        lemma_anc_enter(g0, dag, gi, si, bi, x as int);
    }
    let mut fx: Vec<usize> = Vec::new();
    let mut fj: Vec<usize> = Vec::new();
    let mut fst: Vec<usize> = Vec::new();
    let mut flen: Vec<usize> = Vec::new();
    fx.push(x);
    fj.push(0);
    fst.push(buf.len());
    flen.push(g[x].len());
    proof_decl! {
        let ghost mut eg: Seq<Seq<Vec<usize>>> = seq![gi];
        let ghost mut es: Seq<Seq<bool>> = seq![si];
        let ghost mut eb: Seq<Seq<usize>> = seq![bi];
        let ghost mut cs: Seq<Seq<bool>> = Seq::empty();
    }
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            gi == old(g)@,
            si == old(seen)@,
            bi == old(buf)@,
            n == g.len(),
            n == gi.len(),
            (x as int) < n,
            seen.len() == n,
            mark.len() == n,
            forall|v: int| 0 <= v < n ==> !mark@[v],
            fj.len() == fx.len(),
            fst.len() == fx.len(),
            flen.len() == fx.len(),
            eg.len() == fx.len(),
            es.len() == fx.len(),
            eb.len() == fx.len(),
            fx.len() > 0 ==> cs.len() == fx.len() - 1,
            fx.len() > 0 ==> eg[0] == gi && es[0] == si && eb[0] == bi && fx@[0] == x,
            forall|k: int| 0 <= k < fx.len() ==> (#[trigger] fx@[k] as int) < n && fst@[k] == eb[k].len()
                && flen@[k] == eg[k][fx@[k] as int]@.len() && fj@[k] <= flen@[k],
            fx.len() > 0 ==> anc_loop(g0, dag, eg[fx.len() - 1], es[fx.len() - 1], eb[fx.len() - 1],
                g@, seen@, buf@, fx@[fx.len() - 1] as int, fj@[fx.len() - 1] as int),
            forall|k: int| 0 <= k < fx.len() - 1 ==> #[trigger] anc_frozen(g0, dag, eg, es, eb, cs, fx@, fj@, k),
            fx.len() == 0 ==> anc_post(g0, dag, gi, si, bi, g@, seen@, buf@, x as int),
        decreases n - count_seen(seen@, n), fx.len(), anc_rem(flen@, fj@)
    ))]
    while fx.len() > 0 {
        proof_decl! {
            let ghost eg1 = eg;
            let ghost es1 = es;
            let ghost eb1 = eb;
            let ghost cs1 = cs;
            let ghost fx1 = fx@;
            let ghost fj1 = fj@;
        }
        let t = fx.len() - 1;
        let y = fx[t];
        let j = fj[t];
        proof! {
            lemma_anc_facts(g0, dag, eg[t as int], es[t as int], eb[t as int], g@, seen@, buf@, y as int, j as int);
            lemma_count_seen_bound(seen@, n);
        }
        if j < flen[t] {
            let a = g[y][j];
            if !seen[a] {
                proof_decl! {
                    let ghost sa = seen@;
                }
                proof! {
                    lemma_anc_child(g0, dag, eg[t as int], es[t as int], eb[t as int], g@, sa, buf@, y as int, j as int);
                    lemma_count_seen_set(sa, n, a as int);
                }
                seen[a] = true;
                proof! {
                    assert(seen@ == sa.update(a as int, true));
                    lemma_count_seen_bound(seen@, n);
                    lemma_anc_enter(g0, dag, g@, seen@, buf@, a as int);
                }
                fx.push(a);
                fj.push(0);
                fst.push(buf.len());
                flen.push(g[a].len());
                proof! {
                    eg = eg.push(g@);
                    es = es.push(seen@);
                    eb = eb.push(buf@);
                    cs = cs.push(sa);
                    lemma_anc_keep(g0, dag, eg1, es1, eb1, cs1, fx1, fj1, eg, es, eb, cs, fx@, fj@, t as int);
                    assert(anc_frozen(g0, dag, eg, es, eb, cs, fx@, fj@, t as int));
                }
            } else {
                proof! {
                    lemma_anc_seen(g0, dag, eg[t as int], es[t as int], eb[t as int], g@, seen@, buf@, y as int, j as int);
                }
                proof_decl! {
                    let ghost bb = buf@;
                }
                append_row(buf, &g[a]);
                proof! {
                    lemma_anc_append(g0, dag, eg[t as int], es[t as int], eb[t as int], g@, seen@, bb, buf@, y as int, j as int);
                }
                fj[t] = j + 1;
                proof! {
                    lemma_anc_keep(g0, dag, eg1, es1, eb1, cs1, fx1, fj1, eg, es, eb, cs, fx@, fj@, t as int);
                }
            }
        } else {
            let s = fst[t];
            proof_with!(Ghost(g0), Ghost(dag), Ghost(eg[t as int]), Ghost(es[t as int]), Ghost(eb[t as int]), Ghost(seen@));
            close_row(g, y, buf, s, mark);
            fx.pop();
            fj.pop();
            fst.pop();
            flen.pop();
            proof! {
                eg = eg.drop_last();
                es = es.drop_last();
                eb = eb.drop_last();
            }
            if t > 0 {
                let p = t - 1;
                let jp = fj[p];
                proof! {
                    assert(anc_frozen(g0, dag, eg1, es1, eb1, cs1, fx1, fj1, p as int));
                    assert(jp == fj1[p as int]);
                    lemma_anc_after_child(g0, dag, eg[p as int], es[p as int], eb[p as int], eg1[t as int], cs1[p as int],
                        eb1[t as int], g@, seen@, fx1[p as int] as int, jp as int);
                    lemma_anc_facts(g0, dag, eg[p as int], es[p as int], eb[p as int], g@, seen@, buf@, fx1[p as int] as int, jp as int);
                }
                proof_decl! {
                    let ghost bb = buf@;
                }
                append_row(buf, &g[y]);
                proof! {
                    lemma_anc_append(g0, dag, eg[p as int], es[p as int], eb[p as int], g@, seen@, bb, buf@, fx1[p as int] as int, jp as int);
                }
                fj[p] = jp + 1;
                proof! {
                    cs = cs.drop_last();
                    lemma_anc_keep(g0, dag, eg1, es1, eb1, cs1, fx1, fj1, eg, es, eb, cs, fx@, fj@, p as int);
                }
            }
        }
    }
}

#[cfg(verus_keep_ghost)]
verus! {

/// `h` is `g0` restricted to `fix` and the targets of the rows of `fix`,
/// over the same indices: every row of `h` is the row of `g0` or empty, and
/// it is the row of `g0` at `fix` and at the targets of the rows of `fix`.
pub open spec fn restricts(g0: Seq<Vec<usize>>, h: Seq<Vec<usize>>, fix: Seq<usize>) -> bool {
    &&& h.len() <= g0.len() <= usize::MAX
    &&& wf(g0)
    &&& wf(h)
    &&& forall|i: int| 0 <= i < fix.len() ==> (#[trigger] fix[i] as int) < h.len()
    &&& forall|i: int| 0 <= i < h.len() ==> #[trigger] h[i]@ == g0[i]@ || h[i]@.len() == 0
    &&& forall|i: int| 0 <= i < fix.len() ==> #[trigger] h[fix[i] as int]@ == g0[fix[i] as int]@
    &&& forall|i: int, j: int| 0 <= i < fix.len() && 0 <= j < g0[fix[i] as int]@.len() ==>
        #[trigger] h[g0[fix[i] as int]@[j] as int]@ == g0[g0[fix[i] as int]@[j] as int]@
}

proof fn lemma_restrict_edge(g0: Seq<Vec<usize>>, h: Seq<Vec<usize>>, fix: Seq<usize>, u: int, v: int)
    requires
        restricts(g0, h, fix),
        edge(h, u, v),
    ensures
        edge(g0, u, v),
        h[u]@ == g0[u]@,
{
    assert(h[u]@.len() > 0);
}

proof fn lemma_restrict_reach_n(g0: Seq<Vec<usize>>, h: Seq<Vec<usize>>, fix: Seq<usize>, u: int, v: int, k: nat)
    requires
        restricts(g0, h, fix),
        reach_n(h, u, v, k),
    ensures
        reach_n(g0, u, v, k),
    decreases k,
{
    if edge(h, u, v) {
        lemma_restrict_edge(g0, h, fix, u, v);
    } else {
        let w = choose|w: int| #[trigger] edge(h, u, w) && reach_n(h, w, v, (k - 1) as nat);
        lemma_restrict_edge(g0, h, fix, u, w);
        lemma_restrict_reach_n(g0, h, fix, w, v, (k - 1) as nat);
        assert(edge(g0, u, w) && reach_n(g0, w, v, (k - 1) as nat));
    }
}

proof fn lemma_restrict_reach(g0: Seq<Vec<usize>>, h: Seq<Vec<usize>>, fix: Seq<usize>, u: int, v: int)
    requires
        restricts(g0, h, fix),
        reach(h, u, v),
    ensures
        reach(g0, u, v),
{
    let k = choose|k: nat| #[trigger] reach_n(h, u, v, k);
    lemma_restrict_reach_n(g0, h, fix, u, v, k);
}

/// From a node of `fix`, a path of `g0` is a path of `h`, if the rows of
/// `g0` outside `fix` are closed.
proof fn lemma_restrict_from_fix(g0: Seq<Vec<usize>>, h: Seq<Vec<usize>>, fix: Seq<usize>, i: int, v: int, k: nat)
    requires
        restricts(g0, h, fix),
        forall|u: int| 0 <= u < g0.len() && !fix.contains(u as usize) ==> #[trigger] closed_at(g0, g0, u),
        0 <= i < fix.len(),
        0 <= v < g0.len(),
        reach_n(g0, fix[i] as int, v, k),
    ensures
        v < h.len(),
        reach(h, fix[i] as int, v),
    decreases k,
{
    let x = fix[i] as int;
    assert(h[x]@ == g0[x]@);
    assert(x < h.len());
    if edge(g0, x, v) {
        assert(h[x]@.contains(v as usize));
        let j = choose|j: int| 0 <= j < h[x]@.len() && h[x]@[j] == v as usize;
        assert((h[x]@[j] as int) < h.len());
        lemma_reach_edge(h, x, v);
    } else {
        let w = choose|w: int| #[trigger] edge(g0, x, w) && reach_n(g0, w, v, (k - 1) as nat);
        assert(g0[x]@.contains(w as usize));
        let j = choose|j: int| 0 <= j < g0[x]@.len() && g0[x]@[j] == w as usize;
        assert((h[x]@[j] as int) < h.len());
        assert(h[x]@.contains(w as usize));
        lemma_reach_edge(h, x, w);
        if fix.contains(w as usize) {
            let i2 = choose|i2: int| 0 <= i2 < fix.len() && fix[i2] == w as usize;
            lemma_restrict_from_fix(g0, h, fix, i2, v, (k - 1) as nat);
            lemma_reach_trans(h, x, w, v);
        } else {
            assert(reach(g0, w, v));
            assert(closed_at(g0, g0, w));
            assert(g0[w]@.contains(v as usize));
            assert(h[g0[fix[i] as int]@[j] as int]@ == g0[g0[fix[i] as int]@[j] as int]@);
            assert(h[w]@ == g0[w]@);
            assert(h[w]@.contains(v as usize));
            let j2 = choose|j2: int| 0 <= j2 < h[w]@.len() && h[w]@[j2] == v as usize;
            assert((h[w]@[j2] as int) < h.len());
            lemma_reach_edge(h, w, v);
            lemma_reach_trans(h, x, w, v);
        }
    }
}

/// Repair on the restriction `h` of `g0` to `fix` and the targets of the
/// rows of `fix` (the graph that `repair_tc` in `cedar-policy-core` builds):
/// (a) a cycle of `h` is a cycle of `g0`; (b) a path of `h` is a path of
/// `g0`. If the rows of `g0` outside `fix` are closed, then (c) so are the
/// rows of `h` outside `fix`, and (d) the nodes that a node of `fix` reaches
/// in `g0` are the nodes it reaches in `h`.
///
/// With (a) and (c), R4 of [`repair_closure`] applies to `h` when `g0` has no
/// cycle, and with (d) the repaired row in `h` of each node of `fix` contains
/// exactly the nodes it reaches in `g0`. With (b) and R3, every repaired edge
/// is a path of `g0` on every input, and with (a) and D1 a reported node
/// implies a cycle of `g0`.
pub proof fn lemma_repair_restrict(g0: Seq<Vec<usize>>, h: Seq<Vec<usize>>, fix: Seq<usize>)
    requires
        restricts(g0, h, fix),
    ensures
        has_cycle(h) ==> has_cycle(g0),
        forall|u: int, v: int| #[trigger] reach(h, u, v) ==> reach(g0, u, v),
        (forall|u: int| 0 <= u < g0.len() && !fix.contains(u as usize) ==> #[trigger] closed_at(g0, g0, u)) ==>
            forall|u: int| 0 <= u < h.len() && !fix.contains(u as usize) ==> #[trigger] closed_at(h, h, u),
        (forall|u: int| 0 <= u < g0.len() && !fix.contains(u as usize) ==> #[trigger] closed_at(g0, g0, u)) ==>
            forall|i: int, v: int| 0 <= i < fix.len() && 0 <= v < g0.len() ==>
                (#[trigger] reach(g0, fix[i] as int, v) <==> (v < h.len() && reach(h, fix[i] as int, v))),
{
    assert forall|u: int, v: int| #[trigger] reach(h, u, v) implies reach(g0, u, v) by {
        lemma_restrict_reach(g0, h, fix, u, v);
    }
    if has_cycle(h) {
        let u = choose|u: int| 0 <= u < h.len() && #[trigger] reach(h, u, u);
        assert(reach(g0, u, u));
    }
    if forall|u: int| 0 <= u < g0.len() && !fix.contains(u as usize) ==> #[trigger] closed_at(g0, g0, u) {
        assert forall|u: int| 0 <= u < h.len() && !fix.contains(u as usize) implies #[trigger] closed_at(h, h, u) by {
            assert(closed_at(g0, g0, u));
            assert forall|v: int| 0 <= v < h.len() implies (h[u]@.contains(v as usize) <==> #[trigger] reach(h, u, v)) by {
                if h[u]@.contains(v as usize) {
                    lemma_reach_edge(h, u, v);
                }
                if reach(h, u, v) {
                    lemma_reach_first(h, u, v);
                    let w = choose|w: int| #[trigger] edge(h, u, w) && (w == v || reach(h, w, v));
                    lemma_restrict_edge(g0, h, fix, u, w);
                    assert(reach(g0, u, v));
                }
            }
        }
        assert forall|i: int, v: int| 0 <= i < fix.len() && 0 <= v < g0.len() implies
            (#[trigger] reach(g0, fix[i] as int, v) <==> (v < h.len() && reach(h, fix[i] as int, v))) by {
            if reach(g0, fix[i] as int, v) {
                let k = choose|k: nat| #[trigger] reach_n(g0, fix[i] as int, v, k);
                lemma_restrict_from_fix(g0, h, fix, i, v, k);
            }
        }
    }
}

} // verus!

/// Repairs the transitive closure of `g` at the nodes in `fix`, in place,
/// by calling the port of `add_ancestors` on each node of `fix` in order.
///
/// Rows outside `fix` are unchanged (R1), and rows only grow, by appending
/// (R2). Every edge of the result is a path of the input (R3), on every
/// input. If the input has no cycle and every row outside `fix` is closed,
/// the result is the transitive closure of the input (R4). On cyclic inputs
/// the result may miss paths.
///
/// Returns the first node of `fix` whose repaired row contains itself (the
/// DAG check of `repair_tc`). `Some` implies that the input has a cycle
/// (D1); if the input has no cycle, the result is `None` (D2).
#[cfg_attr(verus_keep_ghost, verus_spec(res =>
    requires
        wf(old(g)@),
        forall|i: int| 0 <= i < fix.len() ==> (#[trigger] fix@[i] as int) < old(g).len(),
    ensures
        final(g).len() == old(g).len(),
        wf(final(g)@),
        forall|u: int| 0 <= u < old(g).len() && !fix@.contains(u as usize) ==> #[trigger] final(g)@[u]@ == old(g)@[u]@,
        forall|u: int, v: usize| 0 <= u < old(g).len() && #[trigger] old(g)@[u]@.contains(v) ==> final(g)@[u]@.contains(v),
        forall|u: int| 0 <= u < old(g).len() ==> old(g)@[u]@.len() <= (#[trigger] final(g)@[u])@.len(),
        forall|u: int, j: int| 0 <= u < old(g).len() && 0 <= j < old(g)@[u]@.len() ==>
            #[trigger] final(g)@[u]@[j] == old(g)@[u]@[j],
        forall|u: int, v: usize| 0 <= u < old(g).len() && #[trigger] final(g)@[u]@.contains(v) ==> reach(old(g)@, u, v as int),
        (!has_cycle(old(g)@) && forall|u: int| 0 <= u < old(g).len() && !fix@.contains(u as usize) ==>
            #[trigger] closed_at(old(g)@, old(g)@, u))
        ==> forall|u: int| 0 <= u < old(g).len() ==> #[trigger] closed_at(old(g)@, final(g)@, u),
        match res {
            None => forall|i: int| 0 <= i < fix.len() ==>
                !final(g)@[#[trigger] fix@[i] as int]@.contains(fix@[i]),
            Some(u) => exists|i: int| 0 <= i < fix.len() && #[trigger] fix@[i] == u
                && final(g)@[u as int]@.contains(u)
                && forall|j: int| 0 <= j < i ==> !final(g)@[#[trigger] fix@[j] as int]@.contains(fix@[j]),
        },
        res is Some ==> has_cycle(old(g)@),
        !has_cycle(old(g)@) ==> res is None,
))]
pub fn repair_closure(g: &mut Vec<Vec<usize>>, fix: &Vec<usize>) -> Option<usize> {
    let n = g.len();
    let mut seen: Vec<bool> = Vec::with_capacity(n);
    let mut mark: Vec<bool> = Vec::with_capacity(n);
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            seen.len() <= n,
            mark.len() == seen.len(),
            forall|u: int| 0 <= u < seen.len() ==> #[trigger] seen@[u],
            forall|u: int| 0 <= u < mark.len() ==> !#[trigger] mark@[u],
        decreases n - seen.len()
    ))]
    while seen.len() < n {
        seen.push(true);
        mark.push(false);
    }
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            n == g.len(),
            i <= fix.len(),
            seen.len() == n,
            forall|i2: int| 0 <= i2 < fix.len() ==> (#[trigger] fix@[i2] as int) < n,
            forall|u: int| 0 <= u < n ==> (#[trigger] seen@[u] <==> !fix@.subrange(0, i as int).contains(u as usize)),
            mark.len() == n,
            forall|v: int| 0 <= v < n ==> !mark@[v],
        decreases fix.len() - i
    ))]
    while i < fix.len() {
        proof! {
            assert forall|u: int| 0 <= u < n implies
                (#[trigger] seen@.update(fix@[i as int] as int, false)[u] <==> !fix@.subrange(0, i as int + 1).contains(u as usize)) by {
                lemma_prefix_contains(fix@, i as int, u as usize);
            }
        }
        seen[fix[i]] = false;
        i += 1;
    }
    proof! {
        assert(fix@.subrange(0, fix.len() as int) =~= fix@);
    }
    let mut buf: Vec<usize> = Vec::new();
    proof_decl! {
        let ghost g0 = g@;
        let ghost dag = !has_cycle(g0) && forall|u: int| 0 <= u < g0.len() && !fix@.contains(u as usize) ==>
            #[trigger] closed_at(g0, g0, u);
    }
    proof! {
        lemma_sound_init(g0);
    }
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            n == g.len(),
            n == g0.len(),
            i <= fix.len(),
            forall|i2: int| 0 <= i2 < fix.len() ==> (#[trigger] fix@[i2] as int) < n,
            sound(g0, g@),
            grown(g0, g@),
            forall|u: int| 0 <= u < n && !fix@.contains(u as usize) ==> #[trigger] g@[u]@ == g0[u]@,
            seen.len() == n,
            forall|u: int| 0 <= u < n && !fix@.contains(u as usize) ==> #[trigger] seen@[u],
            mark.len() == n,
            forall|v: int| 0 <= v < n ==> !mark@[v],
            buf.len() == 0,
            dag ==> !has_cycle(g0),
            dag ==> forall|u: int| 0 <= u < n && #[trigger] seen@[u] ==> closed_at(g0, g@, u),
            dag ==> forall|i2: int| 0 <= i2 < i ==> closed_at(g0, g@, #[trigger] fix@[i2] as int),
        decreases fix.len() - i
    ))]
    while i < fix.len() {
        let x = fix[i];
        proof_decl! {
            let ghost gi = g@;
            let ghost si = seen@;
        }
        proof_with!(Ghost(g0), Ghost(dag));
        add_ancestors(g, x, &mut seen, &mut buf, &mut mark);
        proof! {
            lemma_grown_trans(g0, gi, g@);
            assert(fix@[i as int] == x);
            assert forall|u: int| 0 <= u < n && !fix@.contains(u as usize) implies #[trigger] g@[u]@ == g0[u]@ by {
                assert(si[u]);
                assert(u != x as int);
            }
            assert forall|u: int| 0 <= u < n && !fix@.contains(u as usize) implies #[trigger] seen@[u] by {
                assert(si[u]);
            }
            if dag {
                assert forall|u: int| 0 <= u < n && #[trigger] seen@[u] implies closed_at(g0, g@, u) by {
                    if !closed_at(g0, g@, u) {
                        assert(si[u] && !closed_at(g0, gi, u));
                    }
                }
                assert forall|i2: int| 0 <= i2 < i + 1 implies closed_at(g0, g@, #[trigger] fix@[i2] as int) by {
                    if i2 < i {
                        lemma_closed_mono(g0, gi, g@, fix@[i2] as int);
                    }
                }
            }
        }
        i += 1;
    }
    proof! {
        assert forall|u: int, v: usize| 0 <= u < n && #[trigger] g0[u]@.contains(v) implies g@[u]@.contains(v) by {
            lemma_grown_contains(g0, g@, u, v);
        }
        assert forall|u: int, v: usize| 0 <= u < n && #[trigger] g@[u]@.contains(v) implies reach(g0, u, v as int) by {
            let q = choose|q: int| 0 <= q < g@[u]@.len() && g@[u]@[q] == v;
            assert(reach(g0, u, g@[u]@[q] as int));
        }
        assert forall|u: int, j: int| 0 <= u < n && 0 <= j < g@[u]@.len() implies (#[trigger] g@[u]@[j] as int) < n by {}
        if dag {
            assert forall|u: int| 0 <= u < n implies #[trigger] closed_at(g0, g@, u) by {
                if fix@.contains(u as usize) {
                    let i2 = choose|i2: int| 0 <= i2 < fix.len() && fix@[i2] == u as usize;
                    assert(closed_at(g0, g@, fix@[i2] as int));
                } else {
                    assert(seen@[u]);
                }
            }
        }
    }
    let res = crate::dag::first_self_loop(g, fix);
    proof! {
        crate::dag::lemma_repair_dag_check(g0, g@, fix@);
        if res is Some {
            let u = res.unwrap();
            let i = choose|i: int| 0 <= i < fix.len() && #[trigger] fix@[i] == u && g@[u as int]@.contains(u);
            assert(g@[fix@[i] as int]@.contains(fix@[i]));
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Row `u`: the nodes reachable from `u` by a path of length at least 1.
    fn bfs_closure(g: &[Vec<usize>]) -> Vec<Vec<usize>> {
        (0..g.len())
            .map(|u| {
                let mut seen = vec![false; g.len()];
                let mut todo: Vec<usize> = g[u].clone();
                while let Some(x) = todo.pop() {
                    if !seen[x] {
                        seen[x] = true;
                        todo.extend(g[x].iter().copied());
                    }
                }
                (0..g.len()).filter(|&v| seen[v]).collect()
            })
            .collect()
    }

    fn check(g: Vec<Vec<usize>>) {
        let (r, cyc) = transitive_closure(&g);
        let full = bfs_closure(&g);
        for (u, row) in r.iter().enumerate() {
            assert!(row.iter().all(|v| !g[u].contains(v)), "graph {g:?}");
            let mut all: Vec<usize> = row.iter().chain(g[u].iter()).copied().collect();
            all.sort_unstable();
            all.dedup();
            assert_eq!(all, full[u], "graph {g:?}");
        }
        assert_eq!(r.len(), g.len());
        assert_eq!(
            cyc,
            (0..g.len()).find(|&u| full[u].contains(&u)),
            "graph {g:?}"
        );
    }

    #[test]
    fn small_graphs() {
        check(vec![]);
        check(vec![vec![]]);
        check(vec![vec![0]]);
        check(vec![vec![1], vec![2], vec![]]);
        check(vec![vec![1], vec![2], vec![0]]);
        check(vec![vec![1, 2], vec![3], vec![3], vec![]]);
        check(vec![vec![1], vec![0, 2], vec![3], vec![2], vec![4]]);
        check(vec![vec![1], vec![2], vec![1, 3], vec![]]);
        // A -> B -> C -> E -> D -> A, D -> B, D -> F -> E
        check(vec![
            vec![1],
            vec![2],
            vec![4],
            vec![0, 1, 5],
            vec![3],
            vec![4],
        ]);
        // Node 3 has an empty row (a dangling target).
        check(vec![vec![1, 3], vec![2], vec![], vec![]]);
    }

    #[test]
    fn all_graphs_on_4_nodes() {
        let n = 4;
        for bits in 0u32..(1 << (n * n)) {
            let g: Vec<Vec<usize>> = (0..n)
                .map(|u| (0..n).filter(|&v| bits & (1 << (u * n + v)) != 0).collect())
                .collect();
            check(g);
        }
    }

    fn direct(n: usize, edges: &[(usize, usize)]) -> Vec<Vec<usize>> {
        let mut g = vec![Vec::new(); n];
        for &(u, v) in edges {
            g[u].push(v);
        }
        g
    }

    fn sorted(mut g: Vec<Vec<usize>>) -> Vec<Vec<usize>> {
        for row in &mut g {
            row.sort_unstable();
        }
        g
    }

    type Case = (usize, Vec<(usize, usize)>, Vec<(usize, usize)>, Vec<usize>);

    /// The shapes of `repair_tc_test_cases` in `cedar-policy-core`, with
    /// A = 0, B = 1, ...: the initial edges, the new edges, and `fix`.
    fn cases() -> Vec<Case> {
        vec![
            (4, vec![(0, 1), (1, 2)], vec![(3, 2)], vec![3]),
            (4, vec![(0, 1), (1, 2), (2, 3)], vec![(0, 2)], vec![0]),
            (
                5,
                vec![(0, 1), (0, 2), (1, 3), (2, 3)],
                vec![(4, 1)],
                vec![4],
            ),
            (5, vec![(0, 1), (1, 2)], vec![(3, 0), (4, 0)], vec![3, 4]),
            (
                6,
                vec![(0, 1), (1, 2), (2, 3), (3, 4)],
                vec![(5, 0)],
                vec![5],
            ),
            (4, vec![(1, 3), (2, 3)], vec![(0, 1), (0, 2)], vec![0]),
            (5, vec![(0, 1), (2, 3)], vec![(4, 1), (4, 3)], vec![4]),
            (
                5,
                vec![(0, 1), (1, 2), (2, 3)],
                vec![(1, 4), (4, 3)],
                vec![0, 1, 4],
            ),
        ]
    }

    /// Closes the initial graph and replaces the rows of `fix` with their
    /// direct edges (initial and new). Also returns the closure of all edges.
    fn repair_input((n, edges, new_edges, fix): &Case) -> (Vec<Vec<usize>>, Vec<Vec<usize>>) {
        let all: Vec<_> = edges.iter().chain(new_edges.iter()).copied().collect();
        let full = direct(*n, &all);
        let mut g = bfs_closure(&direct(*n, edges));
        for &x in fix {
            g[x] = full[x].clone();
        }
        (g, bfs_closure(&full))
    }

    #[test]
    fn repair_cases() {
        for case in cases() {
            let (mut g, closure) = repair_input(&case);
            let fix = &case.3;
            assert_eq!(repair_closure(&mut g, fix), None);
            assert_eq!(sorted(g), closure, "case {case:?}");
        }
    }

    /// `lemma_repair_restrict`: repair on the rows of `fix` and of their
    /// targets, the other rows empty, gives the same rows at `fix`.
    #[test]
    fn repair_restricted_matches_full() {
        for case in cases() {
            let (mut g, _) = repair_input(&case);
            let fix = &case.3;
            let mut h = vec![Vec::new(); g.len()];
            for &x in fix {
                h[x] = g[x].clone();
                for &t in &g[x] {
                    h[t] = g[t].clone();
                }
            }
            assert_eq!(repair_closure(&mut h, fix), None);
            assert_eq!(repair_closure(&mut g, fix), None);
            let (h, g) = (sorted(h), sorted(g));
            for &x in fix {
                assert_eq!(h[x], g[x], "case {case:?}, node {x}");
            }
        }
    }

    /// On a 3-cycle the repair terminates, adds only paths and reports a cycle.
    #[test]
    fn repair_three_cycle() {
        let g0 = vec![vec![1], vec![2], vec![0]];
        let closure = bfs_closure(&g0);
        let mut g = g0.clone();
        assert!(repair_closure(&mut g, &vec![0, 1, 2]).is_some());
        for (row, full) in g.iter().zip(&closure) {
            assert!(row.iter().all(|v| full.contains(v)), "{g:?}");
        }
    }

    /// The repair of a 1,000-node chain runs in a 128 KiB stack.
    #[test]
    fn repair_deep_chain_small_stack() {
        let n = 1_000;
        let h = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || {
                let mut g: Vec<Vec<usize>> = (1..n).map(|i| vec![i]).collect();
                g.push(vec![]);
                let fix: Vec<usize> = (0..n).collect();
                assert_eq!(repair_closure(&mut g, &fix), None);
                assert_eq!(g[0].len(), n - 1);
                assert_eq!(g[n - 2], vec![n - 1]);
            })
            .unwrap();
        h.join().unwrap();
    }
}
