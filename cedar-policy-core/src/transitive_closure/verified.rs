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

//! Transitive closure with `cedar_verified_core`, which works on graphs
//! over dense `usize` indices.

use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display};
use std::hash::Hash;

use super::{Result, TCNode, TcError};

/// Pushes to `g` the row of `node`: its out-edges as indices, in `out_edges`
/// order. A target without an index gets the next one.
fn push_row<'a, K, V>(
    node: &'a V,
    idx: &mut HashMap<&'a K, usize>,
    keys: &mut Vec<K>,
    g: &mut Vec<Vec<usize>>,
) where
    K: Clone + Eq + Hash,
    V: TCNode<K>,
{
    let mut row = Vec::new();
    for t in node.out_edges() {
        let v = match idx.get(t) {
            Some(v) => *v,
            None => {
                let v = keys.len();
                idx.insert(t, v);
                keys.push(t.clone());
                v
            }
        };
        row.push(v);
    }
    g.push(row);
}

/// The graph of `nodes` over indices. Trusted postconditions:
/// - `keys` has no duplicates, and `idx` is a bijection between `keys` and
///   `0..keys.len()`;
/// - for `i < nodes.len()`, `keys[i]` is the `i`-th key of `nodes` in
///   iteration order, and `g[i]` lists the out-edges of `keys[i]` as indices,
///   in `out_edges` order;
/// - for `i >= nodes.len()`, `keys[i]` is an edge target that is not a key of
///   `nodes`, and `g[i]` is empty;
/// - `g.len() == keys.len()`.
fn index_graph<K, V>(nodes: &HashMap<K, V>) -> (Vec<K>, Vec<Vec<usize>>)
where
    K: Clone + Eq + Hash,
    V: TCNode<K>,
{
    let mut idx: HashMap<&K, usize> = HashMap::with_capacity(nodes.len());
    let mut keys: Vec<K> = Vec::with_capacity(nodes.len());
    for k in nodes.keys() {
        idx.insert(k, keys.len());
        keys.push(k.clone());
    }
    let mut g: Vec<Vec<usize>> = Vec::with_capacity(nodes.len());
    for node in nodes.values() {
        push_row(node, &mut idx, &mut keys, &mut g);
    }
    g.resize_with(keys.len(), Vec::new);
    debug_assert_eq!(g.len(), keys.len());
    (keys, g)
}

/// The graph of `nodes` restricted to `to_fix` and the targets of their
/// rows, over indices. Returns `keys`, `g` and `n`. Trusted postconditions:
/// - `keys` has no duplicates, and `idx` is a bijection between `keys` and
///   `0..keys.len()`;
/// - `keys[..n]` are the keys of `to_fix` that are keys of `nodes`, in
///   `to_fix` iteration order;
/// - `g[i]` lists the out-edges of `keys[i]` as indices, in `out_edges` order,
///   for `i < n` and for every `i` that is a target of a row `g[j]`, `j < n`,
///   and a key of `nodes`; every other row is empty;
/// - `g.len() == keys.len()`.
///
/// So `g` is `restricts(g0, g, 0..n)` of `cedar_verified_core::tc` for any
/// indexing `g0` of the whole graph that extends `keys`.
fn index_fix<K, V>(nodes: &HashMap<K, V>, to_fix: &HashSet<K>) -> (Vec<K>, Vec<Vec<usize>>, usize)
where
    K: Clone + Eq + Hash,
    V: TCNode<K>,
{
    let mut idx: HashMap<&K, usize> = HashMap::with_capacity(to_fix.len());
    let mut keys: Vec<K> = Vec::with_capacity(to_fix.len());
    let mut fixed: Vec<&V> = Vec::with_capacity(to_fix.len());
    for k in to_fix {
        if let Some((k, node)) = nodes.get_key_value(k) {
            idx.insert(k, keys.len());
            keys.push(k.clone());
            fixed.push(node);
        }
    }
    let n = keys.len();
    let mut g: Vec<Vec<usize>> = Vec::with_capacity(n);
    for node in fixed {
        push_row(node, &mut idx, &mut keys, &mut g);
    }
    let m = keys.len();
    for u in n..m {
        match keys.get(u).and_then(|k| nodes.get(k)) {
            Some(node) => push_row(node, &mut idx, &mut keys, &mut g),
            None => g.push(Vec::new()),
        }
    }
    g.resize_with(keys.len(), Vec::new);
    debug_assert_eq!(g.len(), keys.len());
    (keys, g, n)
}

/// [`super::compute_tc`] with `cedar_verified_core::transitive_closure`.
///
/// Trusted: `keys` and `g` are as documented on `index_graph`; `iter_mut`
/// visits the keys in index order; `add_edge_to` is idempotent and adds no
/// edge other than its argument.
pub(super) fn compute_tc<K, V>(nodes: &mut HashMap<K, V>, enforce_dag: bool) -> Result<(), K>
where
    K: Clone + Eq + Hash + Debug + Display,
    V: TCNode<K>,
{
    let (keys, g) = index_graph(nodes);
    let (r, cyc) = cedar_verified_core::transitive_closure(&g);
    for (i, ((k, node), row)) in nodes.iter_mut().zip(r.iter()).enumerate() {
        debug_assert!(keys.get(i) == Some(k));
        for v in row {
            #[expect(
                clippy::indexing_slicing,
                reason = "`transitive_closure` returns targets below `g.len() == keys.len()`"
            )]
            node.add_edge_to(keys[*v].clone());
        }
    }
    if enforce_dag {
        if let Some(u) = cyc {
            #[expect(
                clippy::indexing_slicing,
                reason = "`transitive_closure` returns a node below `g.len() == keys.len()`"
            )]
            return Err(TcError::has_cycle(keys[u].clone()));
        }
    }
    Ok(())
}

/// [`super::repair_tc`] with `cedar_verified_core::repair_closure`, on the
/// graph of `index_fix` instead of the whole graph.
///
/// When the whole graph has no cycle and its rows outside `nodes_to_fix`
/// are closed, `lemma_repair_restrict` and R4 of `repair_closure` give that
/// the repaired rows are the closure of the whole graph at `nodes_to_fix`,
/// and D2 that no cycle is reported. On every input, each added edge is a
/// path of the whole graph, and a reported node is on a cycle of the whole
/// graph. Outside these preconditions, equality with a repair on the whole
/// graph is not proved; `verified_repair_restricted_matches_full` tests it.
pub(super) fn repair_tc<K, V>(
    nodes_to_fix: &HashSet<K>,
    nodes: &mut HashMap<K, V>,
    enforce_dag: bool,
) -> Result<(), K>
where
    K: Clone + Eq + Hash + Debug + Display,
    V: TCNode<K>,
{
    let (keys, g, n) = index_fix(nodes, nodes_to_fix);
    repair_indexed(&keys, g, &(0..n).collect(), nodes, enforce_dag)
}

/// Repairs the rows of `fix` in `g` and writes the added edges back to
/// `nodes`. Trusted: `keys[i]` is the key of index `i`, `fix` holds indices
/// of keys of `nodes`, and `g.len() == keys.len()`; `add_edge_to` adds no
/// edge other than its argument.
fn repair_indexed<K, V>(
    keys: &[K],
    mut g: Vec<Vec<usize>>,
    fix: &Vec<usize>,
    nodes: &mut HashMap<K, V>,
    enforce_dag: bool,
) -> Result<(), K>
where
    K: Clone + Eq + Hash + Debug + Display,
    V: TCNode<K>,
{
    #[expect(
        clippy::indexing_slicing,
        reason = "`fix` holds indices below `g.len()`"
    )]
    let len0: Vec<usize> = fix.iter().map(|x| g[*x].len()).collect();
    let cyc = cedar_verified_core::repair_closure(&mut g, fix);
    // `repair_closure` only appends to rows, and only targets not already in the row
    for (x, l) in fix.iter().zip(len0) {
        #[expect(
            clippy::indexing_slicing,
            reason = "`x < g.len() == keys.len()`, and `repair_closure` only appends to rows"
        )]
        let (key, added) = (&keys[*x], &g[*x][l..]);
        if let Some(node) = nodes.get_mut(key) {
            for v in added {
                #[expect(
                    clippy::indexing_slicing,
                    reason = "`repair_closure` keeps targets below `g.len() == keys.len()`"
                )]
                let key = &keys[*v];
                node.add_edge_to(key.clone());
            }
        }
    }
    if enforce_dag {
        if let Some(u) = cyc {
            #[expect(
                clippy::indexing_slicing,
                reason = "`repair_closure` returns a node of `fix`, below `keys.len()`"
            )]
            return Err(TcError::has_cycle(keys[u].clone()));
        }
    }
    Ok(())
}

/// [`repair_tc`] on the whole graph, as before `index_fix`.
#[cfg(test)]
pub(super) fn repair_full<K, V>(
    nodes_to_fix: &HashSet<K>,
    nodes: &mut HashMap<K, V>,
    enforce_dag: bool,
) -> Result<(), K>
where
    K: Clone + Eq + Hash + Debug + Display,
    V: TCNode<K>,
{
    let (keys, g) = index_graph(nodes);
    let pos: HashMap<&K, usize> = keys.iter().enumerate().map(|(i, k)| (k, i)).collect();
    let fix: Vec<usize> = nodes_to_fix
        .iter()
        .filter(|k| nodes.contains_key(*k))
        .filter_map(|k| pos.get(k).copied())
        .collect();
    repair_indexed(&keys, g, &fix, nodes, enforce_dag)
}

#[cfg(test)]
#[expect(clippy::indexing_slicing, reason = "test code")]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::{index_fix, index_graph};
    use crate::ast::{Entity, EntityUID};
    use crate::transitive_closure::TCNode;

    fn entity(id: &str, parents: &[&str]) -> (EntityUID, Entity) {
        let mut e = Entity::with_uid(EntityUID::with_eid(id));
        for p in parents {
            e.add_parent(EntityUID::with_eid(p));
        }
        (e.uid().clone(), e)
    }

    /// The postconditions of `index_graph`, on a graph with a dangling target `X`.
    #[test]
    fn index_graph_postconditions() {
        let nodes: HashMap<EntityUID, Entity> = HashMap::from([
            entity("A", &["B", "X"]),
            entity("B", &["C"]),
            entity("C", &[]),
        ]);
        let (keys, g) = index_graph(&nodes);
        assert_eq!(g.len(), keys.len());
        assert_eq!(keys.len(), 4);
        assert_eq!(keys.iter().collect::<HashSet<_>>().len(), keys.len());
        for (i, (k, node)) in nodes.iter().enumerate() {
            assert_eq!(&keys[i], k);
            let row: Vec<&EntityUID> = g[i].iter().map(|v| &keys[*v]).collect();
            assert_eq!(row, node.out_edges().collect::<Vec<_>>());
        }
        assert_eq!(keys[3], EntityUID::with_eid("X"));
        assert!(g[3].is_empty());
    }

    /// The postconditions of `index_fix` on `A -> B`, with `B -> C -> D`
    /// closed: `B` has its row, `C` and `D` have indices and empty rows.
    #[test]
    fn index_fix_postconditions() {
        let nodes: HashMap<EntityUID, Entity> = HashMap::from([
            entity("A", &["B"]),
            entity("B", &["C", "D"]),
            entity("C", &["D"]),
            entity("D", &[]),
        ]);
        let to_fix = HashSet::from([EntityUID::with_eid("A"), EntityUID::with_eid("Y")]);
        let (keys, g, n) = index_fix(&nodes, &to_fix);
        assert_eq!(n, 1);
        assert_eq!(g.len(), keys.len());
        assert_eq!(keys.len(), 4);
        assert_eq!(keys.iter().collect::<HashSet<_>>().len(), keys.len());
        let row = |i: usize| -> HashSet<&EntityUID> { g[i].iter().map(|v| &keys[*v]).collect() };
        let out = |id: &str| -> HashSet<&EntityUID> {
            nodes[&EntityUID::with_eid(id)].out_edges().collect()
        };
        assert_eq!(keys[0], EntityUID::with_eid("A"));
        assert_eq!(row(0), out("A"));
        assert_eq!(keys[1], EntityUID::with_eid("B"));
        assert_eq!(row(1), out("B"));
        for i in 2..4 {
            assert!(["C", "D"].map(EntityUID::with_eid).contains(&keys[i]));
            assert!(g[i].is_empty());
        }
    }
}
