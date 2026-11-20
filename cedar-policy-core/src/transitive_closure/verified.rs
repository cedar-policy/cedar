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

/// The graph of `nodes` over indices: index `i < nodes.len()` is the `i`-th
/// key of `nodes` in iteration order, and every edge target that is not a key
/// gets a further index with an empty row. Returns the key of each index,
/// the rows (without duplicate targets), and the indices of the keys of
/// `nodes` that are in `to_fix`, in the iteration order of `to_fix`.
fn index_graph<K, V>(
    nodes: &HashMap<K, V>,
    to_fix: &HashSet<K>,
) -> (Vec<K>, Vec<Vec<usize>>, Vec<usize>)
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
    let fix = to_fix.iter().filter_map(|k| idx.get(k).copied()).collect();
    let mut g: Vec<Vec<usize>> = Vec::with_capacity(nodes.len());
    // `stamp[v] == u` iff `v` is already in row `u`
    let mut stamp: Vec<usize> = vec![usize::MAX; nodes.len()];
    for (u, node) in nodes.values().enumerate() {
        let mut row = Vec::new();
        for t in node.out_edges() {
            let v = match idx.get(t) {
                Some(v) => *v,
                None => {
                    let v = keys.len();
                    idx.insert(t, v);
                    keys.push(t.clone());
                    stamp.push(usize::MAX);
                    v
                }
            };
            #[expect(
                clippy::indexing_slicing,
                reason = "`stamp` has one entry per index, and `v` is an index"
            )]
            if stamp[v] != u {
                stamp[v] = u;
                row.push(v);
            }
        }
        g.push(row);
    }
    g.resize_with(keys.len(), Vec::new);
    (keys, g, fix)
}

/// [`super::compute_tc`] with `cedar_verified_core::transitive_closure`.
pub(super) fn compute_tc<K, V>(nodes: &mut HashMap<K, V>, enforce_dag: bool) -> Result<(), K>
where
    K: Clone + Eq + Hash + Debug + Display,
    V: TCNode<K>,
{
    let (keys, g, _) = index_graph(nodes, &HashSet::new());
    let r = cedar_verified_core::transitive_closure(&g);
    // `iter_mut` visits the keys in the order `index_graph` numbered them
    for (i, ((k, node), row)) in nodes.iter_mut().zip(r.iter()).enumerate() {
        debug_assert!(keys.get(i) == Some(k));
        for v in row {
            #[expect(
                clippy::indexing_slicing,
                reason = "`transitive_closure` returns targets below `g.len() == keys.len()`"
            )]
            let key = &keys[*v];
            if !node.has_edge_to(key) {
                node.add_edge_to(key.clone());
            }
        }
    }
    if enforce_dag {
        let order: Vec<usize> = (0..nodes.len()).collect();
        if let Some(u) = cedar_verified_core::first_self_loop(&r, &order) {
            #[expect(clippy::indexing_slicing, reason = "`u < nodes.len() <= keys.len()`")]
            return Err(TcError::has_cycle(keys[u].clone()));
        }
    }
    Ok(())
}

/// [`super::repair_tc`] with `cedar_verified_core::repair_closure`.
pub(super) fn repair_tc<K, V>(
    nodes_to_fix: &HashSet<K>,
    nodes: &mut HashMap<K, V>,
    enforce_dag: bool,
) -> Result<(), K>
where
    K: Clone + Eq + Hash + Debug + Display,
    V: TCNode<K>,
{
    let (keys, mut g, fix) = index_graph(nodes, nodes_to_fix);
    #[expect(
        clippy::indexing_slicing,
        reason = "`index_graph` returns indices below `g.len()`"
    )]
    let len0: Vec<usize> = fix.iter().map(|x| g[*x].len()).collect();
    cedar_verified_core::repair_closure(&mut g, &fix);
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
        if let Some(u) = cedar_verified_core::first_self_loop(&g, &fix) {
            #[expect(
                clippy::indexing_slicing,
                reason = "`fix` holds indices below `keys.len()`"
            )]
            return Err(TcError::has_cycle(keys[u].clone()));
        }
    }
    Ok(())
}
