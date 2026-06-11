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

//! Generic topological sort using Kahn's algorithm.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// Topologically sort nodes given a dependency graph.
///
/// `graph` maps each node to the set of nodes it depends on (i.e., must come
/// before it in the output). Dependencies that don't appear as keys in the
/// graph are ignored.
///
/// Returns nodes in dependency order (leaves first), or `Err(node)` with a
/// cycle participant.
///
/// This implements a variant of Kahn's algorithm.
pub(crate) fn topo_sort<'a, N>(graph: &HashMap<&'a N, HashSet<&'a N>>) -> Result<Vec<&'a N>, &'a N>
where
    N: Eq + Hash,
{
    // The in-degree map
    let mut indegrees: HashMap<&N, usize> = HashMap::new();
    for (ty_name, deps) in graph.iter() {
        indegrees.entry(ty_name).or_insert(0);
        for dep in deps {
            if graph.contains_key(dep) {
                *indegrees.entry(dep).or_insert(0) += 1;
            }
        }
    }

    // The set that contains names with zero incoming edges
    let mut work_set: HashSet<&N> = HashSet::new();
    let mut res: Vec<&N> = Vec::new();

    for (name, degree) in indegrees.iter() {
        let name = *name;
        if *degree == 0 {
            work_set.insert(name);
            if graph.contains_key(name) {
                res.push(name);
            }
        }
    }

    // Pop a node
    while let Some(name) = work_set.iter().next().copied() {
        work_set.remove(name);
        if let Some(deps) = graph.get(name) {
            for dep in deps {
                if let Some(degree) = indegrees.get_mut(dep) {
                    *degree -= 1;
                    if *degree == 0 {
                        work_set.insert(dep);
                        if graph.contains_key(dep) {
                            res.push(dep);
                        }
                    }
                }
            }
        }
    }

    // Nodes not in the result have incoming edges remaining, i.e., a cycle
    let mut remaining: HashSet<&N> = HashSet::from_iter(graph.keys().copied());
    for name in res.iter() {
        remaining.remove(name);
    }

    if let Some(cycle) = remaining.into_iter().next() {
        Err(cycle)
    } else {
        res.reverse();
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_graph() {
        let graph: HashMap<&&str, HashSet<&&str>> = HashMap::new();
        assert_eq!(topo_sort(&graph).unwrap(), Vec::<&&str>::new());
    }

    #[test]
    fn single_node_no_deps() {
        let graph: HashMap<&&str, HashSet<&&str>> = HashMap::from([(&"A", HashSet::new())]);
        assert_eq!(topo_sort(&graph).unwrap(), vec![&"A"]);
    }

    #[test]
    fn linear_chain() {
        let a = "A";
        let b = "B";
        let c = "C";
        let graph: HashMap<&&str, HashSet<&&str>> = HashMap::from([
            (&a, HashSet::from([&b])),
            (&b, HashSet::from([&c])),
            (&c, HashSet::new()),
        ]);
        let sorted = topo_sort(&graph).unwrap();
        let pos = |n: &&str| sorted.iter().position(|x| *x == n).unwrap();
        assert!(pos(&c) < pos(&b));
        assert!(pos(&b) < pos(&a));
    }

    #[test]
    fn cycle_detected() {
        let a = "A";
        let b = "B";
        let graph: HashMap<&&str, HashSet<&&str>> =
            HashMap::from([(&a, HashSet::from([&b])), (&b, HashSet::from([&a]))]);
        assert!(topo_sort(&graph).is_err());
    }

    #[test]
    fn deps_outside_graph_ignored() {
        let a = "A";
        let z = "Z";
        let graph: HashMap<&&str, HashSet<&&str>> = HashMap::from([(&a, HashSet::from([&z]))]);
        assert_eq!(topo_sort(&graph).unwrap(), vec![&"A"]);
    }
}
