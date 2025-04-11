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

//! Module containing code to compute the transitive closure of a graph.
//! This is a generic utility, and not specific to Cedar.

use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display};
use std::hash::Hash;

mod err;
pub use err::*;
use itertools::Itertools;

/// Trait used to generalize transitive closure computation. This trait should
/// be implemented for types representing a node in the hierarchy (e.g., the
/// entity hierarchy) where we need to compute the transitive closure of the
/// hierarchy starting from only direct adjacencies. This trait is parametrized
/// by a type `K` which represents a unique identifier for graph nodes.
pub trait TCNode<K> {
    /// Extract a unique identifier for the node.
    fn get_key(&self) -> K;

    /// Add an edge out off this node to the node with key `k`.
    fn add_edge_to(&mut self, k: K);

    /// Retrieve an iterator for the edges out of this node.
    fn out_edges(&self) -> Box<dyn Iterator<Item = &K> + '_>;

    /// Return true when their is an edge between this node and the node with
    /// key `k`.
    fn has_edge_to(&self, k: &K) -> bool;
}

/// Given Graph as a map from keys with type `K` to implementations of `TCNode`
/// with type `V`, compute the transitive closure of the hierarchy. In case of
/// error, the result contains an error structure `Err<K>` which contains the
/// keys (with type `K`) for the nodes in the graph which caused the error.
/// If `enforce_dag` then also check that the heirarchy is a DAG
pub fn compute_tc<K, V>(nodes: &mut HashMap<K, V>, enforce_dag: bool) -> Result<(), K>
where
    K: Clone + Eq + Hash + Debug + Display,
    V: TCNode<K>,
{
    let all_node_ids = nodes.keys().map(K::clone).collect::<Vec<K>>();

    // If the caller does not want to check that the graph is a DAG,
    // we assume that the graph is acyclic during the below call.
    // This allows the below call to do a single scan of each node
    // rather than two scans of each node.
    compute_tc_internal(all_node_ids.into_iter(), nodes, HashSet::new(), enforce_dag);

    if enforce_dag {
        return enforce_dag_from_tc(nodes);
    }
    Ok(())
}

/// Given Graph as a map from keys with type `K` to implementations of `TCNode`
/// with type `V`, repair the transitive closure of the hierarchy. The below code
/// will assume that for each `node` in `nodes` except the nodes appearing in
/// `nodes_to_fix`, the out-going edges of `node` will contain all ancestors of `node`.
/// That is we may assume the transitive closure for all such nodes is correct while
/// computing the transitive closure of each node appearing in `nodes_to_fix`.
/// In case of error, the result contains an error structure `Err<K>` which contains
/// the keys (with type `K`) for the nodes in the graph which caused the error.
/// If `enforce_dag` then also check that the heirarchy is a DAG
pub fn repair_tc<K, V>(
    nodes_to_fix: HashSet<K>,
    nodes: &mut HashMap<K, V>,
    enforce_dag: bool,
) -> Result<(), K>
where
    K: Clone + Eq + Hash + Debug + Display,
    V: TCNode<K>,
{
    let seen: HashSet<K> = nodes
        .keys()
        .filter_map(|node_id| {
            if nodes_to_fix.contains(node_id) {
                None
            } else {
                Some(node_id.clone())
            }
        })
        .collect();

    // If the caller does not want to check that the graph is a DAG,
    // we assume that the graph is acyclic during the below call.
    // This allows the below call to do a single scan of each node
    // rather than two scans of each node.
    compute_tc_internal::<K, V>(nodes_to_fix.into_iter(), nodes, seen, enforce_dag);

    if enforce_dag {
        return enforce_dag_from_tc(nodes);
    }
    Ok(())
}

/// Saturate the out-going edges of each node in `node_ids` to include
/// all reachable ancestors within the graph represnted by `nodes`.
/// Assume that all nodes appearing in `seen` already satisfy this property.
/// If `detect_cyles` is false, we assume the the graph represented by `nodes`
/// is a DAG so that we may perform a single scan over the graph. Otherwise,
/// we scan each node twice. This is sufficient for detecting cycles and for computing
/// the exact TC for graphs containing simple cycles. For more complex cyclic graphs,
/// the below code computes enough of the transtive closure to ensure that if one
/// calls `enforce_dag_from_tc` on `nodes` after this function returns then it will
/// correctly detect any cycles (simple or compelx).
fn compute_tc_internal<K, V>(
    node_ids: impl Iterator<Item = K>,
    nodes: &mut HashMap<K, V>,
    mut seen: HashSet<K>,
    detect_cyles: bool,
) where
    K: Clone + Eq + Hash,
    V: TCNode<K>,
{
    for node_id in node_ids {
        if detect_cyles {
            add_ancestors(&node_id, nodes, &mut seen);
        } else if seen.insert(node_id.clone()) {
            add_ancestors(&node_id, nodes, &mut seen);
        }
    }
}

fn cyclic_tc<K, V>(nodes: &mut HashMap<K, V>)
where
    K: Clone + Eq + Hash + Debug,
    V: TCNode<K>,
{
    let node_ids = nodes.keys().map(K::clone).collect::<Vec<K>>();
    let mut order_visited = HashMap::new();
    let mut root = HashMap::new();
    let mut vstack = Vec::new();
    let mut cstack = Vec::new();
    let mut component = HashMap::new();
    let mut comp_succ = Vec::new();
    let mut comp_elts = Vec::new();
    for node_id in node_ids {
        if !order_visited.contains_key(&node_id) {
            cyclic_tc_internal(
                &node_id,
                &nodes,
                &mut order_visited,
                &mut root,
                &mut vstack,
                &mut cstack,
                &mut component,
                &mut comp_succ,
                &mut comp_elts,
            );    
        }
    }
    // component_tc => nodes_tc
    for comp_id in 0..comp_elts.len() {
        let mut elt_succ = HashSet::new();
        // PANIC SAFETY! `comp_succ` and `comp_elts` must have the same length, thus `comp_id` is a valid index to `comp_succ`.
        #[allow(clippy::indexing_slicing)]
        for comp_parent_id in comp_succ[comp_id].iter() {
            // PANIC SAFETY! `comp_parent_id` must be a valid component id to be inserted into `comp_succ` therefore must exist within `comp_elts`.
            #[allow(clippy::indexing_slicing)]
            for node_id in comp_elts[*comp_parent_id].iter() {
                // not fine to consume here
                elt_succ.insert(node_id.clone());
            }
        }
        // PANIC SAFETY! `comp_id` \in [0, |`comp_elts`|) is a valid index into `comp_elts`.
        #[allow(clippy::indexing_slicing)]
        for node_id in comp_elts[comp_id].iter() {
            let node = match nodes.get_mut(node_id) {
                Some(node) => node,
                None => continue,
            };
            for parent_id in elt_succ.iter() {
                node.add_edge_to(parent_id.clone());
            }
        }
    }
}

fn cyclic_tc_internal<K, V>(
    node_id: &K,
    nodes: &HashMap<K, V>,
    order_visited: &mut HashMap<K, usize>,
    root: &mut HashMap<K, K>,
    vstack: &mut Vec<K>,
    cstack: &mut Vec<usize>,
    component: &mut HashMap<K, usize>,
    comp_succ: &mut Vec<HashSet<usize>>,
    comp_elts: &mut Vec<HashSet<K>>,
) where
    K: Clone + Eq + Hash + Debug,
    V: TCNode<K>,
{
    let node_order = order_visited.len();
    // when was the root of this node's component visited?
    // initially the root of this node's component is this node itself
    // keeping track in auxillary function to avoid re-fetching in a loop
    let mut root_order = node_order;
    order_visited.insert(node_id.clone(), node_order);
    root.insert(node_id.clone(), node_id.clone());
    vstack.push(node_id.clone());
    let height = cstack.len();
    let mut self_loop = false;
    let out_edges = match nodes.get(node_id) {
        Some(node) => node.out_edges().collect(),
        None => Vec::new(),
    };
    for parent_id in out_edges {
        if node_id == parent_id {
            self_loop = true;
        } else {
            // The edge from node_id to parent_id is a forward edge iff
            // node_id is visited before parent_id and we do not visit
            // parent_id from node_id (i.e., we do not recursively call
            // cyclic_tc_interanl on parent_id from this call).
            let mut maybe_forward_edge = true;
            if !order_visited.contains_key(parent_id) {
                maybe_forward_edge = false;
                cyclic_tc_internal(
                    parent_id,
                    nodes,
                    order_visited,
                    root,
                    vstack,
                    cstack,
                    component,
                    comp_succ,
                    comp_elts,
                );
            }
            match component.get(parent_id) {
                None => {
                    // PANIC SAFETY! `parent_id` must have been visited either by a previous call or just above
                    #[allow(clippy::expect_used)]
                    let parent_root = root
                        .get(parent_id)
                        .expect("Parent has been visited so it must have a root.");
                    // PANIC SAFETY! in order for `parent_root` to be the parent of `parent_id` it must have been visited.
                    #[allow(clippy::expect_used)]
                    let parent_root_order = order_visited
                        .get(parent_root)
                        .expect("The parent's root must have been visited.");
                    if *parent_root_order < root_order {
                        root_order = *parent_root_order;
                        root.insert(node_id.clone(), parent_root.clone());
                    }
                }
                Some(parent_component) => {
                    // PANIC SAFETY! `parent_id` must have been visited either by a previous call or just above
                    #[allow(clippy::expect_used)]
                    let parent_order = order_visited
                        .get(parent_id)
                        .expect("The parent must have been traversed by this point.");
                    // if not a forward edge
                    if !(maybe_forward_edge && &node_order < parent_order) {
                        cstack.push(*parent_component);
                    }
                }
            }
        }
    } // end for loop over parents
      // PANIC SAFETY! `node_id` must have a root. It was inserted at the begining of this function
    #[allow(clippy::expect_used)]
    let node_root = root
        .get(node_id)
        .expect("Node must have a root by this point.");
    // if this node is the root of its connected component
    if node_id == node_root {
        let component_id = comp_elts.len();
        let mut succ = HashSet::new();
        let mut elmts = HashSet::new();
        // PANIC SAFETY! The vertex stack must not be empty because at least node_id must be on the stack!
        #[allow(clippy::expect_used)]
        if self_loop || vstack.last().expect("vertex stack must be non-empty") != node_id {
            succ.insert(component_id);
        }
        let mut cstack_tail = cstack.split_off(height);
        // sort by topological order of the components, which should be equivalent to the reverse order of their ids
        // cstack_tail are all of the components reachable (1 step) from any node within this component
        cstack_tail.sort_by(|a, b| b.cmp(a));
        // iterate through components in topological order
        for i in 0..cstack_tail.len() {
            // update this component's successors with next component avoiding duplicate components
            // PANIC SAFETY! both `i` and `i - 1` are gauranteed to be valid indices into `cstack_tail`.
            #[allow(clippy::indexing_slicing)]
            if i == 0 || cstack_tail[i - 1] == cstack_tail[i] {
                // PANIC SAFETY! `i` is a valid index into `cstack_tail`.
                #[allow(clippy::indexing_slicing)]
                let X = cstack_tail[i];
                if succ.insert(X) {
                    // PANIC SAFETY! `X` is a component id created by a previous call to `cyclic_tc_internal` and thus must be a valid index to `comp_succ`.
                    #[allow(clippy::indexing_slicing)]
                    succ.extend(comp_succ[X].clone());
                }
            }
        }
        loop {
            // PANIC SAFETY! The vertex stack `vstack` must contain at least `node_id`
            #[allow(clippy::expect_used)]
            let ancestor_id = vstack.pop().expect("Vetex stack must be non-empty");
            component.insert(ancestor_id.clone(), component_id);
            elmts.insert(ancestor_id.clone());
            if *node_id == ancestor_id {
                break;
            }
        }
        comp_succ.push(succ);
        comp_elts.push(elmts);
    }
}

/// Saturate the out-going edges of the node identified by `node_id` within the graph
/// represented by `nodes` assuming that each node appearing in `seen` already satisfies
/// this property. The process works by performing a depth-first search over the ancestors
/// of `node_id` (and stopping if any ancestor is already in the `seen` set).
fn add_ancestors<K, V>(node_id: &K, nodes: &mut HashMap<K, V>, seen: &mut HashSet<K>)
where
    K: Clone + Eq + Hash,
    V: TCNode<K>,
{
    let mut ancestors: HashSet<K> = HashSet::new();
    let out_edges: Vec<K> = match nodes.get(node_id) {
        Some(node) => node.out_edges().map(K::clone).collect(),
        None => return,
    };
    for ancestor_id in out_edges {
        if seen.insert(ancestor_id.clone()) {
            add_ancestors(&ancestor_id, nodes, seen);
        }
        // a slight optimization to avoid adding the ancestors of `ancestor_id` if
        // `ancestor_id` was an ancestor of any parent already explored by this loop.
        if !ancestors.contains(&ancestor_id) {
            let ancestor = match nodes.get(&ancestor_id) {
                Some(ancestor) => ancestor,
                None => return,
            };
            for grand_ancestor_id in ancestor.out_edges() {
                ancestors.insert(grand_ancestor_id.clone());
            }
        }
    }
    // PANIC SAFETY this node should always exist because of the check to get `out_edges`
    #[allow(clippy::expect_used)]
    let node = nodes
        .get_mut(node_id)
        .expect("This node should always exist.");
    // Do the actual saturation of out-going edges of `node` here to avoid
    // issues with rust's borrow checker.
    for ancestor_id in ancestors {
        node.add_edge_to(ancestor_id);
    }
}

/// Given a graph (as a map from keys to `TCNode`), enforce that
/// all transitive edges are included, ie, the transitive closure has already
/// been computed and that it is a DAG. If this is not the case, return an appropriate
/// `TCEnforcementError`.
pub fn enforce_tc_and_dag<K, V>(entities: &HashMap<K, V>) -> Result<(), K>
where
    K: Clone + Eq + Hash + Debug + Display,
    V: TCNode<K>,
{
    let res = enforce_tc(entities);
    if res.is_ok() {
        return enforce_dag_from_tc(entities);
    }
    res
}

/// Given a DAG (as a map from keys to `TCNode`), enforce that
/// all transitive edges are included, i.e., the transitive closure has already
/// been computed. If this is not the case, return an appropriate
/// `MissingTcEdge` error.
fn enforce_tc<K, V>(entities: &HashMap<K, V>) -> Result<(), K>
where
    K: Clone + Eq + Hash + Debug + Display,
    V: TCNode<K>,
{
    for entity in entities.values() {
        for parent_uid in entity.out_edges() {
            // check that `entity` is also a child of all of this parent's parents
            if let Some(parent) = entities.get(parent_uid) {
                for grandparent in parent.out_edges() {
                    if !entity.has_edge_to(grandparent) {
                        return Err(TcError::missing_tc_edge(
                            entity.get_key(),
                            parent_uid.clone(),
                            grandparent.clone(),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Once the transitive closure (as defined above) is computed/enforced for the graph, we have:
/// \forall u,v,w \in Vertices . (u,v) \in Edges /\ (v,w) \in Edges -> (u,w) \in Edges
///
/// Then the graph has a cycle if
/// \exists v \in Vertices. (v,v) \in Edges
fn enforce_dag_from_tc<K, V>(entities: &HashMap<K, V>) -> Result<(), K>
where
    K: Clone + Eq + Hash + Debug + Display,
    V: TCNode<K>,
{
    for entity in entities.values() {
        let key = entity.get_key();
        if entity.out_edges().contains(&key) {
            return Err(TcError::has_cycle(key));
        }
    }
    Ok(())
}

// PANIC SAFETY test cases
#[allow(clippy::indexing_slicing)]
// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
#[cfg(test)]
mod tests {
    use crate::ast::{Entity, EntityUID};

    use super::*;

    #[test]
    fn basic() {
        // start with A -> B -> C
        let mut a = Entity::with_uid(EntityUID::with_eid("A"));
        a.add_indirect_ancestor(EntityUID::with_eid("B"));
        let mut b = Entity::with_uid(EntityUID::with_eid("B"));
        b.add_indirect_ancestor(EntityUID::with_eid("C"));
        let c = Entity::with_uid(EntityUID::with_eid("C"));
        let mut entities = HashMap::from([
            (a.uid().clone(), a),
            (b.uid().clone(), b),
            (c.uid().clone(), c),
        ]);
        // currently doesn't pass TC enforcement
        assert!(enforce_tc(&entities).is_err());
        // compute TC
        compute_tc(&mut entities, false).expect("Failed to compute transitive closure");
        let a = &entities[&EntityUID::with_eid("A")];
        let b = &entities[&EntityUID::with_eid("B")];
        let c = &entities[&EntityUID::with_eid("C")];
        // should have added the A -> C edge
        assert!(a.is_descendant_of(&EntityUID::with_eid("C")));
        // but we shouldn't have added other edges, like B -> A or C -> A
        assert!(!b.is_descendant_of(&EntityUID::with_eid("A")));
        assert!(!c.is_descendant_of(&EntityUID::with_eid("A")));
        // now it should pass TC enforcement
        assert!(enforce_tc(&entities).is_ok());
        // passes cycle check after TC enforcement
        assert!(enforce_dag_from_tc(&entities).is_ok());
    }

    #[test]
    fn reversed() {
        // same as basic(), but we put the entities in the map in the reverse
        // order, which shouldn't make a difference
        let mut a = Entity::with_uid(EntityUID::with_eid("A"));
        a.add_indirect_ancestor(EntityUID::with_eid("B"));
        let mut b = Entity::with_uid(EntityUID::with_eid("B"));
        b.add_indirect_ancestor(EntityUID::with_eid("C"));
        let c = Entity::with_uid(EntityUID::with_eid("C"));
        let mut entities = HashMap::from([
            (c.uid().clone(), c),
            (b.uid().clone(), b),
            (a.uid().clone(), a),
        ]);
        // currently doesn't pass TC enforcement
        assert!(enforce_tc(&entities).is_err());
        // compute TC
        compute_tc(&mut entities, false).expect("Failed to compute transitive closure");
        let a = &entities[&EntityUID::with_eid("A")];
        let b = &entities[&EntityUID::with_eid("B")];
        let c = &entities[&EntityUID::with_eid("C")];
        // should have added the A -> C edge
        assert!(a.is_descendant_of(&EntityUID::with_eid("C")));
        // but we shouldn't have added other edges, like B -> A or C -> A
        assert!(!b.is_descendant_of(&EntityUID::with_eid("A")));
        assert!(!c.is_descendant_of(&EntityUID::with_eid("A")));
        // now it should pass TC enforcement
        assert!(enforce_tc(&entities).is_ok());
        // passes cycle check after TC enforcement
        assert!(enforce_dag_from_tc(&entities).is_ok());
    }

    #[test]
    fn deeper() {
        // start with A -> B -> C -> D -> E
        let mut a = Entity::with_uid(EntityUID::with_eid("A"));
        a.add_indirect_ancestor(EntityUID::with_eid("B"));
        let mut b = Entity::with_uid(EntityUID::with_eid("B"));
        b.add_indirect_ancestor(EntityUID::with_eid("C"));
        let mut c = Entity::with_uid(EntityUID::with_eid("C"));
        c.add_indirect_ancestor(EntityUID::with_eid("D"));
        let mut d = Entity::with_uid(EntityUID::with_eid("D"));
        d.add_indirect_ancestor(EntityUID::with_eid("E"));
        let e = Entity::with_uid(EntityUID::with_eid("E"));
        let mut entities = HashMap::from([
            (a.uid().clone(), a),
            (b.uid().clone(), b),
            (c.uid().clone(), c),
            (d.uid().clone(), d),
            (e.uid().clone(), e),
        ]);
        // currently doesn't pass TC enforcement
        assert!(enforce_tc(&entities).is_err());
        // compute TC
        compute_tc(&mut entities, false).expect("Failed to compute transitive closure");
        let a = &entities[&EntityUID::with_eid("A")];
        let b = &entities[&EntityUID::with_eid("B")];
        let c = &entities[&EntityUID::with_eid("C")];
        // should have added many edges which we check for
        assert!(a.is_descendant_of(&EntityUID::with_eid("C")));
        assert!(a.is_descendant_of(&EntityUID::with_eid("D")));
        assert!(a.is_descendant_of(&EntityUID::with_eid("E")));
        assert!(b.is_descendant_of(&EntityUID::with_eid("D")));
        assert!(b.is_descendant_of(&EntityUID::with_eid("E")));
        assert!(c.is_descendant_of(&EntityUID::with_eid("E")));
        // now it should pass TC enforcement
        assert!(enforce_tc(&entities).is_ok());
        // passes cycle check after TC enforcement
        assert!(enforce_dag_from_tc(&entities).is_ok());
    }

    #[test]
    fn not_alphabetized() {
        // same as deeper(), but the entities' parent relations don't follow
        // alphabetical order. (In case we end up iterating through the map
        // in alphabetical order, this test will ensure that everything works
        // even when we aren't processing the entities in hierarchy order.)
        // start with foo -> bar -> baz -> ham -> eggs
        let mut foo = Entity::with_uid(EntityUID::with_eid("foo"));
        foo.add_indirect_ancestor(EntityUID::with_eid("bar"));
        let mut bar = Entity::with_uid(EntityUID::with_eid("bar"));
        bar.add_indirect_ancestor(EntityUID::with_eid("baz"));
        let mut baz = Entity::with_uid(EntityUID::with_eid("baz"));
        baz.add_indirect_ancestor(EntityUID::with_eid("ham"));
        let mut ham = Entity::with_uid(EntityUID::with_eid("ham"));
        ham.add_indirect_ancestor(EntityUID::with_eid("eggs"));
        let eggs = Entity::with_uid(EntityUID::with_eid("eggs"));
        let mut entities = HashMap::from([
            (ham.uid().clone(), ham),
            (bar.uid().clone(), bar),
            (foo.uid().clone(), foo),
            (eggs.uid().clone(), eggs),
            (baz.uid().clone(), baz),
        ]);
        // currently doesn't pass TC enforcement
        assert!(enforce_tc(&entities).is_err());
        // compute TC
        compute_tc(&mut entities, false).expect("Failed to compute transitive closure");
        let foo = &entities[&EntityUID::with_eid("foo")];
        let bar = &entities[&EntityUID::with_eid("bar")];
        let baz = &entities[&EntityUID::with_eid("baz")];
        // should have added many edges which we check for
        assert!(foo.is_descendant_of(&EntityUID::with_eid("baz")));
        assert!(foo.is_descendant_of(&EntityUID::with_eid("ham")));
        assert!(foo.is_descendant_of(&EntityUID::with_eid("eggs")));
        assert!(bar.is_descendant_of(&EntityUID::with_eid("ham")));
        assert!(bar.is_descendant_of(&EntityUID::with_eid("eggs")));
        assert!(baz.is_descendant_of(&EntityUID::with_eid("eggs")));
        // now it should pass TC enforcement
        assert!(enforce_tc(&entities).is_ok());
        // passes cycle check after TC enforcement
        assert!(enforce_dag_from_tc(&entities).is_ok());
    }

    #[test]
    fn multi_parents() {
        // start with this:
        //     B -> C
        //   /
        // A
        //   \
        //     D -> E
        let mut a = Entity::with_uid(EntityUID::with_eid("A"));
        a.add_indirect_ancestor(EntityUID::with_eid("B"));
        a.add_indirect_ancestor(EntityUID::with_eid("D"));
        let mut b = Entity::with_uid(EntityUID::with_eid("B"));
        b.add_indirect_ancestor(EntityUID::with_eid("C"));
        let c = Entity::with_uid(EntityUID::with_eid("C"));
        let mut d = Entity::with_uid(EntityUID::with_eid("D"));
        d.add_indirect_ancestor(EntityUID::with_eid("E"));
        let e = Entity::with_uid(EntityUID::with_eid("E"));
        let mut entities = HashMap::from([
            (a.uid().clone(), a),
            (b.uid().clone(), b),
            (c.uid().clone(), c),
            (d.uid().clone(), d),
            (e.uid().clone(), e),
        ]);
        // currently doesn't pass TC enforcement
        assert!(enforce_tc(&entities).is_err());
        // compute TC
        compute_tc(&mut entities, false).expect("Failed to compute transitive closure");
        let a = &entities[&EntityUID::with_eid("A")];
        let b = &entities[&EntityUID::with_eid("B")];
        let d = &entities[&EntityUID::with_eid("D")];
        // should have added the A -> C edge and the A -> E edge
        assert!(a.is_descendant_of(&EntityUID::with_eid("C")));
        assert!(a.is_descendant_of(&EntityUID::with_eid("E")));
        // but it shouldn't have added these other edges
        assert!(!b.is_descendant_of(&EntityUID::with_eid("D")));
        assert!(!b.is_descendant_of(&EntityUID::with_eid("E")));
        assert!(!d.is_descendant_of(&EntityUID::with_eid("B")));
        assert!(!d.is_descendant_of(&EntityUID::with_eid("C")));
        // now it should pass TC enforcement
        assert!(enforce_tc(&entities).is_ok());
        // passes cycle check after TC enforcement
        assert!(enforce_dag_from_tc(&entities).is_ok());
    }

    #[test]
    fn dag() {
        // start with this:
        //     B -> C
        //   /  \
        // A      D -> E -> H
        //   \        /
        //     F -> G
        let mut a = Entity::with_uid(EntityUID::with_eid("A"));
        a.add_indirect_ancestor(EntityUID::with_eid("B"));
        a.add_indirect_ancestor(EntityUID::with_eid("F"));
        let mut b = Entity::with_uid(EntityUID::with_eid("B"));
        b.add_indirect_ancestor(EntityUID::with_eid("C"));
        b.add_indirect_ancestor(EntityUID::with_eid("D"));
        let c = Entity::with_uid(EntityUID::with_eid("C"));
        let mut d = Entity::with_uid(EntityUID::with_eid("D"));
        d.add_indirect_ancestor(EntityUID::with_eid("E"));
        let mut e = Entity::with_uid(EntityUID::with_eid("E"));
        e.add_indirect_ancestor(EntityUID::with_eid("H"));
        let mut f = Entity::with_uid(EntityUID::with_eid("F"));
        f.add_indirect_ancestor(EntityUID::with_eid("G"));
        let mut g = Entity::with_uid(EntityUID::with_eid("G"));
        g.add_indirect_ancestor(EntityUID::with_eid("E"));
        let h = Entity::with_uid(EntityUID::with_eid("H"));
        let mut entities = HashMap::from([
            (a.uid().clone(), a),
            (b.uid().clone(), b),
            (c.uid().clone(), c),
            (d.uid().clone(), d),
            (e.uid().clone(), e),
            (f.uid().clone(), f),
            (g.uid().clone(), g),
            (h.uid().clone(), h),
        ]);
        // currently doesn't pass TC enforcement
        assert!(enforce_tc(&entities).is_err());
        // compute TC
        compute_tc(&mut entities, false).expect("Failed to compute transitive closure");
        let a = &entities[&EntityUID::with_eid("A")];
        let b = &entities[&EntityUID::with_eid("B")];
        let f = &entities[&EntityUID::with_eid("F")];
        // should have added many edges which we check for
        assert!(a.is_descendant_of(&EntityUID::with_eid("C")));
        assert!(a.is_descendant_of(&EntityUID::with_eid("D")));
        assert!(a.is_descendant_of(&EntityUID::with_eid("E")));
        assert!(a.is_descendant_of(&EntityUID::with_eid("F")));
        assert!(a.is_descendant_of(&EntityUID::with_eid("G")));
        assert!(a.is_descendant_of(&EntityUID::with_eid("H")));
        assert!(b.is_descendant_of(&EntityUID::with_eid("E")));
        assert!(b.is_descendant_of(&EntityUID::with_eid("H")));
        assert!(f.is_descendant_of(&EntityUID::with_eid("E")));
        assert!(f.is_descendant_of(&EntityUID::with_eid("H")));
        // but it shouldn't have added these other edges
        assert!(!b.is_descendant_of(&EntityUID::with_eid("F")));
        assert!(!b.is_descendant_of(&EntityUID::with_eid("G")));
        assert!(!f.is_descendant_of(&EntityUID::with_eid("C")));
        assert!(!f.is_descendant_of(&EntityUID::with_eid("D")));
        // now it should pass TC enforcement
        assert!(enforce_tc(&entities).is_ok());
        // passes cycle check after TC enforcement
        assert!(enforce_dag_from_tc(&entities).is_ok());
    }

    #[test]
    fn already_edges() {
        // start with this, which already includes some (but not all) transitive
        // edges
        //     B --> E
        //   /  \   /
        // A ---> C
        //   \   /
        //     D --> F
        let mut a = Entity::with_uid(EntityUID::with_eid("A"));
        a.add_indirect_ancestor(EntityUID::with_eid("B"));
        a.add_indirect_ancestor(EntityUID::with_eid("C"));
        a.add_indirect_ancestor(EntityUID::with_eid("D"));
        let mut b = Entity::with_uid(EntityUID::with_eid("B"));
        b.add_indirect_ancestor(EntityUID::with_eid("C"));
        b.add_indirect_ancestor(EntityUID::with_eid("E"));
        let mut c = Entity::with_uid(EntityUID::with_eid("C"));
        c.add_indirect_ancestor(EntityUID::with_eid("E"));
        let mut d = Entity::with_uid(EntityUID::with_eid("D"));
        d.add_indirect_ancestor(EntityUID::with_eid("C"));
        d.add_indirect_ancestor(EntityUID::with_eid("F"));
        let e = Entity::with_uid(EntityUID::with_eid("E"));
        let f = Entity::with_uid(EntityUID::with_eid("F"));
        let mut entities = HashMap::from([
            (a.uid().clone(), a),
            (b.uid().clone(), b),
            (c.uid().clone(), c),
            (d.uid().clone(), d),
            (e.uid().clone(), e),
            (f.uid().clone(), f),
        ]);
        // currently doesn't pass TC enforcement
        assert!(enforce_tc(&entities).is_err());
        // compute TC
        compute_tc(&mut entities, false).expect("Failed to compute transitive closure");
        let a = &entities[&EntityUID::with_eid("A")];
        let b = &entities[&EntityUID::with_eid("B")];
        let c = &entities[&EntityUID::with_eid("C")];
        let d = &entities[&EntityUID::with_eid("D")];
        // should have added many edges which we check for
        assert!(a.is_descendant_of(&EntityUID::with_eid("E")));
        assert!(a.is_descendant_of(&EntityUID::with_eid("F")));
        assert!(d.is_descendant_of(&EntityUID::with_eid("E")));
        // but it shouldn't have added these other edges
        assert!(!b.is_descendant_of(&EntityUID::with_eid("F")));
        assert!(!c.is_descendant_of(&EntityUID::with_eid("F")));
        // now it should pass TC enforcement
        assert!(enforce_tc(&entities).is_ok());
        // passes cycle check after TC enforcement
        assert!(enforce_dag_from_tc(&entities).is_ok());
    }

    #[test]
    fn disjoint_dag() {
        // graph with disconnected components:
        //     B -> C
        //
        // A      D -> E -> H
        //   \
        //     F -> G
        let mut a = Entity::with_uid(EntityUID::with_eid("A"));
        a.add_indirect_ancestor(EntityUID::with_eid("F"));
        let mut b = Entity::with_uid(EntityUID::with_eid("B"));
        b.add_indirect_ancestor(EntityUID::with_eid("C"));
        let c = Entity::with_uid(EntityUID::with_eid("C"));
        let mut d = Entity::with_uid(EntityUID::with_eid("D"));
        d.add_indirect_ancestor(EntityUID::with_eid("E"));
        let mut e = Entity::with_uid(EntityUID::with_eid("E"));
        e.add_indirect_ancestor(EntityUID::with_eid("H"));
        let mut f = Entity::with_uid(EntityUID::with_eid("F"));
        f.add_indirect_ancestor(EntityUID::with_eid("G"));
        let g = Entity::with_uid(EntityUID::with_eid("G"));
        let h = Entity::with_uid(EntityUID::with_eid("H"));
        let mut entities = HashMap::from([
            (a.uid().clone(), a),
            (b.uid().clone(), b),
            (c.uid().clone(), c),
            (d.uid().clone(), d),
            (e.uid().clone(), e),
            (f.uid().clone(), f),
            (g.uid().clone(), g),
            (h.uid().clone(), h),
        ]);
        // currently doesn't pass TC enforcement
        assert!(enforce_tc(&entities).is_err());
        // compute TC
        compute_tc(&mut entities, false).expect("Failed to compute transitive closure");
        let a = &entities[&EntityUID::with_eid("A")];
        let b = &entities[&EntityUID::with_eid("B")];
        let d = &entities[&EntityUID::with_eid("D")];
        let f = &entities[&EntityUID::with_eid("F")];
        // should have added two edges
        assert!(a.is_descendant_of(&EntityUID::with_eid("G")));
        assert!(d.is_descendant_of(&EntityUID::with_eid("H")));
        // but it shouldn't have added these other edges
        assert!(!a.is_descendant_of(&EntityUID::with_eid("C")));
        assert!(!a.is_descendant_of(&EntityUID::with_eid("D")));
        assert!(!a.is_descendant_of(&EntityUID::with_eid("E")));
        assert!(!a.is_descendant_of(&EntityUID::with_eid("H")));
        assert!(!b.is_descendant_of(&EntityUID::with_eid("E")));
        assert!(!b.is_descendant_of(&EntityUID::with_eid("H")));
        assert!(!f.is_descendant_of(&EntityUID::with_eid("E")));
        assert!(!f.is_descendant_of(&EntityUID::with_eid("H")));
        assert!(!b.is_descendant_of(&EntityUID::with_eid("F")));
        assert!(!b.is_descendant_of(&EntityUID::with_eid("G")));
        assert!(!f.is_descendant_of(&EntityUID::with_eid("C")));
        assert!(!f.is_descendant_of(&EntityUID::with_eid("D")));
        // now it should pass TC enforcement
        assert!(enforce_tc(&entities).is_ok());
        // passes cycle check after TC enforcement
        assert!(enforce_dag_from_tc(&entities).is_ok());
    }

    #[test]
    fn trivial_cycle() {
        // this graph is invalid, but we want to still have some reasonable behavior
        // if we encounter it (and definitely not panic, infinitely recurse, etc)
        //
        // A -> B -> B
        let mut a = Entity::with_uid(EntityUID::with_eid("A"));
        a.add_indirect_ancestor(EntityUID::with_eid("B"));
        let mut b = Entity::with_uid(EntityUID::with_eid("B"));
        b.add_indirect_ancestor(EntityUID::with_eid("B"));
        let mut entities = HashMap::from([(a.uid().clone(), a), (b.uid().clone(), b)]);
        // computing TC should succeed without panicking, infinitely recursing, etc
        compute_tc(&mut entities, false).expect("Failed to compute transitive closure");
        // fails cycle check
        match enforce_dag_from_tc(&entities) {
            Ok(_) => panic!("enforce_dag_from_tc should have returned an error"),
            Err(TcError::HasCycle(err)) => {
                assert!(err.vertex_with_loop() == &EntityUID::with_eid("B"));
            }
            Err(_) => panic!("Unexpected error in enforce_dag_from_tc"),
        }
        let a = &entities[&EntityUID::with_eid("A")];
        let b = &entities[&EntityUID::with_eid("B")];
        // we check that the A -> B edge still exists
        assert!(a.is_descendant_of(&EntityUID::with_eid("B")));
        // but it shouldn't have added a B -> A edge
        assert!(!b.is_descendant_of(&EntityUID::with_eid("A")));
        // we also check that, whatever compute_tc did with this invalid input, the
        // final result still passes enforce_tc
        assert!(enforce_tc(&entities).is_ok());
        // still fails cycle check
        match enforce_dag_from_tc(&entities) {
            Ok(_) => panic!("enforce_dag_from_tc should have returned an error"),
            Err(TcError::HasCycle(err)) => {
                assert!(err.vertex_with_loop() == &EntityUID::with_eid("B"));
            }
            Err(_) => panic!("Unexpected error in enforce_dag_from_tc"),
        }
    }

    #[test]
    fn nontrivial_cycle() {
        // this graph is invalid, but we want to still have some reasonable behavior
        // if we encounter it (and definitely not panic, infinitely recurse, etc)
        //
        //          D
        //        /
        // A -> B -> C -> A
        let mut a = Entity::with_uid(EntityUID::with_eid("A"));
        a.add_indirect_ancestor(EntityUID::with_eid("B"));
        let mut b = Entity::with_uid(EntityUID::with_eid("B"));
        b.add_indirect_ancestor(EntityUID::with_eid("C"));
        b.add_indirect_ancestor(EntityUID::with_eid("D"));
        let mut c = Entity::with_uid(EntityUID::with_eid("C"));
        c.add_indirect_ancestor(EntityUID::with_eid("A"));
        let d = Entity::with_uid(EntityUID::with_eid("D"));
        let mut entities = HashMap::from([
            (a.uid().clone(), a),
            (b.uid().clone(), b),
            (c.uid().clone(), c),
            (d.uid().clone(), d),
        ]);
        // computing TC should succeed without panicking, infinitely recursing, etc
        compute_tc_internal(
            entities
                .keys()
                .map(EntityUID::clone)
                .collect::<Vec<EntityUID>>()
                .into_iter(),
            &mut entities,
            HashSet::new(),
            true,
        );
        // fails cycle check
        match enforce_dag_from_tc(&entities) {
            Ok(_) => panic!("enforce_dag_from_tc should have returned an error"),
            Err(TcError::HasCycle(err)) => {
                assert!(
                    err.vertex_with_loop() == &EntityUID::with_eid("A")
                        || err.vertex_with_loop() == &EntityUID::with_eid("B")
                        || err.vertex_with_loop() == &EntityUID::with_eid("C")
                );
            }
            Err(_) => panic!("Unexpected error in enforce_dag_from_tc"),
        }
        //TC tests
        let a = &entities[&EntityUID::with_eid("A")];
        let b = &entities[&EntityUID::with_eid("B")];
        // we should have added A -> C and A -> D edges, at least
        assert!(a.is_descendant_of(&EntityUID::with_eid("C")));
        assert!(a.is_descendant_of(&EntityUID::with_eid("D")));
        // and we should also have added a B -> A edge
        assert!(b.is_descendant_of(&EntityUID::with_eid("A")));
        // we also check that, whatever compute_tc did with this invalid input, the
        // final result still passes enforce_tc
        assert!(enforce_tc(&entities).is_ok());
        // still fails cycle check
        match enforce_dag_from_tc(&entities) {
            Ok(_) => panic!("enforce_dag_from_tc should have returned an error"),
            Err(TcError::HasCycle(err)) => {
                assert!(
                    err.vertex_with_loop() == &EntityUID::with_eid("A")
                        || err.vertex_with_loop() == &EntityUID::with_eid("B")
                        || err.vertex_with_loop() == &EntityUID::with_eid("C")
                );
            }
            Err(_) => panic!("Unexpected error in enforce_dag_from_tc"),
        }
    }

    #[test]
    fn disjoint_cycles() {
        // graph with disconnected components including cycles:
        //     B -> C -> B
        //
        // A      D -> E -> H -> D
        //   \
        //     F -> G
        let mut a = Entity::with_uid(EntityUID::with_eid("A"));
        a.add_indirect_ancestor(EntityUID::with_eid("F"));
        let mut b = Entity::with_uid(EntityUID::with_eid("B"));
        b.add_indirect_ancestor(EntityUID::with_eid("C"));
        let mut c = Entity::with_uid(EntityUID::with_eid("C"));
        c.add_indirect_ancestor(EntityUID::with_eid("B"));
        let mut d = Entity::with_uid(EntityUID::with_eid("D"));
        d.add_indirect_ancestor(EntityUID::with_eid("E"));
        let mut e = Entity::with_uid(EntityUID::with_eid("E"));
        e.add_indirect_ancestor(EntityUID::with_eid("H"));
        let mut f = Entity::with_uid(EntityUID::with_eid("F"));
        f.add_indirect_ancestor(EntityUID::with_eid("G"));
        let g = Entity::with_uid(EntityUID::with_eid("G"));
        let mut h = Entity::with_uid(EntityUID::with_eid("H"));
        h.add_indirect_ancestor(EntityUID::with_eid("D"));
        let mut entities = HashMap::from([
            (a.uid().clone(), a),
            (b.uid().clone(), b),
            (c.uid().clone(), c),
            (d.uid().clone(), d),
            (e.uid().clone(), e),
            (f.uid().clone(), f),
            (g.uid().clone(), g),
            (h.uid().clone(), h),
        ]);
        // currently doesn't pass TC enforcement
        assert!(enforce_tc(&entities).is_err());
        // compute TC
        compute_tc_internal(
            entities
                .keys()
                .map(EntityUID::clone)
                .collect::<Vec<EntityUID>>()
                .into_iter(),
            &mut entities,
            HashSet::new(),
            true,
        );
        // now it should pass TC enforcement
        assert!(enforce_tc(&entities).is_ok());
        // still fails cycle check
        match enforce_dag_from_tc(&entities) {
            Ok(_) => panic!("enforce_dag_from_tc should have returned an error"),
            Err(TcError::HasCycle(err)) => {
                // two possible cycles
                assert!(
                    err.vertex_with_loop() == &EntityUID::with_eid("B")
                        || err.vertex_with_loop() == &EntityUID::with_eid("C")
                        || err.vertex_with_loop() == &EntityUID::with_eid("D")
                        || err.vertex_with_loop() == &EntityUID::with_eid("E")
                        || err.vertex_with_loop() == &EntityUID::with_eid("H")
                );
            }
            Err(_) => panic!("Unexpected error in enforce_dag_from_tc"),
        }
    }

    #[test]
    fn intersecting_cycles() {
        // graph with two intersecting cycles:
        //  A -> B -> C -> E -
        //  ^    ^         ^  |
        //  |    |         |  |
        //  |    |        /   |
        //   \  /        /    |
        //    D ------>F      |
        //    ^               |
        //    |___------------
        let mut a = Entity::with_uid(EntityUID::with_eid("A"));
        a.add_indirect_ancestor(EntityUID::with_eid("B"));
        let mut b = Entity::with_uid(EntityUID::with_eid("B"));
        b.add_indirect_ancestor(EntityUID::with_eid("C"));
        let mut c = Entity::with_uid(EntityUID::with_eid("C"));
        c.add_indirect_ancestor(EntityUID::with_eid("E"));
        let mut d = Entity::with_uid(EntityUID::with_eid("D"));
        d.add_indirect_ancestor(EntityUID::with_eid("A"));
        d.add_indirect_ancestor(EntityUID::with_eid("B"));
        d.add_indirect_ancestor(EntityUID::with_eid("F"));
        let mut e = Entity::with_uid(EntityUID::with_eid("E"));
        e.add_indirect_ancestor(EntityUID::with_eid("D"));
        let mut f = Entity::with_uid(EntityUID::with_eid("F"));
        f.add_indirect_ancestor(EntityUID::with_eid("E"));
        let mut entities = HashMap::from([
            (a.uid().clone(), a),
            (b.uid().clone(), b),
            (c.uid().clone(), c),
            (d.uid().clone(), d),
            (e.uid().clone(), e),
            (f.uid().clone(), f),
        ]);
        // fails TC enforcement
        assert!(enforce_tc(&entities).is_err());
        // compute TC
        cyclic_tc(&mut entities);
        // compute_tc_internal(
        //     entities
        //         .keys()
        //         .map(EntityUID::clone)
        //         .collect::<Vec<EntityUID>>()
        //         .into_iter(),
        //     &mut entities,
        //     HashSet::new(),
        //     true,
        // );
        assert!(enforce_tc(&entities).is_ok());
        // the graph may or may not pass the TC check but it will always fail cycle check
        match enforce_dag_from_tc(&entities) {
            Ok(_) => panic!("enforce_dag_from_tc should have returned an error"),
            Err(TcError::HasCycle(_)) => (), // Every vertex is in a cycle
            Err(_) => panic!("Unexpected error in enforce_dag_from_tc"),
        }
    }
}
