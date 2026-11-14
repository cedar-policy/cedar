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

//! An index of the linked policies of a policy set by action, and the map of
//! linked policies that owns it.

use crate::ast::{
    ActionConstraint, Entity, EntityUID, Policy, PolicyID, PrincipalOrResourceConstraint, SlotEnv,
    SlotId,
};
use itertools::Itertools;
use linked_hash_map::LinkedHashMap;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, OnceLock};

/// The linked policies of a policy set, with an [`ActionIndex`] of them that
/// is built on first use.
///
/// The map is read through `Deref` and written only through
/// [`IndexedLinks::get_mut`], which discards the index. So the index is
/// either absent or describes the current policies. A clone shares the index
/// until either copy is written.
#[derive(Clone, Default)]
pub(super) struct IndexedLinks {
    links: LinkedHashMap<PolicyID, Policy>,
    index: OnceLock<Arc<ActionIndex>>,
}

// The index is derived from the map, so only the map is compared.
impl PartialEq for IndexedLinks {
    fn eq(&self, other: &Self) -> bool {
        self.links == other.links
    }
}

impl Eq for IndexedLinks {}

impl IndexedLinks {
    /// The policies, for writing. Discards the index.
    pub(super) fn get_mut(&mut self) -> &mut LinkedHashMap<PolicyID, Policy> {
        self.index = OnceLock::new();
        &mut self.links
    }

    /// The policies, by value.
    pub(super) fn into_inner(self) -> LinkedHashMap<PolicyID, Policy> {
        self.links
    }

    /// The index of the policies by action.
    pub(super) fn action_index(&self) -> &ActionIndex {
        self.index
            .get_or_init(|| Arc::new(ActionIndex::new(self.links.values())))
    }
}

impl Deref for IndexedLinks {
    type Target = LinkedHashMap<PolicyID, Policy>;

    fn deref(&self) -> &Self::Target {
        &self.links
    }
}

impl From<LinkedHashMap<PolicyID, Policy>> for IndexedLinks {
    fn from(links: LinkedHashMap<PolicyID, Policy>) -> Self {
        Self {
            links,
            index: OnceLock::new(),
        }
    }
}

impl FromIterator<(PolicyID, Policy)> for IndexedLinks {
    fn from_iter<T: IntoIterator<Item = (PolicyID, Policy)>>(iter: T) -> Self {
        LinkedHashMap::from_iter(iter).into()
    }
}

// The index is derived from the map, so only the map is printed.
impl std::fmt::Debug for IndexedLinks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.links.fmt(f)
    }
}

/// The policies of a policy set, indexed by the action UIDs that their action
/// scope constraints name.
///
/// A policy's condition evaluates its principal scope constraint, then its
/// action scope constraint, then the rest. So a policy evaluates to `false`
/// if its action scope constraint is `false` and its principal scope
/// constraint is a boolean. [`ActionIndex::candidates`] yields every other
/// policy.
#[derive(Debug)]
pub(crate) struct ActionIndex {
    /// The policies, in the order of the map they are indexed from. These are
    /// clones, because an index that is stored next to that map cannot borrow
    /// from it.
    policies: Vec<Policy>,
    /// For each `uid`, the positions in `policies` of the policies with the
    /// scope constraint `action == uid`, ascending
    eq: HashMap<Arc<EntityUID>, Vec<usize>>,
    /// For each `uid`, the positions in `policies` of the policies with a
    /// scope constraint `action in [.., uid, ..]`, ascending
    within: HashMap<Arc<EntityUID>, Vec<usize>>,
    /// Positions in `policies` of the policies that are candidates for every
    /// action, ascending
    unindexed: Vec<usize>,
}

impl ActionIndex {
    fn new<'a>(policies: impl Iterator<Item = &'a Policy>) -> Self {
        let policies: Vec<Policy> = policies.cloned().collect();
        let mut eq: HashMap<Arc<EntityUID>, Vec<usize>> = HashMap::new();
        let mut within: HashMap<Arc<EntityUID>, Vec<usize>> = HashMap::new();
        let mut unindexed = Vec::new();
        for (pos, p) in policies.iter().enumerate() {
            let principal = p.template().principal_constraint().as_inner();
            if !principal_scope_is_boolean(principal, p.env()) {
                unindexed.push(pos);
                continue;
            }
            match p.action_constraint() {
                ActionConstraint::Eq(uid) => eq.entry(Arc::clone(uid)).or_default().push(pos),
                // `action in []` is `false`, so such a policy is a candidate
                // for no action
                ActionConstraint::In(uids) => {
                    for uid in uids {
                        let positions = within.entry(Arc::clone(uid)).or_default();
                        if positions.last() != Some(&pos) {
                            positions.push(pos);
                        }
                    }
                }
                ActionConstraint::Any => unindexed.push(pos),
                #[cfg(feature = "tolerant-ast")]
                ActionConstraint::ErrorConstraint => unindexed.push(pos),
            }
        }
        Self {
            policies,
            eq,
            within,
            unindexed,
        }
    }

    /// The policies that can be satisfied or can error for a request with
    /// this `action`, in the order they are indexed in. `action_entity` is
    /// the entity of `action`, if the entity store has one.
    ///
    /// The request's principal and action must be concrete, and the entity
    /// store must resolve both, to an entity or to the absence of one. A
    /// partial store that lacks one of them does not: `in` on it is a
    /// residual, not a boolean.
    #[expect(
        clippy::indexing_slicing,
        reason = "every position in the index is a position in `policies`"
    )]
    pub(crate) fn candidates(
        &self,
        action: &EntityUID,
        action_entity: Option<&Entity>,
    ) -> impl Iterator<Item = &Policy> {
        // `action in [.., uid, ..]` holds if `uid` is the action or one of
        // its ancestors
        let ancestors = action_entity.into_iter().flat_map(Entity::ancestors);
        let within = std::iter::once(action)
            .chain(ancestors)
            .filter_map(|uid| self.within.get(uid));
        // Each list is ascending, so merging them keeps the order of
        // `policies`. The positions are merged without copying or sorting
        // the lists; `kmerge` allocates one small heap of list heads. A
        // policy that names several ancestors of the action is in several
        // lists.
        std::iter::once(&self.unindexed)
            .chain(self.eq.get(action))
            .chain(within)
            .map(|positions| positions.iter().copied())
            .kmerge()
            .dedup()
            .map(|pos| &self.policies[pos])
    }
}

/// Does this principal scope constraint evaluate to a boolean for every
/// request that meets the precondition of [`ActionIndex::candidates`]?
///
/// `env` is the slot environment of the policy. The one constraint that does
/// not is a slot that `env` does not bind, which is an evaluation error. A
/// policy with such a constraint errors whatever its action constraint, so it
/// cannot be indexed by action.
fn principal_scope_is_boolean(constraint: &PrincipalOrResourceConstraint, env: &SlotEnv) -> bool {
    match constraint {
        PrincipalOrResourceConstraint::Any | PrincipalOrResourceConstraint::Is(_) => true,
        PrincipalOrResourceConstraint::Eq(reference)
        | PrincipalOrResourceConstraint::In(reference)
        | PrincipalOrResourceConstraint::IsIn(_, reference) => {
            reference.resolve(SlotId::principal(), env).is_some()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ast::EntityType;

    #[test]
    fn principal_scope_with_unbound_slot_is_not_boolean() {
        let alice = Arc::new(EntityUID::with_eid_and_type("User", "alice").expect("valid type"));
        let user: Arc<EntityType> = Arc::new("User".parse().expect("valid entity type"));
        let unbound = SlotEnv::new();
        let bound = SlotEnv::from([(SlotId::principal(), alice.as_ref().clone())]);
        // a binding for the resource slot does not help
        let resource_only = SlotEnv::from([(SlotId::resource(), alice.as_ref().clone())]);

        let without_slot = [
            PrincipalOrResourceConstraint::any(),
            PrincipalOrResourceConstraint::is_eq(Arc::clone(&alice)),
            PrincipalOrResourceConstraint::is_in(Arc::clone(&alice)),
            PrincipalOrResourceConstraint::is_entity_type(Arc::clone(&user)),
            PrincipalOrResourceConstraint::is_entity_type_in(Arc::clone(&user), alice),
        ];
        for constraint in &without_slot {
            assert!(
                principal_scope_is_boolean(constraint, &unbound),
                "{constraint:?}"
            );
        }

        let with_slot = [
            PrincipalOrResourceConstraint::is_eq_slot(),
            PrincipalOrResourceConstraint::is_in_slot(),
            PrincipalOrResourceConstraint::is_entity_type_in_slot(user),
        ];
        for constraint in &with_slot {
            assert!(
                principal_scope_is_boolean(constraint, &bound),
                "{constraint:?}"
            );
            assert!(
                !principal_scope_is_boolean(constraint, &unbound),
                "{constraint:?}"
            );
            assert!(
                !principal_scope_is_boolean(constraint, &resource_only),
                "{constraint:?}"
            );
        }
    }
}
