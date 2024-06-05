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


use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use itertools::Itertools;

use crate::{
    ast::{EntityUID, EntityUIDEntry, PolicyID, PolicySet, Request},
    entities::{Dereference, Entities},
};

/// Simple policy slicer
#[derive(Debug, Clone)]
pub struct Slicer<'s, 'e> {
    // Entity store snapshot
    store: &'e Entities,
    // Input policy set
    policy_set: &'s PolicySet,
    // Policies indexed by (principal, resource) tuple
    indexed: HashMap<(Option<Arc<EntityUID>>, Option<Arc<EntityUID>>), HashSet<&'s PolicyID>>,
}

impl<'s, 'e> Slicer<'s, 'e> {
    /// Construct a slicer
    pub fn new(policy_set: &'s PolicySet, store: &'e Entities) -> Self {
        let mut indexed: HashMap<
            (Option<Arc<EntityUID>>, Option<Arc<EntityUID>>),
            HashSet<&'s PolicyID>,
        > = HashMap::new();
        // Construct policy indices
        for policy in policy_set.policies() {
            let key = (
                policy
                    .principal_constraint()
                    .constraint
                    .iter_euids()
                    .next()
                    .map(|e| Arc::new(e.clone())),
                policy
                    .resource_constraint()
                    .constraint
                    .iter_euids()
                    .next()
                    .map(|e| Arc::new(e.clone())),
            );
            if let Some(set) = indexed.get_mut(&key) {
                set.insert(policy.id());
            } else {
                indexed.insert(key, HashSet::from_iter(std::iter::once(policy.id())));
            }
        }
        Self {
            policy_set,
            store,
            indexed,
        }
    }

    fn make_keys(
        &self,
        principal: Arc<EntityUID>,
        resource: Arc<EntityUID>,
    ) -> impl Iterator<Item = (Option<Arc<EntityUID>>, Option<Arc<EntityUID>>)> {
        let make_iter = |uid: Arc<EntityUID>| {
            std::iter::once(Some(uid.clone()))
                .chain(std::iter::once(None))
                .chain(match self.store.entity(&uid) {
                    Dereference::Data(e) => e
                        .ancestors()
                        .map(|uid| Some(Arc::new(uid.clone())))
                        .collect_vec(),
                    Dereference::Residual(_) => unreachable!("partial evaluation is not enabled!"),
                    Dereference::NoSuchEntity => vec![],
                })
        };
        make_iter(principal).cartesian_product(make_iter(resource))
    }

    /// Get a slice of the policy set
    pub fn get_slice(&self, request: &Request) -> PolicySet {
        let (req_principal, req_resource) = match (request.principal(), request.resource()) {
            (
                EntityUIDEntry::Known {
                    euid: principal, ..
                },
                EntityUIDEntry::Known { euid: resource, .. },
            ) => (principal.clone(), resource.clone()),
            _ => unreachable!("partial evaluation is not enabled!"),
        };
        let keys = self.make_keys(req_principal, req_resource);
        let mut slice = PolicySet::new();
        for key in keys {
            if let Some(set) = self.indexed.get(&key) {
                for id in set {
                    slice
                        .add(self.policy_set.get(id).expect("id should exist").clone())
                        .expect("should not fail");
                }
            }
        }
        slice
    }
}
