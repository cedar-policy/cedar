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

use std::collections::{HashMap, HashSet};

use itertools::Itertools;

use crate::{
    ast::{Eid, EntityUID, EntityUIDEntry, PolicyID, PolicySet, Request},
    entities::{Dereference, Entities},
};

/// Cedar policy slicer
#[derive(Debug, Clone)]
pub struct Slicer<'s, 'e> {
    store: &'e Entities,
    policy_set: &'s PolicySet,
    indexed: HashMap<(EntityUID, EntityUID), HashSet<&'s PolicyID>>,
}

impl<'s, 'e> Slicer<'s, 'e> {
    fn any() -> EntityUID {
        EntityUID::unspecified_from_eid(Eid::new(""))
    }
    /// Construct a slicer
    pub fn new(policy_set: &'s PolicySet, store: &'e Entities) -> Self {
        let mut indexed: HashMap<(EntityUID, EntityUID), HashSet<&'s PolicyID>> = HashMap::new();
        for policy in policy_set.policies() {
            let key = match (
                policy.principal_constraint().constraint.iter_euids().next(),
                policy.resource_constraint().constraint.iter_euids().next(),
            ) {
                (Some(head_principal), Some(head_resource)) => {
                    (head_principal.clone(), head_resource.clone())
                }
                (Some(head_principal), None) => (head_principal.clone(), Self::any()),
                (None, Some(head_resource)) => (Self::any(), head_resource.clone()),
                (None, None) => (Self::any(), Self::any()),
            };
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
        principal: &EntityUID,
        resource: &EntityUID,
    ) -> impl Iterator<Item = (EntityUID, EntityUID)> {
        let make_iter = |uid: &EntityUID| {
            std::iter::once(uid.clone())
                .chain(std::iter::once(Self::any()))
                .chain(match self.store.entity(uid) {
                    Dereference::Data(e) => e.ancestors().map(|uid| uid.clone()).collect_vec(),
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
            ) => (principal.as_ref(), resource.as_ref()),
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
