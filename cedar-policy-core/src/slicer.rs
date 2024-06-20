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

//! This module contains a simple policy slicer.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use itertools::Itertools;

use crate::{
    ast::{Entity, EntityUID, EntityUIDEntry, PolicyID, PolicySet, Request},
    entities::{Dereference, Entities},
};

/// Key type to index policies
pub type IndexKey = (Option<Arc<EntityUID>>, Option<Arc<EntityUID>>);

/// Simple policy slicer
#[derive(Debug)]
pub struct Slicer<'s, 'e> {
    // Entity store snapshot
    store: &'e Entities,
    // Input policy set
    policy_set: &'s PolicySet,
    // Policies indexed by (principal, resource) tuple
    // An unconstrained variable is indexed by `None`
    indexed: HashMap<IndexKey, HashSet<&'s PolicyID>>,
}

impl<'s, 'e> Slicer<'s, 'e> {
    /// Construct a slicer
    pub fn new(policy_set: &'s PolicySet, store: &'e Entities) -> Self {
        let mut indexed: HashMap<IndexKey, HashSet<&'s PolicyID>> = HashMap::new();
        // Construct policy indices
        for policy in policy_set.policies() {
            let key = (
                policy.principal_constraint().constraint.get_euid().cloned(),
                policy.resource_constraint().constraint.get_euid().cloned(),
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

    // Make index keys based on principal and resource `EntityUID`s
    // Return `None` if either of them refers to a residual
    // Otherwise return a cross-product of reachable entity UIDs plus `None`
    // because a concrete entity satisfies corresponding unconstrained var
    fn make_keys(
        &self,
        principal: Arc<EntityUID>,
        resource: Arc<EntityUID>,
    ) -> Option<impl Iterator<Item = IndexKey>> {
        let make_iter = |e: &Entity| {
            vec![Some(Arc::new(e.uid().clone()))]
                .into_iter()
                .chain(std::iter::once(None))
                .chain(e.ancestors().map(|uid| Some(Arc::new(uid.clone()))))
                .collect::<Vec<_>>()
                .into_iter()
        };
        match (self.store.entity(&principal), self.store.entity(&resource)) {
            (Dereference::Data(principal), Dereference::Data(resource)) => {
                Some(make_iter(principal).cartesian_product(make_iter(resource)))
            }
            (Dereference::Residual(_), _) => None,
            (_, Dereference::Residual(_)) => None,
            // Missing entities should index unconstrained vars
            (Dereference::NoSuchEntity, Dereference::Data(resource)) => Some(
                vec![None, Some(principal)]
                    .into_iter()
                    .cartesian_product(make_iter(resource)),
            ),
            (Dereference::Data(principal), Dereference::NoSuchEntity) => {
                Some(make_iter(principal).cartesian_product(vec![None, Some(resource)]))
            }
            (Dereference::NoSuchEntity, Dereference::NoSuchEntity) => Some(
                vec![None, Some(principal)]
                    .into_iter()
                    .cartesian_product(vec![None, Some(resource)]),
            ),
        }
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
            // Do not perform slicing when one of principal or resource is unknown
            _ => {
                return self.policy_set.to_owned();
            }
        };

        if let Some(keys) = self.make_keys(req_principal, req_resource) {
            let policy_ids: HashSet<&PolicyID> = keys
                .flat_map(|key| self.indexed.get(&key).cloned().unwrap_or_default())
                .collect();

            //PANIC SAFETY: a slice should be constructible from a subset of the policy set
            #[allow(clippy::unwrap_used)]
            PolicySet::try_from_iter(
                self.policy_set
                    .policies()
                    .filter(|p| policy_ids.contains(p.id()))
                    .cloned(),
            )
            .unwrap()
        } else {
            self.policy_set.to_owned()
        }
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashSet, sync::Arc};

    use smol_str::SmolStr;

    use crate::{
        ast::{AnyId, Context, Entity, EntityUID, PolicySet, Request},
        entities::{Entities, NoEntitiesSchema},
        extensions::Extensions,
        parser::parse_policyset,
    };

    use super::Slicer;

    fn get_policy_set() -> PolicySet {
        parse_policyset(
            r#"
        @id("unconstrained")
        permit(principal, action, resource);
        @id("1")
        permit(principal == P::"a", action, resource);
        @id("2")
        permit(principal, action, resource == R::"b");
        @id("3")
        permit(principal in P::"c", action, resource);
        @id("4")
        permit(principal, action, resource in R::"d");
        @id("5")
        permit(principal in P::"c", action, resource in R::"d");
        @id("6")
        permit(principal == P::"a", action, resource in R::"d");
        @id("7")
        permit(principal in P::"e", action, resource in R::"d");
        "#,
        )
        .expect("Policy set should parse")
    }

    fn get_ids(ps: &PolicySet) -> HashSet<SmolStr> {
        HashSet::from_iter(ps.policies().map(|p| {
            p.annotation(&AnyId::new_unchecked("id"))
                .unwrap()
                .val
                .to_owned()
        }))
    }

    fn get_entity_store() -> Entities {
        let mut a = Entity::with_uid(EntityUID::with_eid_and_type("P", "a").unwrap());
        let mut b = Entity::with_uid(EntityUID::with_eid_and_type("R", "b").unwrap());
        let mut c = Entity::with_uid(EntityUID::with_eid_and_type("P", "c").unwrap());
        let d = Entity::with_uid(EntityUID::with_eid_and_type("R", "d").unwrap());
        let e = Entity::with_uid(EntityUID::with_eid_and_type("P", "e").unwrap());
        a.add_ancestor(c.uid().clone());
        b.add_ancestor(d.uid().clone());
        c.add_ancestor(e.uid().clone());
        Entities::from_entities(
            [a, b, c, d, e],
            None::<&NoEntitiesSchema>,
            crate::entities::TCComputation::ComputeNow,
            Extensions::all_available(),
        )
        .unwrap()
    }

    fn create_req(p: &str, r: &str) -> Request {
        Request::new_unchecked(
            crate::ast::EntityUIDEntry::Known {
                euid: Arc::new(format!(r#"P::"{p}""#).parse().unwrap()),
                loc: None,
            },
            crate::ast::EntityUIDEntry::Unknown { loc: None },
            crate::ast::EntityUIDEntry::Known {
                euid: Arc::new(format!(r#"R::"{r}""#).parse().unwrap()),
                loc: None,
            },
            Some(Context::empty()),
        )
    }

    #[test]
    fn test_top() {
        let ps = get_policy_set();
        let es = get_entity_store();
        let slicer = Slicer::new(&ps, &es);
        let req = create_req("e", "d");
        assert_eq!(
            get_ids(&slicer.get_slice(&req)),
            HashSet::from_iter(["7".into(), "4".into(), "unconstrained".into()])
        );
        let req = create_req("e", "f");
        assert_eq!(
            get_ids(&slicer.get_slice(&req)),
            HashSet::from_iter(["unconstrained".into()])
        );
    }

    #[test]
    fn test_bottom() {
        let ps = get_policy_set();
        let es = get_entity_store();
        let slicer = Slicer::new(&ps, &es);
        let req = create_req("a", "b");
        assert_eq!(
            get_ids(&slicer.get_slice(&req)),
            HashSet::from_iter([
                "1".into(),
                "2".into(),
                "3".into(),
                "4".into(),
                "5".into(),
                "6".into(),
                "7".into(),
                "unconstrained".into()
            ])
        );
        let req = create_req("a", "d");
        assert_eq!(
            get_ids(&slicer.get_slice(&req)),
            HashSet::from_iter([
                "1".into(),
                "3".into(),
                "4".into(),
                "5".into(),
                "6".into(),
                "7".into(),
                "unconstrained".into()
            ])
        );
        let req = create_req("e", "b");
        assert_eq!(
            get_ids(&slicer.get_slice(&req)),
            HashSet::from_iter(["2".into(), "4".into(), "7".into(), "unconstrained".into()])
        );
    }

    #[test]
    fn test_middle() {
        let ps = get_policy_set();
        let es = get_entity_store();
        let slicer = Slicer::new(&ps, &es);
        let req = create_req("c", "d");
        assert_eq!(
            get_ids(&slicer.get_slice(&req)),
            HashSet::from_iter([
                "3".into(),
                "4".into(),
                "5".into(),
                "7".into(),
                "unconstrained".into()
            ])
        );
    }
}
