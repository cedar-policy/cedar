//! Cedar policy slicer

use crate::{
    ast::{EntityUID, EntityUIDEntry, Policy, PolicySet, Request},
    entities::{Dereference, Entities},
};

/// Cedar policy slicer
#[derive(Debug, Clone)]
pub struct Slicer<'s> {
    /// Entities in a request: (principal, resource)
    request_entities: (EntityUID, EntityUID),
    store: &'s Entities,
}

impl<'s> Slicer<'s> {
    /// Construct a slicer
    pub fn new(request: &Request, store: &'s Entities) -> Self {
        let request_entities = match (request.principal(), request.resource()) {
            (EntityUIDEntry::Concrete(principal), EntityUIDEntry::Concrete(resource)) => {
                (principal.as_ref().clone(), resource.as_ref().clone())
            }
            _ => unreachable!("partial evaluation is not enabled!"),
        };
        Self {
            request_entities,
            store,
        }
    }

    /// Get a slice of the policy set
    pub fn get_slice(&self, policy_set: &PolicySet) -> PolicySet {
        let mut slice = PolicySet::new();
        for policy in policy_set.policies() {
            if self.should_keep(policy) {
                slice
                    .add(policy.clone())
                    .expect("add policy should succeed");
            }
        }
        slice
    }

    fn entity_in_entity(&self, child: &EntityUID, ancestor: &EntityUID) -> bool {
        child == ancestor
            || match self.store.entity(child) {
                Dereference::Data(child_entity) => child_entity.is_descendant_of(ancestor),
                Dereference::NoSuchEntity => false,
                _ => unreachable!("partial evaluation is not enabled!"),
            }
    }

    fn should_keep(&self, policy: &Policy) -> bool {
        match (
            policy.principal_constraint().constraint.iter_euids().next(),
            policy.resource_constraint().constraint.iter_euids().next(),
        ) {
            (Some(head_principal), Some(head_resource)) => {
                self.entity_in_entity(&self.request_entities.0, head_principal)
                    && self.entity_in_entity(&self.request_entities.1, head_resource)
            }
            (Some(head_principal), None) => {
                self.entity_in_entity(&self.request_entities.0, head_principal)
            }
            (None, Some(head_resource)) => {
                self.entity_in_entity(&self.request_entities.1, head_resource)
            }
            (None, None) => true,
        }
    }
}
