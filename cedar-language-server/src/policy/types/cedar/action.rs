use std::hash::Hash;
use std::{collections::BTreeSet, sync::Arc};

use cedar_policy_core::ast::{Eid, EntityType, EntityUID};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum ActionKind {
    AnyAction,
    Action(Arc<ActionEntity>),
    Actions(BTreeSet<ActionEntity>),
}

impl ActionEntity {
    #[must_use]
    pub(crate) fn new(euid: Arc<EntityUID>) -> Self {
        Self { euid }
    }

    #[must_use]
    pub(crate) fn from_entity_type(entity_type: EntityType) -> Self {
        let id = Eid::new("dummy");
        let euid = EntityUID::from_components(entity_type, id, None).into();
        Self { euid }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActionEntity {
    euid: Arc<EntityUID>,
}

impl PartialOrd for ActionEntity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ActionEntity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.euid.cmp(&other.euid)
    }
}

impl Hash for ActionEntity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.euid.hash(state);
    }
}
