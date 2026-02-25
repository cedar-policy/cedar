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

//! Scope constraint types for PST

use super::expr::{EntityType, EntityUID, SlotId};

/// Entity UID or template slot
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EntityOrSlot {
    /// A concrete entity UID
    Entity(EntityUID),
    /// A template slot
    Slot(SlotId),
}

/// Principal scope constraint
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalConstraint {
    /// Any principal
    Any,
    /// Equals specific entity or slot
    Eq(EntityOrSlot),
    /// In hierarchy of entity or slot
    In(EntityOrSlot),
    /// Is of specific type
    Is(EntityType),
    /// Is of specific type and in hierarchy
    IsIn(EntityType, EntityOrSlot),
}

/// Resource scope constraint (same shape as Principal)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceConstraint {
    /// Any resource
    Any,
    /// Equals specific entity or slot
    Eq(EntityOrSlot),
    /// In hierarchy of entity or slot
    In(EntityOrSlot),
    /// Is of specific type
    Is(EntityType),
    /// Is of specific type and in hierarchy
    IsIn(EntityType, EntityOrSlot),
}

/// Action scope constraint
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionConstraint {
    /// Any action
    Any,
    /// Equals specific action
    Eq(EntityUID),
    /// In set of actions (single action is just length 1)
    In(Vec<EntityUID>),
}

impl std::fmt::Display for EntityOrSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntityOrSlot::Entity(uid) => write!(f, "{}", uid),
            EntityOrSlot::Slot(slot) => write!(f, "{}", slot),
        }
    }
}

impl std::fmt::Display for PrincipalConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrincipalConstraint::Any => write!(f, ""),
            PrincipalConstraint::Eq(eos) => write!(f, "== {}", eos),
            PrincipalConstraint::In(eos) => write!(f, "in {}", eos),
            PrincipalConstraint::Is(et) => write!(f, "is {}", et),
            PrincipalConstraint::IsIn(et, eos) => write!(f, "is {} in {}", et, eos),
        }
    }
}

impl std::fmt::Display for ResourceConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceConstraint::Any => write!(f, ""),
            ResourceConstraint::Eq(eos) => write!(f, "== {}", eos),
            ResourceConstraint::In(eos) => write!(f, "in {}", eos),
            ResourceConstraint::Is(et) => write!(f, "is {}", et),
            ResourceConstraint::IsIn(et, eos) => write!(f, "is {} in {}", et, eos),
        }
    }
}

impl std::fmt::Display for ActionConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionConstraint::Any => write!(f, ""),
            ActionConstraint::Eq(uid) => write!(f, "== {}", uid),
            ActionConstraint::In(uids) => {
                write!(f, "in [")?;
                for (i, uid) in uids.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", uid)?;
                }
                write!(f, "]")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pst::expr::Name;
    use smol_str::SmolStr;
    use std::sync::Arc;

    fn make_entity_uid(ty: &str, id: &str) -> EntityUID {
        EntityUID {
            ty: EntityType(Name::unqualified(ty)),
            eid: id.into(),
        }
    }

    #[test]
    fn test_principal_constraint_display() {
        let uid = make_entity_uid("User", "alice");
        let eos = EntityOrSlot::Entity(uid.clone());
        let et = EntityType(Name::unqualified("User"));
        let etq = EntityType(Name::qualified(vec!["Admins"], "User"));
        let cases = vec![
            (PrincipalConstraint::Any, ""),
            (PrincipalConstraint::Eq(eos.clone()), "== User::\"alice\""),
            (
                PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal)),
                "== ?principal",
            ),
            (PrincipalConstraint::In(eos.clone()), "in User::\"alice\""),
            (PrincipalConstraint::Is(et.clone()), "is User"),
            (PrincipalConstraint::Is(etq), "is Admins::User"),
            (
                PrincipalConstraint::IsIn(et, eos),
                "is User in User::\"alice\"",
            ),
        ];

        for (constraint, expected) in cases {
            assert_eq!(constraint.to_string(), expected);
        }
    }

    #[test]
    fn test_resource_constraint_display() {
        let uid = make_entity_uid("File", "doc.txt");
        let eos = EntityOrSlot::Entity(uid.clone());
        let et = EntityType(Name {
            id: SmolStr::from("File"),
            namespace: Arc::new(vec![]),
        });

        let cases = vec![
            (ResourceConstraint::Any, ""),
            (ResourceConstraint::Eq(eos.clone()), "== File::\"doc.txt\""),
            (ResourceConstraint::In(eos.clone()), "in File::\"doc.txt\""),
            (
                ResourceConstraint::Eq(EntityOrSlot::Slot(SlotId::Resource)),
                "== ?resource",
            ),
            (ResourceConstraint::Is(et.clone()), "is File"),
            (
                ResourceConstraint::IsIn(et, eos),
                "is File in File::\"doc.txt\"",
            ),
        ];

        for (constraint, expected) in cases {
            assert_eq!(constraint.to_string(), expected);
        }
    }

    #[test]
    fn test_action_constraint_display() {
        let uid1 = make_entity_uid("Action", "read");
        let uid2 = make_entity_uid("Action", "write");

        let cases = vec![
            (ActionConstraint::Any, ""),
            (ActionConstraint::Eq(uid1.clone()), "== Action::\"read\""),
            (ActionConstraint::In(vec![]), "in []"),
            (
                ActionConstraint::In(vec![uid1.clone()]),
                "in [Action::\"read\"]",
            ),
            (
                ActionConstraint::In(vec![uid1, uid2]),
                "in [Action::\"read\", Action::\"write\"]",
            ),
        ];

        for (constraint, expected) in cases {
            assert_eq!(constraint.to_string(), expected);
        }
    }
}
