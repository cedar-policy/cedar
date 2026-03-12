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

//! Scope constraint types for PST.
//!
//! These types represent the principal, action, and resource scope constraints
//! in a Cedar policy head:
//!
//! ```cedar
//! permit (
//!   principal == User::"alice",       // PrincipalConstraint::Eq
//!   action == Action::"view",         // ActionConstraint::Eq
//!   resource in Album::"vacation"     // ResourceConstraint::In
//! );
//! ```

use super::err::error_body::LinkingError;
use super::expr::{EntityType, EntityUID, SlotId};
use std::collections::HashMap;

/// Entity UID or template slot.
///
/// Used in principal and resource constraints where either a concrete entity
/// or a template slot is allowed.
///
/// ```cedar
/// principal == User::"alice"      // EntityOrSlot::Entity
/// principal == ?principal         // EntityOrSlot::Slot
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EntityOrSlot {
    /// A concrete entity UID
    Entity(EntityUID),
    /// A template slot
    Slot(SlotId),
}

impl EntityOrSlot {
    /// Fill in any slot using the values in `vals`.
    fn link(self, vals: &HashMap<SlotId, EntityUID>) -> Result<EntityOrSlot, LinkingError> {
        match self {
            EntityOrSlot::Entity(_) => Ok(self),
            EntityOrSlot::Slot(slot) => match vals.get(&slot) {
                Some(uid) => Ok(EntityOrSlot::Entity(uid.clone())),
                None => Err(LinkingError::MissedSlot { slot }),
            },
        }
    }
}

/// Principal scope constraint.
///
/// ```cedar
/// principal,                              // Any
/// principal == User::"alice",             // Eq(Entity)
/// principal == ?principal,                // Eq(Slot)
/// principal in Group::"admins",           // In(Entity)
/// principal is User,                      // Is
/// principal is User in Group::"admins",   // IsIn
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalConstraint {
    /// `principal` — matches any principal
    Any,
    /// `principal == <entity_or_slot>`
    Eq(EntityOrSlot),
    /// `principal in <entity_or_slot>`
    In(EntityOrSlot),
    /// `principal is <type>`
    Is(EntityType),
    /// `principal is <type> in <entity_or_slot>`
    IsIn(EntityType, EntityOrSlot),
}

impl PrincipalConstraint {
    /// Fill in any slots in this constraint using the values in `vals`.
    pub fn link(self, vals: &HashMap<SlotId, EntityUID>) -> Result<Self, LinkingError> {
        match self {
            PrincipalConstraint::Any => Ok(PrincipalConstraint::Any),
            PrincipalConstraint::Eq(eos) => Ok(PrincipalConstraint::Eq(eos.link(vals)?)),
            PrincipalConstraint::In(eos) => Ok(PrincipalConstraint::In(eos.link(vals)?)),
            PrincipalConstraint::Is(et) => Ok(PrincipalConstraint::Is(et)),
            PrincipalConstraint::IsIn(et, eos) => {
                Ok(PrincipalConstraint::IsIn(et, eos.link(vals)?))
            }
        }
    }

    /// Test whether the constraint contains any slots.
    pub fn has_slot(&self) -> bool {
        matches!(
            self,
            PrincipalConstraint::Eq(EntityOrSlot::Slot(_))
                | PrincipalConstraint::In(EntityOrSlot::Slot(_))
                | PrincipalConstraint::IsIn(_, EntityOrSlot::Slot(_))
        )
    }

    /// Get the slot, if any
    pub fn slot(&self) -> Option<SlotId> {
        match self {
            PrincipalConstraint::Eq(EntityOrSlot::Slot(s))
            | PrincipalConstraint::In(EntityOrSlot::Slot(s))
            | PrincipalConstraint::IsIn(_, EntityOrSlot::Slot(s)) => Some(*s),
            _ => None,
        }
    }
}

/// Resource scope constraint (same shape as [`PrincipalConstraint`]).
///
/// ```cedar
/// resource,                               // Any
/// resource == Photo::"pic.jpg",           // Eq(Entity)
/// resource == ?resource,                  // Eq(Slot)
/// resource in Album::"vacation",          // In(Entity)
/// resource is Photo,                      // Is
/// resource is Photo in Album::"vacation", // IsIn
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceConstraint {
    /// `resource` — matches any resource
    Any,
    /// `resource == <entity_or_slot>`
    Eq(EntityOrSlot),
    /// `resource in <entity_or_slot>`
    In(EntityOrSlot),
    /// `resource is <type>`
    Is(EntityType),
    /// `resource is <type> in <entity_or_slot>`
    IsIn(EntityType, EntityOrSlot),
}

impl ResourceConstraint {
    /// Fill in any slots in this constraint using the values in `vals`.
    pub fn link(self, vals: &HashMap<SlotId, EntityUID>) -> Result<Self, LinkingError> {
        match self {
            ResourceConstraint::Any => Ok(ResourceConstraint::Any),
            ResourceConstraint::Eq(eos) => Ok(ResourceConstraint::Eq(eos.link(vals)?)),
            ResourceConstraint::In(eos) => Ok(ResourceConstraint::In(eos.link(vals)?)),
            ResourceConstraint::Is(et) => Ok(ResourceConstraint::Is(et)),
            ResourceConstraint::IsIn(et, eos) => Ok(ResourceConstraint::IsIn(et, eos.link(vals)?)),
        }
    }

    /// Test whether the constraint contains any slots.
    pub fn has_slot(&self) -> bool {
        matches!(
            self,
            ResourceConstraint::Eq(EntityOrSlot::Slot(_))
                | ResourceConstraint::In(EntityOrSlot::Slot(_))
                | ResourceConstraint::IsIn(_, EntityOrSlot::Slot(_)),
        )
    }

    /// Get the slot, if any
    pub fn slot(&self) -> Option<SlotId> {
        match self {
            ResourceConstraint::Eq(EntityOrSlot::Slot(s))
            | ResourceConstraint::In(EntityOrSlot::Slot(s))
            | ResourceConstraint::IsIn(_, EntityOrSlot::Slot(s)) => Some(*s),
            _ => None,
        }
    }
}

/// Action scope constraint.
///
/// ```cedar
/// action,                                                     // Any
/// action == Action::"view",                                   // Eq
/// action in [Action::"view", Action::"edit"],                 // In
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionConstraint {
    /// `action` — matches any action
    Any,
    /// `action == <entity_uid>`
    Eq(EntityUID),
    /// `action in [<entity_uid>, ...]`
    In(Vec<EntityUID>),
}

impl ActionConstraint {
    /// Actions cannot contain slots, so linking is a no-op.
    pub fn link(self, _vals: &HashMap<SlotId, EntityUID>) -> Result<Self, LinkingError> {
        Ok(self)
    }

    /// Actions cannot contains slots: returns false
    pub fn has_slot(&self) -> bool {
        false
    }

    /// Action cannot have slots
    pub fn slot(&self) -> Option<SlotId> {
        None
    }
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

    fn make_vals() -> HashMap<SlotId, EntityUID> {
        let mut vals = HashMap::new();
        vals.insert(SlotId::Principal, make_entity_uid("User", "alice"));
        vals.insert(SlotId::Resource, make_entity_uid("File", "doc.txt"));
        vals
    }

    #[test]
    fn test_entity_or_slot_link_entity_passthrough() {
        let uid = make_entity_uid("User", "alice");
        let eos = EntityOrSlot::Entity(uid.clone());
        assert_eq!(eos.link(&make_vals()).unwrap(), EntityOrSlot::Entity(uid));
    }

    #[test]
    fn test_entity_or_slot_link_slot_resolves() {
        let eos = EntityOrSlot::Slot(SlotId::Principal);
        assert_eq!(
            eos.link(&make_vals()).unwrap(),
            EntityOrSlot::Entity(make_entity_uid("User", "alice"))
        );
    }

    #[test]
    fn test_entity_or_slot_link_missing_slot() {
        let eos = EntityOrSlot::Slot(SlotId::Resource);
        let empty = HashMap::new();
        assert!(matches!(
            eos.link(&empty),
            Err(LinkingError::MissedSlot {
                slot: SlotId::Resource
            })
        ));
    }

    #[test]
    fn test_principal_constraint_link_all_variants() {
        let vals = make_vals();
        let alice = make_entity_uid("User", "alice");
        let et = EntityType(Name::unqualified("User"));

        // Any passes through
        assert_eq!(
            PrincipalConstraint::Any.link(&vals).unwrap(),
            PrincipalConstraint::Any
        );
        // Eq with entity passes through
        assert_eq!(
            PrincipalConstraint::Eq(EntityOrSlot::Entity(alice.clone()))
                .link(&vals)
                .unwrap(),
            PrincipalConstraint::Eq(EntityOrSlot::Entity(alice.clone()))
        );
        // Eq with slot resolves
        assert_eq!(
            PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal))
                .link(&vals)
                .unwrap(),
            PrincipalConstraint::Eq(EntityOrSlot::Entity(alice.clone()))
        );
        // In with slot resolves
        assert_eq!(
            PrincipalConstraint::In(EntityOrSlot::Slot(SlotId::Principal))
                .link(&vals)
                .unwrap(),
            PrincipalConstraint::In(EntityOrSlot::Entity(alice.clone()))
        );
        // Is passes through (no slot)
        assert_eq!(
            PrincipalConstraint::Is(et.clone()).link(&vals).unwrap(),
            PrincipalConstraint::Is(et.clone())
        );
        // IsIn with slot resolves
        assert_eq!(
            PrincipalConstraint::IsIn(et.clone(), EntityOrSlot::Slot(SlotId::Principal))
                .link(&vals)
                .unwrap(),
            PrincipalConstraint::IsIn(et, EntityOrSlot::Entity(alice))
        );
    }

    #[test]
    fn test_resource_constraint_link_slot_resolves() {
        let vals = make_vals();
        let doc = make_entity_uid("File", "doc.txt");

        assert_eq!(
            ResourceConstraint::Eq(EntityOrSlot::Slot(SlotId::Resource))
                .link(&vals)
                .unwrap(),
            ResourceConstraint::Eq(EntityOrSlot::Entity(doc))
        );
    }

    #[test]
    fn test_principal_constraint_link_missing_slot() {
        let empty = HashMap::new();
        assert!(matches!(
            PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal)).link(&empty),
            Err(LinkingError::MissedSlot {
                slot: SlotId::Principal
            })
        ));
    }

    #[test]
    fn test_action_constraint_link_noop() {
        let uid = make_entity_uid("Action", "read");
        let vals = make_vals();
        assert_eq!(
            ActionConstraint::Eq(uid.clone()).link(&vals).unwrap(),
            ActionConstraint::Eq(uid)
        );
    }
}
