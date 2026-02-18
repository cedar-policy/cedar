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
    In(nonempty::NonEmpty<EntityUID>),
}
