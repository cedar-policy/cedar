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

use std::collections::BTreeMap;

use crate::ast::SlotId;
use crate::validator::{json_schema::Type, RawName};
use serde::{Deserialize, Serialize};

/// Struct which holds the type & position of a generalized slot
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
pub struct GeneralizedSlotsAnnotation(BTreeMap<SlotId, SlotTypePosition>);

impl GeneralizedSlotsAnnotation {
    /// Create a new empty `GeneralizedSlotsAnnotation` (with no slots)
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Get an GeneralizedSlotsAnnotation by key
    pub fn get(&self, key: &SlotId) -> Option<&SlotTypePosition> {
        self.0.get(key)
    }

    /// Iterate over all GeneralizedSlotsAnnotation
    pub fn iter(&self) -> impl Iterator<Item = (&SlotId, &SlotTypePosition)> {
        self.0.iter()
    }

    /// Tell if it's empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for GeneralizedSlotsAnnotation {
    fn default() -> Self {
        Self::new()
    }
}

impl FromIterator<(SlotId, SlotTypePosition)> for GeneralizedSlotsAnnotation {
    fn from_iter<T: IntoIterator<Item = (SlotId, SlotTypePosition)>>(iter: T) -> Self {
        Self(BTreeMap::from_iter(iter))
    }
}

impl From<BTreeMap<SlotId, SlotTypePosition>> for GeneralizedSlotsAnnotation {
    fn from(value: BTreeMap<SlotId, SlotTypePosition>) -> Self {
        Self(value)
    }
}

/// Enum for scope position of generalized slots
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ScopePosition {
    /// Principal position in scope
    Principal,
    /// Resource position in scope
    Resource,
}

/// Stores the position and type for generalized slots
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum SlotTypePosition {
    /// Type & Position of a slot
    TyPosition(Type<RawName>, ScopePosition),
    /// Type of a slot
    Ty(Type<RawName>),
    /// Position of a slot
    Position(ScopePosition),
}
