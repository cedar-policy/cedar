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
use crate::extensions::Extensions;
use crate::validator::{
    json_schema::Type, types::Type as ValidatorType, RawName, SchemaError, ValidatorSchema,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::fmt;

/// Struct which holds the type & position of a generalized slot
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
#[serde_as]
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

    /// Given a generalized slots annotation and schema convert it into a BTreeMap from SlotIds to an equivalent form
    /// with a validator type instead of the JSON Schema type
    pub fn convert_to_validator_type_position_map(
        &self,
        schema: &ValidatorSchema,
    ) -> Result<BTreeMap<SlotId, (Option<ValidatorType>, Option<ScopePosition>)>, SchemaError> {
        let mut generalized_slots_to_validator_type = BTreeMap::new();
        for (slot_id, slot_type_position) in self.0.iter() {
            match slot_type_position {
                SlotTypePosition::TyPosition(ty, pos) => {
                    let validator_ty = schema.json_schema_type_to_validator_type(
                        ty.clone(),
                        Extensions::all_available(),
                    )?;

                    BTreeMap::insert(
                        &mut generalized_slots_to_validator_type,
                        slot_id.clone(),
                        (Some(validator_ty), Some(*pos)),
                    );
                }
                SlotTypePosition::Ty(ty) => {
                    let validator_ty = schema.json_schema_type_to_validator_type(
                        ty.clone(),
                        Extensions::all_available(),
                    )?;

                    BTreeMap::insert(
                        &mut generalized_slots_to_validator_type,
                        slot_id.clone(),
                        (Some(validator_ty), None),
                    );
                }
                SlotTypePosition::Position(pos) => {
                    BTreeMap::insert(
                        &mut generalized_slots_to_validator_type,
                        slot_id.clone(),
                        (None, Some(*pos)),
                    );
                }
            }
        }
        Ok(generalized_slots_to_validator_type)
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

impl std::fmt::Display for SlotTypePosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlotTypePosition::TyPosition(ty, _) => write!(f, "{}", ty),
            SlotTypePosition::Ty(ty) => write!(f, "{}", ty),
            _ => Ok(()),
        }
    }
}
