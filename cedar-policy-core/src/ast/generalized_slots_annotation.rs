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

    pub(crate) fn into_validator_generalized_slots_annotation(
        self,
        schema: &ValidatorSchema,
    ) -> Result<ValidatorGeneralizedSlotsAnnotation, SchemaError> {
        let validator_generalized_slots_annotation: Result<BTreeMap<_, _>, SchemaError> = self
            .0
            .into_iter()
            .map(|(k, v)| -> Result<_, SchemaError> {
                Ok((k, v.to_validator_slot_type_position(schema)?))
            })
            .collect();
        Ok(validator_generalized_slots_annotation?.into())
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
    /// Type of a slot
    Ty(Type<RawName>),
    /// Position of a slot
    Position(ScopePosition),
}

impl SlotTypePosition {
    pub(crate) fn to_validator_slot_type_position(
        &self,
        schema: &ValidatorSchema,
    ) -> Result<ValidatorSlotTypePosition, SchemaError> {
        match self {
            Self::Ty(ty) => {
                let validator_ty = schema
                    .json_schema_type_to_validator_type(ty.clone(), Extensions::all_available())?;
                Ok(ValidatorSlotTypePosition::Ty(validator_ty))
            }
            Self::Position(pos) => Ok(ValidatorSlotTypePosition::Position(pos.clone())),
        }
    }
}

impl std::fmt::Display for SlotTypePosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlotTypePosition::Ty(ty) => write!(f, "{}", ty),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub(crate) enum ValidatorSlotTypePosition {
    /// Type of a slot
    Ty(ValidatorType),
    /// Position of a slot
    Position(ScopePosition),
}

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Debug, Hash)]
pub(crate) struct ValidatorGeneralizedSlotsAnnotation(BTreeMap<SlotId, ValidatorSlotTypePosition>);

impl FromIterator<(SlotId, ValidatorSlotTypePosition)> for ValidatorGeneralizedSlotsAnnotation {
    fn from_iter<T: IntoIterator<Item = (SlotId, ValidatorSlotTypePosition)>>(iter: T) -> Self {
        Self(BTreeMap::from_iter(iter))
    }
}

impl From<BTreeMap<SlotId, ValidatorSlotTypePosition>> for ValidatorGeneralizedSlotsAnnotation {
    fn from(value: BTreeMap<SlotId, ValidatorSlotTypePosition>) -> Self {
        Self(value)
    }
}

impl Default for ValidatorGeneralizedSlotsAnnotation {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidatorGeneralizedSlotsAnnotation {
    pub(crate) fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub(crate) fn get_validator_slot_type_position(
        &self,
        slot: &SlotId,
    ) -> Option<&ValidatorSlotTypePosition> {
        self.0.get(slot)
    }

    pub(crate) fn in_principal_position(&self, slot: &SlotId) -> bool {
        matches!(
            self.0.get(slot),
            Some(&ValidatorSlotTypePosition::Position(
                ScopePosition::Principal
            ))
        )
    }

    pub(crate) fn in_resource_position(&self, slot: &SlotId) -> bool {
        matches!(
            self.0.get(slot),
            Some(&ValidatorSlotTypePosition::Position(
                ScopePosition::Resource
            ))
        )
    }

    pub(crate) fn get_type(&self, slot: &SlotId) -> Option<ValidatorType> {
        self.0.get(slot).and_then(
            |validator_slot_type_position| match validator_slot_type_position {
                ValidatorSlotTypePosition::Ty(ty) => Some(ty.clone()),
                ValidatorSlotTypePosition::Position(_) => None,
            },
        )
    }
}
