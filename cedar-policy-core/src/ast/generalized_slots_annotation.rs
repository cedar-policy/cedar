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
    json_schema::Type as JSONSchemaType, types::Type as ValidatorType, RawName, SchemaError,
    ValidatorSchema,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Struct which holds the type & position of a generalized slot
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
#[serde_as]
pub struct GeneralizedSlotsAnnotation(BTreeMap<SlotId, JSONSchemaType<RawName>>);

impl GeneralizedSlotsAnnotation {
    /// Create a new empty `GeneralizedSlotsAnnotation` (with no slots)
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Get the type of the slot by key
    pub fn get(&self, key: &SlotId) -> Option<&JSONSchemaType<RawName>> {
        self.0.get(key)
    }

    /// Iterate over all pairs of slots and their types
    pub fn iter(&self) -> impl Iterator<Item = (&SlotId, &JSONSchemaType<RawName>)> {
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
            .map(|(k, ty)| -> Result<_, SchemaError> {
                Ok((
                    k,
                    schema.json_schema_type_to_validator_type(ty, Extensions::all_available())?,
                ))
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

impl FromIterator<(SlotId, JSONSchemaType<RawName>)> for GeneralizedSlotsAnnotation {
    fn from_iter<T: IntoIterator<Item = (SlotId, JSONSchemaType<RawName>)>>(iter: T) -> Self {
        Self(BTreeMap::from_iter(iter))
    }
}

impl From<BTreeMap<SlotId, JSONSchemaType<RawName>>> for GeneralizedSlotsAnnotation {
    fn from(value: BTreeMap<SlotId, JSONSchemaType<RawName>>) -> Self {
        Self(value)
    }
}

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Debug, Hash)]
pub(crate) struct ValidatorGeneralizedSlotsAnnotation(BTreeMap<SlotId, ValidatorType>);

impl FromIterator<(SlotId, ValidatorType)> for ValidatorGeneralizedSlotsAnnotation {
    fn from_iter<T: IntoIterator<Item = (SlotId, ValidatorType)>>(iter: T) -> Self {
        Self(BTreeMap::from_iter(iter))
    }
}

impl From<BTreeMap<SlotId, ValidatorType>> for ValidatorGeneralizedSlotsAnnotation {
    fn from(value: BTreeMap<SlotId, ValidatorType>) -> Self {
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

    pub(crate) fn get(&self, slot: &SlotId) -> Option<&ValidatorType> {
        self.0.get(slot)
    }
}
