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

/// Struct storing the pairs of SlotId's and their corresponding type
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
pub struct SlotsTypeDeclaration(BTreeMap<SlotId, JSONSchemaType<RawName>>);

impl SlotsTypeDeclaration {
    /// Create a new empty `SlotsTypeDeclaration` (with no slots)
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

    /// Converts the types of slots_type_declaration to
    /// use validator types so that they can be used by the typechecker
    pub fn into_validator_slots_type_declaration(
        self,
        schema: &ValidatorSchema,
    ) -> Result<ValidatorSlotsTypeDeclaration, SchemaError> {
        let validator_slots_type_declaration: Result<BTreeMap<_, _>, SchemaError> = self
            .0
            .into_iter()
            .map(|(k, ty)| -> Result<_, SchemaError> {
                Ok((
                    k,
                    schema.json_schema_type_to_validator_type(ty, Extensions::all_available())?,
                ))
            })
            .collect();
        Ok(validator_slots_type_declaration?.into())
    }

    /// Converts the types of slots_type_declaration to
    /// a validator type so we can perform link time type checking
    /// for users who do not use a schema.
    pub fn into_validator_slots_type_declaration_without_schema(
        self,
    ) -> Result<ValidatorSlotsTypeDeclaration, SchemaError> {
        let validator_slots_type_declaration: Result<BTreeMap<_, _>, SchemaError> = self
            .0
            .into_iter()
            .map(|(k, ty)| -> Result<_, SchemaError> {
                Ok((
                    k,
                    ValidatorSchema::json_schema_type_to_validator_type_without_schema(
                        ty,
                        Extensions::all_available(),
                    )?,
                ))
            })
            .collect();
        Ok(validator_slots_type_declaration?.into())
    }
}

impl Default for SlotsTypeDeclaration {
    fn default() -> Self {
        Self::new()
    }
}

impl FromIterator<(SlotId, JSONSchemaType<RawName>)> for SlotsTypeDeclaration {
    fn from_iter<T: IntoIterator<Item = (SlotId, JSONSchemaType<RawName>)>>(iter: T) -> Self {
        Self(BTreeMap::from_iter(iter))
    }
}

impl From<BTreeMap<SlotId, JSONSchemaType<RawName>>> for SlotsTypeDeclaration {
    fn from(value: BTreeMap<SlotId, JSONSchemaType<RawName>>) -> Self {
        Self(value)
    }
}

/// Struct storing the pairs of SlotId's and their corresponding validator types
/// This struct is used when typechecking. JSONSchemaType's can't be used
/// by the typechecker and need to be translated to a validator type by using a schema.
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Debug, Hash)]
pub struct ValidatorSlotsTypeDeclaration(pub BTreeMap<SlotId, ValidatorType>);

impl FromIterator<(SlotId, ValidatorType)> for ValidatorSlotsTypeDeclaration {
    fn from_iter<T: IntoIterator<Item = (SlotId, ValidatorType)>>(iter: T) -> Self {
        Self(BTreeMap::from_iter(iter))
    }
}

impl From<BTreeMap<SlotId, ValidatorType>> for ValidatorSlotsTypeDeclaration {
    fn from(value: BTreeMap<SlotId, ValidatorType>) -> Self {
        Self(value)
    }
}

impl Default for ValidatorSlotsTypeDeclaration {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidatorSlotsTypeDeclaration {
    /// Create a new empty `ValidatorSlotsTypeDeclaration` (with no slots)
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Get the validator type of the slot by key
    pub fn get(&self, slot: &SlotId) -> Option<&ValidatorType> {
        self.0.get(slot)
    }
}
