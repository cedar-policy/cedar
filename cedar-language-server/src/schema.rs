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

mod completions;
mod definition;
mod diagnostics;
mod fold;
mod symbols;

use cedar_policy::SchemaFragment;
use cedar_policy_core::extensions::Extensions;
use cedar_policy_core::validator::ValidatorSchema;
pub(crate) use completions::*;
pub(crate) use definition::*;
pub(crate) use diagnostics::*;
pub(crate) use fold::*;
use serde::{Deserialize, Serialize};
pub(crate) use symbols::*;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(feature = "wasm")]
extern crate tsify;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum SchemaType {
    CedarSchema,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct SchemaInfo {
    pub schema_type: SchemaType,
    pub text: String,
}

impl SchemaInfo {
    #[must_use]
    pub(crate) fn new(schema_type: SchemaType, schema: String) -> Self {
        Self {
            schema_type,
            text: schema,
        }
    }

    #[must_use]
    pub(crate) fn is_json_schema(&self) -> bool {
        self.schema_type == SchemaType::Json
    }

    #[must_use]
    pub(crate) fn cedar_schema(schema: String) -> Self {
        Self {
            schema_type: SchemaType::CedarSchema,
            text: schema,
        }
    }

    #[must_use]
    pub(crate) fn json_schema(schema: String) -> Self {
        Self {
            schema_type: SchemaType::Json,
            text: schema,
        }
    }

    pub(crate) fn convert_to_json_schema(self) -> anyhow::Result<Self> {
        match self.schema_type {
            SchemaType::CedarSchema => {
                let fragment = SchemaFragment::from_cedarschema_str(&self.text)?;
                let json = fragment.0.to_json_value()?;
                let schema = serde_json::to_string_pretty(&json)?;
                Ok(Self::new(SchemaType::Json, schema))
            }
            SchemaType::Json => Ok(self),
        }
    }

    pub(crate) fn convert_to_cedar_schema(self) -> anyhow::Result<Self> {
        match self.schema_type {
            SchemaType::CedarSchema => Ok(self),
            SchemaType::Json => {
                let fragment = SchemaFragment::from_json_str(&self.text)?;
                Ok(Self::new(
                    SchemaType::CedarSchema,
                    fragment.to_cedarschema()?,
                ))
            }
        }
    }

    pub(crate) fn swap_format(self) -> anyhow::Result<Self> {
        match self.schema_type {
            SchemaType::CedarSchema => self.convert_to_json_schema(),
            SchemaType::Json => self.convert_to_cedar_schema(),
        }
    }
}

impl TryFrom<&SchemaInfo> for ValidatorSchema {
    type Error = anyhow::Error;

    fn try_from(value: &SchemaInfo) -> Result<Self, Self::Error> {
        match value.schema_type {
            SchemaType::CedarSchema => {
                Self::from_cedarschema_str(&value.text, Extensions::all_available())
                    .map(|v| v.0)
                    .map_err(Into::into)
            }
            SchemaType::Json => {
                Self::from_json_str(&value.text, Extensions::all_available()).map_err(Into::into)
            }
        }
    }
}
