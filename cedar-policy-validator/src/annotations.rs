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

//! Annotations used in Cedar/JSON schemas

use std::collections::BTreeMap;

use cedar_policy_core::ast::AnyId;
use serde::Serialize;
use smol_str::SmolStr;

/// Annotations
pub type Annotations = BTreeMap<AnyId, SmolStr>;

/// A struct that can be annotated, e.g., entity types.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct Annotated<T> {
    /// The struct that's optionally annotated
    #[serde(flatten)]
    pub data: T,
    /// Annotations
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: Annotations,
}

impl<T> From<T> for Annotated<T> {
    fn from(value: T) -> Self {
        Self {
            data: value,
            annotations: BTreeMap::new(),
        }
    }
}
