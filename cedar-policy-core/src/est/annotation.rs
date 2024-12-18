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

use serde::{Deserialize, Serialize};

use crate::ast::{self, Annotation, AnyId};
#[cfg(feature = "wasm")]
extern crate tsify;

/// Similar to [`ast::Annotations`] but allow annotation value to be `null`
#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Annotations(
    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    #[cfg_attr(feature = "wasm", tsify(type = "Record<string, Annotation>"))]
    pub BTreeMap<AnyId, Option<Annotation>>,
);

impl Annotations {
    /// Create a new empty `Annotations` (with no annotations)
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
    /// Tell if it's empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Annotations> for ast::Annotations {
    fn from(value: Annotations) -> Self {
        ast::Annotations::from_iter(
            value
                .0
                .into_iter()
                .map(|(key, value)| (key, value.unwrap_or_default())),
        )
    }
}

impl From<ast::Annotations> for Annotations {
    fn from(value: ast::Annotations) -> Self {
        Self(
            value
                .into_iter()
                .map(|(key, value)| (key, Some(value)))
                .collect(),
        )
    }
}

impl std::fmt::Display for Annotations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (k, v) in &self.0 {
            if let Some(anno) = v {
                writeln!(f, "@{k}({anno})")?
            } else {
                writeln!(f, "@{k}")?
            }
        }
        Ok(())
    }
}

impl Default for Annotations {
    fn default() -> Self {
        Self::new()
    }
}
