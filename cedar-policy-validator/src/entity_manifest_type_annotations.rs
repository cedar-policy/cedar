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

//! Annotate entity manifest with type information.

impl EntityManifest {
    /// Given an untyped entity manifest and the schema that produced it,
    /// return a newly typed entity manifest.
    pub fn to_typed(&self, schema: &ValidatorSchema) -> EntityManifest<Type> {
        EntityManifest {
            per_action: self
                .per_action
                .iter()
                .map(|(key, val)| (key.clone(), val.to_typed(key, schema)))
                .collect(),
        }
    }
}
