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

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use cedar_policy_core::{
    ast::{EntityUID, Value},
    entities::EntityUidJson,
    jsonvalue::JsonValueWithNoDuplicateKeys,
    transitive_closure::TCNode,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde_as]
#[serde(transparent)]
pub struct DeduplicatedMap {
    #[serde_as(as = "serde_with::MapPreventDuplicates<_,_>")]
    pub map: HashMap<SmolStr, JsonValueWithNoDuplicateKeys>,
}

/// Serde JSON format for a single entity
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct EntityJson {
    /// UID of the entity, specified in any form accepted by `EntityUidJson`
    uid: EntityUidJson,
    /// attributes, whose values can be any JSON value.
    /// (Probably a `CedarValueJson`, but for schema-based parsing, it could for
    /// instance be an `EntityUidJson` if we're expecting an entity reference,
    /// so for now we leave it in its raw json-value form, albeit not allowing
    /// any duplicate keys in any records that may occur in an attribute value
    /// (even nested).)
    #[serde(default)]
    // the annotation covers duplicates in this `HashMap` itself, while the `JsonValueWithNoDuplicateKeys` covers duplicates in any records contained in attribute values (including recursively)
    attrs: Option<DeduplicatedMap>,
    #[serde(default)]
    /// Parents of the entity, specified in any form accepted by `EntityUidJson`
    parents: Option<Vec<EntityUidJson>>,
    #[serde(default)]
    // the annotation covers duplicates in this `HashMap` itself, while the `JsonValueWithNoDuplicateKeys` covers duplicates in any records contained in tag values (including recursively)
    // Note that unlike the concrete JSON entity format, when the `tags` field
    // is missing, it means `tags` are unknown
    // This is because we need to represent `tags` being unknowns
    tags: Option<DeduplicatedMap>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialEntity {
    pub uid: EntityUID,
    pub attrs: Option<BTreeMap<SmolStr, Value>>,
    pub ancestors: Option<HashSet<EntityUID>>,
    pub tags: Option<BTreeMap<SmolStr, Value>>,
}

impl PartialEntity {
    pub(crate) fn add_ancestor(&mut self, uid: EntityUID) {
        self.ancestors
            .as_mut()
            .expect("should not be unknown")
            .insert(uid);
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialEntities {
    /// Important internal invariant: for any `Entities` object that exists,
    /// the `ancestor` relation is transitively closed.
    pub(crate) entities: HashMap<EntityUID, Arc<PartialEntity>>,
}

#[cfg(test)]
mod tests {
    use super::EntityJson;

    #[test]
    fn basic() {
        let json = serde_json::json!(
            {
                "uid" : {
                    "type" : "A",
                    "id" : "",
                },
                "tags" : null,
            }
        );
        let ejson: EntityJson = serde_json::from_value(json).expect("should parse");
    }
}
