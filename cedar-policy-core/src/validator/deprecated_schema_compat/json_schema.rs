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

//! Contains a copy of the schema structures used to define JSON schema parsing
//! in version 2.5.x.
//!
//! Do not make changes to this file without careful consideration. It exist to
//! provide compatibility with version 2.5.x, so changes should not result in
//! any new errors being reported. Specifically, it provides a parsing mode that
//! ignores (some) unrecognized fields, so we not should change it to report these
//! as errors.  We also do not need to update these definitions to support new
//! features.

use crate::ast::UnreservedId;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashMap};

use crate::validator::{json_schema::CommonTypeId, RawName};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SchemaFragment(
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    pub  HashMap<SmolStr, NamespaceDefinition>,
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde_as]
#[serde(deny_unknown_fields)]
pub struct NamespaceDefinition {
    // Key changed from `SmolStr` in 2.5.0 to `CommonTypeId` to avoid excess code duplication
    #[serde(default)]
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    #[serde(rename = "commonTypes")]
    pub common_types: HashMap<CommonTypeId, SchemaType>,
    // Key changed from `SmolStr` in 2.5.0 to `UnreservedId` to avoid excess code duplication
    #[serde(rename = "entityTypes")]
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    pub entity_types: HashMap<UnreservedId, EntityType>,
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    pub actions: HashMap<SmolStr, ActionType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityType {
    // Key changed from `SmolStr` in 2.5.0 to `RawName` to avoid excess code duplication
    #[serde(default)]
    #[serde(rename = "memberOfTypes")]
    pub member_of_types: Vec<RawName>,
    #[serde(default)]
    pub shape: AttributesOrContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AttributesOrContext(pub SchemaType);

impl Default for AttributesOrContext {
    fn default() -> Self {
        Self(SchemaType::Type(SchemaTypeVariant::Record {
            attributes: BTreeMap::new(),
            additional_attributes: false,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionType {
    #[serde(default)]
    pub attributes: Option<HashMap<SmolStr, serde_json::Value>>,
    #[serde(default)]
    #[serde(rename = "appliesTo")]
    pub applies_to: Option<ApplySpec>,
    #[serde(default)]
    #[serde(rename = "memberOf")]
    pub member_of: Option<Vec<ActionEntityUID>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplySpec {
    // Key changed from `SmolStr` in 2.5.0 to `RawName` to avoid excess code duplication
    #[serde(default)]
    #[serde(rename = "resourceTypes")]
    pub resource_types: Option<Vec<RawName>>,
    // Key changed from `SmolStr` in 2.5.0 to `RawName` to avoid excess code duplication
    #[serde(default)]
    #[serde(rename = "principalTypes")]
    pub principal_types: Option<Vec<RawName>>,
    #[serde(default)]
    pub context: AttributesOrContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionEntityUID {
    pub id: SmolStr,

    // Key changed from `SmolStr` in 2.5.0 to `RawName` to avoid excess code duplication
    #[serde(rename = "type")]
    #[serde(default)]
    pub ty: Option<RawName>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SchemaType {
    Type(SchemaTypeVariant),
    TypeDef {
        #[serde(rename = "type")]
        type_name: SmolStr,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type")]
// This annotation exists in 2.5.x and prior 2.x versions of the JSON schema
// structs but doesn't actually deny (all) unknown fields here. Supporting
// unknown fields is the primary motivation of this module, so leaving this
// feels a bit odd, but we specifically want to support the same 2.5.x behavior
// around unknown fields, so we should leave this as is unless we have a reason not to.
#[serde(deny_unknown_fields)]
pub enum SchemaTypeVariant {
    String,
    Long,
    Boolean,
    Set {
        element: Box<SchemaType>,
    },
    Record {
        #[serde(with = "serde_with::rust::maps_duplicate_key_is_error")]
        attributes: BTreeMap<SmolStr, TypeOfAttribute>,
        #[serde(rename = "additionalAttributes")]
        #[serde(default = "additional_attributes_default")]
        additional_attributes: bool,
    },
    Entity {
        name: SmolStr,
    },
    Extension {
        name: SmolStr,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, PartialOrd, Ord)]
pub struct TypeOfAttribute {
    #[serde(flatten)]
    pub ty: SchemaType,
    #[serde(default = "record_attribute_required_default")]
    pub required: bool,
}

fn additional_attributes_default() -> bool {
    false
}

fn record_attribute_required_default() -> bool {
    true
}
