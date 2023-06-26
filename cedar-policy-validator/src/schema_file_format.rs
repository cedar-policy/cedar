/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

use cedar_policy_core::entities::JSONValue;
use serde::{
    de::{MapAccess, Visitor},
    Deserialize, Serialize,
};
use serde_with::serde_as;
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashMap};

use crate::Result;

/// A SchemaFragment describe the types for a given instance of Cedar.
/// SchemaFragments are composed of Entity Types and Action Types. The
/// schema fragment is split into multiple namespace definitions, eac including
/// a namespace name which is applied to all entity types (and the implicit
/// `Action` entity type for all actions) in the schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SchemaFragment(
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    pub  HashMap<SmolStr, NamespaceDefinition>,
);

impl SchemaFragment {
    /// Create a `SchemaFragment` from a JSON value (which should be an object
    /// of the appropriate shape).
    pub fn from_json_value(json: serde_json::Value) -> Result<Self> {
        serde_json::from_value(json).map_err(Into::into)
    }

    /// Create a `SchemaFragment` directly from a file.
    pub fn from_file(file: impl std::io::Read) -> Result<Self> {
        serde_json::from_reader(file).map_err(Into::into)
    }
}

/// A single namespace definition from a SchemaFragment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde_as]
#[serde(deny_unknown_fields)]
#[doc(hidden)]
pub struct NamespaceDefinition {
    #[serde(default)]
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    #[serde(rename = "commonTypes")]
    pub common_types: HashMap<SmolStr, SchemaType>,
    #[serde(rename = "entityTypes")]
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    pub entity_types: HashMap<SmolStr, EntityType>,
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    pub actions: HashMap<SmolStr, ActionType>,
}

impl NamespaceDefinition {
    pub fn new(
        entity_types: impl IntoIterator<Item = (SmolStr, EntityType)>,
        actions: impl IntoIterator<Item = (SmolStr, ActionType)>,
    ) -> Self {
        Self {
            common_types: HashMap::new(),
            entity_types: entity_types.into_iter().collect(),
            actions: actions.into_iter().collect(),
        }
    }
}

impl std::fmt::Display for NamespaceDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(
            &serde_json::to_string_pretty(&self).expect("failed to serialize NamespaceContents"),
        )
    }
}

/// Entity types describe the relationships in the entity store, including what
/// entities can be members of groups of what types, and what attributes
/// can/should be included on entities of each type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityType {
    #[serde(default)]
    #[serde(rename = "memberOfTypes")]
    pub member_of_types: Vec<SmolStr>,
    #[serde(default)]
    pub shape: AttributesOrContext,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AttributesOrContext(
    // We use the usual `SchemaType` deserialization, but it will ultimately
    // need to be a `Record` or type def which resolves to a `Record`.
    pub SchemaType,
);

impl AttributesOrContext {
    pub fn into_inner(self) -> SchemaType {
        self.0
    }
}

impl Default for AttributesOrContext {
    fn default() -> Self {
        Self(SchemaType::Type(SchemaTypeVariant::Record {
            attributes: BTreeMap::new(),
            additional_attributes: false,
        }))
    }
}

/// An action type describes a specific action entity.  It also describes what
/// kinds of entities it can be used on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionType {
    /// This maps attribute names to
    /// `cedar_policy_core::entities::json::jsonvalue::JSONValue` which is the
    /// canonical representation of a cedar value as JSON.
    #[serde(default)]
    pub attributes: Option<HashMap<SmolStr, JSONValue>>,
    #[serde(default)]
    #[serde(rename = "appliesTo")]
    pub applies_to: Option<ApplySpec>,
    #[serde(default)]
    #[serde(rename = "memberOf")]
    pub member_of: Option<Vec<ActionEntityUID>>,
}

/// The apply spec specifies what principals and resources an action can be used
/// with.  This specification can either be done through containing to entity
/// types. The fields of this record are optional so that they can be omitted to
/// declare that the apply spec for the principal or resource is undefined,
/// meaning that the action can be applied to any principal or resource. This is
/// different than providing an empty list because the empty list is interpreted
/// as specifying that there are no principals or resources that an action
/// applies to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplySpec {
    #[serde(default)]
    #[serde(rename = "resourceTypes")]
    pub resource_types: Option<Vec<SmolStr>>,
    #[serde(default)]
    #[serde(rename = "principalTypes")]
    pub principal_types: Option<Vec<SmolStr>>,
    #[serde(default)]
    pub context: AttributesOrContext,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionEntityUID {
    pub id: SmolStr,

    #[serde(rename = "type")]
    #[serde(default)]
    pub ty: Option<SmolStr>,
}

impl ActionEntityUID {
    pub fn default_type(id: SmolStr) -> Self {
        Self { id, ty: None }
    }
}

impl std::fmt::Display for ActionEntityUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ty) = &self.ty {
            write!(f, "{}::", ty)?
        } else {
            write!(f, "Action::")?
        }
        write!(f, "\"{}\"", self.id)
    }
}

/// A restricted version of the `Type` enum containing only the types which are
/// exposed to users.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
// This enum is `untagged` with these variants as a workaround to a serde
// limitation. It is not possible to have the known variants on one enum, and
// then, have catch-all variant for any unrecognized tag in the same enum that
// captures the name of the unrecognized tag.
#[serde(untagged)]
pub enum SchemaType {
    Type(SchemaTypeVariant),
    TypeDef {
        #[serde(rename = "type")]
        type_name: SmolStr,
    },
}

impl<'de> Deserialize<'de> for SchemaType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(SchemaTypeVisitor)
    }
}

struct SchemaTypeVisitor;

impl<'de> Visitor<'de> for SchemaTypeVisitor {
    type Value = SchemaType;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("builtin type or reference to type defined in commonTypes")
    }

    fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Fields {
            Type,
            Element,
            Attributes,
            AdditionalAttributes,
            Name,
        }

        let mut type_name: Option<SmolStr> = None;
        let mut element: Option<SchemaType> = None;
        let mut attributes: Option<BTreeMap<SmolStr, TypeOfAttribute>> = None;
        let mut additional_attributes: Option<bool> = None;
        let mut name: Option<SmolStr> = None;

        while let Some(key) = map.next_key()? {
            match key {
                Fields::Type => {
                    if type_name.is_some() {
                        return Err(serde::de::Error::duplicate_field("type"));
                    }
                    type_name = Some(map.next_value()?)
                }
                Fields::Element => {
                    if element.is_some() {
                        return Err(serde::de::Error::duplicate_field("element"));
                    }
                    element = Some(map.next_value()?)
                }
                Fields::Attributes => {
                    if attributes.is_some() {
                        return Err(serde::de::Error::duplicate_field("attributes"));
                    }
                    attributes = Some(map.next_value()?)
                }
                Fields::AdditionalAttributes => {
                    if additional_attributes.is_some() {
                        return Err(serde::de::Error::duplicate_field("additionalAttributes"));
                    }
                    additional_attributes = Some(map.next_value()?)
                }
                Fields::Name => {
                    if name.is_some() {
                        return Err(serde::de::Error::duplicate_field("name"));
                    }
                    name = Some(map.next_value()?)
                }
            }
        }

        match type_name.as_ref().map(|s| s.as_str()) {
            Some("String") => {
                if element.is_some() {
                    Err(serde::de::Error::unknown_field("element", &[]))
                } else if attributes.is_some() {
                    Err(serde::de::Error::unknown_field("attributes", &[]))
                } else if additional_attributes.is_some() {
                    Err(serde::de::Error::unknown_field("additionalAttributes", &[]))
                } else if name.is_some() {
                    Err(serde::de::Error::unknown_field("name", &[]))
                } else {
                    Ok(SchemaType::Type(SchemaTypeVariant::String))
                }
            }
            Some("Long") => {
                if element.is_some() {
                    Err(serde::de::Error::unknown_field("element", &[]))
                } else if attributes.is_some() {
                    Err(serde::de::Error::unknown_field("attributes", &[]))
                } else if additional_attributes.is_some() {
                    Err(serde::de::Error::unknown_field("additionalAttributes", &[]))
                } else if name.is_some() {
                    Err(serde::de::Error::unknown_field("name", &[]))
                } else {
                    Ok(SchemaType::Type(SchemaTypeVariant::Long))
                }
            }
            Some("Boolean") => {
                if element.is_some() {
                    Err(serde::de::Error::unknown_field("element", &[]))
                } else if attributes.is_some() {
                    Err(serde::de::Error::unknown_field("attributes", &[]))
                } else if additional_attributes.is_some() {
                    Err(serde::de::Error::unknown_field("additionalAttributes", &[]))
                } else if name.is_some() {
                    Err(serde::de::Error::unknown_field("name", &[]))
                } else {
                    Ok(SchemaType::Type(SchemaTypeVariant::Boolean))
                }
            }
            Some("Set") => {
                if attributes.is_some() {
                    Err(serde::de::Error::unknown_field("attributes", &["element"]))
                } else if additional_attributes.is_some() {
                    Err(serde::de::Error::unknown_field(
                        "additionalAttributes",
                        &["element"],
                    ))
                } else if name.is_some() {
                    Err(serde::de::Error::unknown_field("name", &["element"]))
                } else if let Some(element) = element {
                    Ok(SchemaType::Type(SchemaTypeVariant::Set {
                        element: Box::new(element),
                    }))
                } else {
                    Err(serde::de::Error::missing_field("element"))
                }
            }
            Some("Record") => {
                if element.is_some() {
                    Err(serde::de::Error::unknown_field(
                        "element",
                        &["attributes", "additionalAttributes"],
                    ))
                } else if name.is_some() {
                    Err(serde::de::Error::unknown_field(
                        "name",
                        &["attributes", "additionalAttributes"],
                    ))
                } else if let Some(attributes) = attributes {
                    let additional_attributes =
                        additional_attributes.unwrap_or(additional_attributes_default());
                    Ok(SchemaType::Type(SchemaTypeVariant::Record {
                        attributes,
                        additional_attributes,
                    }))
                } else {
                    Err(serde::de::Error::missing_field("attributes"))
                }
            }
            Some("Entity") => {
                if element.is_some() {
                    Err(serde::de::Error::unknown_field("element", &["name"]))
                } else if attributes.is_some() {
                    Err(serde::de::Error::unknown_field("attributes", &["name"]))
                } else if additional_attributes.is_some() {
                    Err(serde::de::Error::unknown_field(
                        "additionalAttributes",
                        &["name"],
                    ))
                } else if let Some(name) = name {
                    Ok(SchemaType::Type(SchemaTypeVariant::Entity { name }))
                } else {
                    Err(serde::de::Error::missing_field("name"))
                }
            }
            Some("Extension") => {
                if element.is_some() {
                    Err(serde::de::Error::unknown_field("element", &["name"]))
                } else if attributes.is_some() {
                    Err(serde::de::Error::unknown_field("attributes", &["name"]))
                } else if additional_attributes.is_some() {
                    Err(serde::de::Error::unknown_field(
                        "additionalAttributes",
                        &["name"],
                    ))
                } else if let Some(name) = name {
                    Ok(SchemaType::Type(SchemaTypeVariant::Extension { name }))
                } else {
                    Err(serde::de::Error::missing_field("name"))
                }
            }
            Some(type_name) => {
                if element.is_some() {
                    Err(serde::de::Error::unknown_field("element", &[]))
                } else if attributes.is_some() {
                    Err(serde::de::Error::unknown_field("attributes", &[]))
                } else if additional_attributes.is_some() {
                    Err(serde::de::Error::unknown_field("additionalAttributes", &[]))
                } else if name.is_some() {
                    Err(serde::de::Error::unknown_field("name", &[]))
                } else {
                    Ok(SchemaType::TypeDef {
                        type_name: type_name.into(),
                    })
                }
            }
            None => Err(serde::de::Error::missing_field("type")),
        }
    }
}

impl From<SchemaTypeVariant> for SchemaType {
    fn from(variant: SchemaTypeVariant) -> Self {
        Self::Type(variant)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "type")]
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

// The possible tags for a SchemaType as written in a schema JSON document. Used
// to forbid declaring a custom typedef with the same name as a builtin type.
// This must be kept up to date with the variants for `SchemaTypeVariant` and
// their actual serialization by serde. There is crate that looks like it could
// do this automatically, but it returns an empty slice for the variants names
// of `SchemaTypeVariant`.
// https://docs.rs/serde-aux/latest/serde_aux/serde_introspection/fn.serde_introspect.html
pub(crate) static SCHEMA_TYPE_VARIANT_TAGS: &[&str] = &[
    "String",
    "Long",
    "Boolean",
    "Set",
    "Record",
    "Entity",
    "Extension",
];

impl SchemaType {
    /// Is this `SchemaType` an extension type, or does it contain one
    /// (recursively)? Returns `None` if this is a `TypeDef` because we can't
    /// easily properly check the type of a typedef, accounting for namespaces,
    /// without first converting to a `Type`.
    pub fn is_extension(&self) -> Option<bool> {
        match self {
            Self::Type(SchemaTypeVariant::Extension { .. }) => Some(true),
            Self::Type(SchemaTypeVariant::Set { element }) => element.is_extension(),
            Self::Type(SchemaTypeVariant::Record { attributes, .. }) => {
                attributes
                    .values()
                    .fold(Some(false), |a, e| match e.ty.is_extension() {
                        Some(true) => Some(true),
                        Some(false) => a,
                        None => None,
                    })
            }
            Self::Type(_) => Some(false),
            Self::TypeDef { .. } => None,
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for SchemaType {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<SchemaType> {
        use cedar_policy_core::ast::Name;
        use std::collections::HashSet;

        Ok(SchemaType::Type(match u.int_in_range::<u8>(1..=8)? {
            1 => SchemaTypeVariant::String,
            2 => SchemaTypeVariant::Long,
            3 => SchemaTypeVariant::Boolean,
            4 => SchemaTypeVariant::Set {
                element: Box::new(u.arbitrary()?),
            },
            5 => {
                let attributes = {
                    let attr_names: HashSet<String> = u.arbitrary()?;
                    attr_names
                        .into_iter()
                        .map(|attr_name| Ok((attr_name.into(), u.arbitrary()?)))
                        .collect::<arbitrary::Result<_>>()?
                };
                SchemaTypeVariant::Record {
                    attributes,
                    additional_attributes: u.arbitrary()?,
                }
            }
            6 => {
                let name: Name = u.arbitrary()?;
                SchemaTypeVariant::Entity {
                    name: name.to_string().into(),
                }
            }
            7 => SchemaTypeVariant::Extension {
                name: "ipaddr".into(),
            },
            8 => SchemaTypeVariant::Extension {
                name: "decimal".into(),
            },
            n => panic!("bad index: {n}"),
        }))
    }
    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        (1, None) // Unfortunately, we probably can't be more precise than this
    }
}

/// Used to describe the type of a record or entity attribute. It contains a the
/// type of the attribute and whether the attribute is required. The type is
/// flattened for serialization, so, in JSON format, this appears as a regular
/// type with one extra property `required`.
///
/// Note that we can't add #[serde(deny_unknown_fields)] here because we are
/// using #[serde(tag = "type")] in ty:SchemaType which is flattened here.
/// The way serde(flatten) is implemented means it may be possible to access
/// fields incorrectly if a struct contains two structs that are flattened
/// (`<https://github.com/serde-rs/serde/issues/1547>`). This shouldn't apply to
/// us as we're using flatten only once
/// (`<https://github.com/serde-rs/serde/issues/1600>`). This should be ok because
/// unknown fields for TypeOfAttribute should be passed to SchemaType where
/// they will be denied (`<https://github.com/serde-rs/serde/issues/1600>`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct TypeOfAttribute {
    #[serde(flatten)]
    pub ty: SchemaType,
    #[serde(default = "record_attribute_required_default")]
    pub required: bool,
}

/// Defines the default value for `additionalAttributes` on records and
/// entities
fn additional_attributes_default() -> bool {
    false
}

/// Defines the default value for `required` on record and entity attributes.
fn record_attribute_required_default() -> bool {
    true
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_entity_type_parser1() {
        let user = r#"
        {
            "memberOfTypes" : ["UserGroup"]
        }
        "#;
        let et = serde_json::from_str::<EntityType>(user).expect("Parse Error");
        assert_eq!(et.member_of_types, vec!["UserGroup"]);
        assert_eq!(
            et.shape.into_inner(),
            SchemaType::Type(SchemaTypeVariant::Record {
                attributes: BTreeMap::new(),
                additional_attributes: false
            })
        );
    }

    #[test]
    fn test_entity_type_parser2() {
        let src = r#"
              { }
        "#;
        let et = serde_json::from_str::<EntityType>(src).expect("Parse Error");
        assert_eq!(et.member_of_types.len(), 0);
        assert_eq!(
            et.shape.into_inner(),
            SchemaType::Type(SchemaTypeVariant::Record {
                attributes: BTreeMap::new(),
                additional_attributes: false
            })
        );
    }

    #[test]
    fn test_entity_type_parser3() {
        let src = r#"
        {
            "memberOf" : ["UserGroup"],
            "shape": {
                "type": "Record",
                "attributes": {
                    "name": { "type": "String", "required": false},
                    "name": { "type": "String", "required": true},
                    "age": { "type": "Long", "required": false}
                }
            }
        }
        "#;
        let et = serde_json::from_str::<EntityType>(src);
        match et {
            Ok(_) => panic!("serde_json parsing should have failed"),
            Err(e) => {
                assert_eq!(e.classify(), serde_json::error::Category::Data);
            }
        }
    }

    #[test]
    fn test_action_type_parser1() {
        let src = r#"
              {
                "appliesTo" : {
                  "resourceTypes": ["Album"],
                  "principalTypes": ["User"]
                },
                "memberOf": [{"id": "readWrite"}]
              }
        "#;
        let at: ActionType = serde_json::from_str(src).expect("Parse Error");
        let spec = ApplySpec {
            resource_types: Some(vec!["Album".into()]),
            principal_types: Some(vec!["User".into()]),
            context: AttributesOrContext::default(),
        };
        assert_eq!(at.applies_to, Some(spec));
        assert_eq!(
            at.member_of,
            Some(vec![ActionEntityUID {
                ty: None,
                id: "readWrite".into()
            }])
        );
    }

    #[test]
    fn test_action_type_parser2() {
        let src = r#"
              { }
        "#;
        let at: ActionType = serde_json::from_str(src).expect("Parse Error");
        assert_eq!(at.applies_to, None);
        assert!(at.member_of.is_none());
    }

    #[test]
    fn test_schema_file_parser() {
        let src = serde_json::json!(
        {
            "entityTypes": {

              "User": {
                "memberOfTypes": ["UserGroup"]
              },
              "Photo": {
                "memberOfTypes": ["Album", "Account"]
              },

              "Album": {
                "memberOfTypes": ["Album", "Account"]
              },
              "Account": { },
              "UserGroup": { }
           },

           "actions": {
              "readOnly": { },
              "readWrite": { },
              "createAlbum": {
                "appliesTo" : {
                  "resourceTypes": ["Account", "Album"],
                  "principalTypes": ["User"]
                },
                "memberOf": [{"id": "readWrite"}]
              },
              "addPhotoToAlbum": {
                "appliesTo" : {
                  "resourceTypes": ["Album"],
                  "principalTypes": ["User"]
                },
                "memberOf": [{"id": "readWrite"}]
              },
              "viewPhoto": {
                "appliesTo" : {
                  "resourceTypes": ["Photo"],
                  "principalTypes": ["User"]
                },
                "memberOf": [{"id": "readOnly"}, {"id": "readWrite"}]
              },
              "viewComments": {
                "appliesTo" : {
                  "resourceTypes": ["Photo"],
                  "principalTypes": ["User"]
                },
                "memberOf": [{"id": "readOnly"}, {"id": "readWrite"}]
              }
            }
          });
        let schema_file: NamespaceDefinition = serde_json::from_value(src).expect("Parse Error");

        assert_eq!(schema_file.entity_types.len(), 5);
        assert_eq!(schema_file.actions.len(), 6);
    }

    #[test]
    fn test_parse_namespaces() {
        let src = r#"
        {
            "foo::foo::bar::baz": {
                "entityTypes": {},
                "actions": {}
            }
        }"#;
        let schema: SchemaFragment = serde_json::from_str(src).expect("Parse Error");
        let (namespace, _descriptor) = schema.0.into_iter().next().unwrap();
        assert_eq!(namespace, "foo::foo::bar::baz".to_string());
    }

    #[test]
    #[should_panic(expected = "unknown field `requiredddddd`")]
    fn test_schema_file_with_misspelled_required() {
        let src = serde_json::json!(
        {
            "entityTypes": {
                "User": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "favorite": {
                                "type": "Entity",
                                "name": "Photo",
                                "requiredddddd": false
                            }
                        }
                    }
                }
            },
            "actions": {}
        });
        let schema: NamespaceDefinition = serde_json::from_value(src).unwrap();
        println!("{:#?}", schema);
    }

    #[test]
    #[should_panic(expected = "unknown field `nameeeeee`")]
    fn test_schema_file_with_misspelled_field() {
        let src = serde_json::json!(
        {
            "entityTypes": {
                "User": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "favorite": {
                                "type": "Entity",
                                "nameeeeee": "Photo",
                            }
                        }
                    }
                }
            },
            "actions": {}
        });
        let schema: NamespaceDefinition = serde_json::from_value(src).unwrap();
        println!("{:#?}", schema);
    }

    #[test]
    #[should_panic(expected = "unknown field `extra`")]
    fn test_schema_file_with_extra_field() {
        let src = serde_json::json!(
        {
            "entityTypes": {
                "User": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "favorite": {
                                "type": "Entity",
                                "name": "Photo",
                                "extra": "Should not exist"
                            }
                        }
                    }
                }
            },
            "actions": {}
        });
        let schema: NamespaceDefinition = serde_json::from_value(src).unwrap();
        println!("{:#?}", schema);
    }

    #[test]
    #[should_panic(expected = "unknown field `memberOfTypes`")]
    fn test_schema_file_with_misplaced_field() {
        let src = serde_json::json!(
        {
            "entityTypes": {
                "User": {
                    "shape": {
                        "memberOfTypes": [],
                        "type": "Record",
                        "attributes": {
                            "favorite": {
                                "type": "Entity",
                                "name": "Photo",
                            }
                        }
                    }
                }
            },
            "actions": {}
        });
        let schema: NamespaceDefinition = serde_json::from_value(src).unwrap();
        println!("{:#?}", schema);
    }

    #[test]
    #[should_panic(expected = "missing field `name`")]
    fn schema_file_with_missing_field() {
        let src = serde_json::json!(
        {
            "entityTypes": {
                "User": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "favorite": {
                                "type": "Entity",
                            }
                        }
                    }
                }
            },
            "actions": {}
        });
        let schema: NamespaceDefinition = serde_json::from_value(src).unwrap();
        println!("{:#?}", schema);
    }

    #[test]
    #[should_panic(expected = "missing field `type`")]
    fn schema_file_with_missing_type() {
        let src = serde_json::json!(
        {
            "entityTypes": {
                "User": {
                    "shape": { }
                }
            },
            "actions": {}
        });
        let schema: NamespaceDefinition = serde_json::from_value(src).unwrap();
        println!("{:#?}", schema);
    }
}
