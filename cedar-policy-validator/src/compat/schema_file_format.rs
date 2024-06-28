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

use cedar_policy_core::{
    ast::{Id, Name},
    entities::CedarValueJson,
    FromNormalizedStr,
};
use serde::{ser::SerializeMap, Deserialize, Deserializer, Serialize, Serializer};
use serde_with::serde_as;
use smol_str::{SmolStr, ToSmolStr};
use std::{collections::HashMap, fmt::Display};

use crate::{
    err::{schema_errors::*, Result},
    human_schema::fmt::ToHumanSchemaSyntaxError,
    schema_file_format::DEFAULT_CEDAR_TYPE,
    RawName,
};

use crate::schema_file_format as current;

/// A [`SchemaFragment`] is split into multiple namespace definitions, and is just
/// a map from namespace name to namespace definition (i.e., definitions of
/// common types, entity types, and actions in that namespace).
/// The namespace name is implicitly applied to all definitions in the
/// corresponding [`NamespaceDefinition`].
/// See [`NamespaceDefinition`].
///
/// The parameter `N` is the type of entity type names and common type names in
/// attributes/parents fields in this [`SchemaFragment`], including
/// recursively. (It doesn't affect the type of common and entity type names
/// _that are being declared here_, which is always an [`Id`] and unambiguously
/// refers to the [`Name`] with the appropriate implicit namespace prepended.)
/// For example:
/// - `N` = [`RawName`]: This is the schema JSON format exposed to users
/// - `N` = [`Name`]: a [`SchemaFragment`] in which all names have been
///     resolved into fully-qualified [`Name`]s
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[serde(transparent)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct SchemaFragment<N>(
    #[serde(deserialize_with = "deserialize_schema_fragment")]
    #[cfg_attr(feature = "wasm", tsify(type = "Record<string, NamespaceDefinition>"))]
    pub HashMap<Option<Name>, NamespaceDefinition<N>>,
);

impl From<SchemaFragment<Name>> for current::SchemaFragment<Name> {
    fn from(value: SchemaFragment<Name>) -> Self {
        Self(
            value
                .0
                .into_iter()
                .map(|(name, namespace)| (name, namespace.into()))
                .collect(),
        )
    }
}

impl From<SchemaFragment<RawName>> for current::SchemaFragment<RawName> {
    fn from(value: SchemaFragment<RawName>) -> Self {
        Self(
            value
                .0
                .into_iter()
                .map(|(name, namespace)| (name, namespace.into()))
                .collect(),
        )
    }
}

/// Custom deserializer to ensure that the empty namespace is mapped to `None`
fn deserialize_schema_fragment<'de, D, N: Deserialize<'de> + From<RawName>>(
    deserializer: D,
) -> std::result::Result<HashMap<Option<Name>, NamespaceDefinition<N>>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: HashMap<SmolStr, NamespaceDefinition<N>> =
        serde_with::rust::maps_duplicate_key_is_error::deserialize(deserializer)?;
    Ok(HashMap::from_iter(
        raw.into_iter()
            .map(|(key, value)| {
                let key = if key.is_empty() {
                    None
                } else {
                    Some(Name::from_normalized_str(&key).map_err(|err| {
                        serde::de::Error::custom(format!("invalid namespace `{key}`: {err}"))
                    })?)
                };
                Ok((key, value))
            })
            .collect::<std::result::Result<Vec<(Option<Name>, NamespaceDefinition<N>)>, D::Error>>(
            )?,
    ))
}

impl<N: Serialize> Serialize for SchemaFragment<N> {
    /// Custom serializer to ensure that `None` is mapped to the empty namespace
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            let k: SmolStr = match k {
                None => "".into(),
                Some(name) => name.to_smolstr(),
            };
            map.serialize_entry(&k, &v)?;
        }
        map.end()
    }
}

impl SchemaFragment<RawName> {
    /// Create a [`SchemaFragment`] from a string containing JSON (which should
    /// be an object of the appropriate shape).
    pub fn from_json_str(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| JsonDeserializationError::new(e, Some(json)).into())
    }

    /// Create a [`SchemaFragment`] from a JSON value (which should be an object
    /// of the appropriate shape).
    pub fn from_json_value(json: serde_json::Value) -> Result<Self> {
        serde_json::from_value(json).map_err(|e| JsonDeserializationError::new(e, None).into())
    }

    /// Create a [`SchemaFragment`] directly from a file containing a JSON object.
    pub fn from_file(file: impl std::io::Read) -> Result<Self> {
        serde_json::from_reader(file).map_err(|e| JsonDeserializationError::new(e, None).into())
    }
}

impl<N: Display> SchemaFragment<N> {
    /// Pretty print this [`SchemaFragment`]
    pub fn as_natural_schema(&self) -> std::result::Result<String, ToHumanSchemaSyntaxError> {
        todo!()
        // let src = human_schema::fmt::json_schema_to_custom_schema_str(self)?;
        // Ok(src)
    }
}

/// A single namespace definition from a SchemaFragment.
/// This is composed of common types, entity types, and action definitions.
///
/// The parameter `N` is the type of entity type names and common type names in
/// attributes/parents fields in this [`NamespaceDefinition`], including
/// recursively. (It doesn't affect the type of common and entity type names
/// _that are being declared here_, which is always an `Id` and unambiguously
/// refers to the `Name` with the implicit current/active namespace prepended.)
/// See notes on [`SchemaFragment`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde_as]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[serde(bound(serialize = "N: Serialize"))]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
#[doc(hidden)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct NamespaceDefinition<N> {
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    pub common_types: HashMap<Id, current::SchemaType<N>>,
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    pub entity_types: HashMap<Id, EntityType<N>>,
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    pub actions: HashMap<SmolStr, ActionType<N>>,
}

impl From<NamespaceDefinition<Name>> for current::NamespaceDefinition<Name> {
    fn from(value: NamespaceDefinition<Name>) -> Self {
        Self {
            common_types: value
                .common_types
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            entity_types: value
                .entity_types
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            actions: value
                .actions
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}

impl From<NamespaceDefinition<RawName>> for current::NamespaceDefinition<RawName> {
    fn from(value: NamespaceDefinition<RawName>) -> Self {
        Self {
            common_types: value
                .common_types
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            entity_types: value
                .entity_types
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            actions: value
                .actions
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}

impl<N> NamespaceDefinition<N> {
    pub fn new(
        entity_types: impl IntoIterator<Item = (Id, EntityType<N>)>,
        actions: impl IntoIterator<Item = (SmolStr, ActionType<N>)>,
    ) -> Self {
        Self {
            common_types: HashMap::new(),
            entity_types: entity_types.into_iter().collect(),
            actions: actions.into_iter().collect(),
        }
    }
}

impl NamespaceDefinition<RawName> {
    /// Prefix unqualified entity and common type references with the namespace they are in
    pub fn qualify_type_references(self, ns: Option<&Name>) -> NamespaceDefinition<Name> {
        NamespaceDefinition {
            common_types: self
                .common_types
                .into_iter()
                .map(|(k, v)| (k, v.qualify_type_references(ns)))
                .collect(),
            entity_types: self
                .entity_types
                .into_iter()
                .map(|(k, v)| (k, v.qualify_type_references(ns)))
                .collect(),
            actions: self
                .actions
                .into_iter()
                .map(|(k, v)| (k, v.qualify_type_references(ns)))
                .collect(),
        }
    }
}

/// Represents the full definition of an entity type in the schema.
/// Entity types describe the relationships in the entity store, including what
/// entities can be members of groups of what types, and what attributes
/// can/should be included on entities of each type.
///
/// The parameter `N` is the type of entity type names and common type names in
/// this [`EntityType`], including recursively.
/// See notes on [`SchemaFragment`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct EntityType<N> {
    /// Entities of this [`EntityType`] are allowed to be members of entities of
    /// these types.
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub member_of_types: Vec<N>,
    /// Description of the attributes for entities of this [`EntityType`].
    #[serde(default)]
    #[serde(skip_serializing_if = "current::AttributesOrContext::is_empty_record")]
    pub shape: current::AttributesOrContext<N>,
}

impl From<EntityType<Name>> for current::EntityType<Name> {
    fn from(value: EntityType<Name>) -> Self {
        Self {
            member_of_types: value.member_of_types,
            shape: value.shape.into(),
        }
    }
}

impl From<EntityType<RawName>> for current::EntityType<RawName> {
    fn from(value: EntityType<RawName>) -> Self {
        Self {
            member_of_types: value.member_of_types,
            shape: value.shape.into(),
        }
    }
}

impl EntityType<RawName> {
    /// Prefix unqualified entity and common type references with the namespace they are in
    pub fn qualify_type_references(self, ns: Option<&Name>) -> EntityType<Name> {
        EntityType {
            member_of_types: self
                .member_of_types
                .into_iter()
                .map(|rname| rname.qualify_with(ns))
                .collect(),
            shape: self.shape.qualify_type_references(ns),
        }
    }
}

/// An [`ActionType`] describes a specific action entity.
/// It also describes what principals/resources/contexts are valid for the
/// action.
///
/// The parameter `N` is the type of entity type names and common type names in
/// this [`ActionType`], including recursively.
/// See notes on [`SchemaFragment`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct ActionType<N> {
    /// This maps attribute names to
    /// `cedar_policy_core::entities::CedarValueJson` which is the
    /// canonical representation of a cedar value as JSON.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<SmolStr, CedarValueJson>>,
    /// Describes what principals/resources/contexts are valid for this action.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applies_to: Option<ApplySpec<N>>,
    /// Which actions are parents of this action.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_of: Option<Vec<current::ActionEntityUID<N>>>,
}

impl From<ActionType<Name>> for current::ActionType<Name> {
    fn from(value: ActionType<Name>) -> Self {
        Self {
            attributes: value.attributes.map(|v| v.into_iter().collect()),
            applies_to: value
                .applies_to
                .map(|v| Some(v.into()))
                .unwrap_or_else(|| Some(unspecified_applies_to::<Name>().into())),
            member_of: value
                .member_of
                .map(|v| v.into_iter().map(Into::into).collect()),
        }
    }
}

fn unspecified_applies_to<T>() -> ApplySpec<T> {
    ApplySpec {
        principal_types: None,
        resource_types: None,
        context: current::AttributesOrContext::default(),
    }
}

impl From<ActionType<RawName>> for current::ActionType<RawName> {
    fn from(value: ActionType<RawName>) -> Self {
        Self {
            attributes: value.attributes.map(|v| v.into_iter().collect()),
            applies_to: value
                .applies_to
                .map(|v| Some(v.into()))
                .unwrap_or_else(|| Some(unspecified_applies_to::<RawName>().into())),
            member_of: value
                .member_of
                .map(|v| v.into_iter().map(Into::into).collect()),
        }
    }
}

impl ActionType<RawName> {
    /// Qualify type references with the namespace they are in
    pub fn qualify_type_references(self, ns: Option<&Name>) -> ActionType<Name> {
        ActionType {
            attributes: self.attributes,
            applies_to: self.applies_to.map(|v| v.qualify_type_references(ns)),
            member_of: self.member_of.map(|v| {
                v.into_iter()
                    .map(|v| v.qualify_type_references(ns))
                    .collect()
            }),
        }
    }
}

/// The apply spec specifies what principals and resources an action can be used
/// with.  This specification can either be done through containing to entity
/// types.
/// An empty list is interpreted as specifying that there are no principals or
/// resources that an action applies to.
///
/// The parameter `N` is the type of entity type names and common type names in
/// this [`ApplySpec`], including recursively.
/// See notes on [`SchemaFragment`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct ApplySpec<N> {
    /// Resource types that are valid for the action
    #[serde(default)]
    pub resource_types: Option<Vec<N>>,
    /// Principal types that are valid for the action
    #[serde(default)]
    pub principal_types: Option<Vec<N>>,
    /// Context type that this action expects
    #[serde(default)]
    #[serde(skip_serializing_if = "current::AttributesOrContext::is_empty_record")]
    pub context: current::AttributesOrContext<N>,
}

impl From<ApplySpec<Name>> for current::ApplySpec<Name> {
    fn from(value: ApplySpec<Name>) -> Self {
        Self {
            resource_types: value
                .resource_types
                .unwrap_or_else(|| vec![DEFAULT_CEDAR_TYPE.clone()]),
            principal_types: value
                .principal_types
                .unwrap_or_else(|| vec![DEFAULT_CEDAR_TYPE.clone()]),
            context: value.context,
        }
    }
}

impl From<ApplySpec<RawName>> for current::ApplySpec<RawName> {
    fn from(value: ApplySpec<RawName>) -> Self {
        Self {
            resource_types: value
                .resource_types
                .unwrap_or_else(|| vec![RawName::from_name(DEFAULT_CEDAR_TYPE.clone())]),
            principal_types: value
                .principal_types
                .unwrap_or_else(|| vec![RawName::from_name(DEFAULT_CEDAR_TYPE.clone())]),
            context: value.context,
        }
    }
}

impl ApplySpec<RawName> {
    /// Qualify type references with the namespace they are in
    pub fn qualify_type_references(self, ns: Option<&Name>) -> ApplySpec<Name> {
        ApplySpec {
            resource_types: self
                .resource_types
                .map(|v| v.into_iter().map(|rname| rname.qualify_with(ns)).collect()),
            principal_types: self
                .principal_types
                .map(|v| v.into_iter().map(|rname| rname.qualify_with(ns)).collect()),
            context: self.context.qualify_type_references(ns),
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use cedar_policy_core::{
        extensions::Extensions,
        test_utils::{expect_err, ExpectedErrorMessageBuilder},
    };
    use cool_asserts::assert_matches;

    use crate::ValidatorSchema;
    use current::{AttributesOrContext, SchemaType, SchemaTypeVariant};
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn test_entity_type_parser1() {
        let user = r#"
        {
            "memberOfTypes" : ["UserGroup"]
        }
        "#;
        let et = serde_json::from_str::<EntityType<RawName>>(user).expect("Parse Error");
        assert_eq!(et.member_of_types, vec!["UserGroup".parse().unwrap()]);
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
        let et = serde_json::from_str::<EntityType<RawName>>(src).expect("Parse Error");
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
        let at: ActionType<RawName> = serde_json::from_str(src).expect("Parse Error");
        let spec = ApplySpec {
            resource_types: Some(vec!["Album".parse().unwrap()]),
            principal_types: Some(vec!["User".parse().unwrap()]),
            context: AttributesOrContext::default(),
        };
        assert_eq!(at.applies_to, Some(spec));
        assert_eq!(
            at.member_of,
            Some(vec![current::ActionEntityUID {
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
        let at: ActionType<RawName> = serde_json::from_str(src).expect("Parse Error");
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
        let schema_file: NamespaceDefinition<RawName> =
            serde_json::from_value(src).expect("Parse Error");

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
        let schema: SchemaFragment<RawName> = serde_json::from_str(src).expect("Parse Error");
        let (namespace, _descriptor) = schema.0.into_iter().next().unwrap();
        assert_eq!(namespace, Some("foo::foo::bar::baz".parse().unwrap()));
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
        let schema: NamespaceDefinition<RawName> = serde_json::from_value(src).unwrap();
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
        let schema: NamespaceDefinition<RawName> = serde_json::from_value(src).unwrap();
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
        let schema: NamespaceDefinition<RawName> = serde_json::from_value(src).unwrap();
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
        let schema: NamespaceDefinition<RawName> = serde_json::from_value(src).unwrap();
        println!("{:#?}", schema);
    }

    #[test]
    fn schema_file_with_missing_field() {
        let src = serde_json::json!(
        {
            "": {
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
            }
        });
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"undeclared common type: Entity"#)
                    .help("any common types used in entity or context attributes need to be declared in `commonTypes`")
                    .build());
        });
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
        let schema: NamespaceDefinition<RawName> = serde_json::from_value(src).unwrap();
        println!("{:#?}", schema);
    }

    #[test]
    #[should_panic(expected = "unknown field `attributes`")]
    fn schema_file_unexpected_malformed_attribute() {
        let src = serde_json::json!(
        {
            "entityTypes": {
                "User": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                                "attributes": {
                                    "b": {"foo": "bar"}
                                }
                            }
                        }
                    }
                }
            },
            "actions": {}
        });
        let schema: NamespaceDefinition<RawName> = serde_json::from_value(src).unwrap();
        println!("{:#?}", schema);
    }

    #[test]
    fn missing_namespace() {
        let src = r#"
        {
            "entityTypes": { "User": { } },
            "actions": {}
        }"#;
        let schema = ValidatorSchema::from_str(src);
        assert_matches!(schema, Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"failed to parse schema in JSON format: unknown field `User`, expected one of `commonTypes`, `entityTypes`, `actions` at line 3 column 35"#)
                    .help("JSON formatted schema must specify a namespace. If you want to use the empty namespace, explicitly specify it with `{ \"\": {..} }`")
                    .build());
        });
    }
}

/// Tests related to PR #749
#[cfg(test)]
mod strengthened_types {
    use cool_asserts::assert_matches;

    use crate::{
        ActionEntityUID, ApplySpec, EntityType, NamespaceDefinition, RawName, SchemaFragment,
        SchemaType,
    };

    /// Assert that `result` is an `Err`, and the error message matches `msg`
    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_error_matches<T: std::fmt::Debug>(result: Result<T, serde_json::Error>, msg: &str) {
        assert_matches!(result, Err(err) => assert_eq!(&err.to_string(), msg));
    }

    #[test]
    fn invalid_namespace() {
        let src = serde_json::json!(
        {
           "\n" : {
            "entityTypes": {},
            "actions": {}
           }
        });
        let schema: Result<SchemaFragment<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid namespace `\n`: unexpected end of input");

        let src = serde_json::json!(
        {
           "1" : {
            "entityTypes": {},
            "actions": {}
           }
        });
        let schema: Result<SchemaFragment<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid namespace `1`: unexpected token `1`");

        let src = serde_json::json!(
        {
           "*1" : {
            "entityTypes": {},
            "actions": {}
           }
        });
        let schema: Result<SchemaFragment<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid namespace `*1`: unexpected token `*`");

        let src = serde_json::json!(
        {
           "::" : {
            "entityTypes": {},
            "actions": {}
           }
        });
        let schema: Result<SchemaFragment<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid namespace `::`: unexpected token `::`");

        let src = serde_json::json!(
        {
           "A::" : {
            "entityTypes": {},
            "actions": {}
           }
        });
        let schema: Result<SchemaFragment<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid namespace `A::`: unexpected end of input");
    }

    #[test]
    fn invalid_common_type() {
        let src = serde_json::json!(
        {
            "entityTypes": {},
            "actions": {},
            "commonTypes": {
                "" : {
                    "type": "String"
                }
            }
        });
        let schema: Result<NamespaceDefinition<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid id ``: unexpected end of input");

        let src = serde_json::json!(
        {
            "entityTypes": {},
            "actions": {},
            "commonTypes": {
                "~" : {
                    "type": "String"
                }
            }
        });
        let schema: Result<NamespaceDefinition<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid id `~`: invalid token");

        let src = serde_json::json!(
        {
            "entityTypes": {},
            "actions": {},
            "commonTypes": {
                "A::B" : {
                    "type": "String"
                }
            }
        });
        let schema: Result<NamespaceDefinition<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid id `A::B`: unexpected token `::`");
    }

    #[test]
    fn invalid_entity_type() {
        let src = serde_json::json!(
        {
            "entityTypes": {
                "": {}
            },
            "actions": {}
        });
        let schema: Result<NamespaceDefinition<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid id ``: unexpected end of input");

        let src = serde_json::json!(
        {
            "entityTypes": {
                "*": {}
            },
            "actions": {}
        });
        let schema: Result<NamespaceDefinition<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid id `*`: unexpected token `*`");

        let src = serde_json::json!(
        {
            "entityTypes": {
                "A::B": {}
            },
            "actions": {}
        });
        let schema: Result<NamespaceDefinition<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid id `A::B`: unexpected token `::`");
    }

    #[test]
    fn invalid_member_of_types() {
        let src = serde_json::json!(
        {
           "memberOfTypes": [""]
        });
        let schema: Result<EntityType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid name ``: unexpected end of input");

        let src = serde_json::json!(
        {
           "memberOfTypes": ["*"]
        });
        let schema: Result<EntityType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid name `*`: unexpected token `*`");

        let src = serde_json::json!(
        {
           "memberOfTypes": ["A::"]
        });
        let schema: Result<EntityType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid name `A::`: unexpected end of input");

        let src = serde_json::json!(
        {
           "memberOfTypes": ["::A"]
        });
        let schema: Result<EntityType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid name `::A`: unexpected token `::`");
    }

    #[test]
    fn invalid_apply_spec() {
        let src = serde_json::json!(
        {
           "resourceTypes": [""]
        });
        let schema: Result<ApplySpec<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid name ``: unexpected end of input");

        let src = serde_json::json!(
        {
           "resourceTypes": ["*"]
        });
        let schema: Result<ApplySpec<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid name `*`: unexpected token `*`");

        let src = serde_json::json!(
        {
           "resourceTypes": ["A::"]
        });
        let schema: Result<ApplySpec<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid name `A::`: unexpected end of input");

        let src = serde_json::json!(
        {
           "resourceTypes": ["::A"]
        });
        let schema: Result<ApplySpec<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid name `::A`: unexpected token `::`");
    }

    #[test]
    fn invalid_schema_entity_types() {
        let src = serde_json::json!(
        {
           "type": "Entity",
            "name": ""
        });
        let schema: Result<SchemaType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid entity type ``: unexpected end of input");

        let src = serde_json::json!(
        {
           "type": "Entity",
            "name": "*"
        });
        let schema: Result<SchemaType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid entity type `*`: unexpected token `*`");

        let src = serde_json::json!(
        {
           "type": "Entity",
            "name": "::A"
        });
        let schema: Result<SchemaType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid entity type `::A`: unexpected token `::`");

        let src = serde_json::json!(
        {
           "type": "Entity",
            "name": "A::"
        });
        let schema: Result<SchemaType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid entity type `A::`: unexpected end of input");
    }

    #[test]
    fn invalid_action_euid() {
        let src = serde_json::json!(
        {
           "id": "action",
            "type": ""
        });
        let schema: Result<ActionEntityUID<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid name ``: unexpected end of input");

        let src = serde_json::json!(
        {
           "id": "action",
            "type": "*"
        });
        let schema: Result<ActionEntityUID<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid name `*`: unexpected token `*`");

        let src = serde_json::json!(
        {
           "id": "action",
            "type": "Action::"
        });
        let schema: Result<ActionEntityUID<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid name `Action::`: unexpected end of input");

        let src = serde_json::json!(
        {
           "id": "action",
            "type": "::Action"
        });
        let schema: Result<ActionEntityUID<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid name `::Action`: unexpected token `::`");
    }

    #[test]
    fn invalid_schema_common_types() {
        let src = serde_json::json!(
        {
           "type": ""
        });
        let schema: Result<SchemaType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid common type ``: unexpected end of input");

        let src = serde_json::json!(
        {
           "type": "*"
        });
        let schema: Result<SchemaType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid common type `*`: unexpected token `*`");

        let src = serde_json::json!(
        {
           "type": "::A"
        });
        let schema: Result<SchemaType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid common type `::A`: unexpected token `::`");

        let src = serde_json::json!(
        {
           "type": "A::"
        });
        let schema: Result<SchemaType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid common type `A::`: unexpected end of input");
    }

    #[test]
    fn invalid_schema_extension_types() {
        let src = serde_json::json!(
        {
           "type": "Extension",
           "name": ""
        });
        let schema: Result<SchemaType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid extension type ``: unexpected end of input");

        let src = serde_json::json!(
        {
            "type": "Extension",
           "name": "*"
        });
        let schema: Result<SchemaType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid extension type `*`: unexpected token `*`");

        let src = serde_json::json!(
        {
            "type": "Extension",
           "name": "__cedar::decimal"
        });
        let schema: Result<SchemaType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(
            schema,
            "invalid extension type `__cedar::decimal`: unexpected token `::`",
        );

        let src = serde_json::json!(
        {
            "type": "Extension",
           "name": "__cedar::"
        });
        let schema: Result<SchemaType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(
            schema,
            "invalid extension type `__cedar::`: unexpected token `::`",
        );

        let src = serde_json::json!(
        {
            "type": "Extension",
           "name": "::__cedar"
        });
        let schema: Result<SchemaType<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(
            schema,
            "invalid extension type `::__cedar`: unexpected token `::`",
        );
    }
}

/// Check that (de)serialization works as expected.
#[cfg(test)]
mod test_json_roundtrip {
    use super::*;
    use current::{AttributesOrContext, SchemaType, SchemaTypeVariant};
    use std::collections::BTreeMap;

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn roundtrip(schema: SchemaFragment<RawName>) {
        let json = serde_json::to_value(schema.clone()).unwrap();
        let new_schema: SchemaFragment<RawName> = serde_json::from_value(json).unwrap();
        assert_eq!(schema, new_schema);
    }

    #[test]
    fn empty_namespace() {
        let fragment = SchemaFragment(HashMap::from([(
            None,
            NamespaceDefinition {
                common_types: HashMap::new(),
                entity_types: HashMap::new(),
                actions: HashMap::new(),
            },
        )]));
        roundtrip(fragment);
    }

    #[test]
    fn nonempty_namespace() {
        let fragment = SchemaFragment(HashMap::from([(
            Some("a".parse().unwrap()),
            NamespaceDefinition {
                common_types: HashMap::new(),
                entity_types: HashMap::new(),
                actions: HashMap::new(),
            },
        )]));
        roundtrip(fragment);
    }

    #[test]
    fn nonempty_entity_types() {
        let fragment = SchemaFragment(HashMap::from([(
            None,
            NamespaceDefinition {
                common_types: HashMap::new(),
                entity_types: HashMap::from([(
                    "a".parse().unwrap(),
                    EntityType {
                        member_of_types: vec!["a".parse().unwrap()],
                        shape: AttributesOrContext(SchemaType::Type(SchemaTypeVariant::Record {
                            attributes: BTreeMap::new(),
                            additional_attributes: false,
                        })),
                    },
                )]),
                actions: HashMap::from([(
                    "action".into(),
                    ActionType {
                        attributes: None,
                        applies_to: Some(ApplySpec {
                            resource_types: Some(vec!["a".parse().unwrap()]),
                            principal_types: Some(vec!["a".parse().unwrap()]),
                            context: AttributesOrContext(SchemaType::Type(
                                SchemaTypeVariant::Record {
                                    attributes: BTreeMap::new(),
                                    additional_attributes: false,
                                },
                            )),
                        }),
                        member_of: None,
                    },
                )]),
            },
        )]));
        roundtrip(fragment);
    }

    #[test]
    fn multiple_namespaces() {
        let fragment = SchemaFragment(HashMap::from([
            (
                Some("foo".parse().unwrap()),
                NamespaceDefinition {
                    common_types: HashMap::new(),
                    entity_types: HashMap::from([(
                        "a".parse().unwrap(),
                        EntityType {
                            member_of_types: vec!["a".parse().unwrap()],
                            shape: AttributesOrContext(SchemaType::Type(
                                SchemaTypeVariant::Record {
                                    attributes: BTreeMap::new(),
                                    additional_attributes: false,
                                },
                            )),
                        },
                    )]),
                    actions: HashMap::new(),
                },
            ),
            (
                None,
                NamespaceDefinition {
                    common_types: HashMap::new(),
                    entity_types: HashMap::new(),
                    actions: HashMap::from([(
                        "action".into(),
                        ActionType {
                            attributes: None,
                            applies_to: Some(ApplySpec {
                                resource_types: Some(vec!["foo::a".parse().unwrap()]),
                                principal_types: Some(vec!["foo::a".parse().unwrap()]),
                                context: AttributesOrContext(SchemaType::Type(
                                    SchemaTypeVariant::Record {
                                        attributes: BTreeMap::new(),
                                        additional_attributes: false,
                                    },
                                )),
                            }),
                            member_of: None,
                        },
                    )]),
                },
            ),
        ]));
        roundtrip(fragment);
    }
}

/// Tests in this module check the behavior of schema parsing given duplicate
/// map keys. The `json!` macro silently drops duplicate keys before they reach
/// our parser, so these tests must be written with `serde_json::from_str`
/// instead.
#[cfg(test)]
mod test_duplicates_error {
    use super::*;

    #[test]
    #[should_panic(expected = "invalid entry: found duplicate key")]
    fn namespace() {
        let src = r#"{
            "Foo": {
              "entityTypes" : {},
              "actions": {}
            },
            "Foo": {
              "entityTypes" : {},
              "actions": {}
            }
        }"#;
        serde_json::from_str::<SchemaFragment<RawName>>(src).unwrap();
    }

    #[test]
    #[should_panic(expected = "invalid entry: found duplicate key")]
    fn entity_type() {
        let src = r#"{
            "Foo": {
              "entityTypes" : {
                "Bar": {},
                "Bar": {},
              },
              "actions": {}
            }
        }"#;
        serde_json::from_str::<SchemaFragment<RawName>>(src).unwrap();
    }

    #[test]
    #[should_panic(expected = "invalid entry: found duplicate key")]
    fn action() {
        let src = r#"{
            "Foo": {
              "entityTypes" : {},
              "actions": {
                "Bar": {},
                "Bar": {}
              }
            }
        }"#;
        serde_json::from_str::<SchemaFragment<RawName>>(src).unwrap();
    }

    #[test]
    #[should_panic(expected = "invalid entry: found duplicate key")]
    fn common_types() {
        let src = r#"{
            "Foo": {
              "entityTypes" : {},
              "actions": { },
              "commonTypes": {
                "Bar": {"type": "Long"},
                "Bar": {"type": "String"}
              }
            }
        }"#;
        serde_json::from_str::<SchemaFragment<RawName>>(src).unwrap();
    }

    #[test]
    #[should_panic(expected = "invalid entry: found duplicate key")]
    fn record_type() {
        let src = r#"{
            "Foo": {
              "entityTypes" : {
                "Bar": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "Baz": {"type": "Long"},
                            "Baz": {"type": "String"}
                        }
                    }
                }
              },
              "actions": { }
            }
        }"#;
        serde_json::from_str::<SchemaFragment<RawName>>(src).unwrap();
    }
}

#[cfg(test)]
mod back_compat {
    use super::*;
    #[test]
    fn test_parse() {
        let src = r#"{
            "Foo": {
              "entityTypes" : {},
              "actions": {
                "Bar": {
                    "appliesTo": {
                    }
                },
                "Baz": {
                    "appliesTo": {
                        "resourceTypes": ["a", "b"]
                    }
                },
                "Another": {
                    "appliesTo": {
                        "principalTypes": ["a", "b"]
                    }
                }
              }
            }
        }"#;
        let schema = serde_json::from_str::<SchemaFragment<RawName>>(src).unwrap();
        let c: current::SchemaFragment<RawName> = schema.into();
        let namespace = c.0.get(&Some("Foo".parse().unwrap())).unwrap();
        let action = namespace.actions.get("Bar").unwrap();
        let applies_to = action.applies_to.as_ref().unwrap();
        assert_eq!(applies_to.principal_types.len(), 1);
        assert!(applies_to
            .principal_types
            .contains(&RawName::from_name(DEFAULT_CEDAR_TYPE.clone())));
        assert_eq!(applies_to.resource_types.len(), 1);
        assert!(applies_to
            .resource_types
            .contains(&RawName::from_name(DEFAULT_CEDAR_TYPE.clone())));

        let action = namespace.actions.get("Another").unwrap();
        let applies_to = action.applies_to.as_ref().unwrap();
        assert_eq!(applies_to.principal_types.len(), 2);
        assert!(applies_to.principal_types.contains(&"a".parse().unwrap()));
        assert!(applies_to.principal_types.contains(&"b".parse().unwrap()));
        assert_eq!(applies_to.resource_types.len(), 1);
        assert!(applies_to
            .resource_types
            .contains(&RawName::from_name(DEFAULT_CEDAR_TYPE.clone())));

        let action = namespace.actions.get("Baz").unwrap();
        let applies_to = action.applies_to.as_ref().unwrap();
        assert_eq!(applies_to.resource_types.len(), 2);
        assert!(applies_to.resource_types.contains(&"a".parse().unwrap()));
        assert!(applies_to.resource_types.contains(&"b".parse().unwrap()));
        assert_eq!(applies_to.principal_types.len(), 1);
        assert!(applies_to
            .principal_types
            .contains(&RawName::from_name(DEFAULT_CEDAR_TYPE.clone())));
    }
}
