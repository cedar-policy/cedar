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

//! Structures defining the JSON syntax for Cedar schemas

use cedar_policy_core::{
    ast::{Eid, EntityUID, InternalName, Name, UnreservedId},
    entities::CedarValueJson,
    extensions::Extensions,
    FromNormalizedStr,
};
use nonempty::nonempty;
use serde::{
    de::{MapAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_with::serde_as;
use smol_str::{SmolStr, ToSmolStr};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Display,
    marker::PhantomData,
    str::FromStr,
};

use crate::{
    cedar_schema::{
        self, fmt::ToCedarSchemaSyntaxError, parser::parse_cedar_schema_fragment, SchemaWarning,
    },
    err::{schema_errors::*, Result},
    CedarSchemaError, CedarSchemaParseError, ConditionalName, RawName, ReferenceType,
};

/// A [`Fragment`] is split into multiple namespace definitions, and is just a
/// map from namespace name to namespace definition (i.e., definitions of common
/// types, entity types, and actions in that namespace).
/// The namespace name is implicitly applied to all definitions in the
/// corresponding [`NamespaceDefinition`].
/// See [`NamespaceDefinition`].
///
/// The parameter `N` is the type of entity type names and common type names in
/// attributes/parents fields in this [`Fragment`], including recursively. (It
/// doesn't affect the type of common and entity type names _that are being
/// declared here_, which is always an [`UnreservedId`] and unambiguously refers
/// to the [`InternalName`] with the appropriate implicit namespace prepended.
/// It only affects the type of common and entity type _references_.)
/// For example:
/// - `N` = [`RawName`]: This is the schema JSON format exposed to users
/// - `N` = [`ConditionalName`]: a [`Fragment`] which has been partially
///     processed, by converting [`RawName`]s into [`ConditionalName`]s
/// - `N` = [`InternalName`]: a [`Fragment`] in which all names have been
///     resolved into fully-qualified [`InternalName`]s
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[serde(transparent)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "wasm", serde(rename = "SchemaJson"))]
pub struct Fragment<N>(
    #[serde(deserialize_with = "deserialize_schema_fragment")]
    #[cfg_attr(
        feature = "wasm",
        tsify(type = "Record<string, NamespaceDefinition<N>>")
    )]
    pub HashMap<Option<Name>, NamespaceDefinition<N>>,
);

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

impl<N: Serialize> Serialize for Fragment<N> {
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

impl Fragment<RawName> {
    /// Create a [`Fragment`] from a string containing JSON (which should
    /// be an object of the appropriate shape).
    pub fn from_json_str(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| JsonDeserializationError::new(e, Some(json)).into())
    }

    /// Create a [`Fragment`] from a JSON value (which should be an object
    /// of the appropriate shape).
    pub fn from_json_value(json: serde_json::Value) -> Result<Self> {
        serde_json::from_value(json).map_err(|e| JsonDeserializationError::new(e, None).into())
    }

    /// Create a [`Fragment`] directly from a file containing a JSON object.
    pub fn from_json_file(file: impl std::io::Read) -> Result<Self> {
        serde_json::from_reader(file).map_err(|e| JsonDeserializationError::new(e, None).into())
    }

    /// Parse the schema (in the Cedar schema syntax) from a string
    pub fn from_cedarschema_str<'a>(
        src: &str,
        extensions: &Extensions<'a>,
    ) -> std::result::Result<(Self, impl Iterator<Item = SchemaWarning> + 'a), CedarSchemaError>
    {
        parse_cedar_schema_fragment(src, extensions)
            .map_err(|e| CedarSchemaParseError::new(e, src).into())
    }

    /// Parse the schema (in the Cedar schema syntax) from a reader
    pub fn from_cedarschema_file<'a>(
        mut file: impl std::io::Read,
        extensions: &'a Extensions<'_>,
    ) -> std::result::Result<(Self, impl Iterator<Item = SchemaWarning> + 'a), CedarSchemaError>
    {
        let mut src = String::new();
        file.read_to_string(&mut src)?;
        Self::from_cedarschema_str(&src, extensions)
    }
}

impl<N: Display> Fragment<N> {
    /// Pretty print this [`Fragment`]
    pub fn to_cedarschema(&self) -> std::result::Result<String, ToCedarSchemaSyntaxError> {
        let src = cedar_schema::fmt::json_schema_to_cedar_schema_str(self)?;
        Ok(src)
    }
}

/// A single namespace definition from a Fragment.
/// This is composed of common types, entity types, and action definitions.
///
/// The parameter `N` is the type of entity type names and common type names in
/// attributes/parents fields in this [`NamespaceDefinition`], including
/// recursively. (It doesn't affect the type of common and entity type names
/// _that are being declared here_, which is always an `UnreservedId` and unambiguously
/// refers to the [`InternalName`] with the implicit current/active namespace prepended.)
/// See notes on [`Fragment`].
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
    pub common_types: HashMap<UnreservedId, Type<N>>,
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    pub entity_types: HashMap<UnreservedId, EntityType<N>>,
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    pub actions: HashMap<SmolStr, ActionType<N>>,
}

impl<N> NamespaceDefinition<N> {
    pub fn new(
        entity_types: impl IntoIterator<Item = (UnreservedId, EntityType<N>)>,
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
    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> NamespaceDefinition<ConditionalName> {
        NamespaceDefinition {
            common_types: self
                .common_types
                .into_iter()
                .map(|(k, v)| (k, v.conditionally_qualify_type_references(ns)))
                .collect(),
            entity_types: self
                .entity_types
                .into_iter()
                .map(|(k, v)| (k, v.conditionally_qualify_type_references(ns)))
                .collect(),
            actions: self
                .actions
                .into_iter()
                .map(|(k, v)| (k, v.conditionally_qualify_type_references(ns)))
                .collect(),
        }
    }
}

impl NamespaceDefinition<ConditionalName> {
    /// Convert this [`NamespaceDefinition<ConditionalName>`] into a
    /// [`NamespaceDefinition<InternalName>`] by fully-qualifying all typenames
    /// that appear anywhere in any definitions.
    ///
    /// `all_common_defs` and `all_entity_defs` need to be the full set of all
    /// fully-qualified typenames (of common and entity types respectively) that
    /// are defined in the schema (in all schema fragments).
    ///
    /// `all_action_defs` needs to be the full set of all fully-qualified action
    /// EUIDs that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_common_defs: &HashSet<InternalName>,
        all_entity_defs: &HashSet<InternalName>,
        all_action_defs: &HashSet<EntityUID>,
    ) -> Result<NamespaceDefinition<InternalName>> {
        Ok(NamespaceDefinition {
            common_types: self
                .common_types
                .into_iter()
                .map(|(k, v)| {
                    Ok((
                        k,
                        v.fully_qualify_type_references(all_common_defs, all_entity_defs)?,
                    ))
                })
                .collect::<std::result::Result<_, TypeResolutionError>>()?,
            entity_types: self
                .entity_types
                .into_iter()
                .map(|(k, v)| {
                    Ok((
                        k,
                        v.fully_qualify_type_references(all_common_defs, all_entity_defs)?,
                    ))
                })
                .collect::<std::result::Result<_, TypeResolutionError>>()?,
            actions: self
                .actions
                .into_iter()
                .map(|(k, v)| {
                    Ok((
                        k,
                        v.fully_qualify_type_references(
                            all_common_defs,
                            all_entity_defs,
                            all_action_defs,
                        )?,
                    ))
                })
                .collect::<Result<_>>()?,
        })
    }
}

/// Represents the full definition of an entity type in the schema.
/// Entity types describe the relationships in the entity store, including what
/// entities can be members of groups of what types, and what attributes
/// can/should be included on entities of each type.
///
/// The parameter `N` is the type of entity type names and common type names in
/// this [`EntityType`], including recursively.
/// See notes on [`Fragment`].
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
    #[serde(skip_serializing_if = "AttributesOrContext::is_empty_record")]
    pub shape: AttributesOrContext<N>,
}

impl EntityType<RawName> {
    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> EntityType<ConditionalName> {
        EntityType {
            member_of_types: self
                .member_of_types
                .into_iter()
                .map(|rname| rname.conditionally_qualify_with(ns, ReferenceType::Entity)) // Only entity, not common, here for now; see #1064
                .collect(),
            shape: self.shape.conditionally_qualify_type_references(ns),
        }
    }
}

impl EntityType<ConditionalName> {
    /// Convert this [`EntityType<ConditionalName>`] into an
    /// [`EntityType<InternalName>`] by fully-qualifying all typenames that
    /// appear anywhere in any definitions.
    ///
    /// `all_common_defs` and `all_entity_defs` need to be the full set of all
    /// fully-qualified typenames (of common and entity types respectively) that
    /// are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_common_defs: &HashSet<InternalName>,
        all_entity_defs: &HashSet<InternalName>,
    ) -> std::result::Result<EntityType<InternalName>, TypeResolutionError> {
        Ok(EntityType {
            member_of_types: self
                .member_of_types
                .into_iter()
                .map(|cname| cname.resolve(all_common_defs, all_entity_defs).cloned())
                .collect::<std::result::Result<_, _>>()?,
            shape: self
                .shape
                .fully_qualify_type_references(all_common_defs, all_entity_defs)?,
        })
    }
}

/// Declaration of entity or record attributes, or of an action context.
/// These share a JSON format.
///
/// The parameter `N` is the type of entity type names and common type names in
/// this [`AttributesOrContext`], including recursively.
/// See notes on [`Fragment`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[serde(transparent)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct AttributesOrContext<N>(
    // We use the usual `Type` deserialization, but it will ultimately need to
    // be a `Record` or common-type reference which resolves to a `Record`.
    pub Type<N>,
);

impl<N> AttributesOrContext<N> {
    /// Convert the [`AttributesOrContext`] into its [`Type`].
    pub fn into_inner(self) -> Type<N> {
        self.0
    }

    /// Is this `AttributesOrContext` an empty record?
    pub fn is_empty_record(&self) -> bool {
        self.0.is_empty_record()
    }
}

impl<N> Default for AttributesOrContext<N> {
    fn default() -> Self {
        Self::from(RecordType::default())
    }
}

impl<N: Display> Display for AttributesOrContext<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<N> From<RecordType<N>> for AttributesOrContext<N> {
    fn from(rty: RecordType<N>) -> AttributesOrContext<N> {
        Self(Type::Type(TypeVariant::Record(rty)))
    }
}

impl AttributesOrContext<RawName> {
    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> AttributesOrContext<ConditionalName> {
        AttributesOrContext(self.0.conditionally_qualify_type_references(ns))
    }
}

impl AttributesOrContext<ConditionalName> {
    /// Convert this [`AttributesOrContext<ConditionalName>`] into an
    /// [`AttributesOrContext<InternalName>`] by fully-qualifying all typenames
    /// that appear anywhere in any definitions.
    ///
    /// `all_common_defs` and `all_entity_defs` need to be the full set of all
    /// fully-qualified typenames (of common and entity types respectively) that
    /// are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_common_defs: &HashSet<InternalName>,
        all_entity_defs: &HashSet<InternalName>,
    ) -> std::result::Result<AttributesOrContext<InternalName>, TypeResolutionError> {
        Ok(AttributesOrContext(self.0.fully_qualify_type_references(
            all_common_defs,
            all_entity_defs,
        )?))
    }
}

/// An [`ActionType`] describes a specific action entity.
/// It also describes what principals/resources/contexts are valid for the
/// action.
///
/// The parameter `N` is the type of entity type names and common type names in
/// this [`ActionType`], including recursively.
/// See notes on [`Fragment`].
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
    pub member_of: Option<Vec<ActionEntityUID<N>>>,
}

impl ActionType<RawName> {
    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> ActionType<ConditionalName> {
        ActionType {
            attributes: self.attributes,
            applies_to: self
                .applies_to
                .map(|applyspec| applyspec.conditionally_qualify_type_references(ns)),
            member_of: self.member_of.map(|v| {
                v.into_iter()
                    .map(|aeuid| aeuid.conditionally_qualify_type_references(ns))
                    .collect()
            }),
        }
    }
}

impl ActionType<ConditionalName> {
    /// Convert this [`ActionType<ConditionalName>`] into an
    /// [`ActionType<InternalName>`] by fully-qualifying all typenames that
    /// appear anywhere in any definitions.
    ///
    /// `all_common_defs` and `all_entity_defs` need to be the full set of all
    /// fully-qualified typenames (of common and entity types respectively) that
    /// are defined in the schema (in all schema fragments).
    ///
    /// `all_action_defs` needs to be the full set of all fully-qualified action
    /// EUIDs that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_common_defs: &HashSet<InternalName>,
        all_entity_defs: &HashSet<InternalName>,
        all_action_defs: &HashSet<EntityUID>,
    ) -> Result<ActionType<InternalName>> {
        Ok(ActionType {
            attributes: self.attributes,
            applies_to: self
                .applies_to
                .map(|applyspec| {
                    applyspec.fully_qualify_type_references(all_common_defs, all_entity_defs)
                })
                .transpose()?,
            member_of: self
                .member_of
                .map(|v| {
                    v.into_iter()
                        .map(|aeuid| aeuid.fully_qualify_type_references(all_action_defs))
                        .collect::<std::result::Result<_, ActionResolutionError>>()
                })
                .transpose()?,
        })
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
/// See notes on [`Fragment`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct ApplySpec<N> {
    /// Resource types that are valid for the action
    pub resource_types: Vec<N>,
    /// Principal types that are valid for the action
    pub principal_types: Vec<N>,
    /// Context type that this action expects
    #[serde(default)]
    #[serde(skip_serializing_if = "AttributesOrContext::is_empty_record")]
    pub context: AttributesOrContext<N>,
}

impl ApplySpec<RawName> {
    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> ApplySpec<ConditionalName> {
        ApplySpec {
            resource_types: self
                .resource_types
                .into_iter()
                .map(|rname| rname.conditionally_qualify_with(ns, ReferenceType::Entity)) // Only entity, not common, here for now; see #1064
                .collect(),
            principal_types: self
                .principal_types
                .into_iter()
                .map(|rname| rname.conditionally_qualify_with(ns, ReferenceType::Entity)) // Only entity, not common, here for now; see #1064
                .collect(),
            context: self.context.conditionally_qualify_type_references(ns),
        }
    }
}

impl ApplySpec<ConditionalName> {
    /// Convert this [`ApplySpec<ConditionalName>`] into an
    /// [`ApplySpec<InternalName>`] by fully-qualifying all typenames that
    /// appear anywhere in any definitions.
    ///
    /// `all_common_defs` and `all_entity_defs` need to be the full set of all
    /// fully-qualified typenames (of common and entity types respectively) that
    /// are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_common_defs: &HashSet<InternalName>,
        all_entity_defs: &HashSet<InternalName>,
    ) -> std::result::Result<ApplySpec<InternalName>, TypeResolutionError> {
        Ok(ApplySpec {
            resource_types: self
                .resource_types
                .into_iter()
                .map(|cname| cname.resolve(all_common_defs, all_entity_defs).cloned())
                .collect::<std::result::Result<_, TypeResolutionError>>()?,
            principal_types: self
                .principal_types
                .into_iter()
                .map(|cname| cname.resolve(all_common_defs, all_entity_defs).cloned())
                .collect::<std::result::Result<_, TypeResolutionError>>()?,
            context: self
                .context
                .fully_qualify_type_references(all_common_defs, all_entity_defs)?,
        })
    }
}

/// Represents the [`cedar_policy_core::ast::EntityUID`] of an action
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct ActionEntityUID<N> {
    /// Represents the [`cedar_policy_core::ast::Eid`] of the action
    pub id: SmolStr,

    /// Represents the type of the action.
    /// `None` is shorthand for `Action`.
    /// If this is `Some`, the last component of the `N` should be `Action`.
    ///
    /// INVARIANT: This can only be `None` in the `N` = `RawName` case.
    /// This invariant is upheld by all the code below that constructs
    /// `ActionEntityUID`.
    /// We also rely on `ActionEntityUID<N>` only being `Deserialize` for
    /// `N` = `RawName`, so that you can't create an `ActionEntityUID` that
    /// violates this invariant via deserialization.
    #[serde(rename = "type")]
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    ty: Option<N>,
}

impl ActionEntityUID<RawName> {
    /// Create a new `ActionEntityUID<RawName>`.
    /// `ty` = `None` is shorthand for `Action`.
    pub fn new(ty: Option<RawName>, id: SmolStr) -> Self {
        Self { id, ty }
    }

    /// Given an `id`, get the [`ActionEntityUID`] representing `Action::<id>`.
    //
    // This function is only available for `RawName` and not other values of `N`,
    // in order to uphold the INVARIANT on self.ty.
    pub fn default_type(id: SmolStr) -> Self {
        Self { id, ty: None }
    }
}

impl<N: std::fmt::Display> std::fmt::Display for ActionEntityUID<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ty) = &self.ty {
            write!(f, "{}::", ty)?
        } else {
            write!(f, "Action::")?
        }
        write!(f, "\"{}\"", self.id.escape_debug())
    }
}

impl ActionEntityUID<RawName> {
    /// (Conditionally) prefix this action entity UID's typename with the given namespace
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> ActionEntityUID<ConditionalName> {
        // Upholding the INVARIANT on ActionEntityUID.ty: constructing an `ActionEntityUID<ConditionalName>`,
        // so in the constructed `ActionEntityUID`, `.ty` must be `Some` in all cases
        ActionEntityUID {
            id: self.id,
            ty: {
                // PANIC SAFETY: this is a valid raw name
                #[allow(clippy::expect_used)]
                let raw_name = self
                    .ty
                    .unwrap_or(RawName::from_str("Action").expect("valid raw name"));
                Some(raw_name.conditionally_qualify_with(ns, ReferenceType::Entity))
            },
        }
    }

    /// Unconditionally prefix this action entity UID's typename with the given namespace
    pub fn qualify_with(self, ns: Option<&InternalName>) -> ActionEntityUID<InternalName> {
        // Upholding the INVARIANT on ActionEntityUID.ty: constructing an `ActionEntityUID<InternalName>`,
        // so in the constructed `ActionEntityUID`, `.ty` must be `Some` in all cases
        ActionEntityUID {
            id: self.id,
            ty: {
                // PANIC SAFETY: this is a valid raw name
                #[allow(clippy::expect_used)]
                let raw_name = self
                    .ty
                    .unwrap_or(RawName::from_str("Action").expect("valid raw name"));
                Some(raw_name.qualify_with(ns))
            },
        }
    }
}

impl ActionEntityUID<ConditionalName> {
    /// Get the action type, as a [`ConditionalName`].
    pub fn ty(&self) -> &ConditionalName {
        // PANIC SAFETY: by INVARIANT on self.ty
        #[allow(clippy::expect_used)]
        self.ty.as_ref().expect("by INVARIANT on self.ty")
    }

    /// Convert this [`ActionEntityUID<ConditionalName>`] into an
    /// [`ActionEntityUID<InternalName>`] by fully-qualifying its typename.
    ///
    /// `all_action_defs` needs to be the full set of all fully-qualified action
    /// EUIDs that are defined in the schema (in all schema fragments).
    /// This `ActionEntityUID<ConditionalName>` must resolve to one of the
    /// `all_action_defs` or else it throws `UndeclaredActionsError`.
    pub fn fully_qualify_type_references(
        self,
        all_action_defs: &HashSet<EntityUID>,
    ) -> std::result::Result<ActionEntityUID<InternalName>, ActionResolutionError> {
        for possibility in self.possibilities() {
            // This ignores any possibilities that aren't valid `EntityUID`,
            // because we know that all defined actions are valid `EntityUID`s
            // (because `all_action_defs` has type `&HashSet<EntityUID>`).
            if let Ok(euid) = EntityUID::try_from(possibility.clone()) {
                if all_action_defs.contains(&euid) {
                    return Ok(possibility);
                }
            }
        }
        return Err(ActionResolutionError(nonempty!(self)));
    }

    /// Get the possible fully-qualified [`ActionEntityUID<InternalName>`]s
    /// which this [`ActionEntityUID<ConditionalName>`] might resolve to, in
    /// priority order (highest-priority first).
    pub(crate) fn possibilities(&self) -> impl Iterator<Item = ActionEntityUID<InternalName>> + '_ {
        // Upholding the INVARIANT on ActionEntityUID.ty: constructing `ActionEntityUID<InternalName>`,
        // so in the constructed `ActionEntityUID`, `.ty` must be `Some` in all cases
        self.ty()
            .possibilities()
            .map(|possibility| ActionEntityUID {
                id: self.id.clone(),
                ty: Some(possibility.clone()),
            })
    }

    /// Convert this [`ActionEntityUID<ConditionalName>`] back into a [`ActionEntityUID<RawName>`].
    /// As of this writing, [`ActionEntityUID<RawName>`] has a `Display` impl while
    /// [`ActionEntityUID<ConditionalName>`] does not.
    pub(crate) fn as_raw(&self) -> ActionEntityUID<RawName> {
        ActionEntityUID {
            id: self.id.clone(),
            ty: self.ty.as_ref().map(|ty| ty.raw().clone()),
        }
    }
}

impl ActionEntityUID<Name> {
    /// Get the action type, as a [`Name`].
    pub fn ty(&self) -> &Name {
        // PANIC SAFETY: by INVARIANT on self.ty
        #[allow(clippy::expect_used)]
        self.ty.as_ref().expect("by INVARIANT on self.ty")
    }
}

impl ActionEntityUID<InternalName> {
    /// Get the action type, as an [`InternalName`].
    pub fn ty(&self) -> &InternalName {
        // PANIC SAFETY: by INVARIANT on self.ty
        #[allow(clippy::expect_used)]
        self.ty.as_ref().expect("by INVARIANT on self.ty")
    }
}

impl From<ActionEntityUID<Name>> for EntityUID {
    fn from(aeuid: ActionEntityUID<Name>) -> Self {
        EntityUID::from_components(aeuid.ty().clone().into(), Eid::new(aeuid.id), None)
    }
}

impl TryFrom<ActionEntityUID<InternalName>> for EntityUID {
    type Error = <InternalName as TryInto<Name>>::Error;
    fn try_from(aeuid: ActionEntityUID<InternalName>) -> std::result::Result<Self, Self::Error> {
        let ty = Name::try_from(aeuid.ty().clone())?;
        Ok(EntityUID::from_components(
            ty.into(),
            Eid::new(aeuid.id),
            None,
        ))
    }
}

impl From<EntityUID> for ActionEntityUID<Name> {
    fn from(euid: EntityUID) -> Self {
        let (ty, id) = euid.components();
        ActionEntityUID {
            ty: Some(ty.into()),
            id: <Eid as AsRef<SmolStr>>::as_ref(&id).clone(),
        }
    }
}

/// A restricted version of the [`crate::types::Type`] enum containing only the types
/// which are exposed to users.
///
/// The parameter `N` is the type of entity type names and common type names in
/// this [`Type`], including recursively.
/// See notes on [`Fragment`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
// This enum is `untagged` with these variants as a workaround to a serde
// limitation. It is not possible to have the known variants on one enum, and
// then, have catch-all variant for any unrecognized tag in the same enum that
// captures the name of the unrecognized tag.
#[serde(untagged)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum Type<N> {
    /// One of the standard types exposed to users.
    ///
    /// This branch also includes the "entity-or-common-type-reference" possibility.
    Type(TypeVariant<N>),
    /// Reference to a common type
    ///
    /// This is only used for references that _must_ resolve to common types.
    /// References that may resolve to either common or entity types can use
    /// `Type::Type(TypeVariant::EntityOrCommon)`.
    CommonTypeRef {
        /// Name of the common type.
        /// For the important case of `N` = [`RawName`], this is the schema JSON
        /// format, and the `RawName` is exactly how it appears in the schema;
        /// may not yet be fully qualified
        #[serde(rename = "type")]
        type_name: N,
    },
}

impl<N> Type<N> {
    /// Iterate over all references which occur in the type and (must or may)
    /// resolve to a common type
    pub(crate) fn common_type_references(&self) -> Box<dyn Iterator<Item = &N> + '_> {
        match self {
            Type::Type(TypeVariant::Record(RecordType { attributes, .. })) => attributes
                .iter()
                .map(|(_, ty)| ty.ty.common_type_references())
                .fold(Box::new(std::iter::empty()), |it, tys| {
                    Box::new(it.chain(tys))
                }),
            Type::Type(TypeVariant::Set { element }) => element.common_type_references(),
            Type::Type(TypeVariant::EntityOrCommon { type_name }) => {
                Box::new(std::iter::once(type_name))
            }
            Type::CommonTypeRef { type_name } => Box::new(std::iter::once(type_name)),
            _ => Box::new(std::iter::empty()),
        }
    }

    /// Is this [`Type`] an extension type, or does it contain one
    /// (recursively)? Returns `None` if this is a `CommonTypeRef` or
    /// `EntityOrCommon` because we can't easily check the type of a common type
    /// reference, accounting for namespaces, without first converting to a
    /// [`crate::types::Type`].
    pub fn is_extension(&self) -> Option<bool> {
        match self {
            Self::Type(TypeVariant::Extension { .. }) => Some(true),
            Self::Type(TypeVariant::Set { element }) => element.is_extension(),
            Self::Type(TypeVariant::Record(RecordType { attributes, .. })) => attributes
                .values()
                .try_fold(false, |a, e| match e.ty.is_extension() {
                    Some(true) => Some(true),
                    Some(false) => Some(a),
                    None => None,
                }),
            Self::Type(_) => Some(false),
            Self::CommonTypeRef { .. } => None,
        }
    }

    /// Is this [`Type`] an empty record? This function is used by the `Display`
    /// implementation to avoid printing unnecessary entity/action data.
    pub fn is_empty_record(&self) -> bool {
        match self {
            Self::Type(TypeVariant::Record(rty)) => rty.is_empty_record(),
            _ => false,
        }
    }
}

impl Type<RawName> {
    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> Type<ConditionalName> {
        match self {
            Self::Type(tv) => Type::Type(tv.conditionally_qualify_type_references(ns)),
            Self::CommonTypeRef { type_name } => Type::CommonTypeRef {
                type_name: type_name.conditionally_qualify_with(ns, ReferenceType::Common),
            },
        }
    }

    fn into_n<N: From<RawName>>(self) -> Type<N> {
        match self {
            Self::Type(tv) => Type::Type(tv.into_n()),
            Self::CommonTypeRef { type_name } => Type::CommonTypeRef {
                type_name: type_name.into(),
            },
        }
    }
}

impl Type<ConditionalName> {
    /// Convert this [`Type<ConditionalName>`] into a [`Type<InternalName>`] by
    /// fully-qualifying all typenames that appear anywhere in any definitions.
    ///
    /// `all_common_defs` and `all_entity_defs` need to be the full set of all
    /// fully-qualified typenames (of common and entity types respectively) that
    /// are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_common_defs: &HashSet<InternalName>,
        all_entity_defs: &HashSet<InternalName>,
    ) -> std::result::Result<Type<InternalName>, TypeResolutionError> {
        match self {
            Self::Type(tv) => Ok(Type::Type(
                tv.fully_qualify_type_references(all_common_defs, all_entity_defs)?,
            )),
            Self::CommonTypeRef { type_name } => Ok(Type::CommonTypeRef {
                type_name: type_name.resolve(all_common_defs, all_entity_defs)?.clone(),
            }),
        }
    }
}

impl<'de, N: Deserialize<'de> + From<RawName>> Deserialize<'de> for Type<N> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(TypeVisitor {
            _phantom: PhantomData,
        })
    }
}

/// The fields for a `Type`. Used for implementing deserialization.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(field_identifier, rename_all = "camelCase")]
enum TypeFields {
    Type,
    Element,
    Attributes,
    AdditionalAttributes,
    Name,
}

// This macro is used to avoid duplicating the fields names when calling
// `serde::de::Error::unknown_field`. It wants an `&'static [&'static str]`, and
// AFAIK, the elements of the static slice must be literals.
macro_rules! type_field_name {
    (Type) => {
        "type"
    };
    (Element) => {
        "element"
    };
    (Attributes) => {
        "attributes"
    };
    (AdditionalAttributes) => {
        "additionalAttributes"
    };
    (Name) => {
        "name"
    };
}

impl TypeFields {
    fn as_str(&self) -> &'static str {
        match self {
            TypeFields::Type => type_field_name!(Type),
            TypeFields::Element => type_field_name!(Element),
            TypeFields::Attributes => type_field_name!(Attributes),
            TypeFields::AdditionalAttributes => type_field_name!(AdditionalAttributes),
            TypeFields::Name => type_field_name!(Name),
        }
    }
}

/// Used during deserialization to deserialize the attributes type map while
/// reporting an error if there are any duplicate keys in the map. I could not
/// find a way to do the `serde_with` conversion inline without introducing this
/// struct.
#[derive(Deserialize)]
struct AttributesTypeMap(
    #[serde(with = "serde_with::rust::maps_duplicate_key_is_error")]
    BTreeMap<SmolStr, TypeOfAttribute<RawName>>,
);

struct TypeVisitor<N> {
    _phantom: PhantomData<N>,
}

impl<'de, N: Deserialize<'de> + From<RawName>> Visitor<'de> for TypeVisitor<N> {
    type Value = Type<N>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("builtin type or reference to type defined in commonTypes")
    }

    fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        use TypeFields::{AdditionalAttributes, Attributes, Element, Name, Type as TypeField};

        // We keep field values wrapped in a `Result` initially so that we do
        // not report errors due the contents of a field when the field is not
        // expected for a particular type variant. We instead report that the
        // field so not exist at all, so that the schema author can delete the
        // field without wasting time fixing errors in the value.
        let mut type_name: Option<std::result::Result<SmolStr, M::Error>> = None;
        let mut element: Option<std::result::Result<Type<N>, M::Error>> = None;
        let mut attributes: Option<std::result::Result<AttributesTypeMap, M::Error>> = None;
        let mut additional_attributes: Option<std::result::Result<bool, M::Error>> = None;
        let mut name: Option<std::result::Result<SmolStr, M::Error>> = None;

        // Gather all the fields in the object. Any fields that are not one of
        // the possible fields for some schema type will have been reported by
        // serde already.
        while let Some(key) = map.next_key()? {
            match key {
                TypeField => {
                    if type_name.is_some() {
                        return Err(serde::de::Error::duplicate_field(TypeField.as_str()));
                    }
                    type_name = Some(map.next_value());
                }
                Element => {
                    if element.is_some() {
                        return Err(serde::de::Error::duplicate_field(Element.as_str()));
                    }
                    element = Some(map.next_value());
                }
                Attributes => {
                    if attributes.is_some() {
                        return Err(serde::de::Error::duplicate_field(Attributes.as_str()));
                    }
                    attributes = Some(map.next_value());
                }
                AdditionalAttributes => {
                    if additional_attributes.is_some() {
                        return Err(serde::de::Error::duplicate_field(
                            AdditionalAttributes.as_str(),
                        ));
                    }
                    additional_attributes = Some(map.next_value());
                }
                Name => {
                    if name.is_some() {
                        return Err(serde::de::Error::duplicate_field(Name.as_str()));
                    }
                    name = Some(map.next_value());
                }
            }
        }

        Self::build_schema_type::<M>(type_name, element, attributes, additional_attributes, name)
    }
}

impl<'de, N: Deserialize<'de> + From<RawName>> TypeVisitor<N> {
    /// Construct a schema type given the name of the type and its fields.
    /// Fields which were not present are `None`. It is an error for a field
    /// which is not used for a particular type to be `Some` when building that
    /// type.
    fn build_schema_type<M>(
        type_name: Option<std::result::Result<SmolStr, M::Error>>,
        element: Option<std::result::Result<Type<N>, M::Error>>,
        attributes: Option<std::result::Result<AttributesTypeMap, M::Error>>,
        additional_attributes: Option<std::result::Result<bool, M::Error>>,
        name: Option<std::result::Result<SmolStr, M::Error>>,
    ) -> std::result::Result<Type<N>, M::Error>
    where
        M: MapAccess<'de>,
    {
        use TypeFields::{AdditionalAttributes, Attributes, Element, Name, Type as TypeField};
        // Fields that remain to be parsed
        let mut remaining_fields = [
            (TypeField, type_name.is_some()),
            (Element, element.is_some()),
            (Attributes, attributes.is_some()),
            (AdditionalAttributes, additional_attributes.is_some()),
            (Name, name.is_some()),
        ]
        .into_iter()
        .filter(|(_, present)| *present)
        .map(|(field, _)| field)
        .collect::<HashSet<_>>();

        match type_name.transpose()?.as_ref() {
            Some(s) => {
                // We've concluded that type exists
                remaining_fields.remove(&TypeField);
                // Used to generate the appropriate serde error if a field is present
                // when it is not expected.
                let error_if_fields = |fs: &[TypeFields],
                                       expected: &'static [&'static str]|
                 -> std::result::Result<(), M::Error> {
                    for f in fs {
                        if remaining_fields.contains(f) {
                            return Err(serde::de::Error::unknown_field(f.as_str(), expected));
                        }
                    }
                    Ok(())
                };
                let error_if_any_fields = || -> std::result::Result<(), M::Error> {
                    error_if_fields(&[Element, Attributes, AdditionalAttributes, Name], &[])
                };
                match s.as_str() {
                    "String" => {
                        error_if_any_fields()?;
                        Ok(Type::Type(TypeVariant::String))
                    }
                    "Long" => {
                        error_if_any_fields()?;
                        Ok(Type::Type(TypeVariant::Long))
                    }
                    "Boolean" => {
                        error_if_any_fields()?;
                        Ok(Type::Type(TypeVariant::Boolean))
                    }
                    "Set" => {
                        error_if_fields(
                            &[Attributes, AdditionalAttributes, Name],
                            &[type_field_name!(Element)],
                        )?;

                        match element {
                            Some(element) => Ok(Type::Type(TypeVariant::Set {
                                element: Box::new(element?),
                            })),
                            None => Err(serde::de::Error::missing_field(Element.as_str())),
                        }
                    }
                    "Record" => {
                        error_if_fields(
                            &[Element, Name],
                            &[
                                type_field_name!(Attributes),
                                type_field_name!(AdditionalAttributes),
                            ],
                        )?;

                        if let Some(attributes) = attributes {
                            let additional_attributes =
                                additional_attributes.unwrap_or(Ok(partial_schema_default()));
                            Ok(Type::Type(TypeVariant::Record(RecordType {
                                attributes: attributes?
                                    .0
                                    .into_iter()
                                    .map(|(k, TypeOfAttribute { ty, required })| {
                                        (
                                            k,
                                            TypeOfAttribute {
                                                ty: ty.into_n(),
                                                required,
                                            },
                                        )
                                    })
                                    .collect(),
                                additional_attributes: additional_attributes?,
                            })))
                        } else {
                            Err(serde::de::Error::missing_field(Attributes.as_str()))
                        }
                    }
                    "Entity" => {
                        error_if_fields(
                            &[Element, Attributes, AdditionalAttributes],
                            &[type_field_name!(Name)],
                        )?;
                        match name {
                            Some(name) => {
                                let name = name?;
                                Ok(Type::Type(TypeVariant::Entity {
                                    name: RawName::from_normalized_str(&name)
                                        .map_err(|err| {
                                            serde::de::Error::custom(format!(
                                                "invalid entity type `{name}`: {err}"
                                            ))
                                        })?
                                        .into(),
                                }))
                            }
                            None => Err(serde::de::Error::missing_field(Name.as_str())),
                        }
                    }
                    "EntityOrCommon" => {
                        error_if_fields(
                            &[Element, Attributes, AdditionalAttributes],
                            &[type_field_name!(Name)],
                        )?;
                        match name {
                            Some(name) => {
                                let name = name?;
                                Ok(Type::Type(TypeVariant::EntityOrCommon {
                                    type_name: RawName::from_normalized_str(&name)
                                        .map_err(|err| {
                                            serde::de::Error::custom(format!(
                                                "invalid entity or common type `{name}`: {err}"
                                            ))
                                        })?
                                        .into(),
                                }))
                            }
                            None => Err(serde::de::Error::missing_field(Name.as_str())),
                        }
                    }
                    "Extension" => {
                        error_if_fields(
                            &[Element, Attributes, AdditionalAttributes],
                            &[type_field_name!(Name)],
                        )?;

                        match name {
                            Some(name) => {
                                let name = name?;
                                Ok(Type::Type(TypeVariant::Extension {
                                    name: UnreservedId::from_normalized_str(&name).map_err(
                                        |err| {
                                            serde::de::Error::custom(format!(
                                                "invalid extension type `{name}`: {err}"
                                            ))
                                        },
                                    )?,
                                }))
                            }
                            None => Err(serde::de::Error::missing_field(Name.as_str())),
                        }
                    }
                    type_name => {
                        error_if_any_fields()?;
                        Ok(Type::CommonTypeRef {
                            type_name: N::from(RawName::from_normalized_str(type_name).map_err(
                                |err| {
                                    serde::de::Error::custom(format!(
                                        "invalid common type `{type_name}`: {err}"
                                    ))
                                },
                            )?),
                        })
                    }
                }
            }
            None => Err(serde::de::Error::missing_field(TypeField.as_str())),
        }
    }
}

impl<N> From<TypeVariant<N>> for Type<N> {
    fn from(variant: TypeVariant<N>) -> Self {
        Self::Type(variant)
    }
}

/// Represents the type-level information about a record type.
///
/// The parameter `N` is the type of entity type names and common type names in
/// this [`RecordType`], including recursively.
/// See notes on [`Fragment`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct RecordType<N> {
    /// Attribute names and types for the record
    pub attributes: BTreeMap<SmolStr, TypeOfAttribute<N>>,
    /// Whether "additional attributes" are possible on this record
    #[serde(default = "partial_schema_default")]
    #[serde(skip_serializing_if = "is_partial_schema_default")]
    pub additional_attributes: bool,
}

impl<N> Default for RecordType<N> {
    fn default() -> Self {
        Self {
            attributes: BTreeMap::new(),
            additional_attributes: partial_schema_default(),
        }
    }
}

impl<N> RecordType<N> {
    /// Is this [`RecordType`] an empty record?
    pub fn is_empty_record(&self) -> bool {
        self.additional_attributes == partial_schema_default() && self.attributes.is_empty()
    }
}

impl RecordType<RawName> {
    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> RecordType<ConditionalName> {
        RecordType {
            attributes: self
                .attributes
                .into_iter()
                .map(|(k, v)| (k, v.conditionally_qualify_type_references(ns)))
                .collect(),
            additional_attributes: self.additional_attributes,
        }
    }
}

impl RecordType<ConditionalName> {
    /// Convert this [`RecordType<ConditionalName>`] into a
    /// [`RecordType<InternalName>`] by fully-qualifying all typenames that
    /// appear anywhere in any definitions.
    ///
    /// `all_common_defs` and `all_entity_defs` need to be the full set of all
    /// fully-qualified typenames (of common and entity types respectively) that
    /// are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_common_defs: &HashSet<InternalName>,
        all_entity_defs: &HashSet<InternalName>,
    ) -> std::result::Result<RecordType<InternalName>, TypeResolutionError> {
        Ok(RecordType {
            attributes: self
                .attributes
                .into_iter()
                .map(|(k, v)| {
                    Ok((
                        k,
                        v.fully_qualify_type_references(all_common_defs, all_entity_defs)?,
                    ))
                })
                .collect::<std::result::Result<_, _>>()?,
            additional_attributes: self.additional_attributes,
        })
    }
}

/// All the variants of [`Type`] other than common types, which are handled
/// directly in [`Type`]. See notes on [`Type`] for why it's necessary to have a
/// separate enum here.
///
/// The parameter `N` is the type of entity type names and common type names in
/// this [`TypeVariant`], including recursively.
/// See notes on [`Fragment`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum TypeVariant<N> {
    /// String
    String,
    /// Long
    Long,
    /// Boolean
    Boolean,
    /// Set
    Set {
        /// Element type
        element: Box<Type<N>>,
    },
    /// Record
    Record(RecordType<N>),
    /// Entity
    Entity {
        /// Name of the entity type.
        /// For the important case of `N` = `RawName`, this is the schema JSON
        /// format, and the `RawName` is exactly how it appears in the schema;
        /// may not yet be fully qualified
        name: N,
    },
    /// Reference that may resolve to either an entity or common type
    EntityOrCommon {
        /// Name of the entity or common type.
        /// For the important case of `N` = `RawName`, this is the schema JSON
        /// format, and the `RawName` is exactly how it appears in the schema;
        /// may not yet be fully qualified.
        ///
        /// There is no possible ambiguity in the JSON syntax between this and
        /// `Entity`, nor between this and `Type::Common`.
        /// - To represent a must-be-entity-type reference in the JSON syntax,
        ///     use `{ "type": "Entity", "name": "foo" }`. This ser/de as
        ///     `Type::Type(TypeVariant::Entity)`.
        /// - To represent a must-be-common-type reference in the JSON syntax,
        ///     use `{ "type": "foo" }`. This ser/de as
        ///     `Type::CommonTypeRef`.
        /// - To represent an either-entity-or-common-type reference in the
        ///     JSON syntax, use `{ "type": "EntityOrCommon", "name": "foo" }`.
        ///     This ser/de as `Type::Type(TypeVariant::EntityOrCommon`.
        ///
        /// You can still use `{ "type": "Entity" }` alone (no `"name"` key) to
        /// indicate a common type named `Entity`, and likewise for
        /// `EntityOrCommon`.
        #[serde(rename = "name")]
        type_name: N,
    },
    /// Extension types
    Extension {
        /// Name of the extension type
        name: UnreservedId,
    },
}

impl TypeVariant<RawName> {
    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> TypeVariant<ConditionalName> {
        match self {
            Self::Boolean => TypeVariant::Boolean,
            Self::Long => TypeVariant::Long,
            Self::String => TypeVariant::String,
            Self::Extension { name } => TypeVariant::Extension { name },
            Self::Entity { name } => TypeVariant::Entity {
                name: name.conditionally_qualify_with(ns, ReferenceType::Entity), // `Self::Entity` must resolve to an entity type, not a common type
            },
            Self::EntityOrCommon { type_name } => TypeVariant::EntityOrCommon {
                type_name: type_name.conditionally_qualify_with(ns, ReferenceType::CommonOrEntity),
            },
            Self::Set { element } => TypeVariant::Set {
                element: Box::new(element.conditionally_qualify_type_references(ns)),
            },
            Self::Record(RecordType {
                attributes,
                additional_attributes,
            }) => TypeVariant::Record(RecordType {
                attributes: BTreeMap::from_iter(attributes.into_iter().map(
                    |(attr, TypeOfAttribute { ty, required })| {
                        (
                            attr,
                            TypeOfAttribute {
                                ty: ty.conditionally_qualify_type_references(ns),
                                required,
                            },
                        )
                    },
                )),
                additional_attributes,
            }),
        }
    }

    fn into_n<N: From<RawName>>(self) -> TypeVariant<N> {
        match self {
            Self::Boolean => TypeVariant::Boolean,
            Self::Long => TypeVariant::Long,
            Self::String => TypeVariant::String,
            Self::Entity { name } => TypeVariant::Entity { name: name.into() },
            Self::EntityOrCommon { type_name } => TypeVariant::EntityOrCommon {
                type_name: type_name.into(),
            },
            Self::Record(RecordType {
                attributes,
                additional_attributes,
            }) => TypeVariant::Record(RecordType {
                attributes: attributes
                    .into_iter()
                    .map(|(k, v)| (k, v.into_n()))
                    .collect(),
                additional_attributes,
            }),
            Self::Set { element } => TypeVariant::Set {
                element: Box::new(element.into_n()),
            },
            Self::Extension { name } => TypeVariant::Extension { name },
        }
    }
}

impl TypeVariant<ConditionalName> {
    /// Convert this [`TypeVariant<ConditionalName>`] into a
    /// [`TypeVariant<InternalName>`] by fully-qualifying all typenames that
    /// appear anywhere in any definitions.
    ///
    /// `all_common_defs` and `all_entity_defs` need to be the full set of all
    /// fully-qualified typenames (of common and entity types respectively) that
    /// are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_common_defs: &HashSet<InternalName>,
        all_entity_defs: &HashSet<InternalName>,
    ) -> std::result::Result<TypeVariant<InternalName>, TypeResolutionError> {
        match self {
            Self::Boolean => Ok(TypeVariant::Boolean),
            Self::Long => Ok(TypeVariant::Long),
            Self::String => Ok(TypeVariant::String),
            Self::Extension { name } => Ok(TypeVariant::Extension { name }),
            Self::Entity { name } => Ok(TypeVariant::Entity {
                name: name.resolve(all_common_defs, all_entity_defs)?.clone(),
            }),
            Self::EntityOrCommon { type_name } => Ok(TypeVariant::EntityOrCommon {
                type_name: type_name.resolve(all_common_defs, all_entity_defs)?.clone(),
            }),
            Self::Set { element } => Ok(TypeVariant::Set {
                element: Box::new(
                    element.fully_qualify_type_references(all_common_defs, all_entity_defs)?,
                ),
            }),
            Self::Record(RecordType {
                attributes,
                additional_attributes,
            }) => Ok(TypeVariant::Record(RecordType {
                attributes: attributes
                    .into_iter()
                    .map(|(attr, TypeOfAttribute { ty, required })| {
                        Ok((
                            attr,
                            TypeOfAttribute {
                                ty: ty.fully_qualify_type_references(
                                    all_common_defs,
                                    all_entity_defs,
                                )?,
                                required,
                            },
                        ))
                    })
                    .collect::<std::result::Result<BTreeMap<_, _>, _>>()?,
                additional_attributes,
            })),
        }
    }
}

// Only used for serialization
fn is_partial_schema_default(b: &bool) -> bool {
    *b == partial_schema_default()
}

#[cfg(feature = "arbitrary")]
// PANIC SAFETY property testing code
#[allow(clippy::panic)]
impl<'a> arbitrary::Arbitrary<'a> for Type<RawName> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Type<RawName>> {
        use std::collections::BTreeSet;

        Ok(Type::Type(match u.int_in_range::<u8>(1..=8)? {
            1 => TypeVariant::String,
            2 => TypeVariant::Long,
            3 => TypeVariant::Boolean,
            4 => TypeVariant::Set {
                element: Box::new(u.arbitrary()?),
            },
            5 => {
                let attributes = {
                    let attr_names: BTreeSet<String> = u.arbitrary()?;
                    attr_names
                        .into_iter()
                        .map(|attr_name| Ok((attr_name.into(), u.arbitrary()?)))
                        .collect::<arbitrary::Result<_>>()?
                };
                TypeVariant::Record(RecordType {
                    attributes,
                    additional_attributes: u.arbitrary()?,
                })
            }
            6 => TypeVariant::Entity {
                name: u.arbitrary()?,
            },
            7 => TypeVariant::Extension {
                // PANIC SAFETY: `ipaddr` is a valid `UnreservedId`
                #[allow(clippy::unwrap_used)]
                name: "ipaddr".parse().unwrap(),
            },
            8 => TypeVariant::Extension {
                // PANIC SAFETY: `decimal` is a valid `UnreservedId`
                #[allow(clippy::unwrap_used)]
                name: "decimal".parse().unwrap(),
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
/// The parameter `N` is the type of entity type names and common type names in
/// this [`TypeOfAttribute`], including recursively.
/// See notes on [`Fragment`].
///
/// Note that we can't add `#[serde(deny_unknown_fields)]` here because we are
/// using `#[serde(tag = "type")]` in [`Type`] which is flattened here.
/// The way `serde(flatten)` is implemented means it may be possible to access
/// fields incorrectly if a struct contains two structs that are flattened
/// (`<https://github.com/serde-rs/serde/issues/1547>`). This shouldn't apply to
/// us as we're using `flatten` only once
/// (`<https://github.com/serde-rs/serde/issues/1600>`). This should be ok because
/// unknown fields for [`TypeOfAttribute`] should be passed to [`Type`] where
/// they will be denied (`<https://github.com/serde-rs/serde/issues/1600>`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, PartialOrd, Ord)]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
pub struct TypeOfAttribute<N> {
    /// Underlying type of the attribute
    #[serde(flatten)]
    pub ty: Type<N>,
    /// Whether the attribute is required
    #[serde(default = "record_attribute_required_default")]
    #[serde(skip_serializing_if = "is_record_attribute_required_default")]
    pub required: bool,
}

impl TypeOfAttribute<RawName> {
    fn into_n<N: From<RawName>>(self) -> TypeOfAttribute<N> {
        TypeOfAttribute {
            ty: self.ty.into_n(),
            required: self.required,
        }
    }

    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> TypeOfAttribute<ConditionalName> {
        TypeOfAttribute {
            ty: self.ty.conditionally_qualify_type_references(ns),
            required: self.required,
        }
    }
}

impl TypeOfAttribute<ConditionalName> {
    /// Convert this [`TypeOfAttribute<ConditionalName>`] into a
    /// [`TypeOfAttribute<InternalName>`] by fully-qualifying all typenames that
    /// appear anywhere in any definitions.
    ///
    /// `all_common_defs` and `all_entity_defs` need to be the full set of all
    /// fully-qualified typenames (of common and entity types respectively) that
    /// are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_common_defs: &HashSet<InternalName>,
        all_entity_defs: &HashSet<InternalName>,
    ) -> std::result::Result<TypeOfAttribute<InternalName>, TypeResolutionError> {
        Ok(TypeOfAttribute {
            ty: self
                .ty
                .fully_qualify_type_references(all_common_defs, all_entity_defs)?,
            required: self.required,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for TypeOfAttribute<RawName> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            ty: u.arbitrary()?,
            required: u.arbitrary()?,
        })
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        arbitrary::size_hint::and(
            <Type<RawName> as arbitrary::Arbitrary>::size_hint(depth),
            <bool as arbitrary::Arbitrary>::size_hint(depth),
        )
    }
}

// Only used for serialization
fn is_record_attribute_required_default(b: &bool) -> bool {
    *b == record_attribute_required_default()
}

/// By default schema properties which enable parts of partial schema validation
/// should be `false`.  Defines the default value for `additionalAttributes`.
fn partial_schema_default() -> bool {
    false
}

/// Defines the default value for `required` on record and entity attributes.
fn record_attribute_required_default() -> bool {
    true
}

#[cfg(test)]
mod test {
    use cedar_policy_core::{
        extensions::Extensions,
        test_utils::{expect_err, ExpectedErrorMessageBuilder},
    };
    use cool_asserts::assert_matches;

    use crate::ValidatorSchema;

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
            et.shape,
            AttributesOrContext(Type::Type(TypeVariant::Record(RecordType {
                attributes: BTreeMap::new(),
                additional_attributes: false
            }))),
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
            et.shape,
            AttributesOrContext(Type::Type(TypeVariant::Record(RecordType {
                attributes: BTreeMap::new(),
                additional_attributes: false
            }))),
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
            resource_types: vec!["Album".parse().unwrap()],
            principal_types: vec!["User".parse().unwrap()],
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
        let schema: Fragment<RawName> = serde_json::from_str(src).expect("Parse Error");
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
        let schema = ValidatorSchema::from_json_value(src.clone(), &Extensions::all_available());
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"missing field `name`"#)
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
        let schema = ValidatorSchema::from_json_str(src, Extensions::all_available());
        assert_matches!(schema, Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"unknown field `User`, expected one of `commonTypes`, `entityTypes`, `actions` at line 3 column 35"#)
                    .help("JSON formatted schema must specify a namespace. If you want to use the empty namespace, explicitly specify it with `{ \"\": {..} }`")
                    .build());
        });
    }
}

/// Tests related to PR #749
#[cfg(test)]
mod strengthened_types {
    use cool_asserts::assert_matches;

    use super::{
        ActionEntityUID, ApplySpec, EntityType, Fragment, NamespaceDefinition, RawName, Type,
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
        let schema: Result<Fragment<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid namespace `\n`: unexpected end of input");

        let src = serde_json::json!(
        {
           "1" : {
            "entityTypes": {},
            "actions": {}
           }
        });
        let schema: Result<Fragment<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid namespace `1`: unexpected token `1`");

        let src = serde_json::json!(
        {
           "*1" : {
            "entityTypes": {},
            "actions": {}
           }
        });
        let schema: Result<Fragment<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid namespace `*1`: unexpected token `*`");

        let src = serde_json::json!(
        {
           "::" : {
            "entityTypes": {},
            "actions": {}
           }
        });
        let schema: Result<Fragment<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid namespace `::`: unexpected token `::`");

        let src = serde_json::json!(
        {
           "A::" : {
            "entityTypes": {},
            "actions": {}
           }
        });
        let schema: Result<Fragment<RawName>, _> = serde_json::from_value(src);
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
        let schema: Result<Type<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid entity type ``: unexpected end of input");

        let src = serde_json::json!(
        {
           "type": "Entity",
            "name": "*"
        });
        let schema: Result<Type<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid entity type `*`: unexpected token `*`");

        let src = serde_json::json!(
        {
           "type": "Entity",
            "name": "::A"
        });
        let schema: Result<Type<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid entity type `::A`: unexpected token `::`");

        let src = serde_json::json!(
        {
           "type": "Entity",
            "name": "A::"
        });
        let schema: Result<Type<RawName>, _> = serde_json::from_value(src);
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
        let schema: Result<Type<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid common type ``: unexpected end of input");

        let src = serde_json::json!(
        {
           "type": "*"
        });
        let schema: Result<Type<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid common type `*`: unexpected token `*`");

        let src = serde_json::json!(
        {
           "type": "::A"
        });
        let schema: Result<Type<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid common type `::A`: unexpected token `::`");

        let src = serde_json::json!(
        {
           "type": "A::"
        });
        let schema: Result<Type<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid common type `A::`: unexpected end of input");
    }

    #[test]
    fn invalid_schema_extension_types() {
        let src = serde_json::json!(
        {
           "type": "Extension",
           "name": ""
        });
        let schema: Result<Type<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid extension type ``: unexpected end of input");

        let src = serde_json::json!(
        {
            "type": "Extension",
           "name": "*"
        });
        let schema: Result<Type<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(schema, "invalid extension type `*`: unexpected token `*`");

        let src = serde_json::json!(
        {
            "type": "Extension",
           "name": "__cedar::decimal"
        });
        let schema: Result<Type<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(
            schema,
            "invalid extension type `__cedar::decimal`: unexpected token `::`",
        );

        let src = serde_json::json!(
        {
            "type": "Extension",
           "name": "__cedar::"
        });
        let schema: Result<Type<RawName>, _> = serde_json::from_value(src);
        assert_error_matches(
            schema,
            "invalid extension type `__cedar::`: unexpected token `::`",
        );

        let src = serde_json::json!(
        {
            "type": "Extension",
           "name": "::__cedar"
        });
        let schema: Result<Type<RawName>, _> = serde_json::from_value(src);
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

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn roundtrip(schema: Fragment<RawName>) {
        let json = serde_json::to_value(schema.clone()).unwrap();
        let new_schema: Fragment<RawName> = serde_json::from_value(json).unwrap();
        assert_eq!(schema, new_schema);
    }

    #[test]
    fn empty_namespace() {
        let fragment = Fragment(HashMap::from([(
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
        let fragment = Fragment(HashMap::from([(
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
        let fragment = Fragment(HashMap::from([(
            None,
            NamespaceDefinition {
                common_types: HashMap::new(),
                entity_types: HashMap::from([(
                    "a".parse().unwrap(),
                    EntityType {
                        member_of_types: vec!["a".parse().unwrap()],
                        shape: AttributesOrContext(Type::Type(TypeVariant::Record(RecordType {
                            attributes: BTreeMap::new(),
                            additional_attributes: false,
                        }))),
                    },
                )]),
                actions: HashMap::from([(
                    "action".into(),
                    ActionType {
                        attributes: None,
                        applies_to: Some(ApplySpec {
                            resource_types: vec!["a".parse().unwrap()],
                            principal_types: vec!["a".parse().unwrap()],
                            context: AttributesOrContext(Type::Type(TypeVariant::Record(
                                RecordType {
                                    attributes: BTreeMap::new(),
                                    additional_attributes: false,
                                },
                            ))),
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
        let fragment = Fragment(HashMap::from([
            (
                Some("foo".parse().unwrap()),
                NamespaceDefinition {
                    common_types: HashMap::new(),
                    entity_types: HashMap::from([(
                        "a".parse().unwrap(),
                        EntityType {
                            member_of_types: vec!["a".parse().unwrap()],
                            shape: AttributesOrContext(Type::Type(TypeVariant::Record(
                                RecordType {
                                    attributes: BTreeMap::new(),
                                    additional_attributes: false,
                                },
                            ))),
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
                                resource_types: vec!["foo::a".parse().unwrap()],
                                principal_types: vec!["foo::a".parse().unwrap()],
                                context: AttributesOrContext(Type::Type(TypeVariant::Record(
                                    RecordType {
                                        attributes: BTreeMap::new(),
                                        additional_attributes: false,
                                    },
                                ))),
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
        serde_json::from_str::<Fragment<RawName>>(src).unwrap();
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
        serde_json::from_str::<Fragment<RawName>>(src).unwrap();
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
        serde_json::from_str::<Fragment<RawName>>(src).unwrap();
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
        serde_json::from_str::<Fragment<RawName>>(src).unwrap();
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
        serde_json::from_str::<Fragment<RawName>>(src).unwrap();
    }

    #[test]
    #[should_panic(expected = "missing field `resourceTypes`")]
    fn missing_resource() {
        let src = r#"{
            "Foo": {
              "entityTypes" : {},
              "actions": {
                "foo" : {
                    "appliesTo" : {
                        "principalTypes" : ["a"]
                    }
                }
              }
            }
        }"#;
        serde_json::from_str::<Fragment<RawName>>(src).unwrap();
    }

    #[test]
    #[should_panic(expected = "missing field `principalTypes`")]
    fn missing_principal() {
        let src = r#"{
            "Foo": {
              "entityTypes" : {},
              "actions": {
                "foo" : {
                    "appliesTo" : {
                        "resourceTypes" : ["a"]
                    }
                }
              }
            }
        }"#;
        serde_json::from_str::<Fragment<RawName>>(src).unwrap();
    }

    #[test]
    #[should_panic(expected = "missing field `resourceTypes`")]
    fn missing_both() {
        let src = r#"{
            "Foo": {
              "entityTypes" : {},
              "actions": {
                "foo" : {
                    "appliesTo" : {
                    }
                }
              }
            }
        }"#;
        serde_json::from_str::<Fragment<RawName>>(src).unwrap();
    }
}
