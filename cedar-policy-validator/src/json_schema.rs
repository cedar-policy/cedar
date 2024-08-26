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
    jsonvalue::JsonValueWithNoDuplicateKeys,
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
    AllDefs, CedarSchemaError, CedarSchemaParseError, ConditionalName, RawName, ReferenceType,
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

/// An [`UnreservedId`] that cannot be reserved JSON schema keywords
/// like `Set`, `Long`, and etc.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct CommonTypeId(UnreservedId);

impl From<CommonTypeId> for UnreservedId {
    fn from(value: CommonTypeId) -> Self {
        value.0
    }
}

impl CommonTypeId {
    pub(crate) fn unchecked(id: UnreservedId) -> Self {
        Self(id)
    }
}

impl Display for CommonTypeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

// Test if this id is a reserved JSON schema keyword.
// Issues:
// https://github.com/cedar-policy/cedar/issues/1070
// https://github.com/cedar-policy/cedar/issues/1139
pub(crate) fn is_reserved_schema_keyword(id: &UnreservedId) -> bool {
    matches!(
        id.as_ref(),
        "Set" | "Record" | "Entity" | "Extension" | "Long" | "String" | "Boolean"
    )
}

/// Deserialize a [`CommonTypeId`]
impl<'de> Deserialize<'de> for CommonTypeId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        UnreservedId::deserialize(deserializer).and_then(|id| {
            if is_reserved_schema_keyword(&id) {
                Err(serde::de::Error::custom(format!(
                    "Used reserved JSON schema keyword: {id} "
                )))
            } else {
                Ok(Self(id))
            }
        })
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
    pub common_types: HashMap<CommonTypeId, Type<N>>,
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
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> Result<NamespaceDefinition<InternalName>> {
        Ok(NamespaceDefinition {
            common_types: self
                .common_types
                .into_iter()
                .map(|(k, v)| Ok((k, v.fully_qualify_type_references(all_defs)?)))
                .collect::<std::result::Result<_, TypeNotDefinedError>>()?,
            entity_types: self
                .entity_types
                .into_iter()
                .map(|(k, v)| Ok((k, v.fully_qualify_type_references(all_defs)?)))
                .collect::<std::result::Result<_, TypeNotDefinedError>>()?,
            actions: self
                .actions
                .into_iter()
                .map(|(k, v)| Ok((k, v.fully_qualify_type_references(all_defs)?)))
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
    #[serde(skip_serializing_if = "EntityAttributes::is_empty_record")]
    pub shape: EntityAttributes<N>,
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
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> std::result::Result<EntityType<InternalName>, TypeNotDefinedError> {
        Ok(EntityType {
            member_of_types: self
                .member_of_types
                .into_iter()
                .map(|cname| cname.resolve(all_defs))
                .collect::<std::result::Result<_, _>>()?,
            shape: self.shape.fully_qualify_type_references(all_defs)?,
        })
    }
}

/// Declaration of record attributes, or of an action context.
/// These share a JSON format.
///
/// The parameter `N` is the type of entity type names and common type names in
/// this [`RecordOrContextAttributes`], including recursively.
/// See notes on [`Fragment`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[serde(transparent)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct RecordOrContextAttributes<N>(
    // We use the usual `Type` deserialization, but it will ultimately need to
    // be a `Record` or common-type reference which resolves to a `Record`.
    pub Type<N>,
);

impl<N> RecordOrContextAttributes<N> {
    /// Convert the [`RecordOrContextAttributes`] into its [`Type`].
    pub fn into_inner(self) -> Type<N> {
        self.0
    }

    /// Is this [`RecordOrContextAttributes`] an empty record?
    pub fn is_empty_record(&self) -> bool {
        self.0.is_empty_record()
    }
}

impl<N> Default for RecordOrContextAttributes<N> {
    fn default() -> Self {
        Self::from(RecordType::default())
    }
}

impl<N: Display> Display for RecordOrContextAttributes<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<N> From<RecordType<RecordAttributeType<N>>> for RecordOrContextAttributes<N> {
    fn from(rty: RecordType<RecordAttributeType<N>>) -> RecordOrContextAttributes<N> {
        Self(Type::Type(TypeVariant::Record(rty)))
    }
}

impl RecordOrContextAttributes<RawName> {
    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> RecordOrContextAttributes<ConditionalName> {
        RecordOrContextAttributes(self.0.conditionally_qualify_type_references(ns))
    }
}

impl RecordOrContextAttributes<ConditionalName> {
    /// Convert this [`RecordOrContextAttributes<ConditionalName>`] into a
    /// [`RecordOrContextAttributes<InternalName>`] by fully-qualifying all typenames
    /// that appear anywhere in any definitions.
    ///
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> std::result::Result<RecordOrContextAttributes<InternalName>, TypeNotDefinedError> {
        Ok(RecordOrContextAttributes(
            self.0.fully_qualify_type_references(all_defs)?,
        ))
    }
}

/// Declaration of entity attributes
///
/// The parameter `N` is the type of entity type names and common type names in
/// this [`EntityAttributes`], including recursively.
/// See notes on [`Fragment`].
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[serde(untagged)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum EntityAttributes<N> {
    /// Anything valid as record attributes is valid as entity attributes.
    /// Notably, this includes the possibility that we have a single common-type
    /// reference, and not actually a record declaration.
    RecordAttributes(RecordOrContextAttributes<N>),
    /// [`EntityAttributesInternal`] is an analogue of
    /// [`RecordOrContextAttributes`] that covers the JSON forms accepted for
    /// entity attributes but not record attributes
    EntityAttributes(EntityAttributesInternal<N>),
}

/// Helper struct containing the contents of
/// `EntityAttributes::EntityAttributes`.
/// This doesn't cover all possible legal JSON forms for entity attributes
/// (use [`EntityAttributes`] for that) -- in particular this struct doesn't
/// accept a single common-type reference; it requires a record declaration.
/// But, this struct does cover all legal JSON forms for entity attributes that
/// aren't accepted as legal JSON forms for record attributes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[allow(clippy::manual_non_exhaustive)] // a clippy false positive; that's not the reason we're using the `type_placeholder_hack`
pub struct EntityAttributesInternal<N> {
    /// a hack for the derived serializer/deserializer.
    /// We need to require `"type": "Record"` here (it is required for the
    /// corresponding struct [`RecordOrContextAttributes`] by virtue of using
    /// the [`Type`] serialization/deserialization).
    /// The `serialize_with` and `deserialize_with` accomplish this.
    #[serde(rename = "type")]
    #[serde(serialize_with = "record_string")]
    #[serde(deserialize_with = "require_record_string")]
    #[cfg_attr(feature = "wasm", tsify(type = "\"Record\""))]
    type_placeholder_hack: (),
    /// Entity attribute types, as a [`RecordType`]. These may include `EAMap`s.
    #[serde(flatten)]
    pub attrs: RecordType<EntityAttributeType<N>>,
}

fn record_string<S: Serializer>(
    _type_placeholder_hack: &(),
    ser: S,
) -> std::result::Result<S::Ok, S::Error> {
    ser.serialize_str("Record")
}

fn require_record_string<'de, D: Deserializer<'de>>(deser: D) -> std::result::Result<(), D::Error> {
    /// Simple local visitor struct used only by this function
    struct LocalVisitor;

    impl<'de> Visitor<'de> for LocalVisitor {
        type Value = ();
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "the string `Record`")
        }
        fn visit_str<E: serde::de::Error>(self, s: &str) -> std::result::Result<(), E> {
            if s == "Record" {
                Ok(())
            } else {
                Err(serde::de::Error::invalid_value(
                    serde::de::Unexpected::Str(s),
                    &self,
                ))
            }
        }
    }

    deser.deserialize_str(LocalVisitor)
}

impl<N> EntityAttributes<N> {
    /// Is this [`EntityAttributes`] an empty record?
    pub fn is_empty_record(&self) -> bool {
        match self {
            Self::RecordAttributes(attrs) => attrs.is_empty_record(),
            Self::EntityAttributes(internal) => internal.is_empty_record(),
        }
    }
}

impl<N> EntityAttributesInternal<N> {
    /// Is this [`EntityAttributesInternal`] an empty record?
    pub fn is_empty_record(&self) -> bool {
        self.attrs.is_empty_record()
    }
}

impl<N> Default for EntityAttributes<N> {
    fn default() -> Self {
        Self::RecordAttributes(RecordOrContextAttributes::default())
    }
}

impl<N: Display> Display for EntityAttributes<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RecordAttributes(attrs) => attrs.fmt(f),
            Self::EntityAttributes(internal) => internal.fmt(f),
        }
    }
}

impl<N: Display> Display for EntityAttributesInternal<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.attrs.fmt(f)
    }
}

impl<N> From<RecordType<RecordAttributeType<N>>> for EntityAttributes<N> {
    fn from(rty: RecordType<RecordAttributeType<N>>) -> EntityAttributes<N> {
        Self::RecordAttributes(rty.into())
    }
}

impl<N> From<RecordType<EntityAttributeType<N>>> for EntityAttributes<N> {
    fn from(rty: RecordType<EntityAttributeType<N>>) -> EntityAttributes<N> {
        Self::EntityAttributes(EntityAttributesInternal {
            type_placeholder_hack: (),
            attrs: rty,
        })
    }
}

impl EntityAttributes<RawName> {
    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> EntityAttributes<ConditionalName> {
        match self {
            Self::RecordAttributes(attrs) => {
                EntityAttributes::RecordAttributes(attrs.conditionally_qualify_type_references(ns))
            }
            Self::EntityAttributes(internal) => EntityAttributes::EntityAttributes(
                internal.conditionally_qualify_type_references(ns),
            ),
        }
    }
}

impl EntityAttributesInternal<RawName> {
    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> EntityAttributesInternal<ConditionalName> {
        EntityAttributesInternal {
            type_placeholder_hack: self.type_placeholder_hack,
            attrs: self.attrs.conditionally_qualify_type_references(ns),
        }
    }
}

impl EntityAttributes<ConditionalName> {
    /// Convert this [`EntityAttributes<ConditionalName>`] into a
    /// [`EntityAttributes<InternalName>`] by fully-qualifying all typenames
    /// that appear anywhere in any definitions.
    ///
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> std::result::Result<EntityAttributes<InternalName>, TypeNotDefinedError> {
        match self {
            Self::RecordAttributes(attrs) => Ok(EntityAttributes::RecordAttributes(
                attrs.fully_qualify_type_references(all_defs)?,
            )),
            Self::EntityAttributes(internal) => Ok(EntityAttributes::EntityAttributes(
                internal.fully_qualify_type_references(all_defs)?,
            )),
        }
    }
}

impl EntityAttributesInternal<ConditionalName> {
    /// Convert this [`EntityAttributes<ConditionalName>`] into a
    /// [`EntityAttributes<InternalName>`] by fully-qualifying all typenames
    /// that appear anywhere in any definitions.
    ///
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> std::result::Result<EntityAttributesInternal<InternalName>, TypeNotDefinedError> {
        Ok(EntityAttributesInternal {
            type_placeholder_hack: self.type_placeholder_hack,
            attrs: self.attrs.fully_qualify_type_references(all_defs)?,
        })
    }
}

impl<'de, N: Deserialize<'de> + From<RawName>> Deserialize<'de> for EntityAttributes<N> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::IntoDeserializer;
        // This deserialization attempts to mimic what `serde(untagged)` would
        // do, but if the process fails, it gives the error message for the
        // `EntityAttributesInternal` case, assuming that that error message is
        // usually the most helpful one.
        // (The only case it doesn't cover is if you tried, but failed, to use a
        // single common-type reference to represent the entity attributes.)

        // Ideally we'd want to "try deserializing" as `RecordOrContextAttributes`
        // and if that fails, restore the deserializer state to try
        // `EntityAttributesInternal`.
        // I'm not sure how `serde(untagged)` does that, and I can't easily
        // figure it out from reading the serde source.
        // Note that `D` isn't `Clone`.
        // As a workaround, we deserialize into `serde_json::Value` first, then
        // determine which variant we have, then deserialize the appropriate
        // variant.
        let value: serde_json::Value =
            <JsonValueWithNoDuplicateKeys as Deserialize<'de>>::deserialize(deserializer)?.into();
        match value.get("type") {
            Some(s) if s != "Record" => {
                // This is the only case where we need the `Self::RecordAttributes` variant;
                // all other cases can deserialize as `Self::EntityAttributes`, or will have
                // an error such that we want the error from the `Self::EntityAttributes`
                // deserialization attempt.
                let attrs = <RecordOrContextAttributes<N> as Deserialize<'de>>::deserialize(
                    value.into_deserializer(),
                )
                .map_err(|e| serde::de::Error::custom(format!("{e}")))?;
                Ok(Self::RecordAttributes(attrs))
            }
            _ => {
                // In all other cases, we deserialize as `EntityAttributesInternal` or want the
                // error message from trying to deserialize as `EntityAttributesInternal`.
                let attrs = <EntityAttributesInternal<N> as Deserialize<'de>>::deserialize(
                    value.into_deserializer(),
                )
                .map_err(|e| serde::de::Error::custom(format!("{e}")))?;
                Ok(Self::EntityAttributes(attrs))
            }
        }
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
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> Result<ActionType<InternalName>> {
        Ok(ActionType {
            attributes: self.attributes,
            applies_to: self
                .applies_to
                .map(|applyspec| applyspec.fully_qualify_type_references(all_defs))
                .transpose()?,
            member_of: self
                .member_of
                .map(|v| {
                    v.into_iter()
                        .map(|aeuid| aeuid.fully_qualify_type_references(all_defs))
                        .collect::<std::result::Result<_, ActionNotDefinedError>>()
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
    #[serde(skip_serializing_if = "RecordOrContextAttributes::is_empty_record")]
    pub context: RecordOrContextAttributes<N>,
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
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> std::result::Result<ApplySpec<InternalName>, TypeNotDefinedError> {
        Ok(ApplySpec {
            resource_types: self
                .resource_types
                .into_iter()
                .map(|cname| cname.resolve(all_defs))
                .collect::<std::result::Result<_, TypeNotDefinedError>>()?,
            principal_types: self
                .principal_types
                .into_iter()
                .map(|cname| cname.resolve(all_defs))
                .collect::<std::result::Result<_, TypeNotDefinedError>>()?,
            context: self.context.fully_qualify_type_references(all_defs)?,
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
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    /// This `ActionEntityUID<ConditionalName>` must resolve to something defined
    /// in `all_defs` or else it throws [`ActionNotDefinedError`].
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> std::result::Result<ActionEntityUID<InternalName>, ActionNotDefinedError> {
        for possibility in self.possibilities() {
            // This ignores any possibilities that aren't valid `EntityUID`,
            // because we know that all defined actions are valid `EntityUID`s
            // (because `all_action_defs` has type `&HashSet<EntityUID>`).
            if let Ok(euid) = EntityUID::try_from(possibility.clone()) {
                if all_defs.is_defined_as_action(&euid) {
                    return Ok(possibility);
                }
            }
        }
        Err(ActionNotDefinedError(nonempty!(self)).into())
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
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> std::result::Result<Type<InternalName>, TypeNotDefinedError> {
        match self {
            Self::Type(tv) => Ok(Type::Type(tv.fully_qualify_type_references(all_defs)?)),
            Self::CommonTypeRef { type_name } => Ok(Type::CommonTypeRef {
                type_name: type_name.resolve(all_defs)?.clone(),
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
    Default,
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
    (Default) => {
        "default"
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
            TypeFields::Default => type_field_name!(Default),
        }
    }
}

/// The fields for a `SchemaType`, with their accompanying data.
/// Used for implementing deserialization.
///
/// We keep field values wrapped in `Result` here so that we do not report
/// errors due to the contents of a field when the field is not expected/allowed
/// for a particular type variant.
/// We instead report that the field should not exist at all, so that the schema
/// author can delete the field without wasting time fixing errors in the value.
#[derive(Debug)]
struct TypeFieldsWithData<N, E> {
    /// If this is `Some`, the `type` field is present, with the given value
    type_name: Option<std::result::Result<SmolStr, E>>,
    /// If this is `Some`, the `element` field is present, with the given value
    element: Option<std::result::Result<Type<N>, E>>,
    /// If this is `Some`, the `attributes` field is present, with the given value
    attributes: Option<std::result::Result<AttributesTypeMap, E>>,
    /// If this is `Some`, the `additional_attributes` field is present, with the given value
    additional_attributes: Option<std::result::Result<bool, E>>,
    /// If this is `Some`, the `name` field is present, with the given value
    name: Option<std::result::Result<SmolStr, E>>,
    /// If this is `Some`, the `default` field is present, with the given value
    default: Option<std::result::Result<Type<N>, E>>,
}

/// Manual impl of `Default` (rather than `derive(Default)`) because the derived
/// impl of `Default` requires `N: Default`, but this manual impl works for all `N`
impl<N, E> Default for TypeFieldsWithData<N, E> {
    fn default() -> Self {
        Self {
            type_name: None,
            element: None,
            attributes: None,
            additional_attributes: None,
            name: None,
            default: None,
        }
    }
}

/// Helper function to collect the [`TypeFieldsWithData`] from a map type during deserialization.
/// Shared by [`SchemaTypeVisitor`] and [`EntityAttributeTypeInternalVisitor`].
fn collect_type_fields_data<'de, N: Deserialize<'de> + From<RawName>, M: MapAccess<'de>>(
    mut map: M,
) -> std::result::Result<TypeFieldsWithData<N, M::Error>, M::Error> {
    use TypeFields::*;

    let mut fields: TypeFieldsWithData<N, M::Error> = TypeFieldsWithData::default();

    // Gather all the fields in the object. Any fields that are not one of
    // the possible fields for some schema type will have been reported by
    // serde already.
    while let Some(key) = map.next_key()? {
        match key {
            Type => {
                if fields.type_name.is_some() {
                    return Err(serde::de::Error::duplicate_field(Type.as_str()));
                }
                fields.type_name = Some(map.next_value());
            }
            Element => {
                if fields.element.is_some() {
                    return Err(serde::de::Error::duplicate_field(Element.as_str()));
                }
                fields.element = Some(map.next_value());
            }
            Attributes => {
                if fields.attributes.is_some() {
                    return Err(serde::de::Error::duplicate_field(Attributes.as_str()));
                }
                fields.attributes = Some(map.next_value());
            }
            AdditionalAttributes => {
                if fields.additional_attributes.is_some() {
                    return Err(serde::de::Error::duplicate_field(
                        AdditionalAttributes.as_str(),
                    ));
                }
                fields.additional_attributes = Some(map.next_value());
            }
            Name => {
                if fields.name.is_some() {
                    return Err(serde::de::Error::duplicate_field(Name.as_str()));
                }
                fields.name = Some(map.next_value());
            }
            Default => {
                if fields.default.is_some() {
                    return Err(serde::de::Error::duplicate_field(Default.as_str()));
                }
                fields.default = Some(map.next_value());
            }
        }
    }

    Ok(fields)
}

/// Used during deserialization to deserialize the attributes type map while
/// reporting an error if there are any duplicate keys in the map. I could not
/// find a way to do the `serde_with` conversion inline without introducing this
/// struct.
#[derive(Debug, Deserialize)]
struct AttributesTypeMap(
    #[serde(with = "serde_with::rust::maps_duplicate_key_is_error")]
    BTreeMap<SmolStr, RecordAttributeType<RawName>>,
);

struct TypeVisitor<N> {
    _phantom: PhantomData<N>,
}

impl<'de, N: Deserialize<'de> + From<RawName>> Visitor<'de> for TypeVisitor<N> {
    type Value = Type<N>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("builtin type or reference to type defined in commonTypes")
    }

    fn visit_map<M>(self, map: M) -> std::result::Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let fields = collect_type_fields_data(map)?;
        let eatype = Self::build_schema_type::<M>(fields)?;
        // Here, in the deserializer for `Type`, we do not allow EAMap
        // types (because `Type` does not allow EAMap types).
        match eatype {
            EntityAttributeTypeInternal::EAMap { .. } => Err(serde::de::Error::custom("found an embedded attribute map type, but embedded attribute maps are not allowed in this position")),
            EntityAttributeTypeInternal::Type(ty) => Ok(ty),
        }
    }
}

impl<'de, N: Deserialize<'de> + From<RawName>> TypeVisitor<N> {
    /// Construct a schema type given the name of the type and its fields.
    /// Fields which were not present are `None`. It is an error for a field
    /// which is not used for a particular type to be `Some` when building that
    /// type.
    ///
    /// This method accepts `EAMap` types, and will construct one if it is
    /// encountered.
    /// Thus it returns [`EntityAttributeTypeInternal`] rather than [`SchemaType`]
    /// directly.
    /// If `EAMap` types should not be accepted in this position, it is the
    /// caller's responsibility to check that the [`EntityAttributeTypeInternal`]
    /// is an acceptable variant.
    fn build_schema_type<M>(
        fields: TypeFieldsWithData<N, M::Error>,
    ) -> std::result::Result<EntityAttributeTypeInternal<N>, M::Error>
    where
        M: MapAccess<'de>,
    {
        use TypeFields::{
            AdditionalAttributes, Attributes, Default, Element, Name, Type as TypeField,
        };
        // Fields that remain to be parsed
        let mut remaining_fields = [
            (TypeField, fields.type_name.is_some()),
            (Element, fields.element.is_some()),
            (Attributes, fields.attributes.is_some()),
            (AdditionalAttributes, fields.additional_attributes.is_some()),
            (Name, fields.name.is_some()),
            (Default, fields.default.is_some()),
        ]
        .into_iter()
        .filter(|(_, present)| *present)
        .map(|(field, _)| field)
        .collect::<HashSet<_>>();

        match fields.type_name.transpose()?.as_ref() {
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
                    error_if_fields(
                        &[Element, Attributes, AdditionalAttributes, Name, Default],
                        &[],
                    )
                };
                match s.as_str() {
                    "String" => {
                        error_if_any_fields()?;
                        Ok(EntityAttributeTypeInternal::Type(Type::Type(
                            TypeVariant::String,
                        )))
                    }
                    "Long" => {
                        error_if_any_fields()?;
                        Ok(EntityAttributeTypeInternal::Type(Type::Type(
                            TypeVariant::Long,
                        )))
                    }
                    "Boolean" => {
                        error_if_any_fields()?;
                        Ok(EntityAttributeTypeInternal::Type(Type::Type(
                            TypeVariant::Boolean,
                        )))
                    }
                    "Set" => {
                        error_if_fields(
                            &[Attributes, AdditionalAttributes, Default, Name],
                            &[type_field_name!(Element)],
                        )?;

                        match fields.element {
                            Some(element) => Ok(EntityAttributeTypeInternal::Type(Type::Type(
                                TypeVariant::Set {
                                    element: Box::new(element?),
                                },
                            ))),
                            None => Err(serde::de::Error::missing_field(Element.as_str())),
                        }
                    }
                    "Record" => {
                        error_if_fields(
                            &[Element, Name],
                            &[
                                type_field_name!(Attributes),
                                type_field_name!(AdditionalAttributes),
                                type_field_name!(Default),
                            ],
                        )?;

                        if let Some(attributes) = fields.attributes {
                            if fields.default.is_some() {
                                return Err(serde::de::Error::custom("fields `default` and `attributes` cannot exist on the same record type"));
                            }
                            let additional_attributes = fields
                                .additional_attributes
                                .unwrap_or(Ok(partial_schema_default()));
                            Ok(EntityAttributeTypeInternal::Type(Type::Type(
                                TypeVariant::Record(RecordType {
                                    attributes: attributes?
                                        .0
                                        .into_iter()
                                        .map(|(k, RecordAttributeType { ty, required })| {
                                            (
                                                k,
                                                RecordAttributeType {
                                                    ty: ty.into_n(),
                                                    required,
                                                },
                                            )
                                        })
                                        .collect(),
                                    additional_attributes: additional_attributes?,
                                }),
                            )))
                        } else if let Some(default) = fields.default {
                            if fields.attributes.is_some() {
                                return Err(serde::de::Error::custom("fields `default` and `attributes` cannot exist on the same record type"));
                            } else if fields.additional_attributes.is_some() {
                                return Err(serde::de::Error::custom("fields `default` and `additionalAttributes` cannot exist on the same record type"));
                            }
                            Ok(EntityAttributeTypeInternal::EAMap {
                                value_type: default?,
                            })
                        } else {
                            Err(serde::de::Error::missing_field(Attributes.as_str()))
                        }
                    }
                    "Entity" => {
                        error_if_fields(
                            &[Element, Attributes, AdditionalAttributes, Default],
                            &[type_field_name!(Name)],
                        )?;
                        match fields.name {
                            Some(name) => {
                                let name = name?;
                                Ok(EntityAttributeTypeInternal::Type(Type::Type(
                                    TypeVariant::Entity {
                                        name: RawName::from_normalized_str(&name)
                                            .map_err(|err| {
                                                serde::de::Error::custom(format!(
                                                    "invalid entity type `{name}`: {err}"
                                                ))
                                            })?
                                            .into(),
                                    },
                                )))
                            }
                            None => Err(serde::de::Error::missing_field(Name.as_str())),
                        }
                    }
                    "EntityOrCommon" => {
                        error_if_fields(
                            &[Element, Attributes, AdditionalAttributes, Default],
                            &[type_field_name!(Name)],
                        )?;
                        match fields.name {
                            Some(name) => {
                                let name = name?;
                                Ok(EntityAttributeTypeInternal::Type(Type::Type(
                                    TypeVariant::EntityOrCommon {
                                        type_name: RawName::from_normalized_str(&name)
                                            .map_err(|err| {
                                                serde::de::Error::custom(format!(
                                                    "invalid entity or common type `{name}`: {err}"
                                                ))
                                            })?
                                            .into(),
                                    },
                                )))
                            }
                            None => Err(serde::de::Error::missing_field(Name.as_str())),
                        }
                    }
                    "Extension" => {
                        error_if_fields(
                            &[Element, Attributes, AdditionalAttributes, Default],
                            &[type_field_name!(Name)],
                        )?;

                        match fields.name {
                            Some(name) => {
                                let name = name?;
                                Ok(EntityAttributeTypeInternal::Type(Type::Type(
                                    TypeVariant::Extension {
                                        name: UnreservedId::from_normalized_str(&name).map_err(
                                            |err| {
                                                serde::de::Error::custom(format!(
                                                    "invalid extension type `{name}`: {err}"
                                                ))
                                            },
                                        )?,
                                    },
                                )))
                            }
                            None => Err(serde::de::Error::missing_field(Name.as_str())),
                        }
                    }
                    type_name => {
                        error_if_any_fields()?;
                        Ok(EntityAttributeTypeInternal::Type(Type::CommonTypeRef {
                            type_name: N::from(RawName::from_normalized_str(type_name).map_err(
                                |err| {
                                    serde::de::Error::custom(format!(
                                        "invalid common type `{type_name}`: {err}"
                                    ))
                                },
                            )?),
                        }))
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
/// `V` is the type of attribute values in the record.
/// For instance, when `V` is [`RecordAttributeType`], this [`RecordType`]
/// represents the associated information for [`TypeVariant::Record`].
/// Entity attribute values are also allowed to be `EAMap`s, so in that
/// case `V` is [`EntityAttributeType`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
#[serde(bound(deserialize = "V: Deserialize<'de>"))]
#[serde(bound(serialize = "V: Serialize"))]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct RecordType<V> {
    /// Attribute names and types for the record
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    pub attributes: BTreeMap<SmolStr, V>,
    /// Whether "additional attributes" are possible on this record
    #[serde(default = "partial_schema_default")]
    #[serde(skip_serializing_if = "is_partial_schema_default")]
    pub additional_attributes: bool,
}

impl<V> Default for RecordType<V> {
    fn default() -> Self {
        Self {
            attributes: BTreeMap::new(),
            additional_attributes: partial_schema_default(),
        }
    }
}

impl<V> RecordType<V> {
    /// Is this [`RecordType`] an empty record?
    pub fn is_empty_record(&self) -> bool {
        self.additional_attributes == partial_schema_default() && self.attributes.is_empty()
    }
}

impl RecordType<RecordAttributeType<RawName>> {
    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> RecordType<RecordAttributeType<ConditionalName>> {
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

impl RecordType<EntityAttributeType<RawName>> {
    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> RecordType<EntityAttributeType<ConditionalName>> {
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

impl RecordType<RecordAttributeType<ConditionalName>> {
    /// Convert this [`RecordType<RecordAttributeType<ConditionalName>>`] into a
    /// [`RecordType<RecordAttributeType<InternalName>>`] by fully-qualifying
    /// all typenames that appear anywhere in any definitions.
    ///
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> std::result::Result<RecordType<RecordAttributeType<InternalName>>, TypeNotDefinedError>
    {
        Ok(RecordType {
            attributes: self
                .attributes
                .into_iter()
                .map(|(k, v)| Ok((k, v.fully_qualify_type_references(all_defs)?)))
                .collect::<std::result::Result<_, TypeNotDefinedError>>()?,
            additional_attributes: self.additional_attributes,
        })
    }
}

impl RecordType<EntityAttributeType<ConditionalName>> {
    /// Convert this [`RecordType<EntityAttributeType<ConditionalName>>`] into a
    /// [`RecordType<EntityAttributeType<InternalName>>`] by fully-qualifying
    /// all typenames that appear anywhere in any definitions.
    ///
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> std::result::Result<RecordType<EntityAttributeType<InternalName>>, TypeNotDefinedError>
    {
        Ok(RecordType {
            attributes: self
                .attributes
                .into_iter()
                .map(|(k, v)| Ok((k, v.fully_qualify_type_references(all_defs)?)))
                .collect::<std::result::Result<_, TypeNotDefinedError>>()?,
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
    Record(RecordType<RecordAttributeType<N>>),
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
                    |(attr, RecordAttributeType { ty, required })| {
                        (
                            attr,
                            RecordAttributeType {
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
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> std::result::Result<TypeVariant<InternalName>, TypeNotDefinedError> {
        match self {
            Self::Boolean => Ok(TypeVariant::Boolean),
            Self::Long => Ok(TypeVariant::Long),
            Self::String => Ok(TypeVariant::String),
            Self::Extension { name } => Ok(TypeVariant::Extension { name }),
            Self::Entity { name } => Ok(TypeVariant::Entity {
                name: name.resolve(all_defs)?.clone(),
            }),
            Self::EntityOrCommon { type_name } => Ok(TypeVariant::EntityOrCommon {
                type_name: type_name.resolve(all_defs)?.clone(),
            }),
            Self::Set { element } => Ok(TypeVariant::Set {
                element: Box::new(element.fully_qualify_type_references(all_defs)?),
            }),
            Self::Record(RecordType {
                attributes,
                additional_attributes,
            }) => Ok(TypeVariant::Record(RecordType {
                attributes: attributes
                    .into_iter()
                    .map(|(attr, RecordAttributeType { ty, required })| {
                        Ok((
                            attr,
                            RecordAttributeType {
                                ty: ty.fully_qualify_type_references(all_defs)?,
                                required,
                            },
                        ))
                    })
                    .collect::<std::result::Result<BTreeMap<_, _>, TypeNotDefinedError>>()?,
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

/// Describes the underlying type of an entity attribute (not including the
/// required/optional flag).
///
/// The allowed types for an entity attribute are different from the allowed
/// types for a record attribute. See
/// [RFC 68](https://github.com/cedar-policy/rfcs/blob/main/text/0068-entity-tags.md).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum EntityAttributeTypeInternal<N> {
    /// A normal type. Attributes can be `String`, an entity type, a common type, a record type, etc
    Type(Type<N>),
    /// An embedded attribute map (RFC 68)
    ///
    /// That is, a map from String to the given value type.
    EAMap {
        /// The `EAMap` is a map from String to this value type.
        ///
        /// Note that this value type may not itself be (or contain) `EAMap`s.
        value_type: Type<N>,
    },
}

impl EntityAttributeTypeInternal<RawName> {
    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> EntityAttributeTypeInternal<ConditionalName> {
        match self {
            Self::Type(ty) => {
                EntityAttributeTypeInternal::Type(ty.conditionally_qualify_type_references(ns))
            }
            Self::EAMap { value_type } => EntityAttributeTypeInternal::EAMap {
                value_type: value_type.conditionally_qualify_type_references(ns),
            },
        }
    }
}

impl EntityAttributeTypeInternal<ConditionalName> {
    /// Convert this [`EntityAttributeTypeInternal<ConditionalName>`] into a
    /// [`EntityAttributeTypeInternal<InternalName>`] by fully-qualifying all
    /// typenames that appear anywhere in any definitions.
    ///
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> std::result::Result<EntityAttributeTypeInternal<InternalName>, TypeNotDefinedError> {
        match self {
            Self::Type(ty) => Ok(EntityAttributeTypeInternal::Type(
                ty.fully_qualify_type_references(all_defs)?,
            )),
            Self::EAMap { value_type } => Ok(EntityAttributeTypeInternal::EAMap {
                value_type: value_type.fully_qualify_type_references(all_defs)?,
            }),
        }
    }
}

impl<N: Serialize> Serialize for EntityAttributeTypeInternal<N> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Type(ty) => ty.serialize(serializer),
            Self::EAMap { value_type } => {
                serde_json::json!({"type": "Record", "default": value_type}).serialize(serializer)
            }
        }
    }
}

struct EntityAttributeTypeInternalVisitor<N> {
    _phantom: PhantomData<N>,
}

impl<'de, N: Deserialize<'de> + From<RawName>> Deserialize<'de> for EntityAttributeTypeInternal<N> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(EntityAttributeTypeInternalVisitor {
            _phantom: PhantomData,
        })
    }
}

impl<'de, N: Deserialize<'de> + From<RawName>> Visitor<'de>
    for EntityAttributeTypeInternalVisitor<N>
{
    type Value = EntityAttributeTypeInternal<N>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("any valid type, including an embedded attribute map type")
    }

    fn visit_map<M>(self, map: M) -> std::result::Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let fields = collect_type_fields_data(map)?;
        TypeVisitor::build_schema_type::<M>(fields)
    }
}

/// Describes the type of an entity attribute. It contains the type of the
/// attribute and whether the attribute is required. The type is flattened for
/// serialization, so, in JSON format, this appears as a regular type with one
/// extra property `required`.
///
/// The parameter `N` is the type of entity type names and common type names in
/// this [`EntityAttributeType`], including recursively.
/// See notes on [`Fragment`].
///
/// Note that we can't add `#[serde(deny_unknown_fields)]` here because we are
/// using `#[serde(tag = "type")]` in [`Type`] which is (eventually) flattened
/// here.
/// The way `serde(flatten)` is implemented means it may be possible to access
/// fields incorrectly if a struct contains two structs that are flattened
/// (`<https://github.com/serde-rs/serde/issues/1547>`). This shouldn't apply to
/// us as we're using `flatten` only once
/// (`<https://github.com/serde-rs/serde/issues/1600>`). This should be ok because
/// unknown fields for [`EntityAttributeType`] should be passed to [`Type`]
/// where they will be denied
/// (`<https://github.com/serde-rs/serde/issues/1600>`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, PartialOrd, Ord)]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct EntityAttributeType<N> {
    /// Underlying type of the attribute
    #[serde(flatten)]
    // without this explicit `tsify` type, as of this writing, tsify produces a declaration
    // `export interface EntityAttributeType<N> extends EntityAttributeTypeInternal<N> { required?: boolean; }`
    // which `tsc` fails with `error TS2312: An interface can only extend an object
    // type or intersection of object types with statically known members.`
    #[cfg_attr(feature = "wasm", tsify(type = "EntityAttributeTypeInternal<N>"))]
    pub ty: EntityAttributeTypeInternal<N>,
    /// Whether the attribute is required
    #[serde(default = "record_attribute_required_default")]
    #[serde(skip_serializing_if = "is_record_attribute_required_default")]
    pub required: bool,
}

impl EntityAttributeType<RawName> {
    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> EntityAttributeType<ConditionalName> {
        EntityAttributeType {
            ty: self.ty.conditionally_qualify_type_references(ns),
            required: self.required,
        }
    }
}

impl EntityAttributeType<ConditionalName> {
    /// Convert this [`EntityAttributeType<ConditionalName>`] into a
    /// [`EntityAttributeType<InternalName>`] by fully-qualifying
    /// all typenames that appear anywhere in any definitions.
    ///
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> std::result::Result<EntityAttributeType<InternalName>, TypeNotDefinedError> {
        Ok(EntityAttributeType {
            ty: self.ty.fully_qualify_type_references(all_defs)?,
            required: self.required,
        })
    }
}

/// Describes the type of a record attribute. It contains the type of the
/// attribute and whether the attribute is required. The type is flattened for
/// serialization, so, in JSON format, this appears as a regular type with one
/// extra property `required`.
///
/// The parameter `N` is the type of entity type names and common type names in
/// this [`RecordAttributeType`], including recursively.
/// See notes on [`Fragment`].
///
/// Note that we can't add `#[serde(deny_unknown_fields)]` here because we are
/// using `#[serde(tag = "type")]` in [`Type`] which is flattened here.
/// The way `serde(flatten)` is implemented means it may be possible to access
/// fields incorrectly if a struct contains two structs that are flattened
/// (`<https://github.com/serde-rs/serde/issues/1547>`). This shouldn't apply to
/// us as we're using `flatten` only once
/// (`<https://github.com/serde-rs/serde/issues/1600>`). This should be ok because
/// unknown fields for [`RecordAttributeType`] should be passed to [`Type`] where
/// they will be denied (`<https://github.com/serde-rs/serde/issues/1600>`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, PartialOrd, Ord)]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct RecordAttributeType<N> {
    /// Underlying type of the attribute
    #[serde(flatten)]
    // without this explicit `tsify` type, as of this writing, tsify produces a declaration
    // `export interface RecordAttributeType<N> extends Type<N> { required?: boolean; }`
    // which `tsc` fails with `error TS2312: An interface can only extend an object
    // type or intersection of object types with statically known members.`
    #[cfg_attr(feature = "wasm", tsify(type = "Type<N>"))]
    pub ty: Type<N>,
    /// Whether the attribute is required
    #[serde(default = "record_attribute_required_default")]
    #[serde(skip_serializing_if = "is_record_attribute_required_default")]
    pub required: bool,
}

impl RecordAttributeType<RawName> {
    fn into_n<N: From<RawName>>(self) -> RecordAttributeType<N> {
        RecordAttributeType {
            ty: self.ty.into_n(),
            required: self.required,
        }
    }

    /// (Conditionally) prefix unqualified entity and common type references with the namespace they are in
    pub fn conditionally_qualify_type_references(
        self,
        ns: Option<&InternalName>,
    ) -> RecordAttributeType<ConditionalName> {
        RecordAttributeType {
            ty: self.ty.conditionally_qualify_type_references(ns),
            required: self.required,
        }
    }
}

impl RecordAttributeType<ConditionalName> {
    /// Convert this [`RecordAttributeType<ConditionalName>`] into a
    /// [`RecordAttributeType<InternalName>`] by fully-qualifying
    /// all typenames that appear anywhere in any definitions.
    ///
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> std::result::Result<RecordAttributeType<InternalName>, TypeNotDefinedError> {
        Ok(RecordAttributeType {
            ty: self.ty.fully_qualify_type_references(all_defs)?,
            required: self.required,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for RecordAttributeType<RawName> {
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
            EntityAttributes::RecordAttributes(RecordOrContextAttributes(Type::Type(
                TypeVariant::Record(RecordType {
                    attributes: BTreeMap::new(),
                    additional_attributes: false
                })
            ))),
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
            EntityAttributes::RecordAttributes(RecordOrContextAttributes(Type::Type(
                TypeVariant::Record(RecordType {
                    attributes: BTreeMap::new(),
                    additional_attributes: false
                })
            ))),
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
            context: RecordOrContextAttributes::default(),
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
        let schema = Fragment::from_json_str(src).expect("Parse Error");
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

/// Tests involving `EAMap`s (RFC 68)
#[cfg(test)]
mod ea_maps {
    use super::*;
    use crate::cedar_schema::test::assert_entity_attr_has_type;
    use cedar_policy_core::test_utils::{expect_err, ExpectedErrorMessageBuilder};
    use cool_asserts::assert_matches;

    #[test]
    fn entity_attribute() {
        // This schema taken directly from the RFC 68 text
        let src = serde_json::json!({
            "": {
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "jobLevel": {
                                    "type": "Long",
                                },
                                "authTags": {
                                    "type": "Record",
                                    "default": {
                                        "type": "Set",
                                        "element": { "type": "String" },
                                    }
                                }
                            }
                        }
                    },
                    "Document": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "owner": {
                                    "type": "Entity",
                                    "name": "User",
                                },
                                "policyTags": {
                                    "type": "Record",
                                    "default": {
                                        "type": "Set",
                                        "element": { "type": "String" },
                                    }
                                }
                            }
                        }
                    }
                },
                "actions": {}
            }
        });
        assert_matches!(Fragment::from_json_value(src), Ok(frag) => {
            let user = frag.0.get(&None).unwrap().entity_types.get(&"User".parse().unwrap()).unwrap();
            assert_matches!(&user.shape, EntityAttributes::EntityAttributes(EntityAttributesInternal { attrs, .. }) => {
                assert_entity_attr_has_type(
                    attrs.attributes.get("jobLevel").unwrap(),
                    &EntityAttributeTypeInternal::Type(Type::Type(TypeVariant::Long)),
                );
                assert_entity_attr_has_type(
                    attrs.attributes.get("authTags").unwrap(),
                    &EntityAttributeTypeInternal::EAMap { value_type: Type::Type(TypeVariant::Set { element: Box::new(Type::Type(TypeVariant::String)) }) },
                );
            });
            let doc = frag.0.get(&None).unwrap().entity_types.get(&"Document".parse().unwrap()).unwrap();
            assert_matches!(&doc.shape, EntityAttributes::EntityAttributes(EntityAttributesInternal { attrs, .. }) => {
                assert_entity_attr_has_type(
                    attrs.attributes.get("owner").unwrap(),
                    &EntityAttributeTypeInternal::Type(Type::Type(TypeVariant::Entity { name: "User".parse().unwrap() })),
                );
                assert_entity_attr_has_type(
                    attrs.attributes.get("policyTags").unwrap(),
                    &EntityAttributeTypeInternal::EAMap { value_type: Type::Type(TypeVariant::Set { element: Box::new(Type::Type(TypeVariant::String)) }) },
                );
            });
        });
    }

    #[test]
    fn record_attribute_inside_entity_attribute() {
        let src = serde_json::json!({
            "": {
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "userDetails": {
                                    "type": "Record",
                                    "attributes": {
                                        "tags": {
                                            "type": "Record",
                                            "default": {
                                                "type": "String"
                                            }
                                        },
                                    },
                                }
                            }
                        }
                    }
                },
                "actions": {}
            }
        });
        assert_matches!(Fragment::from_json_value(src.clone()), Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("found an embedded attribute map type, but embedded attribute maps are not allowed in this position")
                    .build(),
            );
        });
    }

    #[test]
    fn context_attribute() {
        let src = serde_json::json!({
            "": {
                "actions": {
                    "read": {
                        "appliesTo": {
                            "principalTypes": ["E"],
                            "resourceTypes": ["E"],
                            "context": {
                                "type": "Record",
                                "attributes": {
                                    "operationDetails": {
                                        "type": "Record",
                                        "default": {
                                            "type": "String"
                                        },
                                    }
                                }
                            }
                        }
                    }
                },
                "entityTypes": {}
            }
        });
        assert_matches!(Fragment::from_json_value(src.clone()), Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("found an embedded attribute map type, but embedded attribute maps are not allowed in this position")
                    .build(),
            );
        });
    }

    #[test]
    fn toplevel_entity() {
        let src = serde_json::json!({
            "": {
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "default": {
                                "type": "String"
                            }
                        }
                    }
                },
                "actions": {}
            }
        });
        assert_matches!(Fragment::from_json_value(src.clone()), Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("missing field `attributes`").build(),
            );
        });
    }

    #[test]
    fn toplevel_context() {
        let src = serde_json::json!({
            "": {
                "actions": {
                    "read": {
                        "appliesTo": {
                            "principalTypes": ["E"],
                            "resourceTypes": ["E"],
                            "context": {
                                "type": "Record",
                                "default": {
                                    "type": "String"
                                },
                            }
                        }
                    }
                },
                "entityTypes": {}
            }
        });
        assert_matches!(Fragment::from_json_value(src.clone()), Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("found an embedded attribute map type, but embedded attribute maps are not allowed in this position")
                    .build(),
            );
        });
    }

    #[test]
    fn common_type() {
        let src = serde_json::json!({
            "": {
                "commonTypes": {
                    "blah": {
                        "type": "Record",
                        "default": {
                            "type": "String"
                        }
                    },
                },
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "blah": {
                                    "type": "blah"
                                },
                            }
                        }
                    },
                },
                "actions": {}
            }
        });
        assert_matches!(Fragment::from_json_value(src.clone()), Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("found an embedded attribute map type, but embedded attribute maps are not allowed in this position")
                    .build(),
            );
        });
    }

    #[test]
    fn value_type_is_common_type() {
        let src = serde_json::json!({
            "": {
                "commonTypes": {
                    "blah": {
                        "type": "Record",
                        "attributes": {
                            "foo": { "type": "String" },
                        }
                    },
                },
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "blah": {
                                    "type": "Record",
                                    "default": {
                                        "type": "blah"
                                    }
                                },
                            }
                        }
                    },
                },
                "actions": {}
            }
        });
        assert_matches!(Fragment::from_json_value(src), Ok(frag) => {
            let user = frag.0.get(&None).unwrap().entity_types.get(&"User".parse().unwrap()).unwrap();
            assert_matches!(&user.shape, EntityAttributes::EntityAttributes(EntityAttributesInternal { attrs, .. }) => {
                assert_entity_attr_has_type(
                    attrs.attributes.get("blah").unwrap(),
                    &EntityAttributeTypeInternal::EAMap { value_type: Type::CommonTypeRef { type_name: "blah".parse().unwrap() } },
                );
            });
        });
    }

    #[test]
    fn nested_ea_map() {
        let src = serde_json::json!({
            "": {
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "userDetails": {
                                    "type": "Record",
                                    "default": {
                                        "type": "Record",
                                        "default": {
                                            "type": "String"
                                        }
                                    }
                                },
                            }
                        }
                    }
                },
                "actions": {}
            }
        });
        assert_matches!(Fragment::from_json_value(src.clone()), Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("found an embedded attribute map type, but embedded attribute maps are not allowed in this position")
                    .build(),
            );
        });
    }

    #[test]
    fn bad_default() {
        let src = serde_json::json!({
            "": {
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "jobLevel": {
                                    "type": "Long",
                                },
                                "authTags": {
                                    "type": "Foo",
                                    "default": {
                                        "type": "Set",
                                        "element": "String",
                                    }
                                }
                            }
                        }
                    },
                },
                "actions": {}
            }
        });
        assert_matches!(Fragment::from_json_value(src.clone()), Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("unknown field `default`, there are no fields")
                    .build(),
            );
        });
    }

    #[test]
    fn missing_type_record() {
        let src = serde_json::json!({
            "": {
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "jobLevel": {
                                    "type": "Long",
                                },
                                "authTags": {
                                    "default": {
                                        "type": "Set",
                                        "element": "String",
                                    }
                                }
                            }
                        }
                    },
                },
                "actions": {}
            }
        });
        assert_matches!(Fragment::from_json_value(src.clone()), Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("missing field `type`").build(),
            );
        });
    }

    #[test]
    fn both_default_and_attributes() {
        let src = serde_json::json!({
            "": {
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "jobLevel": {
                                    "type": "Long",
                                },
                                "authTags": {
                                    "type": "Record",
                                    "attributes": {
                                        "foo": {
                                            "type": "String",
                                        },
                                    },
                                    "default": {
                                        "type": "Set",
                                        "element": "String",
                                    }
                                }
                            }
                        }
                    },
                },
                "actions": {}
            }
        });
        assert_matches!(Fragment::from_json_value(src.clone()), Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("fields `default` and `attributes` cannot exist on the same record type")
                    .build(),
            );
        });
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
                        shape: EntityAttributes::RecordAttributes(RecordOrContextAttributes(
                            Type::Type(TypeVariant::Record(RecordType {
                                attributes: BTreeMap::new(),
                                additional_attributes: false,
                            })),
                        )),
                    },
                )]),
                actions: HashMap::from([(
                    "action".into(),
                    ActionType {
                        attributes: None,
                        applies_to: Some(ApplySpec {
                            resource_types: vec!["a".parse().unwrap()],
                            principal_types: vec!["a".parse().unwrap()],
                            context: RecordOrContextAttributes::default(),
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
                            shape: EntityAttributes::default(),
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
                                context: RecordOrContextAttributes::default(),
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
/// our parser, so these tests must be written with `from_json_str`
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
        Fragment::from_json_str(src).unwrap();
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
        Fragment::from_json_str(src).unwrap();
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
        Fragment::from_json_str(src).unwrap();
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
        Fragment::from_json_str(src).unwrap();
    }

    #[test]
    #[should_panic(expected = "the key `Baz` occurs two or more times in the same JSON object")]
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
        Fragment::from_json_str(src).unwrap();
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
        Fragment::from_json_str(src).unwrap();
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
        Fragment::from_json_str(src).unwrap();
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
        Fragment::from_json_str(src).unwrap();
    }
}
