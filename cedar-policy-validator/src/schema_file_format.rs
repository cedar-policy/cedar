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

use cedar_policy_core::{
    ast::{Id, Name},
    entities::CedarValueJson,
    parser::err::ParseErrors,
    FromNormalizedStr,
};
use serde::{
    de::{MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_with::serde_as;
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::{
    human_schema::{
        self, parser::parse_natural_schema_fragment, SchemaWarning, ToHumanSchemaStrError,
    },
    HumanSchemaError, Result, SchemaError,
};

#[cfg(feature = "wasm")]
extern crate tsify;

/// A SchemaFragment describe the types for a given instance of Cedar.
/// SchemaFragments are composed of Entity Types and Action Types. The
/// schema fragment is split into multiple namespace definitions, eac including
/// a namespace name which is applied to all entity types (and the implicit
/// `Action` entity type for all actions) in the schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct SchemaFragment(
    #[serde(deserialize_with = "deserialize_schema_fragment")]
    pub  HashMap<Option<Name>, NamespaceDefinition>,
);

fn deserialize_hash_map<'de, D, K, V>(
    key_parser: impl Fn(SmolStr) -> std::result::Result<K, ParseErrors>,
    deserializer: D,
    kind: &'static str,
) -> std::result::Result<HashMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
    K: std::cmp::Eq + std::hash::Hash,
{
    let raw: HashMap<SmolStr, V> =
        serde_with::rust::maps_duplicate_key_is_error::deserialize(deserializer)?;
    Ok(HashMap::from_iter(
        raw.into_iter()
            .map(|(key, value)| {
                Ok((
                    key_parser(key).map_err(|err| {
                        serde::de::Error::custom(format!("invalid {kind}: {err}"))
                    })?,
                    value,
                ))
            })
            .collect::<std::result::Result<Vec<(K, V)>, D::Error>>()?,
    ))
}

fn deserialize_schema_fragment<'de, D>(
    deserializer: D,
) -> std::result::Result<HashMap<Option<Name>, NamespaceDefinition>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_hash_map(
        |key| {
            if key.is_empty() {
                Ok(None)
            } else {
                Ok(Some(Name::from_normalized_str(&key)?))
            }
        },
        deserializer,
        "namespace",
    )
}

impl SchemaFragment {
    /// Create a [`SchemaFragment`] from a JSON value (which should be an object
    /// of the appropriate shape).
    pub fn from_json_value(json: serde_json::Value) -> Result<Self> {
        serde_json::from_value(json).map_err(Into::into)
    }

    /// Create a [`SchemaFragment`] directly from a file containing a JSON object.
    pub fn from_file(file: impl std::io::Read) -> Result<Self> {
        serde_json::from_reader(file).map_err(Into::into)
    }

    /// Parse the schema (in natural schema syntax) from a string
    pub fn from_str_natural(
        src: &str,
    ) -> std::result::Result<(Self, impl Iterator<Item = SchemaWarning>), HumanSchemaError> {
        let tup = parse_natural_schema_fragment(src)?;
        Ok(tup)
    }

    /// Parse the schema (in natural schema syntax) from a reader
    pub fn from_file_natural(
        mut file: impl std::io::Read,
    ) -> std::result::Result<(Self, impl Iterator<Item = SchemaWarning>), HumanSchemaError> {
        let mut src = String::new();
        file.read_to_string(&mut src)?;
        Self::from_str_natural(&src)
    }

    /// Pretty print this [`SchemaFragment`]
    pub fn as_natural_schema(&self) -> std::result::Result<String, ToHumanSchemaStrError> {
        let src = human_schema::json_schema_to_custom_schema_str(self)?;
        Ok(src)
    }
}

/// A common type reference resolver
#[derive(Debug)]
pub(crate) struct CommonTypeResolver<'a> {
    /// The `SchemaFragment` to resolve
    schema: &'a mut SchemaFragment,
    /// The dependency graph among common type names
    /// A common type name is prefixed with the namespace id where it's declared
    graph: HashMap<Name, HashSet<Name>>,
}

impl<'a> CommonTypeResolver<'a> {
    /// Construct a the resolver
    pub(crate) fn new(schema: &'a mut SchemaFragment) -> Self {
        let mut graph = HashMap::new();
        for (ns, def) in schema.0.iter() {
            for (ty_name, ty) in def.common_types.iter() {
                let name = Name::from(ty_name.clone()).prefix_namespace_if_unqualified(ns.clone());
                graph.insert(name, HashSet::from_iter(ty.common_type_references()));
            }
        }
        Self { schema, graph }
    }

    /// Perform topological sort on the dependency graph
    /// Let A -> B denote the RHS of type `A` refers to type `B` (i.e., `A`
    /// depends on `B`)
    /// topo_sort(A -> B -> C) produces [C, B, A]
    /// If there is a cycle, a type name involving in this cycle is the error
    /// It implements a variant of Kahn's algorithm
    fn topo_sort(&self) -> std::result::Result<Vec<Name>, Name> {
        // The in-degree map
        // Note that the keys of this map may be a superset of all common type
        // names
        let mut indegrees: HashMap<&Name, usize> = HashMap::new();
        for (ty_name, deps) in self.graph.iter() {
            // Ensure that declared common types have values in `indegrees`
            indegrees.entry(ty_name).or_insert(0);
            for dep in deps {
                match indegrees.entry(dep) {
                    std::collections::hash_map::Entry::Occupied(mut o) => {
                        o.insert(o.get() + 1);
                    }
                    std::collections::hash_map::Entry::Vacant(v) => {
                        v.insert(1);
                    }
                }
            }
        }

        // The set that contains type names with zero coming edges
        let mut work_set: HashSet<&Name> = HashSet::new();
        let mut res: Vec<Name> = Vec::new();

        // Find all type names with zero in coming edges
        for (name, degree) in indegrees.iter() {
            let name = *name;
            if *degree == 0 {
                work_set.insert(name);
                // The result only contains *declared* type names
                if self.graph.contains_key(name) {
                    res.push(name.clone());
                }
            }
        }

        while !work_set.is_empty() {
            // Pop a node
            let name = work_set.iter().next().cloned().unwrap();
            work_set.remove(name);

            if let Some(deps) = self.graph.get(name) {
                for dep in deps {
                    if let Some(degree) = indegrees.get_mut(dep) {
                        // There will not be any underflows here because
                        // in order for the in-degree to underflow, `dep`'s
                        // in-degree must be 0 at this point
                        // The only possibility where a node's in-degree
                        // becomes 0 is through the subtraction below, which
                        // means it has been visited and hence has 0 in-degrees
                        // In other words, all its in-coming edges have been
                        // "removed" and hence contradicts with the fact that
                        // one of them is being "removed"
                        *degree -= 1;
                        if *degree == 0 {
                            work_set.insert(dep);
                            if self.graph.contains_key(dep) {
                                res.push(dep.clone());
                            }
                        }
                    }
                }
            }
        }

        // The set of nodes that have not been added to the result
        // i.e., there are still in-coming edges and hence exists a cycle
        let mut set: HashSet<&Name> = HashSet::from_iter(self.graph.keys().clone());
        for name in res.iter() {
            set.remove(name);
        }

        if let Some(cycle) = set.into_iter().next() {
            Err(cycle.clone())
        } else {
            // We need to reverse the result because, e.g.,
            // `res` is now [A,B,C] for A -> B -> C because no one depends on A
            res.reverse();
            Ok(res)
        }
    }

    // Substitute common type references in `ty` according to `resolve_table`
    fn resolve_type(
        resolve_table: &HashMap<&Name, SchemaType>,
        ty: SchemaType,
        ns: &Option<Name>,
    ) -> Result<SchemaType> {
        match ty {
            SchemaType::TypeDef { type_name } => {
                let name = if type_name.is_unqualified() {
                    type_name.prefix_namespace_if_unqualified(ns.clone())
                } else {
                    type_name.clone()
                };
                resolve_table
                    .get(&name)
                    .ok_or(SchemaError::UndeclaredCommonTypes(HashSet::from_iter(
                        std::iter::once(name.to_string()),
                    )))
                    .cloned()
            }
            SchemaType::Type(SchemaTypeVariant::Set { element }) => {
                Ok(SchemaType::Type(SchemaTypeVariant::Set {
                    element: Box::new(Self::resolve_type(resolve_table, *element, ns)?),
                }))
            }
            SchemaType::Type(SchemaTypeVariant::Record {
                attributes,
                additional_attributes,
            }) => Ok(SchemaType::Type(SchemaTypeVariant::Record {
                attributes: BTreeMap::from_iter(
                    attributes
                        .into_iter()
                        .map(|(attr, attr_ty)| {
                            Ok((
                                attr,
                                TypeOfAttribute {
                                    required: attr_ty.required,
                                    ty: Self::resolve_type(resolve_table, attr_ty.ty, ns)?,
                                },
                            ))
                        })
                        .collect::<Result<Vec<(_, _)>>>()?,
                ),
                additional_attributes,
            })),
            _ => Ok(ty),
        }
    }

    // Resolve common type references in `self.schema`
    pub(crate) fn resolve(&mut self) -> Result<()> {
        let sorted_names = self
            .topo_sort()
            .map_err(|name| SchemaError::CycleInCommonTypeReferences(name))?;

        let mut resolve_table = HashMap::new();

        for name in sorted_names.iter() {
            if name.is_unqualified() {
                let ty = &self.schema.0.get(&None).unwrap().common_types[name.basename()];
                let substituted_ty = Self::resolve_type(&resolve_table, ty.clone(), &None)?;
                resolve_table.insert(name, substituted_ty.clone());
                self.schema
                    .0
                    .get_mut(&None)
                    .unwrap()
                    .common_types
                    .insert(name.basename().clone(), substituted_ty);
            } else {
                // TODO: use proper getter for namespace
                let ns: Option<Name> = Some(name.namespace().parse().unwrap());
                let ty = &self.schema.0.get(&ns).unwrap().common_types[name.basename()];
                let substituted_ty = Self::resolve_type(&resolve_table, ty.clone(), &None)?;
                resolve_table.insert(name, substituted_ty.clone());
                self.schema
                    .0
                    .get_mut(&ns)
                    .unwrap()
                    .common_types
                    .insert(name.basename().clone(), substituted_ty);
            }
        }

        Ok(())
    }
}

/// A single namespace definition from a SchemaFragment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde_as]
#[serde(deny_unknown_fields)]
#[doc(hidden)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct NamespaceDefinition {
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_common_types")]
    #[serde(rename = "commonTypes")]
    pub common_types: HashMap<Id, SchemaType>,
    #[serde(rename = "entityTypes")]
    #[serde(deserialize_with = "deserialize_entity_types")]
    pub entity_types: HashMap<Id, EntityType>,
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    pub actions: HashMap<SmolStr, ActionType>,
}

fn deserialize_common_types<'de, D>(
    deserializer: D,
) -> std::result::Result<HashMap<Id, SchemaType>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_hash_map(
        |key| Id::from_normalized_str(&key),
        deserializer,
        "common type",
    )
}

fn deserialize_entity_types<'de, D>(
    deserializer: D,
) -> std::result::Result<HashMap<Id, EntityType>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_hash_map(
        |key| Id::from_normalized_str(&key),
        deserializer,
        "entity type",
    )
}

impl NamespaceDefinition {
    pub fn new(
        entity_types: impl IntoIterator<Item = (Id, EntityType)>,
        actions: impl IntoIterator<Item = (SmolStr, ActionType)>,
    ) -> Self {
        Self {
            common_types: HashMap::new(),
            entity_types: entity_types.into_iter().collect(),
            actions: actions.into_iter().collect(),
        }
    }
}

/// Entity types describe the relationships in the entity store, including what
/// entities can be members of groups of what types, and what attributes
/// can/should be included on entities of each type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct EntityType {
    #[serde(default)]
    #[serde(rename = "memberOfTypes")]
    #[serde(deserialize_with = "deserialize_member_of_types")]
    pub member_of_types: Vec<Name>,
    #[serde(default)]
    pub shape: AttributesOrContext,
}

fn deserialize_member_of_types<'de, D>(deserializer: D) -> std::result::Result<Vec<Name>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Vec::<SmolStr>::deserialize(deserializer)?;
    raw.into_iter()
        .map(|s| Name::from_normalized_str(&s))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| serde::de::Error::custom(format!("invalid member of type: {err}")))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
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
            additional_attributes: partial_schema_default(),
        }))
    }
}

/// An action type describes a specific action entity.  It also describes what
/// kinds of entities it can be used on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct ActionType {
    /// This maps attribute names to
    /// `cedar_policy_core::entities::json::value::CedarValueJson` which is the
    /// canonical representation of a cedar value as JSON.
    #[serde(default)]
    pub attributes: Option<HashMap<SmolStr, CedarValueJson>>,
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
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct ApplySpec {
    #[serde(default)]
    #[serde(rename = "resourceTypes")]
    #[serde(deserialize_with = "deserialize_pr_types")]
    pub resource_types: Option<Vec<Name>>,
    #[serde(default)]
    #[serde(rename = "principalTypes")]
    #[serde(deserialize_with = "deserialize_pr_types")]
    pub principal_types: Option<Vec<Name>>,
    #[serde(default)]
    pub context: AttributesOrContext,
}

fn deserialize_pr_types<'de, D>(deserializer: D) -> std::result::Result<Option<Vec<Name>>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<Vec<SmolStr>>::deserialize(deserializer)?;
    match raw {
        Some(vs) => Ok(Some(
            vs.into_iter()
                .map(|v| Name::from_normalized_str(&v))
                .collect::<std::result::Result<Vec<Name>, _>>()
                .map_err(|err| {
                    serde::de::Error::custom(format!("invalid principal or resource types: {err}"))
                })?,
        )),
        None => Ok(None),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct ActionEntityUID {
    pub id: SmolStr,

    #[serde(rename = "type")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_action_type")]
    pub ty: Option<Name>,
}

fn deserialize_action_type<'de, D>(deserializer: D) -> std::result::Result<Option<Name>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<SmolStr>::deserialize(deserializer)?;
    match raw {
        Some(s) => Ok(Some(Name::from_normalized_str(&s).map_err(|err| {
            serde::de::Error::custom(format!("invalid action type: {err}"))
        })?)),
        None => Ok(None),
    }
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
        write!(f, "\"{}\"", self.id.escape_debug())
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
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum SchemaType {
    Type(SchemaTypeVariant),
    TypeDef {
        #[serde(rename = "type")]
        type_name: Name,
    },
}

impl SchemaType {
    pub(crate) fn common_type_references(&self) -> Box<dyn Iterator<Item = Name>> {
        match self {
            SchemaType::Type(SchemaTypeVariant::Record { attributes, .. }) => attributes
                .into_iter()
                .map(|(_, ty)| ty.ty.common_type_references())
                .fold(Box::new(std::iter::empty()), |it, tys| {
                    Box::new(it.chain(tys))
                }),
            SchemaType::Type(SchemaTypeVariant::Set { element }) => {
                element.common_type_references()
            }
            SchemaType::TypeDef { type_name } => Box::new(std::iter::once(type_name.clone())),
            _ => Box::new(std::iter::empty()),
        }
    }
}

impl<'de> Deserialize<'de> for SchemaType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(SchemaTypeVisitor)
    }
}

/// The fields for a `SchemaTypes`. Used for implementing deserialization.
#[derive(Hash, Eq, PartialEq, Deserialize)]
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
    BTreeMap<SmolStr, TypeOfAttribute>,
);

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
        use TypeFields::*;

        // We keep field values wrapped in a `Result` initially so that we do
        // not report errors due the contents of a field when the field is not
        // expected for a particular type variant. We instead report that the
        // field so not exist at all, so that the schema author can delete the
        // field without wasting time fixing errors in the value.
        let mut type_name: Option<std::result::Result<SmolStr, M::Error>> = None;
        let mut element: Option<std::result::Result<SchemaType, M::Error>> = None;
        let mut attributes: Option<std::result::Result<AttributesTypeMap, M::Error>> = None;
        let mut additional_attributes: Option<std::result::Result<bool, M::Error>> = None;
        let mut name: Option<std::result::Result<SmolStr, M::Error>> = None;

        // Gather all the fields in the object. Any fields that are not one of
        // the possible fields for some schema type will have been reported by
        // serde already.
        while let Some(key) = map.next_key()? {
            match key {
                Type => {
                    if type_name.is_some() {
                        return Err(serde::de::Error::duplicate_field(Type.as_str()));
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

impl SchemaTypeVisitor {
    /// Construct a schema type given the name of the type and its fields.
    /// Fields which were not present are `None`. It is an error for a field
    /// which is not used for a particular type to be `Some` when building that
    /// type.
    fn build_schema_type<'de, M>(
        type_name: Option<std::result::Result<SmolStr, M::Error>>,
        element: Option<std::result::Result<SchemaType, M::Error>>,
        attributes: Option<std::result::Result<AttributesTypeMap, M::Error>>,
        additional_attributes: Option<std::result::Result<bool, M::Error>>,
        name: Option<std::result::Result<SmolStr, M::Error>>,
    ) -> std::result::Result<SchemaType, M::Error>
    where
        M: MapAccess<'de>,
    {
        use TypeFields::*;
        let present_fields = [
            (Type, type_name.is_some()),
            (Element, element.is_some()),
            (Attributes, attributes.is_some()),
            (AdditionalAttributes, additional_attributes.is_some()),
            (Name, name.is_some()),
        ]
        .into_iter()
        .filter(|(_, present)| *present)
        .map(|(field, _)| field)
        .collect::<HashSet<_>>();
        // Used to generate the appropriate serde error if a field is present
        // when it is not expected.
        let error_if_fields = |fs: &[TypeFields],
                               expected: &'static [&'static str]|
         -> std::result::Result<(), M::Error> {
            for f in fs {
                if present_fields.contains(f) {
                    return Err(serde::de::Error::unknown_field(f.as_str(), expected));
                }
            }
            Ok(())
        };
        let error_if_any_fields = || -> std::result::Result<(), M::Error> {
            error_if_fields(&[Element, Attributes, AdditionalAttributes, Name], &[])
        };

        match type_name.transpose()?.as_ref().map(|s| s.as_str()) {
            Some("String") => {
                error_if_any_fields()?;
                Ok(SchemaType::Type(SchemaTypeVariant::String))
            }
            Some("Long") => {
                error_if_any_fields()?;
                Ok(SchemaType::Type(SchemaTypeVariant::Long))
            }
            Some("Boolean") => {
                error_if_any_fields()?;
                Ok(SchemaType::Type(SchemaTypeVariant::Boolean))
            }
            Some("Set") => {
                error_if_fields(
                    &[Attributes, AdditionalAttributes, Name],
                    &[type_field_name!(Element)],
                )?;

                if let Some(element) = element {
                    Ok(SchemaType::Type(SchemaTypeVariant::Set {
                        element: Box::new(element?),
                    }))
                } else {
                    Err(serde::de::Error::missing_field(Element.as_str()))
                }
            }
            Some("Record") => {
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
                    Ok(SchemaType::Type(SchemaTypeVariant::Record {
                        attributes: attributes?.0,
                        additional_attributes: additional_attributes?,
                    }))
                } else {
                    Err(serde::de::Error::missing_field(Attributes.as_str()))
                }
            }
            Some("Entity") => {
                error_if_fields(
                    &[Element, Attributes, AdditionalAttributes],
                    &[type_field_name!(Name)],
                )?;

                if let Some(name) = name {
                    Ok(SchemaType::Type(SchemaTypeVariant::Entity {
                        name: cedar_policy_core::ast::Name::from_normalized_str(&name?).map_err(
                            |err| serde::de::Error::custom(format!("invalid entity type: {err}")),
                        )?,
                    }))
                } else {
                    Err(serde::de::Error::missing_field(Name.as_str()))
                }
            }
            Some("Extension") => {
                error_if_fields(
                    &[Element, Attributes, AdditionalAttributes],
                    &[type_field_name!(Name)],
                )?;

                if let Some(name) = name {
                    Ok(SchemaType::Type(SchemaTypeVariant::Extension {
                        name: Id::from_normalized_str(&name?).map_err(|err| {
                            serde::de::Error::custom(format!("invalid extension type: {err}"))
                        })?,
                    }))
                } else {
                    Err(serde::de::Error::missing_field(Name.as_str()))
                }
            }
            Some(type_name) => {
                error_if_any_fields()?;
                Ok(SchemaType::TypeDef {
                    type_name: cedar_policy_core::ast::Name::from_normalized_str(type_name)
                        .map_err(|err| {
                            serde::de::Error::custom(format!("invalid common type: {err}"))
                        })?,
                })
            }
            None => Err(serde::de::Error::missing_field(Type.as_str())),
        }
    }
}

impl From<SchemaTypeVariant> for SchemaType {
    fn from(variant: SchemaTypeVariant) -> Self {
        Self::Type(variant)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum SchemaTypeVariant {
    String,
    Long,
    Boolean,
    Set {
        element: Box<SchemaType>,
    },
    Record {
        attributes: BTreeMap<SmolStr, TypeOfAttribute>,
        #[serde(rename = "additionalAttributes")]
        additional_attributes: bool,
    },
    Entity {
        name: Name,
    },
    Extension {
        name: Id,
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
            Self::Type(SchemaTypeVariant::Record { attributes, .. }) => attributes
                .values()
                .try_fold(false, |a, e| match e.ty.is_extension() {
                    Some(true) => Some(true),
                    Some(false) => Some(a),
                    None => None,
                }),
            Self::Type(_) => Some(false),
            Self::TypeDef { .. } => None,
        }
    }
}

#[cfg(feature = "arbitrary")]
// PANIC SAFETY property testing code
#[allow(clippy::panic)]
impl<'a> arbitrary::Arbitrary<'a> for SchemaType {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<SchemaType> {
        use std::collections::BTreeSet;

        Ok(SchemaType::Type(match u.int_in_range::<u8>(1..=8)? {
            1 => SchemaTypeVariant::String,
            2 => SchemaTypeVariant::Long,
            3 => SchemaTypeVariant::Boolean,
            4 => SchemaTypeVariant::Set {
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
                SchemaTypeVariant::Record {
                    attributes,
                    additional_attributes: u.arbitrary()?,
                }
            }
            6 => {
                let name: Name = u.arbitrary()?;
                SchemaTypeVariant::Entity { name }
            }
            7 => SchemaTypeVariant::Extension {
                // PANIC SAFETY: `ipaddr` is a valid `Id`
                #[allow(clippy::unwrap_used)]
                name: "ipaddr".parse().unwrap(),
            },
            8 => SchemaTypeVariant::Extension {
                // PANIC SAFETY: `decimal` is a valid `Id`
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
    use super::*;

    #[test]
    fn test_entity_type_parser1() {
        let user = r#"
        {
            "memberOfTypes" : ["UserGroup"]
        }
        "#;
        let et = serde_json::from_str::<EntityType>(user).expect("Parse Error");
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
            resource_types: Some(vec!["Album".parse().unwrap()]),
            principal_types: Some(vec!["User".parse().unwrap()]),
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
        let schema: NamespaceDefinition = serde_json::from_value(src).unwrap();
        println!("{:#?}", schema);
    }
}

/// Tests related to PR #749
#[cfg(test)]
mod strengthened_types {
    use cool_asserts::assert_matches;

    use crate::{
        ActionEntityUID, ApplySpec, EntityType, NamespaceDefinition, SchemaFragment, SchemaType,
    };

    #[test]
    fn invalid_namespace() {
        let src = serde_json::json!(
        {
           "\n" : {
            "entityTypes": {},
            "actions": {}
           }
        });
        let schema: Result<SchemaFragment, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid namespace: unexpected end of input");

        let src = serde_json::json!(
        {
           "1" : {
            "entityTypes": {},
            "actions": {}
           }
        });
        let schema: Result<SchemaFragment, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid namespace: unexpected token `1`");

        let src = serde_json::json!(
        {
           "*1" : {
            "entityTypes": {},
            "actions": {}
           }
        });
        let schema: Result<SchemaFragment, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid namespace: unexpected token `*`");
        let src = serde_json::json!(
        {
           "::" : {
            "entityTypes": {},
            "actions": {}
           }
        });
        let schema: Result<SchemaFragment, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid namespace: unexpected token `::`");
        let src = serde_json::json!(
        {
           "A::" : {
            "entityTypes": {},
            "actions": {}
           }
        });
        let schema: Result<SchemaFragment, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid namespace: unexpected end of input");
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
        let schema: Result<NamespaceDefinition, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid common type: unexpected end of input");

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
        let schema: Result<NamespaceDefinition, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid common type: invalid token");

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
        let schema: Result<NamespaceDefinition, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid common type: unexpected token `::`");
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
        let schema: Result<NamespaceDefinition, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid entity type: unexpected end of input");

        let src = serde_json::json!(
        {
            "entityTypes": {
                "*": {}
            },
            "actions": {}
        });
        let schema: Result<NamespaceDefinition, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid entity type: unexpected token `*`");

        let src = serde_json::json!(
        {
            "entityTypes": {
                "A::B": {}
            },
            "actions": {}
        });
        let schema: Result<NamespaceDefinition, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid entity type: unexpected token `::`");
    }

    #[test]
    fn invalid_member_of_types() {
        let src = serde_json::json!(
        {
           "memberOfTypes": [""]
        });
        let schema: Result<EntityType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid member of type: unexpected end of input");

        let src = serde_json::json!(
        {
           "memberOfTypes": ["*"]
        });
        let schema: Result<EntityType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid member of type: unexpected token `*`");

        let src = serde_json::json!(
        {
           "memberOfTypes": ["A::"]
        });
        let schema: Result<EntityType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid member of type: unexpected end of input");

        let src = serde_json::json!(
        {
           "memberOfTypes": ["::A"]
        });
        let schema: Result<EntityType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid member of type: unexpected token `::`");
    }

    #[test]
    fn invalid_apply_spec() {
        let src = serde_json::json!(
        {
           "resourceTypes": [""]
        });
        let schema: Result<ApplySpec, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid principal or resource types: unexpected end of input");

        let src = serde_json::json!(
        {
           "resourceTypes": ["*"]
        });
        let schema: Result<ApplySpec, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid principal or resource types: unexpected token `*`");

        let src = serde_json::json!(
        {
           "resourceTypes": ["A::"]
        });
        let schema: Result<ApplySpec, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid principal or resource types: unexpected end of input");

        let src = serde_json::json!(
        {
           "resourceTypes": ["::A"]
        });
        let schema: Result<ApplySpec, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid principal or resource types: unexpected token `::`");
    }

    #[test]
    fn invalid_schema_entity_types() {
        let src = serde_json::json!(
        {
           "type": "Entity",
            "name": ""
        });
        let schema: Result<SchemaType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid entity type: unexpected end of input");

        let src = serde_json::json!(
        {
           "type": "Entity",
            "name": "*"
        });
        let schema: Result<SchemaType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid entity type: unexpected token `*`");

        let src = serde_json::json!(
        {
           "type": "Entity",
            "name": "::A"
        });
        let schema: Result<SchemaType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid entity type: unexpected token `::`");
        let src = serde_json::json!(
        {
           "type": "Entity",
            "name": "A::"
        });
        let schema: Result<SchemaType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid entity type: unexpected end of input");
    }

    #[test]
    fn invalid_action_euid() {
        let src = serde_json::json!(
        {
           "id": "action",
            "type": ""
        });
        let schema: Result<ActionEntityUID, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid action type: unexpected end of input");

        let src = serde_json::json!(
        {
           "id": "action",
            "type": "*"
        });
        let schema: Result<ActionEntityUID, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid action type: unexpected token `*`");

        let src = serde_json::json!(
        {
           "id": "action",
            "type": "Action::"
        });
        let schema: Result<ActionEntityUID, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid action type: unexpected end of input");

        let src = serde_json::json!(
        {
           "id": "action",
            "type": "::Action"
        });
        let schema: Result<ActionEntityUID, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid action type: unexpected token `::`");
    }

    #[test]
    fn invalid_schema_common_types() {
        let src = serde_json::json!(
        {
           "type": ""
        });
        let schema: Result<SchemaType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid common type: unexpected end of input");

        let src = serde_json::json!(
        {
           "type": "*"
        });
        let schema: Result<SchemaType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid common type: unexpected token `*`");

        let src = serde_json::json!(
        {
           "type": "::A"
        });
        let schema: Result<SchemaType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid common type: unexpected token `::`");
        let src = serde_json::json!(
        {
           "type": "A::"
        });
        let schema: Result<SchemaType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid common type: unexpected end of input");
    }

    #[test]
    fn invalid_schema_extension_types() {
        let src = serde_json::json!(
        {
           "type": "Extension",
           "name": ""
        });
        let schema: Result<SchemaType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid extension type: unexpected end of input");

        let src = serde_json::json!(
        {
            "type": "Extension",
           "name": "*"
        });
        let schema: Result<SchemaType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid extension type: unexpected token `*`");

        let src = serde_json::json!(
        {
            "type": "Extension",
           "name": "__cedar::decimal"
        });
        let schema: Result<SchemaType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid extension type: unexpected token `::`");
        let src = serde_json::json!(
        {
            "type": "Extension",
           "name": "__cedar::"
        });
        let schema: Result<SchemaType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid extension type: unexpected token `::`");

        let src = serde_json::json!(
        {
            "type": "Extension",
           "name": "::__cedar"
        });
        let schema: Result<SchemaType, _> = serde_json::from_value(src);
        assert_matches!(schema, Err(err) if &err.to_string() == "invalid extension type: unexpected token `::`");
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
        serde_json::from_str::<SchemaFragment>(src).unwrap();
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
        serde_json::from_str::<SchemaFragment>(src).unwrap();
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
        serde_json::from_str::<SchemaFragment>(src).unwrap();
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
        serde_json::from_str::<SchemaFragment>(src).unwrap();
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
        serde_json::from_str::<SchemaFragment>(src).unwrap();
    }
}

#[cfg(test)]
mod test_resolver {
    use crate::{CommonTypeResolver, SchemaFragment};

    #[test]
    fn test_simple() {
        let mut schema = serde_json::from_value::<SchemaFragment>(serde_json::json!(
            {
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "b"
                        },
                        "b": {
                            "type": "Boolean"
                        }
                    }
                }
            }
        ))
        .unwrap();
        let mut resolver = CommonTypeResolver::new(&mut schema);
        let new_schema = resolver.resolve();
        assert!(new_schema.is_ok(), "{:?}", resolver);
    }
}
