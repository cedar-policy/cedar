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

use crate::ast::*;
use crate::entities::{err::EntitiesError, json::err::JsonSerializationError, EntityJson};
use crate::evaluator::{EvaluationError, RestrictedEvaluator};
use crate::extensions::Extensions;
use crate::parser::err::ParseErrors;
use crate::parser::Loc;
use crate::transitive_closure::TCNode;
use crate::FromNormalizedStr;
use itertools::Itertools;
use miette::Diagnostic;
use ref_cast::RefCast;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, TryFromInto};
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;
use thiserror::Error;

/// The entity type that Actions must have
pub static ACTION_ENTITY_TYPE: &str = "Action";

/// Entity type names are just [`Name`]s, but we have some operations on them specific to entity types.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Hash, PartialOrd, Ord, RefCast)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[serde(transparent)]
#[repr(transparent)]
pub struct EntityType(Name);

impl EntityType {
    /// Is this an Action entity type?
    /// Returns true when an entity type is an action entity type. This compares the
    /// base name for the type, so this will return true for any entity type named
    /// `Action` regardless of namespaces.
    pub fn is_action(&self) -> bool {
        self.0.as_ref().basename() == &Id::new_unchecked(ACTION_ENTITY_TYPE)
    }

    /// The name of this entity type
    pub fn name(&self) -> &Name {
        &self.0
    }

    /// The source location of this entity type
    pub fn loc(&self) -> Option<&Loc> {
        self.0.as_ref().loc()
    }

    /// Calls [`Name::qualify_with_name`] on the underlying [`Name`]
    pub fn qualify_with(&self, namespace: Option<&Name>) -> Self {
        Self(self.0.qualify_with_name(namespace))
    }

    /// Wraps [`Name::from_normalized_str`]
    pub fn from_normalized_str(src: &str) -> Result<Self, ParseErrors> {
        Name::from_normalized_str(src).map(Into::into)
    }
}

impl From<Name> for EntityType {
    fn from(n: Name) -> Self {
        Self(n)
    }
}

impl From<EntityType> for Name {
    fn from(ty: EntityType) -> Name {
        ty.0
    }
}

impl AsRef<Name> for EntityType {
    fn as_ref(&self) -> &Name {
        &self.0
    }
}

impl FromStr for EntityType {
    type Err = ParseErrors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

#[cfg(feature = "protobufs")]
impl From<&proto::EntityType> for EntityType {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &proto::EntityType) -> Self {
        Self(Name::from(
            v.name
                .as_ref()
                .expect("`as_ref()` for field that should exist"),
        ))
    }
}

#[cfg(feature = "protobufs")]
impl From<&EntityType> for proto::EntityType {
    fn from(v: &EntityType) -> Self {
        Self {
            name: Some(proto::Name::from(v.name())),
        }
    }
}

impl std::fmt::Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique ID for an entity. These represent entities in the AST.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EntityUID {
    /// Typename of the entity
    ty: EntityType,
    /// EID of the entity
    eid: Eid,
    /// Location of the entity in policy source
    #[serde(skip)]
    loc: Option<Loc>,
}

/// `PartialEq` implementation ignores the `loc`.
impl PartialEq for EntityUID {
    fn eq(&self, other: &Self) -> bool {
        self.ty == other.ty && self.eid == other.eid
    }
}
impl Eq for EntityUID {}

impl std::hash::Hash for EntityUID {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // hash the ty and eid, in line with the `PartialEq` impl which compares
        // the ty and eid.
        self.ty.hash(state);
        self.eid.hash(state);
    }
}

impl PartialOrd for EntityUID {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for EntityUID {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ty.cmp(&other.ty).then(self.eid.cmp(&other.eid))
    }
}

impl StaticallyTyped for EntityUID {
    fn type_of(&self) -> Type {
        Type::Entity {
            ty: self.ty.clone(),
        }
    }
}

impl EntityUID {
    /// Create an `EntityUID` with the given string as its EID.
    /// Useful for testing.
    #[cfg(test)]
    pub(crate) fn with_eid(eid: &str) -> Self {
        Self {
            ty: Self::test_entity_type(),
            eid: Eid(eid.into()),
            loc: None,
        }
    }
    // by default, Coverlay does not track coverage for lines after a line
    // containing #[cfg(test)].
    // we use the following sentinel to "turn back on" coverage tracking for
    // remaining lines of this file, until the next #[cfg(test)]
    // GRCOV_BEGIN_COVERAGE

    /// The type of entities created with the above `with_eid()`.
    #[cfg(test)]
    pub(crate) fn test_entity_type() -> EntityType {
        let name = Name::parse_unqualified_name("test_entity_type")
            .expect("test_entity_type should be a valid identifier");
        EntityType(name)
    }
    // by default, Coverlay does not track coverage for lines after a line
    // containing #[cfg(test)].
    // we use the following sentinel to "turn back on" coverage tracking for
    // remaining lines of this file, until the next #[cfg(test)]
    // GRCOV_BEGIN_COVERAGE

    /// Create an `EntityUID` with the given (unqualified) typename, and the given string as its EID.
    pub fn with_eid_and_type(typename: &str, eid: &str) -> Result<Self, ParseErrors> {
        Ok(Self {
            ty: EntityType(Name::parse_unqualified_name(typename)?),
            eid: Eid(eid.into()),
            loc: None,
        })
    }

    /// Split into the `EntityType` representing the entity type, and the `Eid`
    /// representing its name
    pub fn components(self) -> (EntityType, Eid) {
        (self.ty, self.eid)
    }

    /// Get the source location for this `EntityUID`.
    pub fn loc(&self) -> Option<&Loc> {
        self.loc.as_ref()
    }

    /// Create an [`EntityUID`] with the given typename and [`Eid`]
    pub fn from_components(ty: EntityType, eid: Eid, loc: Option<Loc>) -> Self {
        Self { ty, eid, loc }
    }

    /// Get the type component.
    pub fn entity_type(&self) -> &EntityType {
        &self.ty
    }

    /// Get the Eid component.
    pub fn eid(&self) -> &Eid {
        &self.eid
    }

    /// Does this EntityUID refer to an action entity?
    pub fn is_action(&self) -> bool {
        self.entity_type().is_action()
    }
}

impl std::fmt::Display for EntityUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::\"{}\"", self.entity_type(), self.eid.escaped())
    }
}

// allow `.parse()` on a string to make an `EntityUID`
impl std::str::FromStr for EntityUID {
    type Err = ParseErrors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::parser::parse_euid(s)
    }
}

impl FromNormalizedStr for EntityUID {
    fn describe_self() -> &'static str {
        "Entity UID"
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for EntityUID {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            ty: u.arbitrary()?,
            eid: u.arbitrary()?,
            loc: None,
        })
    }
}

#[cfg(feature = "protobufs")]
impl From<&proto::EntityUid> for EntityUID {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &proto::EntityUid) -> Self {
        let loc: Option<Loc> = v.loc.as_ref().map(Loc::from);
        Self {
            ty: EntityType::from(
                v.ty.as_ref()
                    .expect("`as_ref()` for field that should exist"),
            ),
            eid: Eid::new(v.eid.clone()),
            loc: loc,
        }
    }
}

#[cfg(feature = "protobufs")]
impl From<&EntityUID> for proto::EntityUid {
    fn from(v: &EntityUID) -> Self {
        let loc: Option<proto::Loc> = v.loc.as_ref().map(proto::Loc::from);
        let eid_ref: &str = v.eid.as_ref();
        Self {
            ty: Some(proto::EntityType::from(&v.ty)),
            eid: eid_ref.to_owned(),
            loc: loc,
        }
    }
}

/// The `Eid` type represents the id of an `Entity`, without the typename.
/// Together with the typename it comprises an `EntityUID`.
/// For example, in `User::"alice"`, the `Eid` is `alice`.
///
/// `Eid` does not implement `Display`, partly because it is unclear whether
/// `Display` should produce an escaped representation or an unescaped representation
/// (see [#884](https://github.com/cedar-policy/cedar/issues/884)).
/// To get an escaped representation, use `.escaped()`.
/// To get an unescaped representation, use `.as_ref()`.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Hash, PartialOrd, Ord)]
pub struct Eid(SmolStr);

impl Eid {
    /// Construct an Eid
    pub fn new(eid: impl Into<SmolStr>) -> Self {
        Eid(eid.into())
    }

    /// Get the contents of the `Eid` as an escaped string
    pub fn escaped(&self) -> SmolStr {
        self.0.escape_debug().collect()
    }
}

impl AsRef<SmolStr> for Eid {
    fn as_ref(&self) -> &SmolStr {
        &self.0
    }
}

impl AsRef<str> for Eid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Eid {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let x: String = u.arbitrary()?;
        Ok(Self(x.into()))
    }
}

/// Entity datatype
#[derive(Debug, Clone, Serialize)]
pub struct Entity {
    /// UID
    uid: EntityUID,

    /// Internal BTreMap of attributes.
    /// We use a btreemap so that the keys have a deterministic order.
    ///
    /// In the serialized form of `Entity`, attribute values appear as
    /// `RestrictedExpr`s, for mostly historical reasons.
    attrs: BTreeMap<SmolStr, PartialValueSerializedAsExpr>,

    /// Set of ancestors of this `Entity` (i.e., all direct and transitive
    /// parents), as UIDs
    ancestors: HashSet<EntityUID>,

    /// Tags on this entity (RFC 82)
    ///
    /// Like for `attrs`, we use a `BTreeMap` so that the tags have a
    /// deterministic order.
    /// And like in `attrs`, the values in `tags` appear as `RestrictedExpr` in
    /// the serialized form of `Entity`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    tags: BTreeMap<SmolStr, PartialValueSerializedAsExpr>,
}

impl std::hash::Hash for Entity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.uid.hash(state);
    }
}

impl Entity {
    /// Create a new `Entity` with this UID, attributes, ancestors, and tags
    ///
    /// # Errors
    /// - Will error if any of the [`RestrictedExpr]`s in `attrs` or `tags` error when evaluated
    pub fn new(
        uid: EntityUID,
        attrs: impl IntoIterator<Item = (SmolStr, RestrictedExpr)>,
        ancestors: HashSet<EntityUID>,
        tags: impl IntoIterator<Item = (SmolStr, RestrictedExpr)>,
        extensions: &Extensions<'_>,
    ) -> Result<Self, EntityAttrEvaluationError> {
        let evaluator = RestrictedEvaluator::new(extensions);
        let evaluate_kvs = |(k, v): (SmolStr, RestrictedExpr), was_attr: bool| {
            let attr_val = evaluator
                .partial_interpret(v.as_borrowed())
                .map_err(|err| EntityAttrEvaluationError {
                    uid: uid.clone(),
                    attr_or_tag: k.clone(),
                    was_attr,
                    err,
                })?;
            Ok((k, attr_val.into()))
        };
        let evaluated_attrs = attrs
            .into_iter()
            .map(|kv| evaluate_kvs(kv, true))
            .collect::<Result<_, EntityAttrEvaluationError>>()?;
        let evaluated_tags = tags
            .into_iter()
            .map(|kv| evaluate_kvs(kv, false))
            .collect::<Result<_, EntityAttrEvaluationError>>()?;
        Ok(Entity {
            uid,
            attrs: evaluated_attrs,
            ancestors,
            tags: evaluated_tags,
        })
    }

    /// Create a new `Entity` with this UID, attributes, and ancestors (and no tags)
    ///
    /// Unlike in `Entity::new()`, in this constructor, attributes are expressed
    /// as `PartialValue`.
    ///
    /// Callers should consider directly using [`Entity::new_with_attr_partial_value_serialized_as_expr`]
    /// if they would call this method by first building a map, as it will
    /// deconstruct and re-build the map perhaps unnecessarily.
    pub fn new_with_attr_partial_value(
        uid: EntityUID,
        attrs: impl IntoIterator<Item = (SmolStr, PartialValue)>,
        ancestors: HashSet<EntityUID>,
    ) -> Self {
        Self::new_with_attr_partial_value_serialized_as_expr(
            uid,
            attrs.into_iter().map(|(k, v)| (k, v.into())).collect(),
            ancestors,
        )
    }

    /// Create a new `Entity` with this UID, attributes, and ancestors (and no tags)
    ///
    /// Unlike in `Entity::new()`, in this constructor, attributes are expressed
    /// as `PartialValueSerializedAsExpr`.
    pub fn new_with_attr_partial_value_serialized_as_expr(
        uid: EntityUID,
        attrs: BTreeMap<SmolStr, PartialValueSerializedAsExpr>,
        ancestors: HashSet<EntityUID>,
    ) -> Self {
        Entity {
            uid,
            attrs,
            ancestors,
            tags: BTreeMap::new(),
        }
    }

    /// Get the UID of this entity
    pub fn uid(&self) -> &EntityUID {
        &self.uid
    }

    /// Get the value for the given attribute, or `None` if not present
    pub fn get(&self, attr: &str) -> Option<&PartialValue> {
        self.attrs.get(attr).map(|v| v.as_ref())
    }

    /// Get the value for the given tag, or `None` if not present
    pub fn get_tag(&self, tag: &str) -> Option<&PartialValue> {
        self.tags.get(tag).map(|v| v.as_ref())
    }

    /// Is this `Entity` a descendant of `e` in the entity hierarchy?
    pub fn is_descendant_of(&self, e: &EntityUID) -> bool {
        self.ancestors.contains(e)
    }

    /// Iterate over this entity's ancestors
    pub fn ancestors(&self) -> impl Iterator<Item = &EntityUID> {
        self.ancestors.iter()
    }

    /// Get the number of attributes on this entity
    pub fn attrs_len(&self) -> usize {
        self.attrs.len()
    }

    /// Get the number of tags on this entity
    pub fn tags_len(&self) -> usize {
        self.tags.len()
    }

    /// Iterate over this entity's attribute names
    pub fn keys(&self) -> impl Iterator<Item = &SmolStr> {
        self.attrs.keys()
    }

    /// Iterate over this entity's tag names
    pub fn tag_keys(&self) -> impl Iterator<Item = &SmolStr> {
        self.tags.keys()
    }

    /// Iterate over this entity's attributes
    pub fn attrs(&self) -> impl Iterator<Item = (&SmolStr, &PartialValue)> {
        self.attrs.iter().map(|(k, v)| (k, v.as_ref()))
    }

    /// Iterate over this entity's tags
    pub fn tags(&self) -> impl Iterator<Item = (&SmolStr, &PartialValue)> {
        self.tags.iter().map(|(k, v)| (k, v.as_ref()))
    }

    /// Create an `Entity` with the given UID, no attributes, no parents, and no tags.
    pub fn with_uid(uid: EntityUID) -> Self {
        Self {
            uid,
            attrs: BTreeMap::new(),
            ancestors: HashSet::new(),
            tags: BTreeMap::new(),
        }
    }

    /// Test if two `Entity` objects are deep/structurally equal.
    /// That is, not only do they have the same UID, but also the same
    /// attributes, attribute values, and ancestors.
    pub(crate) fn deep_eq(&self, other: &Self) -> bool {
        self.uid == other.uid && self.attrs == other.attrs && self.ancestors == other.ancestors
    }

    /// Set the UID to the given value.
    // Only used for convenience in some tests
    #[cfg(test)]
    pub fn set_uid(&mut self, uid: EntityUID) {
        self.uid = uid;
    }

    /// Set the given attribute to the given value.
    // Only used for convenience in some tests and when fuzzing
    #[cfg(any(test, fuzzing))]
    pub fn set_attr(
        &mut self,
        attr: SmolStr,
        val: RestrictedExpr,
        extensions: &Extensions<'_>,
    ) -> Result<(), EvaluationError> {
        let val = RestrictedEvaluator::new(extensions).partial_interpret(val.as_borrowed())?;
        self.attrs.insert(attr, val.into());
        Ok(())
    }

    /// Set the given tag to the given value.
    // Only used for convenience in some tests and when fuzzing
    #[cfg(any(test, fuzzing))]
    pub fn set_tag(
        &mut self,
        tag: SmolStr,
        val: RestrictedExpr,
        extensions: &Extensions<'_>,
    ) -> Result<(), EvaluationError> {
        let val = RestrictedEvaluator::new(extensions).partial_interpret(val.as_borrowed())?;
        self.tags.insert(tag, val.into());
        Ok(())
    }

    /// Mark the given `UID` as an ancestor of this `Entity`.
    // When fuzzing, `add_ancestor()` is fully `pub`.
    #[cfg(not(fuzzing))]
    pub(crate) fn add_ancestor(&mut self, uid: EntityUID) {
        self.ancestors.insert(uid);
    }
    /// Mark the given `UID` as an ancestor of this `Entity`
    #[cfg(fuzzing)]
    pub fn add_ancestor(&mut self, uid: EntityUID) {
        self.ancestors.insert(uid);
    }

    /// Consume the entity and return the entity's owned Uid, attributes, parents, and tags.
    pub fn into_inner(
        self,
    ) -> (
        EntityUID,
        HashMap<SmolStr, PartialValue>,
        HashSet<EntityUID>,
        HashMap<SmolStr, PartialValue>,
    ) {
        let Self {
            uid,
            attrs,
            ancestors,
            tags,
        } = self;
        (
            uid,
            attrs.into_iter().map(|(k, v)| (k, v.0)).collect(),
            ancestors,
            tags.into_iter().map(|(k, v)| (k, v.0)).collect(),
        )
    }

    /// Write the entity to a json document
    pub fn write_to_json(&self, f: impl std::io::Write) -> Result<(), EntitiesError> {
        let ejson = EntityJson::from_entity(self)?;
        serde_json::to_writer_pretty(f, &ejson).map_err(JsonSerializationError::from)?;
        Ok(())
    }

    /// write the entity to a json value
    pub fn to_json_value(&self) -> Result<serde_json::Value, EntitiesError> {
        let ejson = EntityJson::from_entity(self)?;
        let v = serde_json::to_value(ejson).map_err(JsonSerializationError::from)?;
        Ok(v)
    }

    /// write the entity to a json string
    pub fn to_json_string(&self) -> Result<String, EntitiesError> {
        let ejson = EntityJson::from_entity(self)?;
        let string = serde_json::to_string(&ejson).map_err(JsonSerializationError::from)?;
        Ok(string)
    }
}

impl PartialEq for Entity {
    fn eq(&self, other: &Self) -> bool {
        self.uid() == other.uid()
    }
}

impl Eq for Entity {}

impl StaticallyTyped for Entity {
    fn type_of(&self) -> Type {
        self.uid.type_of()
    }
}

impl TCNode<EntityUID> for Entity {
    fn get_key(&self) -> EntityUID {
        self.uid().clone()
    }

    fn add_edge_to(&mut self, k: EntityUID) {
        self.add_ancestor(k)
    }

    fn out_edges(&self) -> Box<dyn Iterator<Item = &EntityUID> + '_> {
        Box::new(self.ancestors())
    }

    fn has_edge_to(&self, e: &EntityUID) -> bool {
        self.is_descendant_of(e)
    }
}

impl std::fmt::Display for Entity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:\n  attrs:{}\n  ancestors:{}",
            self.uid,
            self.attrs
                .iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .join("; "),
            self.ancestors.iter().join(", ")
        )
    }
}

#[cfg(feature = "protobufs")]
impl From<&proto::Entity> for Entity {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &proto::Entity) -> Self {
        let eval = RestrictedEvaluator::new(&Extensions::none());

        let attrs: BTreeMap<SmolStr, PartialValueSerializedAsExpr> = v
            .attrs
            .iter()
            .map(|(key, value)| {
                let pval = eval
                    .partial_interpret(
                        BorrowedRestrictedExpr::new(&Expr::from(value)).expect("RestrictedExpr"),
                    )
                    .expect("interpret on RestrictedExpr");
                (key.into(), pval.into())
            })
            .collect();

        let ancestors: HashSet<EntityUID> = v.ancestors.iter().map(EntityUID::from).collect();

        let tags: BTreeMap<SmolStr, PartialValueSerializedAsExpr> = v
            .tags
            .iter()
            .map(|(key, value)| {
                let pval = eval
                    .partial_interpret(
                        BorrowedRestrictedExpr::new(&Expr::from(value)).expect("RestrictedExpr"),
                    )
                    .expect("interpret on RestrictedExpr");
                (key.into(), pval.into())
            })
            .collect();

        Self {
            uid: EntityUID::from(
                v.uid
                    .as_ref()
                    .expect("`as_ref()` for field that should exist"),
            ),
            attrs,
            ancestors,
            tags,
        }
    }
}

#[cfg(feature = "protobufs")]
impl From<&Entity> for proto::Entity {
    fn from(v: &Entity) -> Self {
        let mut attrs: HashMap<String, proto::Expr> = HashMap::with_capacity(v.attrs.len());
        for (key, value) in &v.attrs {
            attrs.insert(
                key.to_string(),
                proto::Expr::from(&Expr::from(PartialValue::from(value.to_owned()))),
            );
        }

        let mut ancestors: Vec<proto::EntityUid> = Vec::with_capacity(v.ancestors.len());
        for ancestor in &v.ancestors {
            ancestors.push(proto::EntityUid::from(ancestor));
        }

        let mut tags: HashMap<String, proto::Expr> = HashMap::with_capacity(v.tags.len());
        for (key, value) in &v.tags {
            tags.insert(
                key.to_string(),
                proto::Expr::from(&Expr::from(PartialValue::from(value.to_owned()))),
            );
        }

        Self {
            uid: Some(proto::EntityUid::from(&v.uid)),
            attrs,
            ancestors,
            tags,
        }
    }
}

/// `PartialValue`, but serialized as a `RestrictedExpr`.
///
/// (Extension values can't be directly serialized, but can be serialized as
/// `RestrictedExpr`)
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PartialValueSerializedAsExpr(
    #[serde_as(as = "TryFromInto<RestrictedExpr>")] PartialValue,
);

impl AsRef<PartialValue> for PartialValueSerializedAsExpr {
    fn as_ref(&self) -> &PartialValue {
        &self.0
    }
}

impl std::ops::Deref for PartialValueSerializedAsExpr {
    type Target = PartialValue;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<PartialValue> for PartialValueSerializedAsExpr {
    fn from(value: PartialValue) -> PartialValueSerializedAsExpr {
        PartialValueSerializedAsExpr(value)
    }
}

impl From<PartialValueSerializedAsExpr> for PartialValue {
    fn from(value: PartialValueSerializedAsExpr) -> PartialValue {
        value.0
    }
}

impl std::fmt::Display for PartialValueSerializedAsExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error type for evaluation errors when evaluating an entity attribute or tag.
/// Contains some extra contextual information and the underlying
/// `EvaluationError`.
//
// This is NOT a publicly exported error type.
#[derive(Debug, Diagnostic, Error)]
#[error("failed to evaluate {} `{attr_or_tag}` of `{uid}`: {err}", if *.was_attr { "attribute" } else { "tag" })]
pub struct EntityAttrEvaluationError {
    /// UID of the entity where the error was encountered
    pub uid: EntityUID,
    /// Attribute or tag of the entity where the error was encountered
    pub attr_or_tag: SmolStr,
    /// If `attr_or_tag` was an attribute (`true`) or tag (`false`)
    pub was_attr: bool,
    /// Underlying evaluation error
    #[diagnostic(transparent)]
    pub err: EvaluationError,
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn display() {
        let e = EntityUID::with_eid("eid");
        assert_eq!(format!("{e}"), "test_entity_type::\"eid\"");
    }

    #[test]
    fn test_euid_equality() {
        let e1 = EntityUID::with_eid("foo");
        let e2 = EntityUID::from_components(
            Name::parse_unqualified_name("test_entity_type")
                .expect("should be a valid identifier")
                .into(),
            Eid("foo".into()),
            None,
        );
        let e3 = EntityUID::from_components(
            Name::parse_unqualified_name("Unspecified")
                .expect("should be a valid identifier")
                .into(),
            Eid("foo".into()),
            None,
        );

        // an EUID is equal to itself
        assert_eq!(e1, e1);
        assert_eq!(e2, e2);

        // constructing with `with_euid` or `from_components` is the same
        assert_eq!(e1, e2);

        // other pairs are not equal
        assert!(e1 != e3);
    }

    #[test]
    fn action_checker() {
        let euid = EntityUID::from_str("Action::\"view\"").unwrap();
        assert!(euid.is_action());
        let euid = EntityUID::from_str("Foo::Action::\"view\"").unwrap();
        assert!(euid.is_action());
        let euid = EntityUID::from_str("Foo::\"view\"").unwrap();
        assert!(!euid.is_action());
        let euid = EntityUID::from_str("Action::Foo::\"view\"").unwrap();
        assert!(!euid.is_action());
    }

    #[cfg(feature = "protobufs")]
    #[test]
    fn round_trip_protobuf() {
        let name = Name::from_normalized_str("B::C::D").unwrap();
        let ety_specified = EntityType(name);
        assert_eq!(
            ety_specified,
            EntityType::from(&proto::EntityType::from(&ety_specified))
        );

        let euid1 = EntityUID::with_eid("foo");
        assert_eq!(euid1, EntityUID::from(&proto::EntityUid::from(&euid1)));

        let euid2 = EntityUID::from_str("Foo::Action::\"view\"").unwrap();
        assert_eq!(euid2, EntityUID::from(&proto::EntityUid::from(&euid2)));

        let attrs = (1..=7)
            .map(|id| (format!("{id}").into(), RestrictedExpr::val(true)))
            .collect::<HashMap<SmolStr, _>>();
        let entity = Entity::new(
            r#"Foo::"bar""#.parse().unwrap(),
            attrs.clone(),
            HashSet::new(),
            BTreeMap::new(),
            &Extensions::none(),
        )
        .unwrap();
        assert_eq!(entity, Entity::from(&proto::Entity::from(&entity)));
    }

    #[test]
    fn action_type_is_valid_id() {
        assert!(Id::from_normalized_str(ACTION_ENTITY_TYPE).is_ok());
    }
}
