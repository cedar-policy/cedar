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
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, TryFromInto};
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;
use thiserror::Error;

/// The entity type that Actions must have
pub static ACTION_ENTITY_TYPE: &str = "Action";

/// Entity type names are just [`Name`]s, but we have some operations on them specific to entity types.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[serde(transparent)]
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

    /// Calls [`Name::qualify_with`] on the underlying [`Name`]
    pub fn qualify_with(&self, namespace: Option<&Name>) -> Self {
        Self(self.0.qualify_with(namespace))
    }

    /// Wraps [`Name::from_normalized_str`]
    pub fn from_normalized_str(src: &str) -> Result<Self, ParseErrors> {
        UncheckedName::from_normalized_str(src)
            .and_then(|n| n.try_into().map(Self).map_err(ParseErrors::singleton))
    }
}

impl From<Name> for EntityType {
    fn from(n: Name) -> Self {
        Self(n)
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
    /// We use a btreemap so that the keys have a determenistic order.
    ///
    /// In the serialized form of `Entity`, attribute values appear as
    /// `RestrictedExpr`s, for mostly historical reasons.
    attrs: BTreeMap<SmolStr, PartialValueSerializedAsExpr>,

    /// Set of ancestors of this `Entity` (i.e., all direct and transitive
    /// parents), as UIDs
    ancestors: HashSet<EntityUID>,
}

impl Entity {
    /// Create a new `Entity` with this UID, attributes, and ancestors
    pub fn new(
        uid: EntityUID,
        attrs: HashMap<SmolStr, RestrictedExpr>,
        ancestors: HashSet<EntityUID>,
        extensions: &Extensions<'_>,
    ) -> Result<Self, EntityAttrEvaluationError> {
        let evaluator = RestrictedEvaluator::new(extensions);
        let evaluated_attrs = attrs
            .into_iter()
            .map(|(k, v)| {
                let attr_val = evaluator
                    .partial_interpret(v.as_borrowed())
                    .map_err(|err| EntityAttrEvaluationError {
                        uid: uid.clone(),
                        attr: k.clone(),
                        err,
                    })?;
                Ok((k, attr_val.into()))
            })
            .collect::<Result<_, EntityAttrEvaluationError>>()?;
        Ok(Entity {
            uid,
            attrs: evaluated_attrs,
            ancestors,
        })
    }

    /// Create a new `Entity` with this UID, attributes, and ancestors.
    ///
    /// Unlike in `Entity::new()`, in this constructor, attributes are expressed
    /// as `PartialValue`.
    pub fn new_with_attr_partial_value(
        uid: EntityUID,
        attrs: HashMap<SmolStr, PartialValue>,
        ancestors: HashSet<EntityUID>,
    ) -> Self {
        Entity {
            uid,
            attrs: attrs.into_iter().map(|(k, v)| (k, v.into())).collect(), // TODO(#540): can we do this without disassembling and reassembling the HashMap
            ancestors,
        }
    }

    /// Create a new `Entity` with this UID, attributes, and ancestors.
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

    /// Iterate over this entity's attribute names
    pub fn keys(&self) -> impl Iterator<Item = &SmolStr> {
        self.attrs.keys()
    }

    /// Iterate over this entity's attributes
    pub fn attrs(&self) -> impl Iterator<Item = (&SmolStr, &PartialValue)> {
        self.attrs.iter().map(|(k, v)| (k, v.as_ref()))
    }

    /// Create an `Entity` with the given UID, no attributes, and no parents.
    pub fn with_uid(uid: EntityUID) -> Self {
        Self {
            uid,
            attrs: BTreeMap::new(),
            ancestors: HashSet::new(),
        }
    }

    /// Test if two `Entity` objects are deep/structurally equal.
    /// That is, not only do they have the same UID, but also the same
    /// attributes, attribute values, and ancestors.
    pub(crate) fn deep_eq(&self, other: &Self) -> bool {
        self.uid == other.uid && self.attrs == other.attrs && self.ancestors == other.ancestors
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

    /// Consume the entity and return the entity's owned Uid, attributes and parents.
    pub fn into_inner(
        self,
    ) -> (
        EntityUID,
        HashMap<SmolStr, PartialValue>,
        HashSet<EntityUID>,
    ) {
        let Self {
            uid,
            attrs,
            ancestors,
        } = self;
        (
            uid,
            attrs.into_iter().map(|(k, v)| (k, v.0)).collect(),
            ancestors,
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

/// Error type for evaluation errors when evaluating an entity attribute.
/// Contains some extra contextual information and the underlying
/// `EvaluationError`.
#[derive(Debug, Diagnostic, Error)]
#[error("failed to evaluate attribute `{attr}` of `{uid}`: {err}")]
pub struct EntityAttrEvaluationError {
    /// UID of the entity where the error was encountered
    pub uid: EntityUID,
    /// Attribute of the entity where the error was encountered
    pub attr: SmolStr,
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

    #[test]
    fn action_type_is_valid_id() {
        assert!(Id::from_normalized_str(ACTION_ENTITY_TYPE).is_ok());
    }
}
