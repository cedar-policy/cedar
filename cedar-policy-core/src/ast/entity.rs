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

use crate::ast::*;
use crate::parser::err::ParseError;
use crate::transitive_closure::TCNode;
use crate::FromNormalizedStr;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::{HashMap, HashSet};

/// We support two types of entities. The first is a nominal type (e.g., User, Action)
/// and the second is an unspecified type, which is used (internally) to represent cases
/// where the input request does not provide a principal, action, and/or resource.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Hash, PartialOrd, Ord)]
#[cfg_attr(fuzzing, derive(arbitrary::Arbitrary))]
pub enum EntityType {
    /// Concrete nominal type
    Concrete(Name),
    /// Unspecified
    Unspecified,
}

// Note: the characters '<' and '>' are not allowed in `Name`s, so the display for
// `Unspecified` never conflicts with `Concrete(name)`.
impl std::fmt::Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspecified => write!(f, "<Unspecified>"),
            Self::Concrete(name) => write!(f, "{}", name),
        }
    }
}

/// Unique ID for an entity. These represent entities in the AST.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Hash, PartialOrd, Ord)]
#[cfg_attr(fuzzing, derive(arbitrary::Arbitrary))]
pub struct EntityUID {
    /// Typename of the entity
    ty: EntityType,
    /// EID of the entity
    eid: Eid,
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
        EntityType::Concrete(name)
    }
    // by default, Coverlay does not track coverage for lines after a line
    // containing #[cfg(test)].
    // we use the following sentinel to "turn back on" coverage tracking for
    // remaining lines of this file, until the next #[cfg(test)]
    // GRCOV_BEGIN_COVERAGE

    /// Create an `EntityUID` with the given (unqualified) typename, and the given string as its EID.
    pub fn with_eid_and_type(typename: &str, eid: &str) -> Result<Self, Vec<ParseError>> {
        Ok(Self {
            ty: EntityType::Concrete(Name::parse_unqualified_name(typename)?),
            eid: Eid(eid.into()),
        })
    }

    /// Split into the `EntityType` representing the entity type, and the `Eid`
    /// representing its name
    pub fn components(self) -> (EntityType, Eid) {
        (self.ty, self.eid)
    }

    /// Create a nominally-typed `EntityUID` with the given typename and EID
    pub fn from_components(name: Name, eid: Eid) -> Self {
        Self {
            ty: EntityType::Concrete(name),
            eid,
        }
    }

    /// Create an unspecified `EntityUID` with the given EID
    pub fn unspecified_from_eid(eid: Eid) -> Self {
        Self {
            ty: EntityType::Unspecified,
            eid,
        }
    }

    /// Get the type component.
    pub fn entity_type(&self) -> &EntityType {
        &self.ty
    }

    /// Get the Eid component.
    pub fn eid(&self) -> &Eid {
        &self.eid
    }
}

impl std::fmt::Display for EntityUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::\"{}\"", self.entity_type(), self.eid)
    }
}

// allow `.parse()` on a string to make an `EntityUID`
impl std::str::FromStr for EntityUID {
    type Err = Vec<ParseError>;

    fn from_str(s: &str) -> Result<Self, Vec<ParseError>> {
        crate::parser::parse_euid(s)
    }
}

impl FromNormalizedStr for EntityUID {
    fn describe_self() -> &'static str {
        "Entity UID"
    }
}

/// EID type is just a SmolStr for now
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Hash, PartialOrd, Ord)]
pub struct Eid(SmolStr);

impl Eid {
    /// Construct an Eid
    pub fn new(eid: impl Into<SmolStr>) -> Self {
        Eid(eid.into())
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

#[cfg(fuzzing)]
impl<'a> arbitrary::Arbitrary<'a> for Eid {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let x: String = u.arbitrary()?;
        Ok(Self(x.into()))
    }
}

impl std::fmt::Display for Eid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.escape_debug())
    }
}

/// Entity datatype
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entity {
    /// UID
    uid: EntityUID,

    /// Internal HashMap of attributes.
    ///
    /// In the serialized form of `Entity`, attribute values appear as
    /// `RestrictedExpr`s.
    attrs: HashMap<SmolStr, RestrictedExpr>,

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
    ) -> Self {
        Entity {
            uid,
            attrs,
            ancestors,
        }
    }

    /// Get the UID of this entity
    pub fn uid(&self) -> EntityUID {
        self.uid.clone()
    }

    /// Get the value for the given attribute, or `None` if not present
    pub fn get(&self, attr: &str) -> Option<&RestrictedExpr> {
        self.attrs.get(attr)
    }

    /// Is this `Entity` a descendant of `e` in the entity hierarchy?
    pub fn is_descendant_of(&self, e: &EntityUID) -> bool {
        self.ancestors.contains(e)
    }

    /// Iterate over this entity's ancestors
    pub fn ancestors(&self) -> impl Iterator<Item = &EntityUID> {
        self.ancestors.iter()
    }

    /// Create an `Entity` with the given UID, no attributes, and no parents.
    pub fn with_uid(uid: EntityUID) -> Self {
        Self {
            uid,
            attrs: HashMap::new(),
            ancestors: HashSet::new(),
        }
    }

    /// Read-only access the internal `attrs` map of String to RestrictedExpr.
    /// This function is available only inside Core.
    pub(crate) fn attrs(&self) -> &HashMap<SmolStr, RestrictedExpr> {
        &self.attrs
    }

    /// Set the given attribute to the given value.
    // Only used for convenience in some tests and when fuzzing
    #[cfg(any(test, fuzzing))]
    pub fn set_attr(&mut self, attr: SmolStr, val: RestrictedExpr) {
        self.attrs.insert(attr, val);
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
        self.uid()
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

#[cfg(test)]
mod test {
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
            Name::parse_unqualified_name("test_entity_type").expect("should be a valid identifier"),
            Eid("foo".into()),
        );
        let e3 = EntityUID::unspecified_from_eid(Eid("foo".into()));
        let e4 = EntityUID::unspecified_from_eid(Eid("bar".into()));
        let e5 = EntityUID::from_components(
            Name::parse_unqualified_name("Unspecified").expect("should be a valid identifier"),
            Eid("foo".into()),
        );

        // an EUID is equal to itself
        assert_eq!(e1, e1);
        assert_eq!(e2, e2);
        assert_eq!(e3, e3);

        // constructing with `with_euid` or `from_components` is the same
        assert_eq!(e1, e2);

        // other pairs are not equal
        assert!(e1 != e3);
        assert!(e1 != e4);
        assert!(e1 != e5);
        assert!(e3 != e4);
        assert!(e3 != e5);
        assert!(e4 != e5);

        // e3 and e5 are displayed differently
        assert!(format!("{e3}") != format!("{e5}"));
    }
}
