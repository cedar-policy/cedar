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

use crate::schema_errors::TypeResolutionError;
use cedar_policy_core::ast::{Id, Name};
use cedar_policy_core::parser::Loc;
use itertools::Itertools;
use nonempty::{nonempty, NonEmpty};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A newtype which indicates that the contained `Name` may not yet be
/// fully-qualified.
///
/// You can convert it to a fully-qualified `Name` using `.qualify_with()` or
/// `.conditionally_qualify_with()`.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct RawName(Name);

impl RawName {
    /// Create a new `RawName` from the given `Id`
    pub fn new(id: Id) -> Self {
        Self(Name::unqualified_name(id))
    }

    /// Create a new `RawName` from the given `Name`.
    ///
    /// Note that if `name` includes explicit namespaces, the result will be a
    /// `RawName` that also includes those explicit namespaces, as if that
    /// fully-qualified name appeared directly in the (JSON or human) schema
    /// format.
    /// If `name` does not include explicit namespaces, the result will be a
    /// `RawName` that also does not include explicit namespaces, which may or
    /// may not translate back to the original input `name`, due to
    /// namespace-qualification rules.
    pub fn from_name(name: Name) -> Self {
        Self(name)
    }

    /// Create a new `RawName` from a basename, namespace components as `Id`s, and optional source location
    pub fn from_components(
        basename: Id,
        namespace: impl IntoIterator<Item = Id>,
        loc: Option<Loc>,
    ) -> Self {
        Self(Name::new(basename, namespace, loc))
    }

    /// Create a new `RawName` by parsing the provided string, which should contain
    /// an unqualified `Name` (no explicit namespaces)
    pub fn parse_unqualified_name(
        s: &str,
    ) -> Result<Self, cedar_policy_core::parser::err::ParseErrors> {
        Name::parse_unqualified_name(s).map(RawName)
    }

    /// Create a new `RawName` by parsing the provided string, which should contain
    /// a `Name` in normalized form.
    ///
    /// (See the [`cedar_policy_core::FromNormalizedStr`] trait.)
    pub fn from_normalized_str(
        s: &str,
    ) -> Result<Self, cedar_policy_core::parser::err::ParseErrors> {
        use cedar_policy_core::FromNormalizedStr;
        Name::from_normalized_str(s).map(RawName)
    }

    /// Is this `RawName` unqualified, that is, written without any _explicit_
    /// namespaces.
    /// (This method returning `true` does not imply that the `RawName` will
    /// _eventually resolve_ to an unqualified name.)
    pub fn is_unqualified(&self) -> bool {
        self.0.is_unqualified()
    }

    /// Convert this [`RawName`] to a [`Name`] by adding the given `ns` as its
    /// prefix, or by no-op if `ns` is `None`.
    ///
    /// Note that if the [`RawName`] already had a non-empty explicit namespace,
    /// no additional prefixing will be done, even if `ns` is `Some`.
    pub fn qualify_with(self, ns: Option<&Name>) -> Name {
        self.0.qualify_with(ns)
    }

    /// Convert this [`RawName`] to a [`ConditionalName`].
    /// This method is appropriate for when we encounter this [`RawName`] as a
    /// type reference while the current/active namespace is `ns` (or `None` if
    /// the current/active namespace is the empty namespace).
    ///
    /// This [`RawName`] will resolve as follows:
    /// - If the [`RawName`] already has a non-empty explicit namespace, there
    ///     is no ambiguity, and it will resolve always and only to itself
    /// - Otherwise (if the [`RawName`] does not have an explicit namespace
    ///     already), then it resolves to the following in priority order:
    ///     1. The fully-qualified name resulting from prefixing `ns` to this
    ///         [`RawName`], if that fully-qualified name is declared in the schema
    ///         (in any schema fragment)
    ///     2. Itself in the empty namespace, if that name is declared in the schema
    ///         (in any schema fragment)
    ///
    /// Note that if the [`RawName`] is the name of a primitive or extension
    /// type (without explicit `__cedar`), it will resolve via (2) above,
    /// because the primitive/extension type names will be added as defined
    /// typedefs in the empty namespace (aliasing to the real `__cedar`
    /// definitions), assuming the user didn't themselves define those names
    /// in the empty namespace.
    pub fn conditionally_qualify_with(
        self,
        ns: Option<&Name>,
        reference_type: ReferenceType,
    ) -> ConditionalName {
        let possibilities = if self.is_unqualified() {
            match ns {
                Some(ns) => {
                    // the `RawName` does not have any namespace attached, so it refers
                    // to something in the current namespace if available; otherwise, it
                    // refers to something in the empty namespace
                    nonempty![
                        self.clone().qualify_with(Some(ns)),
                        self.clone().qualify_with(None),
                    ]
                }
                None => {
                    // Same as the above case, but since the current/active
                    // namespace is the empty namespace, the two possibilities
                    // are the same; there is only one possibility
                    nonempty![self.clone().qualify_with(None)]
                }
            }
        } else {
            // if the `RawName` already had an explicit namespace, there's no
            // ambiguity
            nonempty![self.clone().qualify_with(None)]
        };
        ConditionalName {
            possibilities,
            reference_type,
            raw: self,
        }
    }
}

impl std::fmt::Display for RawName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for RawName {
    type Err = <Name as std::str::FromStr>::Err;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Name::from_str(s).map(RawName)
    }
}

/// A name which may refer to many possible different fully-qualified names,
/// depending on which of them are declared (in any schema fragment)
///
/// Caution using `==` on these: [`ConditionalName`]s are only equal if the have
/// the same raw (source) _and_ the same list of possible resolution targets (in
/// the same order), which in practice means they must be in the same
/// current/active namespace. In particular:
/// - two [`ConditionalName`]s which end up resolving to the same fully-qualified
/// name may nonetheless not be `==` in their [`ConditionalName`] forms; and
/// - two [`ConditionalName`]s which are written the same way in the original
/// schema may nonetheless not be `==` in their [`ConditionalName`] forms
///
/// This type has only one (trivial) public constructor; it is normally
/// constructed using [`RawName::conditionally_qualify_with()`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConditionalName {
    /// The [`ConditionalName`] may refer to any of these `possibilities`, depending
    /// on which of them are declared (in any schema fragment).
    ///
    /// These are in descending priority order. If the first `Name` is declared
    /// (in any schema fragment), then this `ConditionalName` refers to the first
    /// `Name`. If that `Name` is not declared in any schema fragment, then we
    /// check the second `Name`, etc.
    ///
    /// All of the contained `Name`s must be fully-qualified.
    ///
    /// Typical example: In
    /// ```ignore
    /// namespace "NS" { ... some reference to Foo ... }
    /// ```
    /// `Foo` is a `ConditionalName` with `possibilities = [NS::Foo, Foo]`.
    /// That is, if `NS::Foo` exists, `Foo` refers to `NS::Foo`, but otherwise,
    /// `Foo` refers to the `Foo` declared in the empty namespace.
    possibilities: NonEmpty<Name>,
    /// Whether the [`ConditionalName`] can resolve to a common-type name, an
    /// entity-type name, or both
    reference_type: ReferenceType,
    /// Copy of the original/raw name found in the source; this field is
    /// used only in error messages
    raw: RawName,
}

impl ConditionalName {
    /// Create a [`ConditionalName`] which unconditionally resolves to the given
    /// fully-qualified [`Name`].
    pub fn unconditional(name: Name, reference_type: ReferenceType) -> Self {
        ConditionalName {
            possibilities: nonempty!(name.clone()),
            reference_type,
            raw: RawName(name),
        }
    }

    /// Get the (not-yet-necessarily-fully-qualified) [`RawName`] which was
    /// encountered in the source, for the purposes of error messages
    pub fn raw(&self) -> &RawName {
        &self.raw
    }

    /// Resolve the [`ConditionalName`] into a fully-qualified [`Name`], given that
    /// `all_defined_common_types` and `all_defined_entity_types` represent all
    /// fully-qualified [`Name`]s defined in all schema fragments, as common and
    /// entity types respectively.
    pub fn resolve<'a>(
        self,
        all_defined_common_types: &'a HashSet<Name>,
        all_defined_entity_types: &'a HashSet<Name>,
    ) -> Result<&'a Name, TypeResolutionError> {
        for possibility in self.possibilities.iter() {
            // Per RFC 24, we give priority to trying to resolve to a common
            // type, before trying to resolve to an entity type.
            // (However, we have an even stronger preference to resolve earlier
            // in the `possibilities` list. So, in the hypothetical case where
            // we could resolve to either an entity type first in the
            // `possibilities` list, or a common type later in the
            // `possibilities` list, we choose the former.)
            // See also cedar#579.
            if matches!(
                self.reference_type,
                ReferenceType::Common | ReferenceType::CommonOrEntity
            ) {
                if let Some(possibility) = all_defined_common_types.get(possibility) {
                    return Ok(possibility);
                }
            }
            if matches!(
                self.reference_type,
                ReferenceType::Entity | ReferenceType::CommonOrEntity
            ) {
                if let Some(possibility) = all_defined_entity_types.get(possibility) {
                    return Ok(possibility);
                }
            }
        }
        Err(TypeResolutionError(nonempty![self]))
    }

    /// Provide a help message for the case where this [`ConditionalName`] failed to resolve
    pub(crate) fn resolution_failure_help(&self) -> String {
        match self.possibilities.len() {
            1 => format!("`{}` has not been declared", self.possibilities[0]),
            2 => format!(
                "neither `{}` nor `{}` refers to anything that has been declared",
                self.possibilities[0], self.possibilities[1]
            ),
            _ => format!(
                "none of these have been declared: {}",
                self.possibilities
                    .iter()
                    .map(|p| format!("`{p}`"))
                    .join(", ")
            ),
        }
    }
}

/// [`ConditionalName`] serializes as simply the raw name that was originally encountered in the schema
impl Serialize for ConditionalName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.raw().serialize(serializer)
    }
}

/// Describes whether a reference can resolve to a common-type name, an
/// entity-type name, or both
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReferenceType {
    /// The reference can only resolve to a common-type name
    Common,
    /// The reference can only resolve to an entity-type name
    Entity,
    /// The reference can resolve to either an entity or common type name
    CommonOrEntity,
}
