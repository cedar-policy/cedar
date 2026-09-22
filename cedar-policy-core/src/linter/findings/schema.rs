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

//! Finding types produced by the schema lints. Aggregated into
//! [`SchemaFinding`](super::SchemaFinding).

use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

use crate::parser::Loc;

// Shorthand macro for setting the diagnostic severity to Warning. Used for
// lints that flag constructs which are legal today but rejected by strict
// validation, so they only advise about a future migration.
macro_rules! impl_diagnostic_warning {
    () => {
        fn severity(&self) -> Option<miette::Severity> {
            Some(miette::Severity::Warning)
        }
    };
}

/// An attribute whose type is `Set<{key: String, value: T}>`, the idiom used to
/// emulate tags before Cedar had a native `tags` construct. Legal, but native
/// `tags` express the intent directly and are analyzable as tags.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("attribute `{attribute}` on `{entity_type}` looks like emulated tags")]
pub struct AttributeShouldBeTags {
    pub(crate) loc: Option<Loc>,
    pub(crate) entity_type: String,
    pub(crate) attribute: SmolStr,
}

impl Diagnostic for AttributeShouldBeTags {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "`Set<{key: String, value: T}>` emulates tags; consider declaring native `tags T` on the entity type instead",
        ))
    }
}

/// Several entity types in one namespace sharing a name prefix (`PhotoApp_User`,
/// `PhotoApp_Album`, ...), which a namespace would express more cleanly.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("{} entity types share the prefix `{prefix}`", members.len())]
pub struct SharedPrefixNamespace {
    pub(crate) loc: Option<Loc>,
    /// The namespace these types are declared in, if any.
    pub(crate) namespace: Option<String>,
    pub(crate) prefix: String,
    /// The type names sharing the prefix.
    pub(crate) members: Vec<SmolStr>,
}

impl Diagnostic for SharedPrefixNamespace {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "consider a `namespace {prefix} {{ ... }}` with types `{}` instead of the `{prefix}_` prefix",
            self.members.join("`, `"),
            prefix = self.prefix,
        )))
    }
}

/// A declared entity type that no action applies to and that no other type
/// references, so it can never appear in a request or be reached.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("entity type `{entity_type}` is declared but never used")]
pub struct UnusedEntityType {
    pub(crate) loc: Option<Loc>,
    pub(crate) entity_type: String,
}

impl Diagnostic for UnusedEntityType {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "no action's `appliesTo` names it and no other type references it, so no request can involve it; remove it or wire it up",
        ))
    }
}

/// A declared common type that no other type references.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("common type `{common_type}` is declared but never used")]
pub struct UnusedCommonType {
    pub(crate) loc: Option<Loc>,
    pub(crate) common_type: String,
}

impl Diagnostic for UnusedCommonType {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "nothing refers to it, so it has no effect; remove it",
        ))
    }
}

/// An action that no other action lists in its `memberOf`, i.e. a leaf that is
/// also not a group. Reported only for actions that are never a parent *and*
/// never applied — see the lint docs for the precise, conservative condition.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("action `{action}` is declared but never used")]
pub struct UnusedAction {
    pub(crate) loc: Option<Loc>,
    pub(crate) action: String,
}

impl Diagnostic for UnusedAction {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "no policy scope can name it usefully and no action groups it; remove it or add it to a group",
        ))
    }
}

/// A `memberOf` (entity `in`, or action `in`) list that names the same parent
/// more than once. The repeat has no effect on the hierarchy.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`{parent}` is listed more than once in the membership of `{member}`")]
pub struct DuplicateMemberOf {
    pub(crate) loc: Option<Loc>,
    pub(crate) member: String,
    pub(crate) parent: String,
}

impl Diagnostic for DuplicateMemberOf {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "membership is a set, so the repeat has no effect; list each parent once",
        ))
    }
}

/// An enumerated entity type declaring the same EID choice more than once, e.g.
/// `enum ["red", "red"]`. The repeat is inert and likely a typo.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("enum type `{entity_type}` repeats the choice `\"{choice}\"`")]
pub struct DuplicateEnumChoice {
    pub(crate) loc: Option<Loc>,
    pub(crate) entity_type: String,
    pub(crate) choice: SmolStr,
}

impl Diagnostic for DuplicateEnumChoice {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "the choices are a set, so the repeat has no effect; list each choice once",
        ))
    }
}

/// Several entity types sharing many of the same attributes (same name, type, and
/// required-ness), whether or not their shapes are fully identical. The shared
/// block is a candidate for a common type.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("{} entity types share {} attributes ({attrs})", entity_types.len(), shared_count)]
pub struct SharedAttributes {
    pub(crate) loc: Option<Loc>,
    /// The entity types sharing the attribute block.
    pub(crate) entity_types: Vec<String>,
    /// How many attributes they share.
    pub(crate) shared_count: usize,
    /// The shared attribute names, for the message.
    pub(crate) attrs: String,
    /// Whether every one of these types has *only* the shared attributes (a full
    /// duplicate) or has additional ones of its own (a partial overlap).
    pub(crate) full: bool,
}

impl Diagnostic for SharedAttributes {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(if self.full {
            "these types have identical shapes; consider a common type they all use"
        } else {
            "these types share an attribute block; consider factoring it into a common type"
        }))
    }
}

/// An entity type that is referenced only as the type of an attribute — never a
/// principal or resource of any action, never a member of a hierarchy, never
/// otherwise referenced. Its only role is to give structure to that attribute,
/// which a common-type record expresses inline without a separate entity.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("entity type `{entity_type}` is used only as an attribute type")]
pub struct EntityAttrShouldBeCommonType {
    pub(crate) loc: Option<Loc>,
    pub(crate) entity_type: String,
    /// Where the attribute lives, e.g. ``attribute `address` on `User` ``, for
    /// the message.
    pub(crate) used_at: String,
}

impl Diagnostic for EntityAttrShouldBeCommonType {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "it appears only as {used_at}; a common-type record inlines that structure with no separate entity to store or dereference. This does not apply if the same entity is meant to be shared by reference across owners, or if a policy needs to test the entity's existence",
            used_at = self.used_at,
        )))
    }
}

/// Two entity types applicable in the same position (principal or resource) for
/// one action each declare an attribute of the same name but with different types.
/// A policy scoped to that action reading `principal.attr` (or `resource.attr`)
/// therefore sees a different type depending on which entity is supplied — a
/// latent bug, and the schema-side of the union-type footgun.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`{position}` types `{type_a}` and `{type_b}` of action `{action}` both declare attribute `{attribute}` with different types")]
pub struct ConflictingAppliesToAttr {
    pub(crate) loc: Option<Loc>,
    /// The action whose `appliesTo` lists both types, e.g. ``Action::"view"``.
    pub(crate) action: String,
    /// Which scope position they share: `principal` or `resource`.
    pub(crate) position: &'static str,
    /// The two conflicting entity types, in sorted order.
    pub(crate) type_a: String,
    pub(crate) type_b: String,
    /// The attribute they disagree on.
    pub(crate) attribute: SmolStr,
}

impl Diagnostic for ConflictingAppliesToAttr {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "a policy for `{action}` that reads `{position}.{attribute}` gets a different type depending on which entity is the {position}; give the attribute one type across both, or rename one",
            action = self.action,
            position = self.position,
            attribute = self.attribute,
        )))
    }
}

/// Two actions declare a `context` attribute of the same name but with different
/// types (up to entity types). A policy not scoped to a single action — or a
/// shared condition over several — reads `context.attr` without knowing which
/// action's context is in play, so the access is type-ambiguous.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("actions `{action_a}` and `{action_b}` declare context attribute `{attribute}` with different types")]
pub struct ConflictingContextAttr {
    pub(crate) loc: Option<Loc>,
    /// The two actions whose contexts disagree, in sorted order.
    pub(crate) action_a: String,
    pub(crate) action_b: String,
    /// The context attribute they disagree on.
    pub(crate) attribute: SmolStr,
}

impl Diagnostic for ConflictingContextAttr {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "a policy that reads `context.{attribute}` without pinning the action gets a different type depending on which action is in play; give the attribute one type across both, or rename one",
            attribute = self.attribute,
        )))
    }
}

/// Two entity types applicable in the same position (principal or resource) for
/// one action carry tags of different types (up to entity types). A policy scoped
/// to that action calling `principal.getTag(k)` (or `resource.getTag(k)`) sees a
/// different tag type depending on which entity is supplied — the tag-side of the
/// union-type footgun.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`{position}` types `{type_a}` and `{type_b}` of action `{action}` carry tags of different types")]
pub struct ConflictingTagType {
    pub(crate) loc: Option<Loc>,
    /// The action whose `appliesTo` lists both types, e.g. ``Action::"view"``.
    pub(crate) action: String,
    /// Which scope position they share: `principal` or `resource`.
    pub(crate) position: &'static str,
    /// The two conflicting entity types, in sorted order.
    pub(crate) type_a: String,
    pub(crate) type_b: String,
}

impl Diagnostic for ConflictingTagType {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "a policy for `{action}` that calls `{position}.getTag(..)` gets a different type depending on which entity is the {position}; give the tags one type across both",
            action = self.action,
            position = self.position,
        )))
    }
}
