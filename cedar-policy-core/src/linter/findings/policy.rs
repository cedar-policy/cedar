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

//! Finding types produced by the schema-free policy lints. Aggregated into
//! [`Finding`](super::Finding).

use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

use crate::{
    ast::{Name, Var},
    linter::types::Type,
    parser::Loc,
};

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

#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("expected {expected} but got {actual}")]
pub struct TypeError {
    pub(crate) loc: Option<Loc>,
    pub(crate) expected: Type,
    pub(crate) actual: Type,
}

impl Diagnostic for TypeError {
    impl_diagnostic_from_source_loc_opt_field!(loc);
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("expression relates two different types {ty1} and {ty2}")]
pub struct TypeMismatch {
    pub(crate) loc: Option<Loc>,
    pub(crate) ty1: Type,
    pub(crate) ty2: Type,
}

impl Diagnostic for TypeMismatch {
    impl_diagnostic_from_source_loc_opt_field!(loc);
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`getTag` is not preceded by corresponding `hasTag")]
pub struct TagError {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for TagError {
    impl_diagnostic_from_source_loc_opt_field!(loc);
}

/// Which kind of member was accessed on an action.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ActionMember {
    /// An attribute, as in `action.foo` or `action has foo`.
    Attribute,
    /// A tag, as in `action.getTag("t")` or `action.hasTag("t")`.
    Tag,
}

impl std::fmt::Display for ActionMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionMember::Attribute => write!(f, "attribute"),
            ActionMember::Tag => write!(f, "tag"),
        }
    }
}

/// An attribute or tag access on an action.
///
/// Legal today: an action entity in the store may carry attributes and tags, and
/// Cedar evaluates the access normally. But a schema cannot declare either on an
/// action, so strict validation rejects the policy. Warned about to ease migration.
///
/// Attributes and tags are one finding because the cause, the consequence, and the
/// fix are the same; the `member` field says which was written.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("{member} accessed on an action{}", match &self.name {
    Some(n) => format!(" (`{n}`)"),
    None => String::new(),
})]
pub struct ActionMemberAccess {
    pub(crate) loc: Option<Loc>,
    pub(crate) member: ActionMember,
    /// The attribute name, where it is statically known. A tag name is an
    /// arbitrary expression, so it is often absent.
    pub(crate) name: Option<String>,
}

impl Diagnostic for ActionMemberAccess {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "a schema cannot declare {member}s on an action, so strict validation will reject this; consider moving the value into the context",
            member = self.member,
        )))
    }
}

/// An `is` test that no entity can satisfy, because the operand is known to be an
/// action and the type named is not, or vice versa.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("{target} is never of type `{entity_type}`")]
pub struct ImpossibleIsCheck {
    pub(crate) loc: Option<Loc>,
    pub(crate) entity_type: String,
    pub(crate) target: &'static str,
}

impl Diagnostic for ImpossibleIsCheck {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "`action` is always an action type and `principal`/`resource` never are, so this test is always `false`",
        ))
    }
}
