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

/// An empty set literal. Legal today, but rejected by strict validation, which
/// cannot assign the empty set an element type. Warned about to ease migration.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("empty set literal")]
pub struct EmptySet {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for EmptySet {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "strict validation forbids empty set literals because it cannot infer their element type",
        ))
    }
}

/// An extension constructor called with a non-literal argument. Legal today,
/// but rejected by strict validation, which can only check constructor
/// arguments it can evaluate statically. Warned about to ease migration.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("extension constructor `{fn_name}` called with a non-literal argument")]
pub struct NonLitExtConstructor {
    pub(crate) loc: Option<Loc>,
    pub(crate) fn_name: Name,
}

impl Diagnostic for NonLitExtConstructor {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "consider applying extension constructors inside attribute values when constructing entity or context data",
        ))
    }
}

/// An extension constructor called with a literal argument that fails to parse.
/// Unlike the two warnings above, this is always a bug: the call is guaranteed
/// to error at evaluation time.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`{fn_name}` cannot be constructed from `{arg}`: {err}")]
pub struct ExtConstructorError {
    pub(crate) loc: Option<Loc>,
    pub(crate) fn_name: Name,
    pub(crate) arg: String,
    pub(crate) err: String,
    pub(crate) err_help: Option<String>,
}

impl Diagnostic for ExtConstructorError {
    impl_diagnostic_from_source_loc_opt_field!(loc);

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.err_help
            .as_ref()
            .map(|h| Box::new(h) as Box<dyn std::fmt::Display + 'a>)
    }
}

/// A multiplication where neither operand is a constant. Legal and cheap to
/// evaluate, but hard to *analyze*: symbolic analysis compiles `Long` to a
/// fixed-width bitvector, and a variable-by-variable multiply bit-blasts to a
/// multiplier circuit that SAT/SMT solvers reason through slowly. Multiplying by
/// a constant lowers to shifts and adds and stays cheap.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("multiplication of two non-constant expressions")]
pub struct NonLinearArithmetic {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for NonLinearArithmetic {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "multiplying two variables bit-blasts to a multiplier circuit that automated reasoning tools solve slowly; multiplying by a constant avoids it",
        ))
    }
}

/// Arithmetic in a `forbid` policy. Arithmetic errors on overflow, and a policy
/// whose condition errors is skipped, so an overflow here silently drops the
/// `forbid` and may allow a request that should have been denied.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("arithmetic in a `forbid` policy may cause the policy to be skipped")]
pub struct ArithmeticInForbid {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for ArithmeticInForbid {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "arithmetic errors on overflow, and a policy whose condition errors is skipped, so this `forbid` may fail to deny a request; consider bounding the operands or moving the arithmetic into the data",
        ))
    }
}

/// Arithmetic in a `permit` policy. Same mechanism as [`ArithmeticInForbid`],
/// but skipping a `permit` fails closed, so this is only a warning.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("arithmetic in a `permit` policy may cause the policy to be skipped")]
pub struct ArithmeticInPermit {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for ArithmeticInPermit {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "arithmetic errors on overflow, and a policy whose condition errors is skipped, so this `permit` may fail to allow a request",
        ))
    }
}
/// A `like` pattern with no wildcard, which is just a string equality.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`like` pattern `\"{pattern}\"` contains no wildcard")]
pub struct LikeWithoutWildcard {
    pub(crate) loc: Option<Loc>,
    pub(crate) pattern: String,
}

impl Diagnostic for LikeWithoutWildcard {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "this matches only the one exact string; use `==` to compare strings, or add a `*` wildcard",
        ))
    }
}

/// A `like` pattern of only wildcards, which matches every string.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`like` pattern `\"{pattern}\"` matches every string")]
pub struct LikeWithOnlyWildcards {
    pub(crate) loc: Option<Loc>,
    pub(crate) pattern: String,
}

impl Diagnostic for LikeWithOnlyWildcards {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "this comparison is always true for a string operand, so it has no effect",
        ))
    }
}

/// A `like` pattern with two or more consecutive wildcards, e.g. `"a**b"`. A run of
/// `*`s matches exactly what a single `*` matches, so the extra ones are redundant.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`like` pattern `\"{pattern}\"` has consecutive wildcards")]
pub struct LikeWithConsecutiveWildcards {
    pub(crate) loc: Option<Loc>,
    pub(crate) pattern: String,
}

impl Diagnostic for LikeWithConsecutiveWildcards {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "a run of `*`s matches the same as a single `*`; collapse each run to one wildcard",
        ))
    }
}

/// Two `like` patterns on the same operand — a prefix constraint (`"cs*"`) and a
/// suffix constraint (`"*p"`) — that combine into one equivalent pattern
/// (`"cs*p"`). Only reported when the prefix and suffix literals cannot overlap, so
/// the merge is exactly equivalent (see the lint docs).
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`like` patterns `\"{prefix}\"` and `\"{suffix}\"` on the same operand combine into one")]
pub struct CombinableLikePatterns {
    /// Anchored at the first of the two patterns in source order.
    pub(crate) loc: Option<Loc>,
    /// The prefix-constraint pattern (`"cs*"`), as written.
    pub(crate) prefix: String,
    /// The suffix-constraint pattern (`"*p"`), as written.
    pub(crate) suffix: String,
    /// The single equivalent pattern (`"cs*p"`).
    pub(crate) merged: String,
}

impl Diagnostic for CombinableLikePatterns {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "the prefix and suffix cannot overlap, so together they are exactly `like \"{}\"`; use that single pattern",
            self.merged,
        )))
    }
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
