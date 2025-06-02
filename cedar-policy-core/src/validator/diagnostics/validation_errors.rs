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

//! Defines errors returned by the validator.

use crate::entities::conformance::err::InvalidEnumEntityError;
use miette::Diagnostic;
use thiserror::Error;

use std::fmt::Display;

use crate::fuzzy_match::fuzzy_search;
use crate::impl_diagnostic_from_source_loc_opt_field;
use crate::parser::Loc;

use std::collections::BTreeSet;

use crate::ast::{Eid, EntityType, EntityUID, Expr, ExprKind, PolicyID, Var};
use crate::parser::join_with_conjunction;

use crate::validator::level_validate::EntityDerefLevel;
use crate::validator::types::{EntityLUB, EntityRecordKind, RequestEnv, Type};
use crate::validator::ValidatorSchema;
use itertools::Itertools;
use smol_str::SmolStr;

/// Structure containing details about an unrecognized entity type error.
#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
// #[error(error_in_policy!("unrecognized entity type `{actual_entity_type}`"))]
#[error("for policy `{policy_id}`, unrecognized entity type `{actual_entity_type}`")]
pub struct UnrecognizedEntityType {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
    /// The entity type seen in the policy.
    pub actual_entity_type: String,
    /// An entity type from the schema that the user might reasonably have
    /// intended to write.
    pub suggested_entity_type: Option<String>,
}

impl Diagnostic for UnrecognizedEntityType {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        match &self.suggested_entity_type {
            Some(s) => Some(Box::new(format!("did you mean `{s}`?"))),
            None => None,
        }
    }
}

/// Structure containing details about an unrecognized action id error.
#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
#[error("for policy `{policy_id}`, unrecognized action `{actual_action_id}`")]
pub struct UnrecognizedActionId {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
    /// Action Id seen in the policy
    pub actual_action_id: String,
    /// Hint for resolving the error
    pub hint: Option<UnrecognizedActionIdHelp>,
}

impl Diagnostic for UnrecognizedActionId {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.hint
            .as_ref()
            .map(|help| Box::new(help) as Box<dyn std::fmt::Display>)
    }
}

/// Help for resolving an unrecognized action id error
#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
pub enum UnrecognizedActionIdHelp {
    /// Draw attention to action id including action type (e.g., `Action::"Action::view"`)
    #[error("did you intend to include the type in action `{0}`?")]
    AvoidActionTypeInActionId(String),
    /// Suggest an alternative action
    #[error("did you mean `{0}`?")]
    SuggestAlternative(String),
}

/// Determine the help to offer in the presence of an unrecognized action id error.
pub fn unrecognized_action_id_help(
    euid: &EntityUID,
    schema: &ValidatorSchema,
) -> Option<UnrecognizedActionIdHelp> {
    // Check if the user has included the type (i.e., `Action::`) in the action id
    let eid_str: &str = euid.eid().as_ref();
    let eid_with_type = format!("Action::{}", eid_str);
    let eid_with_type_and_quotes = format!("Action::\"{}\"", eid_str);
    let maybe_id_with_type = schema.action_ids().find(|action_id| {
        let eid = <Eid as AsRef<str>>::as_ref(action_id.name().eid());
        eid.contains(&eid_with_type) || eid.contains(&eid_with_type_and_quotes)
    });
    if let Some(id) = maybe_id_with_type {
        // In that case, let the user know about it
        Some(UnrecognizedActionIdHelp::AvoidActionTypeInActionId(
            id.name().to_string(),
        ))
    } else {
        // Otherwise, suggest using another id
        let euids_strs = schema
            .action_ids()
            .map(|id| id.name().to_string())
            .collect::<Vec<_>>();
        fuzzy_search(euid.eid().as_ref(), &euids_strs)
            .map(UnrecognizedActionIdHelp::SuggestAlternative)
    }
}

/// Structure containing details about an invalid action application error.
#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
#[error("for policy `{policy_id}`, unable to find an applicable action given the policy scope constraints")]
pub struct InvalidActionApplication {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
    /// `true` if changing `==` to `in` wouuld fix the principal clause
    pub would_in_fix_principal: bool,
    /// `true` if changing `==` to `in` wouuld fix the resource clause
    pub would_in_fix_resource: bool,
}

impl Diagnostic for InvalidActionApplication {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        match (self.would_in_fix_principal, self.would_in_fix_resource) {
            (true, false) => Some(Box::new(
                "try replacing `==` with `in` in the principal clause",
            )),
            (false, true) => Some(Box::new(
                "try replacing `==` with `in` in the resource clause",
            )),
            (true, true) => Some(Box::new(
                "try replacing `==` with `in` in the principal clause and the resource clause",
            )),
            (false, false) => None,
        }
    }
}

/// Structure containing details about an unexpected type error.
#[derive(Error, Debug, Clone, Hash, PartialEq, Eq)]
#[error("for policy `{policy_id}`, unexpected type: expected {} but saw {}",
    match .expected.iter().next() {
        Some(single) if .expected.len() == 1 => format!("{}", single),
        _ => .expected.iter().join(", or ")
    },
    .actual)]
pub struct UnexpectedType {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
    /// Type(s) which were expected
    pub expected: Vec<Type>,
    /// Type which was encountered
    pub actual: Type,
    /// Optional help for resolving the error
    pub help: Option<UnexpectedTypeHelp>,
}

impl Diagnostic for UnexpectedType {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.help.as_ref().map(|h| Box::new(h) as Box<dyn Display>)
    }
}

/// Help for resolving a type error
#[derive(Error, Debug, Clone, Hash, Eq, PartialEq)]
pub enum UnexpectedTypeHelp {
    /// Try using `like`
    #[error("try using `like` to examine the contents of a string")]
    TryUsingLike,
    /// Try using `contains`, `containsAny`, or `containsAll`
    #[error(
        "try using `contains`, `containsAny`, or `containsAll` to examine the contents of a set"
    )]
    TryUsingContains,
    /// Try using `contains`
    #[error("try using `contains` to test if a single element is in a set")]
    TryUsingSingleContains,
    /// Try using `has`
    #[error("try using `has` to test for an attribute")]
    TryUsingHas,
    /// Try using `is`
    #[error("try using `is` to test for an entity type")]
    TryUsingIs,
    /// Try using `in`
    #[error("try using `in` for entity hierarchy membership")]
    TryUsingIn,
    /// Try using `== ""`
    #[error(r#"try using `== ""` to test if a string is empty"#)]
    TryUsingEqEmptyString,
    /// Cedar doesn't support type tests
    #[error("Cedar only supports run time type tests for entities")]
    TypeTestNotSupported,
    /// Cedar doesn't support string concatenation
    #[error("Cedar does not support string concatenation")]
    ConcatenationNotSupported,
    /// Cedar doesn't support set union, intersection, or difference
    #[error("Cedar does not support computing the union, intersection, or difference of sets")]
    SetOperationsNotSupported,
}

/// Structure containing details about an incompatible type error.
#[derive(Error, Debug, Clone, Hash, PartialEq, Eq)]
pub struct IncompatibleTypes {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
    /// Types which are incompatible
    pub types: BTreeSet<Type>,
    /// Hint for resolving the error
    pub hint: LubHelp,
    /// `LubContext` for the error
    pub context: LubContext,
}

impl Diagnostic for IncompatibleTypes {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new(format!(
            "for policy `{}`, {} must have compatible types. {}",
            self.policy_id, self.context, self.hint
        )))
    }
}

impl Display for IncompatibleTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the types ")?;
        join_with_conjunction(f, "and", self.types.iter(), |f, t| write!(f, "{t}"))?;
        write!(f, " are not compatible")
    }
}

/// Hints for resolving an incompatible-types error
#[derive(Error, Debug, Clone, Hash, Eq, PartialEq)]
pub enum LubHelp {
    /// Attribute qualifier problems
    #[error("Corresponding attributes of compatible record types must have the same optionality, either both being required or both being optional")]
    AttributeQualifier,
    /// Width subtyping
    #[error("Compatible record types must have exactly the same attributes")]
    RecordWidth,
    /// Entities are nominally typed
    #[error("Different entity types are never compatible even when their attributes would be compatible")]
    EntityType,
    /// Entity and record types are never compatible
    #[error("Entity and record types are never compatible even when their attributes would be compatible")]
    EntityRecord,
    /// Catchall
    #[error("Types must be exactly equal to be compatible")]
    None,
}

/// Text describing where the incompatible-types error was found
#[derive(Error, Debug, Clone, Hash, Eq, PartialEq)]
pub enum LubContext {
    /// In the elements of a set
    #[error("elements of a set")]
    Set,
    /// In the branches of a conditional
    #[error("both branches of a conditional")]
    Conditional,
    /// In the operands to `==`
    #[error("both operands to a `==` expression")]
    Equality,
    /// In the operands of `contains`
    #[error("elements of the first operand and the second operand to a `contains` expression")]
    Contains,
    /// In the operand of `containsAny` or `containsAll`
    #[error("elements of both set operands to a `containsAll` or `containsAny` expression")]
    ContainsAnyAll,
    /// While computing the type of a `.getTag()` operation
    #[error("tag types for a `.getTag()` operation")]
    GetTag,
}

/// Structure containing details about a missing attribute error.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Error)]
#[error("for policy `{policy_id}`, attribute {attribute_access} not found")]
pub struct UnsafeAttributeAccess {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
    /// More details about the missing-attribute error
    pub attribute_access: AttributeAccess,
    /// Optional suggestion for resolving the error
    pub suggestion: Option<String>,
    /// When this is true, the attribute might still exist, but the validator
    /// cannot guarantee that it will.
    pub may_exist: bool,
}

impl Diagnostic for UnsafeAttributeAccess {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        match (&self.suggestion, self.may_exist) {
            (Some(suggestion), false) => Some(Box::new(format!("did you mean `{suggestion}`?"))),
            (None, true) => Some(Box::new("there may be additional attributes that the validator is not able to reason about".to_string())),
            (Some(suggestion), true) => Some(Box::new(format!("did you mean `{suggestion}`? (there may also be additional attributes that the validator is not able to reason about)"))),
            (None, false) => None,
        }
    }
}

/// Structure containing details about an unsafe optional attribute error.
#[derive(Error, Debug, Clone, Hash, PartialEq, Eq)]
#[error("for policy `{policy_id}`, unable to guarantee safety of access to optional attribute {attribute_access}")]
pub struct UnsafeOptionalAttributeAccess {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
    /// More details about the attribute-access error
    pub attribute_access: AttributeAccess,
}

impl Diagnostic for UnsafeOptionalAttributeAccess {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new(format!(
            "try testing for the attribute's presence with `{} && ..`",
            self.attribute_access.suggested_has_guard()
        )))
    }
}

/// Structure containing details about an unsafe tag access error.
#[derive(Error, Debug, Clone, Hash, PartialEq, Eq)]
#[error(
    "for policy `{policy_id}`, unable to guarantee safety of access to tag `{tag}`{}",
    match .entity_ty.as_ref().and_then(|lub| lub.get_single_entity()) {
        Some(ety) => format!(" on entity type `{ety}`"),
        None => "".to_string()
    }
)]
pub struct UnsafeTagAccess {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
    /// `EntityLUB` that we tried to access a tag on (or `None` if not an `EntityLUB`, for example, an `AnyEntity`)
    pub entity_ty: Option<EntityLUB>,
    /// Tag name which we tried to access. May be a nonconstant `Expr`.
    pub tag: Expr<Option<Type>>,
}

impl Diagnostic for UnsafeTagAccess {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new(format!(
            "try testing for the tag's presence with `.hasTag({}) && ..`",
            &self.tag
        )))
    }
}

/// Structure containing details about a no-tags-allowed error.
#[derive(Error, Debug, Clone, Hash, PartialEq, Eq)]
#[error(
    "for policy `{policy_id}`, `.getTag()` is not allowed on entities of {} because no `tags` were declared on the entity type in the schema",
    match .entity_ty.as_ref() {
        Some(ty) => format!("type `{ty}`"),
        None => "this type".to_string(),
    }
)]
pub struct NoTagsAllowed {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
    /// Entity type which we tried to call `.getTag()` on but which doesn't have any tags allowed in the schema
    ///
    /// `None` indicates some kind of LUB involving multiple entity types, or `AnyEntity`
    pub entity_ty: Option<EntityType>,
}

impl Diagnostic for NoTagsAllowed {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);
}

/// Structure containing details about an undefined function error.
#[derive(Error, Debug, Clone, Hash, PartialEq, Eq)]
#[error("for policy `{policy_id}`, undefined extension function: {name}")]
pub struct UndefinedFunction {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
    /// Name of the undefined function
    pub name: String,
}

impl Diagnostic for UndefinedFunction {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);
}

/// Structure containing details about a wrong number of arguments error.
#[derive(Error, Debug, Clone, Hash, PartialEq, Eq)]
#[error("for policy `{policy_id}`, wrong number of arguments in extension function application. Expected {expected}, got {actual}")]
pub struct WrongNumberArguments {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
    /// Expected number of arguments
    pub expected: usize,
    /// Actual number of arguments
    pub actual: usize,
}

impl Diagnostic for WrongNumberArguments {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);
}

/// Structure containing details about a function argument validation error.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Error)]
#[error("for policy `{policy_id}`, error during extension function argument validation: {msg}")]
pub struct FunctionArgumentValidation {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
    /// Error message
    pub msg: String,
}

impl Diagnostic for FunctionArgumentValidation {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);
}

/// Structure containing details about a hierarchy not respected error
#[derive(Debug, Clone, Hash, Eq, PartialEq, Error)]
#[error("Internal invariant violated: `HierarchyNotRespected` error should never occur. Please file an issue")]
pub struct HierarchyNotRespected {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
}

impl Diagnostic for HierarchyNotRespected {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new("please file an issue at <https://github.com/cedar-policy/cedar/issues> including the schema and policy that caused this error"))
    }
}

/// Structure containing details about entity dereference level violation
#[derive(Debug, Clone, Hash, Eq, PartialEq, Error)]
#[error("for policy `{policy_id}`, {violation_kind}")]
pub struct EntityDerefLevelViolation {
    /// Location of outer most dereference
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
    /// Provides more information about the specific kind of violation
    pub violation_kind: EntityDerefViolationKind,
}

/// Details for specific kinds of entity deref level violations
#[derive(Debug, Clone, Hash, Eq, PartialEq, Error)]
pub enum EntityDerefViolationKind {
    /// The policy exceeded the maximum allowed level
    #[error(
        "this policy requires level {actual_level}, which exceeds the maximum allowed level ({allowed_level})"
    )]
    MaximumLevelExceeded {
        /// The maximum level allowed by the schema
        allowed_level: EntityDerefLevel,
        /// The actual level this policy uses
        actual_level: EntityDerefLevel,
    },
    /// The policy dereferences an entity literal, which isn't allowed at any level
    #[error("entity literals cannot be dereferenced at any level")]
    LiteralDerefTarget,
}

impl Diagnostic for EntityDerefLevelViolation {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);
}

/// The policy uses an empty set literal in a way that is forbidden
#[derive(Debug, Clone, Hash, Eq, PartialEq, Error)]
#[error("for policy `{policy_id}`, empty set literals are forbidden in policies")]
pub struct EmptySetForbidden {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
}

impl Diagnostic for EmptySetForbidden {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);
}

/// The policy passes a non-literal to an extension constructor, which is
/// forbidden in strict validation
#[derive(Debug, Clone, Hash, Eq, PartialEq, Error)]
#[error("for policy `{policy_id}`, extension constructors may not be called with non-literal expressions")]
pub struct NonLitExtConstructor {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
}

impl Diagnostic for NonLitExtConstructor {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new(
            "consider applying extension constructors inside attribute values when constructing entity or context data"
        ))
    }
}

/// Returned when an internal invariant is violated (should not happen; if
/// this is ever returned, please file an issue)
#[derive(Debug, Clone, Hash, Eq, PartialEq, Error)]
#[error("internal invariant violated")]
pub struct InternalInvariantViolation {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
}

impl Diagnostic for InternalInvariantViolation {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new(
            "please file an issue at <https://github.com/cedar-policy/cedar/issues> including the schema and policy for which you observed the issue"
        ))
    }
}

/// Contains more detailed information about an attribute access when it occurs
/// on an entity type expression or on the `context` variable. Track a `Vec` of
/// attributes rather than a single attribute so that on `principal.foo.bar` can
/// report that the record attribute `foo` of an entity type (e.g., `User`)
/// needs attributes `bar` instead of giving up when the immediate target of the
/// attribute access is not a entity.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum AttributeAccess {
    /// The attribute access is some sequence of attributes accesses eventually
    /// targeting an [`EntityLUB`].
    EntityLUB(EntityLUB, Vec<SmolStr>),
    /// The attribute access is some sequence of attributes accesses eventually
    /// targeting the `context` variable. The context being accessed is identified
    /// by the [`EntityUID`] for the associated action.
    Context(EntityUID, Vec<SmolStr>),
    /// Other cases where we do not attempt to give more information about the
    /// access. This includes any access on the `AnyEntity` type and on record
    /// types other than the `context` variable.
    Other(Vec<SmolStr>),
}

impl AttributeAccess {
    /// Construct an `AttributeAccess` access from a `GetAttr` expression `expr.attr`.
    pub(crate) fn from_expr(
        req_env: &RequestEnv<'_>,
        mut expr: &Expr<Option<Type>>,
        attr: SmolStr,
    ) -> AttributeAccess {
        let mut attrs: Vec<SmolStr> = vec![attr];
        loop {
            if let Some(Type::EntityOrRecord(EntityRecordKind::Entity(lub))) = expr.data() {
                return AttributeAccess::EntityLUB(lub.clone(), attrs);
            } else if matches!(expr.expr_kind(), ExprKind::Var(Var::Context)) {
                return match req_env.action_entity_uid() {
                    Some(action) => AttributeAccess::Context(action.clone(), attrs),
                    None => AttributeAccess::Other(attrs),
                };
            } else if let ExprKind::GetAttr {
                expr: sub_expr,
                attr,
            } = expr.expr_kind()
            {
                expr = sub_expr;
                attrs.push(attr.clone());
            } else {
                return AttributeAccess::Other(attrs);
            }
        }
    }

    pub(crate) fn attrs(&self) -> &Vec<SmolStr> {
        match self {
            AttributeAccess::EntityLUB(_, attrs) => attrs,
            AttributeAccess::Context(_, attrs) => attrs,
            AttributeAccess::Other(attrs) => attrs,
        }
    }

    /// Construct a `has` expression that we can use to suggest a fix after an
    /// unsafe optional attribute access.
    pub(crate) fn suggested_has_guard(&self) -> String {
        // We know if this is an access directly on `context`, so we can suggest
        // specifically `context has ..`. Otherwise, we just use a generic `e`.
        let base_expr = match self {
            AttributeAccess::Context(_, _) => "context".into(),
            _ => "e".into(),
        };

        let (safe_attrs, err_attr) = match self.attrs().split_first() {
            Some((first, rest)) => (rest, first.clone()),
            // We should always have a least one attribute stored, so this
            // shouldn't be possible. If it does happen, just use a placeholder
            // attribute name `f` since we'd rather avoid panicking.
            None => (&[] as &[SmolStr], "f".into()),
        };

        let full_expr = std::iter::once(&base_expr)
            .chain(safe_attrs.iter().rev())
            .join(".");
        format!("{full_expr} has {err_attr}")
    }
}

impl Display for AttributeAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let attrs_str = self.attrs().iter().rev().join(".");
        match self {
            AttributeAccess::EntityLUB(lub, _) => write!(
                f,
                "`{attrs_str}` on entity type{}",
                match lub.get_single_entity() {
                    Some(single) => format!(" `{}`", single),
                    _ => format!("s {}", lub.iter().map(|ety| format!("`{ety}`")).join(", ")),
                },
            ),
            AttributeAccess::Context(action, _) => {
                write!(f, "`{attrs_str}` in context for {action}",)
            }
            AttributeAccess::Other(_) => write!(f, "`{attrs_str}`"),
        }
    }
}

/// Returned when an entity literal is of an enumerated entity type but has
/// undeclared UID
#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
#[error("for policy `{policy_id}`: {err}")]
pub struct InvalidEnumEntity {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the error occurred
    pub policy_id: PolicyID,
    /// The error
    pub err: InvalidEnumEntityError,
}

impl Diagnostic for InvalidEnumEntity {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.err.help()
    }
}

// These tests all assume that the typechecker found an error while checking the
// outermost `GetAttr` in the expressions. If the attribute didn't exist at all,
// only the primary message would included in the final error. If it was an
// optional attribute without a guard, then the help message is also printed.
#[cfg(test)]
mod test_attr_access {
    use crate::{
        ast::{EntityUID, Expr, ExprBuilder, ExprKind, Var},
        expr_builder::ExprBuilder as _,
    };

    use super::AttributeAccess;
    use crate::validator::types::{OpenTag, RequestEnv, Type};

    // PANIC SAFETY: testing
    #[allow(clippy::panic)]
    #[track_caller]
    fn assert_message_and_help(
        attr_access: &Expr<Option<Type>>,
        msg: impl AsRef<str>,
        help: impl AsRef<str>,
    ) {
        let env = RequestEnv::DeclaredAction {
            principal: &"Principal".parse().unwrap(),
            action: &EntityUID::with_eid_and_type(crate::ast::ACTION_ENTITY_TYPE, "action")
                .unwrap(),
            resource: &"Resource".parse().unwrap(),
            context: &Type::record_with_attributes(None, OpenTag::ClosedAttributes),
            principal_slot: None,
            resource_slot: None,
        };

        let ExprKind::GetAttr { expr, attr } = attr_access.expr_kind() else {
            panic!("Can only test `AttributeAccess::from_expr` for `GetAttr` expressions");
        };

        let access = AttributeAccess::from_expr(&env, expr, attr.clone());
        assert_eq!(
            access.to_string().as_str(),
            msg.as_ref(),
            "Error message did not match expected"
        );
        assert_eq!(
            access.suggested_has_guard().as_str(),
            help.as_ref(),
            "Suggested has guard did not match expected"
        );
    }

    #[test]
    fn context_access() {
        // We have to build the Expr manually because the `EntityLUB` case
        // requires type annotations, even though the other cases ignore them.
        let e = ExprBuilder::new().get_attr(ExprBuilder::new().var(Var::Context), "foo".into());
        assert_message_and_help(
            &e,
            "`foo` in context for Action::\"action\"",
            "context has foo",
        );
        let e = ExprBuilder::new().get_attr(e, "bar".into());
        assert_message_and_help(
            &e,
            "`foo.bar` in context for Action::\"action\"",
            "context.foo has bar",
        );
        let e = ExprBuilder::new().get_attr(e, "baz".into());
        assert_message_and_help(
            &e,
            "`foo.bar.baz` in context for Action::\"action\"",
            "context.foo.bar has baz",
        );
    }

    #[test]
    fn entity_access() {
        let e = ExprBuilder::new().get_attr(
            ExprBuilder::with_data(Some(Type::named_entity_reference_from_str("User")))
                .val("User::\"alice\"".parse::<EntityUID>().unwrap()),
            "foo".into(),
        );
        assert_message_and_help(&e, "`foo` on entity type `User`", "e has foo");
        let e = ExprBuilder::new().get_attr(e, "bar".into());
        assert_message_and_help(&e, "`foo.bar` on entity type `User`", "e.foo has bar");
        let e = ExprBuilder::new().get_attr(e, "baz".into());
        assert_message_and_help(
            &e,
            "`foo.bar.baz` on entity type `User`",
            "e.foo.bar has baz",
        );
    }

    #[test]
    fn entity_type_attr_access() {
        let e = ExprBuilder::with_data(Some(Type::named_entity_reference_from_str("Thing")))
            .get_attr(
                ExprBuilder::with_data(Some(Type::named_entity_reference_from_str("User")))
                    .var(Var::Principal),
                "thing".into(),
            );
        assert_message_and_help(&e, "`thing` on entity type `User`", "e has thing");
        let e = ExprBuilder::new().get_attr(e, "bar".into());
        assert_message_and_help(&e, "`bar` on entity type `Thing`", "e has bar");
        let e = ExprBuilder::new().get_attr(e, "baz".into());
        assert_message_and_help(&e, "`bar.baz` on entity type `Thing`", "e.bar has baz");
    }

    #[test]
    fn other_access() {
        let e = ExprBuilder::new().get_attr(
            ExprBuilder::new().ite(
                ExprBuilder::new().val(true),
                ExprBuilder::new().record([]).unwrap(),
                ExprBuilder::new().record([]).unwrap(),
            ),
            "foo".into(),
        );
        assert_message_and_help(&e, "`foo`", "e has foo");
        let e = ExprBuilder::new().get_attr(e, "bar".into());
        assert_message_and_help(&e, "`foo.bar`", "e.foo has bar");
        let e = ExprBuilder::new().get_attr(e, "baz".into());
        assert_message_and_help(&e, "`foo.bar.baz`", "e.foo.bar has baz");
    }
}
