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

use miette::Diagnostic;
use thiserror::Error;

use std::fmt::Display;

use cedar_policy_core::impl_diagnostic_from_source_loc_field;
use cedar_policy_core::parser::Loc;

use std::collections::BTreeSet;

use cedar_policy_core::ast::{
    CallStyle, EntityUID, Expr, ExprKind, ExprShapeOnly, Name, PolicyID, Var,
};
use cedar_policy_core::parser::join_with_conjunction;

use crate::types::{EntityLUB, EntityRecordKind, RequestEnv, Type};
use itertools::Itertools;
use smol_str::SmolStr;

// This macro implements `cedar_policy_core::impl_diagnostic_from_source_loc_field`
// for the validation error variants that have `on_expr` instead.  Some variants
// use `on_expr` instead of `source_loc` because many tests were written to
// check that an error was raised on a particular expression rather than at a
// source location.  Storing the `Expr` should not be required because we only
// care about the source location emended in the expression.  To avoid cloning
// expressions when constructing errors, we should remove `on_expr` and rewrite
// the affected tests to only check for the correct `source_loc`.
macro_rules! impl_diagnostic_from_on_expr_field {
    () => {
        fn source_code(&self) -> Option<&dyn miette::SourceCode> {
            self.on_expr
                .source_loc()
                .as_ref()
                .map(|loc| &loc.src as &dyn miette::SourceCode)
        }

        fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
            self.on_expr.source_loc().as_ref().map(|loc| {
                Box::new(std::iter::once(miette::LabeledSpan::underline(loc.span)))
                    as Box<dyn Iterator<Item = _>>
            })
        }
    };
}

/// Structure containing details about an unrecognized entity type error.
#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
// #[error(error_in_policy!("unrecognized entity type `{actual_entity_type}`"))]
#[error("for policy `{policy_id}`, unrecognized entity type `{actual_entity_type}`")]
pub struct UnrecognizedEntityType {
    pub source_loc: Option<Loc>,
    pub policy_id: PolicyID,
    /// The entity type seen in the policy.
    pub actual_entity_type: String,
    /// An entity type from the schema that the user might reasonably have
    /// intended to write.
    pub suggested_entity_type: Option<String>,
}

impl Diagnostic for UnrecognizedEntityType {
    impl_diagnostic_from_source_loc_field!();

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
    pub source_loc: Option<Loc>,
    pub policy_id: PolicyID,
    /// Action Id seen in the policy.
    pub actual_action_id: String,
    /// An action id from the schema that the user might reasonably have
    /// intended to write.
    pub suggested_action_id: Option<String>,
}

impl Diagnostic for UnrecognizedActionId {
    impl_diagnostic_from_source_loc_field!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        match &self.suggested_action_id {
            Some(s) => Some(Box::new(format!("did you mean `{s}`?"))),
            None => None,
        }
    }
}

/// Structure containing details about an invalid action application error.
#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
#[error("for policy `{policy_id}`, unable to find an applicable action given the policy scope constraints")]
pub struct InvalidActionApplication {
    pub source_loc: Option<Loc>,
    pub policy_id: PolicyID,
    pub would_in_fix_principal: bool,
    pub would_in_fix_resource: bool,
}

impl Diagnostic for InvalidActionApplication {
    impl_diagnostic_from_source_loc_field!();

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

/// Structure containing details about an unspecified entity error.
#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
#[error("for policy `{policy_id}`, unspecified entity with id `{entity_id}`")]
pub struct UnspecifiedEntity {
    pub source_loc: Option<Loc>,
    pub policy_id: PolicyID,
    /// EID of the unspecified entity.
    pub entity_id: String,
}

impl Diagnostic for UnspecifiedEntity {
    impl_diagnostic_from_source_loc_field!();

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new("unspecified entities cannot be used in policies"))
    }
}

/// Structure containing details about an unexpected type error.
#[derive(Error, Debug, Clone, Eq)]
#[error("for policy `{policy_id}`, unexpected type: expected {} but saw {}",
    match .expected.iter().next() {
        Some(single) if .expected.len() == 1 => format!("{}", single),
        _ => .expected.iter().join(", or ")
    },
    .actual)]
pub struct UnexpectedType {
    pub on_expr: Expr,
    pub policy_id: PolicyID,
    pub expected: BTreeSet<Type>,
    pub actual: Type,
    pub help: Option<UnexpectedTypeHelp>,
}

impl std::hash::Hash for UnexpectedType {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        ExprShapeOnly::new(&self.on_expr).hash(state);
        self.expected.hash(state);
        self.actual.hash(state);
        self.help.hash(state);
    }
}

// Manual `PartialEq` implementations are so that we do not need to have the
// same source location for on errors when asserting error equality in tests
// cases. We can remove this impls if we replace `on_expr` with a `Loc` and
// update tests cases with the correct value for this loc check source
// locations.
impl PartialEq for UnexpectedType {
    fn eq(&self, other: &Self) -> bool {
        ExprShapeOnly::new(&self.on_expr) == ExprShapeOnly::new(&other.on_expr)
            && self.expected == other.expected
            && self.actual == other.actual
            && self.help == other.help
    }
}

impl Diagnostic for UnexpectedType {
    impl_diagnostic_from_on_expr_field!();

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.help.as_ref().map(|h| Box::new(h) as Box<dyn Display>)
    }
}

#[derive(Error, Debug, Clone, Hash, Eq, PartialEq)]
pub enum UnexpectedTypeHelp {
    #[error("try using `like` to examine the contents of a string")]
    TryUsingLike,
    #[error(
        "try using `contains`, `containsAny`, or `containsAll` to examine the contents of a set"
    )]
    TryUsingContains,
    #[error("try using `contains` to test if a single element is in a set")]
    TryUsingSingleContains,
    #[error("try using `has` to test for an attribute")]
    TryUsingHas,
    #[error("try using `is` to test for an entity type")]
    TryUsingIs,
    #[error("try using `in` for entity hierarchy membership")]
    TryUsingIn,
    #[error("Cedar only supports run time type tests for entities")]
    TypeTestNotSupported,
    #[error("Cedar does not support string concatenation")]
    ConcatenationNotSupported,
    #[error("Cedar does not support computing the union, intersection, or difference of sets")]
    SetOperationsNotSupported,
}

/// Structure containing details about an incompatible type error.
#[derive(Error, Debug, Clone, Eq)]
pub struct IncompatibleTypes {
    pub on_expr: Expr,
    pub policy_id: PolicyID,
    pub types: BTreeSet<Type>,
    pub hint: LubHelp,
    pub context: LubContext,
}

impl std::hash::Hash for IncompatibleTypes {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        ExprShapeOnly::new(&self.on_expr).hash(state);
        self.types.hash(state);
        self.hint.hash(state);
        self.context.hash(state);
    }
}
impl PartialEq for IncompatibleTypes {
    fn eq(&self, other: &Self) -> bool {
        ExprShapeOnly::new(&self.on_expr) == ExprShapeOnly::new(&other.on_expr)
            && self.types == other.types
            && self.hint == other.hint
            && self.context == other.context
    }
}

impl Diagnostic for IncompatibleTypes {
    impl_diagnostic_from_on_expr_field!();

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

#[derive(Error, Debug, Clone, Hash, Eq, PartialEq)]
pub enum LubHelp {
    #[error("Corresponding attributes of compatible record types must have the same optionality, either both being required or both being optional")]
    AttributeQualifier,
    #[error("Compatible record types must have exactly the same attributes")]
    RecordWidth,
    #[error("Different entity types are never compatible even when their attributes would be compatible")]
    EntityType,
    #[error("Entity and record types are never compatible even when their attributes would be compatible")]
    EntityRecord,
    #[error("Types must be exactly equal to be compatible")]
    None,
}

#[derive(Error, Debug, Clone, Hash, Eq, PartialEq)]
pub enum LubContext {
    #[error("elements of a set")]
    Set,
    #[error("both branches of a conditional")]
    Conditional,
    #[error("both operands to a `==` expression")]
    Equality,
    #[error("elements of the first operand and the second operand to a `contains` expression")]
    Contains,
    #[error("elements of both set operands to a `containsAll` or `containsAny` expression")]
    ContainsAnyAll,
}

/// Structure containing details about a missing attribute error.
#[derive(Debug, Clone, Eq, Error)]
#[error("for policy `{policy_id}`, attribute {attribute_access} not found")]
pub struct UnsafeAttributeAccess {
    pub on_expr: Expr,
    pub policy_id: PolicyID,
    pub attribute_access: AttributeAccess,
    pub suggestion: Option<String>,
    /// When this is true, the attribute might still exist, but the validator
    /// cannot guarantee that it will.
    pub may_exist: bool,
}

impl std::hash::Hash for UnsafeAttributeAccess {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        ExprShapeOnly::new(&self.on_expr).hash(state);
        self.attribute_access.hash(state);
        self.suggestion.hash(state);
        self.may_exist.hash(state);
    }
}
impl PartialEq for UnsafeAttributeAccess {
    fn eq(&self, other: &Self) -> bool {
        ExprShapeOnly::new(&self.on_expr) == ExprShapeOnly::new(&other.on_expr)
            && self.attribute_access == other.attribute_access
            && self.suggestion == other.suggestion
            && self.may_exist == other.may_exist
    }
}

impl Diagnostic for UnsafeAttributeAccess {
    impl_diagnostic_from_on_expr_field!();

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
#[derive(Error, Debug, Clone, Eq)]
#[error("unable to guarantee safety of access to optional attribute {attribute_access}")]
pub struct UnsafeOptionalAttributeAccess {
    pub on_expr: Expr,
    pub policy_id: PolicyID,
    pub attribute_access: AttributeAccess,
}

impl std::hash::Hash for UnsafeOptionalAttributeAccess {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        ExprShapeOnly::new(&self.on_expr).hash(state);
        self.attribute_access.hash(state);
    }
}
impl PartialEq for UnsafeOptionalAttributeAccess {
    fn eq(&self, other: &Self) -> bool {
        ExprShapeOnly::new(&self.on_expr) == ExprShapeOnly::new(&other.on_expr)
            && self.attribute_access == other.attribute_access
    }
}

impl Diagnostic for UnsafeOptionalAttributeAccess {
    impl_diagnostic_from_on_expr_field!();

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new(format!(
            "try testing for the attribute with `{} && ..`",
            self.attribute_access.suggested_has_guard()
        )))
    }
}

/// Structure containing details about an undefined function error.
#[derive(Error, Debug, Clone, Eq)]
#[error("for policy `{policy_id}`, undefined extension function: {name}")]
pub struct UndefinedFunction {
    pub on_expr: Expr,
    pub policy_id: PolicyID,
    pub name: String,
}

impl std::hash::Hash for UndefinedFunction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        ExprShapeOnly::new(&self.on_expr).hash(state);
        self.name.hash(state);
    }
}
impl PartialEq for UndefinedFunction {
    fn eq(&self, other: &Self) -> bool {
        ExprShapeOnly::new(&self.on_expr) == ExprShapeOnly::new(&other.on_expr)
            && self.name == other.name
    }
}

impl Diagnostic for UndefinedFunction {
    impl_diagnostic_from_on_expr_field!();
}

/// Structure containing details about a multiply defined function error.
#[derive(Error, Debug, Clone, Eq)]
#[error("for policy `{policy_id}`, extension function defined multiple times: {name}")]
pub struct MultiplyDefinedFunction {
    pub on_expr: Expr,
    pub policy_id: PolicyID,
    pub name: String,
}

impl std::hash::Hash for MultiplyDefinedFunction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        ExprShapeOnly::new(&self.on_expr).hash(state);
        self.name.hash(state);
    }
}
impl PartialEq for MultiplyDefinedFunction {
    fn eq(&self, other: &Self) -> bool {
        ExprShapeOnly::new(&self.on_expr) == ExprShapeOnly::new(&other.on_expr)
            && self.name == other.name
    }
}

impl Diagnostic for MultiplyDefinedFunction {
    impl_diagnostic_from_on_expr_field!();
}

/// Structure containing details about a wrong number of arguments error.
#[derive(Error, Debug, Clone, Eq)]
#[error("for policy `{policy_id}`, wrong number of arguments in extension function application. Expected {expected}, got {actual}")]
pub struct WrongNumberArguments {
    pub on_expr: Expr,
    pub policy_id: PolicyID,
    pub expected: usize,
    pub actual: usize,
}

impl std::hash::Hash for WrongNumberArguments {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        ExprShapeOnly::new(&self.on_expr).hash(state);
        self.expected.hash(state);
        self.actual.hash(state);
    }
}

impl PartialEq for WrongNumberArguments {
    fn eq(&self, other: &Self) -> bool {
        ExprShapeOnly::new(&self.on_expr) == ExprShapeOnly::new(&other.on_expr)
            && self.expected == other.expected
            && self.actual == other.actual
    }
}

impl Diagnostic for WrongNumberArguments {
    impl_diagnostic_from_on_expr_field!();
}

/// Structure containing details about a wrong call style error.
#[derive(Error, Debug, Clone, Eq)]
#[error("for policy `{policy_id}`, wrong call style in extension function application. Expected {expected}, got {actual}")]
pub struct WrongCallStyle {
    pub on_expr: Expr,
    pub policy_id: PolicyID,
    pub expected: CallStyle,
    pub actual: CallStyle,
}

impl std::hash::Hash for WrongCallStyle {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        ExprShapeOnly::new(&self.on_expr).hash(state);
        self.expected.hash(state);
        self.actual.hash(state);
    }
}

impl PartialEq for WrongCallStyle {
    fn eq(&self, other: &Self) -> bool {
        ExprShapeOnly::new(&self.on_expr) == ExprShapeOnly::new(&other.on_expr)
            && self.expected == other.expected
            && self.actual == other.actual
    }
}

impl Diagnostic for WrongCallStyle {
    impl_diagnostic_from_on_expr_field!();
}

/// Structure containing details about a function argument validation error.
#[derive(Debug, Clone, Eq, Error)]
#[error("for policy `{policy_id}`, error during extension function argument validation: {msg}")]
pub struct FunctionArgumentValidation {
    pub on_expr: Expr,
    pub policy_id: PolicyID,
    pub msg: String,
}

impl std::hash::Hash for FunctionArgumentValidation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        ExprShapeOnly::new(&self.on_expr).hash(state);
        self.msg.hash(state);
    }
}

impl PartialEq for FunctionArgumentValidation {
    fn eq(&self, other: &Self) -> bool {
        ExprShapeOnly::new(&self.on_expr) == ExprShapeOnly::new(&other.on_expr)
            && self.msg == other.msg
    }
}

impl Diagnostic for FunctionArgumentValidation {
    impl_diagnostic_from_on_expr_field!();
}

/// Structure containing details about a hierarchy not respected error
#[derive(Debug, Clone, Hash, Eq, PartialEq, Error)]
#[error("for policy `{policy_id}`, operands to `in` do not respect the entity hierarchy")]
pub struct HierarchyNotRespected {
    pub source_loc: Option<Loc>,
    pub policy_id: PolicyID,
    pub in_lhs: Option<Name>,
    pub in_rhs: Option<Name>,
}

impl Diagnostic for HierarchyNotRespected {
    impl_diagnostic_from_source_loc_field!();

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        match (&self.in_lhs, &self.in_rhs) {
            (Some(in_lhs), Some(in_rhs)) => Some(Box::new(format!(
                "`{in_lhs}` cannot be a descendant of `{in_rhs}`"
            ))),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Error)]
#[error("for policy `{policy_id}`, empty set literals are forbidden in policies")]
pub struct EmptySetForbidden {
    pub source_loc: Option<Loc>,
    pub policy_id: PolicyID,
}

impl Diagnostic for EmptySetForbidden {
    impl_diagnostic_from_source_loc_field!();
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Error)]
#[error("for policy `{policy_id}`, extension constructors may not be called with non-literal expressions")]
pub struct NonLitExtConstructor {
    pub source_loc: Option<Loc>,
    pub policy_id: PolicyID,
}

impl Diagnostic for NonLitExtConstructor {
    impl_diagnostic_from_source_loc_field!();

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new(
            "consider applying extension constructors inside attribute values when constructing entity or context data"
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
    /// targeting an EntityLUB.
    EntityLUB(EntityLUB, Vec<SmolStr>),
    /// The attribute access is some sequence of attributes accesses eventually
    /// targeting the context variable. The context being accessed is identified
    /// by the `EntityUID` for the associated action.
    Context(EntityUID, Vec<SmolStr>),
    /// Other cases where we do not attempt to give more information about the
    /// access. This includes any access on the `AnyEntity` type and on record
    /// types other than the `context` variable.
    Other(Vec<SmolStr>),
}

impl AttributeAccess {
    /// Construct an `AttributeAccess` access from a `GetAttr` expression `expr.attr`.
    pub(crate) fn from_expr(
        req_env: &RequestEnv,
        mut expr: &Expr<Option<Type>>,
        attr: SmolStr,
    ) -> AttributeAccess {
        let mut attrs: Vec<SmolStr> = vec![attr];
        loop {
            if let Some(Type::EntityOrRecord(EntityRecordKind::Entity(lub))) = expr.data() {
                return AttributeAccess::EntityLUB(lub.clone(), attrs);
            } else if let ExprKind::Var(Var::Context) = expr.expr_kind() {
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
                "`{attrs_str}` for entity type{}",
                match lub.get_single_entity() {
                    Some(single) => format!(" {}", single),
                    _ => format!("s {}", lub.iter().join(", ")),
                },
            ),
            AttributeAccess::Context(action, _) => {
                write!(f, "`{attrs_str}` in context for {action}",)
            }
            AttributeAccess::Other(_) => write!(f, "`{attrs_str}`"),
        }
    }
}

// These tests all assume that the typechecker found an error while checking the
// outermost `GetAttr` in the expressions. If the attribute didn't exist at all,
// only the primary message would included in the final error. If it was an
// optional attribute without a guard, then the help message is also printed.
#[cfg(test)]
mod test_attr_access {
    use cedar_policy_core::ast::{EntityType, EntityUID, Expr, ExprBuilder, ExprKind, Var};

    use super::AttributeAccess;
    use crate::types::{OpenTag, RequestEnv, Type};

    #[track_caller]
    fn assert_message_and_help(
        attr_access: &Expr<Option<Type>>,
        msg: impl AsRef<str>,
        help: impl AsRef<str>,
    ) {
        let env = RequestEnv::DeclaredAction {
            principal: &EntityType::Specified("Principal".parse().unwrap()),
            action: &EntityUID::with_eid_and_type(crate::schema::ACTION_ENTITY_TYPE, "action")
                .unwrap(),
            resource: &EntityType::Specified("Resource".parse().unwrap()),
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
        assert_message_and_help(&e, "`foo` for entity type User", "e has foo");
        let e = ExprBuilder::new().get_attr(e, "bar".into());
        assert_message_and_help(&e, "`foo.bar` for entity type User", "e.foo has bar");
        let e = ExprBuilder::new().get_attr(e, "baz".into());
        assert_message_and_help(
            &e,
            "`foo.bar.baz` for entity type User",
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
        assert_message_and_help(&e, "`thing` for entity type User", "e has thing");
        let e = ExprBuilder::new().get_attr(e, "bar".into());
        assert_message_and_help(&e, "`bar` for entity type Thing", "e has bar");
        let e = ExprBuilder::new().get_attr(e, "baz".into());
        assert_message_and_help(&e, "`bar.baz` for entity type Thing", "e.bar has baz");
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
