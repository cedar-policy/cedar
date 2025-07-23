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

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::{self, Display, Write};
use std::iter;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::sync::Arc;

use either::Either;
use lalrpop_util as lalr;
use lazy_static::lazy_static;
use miette::{Diagnostic, LabeledSpan, SourceSpan};
use nonempty::NonEmpty;
use smol_str::SmolStr;
use thiserror::Error;

use crate::ast::{self, ReservedNameError};
use crate::parser::fmt::join_with_conjunction;
use crate::parser::node::Node;
use crate::parser::unescape::UnescapeError;
use crate::parser::{AsLocRef, Loc, MaybeLoc};

use super::cst;

pub(crate) type RawLocation = usize;
pub(crate) type RawToken<'a> = lalr::lexer::Token<'a>;
pub(crate) type RawUserError = Node<String>;

pub(crate) type RawParseError<'a> = lalr::ParseError<RawLocation, RawToken<'a>, RawUserError>;
pub(crate) type RawErrorRecovery<'a> = lalr::ErrorRecovery<RawLocation, RawToken<'a>, RawUserError>;

type OwnedRawParseError = lalr::ParseError<RawLocation, String, RawUserError>;

/// Errors that can occur when parsing Cedar policies or expressions.
#[derive(Clone, Debug, Diagnostic, Error, PartialEq, Eq)]
pub enum ParseError {
    /// Error from the text -> CST parser
    #[error(transparent)]
    #[diagnostic(transparent)]
    ToCST(#[from] ToCSTError),
    /// Error from the CST -> AST transform
    #[error(transparent)]
    #[diagnostic(transparent)]
    ToAST(#[from] ToASTError),
}

/// Errors possible from `Literal::from_str()`
#[derive(Debug, Clone, PartialEq, Diagnostic, Error, Eq)]
pub enum LiteralParseError {
    /// Failed to parse the input
    #[error(transparent)]
    #[diagnostic(transparent)]
    Parse(#[from] ParseErrors),
    /// Parsed successfully as an expression, but failed to construct a literal
    #[error("invalid literal: {0}")]
    InvalidLiteral(ast::Expr),
}

/// Error from the CST -> AST transform
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{kind}")]
pub struct ToASTError {
    kind: ToASTErrorKind,
    loc: MaybeLoc,
}

// Construct `labels` and `source_code` based on the `loc` in this
// struct; and everything else forwarded directly to `kind`.
impl Diagnostic for ToASTError {
    impl_diagnostic_from_source_loc_opt_field!(loc);

    fn code<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.kind.code()
    }

    fn severity(&self) -> Option<miette::Severity> {
        self.kind.severity()
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.kind.help()
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.kind.url()
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.kind.diagnostic_source()
    }
}

impl ToASTError {
    /// Construct a new `ToASTError`.
    pub fn new(kind: ToASTErrorKind, loc: MaybeLoc) -> Self {
        Self { kind, loc }
    }

    /// Get the error kind.
    pub fn kind(&self) -> &ToASTErrorKind {
        &self.kind
    }

    pub(crate) fn source_loc(&self) -> Option<&Loc> {
        self.loc.as_loc_ref()
    }
}

const POLICY_SCOPE_HELP: &str =
    "policy scopes must contain a `principal`, `action`, and `resource` element in that order";

/// Details about a particular kind of `ToASTError`.
//
// This is NOT a publicly exported error type.
#[derive(Debug, Diagnostic, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ToASTErrorKind {
    /// Returned when we attempt to parse a template with a conflicting id
    #[error("a template with id `{0}` already exists in the policy set")]
    DuplicateTemplateId(ast::PolicyID),
    /// Returned when we attempt to parse a policy with a conflicting id
    #[error("a policy with id `{0}` already exists in the policy set")]
    DuplicatePolicyId(ast::PolicyID),
    /// Returned when a template is encountered but a static policy is expected
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExpectedStaticPolicy(#[from] parse_errors::ExpectedStaticPolicy),
    /// Returned when a static policy is encountered but a template is expected
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExpectedTemplate(#[from] parse_errors::ExpectedTemplate),
    /// Returned when we attempt to parse a policy or template with duplicate or
    /// conflicting annotations
    #[error("duplicate annotation: @{0}")]
    DuplicateAnnotation(ast::AnyId),
    /// Returned when a policy contains template slots in a when/unless clause.
    /// This is not currently supported; see [RFC 3](https://github.com/cedar-policy/rfcs/pull/3).
    #[error(transparent)]
    #[diagnostic(transparent)]
    SlotsInConditionClause(#[from] parse_errors::SlotsInConditionClause),
    /// Returned when a policy is missing one of the three required scope elements
    /// (`principal`, `action`, and `resource`)
    #[error("this policy is missing the `{0}` variable in the scope")]
    #[diagnostic(help("{POLICY_SCOPE_HELP}"))]
    MissingScopeVariable(ast::Var),
    /// Returned when a policy has an extra scope element
    #[error("this policy has an extra element in the scope: {0}")]
    #[diagnostic(help("{POLICY_SCOPE_HELP}"))]
    ExtraScopeElement(Box<cst::VariableDef>),
    /// Returned when a policy uses a reserved keyword as an identifier.
    #[error("this identifier is reserved and cannot be used: {0}")]
    ReservedIdentifier(cst::Ident),
    /// Returned when a policy contains an invalid identifier.
    /// This error is not currently returned, but is here for future-proofing;
    /// see [`cst::Ident::Invalid`].
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    /// Returned when a policy uses '=' as a binary operator.
    /// '=' is not an operator in Cedar; we can suggest '==' instead.
    #[error("'=' is not a valid operator in Cedar")]
    #[diagnostic(help("try using '==' instead"))]
    InvalidSingleEq,
    /// Returned when a policy uses an effect keyword beyond `permit` or `forbid`
    #[error("invalid policy effect: {0}")]
    #[diagnostic(help("effect must be either `permit` or `forbid`"))]
    InvalidEffect(cst::Ident),
    /// Returned when a policy uses a condition keyword beyond `when` or `unless`
    #[error("invalid policy condition: {0}")]
    #[diagnostic(help("condition must be either `when` or `unless`"))]
    InvalidCondition(cst::Ident),
    /// Returned when a policy uses a variable in the scope beyond `principal`,
    /// `action`, or `resource`
    #[error("found an invalid variable in the policy scope: {0}")]
    #[diagnostic(help("{POLICY_SCOPE_HELP}"))]
    InvalidScopeVariable(cst::Ident),
    /// Returned when a policy scope clause contains the wrong variable.
    /// (`principal` must be in the first clause, etc...)
    #[error("found the variable `{got}` where the variable `{expected}` must be used")]
    #[diagnostic(help("{POLICY_SCOPE_HELP}"))]
    IncorrectVariable {
        /// The variable that is expected
        expected: ast::Var,
        /// The variable that was present
        got: ast::Var,
    },
    /// Returned when a policy scope uses an operator not allowed in scopes
    #[error("invalid operator in the policy scope: {0}")]
    #[diagnostic(help("policy scope clauses can only use `==`, `in`, `is`, or `_ is _ in _`"))]
    InvalidScopeOperator(cst::RelOp),
    /// Returned when an action scope uses an operator not allowed in action scopes
    /// (special case of `InvalidScopeOperator`)
    #[error("invalid operator in the action scope: {0}")]
    #[diagnostic(help("action scope clauses can only use `==` or `in`"))]
    InvalidActionScopeOperator(cst::RelOp),
    /// Returned when the action scope clause contains an `is`
    #[error("`is` cannot appear in the action scope")]
    #[diagnostic(help("try moving `action is ..` into a `when` condition"))]
    IsInActionScope,
    /// Returned when an `is` operator is used together with `==`
    #[error("`is` cannot be used together with `==`")]
    #[diagnostic(help("try using `_ is _ in _`"))]
    IsWithEq,
    /// Returned when an entity uid used as an action does not have the type `Action`
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidActionType(#[from] parse_errors::InvalidActionType),
    /// Returned when a condition clause is empty
    #[error("{}condition clause cannot be empty", match .0 { Some(ident) => format!("`{ident}` "), None => "".to_string() })]
    EmptyClause(Option<cst::Ident>),
    /// Returned when membership chains do not resolve to an expression,
    /// violating an internal invariant
    #[error("internal invariant violated. Membership chain did not resolve to an expression")]
    #[diagnostic(help("please file an issue at <https://github.com/cedar-policy/cedar/issues> including the text that failed to parse"))]
    MembershipInvariantViolation,
    /// Returned for a non-parse-able string literal
    #[error("invalid string literal: {0}")]
    InvalidString(String),
    /// Returned when attempting to use an arbitrary variable name.
    /// Cedar does not support arbitrary variables.
    #[error("invalid variable: {0}")]
    #[diagnostic(help("the valid Cedar variables are `principal`, `action`, `resource`, and `context`; did you mean to enclose `{0}` in quotes to make a string?"))]
    ArbitraryVariable(SmolStr),
    /// Returned when attempting to use an invalid attribute name
    #[error("invalid attribute name: {0}")]
    #[diagnostic(help("attribute names can either be identifiers or string literals"))]
    InvalidAttribute(SmolStr),
    /// Returned when the RHS of a `has` operation is invalid
    #[error("invalid RHS of a `has` operation: {0}")]
    #[diagnostic(help("valid RHS of a `has` operation is either a sequence of identifiers separated by `.` or a string literal"))]
    InvalidHasRHS(SmolStr),
    /// Returned when attempting to use an attribute with a namespace
    #[error("`{0}` cannot be used as an attribute as it contains a namespace")]
    PathAsAttribute(String),
    /// Returned when a policy attempts to call a method function-style
    #[error("`{0}` is a method, not a function")]
    #[diagnostic(help("use a method-style call `e.{0}(..)`"))]
    FunctionCallOnMethod(ast::UnreservedId),
    /// Returned when a policy attempts to call a function in the method style
    #[error("`{0}` is a function, not a method")]
    #[diagnostic(help("use a function-style call `{0}(..)`"))]
    MethodCallOnFunction(ast::UnreservedId),
    /// Returned when the right hand side of a `like` expression is not a constant pattern literal
    #[error("right hand side of a `like` expression must be a pattern literal, but got `{0}`")]
    InvalidPattern(String),
    /// Returned when the right hand side of a `is` expression is not an entity type name
    #[error("right hand side of an `is` expression must be an entity type name, but got `{rhs}`")]
    #[diagnostic(help("{}", invalid_is_help(lhs, rhs)))]
    InvalidIsType {
        /// LHS of the invalid `is` expression, as a string
        lhs: String,
        /// RHS of the invalid `is` expression, as a string
        rhs: String,
    },
    /// Returned when an unexpected node is in the policy scope
    #[error("expected {expected}, found {got}")]
    WrongNode {
        /// What the expected AST node kind was
        expected: &'static str,
        /// What AST node was present in the policy source
        got: String,
        /// Optional free-form text with a suggestion for how to fix the problem
        #[help]
        suggestion: Option<String>,
    },
    /// Returned when a policy contains ambiguous ordering of operators.
    /// This can be resolved by using parenthesis to make order explicit
    #[error("multiple relational operators (>, ==, in, etc.) must be used with parentheses to make ordering explicit")]
    AmbiguousOperators,
    /// Returned when a policy uses the division operator (`/`), which is not supported
    #[error("division is not supported")]
    UnsupportedDivision,
    /// Returned when a policy uses the remainder/modulo operator (`%`), which is not supported
    #[error("remainder/modulo is not supported")]
    UnsupportedModulo,
    /// Any `ExpressionConstructionError` can also happen while converting CST to AST
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExpressionConstructionError(#[from] ast::ExpressionConstructionError),
    /// Returned when a policy contains an integer literal that is out of range
    #[error("integer literal `{0}` is too large")]
    #[diagnostic(help("maximum allowed integer literal is `{}`", ast::InputInteger::MAX))]
    IntegerLiteralTooLarge(u64),
    /// Returned when a unary operator is chained more than 4 times in a row
    #[error("too many occurrences of `{0}`")]
    #[diagnostic(help("cannot chain more the 4 applications of a unary operator"))]
    UnaryOpLimit(ast::UnaryOp),
    /// Returned when a variable is called as a function, which is not allowed.
    /// Functions are not first class values in Cedar
    #[error("`{0}(...)` is not a valid function call")]
    #[diagnostic(help("variables cannot be called as functions"))]
    VariableCall(ast::Var),
    /// Returned when a policy attempts to call a method on a value that has no methods
    #[error("attempted to call `{0}.{1}(...)`, but `{0}` does not have any methods")]
    NoMethods(ast::Name, ast::UnreservedId),
    /// Returned when a policy attempts to call a method that does not exist
    #[error("`{id}` is not a valid method")]
    UnknownMethod {
        /// The user-provided method id
        id: ast::UnreservedId,
        /// The hint to resolve the error
        #[help]
        hint: Option<String>,
    },
    /// Returned when a policy attempts to call a function that does not exist
    #[error("`{id}` is not a valid function")]
    UnknownFunction {
        /// The user-provided function id
        id: ast::Name,
        /// The hint to resolve the error
        #[help]
        hint: Option<String>,
    },
    /// Returned when a policy attempts to write an entity literal
    #[error("invalid entity literal: {0}")]
    #[diagnostic(help("entity literals should have a form like `Namespace::User::\"alice\"`"))]
    InvalidEntityLiteral(String),
    /// Returned when an expression is the target of a function call.
    /// Functions are not first class values in Cedar
    #[error("function calls must be of the form `<name>(arg1, arg2, ...)`")]
    ExpressionCall,
    /// Returned when a policy attempts to access the fields of a value with no fields
    #[error("invalid member access `{lhs}.{field}`, `{lhs}` has no fields or methods")]
    InvalidAccess {
        /// what we attempted to access a field of
        lhs: ast::Name,
        /// field we attempted to access
        field: SmolStr,
    },
    /// Returned when a policy attempts to index on a fields of a value with no fields
    #[error("invalid indexing expression `{lhs}[\"{}\"]`, `{lhs}` has no fields", .field.escape_debug())]
    InvalidIndex {
        /// what we attempted to access a field of
        lhs: ast::Name,
        /// field we attempted to access
        field: SmolStr,
    },
    /// Returned when the contents of an indexing expression is not a string literal
    #[error("the contents of an index expression must be a string literal")]
    NonStringIndex,
    /// Returned when a user attempts to use type-constraint `:` syntax. This
    /// syntax was not adopted, but `is` can be used to write type constraints
    /// in the policy scope.
    #[error("type constraints using `:` are not supported")]
    #[diagnostic(help("try using `is` instead"))]
    TypeConstraints,
    /// Returned when a string needs to be fully normalized
    #[error("`{kind}` needs to be normalized (e.g., whitespace removed): {src}")]
    #[diagnostic(help("the normalized form is `{normalized_src}`"))]
    NonNormalizedString {
        /// The kind of string we are expecting
        kind: &'static str,
        /// The source string passed in
        src: String,
        /// The normalized form of the string
        normalized_src: String,
    },
    /// Returned when a CST node is empty during CST to AST/EST conversion.
    /// This should have resulted in an error during the text to CST
    /// conversion, which will terminate parsing. So it should be unreachable
    /// in later stages.
    #[error("internal invariant violated. Parsed data node should not be empty")]
    #[diagnostic(help("please file an issue at <https://github.com/cedar-policy/cedar/issues> including the text that failed to parse"))]
    EmptyNodeInvariantViolation,
    /// Returned when a function or method is called with the wrong arity
    #[error("call to `{name}` requires exactly {expected} argument{}, but got {got} argument{}", if .expected == &1 { "" } else { "s" }, if .got == &1 { "" } else { "s" })]
    WrongArity {
        /// Name of the function or method being called
        name: &'static str,
        /// The expected number of arguments
        expected: usize,
        /// The number of arguments present in source
        got: usize,
    },
    /// Returned when a string contains invalid escapes
    #[error(transparent)]
    #[diagnostic(transparent)]
    Unescape(#[from] UnescapeError),
    /// Returned when a policy scope has incorrect entity uids or template slots
    #[error(transparent)]
    #[diagnostic(transparent)]
    WrongEntityArgument(#[from] parse_errors::WrongEntityArgument),
    /// Returned when a policy contains a template slot other than `?principal` or `?resource`
    #[error("`{0}` is not a valid template slot")]
    #[diagnostic(help("a template slot may only be `?principal` or `?resource`"))]
    InvalidSlot(SmolStr),
    /// Returned when an entity type contains a reserved namespace or typename (as of this writing, just `__cedar`)
    #[error(transparent)]
    #[diagnostic(transparent)]
    ReservedNamespace(#[from] ReservedNameError),
    /// Returned when a policy uses `_ in _ is _` instead of `_ is _ in _` in the policy scope
    #[error("when `is` and `in` are used together, `is` must come first")]
    #[diagnostic(help("try `_ is _ in _`"))]
    InvertedIsIn,
    /// Represents an attempt to convert a CST Error node
    #[cfg(feature = "tolerant-ast")]
    #[error("Trying to convert CST error node")]
    CSTErrorNode,
    ///  Represents an attempt to convert a CST Error node
    #[cfg(feature = "tolerant-ast")]
    #[error("Trying to convert AST error node")]
    ASTErrorNode,
}

fn invalid_is_help(lhs: &str, rhs: &str) -> String {
    // in the specific case where rhs is double-quotes surrounding a valid
    // (possibly reserved) identifier, give a different help message
    match strip_surrounding_doublequotes(rhs).map(ast::Id::from_str) {
        Some(Ok(stripped)) => format!("try removing the quotes: `{lhs} is {stripped}`"),
        _ => format!("try using `==` to test for equality: `{lhs} == {rhs}`"),
    }
}

/// If `s` has exactly `"` as both its first and last character, returns `Some`
/// with the first and last character removed.
/// In all other cases, returns `None`.
fn strip_surrounding_doublequotes(s: &str) -> Option<&str> {
    s.strip_prefix('"')?.strip_suffix('"')
}

impl ToASTErrorKind {
    /// Constructor for the [`ToASTErrorKind::WrongNode`] error
    pub fn wrong_node(
        expected: &'static str,
        got: impl Into<String>,
        suggestion: Option<impl Into<String>>,
    ) -> Self {
        Self::WrongNode {
            expected,
            got: got.into(),
            suggestion: suggestion.map(Into::into),
        }
    }

    /// Constructor for the [`ToASTErrorKind::WrongArity`] error
    pub fn wrong_arity(name: &'static str, expected: usize, got: usize) -> Self {
        Self::WrongArity {
            name,
            expected,
            got,
        }
    }

    /// Constructor for the [`ToASTErrorKind::SlotsInConditionClause`] error
    pub fn slots_in_condition_clause(slot: ast::Slot, clause_type: &'static str) -> Self {
        parse_errors::SlotsInConditionClause { slot, clause_type }.into()
    }

    /// Constructor for the [`ToASTErrorKind::ExpectedStaticPolicy`] error
    pub fn expected_static_policy(slot: ast::Slot) -> Self {
        parse_errors::ExpectedStaticPolicy { slot }.into()
    }

    /// Constructor for the [`ToASTErrorKind::ExpectedTemplate`] error
    pub fn expected_template() -> Self {
        parse_errors::ExpectedTemplate::new().into()
    }

    /// Constructor for the [`ToASTErrorKind::WrongEntityArgument`] error when
    /// one kind of entity argument was expected
    pub fn wrong_entity_argument_one_expected(
        expected: parse_errors::Ref,
        got: parse_errors::Ref,
    ) -> Self {
        parse_errors::WrongEntityArgument {
            expected: Either::Left(expected),
            got,
        }
        .into()
    }

    /// Constructor for the [`ToASTErrorKind::WrongEntityArgument`] error when
    /// one of two kinds of entity argument was expected
    pub fn wrong_entity_argument_two_expected(
        r1: parse_errors::Ref,
        r2: parse_errors::Ref,
        got: parse_errors::Ref,
    ) -> Self {
        let expected = Either::Right((r1, r2));
        parse_errors::WrongEntityArgument { expected, got }.into()
    }
}

/// Error subtypes for [`ToASTErrorKind`]
pub mod parse_errors {

    use std::sync::Arc;

    use super::*;

    /// Details about a `ExpectedStaticPolicy` error.
    #[derive(Debug, Clone, Error, PartialEq, Eq)]
    #[error("expected a static policy, got a template containing the slot {}", slot.id)]
    pub struct ExpectedStaticPolicy {
        /// Slot that was found (which is not valid in a static policy)
        pub(crate) slot: ast::Slot,
    }

    impl Diagnostic for ExpectedStaticPolicy {
        fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
            Some(Box::new(
                "try removing the template slot(s) from this policy",
            ))
        }

        impl_diagnostic_from_source_loc_opt_field!(slot.loc);
    }

    impl From<ast::UnexpectedSlotError> for ExpectedStaticPolicy {
        fn from(err: ast::UnexpectedSlotError) -> Self {
            match err {
                ast::UnexpectedSlotError::FoundSlot(slot) => Self { slot },
            }
        }
    }

    /// Details about a `ExpectedTemplate` error.
    #[derive(Debug, Clone, Diagnostic, Error, PartialEq, Eq)]
    #[error("expected a template, got a static policy")]
    #[diagnostic(help("a template should include slot(s) `?principal` or `?resource`"))]
    pub struct ExpectedTemplate {
        /// A private field, just so the public interface notes this as a
        /// private-fields struct and not a empty-fields struct for semver
        /// purposes (e.g., consumers cannot construct this type with
        /// `ExpectedTemplate {}`)
        _dummy: (),
    }

    impl ExpectedTemplate {
        pub(crate) fn new() -> Self {
            Self { _dummy: () }
        }
    }

    /// Details about a `SlotsInConditionClause` error.
    #[derive(Debug, Clone, Diagnostic, Error, PartialEq, Eq)]
    #[error("found template slot {} in a `{clause_type}` clause", slot.id)]
    #[diagnostic(help("slots are currently unsupported in `{clause_type}` clauses"))]
    pub struct SlotsInConditionClause {
        /// Slot that was found in a when/unless clause
        pub(crate) slot: ast::Slot,
        /// Clause type, e.g. "when" or "unless"
        pub(crate) clause_type: &'static str,
    }

    /// Details about an `InvalidActionType` error.
    #[derive(Debug, Clone, Diagnostic, Error, PartialEq, Eq)]
    #[diagnostic(help("action entities must have type `Action`, optionally in a namespace"))]
    pub struct InvalidActionType {
        pub(crate) euids: NonEmpty<Arc<ast::EntityUID>>,
    }

    impl std::fmt::Display for InvalidActionType {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let subject = if self.euids.len() > 1 {
                "entity uids"
            } else {
                "an entity uid"
            };
            write!(f, "expected {subject} with type `Action` but got ")?;
            join_with_conjunction(f, "and", self.euids.iter(), |f, e| write!(f, "`{e}`"))
        }
    }

    /// Details about an `WrongEntityArgument` error.
    #[derive(Debug, Clone, Diagnostic, Error, PartialEq, Eq)]
    #[error("expected {}, found {got}", match .expected { Either::Left(r) => r.to_string(), Either::Right((r1, r2)) => format!("{r1} or {r2}") })]
    pub struct WrongEntityArgument {
        /// What kinds of references the given scope clause required.
        /// Some scope clauses require exactly one kind of reference, some require one of two
        pub(crate) expected: Either<Ref, (Ref, Ref)>,
        /// The kind of reference that was present in the policy
        pub(crate) got: Ref,
    }

    /// The 3 kinds of literals that can be in a policy scope
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Ref {
        /// A single entity uids
        Single,
        /// A list of entity uids
        Set,
        /// A template slot
        Template,
    }

    impl std::fmt::Display for Ref {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Ref::Single => write!(f, "single entity uid"),
                Ref::Template => write!(f, "template slot"),
                Ref::Set => write!(f, "set of entity uids"),
            }
        }
    }
}

/// Error from the text -> CST parser
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub struct ToCSTError {
    err: OwnedRawParseError,
    src: Arc<str>,
}

impl ToCSTError {
    /// Extract a primary source span locating the error.
    pub fn primary_source_span(&self) -> Option<SourceSpan> {
        match &self.err {
            OwnedRawParseError::InvalidToken { location } => Some(SourceSpan::from(*location)),
            OwnedRawParseError::UnrecognizedEof { location, .. } => {
                Some(SourceSpan::from(*location))
            }
            OwnedRawParseError::UnrecognizedToken {
                token: (token_start, _, token_end),
                ..
            } => Some(SourceSpan::from(*token_start..*token_end)),
            OwnedRawParseError::ExtraToken {
                token: (token_start, _, token_end),
            } => Some(SourceSpan::from(*token_start..*token_end)),
            OwnedRawParseError::User { error } => error.loc.clone().map(|loc| loc.span),
        }
    }

    pub(crate) fn from_raw_parse_err(err: RawParseError<'_>, src: Arc<str>) -> Self {
        Self {
            err: err.map_token(|token| token.to_string()),
            src,
        }
    }

    pub(crate) fn from_raw_err_recovery(recovery: RawErrorRecovery<'_>, src: Arc<str>) -> Self {
        Self::from_raw_parse_err(recovery.error, src)
    }
}

impl Display for ToCSTError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.err {
            OwnedRawParseError::InvalidToken { .. } => write!(f, "invalid token"),
            OwnedRawParseError::UnrecognizedEof { .. } => write!(f, "unexpected end of input"),
            OwnedRawParseError::UnrecognizedToken {
                token: (_, token, _),
                ..
            } => write!(f, "unexpected token `{token}`"),
            OwnedRawParseError::ExtraToken {
                token: (_, token, _),
                ..
            } => write!(f, "extra token `{token}`"),
            OwnedRawParseError::User { error } => write!(f, "{error}"),
        }
    }
}

impl Diagnostic for ToCSTError {
    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.src as &dyn miette::SourceCode)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        let span = self.primary_source_span()?;
        let labeled_span = match &self.err {
            OwnedRawParseError::InvalidToken { .. } => LabeledSpan::underline(span),
            OwnedRawParseError::UnrecognizedEof { expected, .. } => {
                LabeledSpan::new_with_span(expected_to_string(expected, &POLICY_TOKEN_CONFIG), span)
            }
            OwnedRawParseError::UnrecognizedToken { expected, .. } => {
                LabeledSpan::new_with_span(expected_to_string(expected, &POLICY_TOKEN_CONFIG), span)
            }
            OwnedRawParseError::ExtraToken { .. } => LabeledSpan::underline(span),
            OwnedRawParseError::User { .. } => LabeledSpan::underline(span),
        };
        Some(Box::new(iter::once(labeled_span)))
    }
}

/// Defines configurable rules for how tokens in an `UnrecognizedToken` or
/// `UnrecognizedEof` error should be displayed to users.
#[derive(Debug)]
pub struct ExpectedTokenConfig {
    /// Defines user-friendly names for tokens used by our parser. Keys are the
    /// names of tokens as defined in the `.lalrpop` grammar file. A token may
    /// be omitted from this map if the name is already friendly enough.
    pub friendly_token_names: HashMap<&'static str, &'static str>,

    /// Some tokens defined in our grammar always cause later processing to fail.
    /// Our policy grammar defines a token for the mod operator `%`, but we
    /// reject any CST that uses the operator. To reduce confusion we filter
    /// these from the list of expected tokens in an error message.
    pub impossible_tokens: HashSet<&'static str>,

    /// Both our policy and schema grammar have a generic identifier token
    /// and some more specific identifier tokens that we use to parse specific
    /// constructs. It is very often not useful to explicitly list out all of
    /// these special identifier because the parser really just wants any
    /// generic identifier. That it would accept these does not give any
    /// useful information.
    pub special_identifier_tokens: HashSet<&'static str>,

    /// If this token is expected, then the parser expected a generic identifier, so
    /// we omit the specific identifiers favor of saying we expect an "identifier".
    pub identifier_sentinel: &'static str,

    /// Special identifiers that may be worth displaying even if the parser
    /// wants a generic identifier. These can tokens will be parsed as something
    /// other than an identifier when they occur as the first token in an
    /// expression (or a type, in the case of the schema grammar).
    pub first_set_identifier_tokens: HashSet<&'static str>,

    /// If this token is expected, then the parser was looking to start parsing
    /// an expression (or type, in the schema). We know that we should report the
    /// tokens that aren't parsed as identifiers at the start of an expression.
    pub first_set_sentinel: &'static str,
}

lazy_static! {
    static ref POLICY_TOKEN_CONFIG: ExpectedTokenConfig = ExpectedTokenConfig {
        friendly_token_names: HashMap::from([
            ("TRUE", "`true`"),
            ("FALSE", "`false`"),
            ("IF", "`if`"),
            ("PERMIT", "`permit`"),
            ("FORBID", "`forbid`"),
            ("WHEN", "`when`"),
            ("UNLESS", "`unless`"),
            ("IN", "`in`"),
            ("HAS", "`has`"),
            ("LIKE", "`like`"),
            ("IS", "`is`"),
            ("THEN", "`then`"),
            ("ELSE", "`else`"),
            ("PRINCIPAL", "`principal`"),
            ("ACTION", "`action`"),
            ("RESOURCE", "`resource`"),
            ("CONTEXT", "`context`"),
            ("PRINCIPAL_SLOT", "`?principal`"),
            ("RESOURCE_SLOT", "`?resource`"),
            ("IDENTIFIER", "identifier"),
            ("NUMBER", "number"),
            ("STRINGLIT", "string literal"),
        ]),
        impossible_tokens: HashSet::from(["\"=\"", "\"%\"", "\"/\"", "OTHER_SLOT"]),
        special_identifier_tokens: HashSet::from([
            "PERMIT",
            "FORBID",
            "WHEN",
            "UNLESS",
            "IN",
            "HAS",
            "LIKE",
            "IS",
            "THEN",
            "ELSE",
            "PRINCIPAL",
            "ACTION",
            "RESOURCE",
            "CONTEXT",
        ]),
        identifier_sentinel: "IDENTIFIER",
        first_set_identifier_tokens: HashSet::from(["TRUE", "FALSE", "IF"]),
        first_set_sentinel: "\"!\"",
    };
}

/// Format lalrpop expected error messages
pub fn expected_to_string(expected: &[String], config: &ExpectedTokenConfig) -> Option<String> {
    let mut expected = expected
        .iter()
        .filter(|e| !config.impossible_tokens.contains(e.as_str()))
        .map(|e| e.as_str())
        .collect::<BTreeSet<_>>();
    if expected.contains(config.identifier_sentinel) {
        for token in config.special_identifier_tokens.iter() {
            expected.remove(*token);
        }
        if !expected.contains(config.first_set_sentinel) {
            for token in config.first_set_identifier_tokens.iter() {
                expected.remove(*token);
            }
        }
    }
    if expected.is_empty() {
        return None;
    }

    let mut expected_string = "expected ".to_owned();
    // PANIC SAFETY Shouldn't be `Err` since we're writing strings to a string
    #[allow(clippy::expect_used)]
    join_with_conjunction(
        &mut expected_string,
        "or",
        expected,
        |f, token| match config.friendly_token_names.get(token) {
            Some(friendly_token_name) => write!(f, "{friendly_token_name}"),
            None => write!(f, "{}", token.replace('"', "`")),
        },
    )
    .expect("failed to format expected tokens");
    Some(expected_string)
}

/// Represents one or more [`ParseError`]s encountered when parsing a policy or
/// template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseErrors(NonEmpty<ParseError>);

impl ParseErrors {
    /// Construct a `ParseErrors` with a single element
    pub(crate) fn singleton(err: impl Into<ParseError>) -> Self {
        Self(NonEmpty::singleton(err.into()))
    }

    /// Construct a new `ParseErrors` with at least one element
    pub(crate) fn new(first: ParseError, rest: impl IntoIterator<Item = ParseError>) -> Self {
        Self(NonEmpty {
            head: first,
            tail: rest.into_iter().collect::<Vec<_>>(),
        })
    }

    /// Construct a new `ParseErrors` from another `NonEmpty` type
    pub(crate) fn new_from_nonempty(errs: NonEmpty<ParseError>) -> Self {
        Self(errs)
    }

    pub(crate) fn from_iter(i: impl IntoIterator<Item = ParseError>) -> Option<Self> {
        NonEmpty::collect(i).map(Self::new_from_nonempty)
    }

    /// Flatten a `Vec<ParseErrors>` into a single `ParseErrors`, returning
    /// `None` if the input vector is empty.
    pub(crate) fn flatten(errs: impl IntoIterator<Item = ParseErrors>) -> Option<Self> {
        let mut errs = errs.into_iter();
        let mut first = errs.next()?;
        for inner in errs {
            first.extend(inner);
        }
        Some(first)
    }

    /// If there are any `Err`s in the input, this function will return a
    /// combined version of all errors. Otherwise, it will return a vector of
    /// all the `Ok` values.
    pub(crate) fn transpose<T>(
        i: impl IntoIterator<Item = Result<T, ParseErrors>>,
    ) -> Result<Vec<T>, Self> {
        let iter = i.into_iter();
        let (lower, upper) = iter.size_hint();
        let capacity = upper.unwrap_or(lower);

        let mut oks = Vec::with_capacity(capacity);
        let mut errs = Vec::new();

        for r in iter {
            match r {
                Ok(v) => oks.push(v),
                Err(e) => errs.push(e),
            }
        }

        if errs.is_empty() {
            Ok(oks)
        } else {
            // PANIC SAFETY: `errs` is not empty so `flatten` will return `Some(..)`
            #[allow(clippy::unwrap_used)]
            Err(Self::flatten(errs).unwrap())
        }
    }
}

impl Display for ParseErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.first()) // intentionally showing only the first error; see #326
    }
}

impl std::error::Error for ParseErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.first().source()
    }

    #[allow(deprecated)]
    fn description(&self) -> &str {
        self.first().description()
    }

    #[allow(deprecated)]
    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.first().cause()
    }
}

// Except for `.related()`, everything else is forwarded to the first error.
// This ensures that users who only use `Display`, `.code()`, `.labels()` etc, still get rich
// information for the first error, even if they don't realize there are multiple errors here.
// See #326.
impl Diagnostic for ParseErrors {
    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        // the .related() on the first error, and then the 2nd through Nth errors (but not their own .related())
        let mut errs = self.iter().map(|err| err as &dyn Diagnostic);
        errs.next().map(move |first_err| match first_err.related() {
            Some(first_err_related) => Box::new(first_err_related.chain(errs)),
            None => Box::new(errs) as Box<dyn Iterator<Item = _>>,
        })
    }

    fn code<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.first().code()
    }

    fn severity(&self) -> Option<miette::Severity> {
        self.first().severity()
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.first().help()
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.first().url()
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        self.first().source_code()
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        self.first().labels()
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.first().diagnostic_source()
    }
}

impl AsRef<NonEmpty<ParseError>> for ParseErrors {
    fn as_ref(&self) -> &NonEmpty<ParseError> {
        &self.0
    }
}

impl AsMut<NonEmpty<ParseError>> for ParseErrors {
    fn as_mut(&mut self) -> &mut NonEmpty<ParseError> {
        &mut self.0
    }
}

impl Deref for ParseErrors {
    type Target = NonEmpty<ParseError>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ParseErrors {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Into<ParseError>> From<T> for ParseErrors {
    fn from(err: T) -> Self {
        ParseErrors::singleton(err.into())
    }
}

impl<T: Into<ParseError>> Extend<T> for ParseErrors {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.0.extend(iter.into_iter().map(Into::into))
    }
}

impl IntoIterator for ParseErrors {
    type Item = ParseError;
    type IntoIter = iter::Chain<iter::Once<Self::Item>, std::vec::IntoIter<Self::Item>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a ParseErrors {
    type Item = &'a ParseError;
    type IntoIter = iter::Chain<iter::Once<Self::Item>, std::slice::Iter<'a, ParseError>>;

    fn into_iter(self) -> Self::IntoIter {
        iter::once(&self.head).chain(self.tail.iter())
    }
}
