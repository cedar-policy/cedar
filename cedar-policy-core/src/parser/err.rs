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

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{self, Display, Write};
use std::iter;
use std::ops::{Deref, DerefMut};

use either::Either;
use lalrpop_util as lalr;
use lazy_static::lazy_static;
use miette::{Diagnostic, LabeledSpan, Severity, SourceCode};
use smol_str::SmolStr;
use thiserror::Error;

use crate::ast::{self, RestrictedExprError};
use crate::ast::{PolicyID, Var};
use crate::parser::unescape::UnescapeError;

use crate::parser::fmt::join_with_conjunction;
use crate::parser::node::ASTNode;

use super::cst;

pub(crate) type RawLocation = usize;
pub(crate) type RawToken<'a> = lalr::lexer::Token<'a>;
pub(crate) type RawUserError = ASTNode<String>;

pub(crate) type RawParseError<'a> = lalr::ParseError<RawLocation, RawToken<'a>, RawUserError>;
pub(crate) type RawErrorRecovery<'a> = lalr::ErrorRecovery<RawLocation, RawToken<'a>, RawUserError>;

type OwnedRawParseError = lalr::ParseError<RawLocation, String, RawUserError>;

/// For errors during parsing
#[derive(Clone, Debug, Diagnostic, Error, PartialEq, Eq)]
pub enum ParseError {
    /// Error from the CST parser.
    #[error(transparent)]
    #[diagnostic(transparent)]
    ToCST(#[from] ToCSTError),
    /// Error in the CST -> AST transform, mostly well-formedness issues.
    #[error("poorly formed: {0}")]
    #[diagnostic(code(cedar_policy_core::parser::to_ast_err))]
    ToAST(#[from] ToASTError),
    /// Error concerning restricted expressions.
    #[error(transparent)]
    RestrictedExpr(#[from] RestrictedExprError),
    /// Errors concerning parsing literals on their own
    #[error(transparent)]
    ParseLiteral(#[from] ParseLiteralError),
}

/// Errors in the top-level parse literal entrypoint
#[derive(Debug, Clone, PartialEq, Error, Eq)]
pub enum ParseLiteralError {
    /// The top-level parser endpoint for parsing a literal encountered a non-literal.
    /// Since this can be any possible other expression, we just return it as a string.
    #[error("the source `{0}` is not a literal")]
    ParseLiteral(String),
}

/// Errors in  the CST -> AST transform, mostly well-formedness issues.
#[derive(Debug, Diagnostic, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ToASTError {
    /// Returned when we attempt to parse a template with a conflicting id
    #[error("a template with this id already exists in the policy set: {0}")]
    DuplicateTemplateId(PolicyID),
    /// Returned when we attempt to parse a policy with a conflicting id
    #[error("a policy with this id already exists in the policy set: {0}")]
    DuplicatePolicyId(PolicyID),
    /// Returned when a template is encountered but a static policy is expected
    #[error(
        "expected a static policy, got a template. Try removing template slots from this policy"
    )]
    InvalidTemplate,
    /// Returned when we attempt to parse a policy with malformed or conflicting annotations
    #[error("this policy uses poorly formed or duplicate annotations")]
    BadAnnotations,
    /// Returned when a policy contains Template Slots in the condition clause. This is not currently supported.
    #[error("template slots are currently unsupported in policy condition clauses")]
    SlotsInConditionClause,
    /// Returned when a policy is missing one of the 3 required scope clauses. (`principal`, `action`, and `resource`)
    #[error("this policy is missing the {0} variable in the scope")]
    MissingScopeConstraint(Var),
    /// Returned when a policy has an extra scope clause. This is not valid syntax
    #[error("this policy has an extra head constraint in the scope; a policy must have exactly `principal`, `action`, and `resource` constraints: {0}")]
    ExtraHeadConstraints(cst::VariableDef),
    /// Returned when a policy uses a reserved keyword as an identifier.
    #[error("this identifier is reserved and cannot be used: {0}")]
    ReservedIdentifier(cst::Ident),
    /// Returned when a policy contains an invalid identifier.
    /// This error is not currently returned, but is here for future-proofing.
    /// See [`cst::Ident::Invalid`]
    #[error("not a valid identifier: {0}")]
    InvalidIdentifier(String),
    /// Returned when a policy uses a effect keyword beyond `permit` or `forbid`
    #[error("not a valid policy effect: `{0}`. Effect must be either `permit` or `forbid`")]
    InvalidEffect(cst::Ident),
    /// Returned when a policy uses a condition keyword beyond `when` or `unless`
    #[error("not a valid policy condition: `{0}`. Condition must be either `when` or `unless`")]
    InvalidCondition(cst::Ident),
    /// Returned when a policy uses a variable in the scope beyond `principal`, `action`, or `resource`
    #[error("expected a variable that's valid in the policy scope. Must be one of `principal`, `action`, or `resource`. Found: {0}")]
    InvalidScopeConstraintVariable(cst::Ident),
    /// Returned when a policy contains an invalid method name
    #[error("not a valid method name: {0}")]
    InvalidMethodName(String),
    /// Returned when a policy scope clause contains the wrong variable. (`principal` must be in the first clause, etc...)
    #[error("the variable `{got}` is invalid in this policy scope clause, the variable `{expected}` is expected")]
    IncorrectVariable {
        /// The variable that is expected in this clause
        expected: Var,
        /// The variable that was present in this clause
        got: Var,
    },
    /// Returned when a policy scope clauses uses an operator beyond `==` or `in`.
    #[error("policy scope constraints must either `==` or `in`. Found `{0}`")]
    InvalidConstraintOperator(cst::RelOp),
    /// Returned when the right hand side of `==` in a policy scope clause is not a single Entity UID or template slot.
    /// This is valid in Cedar conditions, but not in the Scope
    #[error(
        "right hand side of equality in policy scope must be a single Entity UID or template slot"
    )]
    InvalidScopeEqualityRHS,
    /// Returned when an Entity UID used as an action does not have the type `Action`
    #[error("expected an EntityUID with the type `Action`. Got: {0}. Action entities must have type `Action`")]
    InvalidActionType(crate::ast::EntityUID),
    /// Returned when a condition clause is empty
    #[error("{}condition clause cannot be empty", match .0 { Some(ident) => format!("`{}` ", ident), None => "".to_string() })]
    EmptyClause(Option<cst::Ident>),
    /// Returned when the internal invariant around annotation info has been violated
    #[error("internal invariant violated. No parse errors were reported but annotation information was missing")]
    AnnotationInvariantViolation,
    /// Returned when membership chains do not resolve to an expression, violating an internal invariant
    #[error("internal invariant violated. Membership chain did not resolve to an expression")]
    MembershipInvariantViolation,
    /// Returned for a non-parse-able string literal
    #[error("invalid string literal: `\"{0}\"`")]
    InvalidString(String),
    /// Returned for attempting to use an arbitrary variable name. Cedar does not support arbitrary variables.
    #[error("arbitrary variables are not supported; did you mean to enclose `{0}` in quotes to make a string? The valid Cedar variable are `principal`, `action`, `resource`, and `context`")]
    ArbitraryVariable(SmolStr),
    /// Returned for attempting to use an invalid attribute name
    #[error(
        "invalid attribute name: `{0}`. Attribute names can either be identifiers or string literals"
    )]
    InvalidAttribute(SmolStr),
    /// Returned for attempting to use an invalid attribute name in a record name
    #[error("record literal has invalid attributes")]
    InvalidAttributesInRecordLiteral,
    /// Returned for attempting to use an attribute with a namespace
    #[error("`{0}` cannot be used as an attribute as it contains a namespace")]
    PathAsAttribute(String),
    /// Returned when a policy attempts to call a method function-style
    #[error("`{0}` is a method, not a function. Use a method-style call: `e.{0}(..)`")]
    FunctionCallOnMethod(crate::ast::Id),
    /// Returned when the right hand side of a `like` expression is not a constant pattern literal
    #[error("right hand side of a `like` expression must be a pattern literal. Got: {0}")]
    InvalidPattern(String),
    /// Returned when an unexpected node is in the policy scope clause
    #[error("expected a {expected}, found a `{got}` statement")]
    WrongNode {
        /// What the expected AST node kind was
        expected: &'static str,
        /// What AST node was present in the policy source
        got: String,
    },
    /// Returned when a policy contains ambiguous ordering of operators.
    /// This can be resolved by using parenthesis to make order explicit
    #[error("multiple relational operators (>, ==, in, etc.) without parentheses")]
    AmbiguousOperators,
    /// Returned when a policy uses the division operator (`/`), which is not supported
    #[error("division is not supported")]
    UnsupportedDivision,
    /// Returned when a policy uses the remainder/modulo operator (`%`), which is not supported
    #[error("remainder/modulo is not supported")]
    UnsupportedModulo,
    /// Returned when a policy attempts to multiply by a non-constant integer
    #[error("multiplication must be by an integer literal")]
    NonConstantMultiplication,
    /// Returned when a policy contains an integer literal that is out of range
    #[error(
        "integer literal `{0}` is too large. Maximum allowed integer literal is `{}`",
        i64::MAX
    )]
    IntegerLiteralTooLarge(u64),
    /// Returned when a unary operator is chained more than 4 times in a row
    #[error(
        "too many occurrences of `{0}`. Cannot chain more the 4 applications of a unary operator"
    )]
    UnaryOpLimit(crate::ast::UnaryOp),
    /// Returned when a variable is called as a function, which is not allowed.
    /// Functions are not first class values in Cedar
    #[error("variables cannot be called as functions. `{0}(...)` is not a valid function call")]
    VariableCall(crate::ast::Var),
    /// Returned when a policy attempts to call a method on a value that has no methods
    #[error("Attempted to call `{0}.{1}`, but `{0}` does not have any methods")]
    NoMethods(crate::ast::Name, ast::Id),
    /// Returned when a policy attempts to call a function that does not exist
    #[error("`{0}` is not a function")]
    NotAFunction(crate::ast::Name),
    /// Returned when a policy attempts to write an entity literal
    #[error("entity literals are not supported")]
    UnsupportedEntityLiterals,
    /// Returned when an expression is the target of a function call.
    /// Functions are not first class values in Cedar
    #[error("function calls in Cedar must be of the form: `<name>(arg1, arg2, ...)`")]
    ExpressionCall,
    /// Returned when a policy attempts to access the fields of a value with no fields
    #[error("incorrect member access `{0}.{1}`, `{0}` has no fields or methods")]
    InvalidAccess(crate::ast::Name, SmolStr),
    /// Returned when a policy attempts to index on a fields of a value with no fields
    #[error("incorrect indexing expression `{0}[{1}]`, `{0}` has no fields")]
    InvalidIndex(crate::ast::Name, SmolStr),
    /// Returned when the contents of an indexing expression is not a string literal
    #[error("The contents of an index expression must be a string literal")]
    NonStringIndex,
    /// Returned when a user attempts to use type-constraint syntax. This is not currently supported
    #[error("type constraints are not currently supported")]
    TypeConstraints,
    /// Returned when a policy uses a path in an invalid context
    #[error("a path is not valid in this context")]
    InvalidPath,
    /// Returned when a string needs to be fully normalized
    #[error("{kind} needs to be normalized (e.g., whitespace removed): `{src}` The normalized form is `{normalized_src}`")]
    NonNormalizedString {
        /// The kind of string we are expecting
        kind: &'static str,
        /// The source string passed in
        src: String,
        /// The normalized form of the string
        normalized_src: String,
    },
    /// Returned when a CST node is empty
    #[error("data should not be empty")]
    MissingNodeData,
    /// Returned when the right hand side of a `has` expression is neither a field name or a string literal
    #[error("the right-hand-side of a `has` expression must be a field name or a string literal")]
    HasNonLiteralRHS,
    /// Returned when a CST expression is invalid
    #[error("{0} is not a valid expression")]
    InvalidExpression(cst::Name),
    /// Returned when a function has wrong arity
    #[error("call to `{name}` requires exactly {expected} argument{}, but got {got} arguments", if .expected == &1 { "" } else { "s" })]
    WrongArity {
        /// Name of the function being called
        name: &'static str,
        /// The expected number of arguments
        expected: usize,
        /// The number of arguments present in source
        got: usize,
    },
    /// Returned when a string contains invalid escapes
    #[error("{0}")]
    Unescape(#[from] UnescapeError),
    /// Returns when a policy scope has incorrect EntityUIDs/Template Slots
    #[error("{0}")]
    RefCreation(#[from] RefCreationError),
}

impl ToASTError {
    /// Constructor for the [`ToASTError::WrongNode`] error
    pub fn wrong_node(expected: &'static str, got: impl Into<String>) -> Self {
        Self::WrongNode {
            expected,
            got: got.into(),
        }
    }

    /// Constructor for the [`ToASTError::WrongArity`] error
    pub fn wrong_arity(name: &'static str, expected: usize, got: usize) -> Self {
        Self::WrongArity {
            name,
            expected,
            got,
        }
    }
}

// Either::Left(r) => write!(f, "expected {r}, got {}", self.got),
// Either::Right((r1, r2)) => write!(f, "expected {r1} or {r2}, got: {}", self.got),

/// Error surrounding EntityUIds/Template slots in policy scopes
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum RefCreationError {
    /// Error surrounding EntityUIds/Template slots in policy scopes
    #[error("expected {}, got: {got}", match .expected { Either::Left(r) => r.to_string(), Either::Right((r1, r2)) => format!("{r1} or {r2}") })]
    RefCreation {
        /// What kinds of references the given scope clause required.
        /// Some scope clauses require exactly one kind of reference, some require one of two
        expected: Either<Ref, (Ref, Ref)>,
        /// The kind of reference that was present in the policy
        got: Ref,
    },
}

impl RefCreationError {
    /// Constructor for when a policy scope requires exactly one kind of reference
    pub fn one_expected(expected: Ref, got: Ref) -> Self {
        Self::RefCreation {
            expected: Either::Left(expected),
            got,
        }
    }

    /// Constructor for when a policy scope requires one of two kinds of references
    pub fn two_expected(r1: Ref, r2: Ref, got: Ref) -> Self {
        let expected = Either::Right((r1, r2));
        Self::RefCreation { expected, got }
    }
}

impl From<RefCreationError> for ParseError {
    fn from(value: RefCreationError) -> Self {
        ParseError::ToAST(value.into())
    }
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
/// Error from the CST parser.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub struct ToCSTError {
    err: OwnedRawParseError,
}

impl ToCSTError {
    pub(crate) fn from_raw_parse_err(err: RawParseError<'_>) -> Self {
        Self {
            err: err.map_token(|token| token.to_string()),
        }
    }

    pub(crate) fn from_raw_err_recovery(recovery: RawErrorRecovery<'_>) -> Self {
        Self::from_raw_parse_err(recovery.error)
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
    fn code(&self) -> Option<Box<dyn Display + '_>> {
        Some(Box::new("cedar_policy_core::parser::to_cst_error"))
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        let labeled_span = match &self.err {
            OwnedRawParseError::InvalidToken { location } => {
                LabeledSpan::underline(*location..*location)
            }
            OwnedRawParseError::UnrecognizedEof { location, expected } => {
                LabeledSpan::new_with_span(expected_to_string(expected), *location..*location)
            }
            OwnedRawParseError::UnrecognizedToken {
                token: (token_start, _, token_end),
                expected,
            } => LabeledSpan::new_with_span(expected_to_string(expected), *token_start..*token_end),
            OwnedRawParseError::ExtraToken {
                token: (token_start, _, token_end),
            } => LabeledSpan::underline(*token_start..*token_end),
            OwnedRawParseError::User { error } => LabeledSpan::underline(error.info.0.clone()),
        };
        Some(Box::new(iter::once(labeled_span)))
    }
}

lazy_static! {
    /// Keys mirror the token names defined in the `match` block of
    /// `grammar.lalrpop`.
    static ref FRIENDLY_TOKEN_NAMES: HashMap<&'static str, &'static str> = HashMap::from([
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
    ]);
}

fn expected_to_string(expected: &[String]) -> Option<String> {
    if expected.is_empty() {
        return None;
    }

    let mut expected_string = "expected ".to_owned();
    // PANIC SAFETY Shouldn't be `Err` since we're writing strings to a string
    #[allow(clippy::expect_used)]
    join_with_conjunction(&mut expected_string, "or", expected, |f, token| {
        match FRIENDLY_TOKEN_NAMES.get(token.as_str()) {
            Some(friendly_token_name) => write!(f, "{}", friendly_token_name),
            None => write!(f, "{}", token.replace('"', "`")),
        }
    })
    .expect("failed to format expected tokens");
    Some(expected_string)
}

/// Multiple related parse errors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParseErrors(pub Vec<ParseError>);

impl ParseErrors {
    const DESCRIPTION_IF_EMPTY: &'static str = "unknown parse error";

    /// Constructs a new, empty `ParseErrors`.
    pub fn new() -> Self {
        ParseErrors(Vec::new())
    }

    /// Constructs a new, empty `ParseErrors` with the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        ParseErrors(Vec::with_capacity(capacity))
    }

    // TODO(spinda): Can we get rid of this?
    /// returns a Vec with stringified versions of the ParserErrors
    pub fn errors_as_strings(&self) -> Vec<String> {
        self.0
            .iter()
            .map(|parser_error| format!("{}", parser_error))
            .collect()
    }
}

impl Display for ParseErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.first() {
            Some(first_err) => Display::fmt(first_err, f),
            None => write!(f, "{}", Self::DESCRIPTION_IF_EMPTY),
        }
    }
}

impl Error for ParseErrors {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.first().and_then(Error::source)
    }

    #[allow(deprecated)]
    fn description(&self) -> &str {
        match self.first() {
            Some(first_err) => first_err.description(),
            None => Self::DESCRIPTION_IF_EMPTY,
        }
    }

    #[allow(deprecated)]
    fn cause(&self) -> Option<&dyn Error> {
        self.first().and_then(Error::cause)
    }
}

impl Diagnostic for ParseErrors {
    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        let mut errs = self.iter().map(|err| err as &dyn Diagnostic);
        errs.next().map(move |first_err| match first_err.related() {
            Some(first_err_related) => Box::new(first_err_related.chain(errs)),
            None => Box::new(errs) as Box<dyn Iterator<Item = _>>,
        })
    }

    fn code<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.first().and_then(Diagnostic::code)
    }

    fn severity(&self) -> Option<Severity> {
        self.first().and_then(Diagnostic::severity)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.first().and_then(Diagnostic::help)
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.first().and_then(Diagnostic::url)
    }

    fn source_code(&self) -> Option<&dyn SourceCode> {
        self.first().and_then(Diagnostic::source_code)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        self.first().and_then(Diagnostic::labels)
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.first().and_then(Diagnostic::diagnostic_source)
    }
}

impl AsRef<Vec<ParseError>> for ParseErrors {
    fn as_ref(&self) -> &Vec<ParseError> {
        &self.0
    }
}

impl AsMut<Vec<ParseError>> for ParseErrors {
    fn as_mut(&mut self) -> &mut Vec<ParseError> {
        &mut self.0
    }
}

impl AsRef<[ParseError]> for ParseErrors {
    fn as_ref(&self) -> &[ParseError] {
        self.0.as_ref()
    }
}

impl AsMut<[ParseError]> for ParseErrors {
    fn as_mut(&mut self) -> &mut [ParseError] {
        self.0.as_mut()
    }
}

impl Deref for ParseErrors {
    type Target = Vec<ParseError>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ParseErrors {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<ParseError> for ParseErrors {
    fn from(err: ParseError) -> Self {
        vec![err].into()
    }
}

impl From<ToCSTError> for ParseErrors {
    fn from(err: ToCSTError) -> Self {
        ParseError::from(err).into()
    }
}

impl From<Vec<ParseError>> for ParseErrors {
    fn from(errs: Vec<ParseError>) -> Self {
        ParseErrors(errs)
    }
}

impl FromIterator<ParseError> for ParseErrors {
    fn from_iter<T: IntoIterator<Item = ParseError>>(errs: T) -> Self {
        ParseErrors(errs.into_iter().collect())
    }
}

impl IntoIterator for ParseErrors {
    type Item = ParseError;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a ParseErrors {
    type Item = &'a ParseError;
    type IntoIter = std::slice::Iter<'a, ParseError>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a mut ParseErrors {
    type Item = &'a mut ParseError;
    type IntoIter = std::slice::IterMut<'a, ParseError>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}
