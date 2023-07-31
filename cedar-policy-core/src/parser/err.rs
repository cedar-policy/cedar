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

use crate::ast::RestrictedExprError;
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
    RestrictedExpressionError(#[from] RestrictedExprError),
    /// Errors concerning parsing literals on their own
    #[error("{0}")]
    ParseLiteral(#[from] ParseLiteralError),
}

/// Errors in the top-level parse literal entrypoint
#[derive(Debug, Clone, PartialEq, Error)]
pub enum ParseLiteralError {
    #[error("the source `{0}` is not a literal")]
    ParseLiteral(String),
}

/// Errors in  the CST -> AST transform, mostly well-formedness issues.
#[derive(Debug, Diagnostic, Error, Clone, PartialEq)]
#[non_exhaustive]
pub enum ToASTError {
    #[error("a template with this ID already exists in the policy set: {0}")]
    DuplicateTemplateID(PolicyID),
    #[error("a policy with this ID already exists in the policy set: {0}")]
    DuplicatePolicyID(PolicyID),
    #[error("this policy uses poorly formed or duplicate annotations")]
    BadAnnotations,
    #[error("template slots are currently unsupported in policy condition clauses")]
    SlotsInConditionClause,
    #[error("this policy requires the {0} variable in the scope")]
    MissingScopeConstraint(Var),
    #[error("this policy has extra variable in the scope A policy must have exactly `principal`, `action`, and `resource`")]
    ExtraHeadConstraints,
    #[error("this identifier is reserved and cannot be used: {0}")]
    ReservedIdentifier(cst::Ident),
    #[error("not a valid identifier: {0}")]
    InvalidIdentifier(String),
    #[error("not a valid policy effect: `{0}`. Effect must be either `permit` or `forbid`")]
    InvalidEffect(cst::Ident),
    #[error("not a valid policy condition: `{0}`. Condition must be either `when` or `unless`")]
    InvalidCondition(cst::Ident),
    #[error("expected a variable that's valid in the policy scope. Must be one of `principal`, `action` or `resource`. Found: {0}")]
    InvalidScopeConstraintVariable(cst::Ident),
    #[error("expected a variable that's valid in the policy scope. Must be one of `principal`, `action` or `resource`")]
    InvalidScopeConstraintVariableNoIdent,
    #[error("`{0}` is not a valid variable. Valid variables are: `principal`, `action`, `resource`, or `context`")]
    InvalidVariable(cst::Ident),
    #[error("not a valid method name: {0}")]
    InvalidMethodName(String),
    #[error("the variable `{0}` is invalid in this policy scope clause")]
    IncorrectVariable(Var),
    #[error("policy scope constraints must either `==` or `in`. Found `{0}`")]
    InvalidConstraintOperator(cst::RelOp),
    #[error("right-hand side of equality in policy scope must be a single Entity UID")]
    InvalidScopeEqualityRHS,
    #[error("expected an EntityUID with the type `Action`. Got: {0}. Action entities must have type `Action`")]
    InvalidActionType(crate::ast::EntityUID),
    #[error("`{0}` condition clause cannot be empty")]
    EmptyClause(cst::Ident),
    #[error("condition clauses in the EST cannot be empty")]
    EmptyCond,
    #[error("internal invariant violated. No parse errors were reported but annotation information was missing")]
    AnnotationInvariantViolation,
    #[error("invalid use of `{{}}`")]
    InvalidBraces,
    #[error("invalid string literal: `\"{0}\"`")]
    InvalidString(String),
    #[error("arbitrary variables are not supported; did you mean to enclose `{0}` in quotes to make a string?")]
    ArbitraryVariable(crate::ast::Name),
    #[error(
        "invalid attribute name. Attribute names can either be identifiers or string literals"
    )]
    InvalidAttribute,
    #[error("record literal has invalid attributes")]
    InvalidAttributesInRecordLiteral,
    #[error("`{0}` cannot be used as an attribute as it contains a namespace")]
    PathAsAttribute(String),
    #[error("`{0}` is a method, not a function. Use a method-style call: `e.{0}(..)`")]
    FunctionCallOnMethod(crate::ast::Id),
    #[error("right hand side of a `like` expression must be a pattern literal. Got: {0}")]
    InvalidPattern(String),
    #[error("expected a {expected}, found a `{got}` statement")]
    WrongNode { expected: &'static str, got: String },
    #[error("multiple relational operators (>, ==, in, etc.) without parentheses")]
    AmbiguousOperators,
    #[error("division is not supported")]
    Division,
    #[error("remainder/modulo is not supported")]
    Remainder,
    #[error("multiplication must be by an integer literal")]
    NonConstantMultiplication,
    #[error(
        "integer literal `{0}` is too large. Maximum allowed integer literal is `{}`",
        i64::MAX
    )]
    IntegerLiteralTooLarge(u64),
    #[error(
        "too many occurrences of `{0}`. Cannot chain more the 4 applications of a unary operator"
    )]
    UnaryOppLimit(crate::ast::UnaryOp),
    #[error("variables cannot be called as functions. `{0}(...)` is not a valid function call")]
    VariableCall(crate::ast::Var),
    #[error("`{0}` does not have any methods")]
    NoMethods(crate::ast::Name),
    #[error("`{0}` is not a function")]
    NotAFunction(crate::ast::Name),
    #[error("arbitrary entity lookups are not supported")]
    ArbitraryEntityLookup,
    #[error("function calls in cedar must be of the form: `<name>(arg1, arg2, ...)`")]
    ExpressionCall,
    #[error("`{0}` has no fields or methods")]
    InvalidAccess(crate::ast::Name),
    #[error("`{0}` is not a string literal")]
    NonStringLiteral(cst::Primary),
    #[error("The contents of an index expression must be a string literal")]
    NonStringIndex,
    #[error("type constraints are not currently supported")]
    TypeConstraints,
    #[error("a path is not valid in this context")]
    InvalidPath,
    #[error("{kind} needs to be normalized (e.g., whitespace removed): `{src}` The normalized form is `{normalized_src}`")]
    NonNormalizedString {
        kind: &'static str,
        src: String,
        normalized_src: String,
    },
    #[error("data should not be empty")]
    MissingNodeData,
    #[error("the right-hand-side of a `has` expression must be a field name or a string literal")]
    HasNonLiteralRHS,
    #[error("{0} is not a valid expression")]
    InvalidExpression(cst::Name),
    #[error("Invalid Method Call")]
    InvalidMethodCall,
    #[error("call to {0} requires exactly one argument, but got {0} arguments")]
    WrongArity(&'static str, usize),
    #[error("{0}")]
    Unescape(#[from] UnescapeError),
    #[error("{0}")]
    RefCreation(#[from] RefCreationError),
}

impl ToASTError {
    pub fn wrong_node(expected: &'static str, got: impl Into<String>) -> Self {
        Self::WrongNode {
            expected,
            got: got.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RefCreationError {
    expected: Either<Ref, (Ref, Ref)>,
    got: Ref,
}

impl RefCreationError {
    pub fn one_expected(expected: Ref, got: Ref) -> Self {
        Self {
            expected: Either::Left(expected),
            got,
        }
    }

    pub fn two_expected(r1: Ref, r2: Ref, got: Ref) -> Self {
        let expected = Either::Right((r1, r2));
        Self { expected, got }
    }
}

impl Into<ParseError> for RefCreationError {
    fn into(self) -> ParseError {
        ToASTError::RefCreation(self).into()
    }
}

impl std::fmt::Display for RefCreationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.expected {
            Either::Left(r) => write!(f, "expected {r}, got {}", self.got),
            Either::Right((r1, r2)) => write!(f, "expected {r1} or {r2}, got: {}", self.got),
        }
    }
}

impl std::error::Error for RefCreationError {}

#[derive(Debug, Clone, PartialEq)]
pub enum Ref {
    Single,
    Template,
    Set,
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

/// One or more parse errors occurred while performing a task.
#[derive(Debug, Default, Error)]
#[error("{context}")]
pub struct WithContext {
    /// What we were trying to do.
    pub context: String,
    /// Error(s) we encountered while doing it.
    #[source]
    pub errs: ParseErrors,
}

impl Diagnostic for WithContext {
    fn code<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.errs.code()
    }

    fn severity(&self) -> Option<Severity> {
        self.errs.severity()
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.errs.help()
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.errs.url()
    }

    fn source_code(&self) -> Option<&dyn SourceCode> {
        self.errs.source_code()
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        self.errs.labels()
    }

    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        self.errs.related()
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.errs.diagnostic_source()
    }
}
