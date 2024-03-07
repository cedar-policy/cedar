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

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::{self, Display, Write};
use std::iter;
use std::ops::{Deref, DerefMut};

use either::Either;
use lalrpop_util as lalr;
use lazy_static::lazy_static;
use miette::{Diagnostic, LabeledSpan, SourceSpan};
use smol_str::SmolStr;
use thiserror::Error;

use crate::ast::{self, InputInteger, PolicyID, RestrictedExprError, Var};
use crate::parser::fmt::join_with_conjunction;
use crate::parser::loc::Loc;
use crate::parser::node::Node;
use crate::parser::unescape::UnescapeError;

use super::cst;

pub(crate) type RawLocation = usize;
pub(crate) type RawToken<'a> = lalr::lexer::Token<'a>;
pub(crate) type RawUserError = Node<String>;

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
    #[error(transparent)]
    #[diagnostic(transparent)]
    ToAST(#[from] ToASTError),
    /// Error concerning restricted expressions.
    #[error(transparent)]
    #[diagnostic(transparent)]
    RestrictedExpr(#[from] RestrictedExprError),
    /// Errors concerning parsing literals on their own
    #[error(transparent)]
    #[diagnostic(transparent)]
    ParseLiteral(#[from] ParseLiteralError),
}

impl ParseError {
    /// Extract a primary source span locating the error, if one is available.
    pub fn primary_source_span(&self) -> Option<SourceSpan> {
        match self {
            ParseError::ToCST(to_cst_err) => Some(to_cst_err.primary_source_span()),
            ParseError::ToAST(to_ast_err) => Some(to_ast_err.source_loc().span),
            ParseError::RestrictedExpr(restricted_expr_err) => match restricted_expr_err {
                RestrictedExprError::InvalidRestrictedExpression { expr, .. } => {
                    expr.source_loc().map(|loc| loc.span)
                }
            },
            ParseError::ParseLiteral(parse_lit_err) => parse_lit_err
                .labels()
                .and_then(|mut it| it.next().map(|lspan| *lspan.inner())),
        }
    }
}

/// Errors in the top-level parse literal entrypoint
#[derive(Debug, Clone, PartialEq, Diagnostic, Error, Eq)]
pub enum ParseLiteralError {
    /// The top-level parser endpoint for parsing a literal encountered a non-literal.
    /// Since this can be any possible other expression, we just return it as a string.
    #[error("`{0}` is not a literal")]
    ParseLiteral(String),
}

/// Errors in the CST -> AST transform, mostly well-formedness issues.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{kind}")]
pub struct ToASTError {
    kind: ToASTErrorKind,
    loc: Loc,
}

// Construct `labels` and `source_code` based on the `loc` in this struct;
// and everything else forwarded directly to `kind`.
impl Diagnostic for ToASTError {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        Some(Box::new(iter::once(LabeledSpan::underline(self.loc.span))))
    }

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

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.loc.src as &dyn miette::SourceCode)
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.kind.diagnostic_source()
    }
}

impl ToASTError {
    /// Construct a new `ToASTError`.
    pub fn new(kind: ToASTErrorKind, loc: Loc) -> Self {
        Self { kind, loc }
    }

    /// Get the error kind.
    pub fn kind(&self) -> &ToASTErrorKind {
        &self.kind
    }

    pub(crate) fn source_loc(&self) -> &Loc {
        &self.loc
    }
}

/// Details about a particular kind of `ToASTError`.
#[derive(Debug, Diagnostic, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ToASTErrorKind {
    /// Returned when we attempt to parse a template with a conflicting id
    #[error("a template with id `{0}` already exists in the policy set")]
    DuplicateTemplateId(PolicyID),
    /// Returned when we attempt to parse a policy with a conflicting id
    #[error("a policy with id `{0}` already exists in the policy set")]
    DuplicatePolicyId(PolicyID),
    /// Returned when a template is encountered but a static policy is expected
    #[error("expected a static policy, got a template containing the slot {slot}")]
    #[diagnostic(help("try removing the template slot(s) from this policy"))]
    UnexpectedTemplate {
        /// Slot that was found (which is not valid in a static policy)
        slot: cst::Slot,
    },
    /// Returned when we attempt to parse a policy or template with duplicate or conflicting annotations
    #[error("duplicate annotation: @{0}")]
    DuplicateAnnotation(ast::AnyId),
    /// Returned when a policy contains template slots in a when/unless clause. This is not currently supported. See RFC 3
    #[error("found template slot {slot} in a `{clausetype}` clause")]
    #[diagnostic(help("slots are currently unsupported in `{clausetype}` clauses"))]
    SlotsInConditionClause {
        /// Slot that was found in a when/unless clause
        slot: cst::Slot,
        /// Clause type, e.g. "when" or "unless"
        clausetype: &'static str,
    },
    /// Returned when a policy is missing one of the 3 required scope clauses. (`principal`, `action`, and `resource`)
    #[error("this policy is missing the `{0}` variable in the scope")]
    MissingScopeConstraint(Var),
    /// Returned when a policy has an extra scope clause. This is not valid syntax
    #[error("this policy has an extra head constraint in the scope: `{0}`")]
    #[diagnostic(help(
        "a policy must have exactly `principal`, `action`, and `resource` constraints"
    ))]
    ExtraHeadConstraints(cst::VariableDef),
    /// Returned when a policy uses a reserved keyword as an identifier.
    #[error("this identifier is reserved and cannot be used: `{0}`")]
    ReservedIdentifier(cst::Ident),
    /// Returned when a policy contains an invalid identifier.
    /// This error is not currently returned, but is here for future-proofing.
    /// See [`cst::Ident::Invalid`]
    #[error("not a valid identifier: `{0}`")]
    InvalidIdentifier(String),
    /// Returned when a policy uses '=' as a binary operator.
    /// '=' is not an operator in Cedar; we can suggest '==' instead.
    #[error("'=' is not a valid operator in Cedar")]
    #[diagnostic(help("try using '==' instead"))]
    InvalidSingleEq,
    /// Returned when a policy uses a effect keyword beyond `permit` or `forbid`
    #[error("not a valid policy effect: `{0}`")]
    #[diagnostic(help("effect must be either `permit` or `forbid`"))]
    InvalidEffect(cst::Ident),
    /// Returned when a policy uses a condition keyword beyond `when` or `unless`
    #[error("not a valid policy condition: `{0}`")]
    #[diagnostic(help("condition must be either `when` or `unless`"))]
    InvalidCondition(cst::Ident),
    /// Returned when a policy uses a variable in the scope beyond `principal`, `action`, or `resource`
    #[error("expected a variable that is valid in the policy scope; found: `{0}`")]
    #[diagnostic(help(
        "policy scopes must contain a `principal`, `action`, and `resource` element in that order"
    ))]
    InvalidScopeConstraintVariable(cst::Ident),
    /// Returned when a policy contains an invalid method name
    #[error("not a valid method name: `{0}`")]
    InvalidMethodName(String),
    /// Returned when a policy scope clause contains the wrong variable.
    /// (`principal` must be in the first clause, etc...)
    #[error("found the variable `{got}` where the variable `{expected}` must be used")]
    #[diagnostic(help(
        "policy scopes must contain a `principal`, `action`, and `resource` element in that order"
    ))]
    IncorrectVariable {
        /// The variable that is expected in this clause
        expected: Var,
        /// The variable that was present in this clause
        got: Var,
    },
    /// Returned when a policy scope clause uses an operator not allowed in scopes.
    #[error("not a valid policy scope constraint: {0}")]
    #[diagnostic(help(
        "policy scope constraints must be either `==`, `in`, `is`, or `_ is _ in _`"
    ))]
    InvalidConstraintOperator(cst::RelOp),
    /// Returned when the right hand side of `==` in a policy scope clause is not a single Entity UID or a template slot.
    /// This is valid in Cedar conditions, but not in the Scope
    #[error(
        "the right hand side of equality in the policy scope must be a single entity uid or a template slot"
    )]
    InvalidScopeEqualityRHS,
    /// Returned when an Entity UID used as an action does not have the type `Action`
    #[error("expected an entity uid with the type `Action` but got `{0}`")]
    #[diagnostic(help("action entities must have type `Action`, optionally in a namespace"))]
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
    #[error("invalid string literal: `{0}`")]
    InvalidString(String),
    /// Returned for attempting to use an arbitrary variable name. Cedar does not support arbitrary variables.
    #[error("arbitrary variables are not supported; the valid Cedar variables are `principal`, `action`, `resource`, and `context`")]
    #[diagnostic(help("did you mean to enclose `{0}` in quotes to make a string?"))]
    ArbitraryVariable(SmolStr),
    /// Returned for attempting to use an invalid attribute name
    #[error("not a valid attribute name: `{0}`")]
    #[diagnostic(help("attribute names can either be identifiers or string literals"))]
    InvalidAttribute(SmolStr),
    /// Returned for attempting to use an invalid attribute name in a record name
    #[error("record literal has invalid attributes")]
    InvalidAttributesInRecordLiteral,
    /// Returned for attempting to use an attribute with a namespace
    #[error("`{0}` cannot be used as an attribute as it contains a namespace")]
    PathAsAttribute(String),
    /// Returned when a policy attempts to call a method function-style
    #[error("`{0}` is a method, not a function")]
    #[diagnostic(help("use a method-style call: `e.{0}(..)`"))]
    FunctionCallOnMethod(crate::ast::Id),
    /// Returned when a policy attempts to call a function in the method style
    #[error("`{0}` is a function, not a method")]
    #[diagnostic(help("use a function-style call: `{0}(..)`"))]
    MethodCallOnFunction(crate::ast::Id),
    /// Returned when the right hand side of a `like` expression is not a constant pattern literal
    #[error("right hand side of a `like` expression must be a pattern literal, but got `{0}`")]
    InvalidPattern(String),
    /// Returned when the right hand side of a `is` expression is not an entity type name
    #[error("right hand side of an `is` expression must be an entity type name, but got `{0}`")]
    #[diagnostic(help("try using `==` to test for equality"))]
    IsInvalidName(String),
    /// Returned when an unexpected node is in the policy scope clause
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
    /// Returned when a policy attempts to multiply by a non-constant integer
    #[error("multiplication must be by an integer literal")]
    NonConstantMultiplication,
    /// Returned when a policy contains an integer literal that is out of range
    #[error("integer literal `{0}` is too large")]
    #[diagnostic(help("maximum allowed integer literal is `{}`", InputInteger::MAX))]
    IntegerLiteralTooLarge(u64),
    /// Returned when a unary operator is chained more than 4 times in a row
    #[error("too many occurrences of `{0}`")]
    #[diagnostic(help("cannot chain more the 4 applications of a unary operator"))]
    UnaryOpLimit(crate::ast::UnaryOp),
    /// Returned when a variable is called as a function, which is not allowed.
    /// Functions are not first class values in Cedar
    #[error("`{0}(...)` is not a valid function call")]
    #[diagnostic(help("variables cannot be called as functions"))]
    VariableCall(crate::ast::Var),
    /// Returned when a policy attempts to call a method on a value that has no methods
    #[error("attempted to call `{0}.{1}`, but `{0}` does not have any methods")]
    NoMethods(crate::ast::Name, ast::Id),
    /// Returned when a policy attempts to call a function that does not exist
    #[error("`{0}` is not a function")]
    NotAFunction(crate::ast::Name),
    /// Returned when a policy attempts to write an entity literal
    #[error("entity literals are not supported")]
    UnsupportedEntityLiterals,
    /// Returned when an expression is the target of a function call.
    /// Functions are not first class values in Cedar
    #[error("function calls must be of the form: `<name>(arg1, arg2, ...)`")]
    ExpressionCall,
    /// Returned when a policy attempts to access the fields of a value with no fields
    #[error("incorrect member access `{0}.{1}`, `{0}` has no fields or methods")]
    InvalidAccess(crate::ast::Name, SmolStr),
    /// Returned when a policy attempts to index on a fields of a value with no fields
    #[error("incorrect indexing expression `{0}[{1}]`, `{0}` has no fields")]
    InvalidIndex(crate::ast::Name, SmolStr),
    /// Returned when the contents of an indexing expression is not a string literal
    #[error("the contents of an index expression must be a string literal")]
    NonStringIndex,
    /// Returned when the same key appears two or more times in a single record literal
    #[error("duplicate key `{key}` in record literal")]
    DuplicateKeyInRecordLiteral {
        /// The key that appeared two or more times
        key: SmolStr,
    },
    /// Returned when a user attempts to use type-constraint `:` syntax. This
    /// syntax was not adopted, but `is` can be used to write type constraints
    /// in the policy scope.
    #[error("type constraints using `:` are not supported")]
    #[diagnostic(help("try using `is` instead"))]
    TypeConstraints,
    /// Returned when a policy uses a path in an invalid context
    #[error("a path is not valid in this context")]
    InvalidPath,
    /// Returned when a string needs to be fully normalized
    #[error("`{kind}` needs to be normalized (e.g., whitespace removed): `{src}`")]
    #[diagnostic(help("the normalized form is `{normalized_src}`"))]
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
    #[error("the right hand side of a `has` expression must be a field name or string literal")]
    HasNonLiteralRHS,
    /// Returned when a CST expression is invalid
    #[error("`{0}` is not a valid expression")]
    InvalidExpression(cst::Name),
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
    /// Returns when a policy scope has incorrect EntityUIDs/Template Slots
    #[error(transparent)]
    #[diagnostic(transparent)]
    RefCreation(#[from] RefCreationError),
    /// Returned when an `is` appears in an invalid position in the policy scope
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidIs(#[from] InvalidIsError),
    /// Returned when a policy contains a template slot other than `?principal` or `?resource`
    #[error("`{0}` is not a valid template slot")]
    #[diagnostic(help("a template slot may only be `?principal` or `?resource`"))]
    InvalidSlot(SmolStr),
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
}

// Either::Left(r) => write!(f, "expected {r}, got {}", self.got),
// Either::Right((r1, r2)) => write!(f, "expected {r1} or {r2}, got: {}", self.got),

/// Error surrounding EntityUIds/Template slots in policy scopes
#[derive(Debug, Clone, Diagnostic, Error, PartialEq, Eq)]
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

/// Error when `is` appears in the policy scope in a position where it is
/// forbidden.
#[derive(Debug, Clone, Diagnostic, Error, PartialEq, Eq)]
pub enum InvalidIsError {
    /// The action scope may not contain an `is`
    #[error("`is` cannot appear in the action scope")]
    #[diagnostic(help("try moving `action is ..` into a `when` condition"))]
    ActionScope,
    /// An `is` cannot appear with this operator in the policy scope
    #[error("`is` cannot appear in the scope at the same time as `{0}`")]
    #[diagnostic(help("try moving `is` into a `when` condition"))]
    WrongOp(cst::RelOp),
}

/// Error from the CST parser.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub struct ToCSTError {
    err: OwnedRawParseError,
}

impl ToCSTError {
    /// Extract a primary source span locating the error.
    pub fn primary_source_span(&self) -> SourceSpan {
        match &self.err {
            OwnedRawParseError::InvalidToken { location } => SourceSpan::from(*location),
            OwnedRawParseError::UnrecognizedEof { location, .. } => SourceSpan::from(*location),
            OwnedRawParseError::UnrecognizedToken {
                token: (token_start, _, token_end),
                ..
            } => SourceSpan::from(*token_start..*token_end),
            OwnedRawParseError::ExtraToken {
                token: (token_start, _, token_end),
            } => SourceSpan::from(*token_start..*token_end),
            OwnedRawParseError::User { error } => error.loc.span,
        }
    }

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
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        let primary_source_span = self.primary_source_span();
        let labeled_span = match &self.err {
            OwnedRawParseError::InvalidToken { .. } => LabeledSpan::underline(primary_source_span),
            OwnedRawParseError::UnrecognizedEof { expected, .. } => LabeledSpan::new_with_span(
                expected_to_string(expected, &POLICY_TOKEN_CONFIG),
                primary_source_span,
            ),
            OwnedRawParseError::UnrecognizedToken { expected, .. } => LabeledSpan::new_with_span(
                expected_to_string(expected, &POLICY_TOKEN_CONFIG),
                primary_source_span,
            ),
            OwnedRawParseError::ExtraToken { .. } => LabeledSpan::underline(primary_source_span),
            OwnedRawParseError::User { .. } => LabeledSpan::underline(primary_source_span),
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
            Some(friendly_token_name) => write!(f, "{}", friendly_token_name),
            None => write!(f, "{}", token.replace('"', "`")),
        },
    )
    .expect("failed to format expected tokens");
    Some(expected_string)
}

/// Multiple parse errors.
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

    /// Add an error to the `ParseErrors`
    pub(super) fn push(&mut self, err: impl Into<ParseError>) {
        self.0.push(err.into());
    }

    /// returns a Vec with stringified versions of the ParseErrors
    pub fn errors_as_strings(&self) -> Vec<String> {
        self.0.iter().map(ToString::to_string).collect()
    }
}

impl Display for ParseErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.first() {
            Some(first_err) => write!(f, "{first_err}"), // intentionally showing only the first error; see #326
            None => write!(f, "{}", Self::DESCRIPTION_IF_EMPTY),
        }
    }
}

impl std::error::Error for ParseErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.first().and_then(std::error::Error::source)
    }

    #[allow(deprecated)]
    fn description(&self) -> &str {
        match self.first() {
            Some(first_err) => first_err.description(),
            None => Self::DESCRIPTION_IF_EMPTY,
        }
    }

    #[allow(deprecated)]
    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.first().and_then(std::error::Error::cause)
    }
}

// Except for `.related()`, everything else is forwarded to the first error, if it is present.
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
        self.first().and_then(Diagnostic::code)
    }

    fn severity(&self) -> Option<miette::Severity> {
        self.first().and_then(Diagnostic::severity)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.first().and_then(Diagnostic::help)
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.first().and_then(Diagnostic::url)
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
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

impl<T: Into<ParseError>> From<T> for ParseErrors {
    fn from(err: T) -> Self {
        vec![err.into()].into()
    }
}

impl From<Vec<ParseError>> for ParseErrors {
    fn from(errs: Vec<ParseError>) -> Self {
        ParseErrors(errs)
    }
}

impl<T: Into<ParseError>> FromIterator<T> for ParseErrors {
    fn from_iter<I: IntoIterator<Item = T>>(errs: I) -> Self {
        ParseErrors(errs.into_iter().map(Into::into).collect())
    }
}

impl<T: Into<ParseError>> Extend<T> for ParseErrors {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.0.extend(iter.into_iter().map(Into::into))
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
