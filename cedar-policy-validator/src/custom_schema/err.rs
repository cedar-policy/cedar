use std::{collections::HashMap, fmt::Display};

use cedar_policy_core::parser::{err::expected_to_string, unescape::UnescapeError, Loc, Node};
use lalrpop_util as lalr;
use lazy_static::lazy_static;
use miette::{Diagnostic, LabeledSpan, SourceSpan};
use nonempty::NonEmpty;
use smol_str::SmolStr;
use thiserror::Error;

use super::ast::PR;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UserError {
    #[error("An empty list was passed")]
    EmptyList,
    #[error("Invalid escape codes")]
    StringEscape(NonEmpty<UnescapeError>),
}

pub(crate) type RawLocation = usize;
pub(crate) type RawToken<'a> = lalr::lexer::Token<'a>;
pub(crate) type RawUserError = Node<UserError>;

pub(crate) type RawParseError<'a> = lalr::ParseError<RawLocation, RawToken<'a>, RawUserError>;
pub(crate) type RawErrorRecovery<'a> = lalr::ErrorRecovery<RawLocation, RawToken<'a>, RawUserError>;

type OwnedRawParseError = lalr::ParseError<RawLocation, String, RawUserError>;

lazy_static! {
    /// Keys mirror the token names defined in the `match` block of
    /// `grammar.lalrpop`.
    static ref FRIENDLY_TOKEN_NAMES: HashMap<&'static str, &'static str> = HashMap::from([
        ("IN", "`in`"),
        ("PRINCIPAL", "`principal`"),
        ("ACTION", "`action`"),
        ("RESOURCE", "`resource`"),
        ("CONTEXT", "`context`"),
        ("STRINGLIT", "string literal"),
        ("ENTITY", "`entity`"),
        ("NAMESPACE", "`namespace`"),
        ("TYPE", "`type`"),
    ]);
}

/// For errors during parsing
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Error generated by lalrpop
    ToAst(OwnedRawParseError),
}

impl From<RawParseError<'_>> for ParseError {
    fn from(err: RawParseError<'_>) -> Self {
        Self::ToAst(err.map_token(|token| token.to_string()))
    }
}

impl From<RawErrorRecovery<'_>> for ParseError {
    fn from(recovery: RawErrorRecovery<'_>) -> Self {
        recovery.error.into()
    }
}

impl ParseError {
    /// Extract a primary source span locating the error.
    pub fn primary_source_span(&self) -> SourceSpan {
        let Self::ToAst(err) = self;
        match err {
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
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self::ToAst(err) = self;
        match err {
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
            OwnedRawParseError::User {
                error: Node { node, .. },
            } => match node {
                UserError::EmptyList => write!(f, "expected a non-empty list"),
                UserError::StringEscape(unescape_errs) => write!(f, "{}", unescape_errs.first()),
            },
        }
    }
}

impl std::error::Error for ParseError {}

impl Diagnostic for ParseError {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        let primary_source_span = self.primary_source_span();
        let Self::ToAst(err) = self;
        let labeled_span = match err {
            OwnedRawParseError::InvalidToken { .. } => LabeledSpan::underline(primary_source_span),
            OwnedRawParseError::UnrecognizedEof { expected, .. } => LabeledSpan::new_with_span(
                expected_to_string(expected, &FRIENDLY_TOKEN_NAMES),
                primary_source_span,
            ),
            OwnedRawParseError::UnrecognizedToken { expected, .. } => LabeledSpan::new_with_span(
                expected_to_string(expected, &FRIENDLY_TOKEN_NAMES),
                primary_source_span,
            ),
            OwnedRawParseError::ExtraToken { .. } => LabeledSpan::underline(primary_source_span),
            OwnedRawParseError::User { .. } => LabeledSpan::underline(primary_source_span),
        };
        Some(Box::new(std::iter::once(labeled_span)))
    }
}

/// Multiple parse errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseErrors(pub NonEmpty<ParseError>);

impl ParseErrors {
    pub fn new(first: ParseError, rest: impl IntoIterator<Item = ParseError>) -> Self {
        let mut nv = NonEmpty::singleton(first);
        let mut v = rest.into_iter().collect::<Vec<_>>();
        nv.append(&mut v);
        Self(nv)
    }

    pub fn from_iter(i: impl IntoIterator<Item = ParseError>) -> Option<Self> {
        let v = i.into_iter().collect::<Vec<_>>();
        Some(Self(NonEmpty::from_vec(v)?))
    }

    pub fn iter(&self) -> impl Iterator<Item = &ParseError> {
        self.0.iter()
    }
}

impl Display for ParseErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.first())
    }
}

impl std::error::Error for ParseErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(self.0.first())
    }
}

// Except for `.related()`, everything else is forwarded to the first error, if it is present.
// This ensures that users who only use `Display`, `.code()`, `.labels()` etc, still get rich
// information for the first error, even if they don't realize there are multiple errors here.
// See cedar-policy/cedar#326.
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
        Diagnostic::code(self.0.first())
    }

    fn severity(&self) -> Option<miette::Severity> {
        Diagnostic::severity(self.0.first())
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Diagnostic::help(self.0.first())
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Diagnostic::url(self.0.first())
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Diagnostic::source_code(self.0.first())
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        Diagnostic::labels(self.0.first())
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        Diagnostic::diagnostic_source(self.0.first())
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ToJsonSchemaErrors {
    #[error("foo")]
    Errs(Vec<ToJsonSchemaError>),
}

impl ToJsonSchemaErrors {
    pub fn iter(&self) -> impl Iterator<Item = &ToJsonSchemaError> {
        match self {
            Self::Errs(v) => v.iter(),
        }
    }
}

impl IntoIterator for ToJsonSchemaErrors {
    type Item = ToJsonSchemaError;

    type IntoIter = std::vec::IntoIter<ToJsonSchemaError>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::Errs(v) => v.into_iter(),
        }
    }
}

impl From<ToJsonSchemaError> for ToJsonSchemaErrors {
    fn from(value: ToJsonSchemaError) -> Self {
        Self::Errs(vec![value])
    }
}

impl FromIterator<ToJsonSchemaError> for ToJsonSchemaErrors {
    fn from_iter<T: IntoIterator<Item = ToJsonSchemaError>>(iter: T) -> Self {
        Self::Errs(iter.into_iter().collect())
    }
}

/// For errors during schema format conversion
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ToJsonSchemaError {
    /// Error raised when there are duplicate keys
    #[error("Duplicate keys: `{key}`")]
    DuplicateKeys { key: SmolStr, start: Loc, end: Loc },
    /// Error raised when there are duplicate declarations
    #[error("Duplicate declarations: `{decl}`")]
    DuplicateDeclarations { decl: SmolStr, start: Loc, end: Loc },
    #[error("Duplicate context declaration. Action may have at most one context declaration")]
    DuplicateContext { start: Loc, end: Loc },
    #[error("Duplicate {kind} decleration. Action may have at most once {kind} declaration")]
    DuplicatePR { kind: PR, start: Loc, end: Loc },

    /// Error raised when there are duplicate namespace IDs
    #[error("Duplicate namespace IDs: `{namespace_id}`")]
    DuplicateNameSpaces {
        namespace_id: SmolStr,
        start: Loc,
        end: Loc,
    },
    /// Invalid type name
    #[error("Unknown type name: `{0:?}`")]
    UnknownTypeName(Node<SmolStr>),
    #[error("Use reserved namespace `__cedar`")]
    UseReservedNamespace(Loc),
}

impl ToJsonSchemaError {
    pub fn duplicate_keys(key: SmolStr, start: Loc, end: Loc) -> Self {
        Self::DuplicateKeys { key, start, end }
    }
    pub fn duplicate_decls(decl: SmolStr, start: Loc, end: Loc) -> Self {
        Self::DuplicateDeclarations { decl, start, end }
    }
    pub fn duplicate_namespace(namespace_id: SmolStr, start: Loc, end: Loc) -> Self {
        Self::DuplicateNameSpaces {
            namespace_id,
            start,
            end,
        }
    }
}

impl Diagnostic for ToJsonSchemaError {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        match self {
            ToJsonSchemaError::DuplicateDeclarations { start, end, .. }
            | ToJsonSchemaError::DuplicateContext { start, end }
            | ToJsonSchemaError::DuplicatePR { start, end, .. }
            | ToJsonSchemaError::DuplicateKeys { start, end, .. }
            | ToJsonSchemaError::DuplicateNameSpaces { start, end, .. } => Some(Box::new(
                vec![
                    LabeledSpan::underline(start.span),
                    LabeledSpan::underline(end.span),
                ]
                .into_iter(),
            )),
            ToJsonSchemaError::UnknownTypeName(node) => Some(Box::new(std::iter::once(
                LabeledSpan::underline(node.loc.span),
            ))),
            ToJsonSchemaError::UseReservedNamespace(loc) => {
                Some(Box::new(std::iter::once(LabeledSpan::underline(loc.span))))
            }
        }
    }
}
