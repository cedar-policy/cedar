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

use lalrpop_util as lalr;
use lazy_static::lazy_static;
use miette::{Diagnostic, LabeledSpan, Severity, SourceCode};
use thiserror::Error;

use crate::parser::fmt::join_with_conjunction;
use crate::parser::node::ASTNode;

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
    ToAST(String),
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
