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

use lalrpop_util as lalr;
use thiserror::Error;

pub(crate) type RawParseError<'a> = lalr::ParseError<usize, lalr::lexer::Token<'a>, String>;
pub(crate) type RawErrorRecovery<'a> = lalr::ErrorRecovery<usize, lalr::lexer::Token<'a>, String>;

/// For errors during parsing
#[derive(Debug, Error, PartialEq, Clone)]
pub enum ParseError {
    /// Error from the lalrpop parser, no additional information
    #[error("{0}")]
    ToCST(String),
    /// Error in the cst -> ast transform, mostly well-formedness issues
    #[error("poorly formed: {0}")]
    ToAST(String),
    /// (Potentially) multiple errors. This variant includes a "context" for
    /// what we were trying to do when we encountered these errors
    #[error("error while {context}: {}", MultipleParseErrors(errs))]
    WithContext {
        /// What we were trying to do
        context: String,
        /// Error(s) we encountered while doing it
        errs: Vec<ParseError>,
    },
    /// Error concerning restricted expressions
    #[error(transparent)]
    RestrictedExpressionError(#[from] crate::ast::RestrictedExpressionError),
}

impl ParseError {
    pub(crate) fn from_raw(e: RawParseError<'_>) -> Self {
        ParseError::ToCST(format!("{}", e))
    }

    pub(crate) fn from_recovery(e: RawErrorRecovery<'_>) -> Self {
        ParseError::from_raw(e.error)
    }
}

/// if you wrap a `Vec<ParseError>` in this struct, it gains a Display impl
/// that displays each parse error on its own line, indented.
#[derive(Debug, Error)]
pub struct ParseErrors(pub Vec<ParseError>);

impl ParseErrors {
    /// returns a Vec with stringified versions of the ParserErrors
    pub fn errors_as_strings(&self) -> Vec<String> {
        self.0
            .iter()
            .map(|parser_error| format!("{}", parser_error))
            .collect()
    }
}

impl std::fmt::Display for ParseErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", MultipleParseErrors(&self.0))
    }
}

impl From<ParseError> for ParseErrors {
    fn from(e: ParseError) -> ParseErrors {
        ParseErrors(vec![e])
    }
}

/// Like [`ParseErrors`], but you don't have to own the `Vec`
#[derive(Debug, Error)]
pub struct MultipleParseErrors<'a>(pub &'a [ParseError]);

impl<'a> std::fmt::Display for MultipleParseErrors<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            write!(f, "no errors found")
        } else {
            for err in self.0 {
                write!(f, "\n  {}", err)?;
            }
            Ok(())
        }
    }
}
