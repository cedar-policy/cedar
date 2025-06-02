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

//! Parser for schemas in the Cedar syntax

use std::sync::Arc;

use lalrpop_util::lalrpop_mod;
use miette::Diagnostic;
use thiserror::Error;

use super::{
    ast::Schema,
    err::{self, ParseError, ParseErrors, SchemaWarning, ToJsonSchemaErrors},
    to_json_schema::cedar_schema_to_json_schema,
};
use crate::extensions::Extensions;
use crate::validator::json_schema;

lalrpop_mod!(
    #[allow(warnings, unused, missing_docs, missing_debug_implementations)]
    //PANIC SAFETY: lalrpop uses unwraps, and we are trusting lalrpop to generate correct code
    #[allow(clippy::unwrap_used)]
    //PANIC SAFETY: lalrpop uses slicing, and we are trusting lalrpop to generate correct code
    #[allow(clippy::indexing_slicing)]
    //PANIC SAFETY: lalrpop uses unreachable, and we are trusting lalrpop to generate correct code
    #[allow(clippy::unreachable)]
    //PANIC SAFETY: lalrpop uses panic, and we are trusting lalrpop to generate correct code
    #[allow(clippy::panic)]
    pub grammar,
    "/src/validator/cedar_schema/grammar.rs"
);

/// This helper function calls a generated parser, collects errors that could be
/// generated multiple ways, and returns a single Result where the error type is
/// [`err::ParseErrors`].
fn parse_collect_errors<'a, P, T>(
    parser: &P,
    parse: impl FnOnce(
        &P,
        &mut Vec<err::RawErrorRecovery<'a>>,
        &Arc<str>,
        &'a str,
    ) -> Result<T, err::RawParseError<'a>>,
    text: &'a str,
) -> Result<T, err::ParseErrors> {
    let mut errs = Vec::new();
    let result = parse(parser, &mut errs, &Arc::from(text), text);

    let errors = errs
        .into_iter()
        .map(|rc| ParseError::from_raw_error_recovery(rc, Arc::from(text)))
        .collect::<Vec<ParseError>>();
    let parsed = match result {
        Ok(parsed) => parsed,
        Err(e) => {
            return Err(ParseErrors::new(
                ParseError::from_raw_parse_error(e, Arc::from(text)),
                errors,
            ));
        }
    };
    match ParseErrors::from_iter(errors) {
        Some(errors) => Err(errors),
        // No Errors: good to return parse
        None => Ok(parsed),
    }
}

// Thread-safe "global" parsers, initialized at first use
lazy_static::lazy_static! {
    static ref SCHEMA_PARSER: grammar::SchemaParser = grammar::SchemaParser::new();
    static ref TYPE_PARSER: grammar::TypeParser = grammar::TypeParser::new();
}

/// Parse errors for parsing a schema in the Cedar syntax
//
// This is NOT a publicly exported error type.
#[derive(Debug, Diagnostic, Error)]
#[non_exhaustive]
pub enum CedarSchemaParseErrors {
    /// Parse error for the Cedar syntax
    #[error(transparent)]
    #[diagnostic(transparent)]
    SyntaxError(#[from] err::ParseErrors),
    /// Error converting the parsed representation into the internal JSON representation
    #[error(transparent)]
    #[diagnostic(transparent)]
    JsonError(#[from] ToJsonSchemaErrors),
}

/// Parse a schema fragment, in the Cedar syntax, into a [`json_schema::Fragment`],
/// possibly generating warnings
pub fn parse_cedar_schema_fragment<'a>(
    src: &str,
    extensions: &Extensions<'a>,
) -> Result<
    (
        json_schema::Fragment<crate::validator::RawName>,
        impl Iterator<Item = SchemaWarning> + 'a,
    ),
    CedarSchemaParseErrors,
> {
    let ast: Schema = parse_collect_errors(&*SCHEMA_PARSER, grammar::SchemaParser::parse, src)?;
    let tuple = cedar_schema_to_json_schema(ast, extensions)?;
    Ok(tuple)
}

/// Parse schema from text
pub fn parse_schema(text: &str) -> Result<Schema, err::ParseErrors> {
    parse_collect_errors(&*SCHEMA_PARSER, grammar::SchemaParser::parse, text)
}
