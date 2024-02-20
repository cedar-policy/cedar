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

use std::sync::Arc;

use lalrpop_util::lalrpop_mod;
use miette::Diagnostic;
use thiserror::Error;

use crate::human_schema::to_json_schema::custom_schema_to_json_schema;

use super::{
    ast::Schema,
    err::{self, ParseError, ParseErrors, SchemaWarning, ToJsonSchemaErrors},
};

lalrpop_mod!(
    #[allow(warnings, unused)]
    //PANIC SAFETY: lalrpop uses unwraps, and we are trusting lalrpop to generate correct code
    #[allow(clippy::unwrap_used)]
    //PANIC SAFETY: lalrpop uses slicing, and we are trusting lalrpop to generate correct code
    #[allow(clippy::indexing_slicing)]
    //PANIC SAFETY: lalrpop uses unreachable, and we are trusting lalrpop to generate correct code
    #[allow(clippy::unreachable)]
    //PANIC SAFETY: lalrpop uses panic, and we are trusting lalrpop to generate correct code
    #[allow(clippy::panic)]
    pub grammar,
    "/src/human_schema/grammar.rs"
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
        .map(Into::into)
        .collect::<Vec<ParseError>>();
    let parsed = match result {
        Ok(parsed) => parsed,
        Err(e) => {
            return Err(ParseErrors::new(e.into(), errors));
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
    static ref POLICIES_PARSER: grammar::SchemaParser = grammar::SchemaParser::new();
}

#[derive(Debug, Diagnostic, Error)]
pub enum HumanSyntaxParseErrors {
    #[error(transparent)]
    #[diagnostic(transparent)]
    NaturalSyntaxError(#[from] err::ParseErrors),
    #[error(transparent)]
    #[diagnostic(transparent)]
    JsonError(#[from] ToJsonSchemaErrors),
}

pub fn parse_natural_schema_fragment(
    src: &str,
) -> Result<(crate::SchemaFragment, impl Iterator<Item = SchemaWarning>), HumanSyntaxParseErrors> {
    let ast: Schema = parse_collect_errors(&*POLICIES_PARSER, grammar::SchemaParser::parse, src)?;
    let tuple = custom_schema_to_json_schema(ast)?;
    Ok(tuple)
}

/// Parse schema from text
pub fn parse_schema(text: &str) -> Result<Schema, err::ParseErrors> {
    parse_collect_errors(&*POLICIES_PARSER, grammar::SchemaParser::parse, text)
}
