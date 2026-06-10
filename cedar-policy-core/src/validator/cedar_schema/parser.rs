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

use std::sync::{Arc, LazyLock};

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
    #[allow(clippy::unwrap_used, reason = "lalrpop uses unwraps, and we are trusting lalrpop to generate correct code")]
    #[allow(clippy::indexing_slicing, reason = "lalrpop uses slicing, and we are trusting lalrpop to generate correct code")]
    #[allow(clippy::string_slice, reason = "lalrpop uses slicing, and we are trusting lalrpop to generate correct code")]
    #[allow(clippy::unreachable, reason = "lalrpop uses unreachable, and we are trusting lalrpop to generate correct code")]
    #[allow(clippy::panic, reason = "lalrpop uses panic, and we are trusting lalrpop to generate correct code")]
    #[allow(clippy::allow_attributes, reason = "lalrpop allows this, and we are trusting lalrpop to generate correct code")]
    #[allow(clippy::allow_attributes_without_reason, reason = "lalrpop allows this, and we are trusting lalrpop to generate correct code")]
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
        bool,
        &'a str,
    ) -> Result<T, err::RawParseError<'a>>,
    text: &'a str,
) -> Result<T, err::ParseErrors> {
    let mut errs = Vec::new();
    let result = parse(parser, &mut errs, &Arc::from(text), true, text);

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
static SCHEMA_PARSER: LazyLock<grammar::SchemaParser> = LazyLock::new(grammar::SchemaParser::new);

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
    /// Schema type nesting depth exceeds the configured limit
    #[error("schema type depth {depth} exceeds the configured limit of {limit}")]
    TypeTooDeep {
        /// Actual depth of the deepest type
        depth: usize,
        /// Configured limit
        limit: usize,
    },
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

/// Like [`parse_cedar_schema_fragment`], but rejects the schema if any type's
/// effective nesting depth exceeds `depth_limit`. Effective depth accounts for
/// depth introduced through chains of common type (typedef) references.
pub fn parse_cedar_schema_fragment_with_depth_limit<'a>(
    src: &str,
    extensions: &Extensions<'a>,
    depth_limit: usize,
) -> Result<
    (
        json_schema::Fragment<crate::validator::RawName>,
        impl Iterator<Item = SchemaWarning> + 'a,
    ),
    CedarSchemaParseErrors,
> {
    let ast: Schema = parse_collect_errors(&*SCHEMA_PARSER, grammar::SchemaParser::parse, src)?;
    let syntactic_depth = super::depth::schema_type_depth(&ast);
    if syntactic_depth > depth_limit {
        return Err(CedarSchemaParseErrors::TypeTooDeep {
            depth: syntactic_depth,
            limit: depth_limit,
        });
    }
    // The syntactic check passed, so nothing directly exceeds the limit, but
    // there might still be types composed from common types that will exceed it
    // after inlining the type definitions.
    let (fragment, warnings) = cedar_schema_to_json_schema(ast, extensions)?;
    // Now check effective depth (after inlining common types) to ensure we
    // avoid any downstream stackoverflow caused by recursion on the inlined
    // types.  We first need to resolve `RawName` to `InternalName` to know
    // exactly what each common type refers to when computing the depth.
    if let Ok(resolved) = fragment.to_internal_name_fragment_with_resolved_types() {
        if let Some(depth) =
            crate::validator::schema_type_depth::fragment_effective_depth(&resolved)
        {
            if depth > depth_limit {
                return Err(CedarSchemaParseErrors::TypeTooDeep {
                    depth,
                    limit: depth_limit,
                });
            }
        }
    }
    Ok((fragment, warnings))
}

/// Parse schema from text
pub fn parse_schema(text: &str) -> Result<Schema, err::ParseErrors> {
    parse_collect_errors(&*SCHEMA_PARSER, grammar::SchemaParser::parse, text)
}
