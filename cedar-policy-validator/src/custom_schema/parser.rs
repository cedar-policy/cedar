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

use super::{ast::Schema, err};

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
    "/src/custom_schema/grammar.rs"
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

    let mut errors: err::ParseErrors = errs
        .into_iter()
        .map(err::ParseError::from_raw_err_recovery)
        .collect();
    let parsed = match result {
        Ok(parsed) => parsed,
        Err(e) => {
            errors.push(err::ParseError::from_raw_parse_err(e));
            return Err(errors);
        }
    };
    if errors.is_empty() {
        Ok(parsed)
    } else {
        Err(errors)
    }
}

// Thread-safe "global" parsers, initialized at first use
lazy_static::lazy_static! {
    static ref POLICIES_PARSER: grammar::SchemaParser = grammar::SchemaParser::new();
}

/// Parse schema from text
pub fn parse_schema(text: &str) -> Result<Schema, err::ParseErrors> {
    parse_collect_errors(&*POLICIES_PARSER, grammar::SchemaParser::parse, text)
}
