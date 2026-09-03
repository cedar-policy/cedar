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

//! Parser for Cedar entity data syntax

use std::sync::{Arc, LazyLock};

use lalrpop_util::lalrpop_mod;

use super::ast::EntityDataAst;
use super::err::{ParseError, ParseErrors, RawErrorRecovery};

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
    "/src/entities/cedar_syntax/grammar.rs"
);

// Thread-safe "global" parser, initialized at first use
static ENTITIES_PARSER: LazyLock<grammar::EntitiesParser> =
    LazyLock::new(grammar::EntitiesParser::new);

/// Parse entity data from Cedar syntax text.
///
/// Returns a parsed AST that can then be converted to `Entities` via
/// [`super::to_entities::cedar_entities_to_entities`].
pub fn parse_entities(text: &str) -> Result<EntityDataAst, ParseErrors> {
    parse_collect_errors(text)
}

/// Helper: call parser, collect errors, return unified Result
fn parse_collect_errors(text: &str) -> Result<EntityDataAst, ParseErrors> {
    let mut errs: Vec<RawErrorRecovery<'_>> = Vec::new();
    let src = Arc::from(text);
    let result = ENTITIES_PARSER.parse(&mut errs, &src, true, text);

    let errors: Vec<ParseError> = errs
        .into_iter()
        .map(|rc| ParseError::from_raw_error_recovery(rc, Arc::clone(&src)))
        .collect();

    let parsed = match result {
        Ok(parsed) => parsed,
        Err(e) => {
            return Err(ParseErrors::new(
                ParseError::from_raw_parse_error(e, src),
                errors,
            ));
        }
    };

    match ParseErrors::from_iter(errors) {
        Some(errors) => Err(errors),
        None => Ok(parsed),
    }
}
