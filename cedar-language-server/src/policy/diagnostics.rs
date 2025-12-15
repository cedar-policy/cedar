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

use cedar_policy_core::parser::parse_policyset;
use cedar_policy_core::validator::validation_errors::UnrecognizedActionIdHelp;
use cedar_policy_core::validator::{ValidationError, ValidationMode, Validator, ValidatorSchema};
use serde::{Deserialize, Serialize};
use tower_lsp_server::lsp_types::{Diagnostic, Range};

use crate::schema::SchemaInfo;
use crate::utils::{to_lsp_diagnostics, ToRange};

/// Validates a Cedar policy set against a schema and generates diagnostics for any issues.
///
/// This function performs two levels of validation:
/// 1. Syntax validation - checks for parsing errors in the policy text
/// 2. Semantic validation - verifies the policy against a schema (if provided)
///
/// The diagnostics include information about the error location in the source code,
/// error messages, and related details that can be displayed in an IDE or editor.
///
/// # Returns
///
/// A `Result` containing:
/// - A vector of `Diagnostic` objects representing any issues found during validation
/// - An error if the schema validation process itself fails
///
/// # Diagnostics
///
/// The function generates diagnostics for:
/// - Syntax errors (e.g., mismatched brackets, invalid tokens)
/// - Type errors (e.g., comparing a string to a number)
/// - Reference errors (e.g., referencing undefined entity types)
/// - Action constraints that don't match schema definitions
/// - Warnings about potentially problematic policy patterns
pub fn validate_policyset(
    policy: &str,
    schema: Option<SchemaInfo>,
) -> anyhow::Result<Vec<Diagnostic>> {
    let parsed = parse_policyset(policy);
    let policy_set = match parsed {
        Ok(policy_set) => policy_set,
        Err(parse_errors) => {
            return Ok(to_lsp_diagnostics(&parse_errors, policy));
        }
    };

    if let Some(schema) = schema {
        let validator = Validator::new(ValidatorSchema::try_from(&schema)?);
        let result = validator.validate(&policy_set, ValidationMode::Strict);

        Ok(result
            .validation_errors()
            .flat_map(|e| {
                to_lsp_diagnostics(e, policy)
                    .into_iter()
                    .map(|d| Diagnostic {
                        data: convert_validation_error_data(e),
                        ..d
                    })
            })
            .chain(
                result
                    .validation_warnings()
                    .flat_map(|w| to_lsp_diagnostics(w, policy)),
            )
            .collect::<Vec<_>>())
    } else {
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DidYouMeanCodeAction {
    pub(crate) range: Range,
    pub alternative: String,
}

fn convert_validation_error_data(error: &ValidationError) -> Option<serde_json::Value> {
    let data = match error {
        ValidationError::UnrecognizedActionId(error) => error
            .hint
            .as_ref()
            .and_then(|hint| match hint {
                UnrecognizedActionIdHelp::SuggestAlternative(alternative) => alternative.into(),
                UnrecognizedActionIdHelp::AvoidActionTypeInActionId(_) => None,
            })
            .zip(error.source_loc.as_ref()),
        ValidationError::UnrecognizedEntityType(error) => error
            .suggested_entity_type
            .as_ref()
            .zip(error.source_loc.as_ref()),
        _ => None,
    }?;

    let code_action = DidYouMeanCodeAction {
        range: data.1.to_range(),
        alternative: data.0.clone(),
    };

    serde_json::to_value(code_action).ok()
}
