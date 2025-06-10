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

use cedar_policy_core::extensions::Extensions;
use cedar_policy_core::validator::ValidatorSchema;
use lsp_types::Diagnostic;

use crate::utils::to_lsp_diagnostics;

use super::{SchemaInfo, SchemaType};

/// Validates a Cedar schema document and generates diagnostics for any issues.
///
/// This function performs comprehensive validation of a Cedar schema document,
/// handling both Cedar Schema (.cedar) and JSON Schema formats. It reports syntax errors,
/// semantic issues, and warnings that might affect schema behavior or usability.
///
/// # Returns
///
/// A `Result` containing:
/// - A vector of `Diagnostic` objects representing any issues found during validation
/// - An error if the validation process itself fails
///
/// # Diagnostics
///
/// For Cedar Schema format, the function reports:
/// - Syntax errors (with precise source locations)
/// - Type errors and inconsistencies
/// - Entity type conflicts
/// - Entity attribute issues
/// - Action declaration problems
/// - Warnings about shadowed built-ins or entities
///
/// For JSON Schema format, the function reports:
/// - JSON syntax errors
/// - Schema structure validation issues
/// - Type definition problems
///
/// # Examples
///
/// For a Cedar Schema with syntax errors:
///
/// ```cedarschema
/// namespace App {
///   entity Movie = { isFree: Bool,, }; // Extra comma - syntax error
/// }
/// ```
///
/// The function will report the syntax error with the exact position of the problematic token.
///
/// For a schema with shadowed built-ins:
///
/// ```cedarschema
/// namespace App {
///   type String = { value: Long }; // Warning: shadows built-in type
/// }
/// ```
///
/// The function will report a warning about shadowing the built-in `String` type.
///
/// # Notes
///
/// - Some schema errors are reported at the beginning
///   of the document rather than at specific locations due to lack of location information.
pub(crate) fn validate_entire_schema(schema_info: &SchemaInfo) -> Vec<Diagnostic> {
    let text = &schema_info.text;
    match schema_info.schema_type {
        SchemaType::Json => {
            let schema = ValidatorSchema::from_json_str(text, Extensions::all_available());
            match schema {
                Ok(_) => Vec::new(),
                Err(e) => to_lsp_diagnostics(&e, text),
            }
        }
        SchemaType::CedarSchema => {
            let schema = ValidatorSchema::from_cedarschema_str(text, Extensions::all_available());
            match schema {
                Ok((_, warnings)) => {
                    let mut diagnostics = Vec::new();
                    warnings.for_each(|w| {
                        diagnostics.extend(to_lsp_diagnostics(&w, text));
                    });
                    diagnostics
                }
                Err(e) => to_lsp_diagnostics(&e, text),
            }
        }
    }
}
