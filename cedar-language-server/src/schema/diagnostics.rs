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
