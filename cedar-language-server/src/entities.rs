use cedar_policy_core::validator::{CoreSchema, ValidatorSchema};
use cedar_policy_core::{entities::TCComputation, extensions::Extensions};
use lsp_types::Diagnostic;

use crate::{schema::SchemaInfo, utils::to_lsp_diagnostics};

pub(crate) fn entities_diagnostics(
    text: &str,
    schema_info: Option<SchemaInfo>,
) -> Option<Vec<Diagnostic>> {
    let schema = schema_info.and_then(|s| ValidatorSchema::try_from(&s).ok());
    let schema = schema.as_ref().map(CoreSchema::new);

    let eparser = cedar_policy_core::entities::EntityJsonParser::new(
        schema.as_ref(),
        Extensions::all_available(),
        TCComputation::ComputeNow,
    );
    let Err(error) = eparser.from_json_str(text) else {
        return None;
    };

    Some(to_lsp_diagnostics(&error, text))
}
