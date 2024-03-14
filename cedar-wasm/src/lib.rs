#![forbid(unsafe_code)]

use wasm_bindgen::prelude::*;

mod authorizer;
mod formatter;
mod policies_and_templates;
mod schema_and_entities_and_context;
mod validator;

pub use authorizer::wasm_is_authorized;
pub use formatter::wasm_format_policies;
pub use policies_and_templates::{
    check_parse_policy_set, check_parse_template, policy_text_from_json, policy_text_to_json,
};
pub use schema_and_entities_and_context::{
    check_parse_context, check_parse_entities, check_parse_schema,
};
pub use validator::wasm_validate;

#[wasm_bindgen(js_name = "getCedarVersion")]
pub fn get_cedar_version() -> String {
    std::env!("CEDAR_VERSION").to_string()
}
