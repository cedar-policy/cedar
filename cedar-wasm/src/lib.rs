#![forbid(unsafe_code)]

use wasm_bindgen::prelude::*;

mod authorizer;
mod policies_and_templates;
mod schema_validator;
mod validator;

pub use authorizer::wasm_is_authorized;
pub use policies_and_templates::{
    check_parse_policy_set, policy_text_from_json, policy_text_to_json,
};
pub use schema_validator::wasm_validate_schema;
pub use validator::wasm_validate;

#[wasm_bindgen(js_name = "getCedarVersion")]
pub fn get_cedar_version() -> String {
    std::env!("CEDAR_VERSION").to_string()
}
