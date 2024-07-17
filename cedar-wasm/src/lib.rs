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

#![forbid(unsafe_code)]

use wasm_bindgen::prelude::*;

mod authorizer;
mod formatter;
mod policies_and_templates;
mod schema_and_entities_and_context;
mod utils;
mod validator;

pub use authorizer::wasm_is_authorized;
pub use formatter::wasm_format_policies;
pub use policies_and_templates::{
    check_parse_policy_set, check_parse_template, policy_text_from_json, policy_text_to_json,
};
pub use schema_and_entities_and_context::{
    check_parse_context, check_parse_entities, check_parse_schema,
};
pub use utils::*;
pub use validator::wasm_validate;

#[wasm_bindgen(js_name = "getCedarVersion")]
pub fn get_cedar_version() -> String {
    std::env!("CEDAR_VERSION").to_string()
}
