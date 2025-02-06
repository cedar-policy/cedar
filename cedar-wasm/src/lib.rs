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

use wasm_bindgen::prelude::*;
mod utils;

use cedar_policy::ffi;
pub use cedar_policy::ffi::{
    check_parse_context, check_parse_entities, check_parse_policy_set, check_parse_schema, format,
    get_lang_version, is_authorized, policy_to_json, policy_to_text, schema_to_json,
    schema_to_text, validate,
};
pub use utils::*;

#[wasm_bindgen(js_name = "getCedarVersion")]
pub fn get_sdk_version_deprecated() -> String {
    get_sdk_version()
}

#[wasm_bindgen(js_name = "getCedarSDKVersion")]
pub fn get_sdk_version() -> String {
    ffi::get_sdk_version()
}
