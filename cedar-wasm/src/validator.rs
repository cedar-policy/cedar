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

use cedar_policy::frontend::validate::{
    validate, ValidationAnswer, ValidationCall, ValidationError, ValidationWarning,
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum ValidateResult {
    #[serde(rename_all = "camelCase")]
    Success {
        validation_errors: Vec<ValidationError>,
        validation_warnings: Vec<ValidationWarning>,
    },
    Error {
        errors: Vec<String>,
    },
}

#[wasm_bindgen(js_name = "validate")]
pub fn wasm_validate(call: ValidationCall) -> ValidateResult {
    match validate(call) {
        ValidationAnswer::Success {
            validation_errors,
            validation_warnings,
        } => ValidateResult::Success {
            validation_errors,
            validation_warnings,
        },
        ValidationAnswer::Failure { errors } => ValidateResult::Error { errors },
    }
}
