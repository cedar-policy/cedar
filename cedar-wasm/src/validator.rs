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
