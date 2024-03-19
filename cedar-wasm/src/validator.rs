use cedar_policy::frontend::validate::{validate, ValidateAnswer, ValidateCall, ValidationNote};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum ValidateResult {
    Success { notes: Vec<ValidationNote> },
    Error { errors: Vec<String> },
}

#[wasm_bindgen(js_name = "validate")]
pub fn wasm_validate(call: ValidateCall) -> ValidateResult {
    match validate(&call) {
        Ok(answer) => match answer {
            ValidateAnswer::Success { notes } => ValidateResult::Success { notes },
            ValidateAnswer::ParseFailed { errors } => ValidateResult::Error { errors },
        },
        Err(err) => ValidateResult::Error {
            errors: vec![err.to_string()],
        },
    }
}
