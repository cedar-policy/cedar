use std::str::FromStr;

use cedar_policy::Schema;
use serde::{Deserialize, Serialize};

use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Debug, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum SchemaValidationResult {
    Success { ok: bool },
    Error { errors: Vec<String> },
}

#[wasm_bindgen(js_name = "validateSchema")]
pub fn wasm_validate_schema(input: &str) -> SchemaValidationResult {
    match Schema::from_str(input) {
        Ok(_) => SchemaValidationResult::Success { ok: true },
        Err(e) => SchemaValidationResult::Error {
            errors: vec![e.to_string()],
        },
    }
}
