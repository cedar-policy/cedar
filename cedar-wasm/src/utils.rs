use std::collections::HashSet;

use cedar_policy::ffi::{Schema, Template};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[tsify(into_wasm_abi, from_wasm_abi)]
/// struct that defines the result for the syntax validation function
pub enum GetValidRequestEnvsResult {
    /// represents successful syntax validation
    Success((HashSet<String>, HashSet<String>, HashSet<String>)),
    /// represents a syntax error and encloses a vector of the errors
    Error { error: String },
}

/// Get valid request environment
#[wasm_bindgen(js_name = "getValidRequestEnvs")]
pub fn get_valid_request_envs(t: Template, s: Schema) -> GetValidRequestEnvsResult {
    match t.get_valid_request_envs(s) {
        Ok(envs) => GetValidRequestEnvsResult::Success(envs),
        Err(r) => GetValidRequestEnvsResult::Error {
            error: r.to_string(),
        },
    }
}
