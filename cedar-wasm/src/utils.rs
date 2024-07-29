use cedar_policy::ffi::{Schema, Template};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[tsify(into_wasm_abi, from_wasm_abi)]
/// struct that defines the result of getting valid request environments
pub enum GetValidRequestEnvsResult {
    /// represents a successful call to [`get_valid_request_envs()`]
    Success {
        principals: Vec<String>,
        actions: Vec<String>,
        resources: Vec<String>,
    },
    /// represents a failed call to [`get_valid_request_envs()`]
    Error {
        /// the encountered error
        error: String,
    },
}

/// Get valid request environment
#[wasm_bindgen(js_name = "getValidRequestEnvs")]
pub fn get_valid_request_envs(t: Template, s: Schema) -> GetValidRequestEnvsResult {
    match t.get_valid_request_envs(s) {
        Ok((principals, actions, resources)) => GetValidRequestEnvsResult::Success {
            principals: principals.into_iter().collect(),
            actions: actions.into_iter().collect(),
            resources: resources.into_iter().collect(),
        },
        Err(r) => GetValidRequestEnvsResult::Error {
            error: r.to_string(),
        },
    }
}
