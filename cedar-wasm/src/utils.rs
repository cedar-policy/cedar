use cedar_policy::ffi::{Policy, Schema, Template};
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsError;

#[derive(Tsify, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
/// struct that defines the result of getting valid request environments
pub enum GetValidRequestEnvsResult {
    /// represents a successful call to [`get_valid_request_envs_template()`]
    /// or [`get_valid_request_envs_policy()`]
    Success {
        principals: Vec<String>,
        actions: Vec<String>,
        resources: Vec<String>,
    },
    /// represents a failed call to [`get_valid_request_envs_template()`]
    /// or [`get_valid_request_envs_policy()`]
    Failure {
        /// the encountered error
        error: String,
    },
}

/// Get valid request environment
///
/// # Errors
///
/// Throws if `t` does not match the `Template` type or `s` does not
/// match the `Schema` type, or if the result cannot be serialized back to
/// JavaScript.
#[wasm_bindgen(js_name = "getValidRequestEnvsTemplate")]
pub fn get_valid_request_envs_template_wasm(
    t: Ts<Template>,
    s: Ts<Schema>,
) -> Result<Ts<GetValidRequestEnvsResult>, JsError> {
    Ok(get_valid_request_envs_template(t.to_rust()?, s.to_rust()?).into_ts()?)
}

/// Get valid request environment
pub fn get_valid_request_envs_template(t: Template, s: Schema) -> GetValidRequestEnvsResult {
    match t.get_valid_request_envs(s) {
        Ok((principals, actions, resources)) => GetValidRequestEnvsResult::Success {
            principals: principals.collect(),
            actions: actions.collect(),
            resources: resources.collect(),
        },
        Err(r) => GetValidRequestEnvsResult::Failure {
            error: r.to_string(),
        },
    }
}

/// Get valid request environment
///
/// # Errors
///
/// Throws if `t` does not match the `Policy` type or `s` does not
/// match the `Schema` type, or if the result cannot be serialized back to
/// JavaScript.
#[wasm_bindgen(js_name = "getValidRequestEnvsPolicy")]
pub fn get_valid_request_envs_policy_wasm(
    t: Ts<Policy>,
    s: Ts<Schema>,
) -> Result<Ts<GetValidRequestEnvsResult>, JsError> {
    Ok(get_valid_request_envs_policy(t.to_rust()?, s.to_rust()?).into_ts()?)
}

/// Get valid request environment
pub fn get_valid_request_envs_policy(t: Policy, s: Schema) -> GetValidRequestEnvsResult {
    match t.get_valid_request_envs(s) {
        Ok((principals, actions, resources)) => GetValidRequestEnvsResult::Success {
            principals: principals.collect(),
            actions: actions.collect(),
            resources: resources.collect(),
        },
        Err(r) => GetValidRequestEnvsResult::Failure {
            error: r.to_string(),
        },
    }
}
