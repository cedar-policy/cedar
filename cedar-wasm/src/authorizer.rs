//! This module contains the entry point to the wasm isAuthorized functionality.
use cedar_policy::frontend::is_authorized::{
    is_authorized, AuthorizationAnswer, AuthorizationCall, Response,
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum AuthorizationResult {
    Success { response: Response },
    Error { errors: Vec<String> },
}

#[wasm_bindgen(js_name = "isAuthorized")]
pub fn wasm_is_authorized(call: AuthorizationCall) -> AuthorizationResult {
    match is_authorized(call) {
        AuthorizationAnswer::Success { response } => AuthorizationResult::Success { response },
        AuthorizationAnswer::Failure {
            errors,
            warnings: _,
        } => AuthorizationResult::Error { errors },
    }
}
