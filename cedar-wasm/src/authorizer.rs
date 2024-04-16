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

//! This module contains the entry point to the wasm isAuthorized functionality.
use cedar_policy::ffi::{
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
        AuthorizationAnswer::Success {
            response,
            warnings: _,
        } => AuthorizationResult::Success { response },
        AuthorizationAnswer::Failure {
            errors,
            warnings: _,
        } => AuthorizationResult::Error { errors },
    }
}
