//! This module contains the entry point to the wasm isAuthorized functionality.
use cedar_policy::frontend::{is_authorized::is_authorized_json_str, utils::InterfaceResult};

use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = isAuthorized)]
pub fn wasm_is_authorized(input: &str) -> InterfaceResult {
    match is_authorized_json_str(input) {
        Ok(ans) => InterfaceResult::Success { result: ans },
        Err(e) => InterfaceResult::fail_bad_request(vec![e.to_string()]),
    }
}
