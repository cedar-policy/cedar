//! This module contains the entry point to the wasm isAuthorized functionality.
use cedar_policy::frontend::{is_authorized::json_is_authorized, utils::InterfaceResult};

use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = isAuthorized)]
pub fn wasm_is_authorized(input: &str) -> InterfaceResult {
    json_is_authorized(input)
}
