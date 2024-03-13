use cedar_policy::frontend::{utils::InterfaceResult, validate::json_validate};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = "validate")]
pub fn wasm_validate(input: &str) -> InterfaceResult {
    json_validate(input)
}
