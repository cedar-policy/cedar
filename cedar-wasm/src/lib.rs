#![forbid(unsafe_code)]

use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = "getCedarVersion")]
pub fn get_cedar_version() -> String {
    std::env!("CEDAR_VERSION").to_string()
}
