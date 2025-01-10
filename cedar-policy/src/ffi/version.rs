#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::api;

/// Get language version of Cedar
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "getCedarLangVersion"))]
pub fn get_lang_version() -> String {
    let version = api::version::get_lang_version();
    format!("{}.{}", version.major, version.minor)
}

/// Get SDK version of Cedar
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "getCedarSDKVersion"))]
pub fn get_sdk_version() -> String {
    let version = api::version::get_sdk_version();
    format!("{version}")
}
