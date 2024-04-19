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

use cedar_policy::ffi;
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

/// `ffi::ValidationAnswer`, but with `serde(rename_all = "camelCase")`
///
/// REVIEW: do we want to just camelCase the fields in the normal
/// `ValidationAnswer`, and adapt Java and others? It's confusing for
/// Rust<->Wasm to use camelCased JSON field names but Rust<->Java to use
/// snake_cased JSON field names
#[derive(Tsify, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum ValidationAnswer {
    /// Represents a failure to parse or call the validator
    Failure {
        /// Parsing errors
        errors: Vec<ffi::DetailedError>,
        /// Warnings encountered
        warnings: Vec<ffi::DetailedError>,
    },
    /// Represents a successful validation call
    #[serde(rename_all = "camelCase")]
    Success {
        /// Errors from any issues found during validation
        validation_errors: Vec<ffi::ValidationError>,
        /// Warnings from any issues found during validation
        validation_warnings: Vec<ffi::ValidationError>,
        /// Other warnings, not associated with specific policies.
        /// For instance, warnings about your schema itself.
        other_warnings: Vec<ffi::DetailedError>,
    },
}

impl From<ffi::ValidationAnswer> for ValidationAnswer {
    fn from(ans: ffi::ValidationAnswer) -> Self {
        match ans {
            ffi::ValidationAnswer::Failure { errors, warnings } => {
                Self::Failure { errors, warnings }
            }
            ffi::ValidationAnswer::Success {
                validation_errors,
                validation_warnings,
                other_warnings,
            } => Self::Success {
                validation_errors,
                validation_warnings,
                other_warnings,
            },
        }
    }
}

#[wasm_bindgen(js_name = "validate")]
pub fn wasm_validate(call: ffi::ValidationCall) -> ValidationAnswer {
    ffi::validate(call).into()
}
