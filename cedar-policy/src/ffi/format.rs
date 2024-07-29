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

//! JSON FFI entry points for the Cedar policy formatter. The Cedar Wasm
//! formatter is generated from the [`format()`] function in this file.

#![allow(clippy::module_name_repetitions)]

use super::utils::DetailedError;
use cedar_policy_formatter::{policies_str_to_pretty, Config};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(feature = "wasm")]
extern crate tsify;

/// Apply the Cedar policy formatter to a policy set in the Cedar policy format
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "formatPolicies"))]
#[allow(clippy::needless_pass_by_value)]
pub fn format(call: FormattingCall) -> FormattingAnswer {
    let config = Config {
        line_width: call.line_width,
        indent_width: call.indent_width,
    };
    match policies_str_to_pretty(&call.policy_text, &config) {
        Ok(prettified_policy) => FormattingAnswer::Success {
            formatted_policy: prettified_policy,
        },
        Err(err) => FormattingAnswer::Failure {
            errors: vec![err.into()],
        },
    }
}

/// Apply the Cedar policy formatter. Input is a JSON encoding of
/// [`FormattingCall`] and output is a JSON encoding of [`FormattingAnswer`].
///
/// # Errors
///
/// Will return `Err` if the input JSON cannot be deserialized as a
/// [`FormattingCall`].
pub fn format_json(json: serde_json::Value) -> Result<serde_json::Value, serde_json::Error> {
    let ans = format(serde_json::from_value(json)?);
    serde_json::to_value(ans)
}

/// Apply the Cedar policy formatter. Input and output are strings containing
/// serialized JSON, in the shapes expected by [`format_json()`].
///
/// # Errors
///
/// Will return `Err` if the input cannot be converted to valid JSON or
/// deserialized as a [`FormattingCall`].
pub fn format_json_str(json: &str) -> Result<String, serde_json::Error> {
    let ans = format(serde_json::from_str(json)?);
    serde_json::to_string(&ans)
}

/// Struct containing the input data for formatting
#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct FormattingCall {
    /// Policy text. May define multiple policies or templates in the Cedar policy format.
    policy_text: String,
    /// Line width (default is 80)
    #[serde(default = "default_line_width")]
    line_width: usize,
    /// Indentation width (default is 2)
    #[serde(default = "default_indent_width")]
    indent_width: isize,
}

const fn default_line_width() -> usize {
    80
}
const fn default_indent_width() -> isize {
    2
}

/// Result struct for formatting
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum FormattingAnswer {
    /// Represents a failure to call the formatter
    Failure {
        /// Policy parse errors
        errors: Vec<DetailedError>,
    },
    /// Represents a successful formatting call
    Success {
        /// Formatted policy
        formatted_policy: String,
    },
}

// PANIC SAFETY unit tests
#[allow(clippy::panic, clippy::indexing_slicing)]
#[cfg(test)]
mod test {
    use super::*;

    use crate::ffi::test_utils::*;
    use cool_asserts::assert_matches;
    use serde_json::json;

    /// Assert that [`format_json()`] returns [`FormattingAnswer::Success`] and
    /// get the formatted policy
    #[track_caller]
    fn assert_format_succeeds(json: serde_json::Value) -> String {
        let ans_val = format_json(json).unwrap();
        let result: Result<FormattingAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(FormattingAnswer::Success { formatted_policy }) => {
            formatted_policy
        })
    }

    /// Assert that [`format_json()`] returns [`FormattingAnswer::Failure`] and
    /// return the enclosed errors
    #[track_caller]
    fn assert_format_fails(json: serde_json::Value) -> Vec<DetailedError> {
        let ans_val = format_json(json).unwrap();
        let result: Result<FormattingAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(FormattingAnswer::Failure { errors }) => errors)
    }

    #[test]
    fn test_format_succeeds() {
        let json = json!({
        "policyText": "permit(principal in UserGroup::\"alice_friends\", action == Action::\"viewPhoto\", resource);",
        "lineWidth": 100,
        "indentWidth": 4,
        });

        let result = assert_format_succeeds(json);
        assert_eq!(result, "permit (\n    principal in UserGroup::\"alice_friends\",\n    action == Action::\"viewPhoto\",\n    resource\n);");
    }

    #[test]
    fn test_format_succeed_default_values() {
        let json = json!({
        "policyText": "permit(principal in UserGroup::\"alice_friends\", action == Action::\"viewPhoto\", resource);",
        });

        let result = assert_format_succeeds(json);
        assert_eq!(result, "permit (\n  principal in UserGroup::\"alice_friends\",\n  action == Action::\"viewPhoto\",\n  resource\n);");
    }

    #[test]
    fn test_format_fails() {
        let json = json!({
        "policyText": "foo(principal in UserGroup::\"alice_friends\", action == Action::\"viewPhoto\", resource);",
        "lineWidth": 100,
        "indentWidth": 4,
        });

        let errs = assert_format_fails(json);
        assert_exactly_one_error(
            &errs,
            "cannot parse input policies: invalid policy effect: foo",
            Some("effect must be either `permit` or `forbid`"),
        );
    }
}
