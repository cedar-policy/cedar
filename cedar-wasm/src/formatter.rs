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

use cedar_policy_formatter::{policies_str_to_pretty, Config};
use serde::{Deserialize, Serialize};

use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum FormattingResult {
    Success { formatted_policy: String },
    Error { errors: Vec<String> },
}

#[wasm_bindgen(js_name = "formatPolicies")]
pub fn wasm_format_policies(
    policies_str: &str,
    line_width: i32,
    indent_width: i32,
) -> FormattingResult {
    let line_width: usize = match line_width.try_into() {
        Ok(width) => width,
        Err(_) => {
            return FormattingResult::Error {
                errors: vec!["Input size error (line width)".to_string()],
            }
        }
    };
    let indent_width: isize = match indent_width.try_into() {
        Ok(width) => width,
        Err(_) => {
            return FormattingResult::Error {
                errors: vec!["Input size error (indent width)".to_string()],
            }
        }
    };
    let config = Config {
        line_width,
        indent_width,
    };
    match policies_str_to_pretty(policies_str, &config) {
        Ok(prettified_policy) => FormattingResult::Success {
            formatted_policy: prettified_policy,
        },
        Err(err) => FormattingResult::Error {
            errors: vec![err.to_string()],
        },
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use cool_asserts::assert_matches;

    #[test]
    fn test_format_policies() {
        let policy = r#"permit(principal, action == Action::"view", resource in Albums::"gangsta rap") when {principal.is_gangsta == true};"#;
        let expected = "permit (\n    principal,\n    action == Action::\"view\",\n    resource in Albums::\"gangsta rap\"\n)\nwhen { principal.is_gangsta == true };";
        let result = wasm_format_policies(policy, 80, 4);
        assert_matches!(result, FormattingResult::Success { formatted_policy } => {
            assert_eq!(formatted_policy, expected.to_string());
        });
    }
}
