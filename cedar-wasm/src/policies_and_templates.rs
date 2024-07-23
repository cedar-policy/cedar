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

use cedar_policy::Policy;
use cedar_policy_core::parser::parse_policy_or_template_to_est;
use serde::{Deserialize, Serialize};

use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum JsonToPolicyResult {
    #[serde(rename_all = "camelCase")]
    Success {
        policy_text: String,
    },
    Error {
        errors: Vec<String>,
    },
}

#[wasm_bindgen(js_name = "policyTextFromJson")]
pub fn policy_text_from_json(json_str: &str) -> JsonToPolicyResult {
    let parsed_json = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            return JsonToPolicyResult::Error {
                errors: vec![e.to_string()],
            }
        }
    };
    let policy = Policy::from_json(None, parsed_json);
    match policy {
        Ok(p) => JsonToPolicyResult::Success {
            policy_text: p.to_string(),
        },
        Err(e) => JsonToPolicyResult::Error {
            errors: vec![e.to_string()],
        },
    }
}

#[derive(Tsify, Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum PolicyToJsonResult {
    Success {
        policy: cedar_policy_core::est::Policy,
    },
    Error {
        errors: Vec<String>,
    },
}

#[wasm_bindgen(js_name = "policyTextToJson")]
pub fn policy_text_to_json(cedar_str: &str) -> PolicyToJsonResult {
    match parse_policy_or_template_to_est(cedar_str) {
        Ok(policy) => PolicyToJsonResult::Success { policy },
        Err(err) => PolicyToJsonResult::Error {
            errors: err.iter().map(ToString::to_string).collect(),
        },
    }
}

#[derive(Tsify, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[tsify(into_wasm_abi, from_wasm_abi)]
/// struct that defines the result for the syntax validation function
pub enum CheckParsePolicySetResult {
    /// represents successful syntax validation
    Success { policies: i32, templates: i32 },
    /// represents a syntax error and encloses a vector of the errors
    Error { errors: Vec<String> },
}

#[cfg(test)]
mod test {

    use super::*;
    use cool_asserts::assert_matches;

    #[test]
    fn test_conversion_from_cedar() {
        let cedar_repr = r#"permit(principal, action, resource) when { principal has "Email" && principal.Email == "a@a.com" };"#;
        let json_conversion_result = policy_text_to_json(cedar_repr);
        assert_matches!(json_conversion_result, PolicyToJsonResult::Success { .. });
    }

    #[test]
    fn test_conversion_from_json() {
        let est_repr = r#"{
            "effect": "permit",
            "action": {
                "entity": {
                    "id": "pop",
                    "type": "Action"
                },
                "op": "=="
            },
            "principal": {
                "entity": {
                    "id": "DeathRowRecords",
                    "type": "UserGroup"
                },
                "op": "in"
            },
            "resource": {
                "op": "All"
            },
            "conditions": []
        }"#;

        let cedar_conversion_result: JsonToPolicyResult = policy_text_from_json(est_repr);
        assert_matches!(cedar_conversion_result, JsonToPolicyResult::Success { policy_text } => {
            assert_eq!(
                &policy_text,
                "permit(principal in UserGroup::\"DeathRowRecords\", action == Action::\"pop\", resource);"
            );
        });
    }
}
