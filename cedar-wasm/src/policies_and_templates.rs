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

use std::str::FromStr;

use cedar_policy::{Policy, PolicySet, Template};
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
            errors: err.errors_as_strings(),
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

#[wasm_bindgen(js_name = "checkParsePolicySet")]
pub fn check_parse_policy_set(input_policies_str: &str) -> CheckParsePolicySetResult {
    match PolicySet::from_str(input_policies_str) {
        Err(parse_errors) => CheckParsePolicySetResult::Error {
            errors: parse_errors.errors_as_strings(),
        },
        Ok(policy_set) => {
            let policies_count: Result<i32, <i32 as TryFrom<usize>>::Error> =
                policy_set.policies().count().try_into();
            let templates_count: Result<i32, <i32 as TryFrom<usize>>::Error> =
                policy_set.templates().count().try_into();
            match (policies_count, templates_count) {
                (Ok(p), Ok(t)) => CheckParsePolicySetResult::Success {
                    policies: p,
                    templates: t,
                },
                _ => CheckParsePolicySetResult::Error {
                    errors: vec!["Error counting policies or templates".to_string()],
                },
            }
        }
    }
}

#[derive(Tsify, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum CheckParseTemplateResult {
    /// represents successful template validation
    Success { slots: Vec<String> },
    /// represents errors in the template validation and encloses a vector of the errors
    Error { errors: Vec<String> },
}

#[wasm_bindgen(js_name = "checkParseTemplate")]
pub fn check_parse_template(template_str: &str) -> CheckParseTemplateResult {
    match Template::from_str(template_str) {
        Err(parse_errs) => CheckParseTemplateResult::Error {
            errors: parse_errs.errors_as_strings(),
        },
        Ok(template) => match template.slots().count() {
            1 | 2 => CheckParseTemplateResult::Success {
                slots: template.slots().map(|slot| slot.to_string()).collect(),
            },
            _ => CheckParseTemplateResult::Error {
                errors: vec!["Expected template to have one or two slots".to_string()],
            },
        },
    }
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

    #[test]
    fn can_parse_1_policy() {
        let stringified_result = check_parse_policy_set("permit(principal, action, resource);");
        assert_result_is_ok(&stringified_result);
    }

    #[test]
    fn can_parse_multi_policy() {
        assert_result_is_ok(&check_parse_policy_set(
            "forbid(principal, action, resource); permit(principal == User::\"alice\", action == Action::\"view\", resource in Albums::\"alice_albums\");"
        ));
    }

    #[test]
    fn parse_returns_parse_errors_when_expected_1_policy() {
        assert_result_had_syntax_errors(&check_parse_policy_set("permit(2pac, action, resource)"));
    }

    #[test]
    fn parse_returns_parse_errors_when_expected_multi_policy() {
        assert_result_had_syntax_errors(&check_parse_policy_set(
            "forbid(principal, action, resource);permit(2pac, action, resource)",
        ));
    }

    fn assert_result_is_ok(result: &CheckParsePolicySetResult) {
        assert_matches!(result, CheckParsePolicySetResult::Success { .. });
    }

    fn assert_result_had_syntax_errors(result: &CheckParsePolicySetResult) {
        assert_matches!(result, CheckParsePolicySetResult::Error { .. });
    }

    #[test]
    fn can_parse_template() {
        let template_str = r#"permit (principal == ?principal, action, resource == ?resource);"#;
        let result = check_parse_template(template_str);
        assert_matches!(result, CheckParseTemplateResult::Success { slots } => {
            assert_eq!(slots.len(), 2);
        });
    }

    #[test]
    fn parse_template_fails_for_missing_slots() {
        let template_str = r#"permit (principal, action, resource);"#;
        let result = check_parse_template(template_str);
        assert_matches!(result, CheckParseTemplateResult::Error { .. });
    }

    #[test]
    fn parse_template_fails_for_bad_slot() {
        let template_str = r#"permit (principal, action, resource == ?principal);"#;
        let result = check_parse_template(template_str);
        assert_matches!(result, CheckParseTemplateResult::Error { .. });
    }
}
