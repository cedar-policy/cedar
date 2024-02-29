use std::str::FromStr;

use cedar_policy::{Policy, PolicySet};
use cedar_policy_core::parser::parse_policy_or_template_to_est;
use serde::{Deserialize, Serialize};

use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum JsonToPolicyResult {
    Success { policy_text: String },
    Error { errors: Vec<String> },
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
#[serde(untagged)]
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
#[tsify(into_wasm_abi, from_wasm_abi)]
/// struct that defines the result for the syntax validation function
pub enum CheckParsePolicySetResult {
    /// represents successful syntax validation
    Success { policies: i32, templates: i32 },
    /// represents a syntax error and encloses a vector of the errors
    SyntaxError { errors: Vec<String> },
}

#[wasm_bindgen(js_name = "checkParsePolicySet")]
pub fn check_parse_policy_set(input_policies_str: &str) -> CheckParsePolicySetResult {
    match PolicySet::from_str(input_policies_str) {
        Err(parse_errors) => CheckParsePolicySetResult::SyntaxError {
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
                _ => CheckParsePolicySetResult::SyntaxError {
                    errors: vec!["Error counting policies or templates".to_string()],
                },
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct Template {
    text: String,
    slots: Vec<String>,
    parse_errors: Option<Vec<String>>,
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_conversion_from_cedar() {
        let cedar_repr = r#"permit(principal, action, resource) when { principal has "Email" && principal.Email == "a@a.com" };"#;
        let json_conversion_result = policy_text_to_json(cedar_repr);
        assert!(matches!(
            json_conversion_result,
            PolicyToJsonResult::Success { policy: _ }
        ))
    }

    #[test]
    fn test_convertion_from_json() {
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

        let cedar_convertion_result: JsonToPolicyResult = policy_text_from_json(&est_repr);
        match cedar_convertion_result {
            JsonToPolicyResult::Success { policy_text } => assert_eq!(
                &policy_text,
                "permit(principal in UserGroup::\"DeathRowRecords\", action == Action::\"pop\", resource);"
            ),
            JsonToPolicyResult::Error { errors } => {
                dbg!(errors);
                panic!("Test failed")
            }
        }
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
        assert!(matches!(
            result,
            CheckParsePolicySetResult::Success {
                policies: _,
                templates: _,
            }
        ));
    }

    fn assert_result_had_syntax_errors(result: &CheckParsePolicySetResult) {
        assert!(matches!(
            result,
            CheckParsePolicySetResult::SyntaxError { errors: _ }
        ));
    }
}
