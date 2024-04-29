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

use cedar_policy::{Context, Entities, EntityUid, Schema};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[tsify(into_wasm_abi, from_wasm_abi)]
/// struct that defines the result for the syntax validation function
pub enum CheckParseResult {
    /// represents successful syntax validation
    Success,
    /// represents a syntax error and encloses a vector of the errors
    Error { errors: Vec<String> },
}

#[wasm_bindgen(js_name = "checkParseSchema")]
pub fn check_parse_schema(input_schema: &str) -> CheckParseResult {
    match Schema::from_str(input_schema) {
        Ok(_schema) => CheckParseResult::Success,
        Err(err) => CheckParseResult::Error {
            errors: vec![err.to_string()],
        },
    }
}

#[wasm_bindgen(js_name = "checkParseEntities")]
pub fn check_parse_entities(entities_str: &str, schema_str: &str) -> CheckParseResult {
    let parsed_schema = match Schema::from_str(schema_str) {
        Ok(schema) => schema,
        Err(err) => {
            return CheckParseResult::Error {
                errors: vec![err.to_string()],
            }
        }
    };
    match Entities::from_json_str(entities_str, Some(&parsed_schema)) {
        Ok(_) => CheckParseResult::Success,
        Err(err) => CheckParseResult::Error {
            errors: vec![err.to_string()],
        },
    }
}

#[wasm_bindgen(js_name = "checkParseContext")]
pub fn check_parse_context(
    context_str: &str,
    action_str: &str,
    schema_str: &str,
) -> CheckParseResult {
    let parsed_schema = match Schema::from_str(schema_str) {
        Ok(schema) => schema,
        Err(err) => {
            return CheckParseResult::Error {
                errors: vec![err.to_string()],
            }
        }
    };
    let parsed_action = match EntityUid::from_str(action_str) {
        Ok(action) => action,
        Err(err) => {
            return CheckParseResult::Error {
                errors: vec![err.to_string()],
            }
        }
    };
    match Context::from_json_str(context_str, Some((&parsed_schema, &parsed_action))) {
        Ok(_entities) => CheckParseResult::Success,
        Err(err) => CheckParseResult::Error {
            errors: vec![err.to_string()],
        },
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Schema validator
    #[test]
    fn validate_schema_syntax_succeeds_empty_schema() {
        let schema_str = "{}";
        assert_syntax_result_is_ok(&check_parse_schema(schema_str))
    }
    #[test]
    fn validate_schema_syntax_succeeds_nonempty_schema() {
        let schema_str = r#"{
          "MyNamespace": {
            "entityTypes": {},
            "actions": {}
          }
        }"#;
        assert_syntax_result_is_ok(&check_parse_schema(schema_str))
    }

    #[test]
    fn validate_schema_bad_syntax_fails() {
        let schema_str = r#"{
            "MyNamespace": {
              "entityTypes": {}
            }
          }"#;
        assert_syntax_result_has_errors(&check_parse_schema(schema_str))
    }

    // Entities

    #[test]
    fn validate_entities_succeeds() {
        let entities_str = r#"[
            {
                "uid": {
                    "type": "TheNamespace::User",
                    "id": "alice"
                },
                "attrs": {
                    "department": "HardwareEngineering",
                    "jobLevel": 5
                },
                "parents": []
              }
        ]"#;
        let schema_str = r#"{
            "TheNamespace": {
                "entityTypes": {
                    "User": {
                        "memberOfTypes": [],
                        "shape": {
                            "attributes": {
                                "department": {
                                    "type": "String"
                                },
                                "jobLevel": {
                                    "type": "Long"
                                }
                            },
                            "type": "Record"
                        }
                    }
                },
                "actions": {}
            }
        }"#;
        assert_syntax_result_is_ok(&check_parse_entities(entities_str, schema_str));
    }

    #[test]
    fn validate_entities_fails_on_bad_entity() {
        let entities_str = r#"[
            {
                "uid": "TheNamespace::User::\"alice\"",
                "attrs": {
                    "benchPress": "doesn'tevenlift"
                },
                "parents": []
              }
        ]"#;
        let schema_str = r#"{
            "TheNamespace": {
                "entityTypes": {
                    "User": {
                        "memberOfTypes": [],
                        "shape": {
                            "attributes": {
                                "department": {
                                    "type": "String"
                                }
                            },
                            "type": "Record"
                        }
                    }
                },
                "actions": {}
            }
        }"#;
        assert_syntax_result_has_errors(&check_parse_entities(entities_str, schema_str));
    }

    #[test]
    fn validate_context_succeeds() {
        let context_str = r#"{
            "referrer": "Morpheus"
        }"#;
        let action_str = r#"Ex::Action::"Join""#;
        let schema_str = r#"{
            "Ex": {
                "entityTypes": {},
                "actions": {
                    "Join": {
                        "appliesTo": {
                            "context": {
                                "type": "Record",
                                "attributes": {
                                    "referrer": {
                                        "type": "String",
                                        "required": true
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        assert_syntax_result_is_ok(&check_parse_context(context_str, action_str, schema_str));
    }

    #[test]
    fn validate_context_fails_for_bad_context() {
        let context_str = r#"{
            "wrongAttr": true
        }"#;
        let action_str = r#"Ex::Action::"Join""#;
        let schema_str = r#"{
            "Ex": {
                "entityTypes": {},
                "actions": {
                    "Join": {
                        "appliesTo": {
                            "context": {
                                "type": "Record",
                                "attributes": {
                                    "referrer": {
                                        "type": "String",
                                        "required": true
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        assert_syntax_result_has_errors(&check_parse_context(context_str, action_str, schema_str));
    }

    fn assert_syntax_result_is_ok(parse_result: &CheckParseResult) {
        assert!(matches!(parse_result, CheckParseResult::Success))
    }

    fn assert_syntax_result_has_errors(parse_result: &CheckParseResult) {
        assert!(matches!(
            parse_result,
            CheckParseResult::Error { errors: _ }
        ))
    }
}
