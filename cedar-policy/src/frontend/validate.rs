/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

//! This module exposes a JSON-based validate function used by other language FFI's
//!
#![allow(clippy::module_name_repetitions)]
use super::utils::{InterfaceResult, PolicySpecification};
use crate::{PolicySet, Schema, ValidationMode, Validator};
use cedar_policy_core::jsonvalue::JsonValueWithNoDuplicateKeys;
use serde::{Deserialize, Serialize};

#[cfg(feature = "wasm")]
extern crate tsify;

/// Parse a policy set and optionally validate it against a provided schema
fn validate(call: ValidationCall) -> ValidationAnswer {
    match call.get_components() {
        Ok((policies, schema)) => {
            let validator = Validator::new(schema);
            let validation_result = validator.validate(&policies, ValidationMode::default());
            let validation_errors: Vec<ValidationError> = validation_result
                .validation_errors()
                .map(|error| ValidationError {
                    policy_id: error.location().policy_id().to_string(),
                    error: format!("{}", error.error_kind()),
                })
                .collect();
            let validation_warnings: Vec<ValidationWarning> = validation_result
                .validation_warnings()
                .map(|error| ValidationWarning {
                    policy_id: error.location().policy_id().to_string(),
                    warning: format!("{}", error.warning_kind()),
                })
                .collect();
            ValidationAnswer::Success {
                validation_errors,
                validation_warnings,
            }
        }
        Err(errors) => ValidationAnswer::Failure { errors },
    }
}

/// public string-based validation function
pub fn json_validate(input: &str) -> InterfaceResult {
    serde_json::from_str::<ValidationCall>(input).map_or_else(
        |e| InterfaceResult::fail_internally(format!("error parsing call: {e:}")),
        |call| match validate(call) {
            answer @ ValidationAnswer::Success { .. } => InterfaceResult::succeed(answer),
            ValidationAnswer::Failure { errors } => InterfaceResult::fail_bad_request(errors),
        },
    )
}

/// Struct containing the input data for validation
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
struct ValidationCall {
    #[serde(default)]
    #[serde(rename = "validationSettings")]
    validation_settings: ValidationSettings,
    /// Schema in JSON format
    schema: JsonValueWithNoDuplicateKeys,
    #[serde(rename = "policySet")]
    policy_set: PolicySpecification,
}

fn parse_schema(schema_json: JsonValueWithNoDuplicateKeys) -> Result<Schema, Vec<String>> {
    Schema::from_json_value(schema_json.into()).map_err(|e| vec![e.to_string()])
}

impl ValidationCall {
    fn get_components(self) -> Result<(PolicySet, Schema), Vec<String>> {
        let policies = self.policy_set.try_into(None)?;
        let schema = parse_schema(self.schema)?;
        Ok((policies, schema))
    }
}

/// Configuration for the validation call
#[derive(Default, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
struct ValidationSettings {
    enabled: ValidationEnabled,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
enum ValidationEnabled {
    #[serde(rename = "on")]
    #[serde(alias = "regular")]
    On,
    #[serde(rename = "off")]
    Off,
}

impl Default for ValidationEnabled {
    fn default() -> Self {
        Self::On
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidationError {
    #[serde(rename = "policyId")]
    policy_id: String,
    error: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidationWarning {
    #[serde(rename = "policyId")]
    policy_id: String,
    warning: String,
}

/// Result struct for validation
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum ValidationAnswer {
    /// Represents a failure to parse or call the validator
    Failure { errors: Vec<String> },
    /// Represents a successful validation call
    Success {
        validation_errors: Vec<ValidationError>,
        validation_warnings: Vec<ValidationWarning>,
    },
}

// PANIC SAFETY unit tests
#[allow(clippy::panic)]
#[cfg(test)]
mod test {
    use super::*;
    use cool_asserts::assert_matches;
    use std::{collections::HashMap, str::FromStr};

    #[test]
    fn test_validate_empty_policy_directly() {
        let schema =
            JsonValueWithNoDuplicateKeys::from_str("{}").expect("empty schema should be valid");

        let call = ValidationCall {
            validation_settings: ValidationSettings::default(),
            schema,
            policy_set: PolicySpecification::Map(HashMap::new()),
        };

        let call_json: String = serde_json::to_string(&call).expect("could not serialise call");

        let result = json_validate(&call_json);
        assert_validates_without_errors(result);
    }

    #[test]
    fn test_empty_policy_validates_without_errors() {
        let call_json = r#"{
            "schema": {},
            "policySet": {}
        }"#
        .to_string();

        let result = json_validate(&call_json);
        assert_validates_without_errors(result);
    }

    #[test]
    fn test_nontrivial_correct_policy_validates_without_errors() {
        let call_json = r#"{
  "schema": { "": {
    "entityTypes": {
      "User": {
        "memberOfTypes": [ "UserGroup" ]
      },
      "Photo": {
        "memberOfTypes": [ "Album", "Account" ]
      },
      "Album": {
        "memberOfTypes": [ "Album", "Account" ]
      },
      "Account": { },
      "UserGroup": {}
    },
    "actions": {
      "readOnly": { },
      "readWrite": { },
      "createAlbum": {
        "appliesTo": {
          "resourceTypes": [ "Account", "Album" ],
          "principalTypes": [ "User" ]
        }
      },
      "addPhotoToAlbum": {
        "appliesTo": {
          "resourceTypes": [ "Album" ],
          "principalTypes": [ "User" ]
        }
      },
      "viewPhoto": {
        "appliesTo": {
          "resourceTypes": [ "Photo" ],
          "principalTypes": [ "User" ]
        }
      },
      "viewComments": {
        "appliesTo": {
          "resourceTypes": [ "Photo" ],
          "principalTypes": [ "User" ]
        }
      }
    }
  }},
  "policySet": {
    "policy0": "permit(principal in UserGroup::\"alice_friends\", action == Action::\"viewPhoto\", resource);"
  }
}
"#.to_string();

        let result = json_validate(&call_json);
        assert_validates_without_errors(result);
    }

    #[test]
    fn test_policy_with_parse_error_fails_passing_on_errors() {
        let call_json = r#"{
            "schema": {"": {
                "entityTypes": {},
                "actions": {}
            }},
            "policySet": {
                "policy0": "azfghbjknnhbud"
            }
        }"#
        .to_string();

        let result = json_validate(&call_json);
        assert_is_failure(&result, false, "unexpected end of input");
    }

    #[test]
    fn test_semantically_incorrect_policy_fails_with_errors() {
        let call_json = r#"{
  "schema":{"": {
    "entityTypes": {
      "User": {
        "memberOfTypes": [ ]
      },
      "Photo": {
        "memberOfTypes": [ ]
      }
    },
    "actions": {
      "viewPhoto": {
        "appliesTo": {
          "resourceTypes": [ "Photo" ],
          "principalTypes": [ "User" ]
        }
      }
    }
  }},
  "policySet": {
    "policy0": "permit(principal == Photo::\"photo.jpg\", action == Action::\"viewPhoto\", resource == User::\"alice\");",
    "policy1": "permit(principal == Photo::\"photo2.jpg\", action == Action::\"viewPhoto\", resource == User::\"alice2\");"
  }
}
"#.to_string();

        let result = json_validate(&call_json);
        assert_validates_with_errors(result, 2);
    }

    #[test]
    fn test_nontrivial_correct_policy_validates_without_errors_concatenated_policies() {
        let call_json = r#"{
  "schema": { "": {
    "entityTypes": {
      "User": {
        "memberOfTypes": [ "UserGroup" ]
      },
      "Photo": {
        "memberOfTypes": [ "Album", "Account" ]
      },
      "Album": {
        "memberOfTypes": [ "Album", "Account" ]
      },
      "Account": { },
      "UserGroup": {}
    },
    "actions": {
      "readOnly": {},
      "readWrite": {},
      "createAlbum": {
        "appliesTo": {
          "resourceTypes": [ "Account", "Album" ],
          "principalTypes": [ "User" ]
        }
      },
      "addPhotoToAlbum": {
        "appliesTo": {
          "resourceTypes": [ "Album" ],
          "principalTypes": [ "User" ]
        }
      },
      "viewPhoto": {
        "appliesTo": {
          "resourceTypes": [ "Photo" ],
          "principalTypes": [ "User" ]
        }
      },
      "viewComments": {
        "appliesTo": {
          "resourceTypes": [ "Photo" ],
          "principalTypes": [ "User" ]
        }
      }
    }
  }},
  "policySet": {
    "policy0": "permit(principal in UserGroup::\"alice_friends\", action == Action::\"viewPhoto\", resource);"
  }
}
"#.to_string();

        let result = json_validate(&call_json);
        assert_validates_without_errors(result);
    }

    #[test]
    fn test_policy_with_parse_error_fails_passing_on_errors_concatenated_policies() {
        let call_json = r#"{
            "schema": {"": {
                "entityTypes": {},
                "actions": {}
            }},
            "policySet": "azfghbjknnhbud"
        }"#
        .to_string();

        let result = json_validate(&call_json);
        assert_is_failure(&result, false, "unexpected end of input");
    }

    #[test]
    fn test_semantically_incorrect_policy_fails_with_errors_concatenated_policies() {
        let call_json = r#"{
  "schema": {"": {
    "entityTypes": {
      "User": {
        "memberOfTypes": [ ]
      },
      "Photo": {
        "memberOfTypes": [ ]
      }
    },
    "actions": {
      "viewPhoto": {
        "appliesTo": {
          "resourceTypes": [ "Photo" ],
          "principalTypes": [ "User" ]
        }
      }
    }
  }},
  "policySet": "forbid(principal, action, resource);permit(principal == Photo::\"photo.jpg\", action == Action::\"viewPhoto\", resource == User::\"alice\");"
}
"#.to_string();

        let result = json_validate(&call_json);
        assert_validates_with_errors(result, 1);
    }

    #[test]
    fn test_policy_with_parse_error_fails_concatenated_policies() {
        let call_json = r#"{
            "schema": {"": {
                "entityTypes": {},
                "actions": {}
            }},
            "policySet": "permit(principal, action, resource);forbid"
        }"#
        .to_string();
        let result = json_validate(&call_json);
        assert_is_failure(&result, false, "unexpected end of input");
    }

    #[test]
    fn test_bad_call_format_fails() {
        let result = json_validate("uerfheriufheiurfghtrg");
        assert_is_failure(&result, true, "error parsing call: expected value");
    }

    #[test]
    fn test_validate_fails_on_duplicate_namespace() {
        let call_json = r#"{
            "schema": {
              "foo": { "entityTypes": {}, "actions": {} },
              "foo": { "entityTypes": {}, "actions": {} }
            },
            "policySet": ""
        }"#
        .to_string();
        let result = json_validate(&call_json);
        assert_is_failure(
            &result,
            true,
            "error parsing call: the key `foo` occurs two or more times in the same JSON object",
        );
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_validates_without_errors(result: InterfaceResult) {
        assert_matches!(result, InterfaceResult::Success { result } => {
            let parsed_result: ValidationAnswer = serde_json::from_str(result.as_str()).unwrap();
            assert_matches!(parsed_result, ValidationAnswer::Success { validation_errors, validation_warnings: _ } => {
                assert_eq!(validation_errors.len(), 0, "Unexpected validation errors: {validation_errors:?}");
            });
        });
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_validates_with_errors(result: InterfaceResult, expected_num_errors: usize) {
        assert_matches!(result, InterfaceResult::Success { result } => {
            let parsed_result: ValidationAnswer = serde_json::from_str(result.as_str()).unwrap();
            assert_matches!(parsed_result, ValidationAnswer::Success { validation_errors, validation_warnings: _ } => {
                assert_eq!(validation_errors.len(), expected_num_errors);
            });
        });
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_is_failure(result: &InterfaceResult, internal: bool, err: &str) {
        assert_matches!(result, InterfaceResult::Failure { errors, is_internal } => {
            assert!(
                errors.iter().any(|e| e.contains(err)),
                "Expected to see error(s) containing `{err}`, but saw {errors:?}");
            assert_eq!(internal, *is_internal);
        });
    }

    #[test]
    fn test_validate_fails_on_duplicate_policy_id() {
        let call_json = r#"{
            "schema": { "": { "entityTypes": {}, "actions": {} } },
            "policySet": {
              "ID0": "permit(principal, action, resource);",
              "ID0": "permit(principal, action, resource);"
            }
        }"#
        .to_string();
        let result = json_validate(&call_json);
        assert_is_failure(&result, true, "error parsing call: policies as a concatenated string or multiple policies as a hashmap where the policy id is the key");
    }
}
