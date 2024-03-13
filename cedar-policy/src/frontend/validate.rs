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
use cedar_policy_core::{
    ast::PolicySet,
    parser::{parse_policy, parse_policyset},
};
use cedar_policy_validator::Validator;
use serde::{Deserialize, Serialize};

#[cfg(feature = "wasm")]
extern crate tsify;

fn validate(call: &ValidateCall) -> Result<ValidateAnswer, String> {
    let mut policy_set = PolicySet::new();
    let mut parse_errors: Vec<String> = vec![];

    match &call.policy_set {
        PolicySpecification::Concatenated(policies_str) => match parse_policyset(policies_str) {
            Ok(parsed_policy_set) => {
                policy_set = parsed_policy_set;
            }
            Err(policy_set_parse_errs) => {
                parse_errors.extend(
                    policy_set_parse_errs
                        .into_iter()
                        .map(|pe| format!("parse error in policy: {pe}")),
                );
            }
        },
        PolicySpecification::Map(policy_set_input) => {
            for (id, policy_text) in policy_set_input {
                match parse_policy(Some(id.clone()), policy_text.as_str()) {
                    Ok(policy) => {
                        policy_set.add_static(policy).ok();
                    }
                    Err(errors) => {
                        for error in errors {
                            parse_errors.push(format!("parse error in policy {id:}: {error:}"));
                        }
                    }
                };
            }
        }
    }

    if !parse_errors.is_empty() {
        return Ok(ValidateAnswer::ParseFailed {
            errors: parse_errors,
        });
    }

    let schema = call
        .schema
        .clone()
        .try_into()
        .map_err(|e| format!("could not construct schema: {e}"))?;
    let validator = Validator::new(schema);

    let notes: Vec<ValidationNote> = validator
        .validate(
            &policy_set,
            cedar_policy_validator::ValidationMode::default(),
        )
        .validation_errors()
        .map(|error| ValidationNote {
            policy_id: error.location().policy_id().to_string(),
            note: format!("{}", error.error_kind()),
        })
        .collect();

    Ok(ValidateAnswer::Success { notes })
}

/// public string-based validation function
pub fn json_validate(input: &str) -> InterfaceResult {
    serde_json::from_str::<ValidateCall>(input).map_or_else(
        |e| InterfaceResult::fail_internally(format!("error parsing call: {e:}")),
        |call| match validate(&call) {
            Ok(answer @ ValidateAnswer::Success { .. }) => InterfaceResult::succeed(answer),
            Ok(ValidateAnswer::ParseFailed { errors }) => InterfaceResult::fail_bad_request(errors),
            Err(e) => InterfaceResult::fail_internally(e),
        },
    )
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
struct ValidateCall {
    #[serde(default)]
    #[serde(rename = "validationSettings")]
    validation_settings: ValidationSettings,
    schema: cedar_policy_validator::SchemaFragment,
    #[serde(rename = "policySet")]
    policy_set: PolicySpecification,
}

#[derive(Default, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
struct ValidationSettings {
    mode: ValidationMode,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
enum ValidationMode {
    #[serde(rename = "regular")]
    Regular,
    #[serde(rename = "off")]
    Off,
}

impl Default for ValidationMode {
    fn default() -> Self {
        Self::Regular
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidationNote {
    #[serde(rename = "policyId")]
    policy_id: String,
    note: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum ValidateAnswer {
    ParseFailed { errors: Vec<String> },
    Success { notes: Vec<ValidationNote> },
}

// PANIC SAFETY unit tests
#[allow(clippy::panic)]
#[cfg(test)]
mod test {
    use super::*;
    use crate::frontend::utils::assert_is_failure;
    use cool_asserts::assert_matches;
    use std::collections::HashMap;

    #[test]
    fn test_validate_empty_policy_directly() {
        let schema = cedar_policy_validator::SchemaFragment(HashMap::new());

        let call = ValidateCall {
            validation_settings: ValidationSettings::default(),
            schema,
            policy_set: PolicySpecification::Map(HashMap::new()),
        };

        let call_json: String = serde_json::to_string(&call).expect("could not serialise call");

        let result = json_validate(&call_json);
        assert_validates_without_notes(result);
    }

    #[test]
    fn test_empty_policy_validates_without_notes() {
        let call_json = r#"{
            "schema": {},
            "policySet": {}
        }"#
        .to_string();

        let result = json_validate(&call_json);
        assert_validates_without_notes(result);
    }

    #[test]
    fn test_nontrivial_correct_policy_validates_without_notes() {
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
        assert_validates_without_notes(result);
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
        assert_is_failure(
            &result,
            false,
            "parse error in policy policy0: unexpected end of input",
        );
    }

    #[test]
    fn test_semantically_incorrect_policy_fails_with_notes() {
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
        assert_validates_with_notes(result, 4);
    }

    #[test]
    fn test_nontrivial_correct_policy_validates_without_notes_concatenated_policies() {
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
        assert_validates_without_notes(result);
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
        assert_is_failure(
            &result,
            false,
            "parse error in policy: unexpected end of input",
        );
    }

    #[test]
    fn test_semantically_incorrect_policy_fails_with_notes_concatenated_policies() {
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
        assert_validates_with_notes(result, 2);
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
        assert_is_failure(
            &result,
            false,
            "parse error in policy: unexpected end of input",
        );
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
            "error parsing call: invalid entry: found duplicate key",
        );
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_validates_without_notes(result: InterfaceResult) {
        assert_matches!(result, InterfaceResult::Success { result } => {
            let parsed_result: ValidateAnswer = serde_json::from_str(result.as_str()).unwrap();
            assert_matches!(parsed_result, ValidateAnswer::Success { notes, .. } => {
                assert_eq!(notes.len(), 0, "Unexpected validation notes: {notes:?}");
            });
        });
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_validates_with_notes(result: InterfaceResult, expected_num_notes: usize) {
        assert_matches!(result, InterfaceResult::Success { result } => {
            let parsed_result: ValidateAnswer = serde_json::from_str(result.as_str()).unwrap();
            assert_matches!(parsed_result, ValidateAnswer::Success { notes, .. } => {
                assert_eq!(notes.len(), expected_num_notes);
            });
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
        assert_is_failure(&result, true, "no duplicate IDs");
    }
}
