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

//! This module contains the validator entry points that other language FFIs can
//! call
#![allow(clippy::module_name_repetitions)]
use super::utils::{DetailedError, PolicySet, Schema, WithWarnings};
use crate::{ValidationMode, Validator};
use serde::{Deserialize, Serialize};
use smol_str::{SmolStr, ToSmolStr};

#[cfg(feature = "wasm")]
extern crate tsify;

/// Parse a policy set and optionally validate it against a provided schema
///
/// This is the basic validator interface, using [`ValidationCall`] and
/// [`ValidationAnswer`] types
pub fn validate(call: ValidationCall) -> ValidationAnswer {
    match call.get_components() {
        WithWarnings {
            t: Ok((policies, schema)),
            warnings,
        } => {
            let validator = Validator::new(schema);
            let (validation_errors, validation_warnings) = validator
                .validate(&policies, ValidationMode::default())
                .into_errors_and_warnings();
            let validation_errors: Vec<ValidationError> = validation_errors
                .map(|error| ValidationError {
                    policy_id: error.location().policy_id().to_smolstr(),
                    error: miette::Report::new(error).into(),
                })
                .collect();
            let validation_warnings: Vec<ValidationError> = validation_warnings
                .map(|error| ValidationError {
                    policy_id: error.location().policy_id().to_smolstr(),
                    error: miette::Report::new(error).into(),
                })
                .collect();
            ValidationAnswer::Success {
                validation_errors,
                validation_warnings,
                other_warnings: warnings.into_iter().map(Into::into).collect(),
            }
        }
        WithWarnings {
            t: Err(errors),
            warnings,
        } => ValidationAnswer::Failure {
            errors: errors.into_iter().map(Into::into).collect(),
            warnings: warnings.into_iter().map(Into::into).collect(),
        },
    }
}

/// Input is a JSON encoding of [`ValidationCall`] and output is a JSON
/// encoding of [`ValidationAnswer`]
pub fn validate_json(json: serde_json::Value) -> Result<serde_json::Value, serde_json::Error> {
    let ans = validate(serde_json::from_value(json)?);
    serde_json::to_value(ans)
}

/// Input and output are strings containing serialized JSON, in the shapes
/// expected by [`validate_json()`]
pub fn validate_json_str(json: &str) -> Result<String, serde_json::Error> {
    let ans = validate(serde_json::from_str(json)?);
    serde_json::to_string(&ans)
}

/// Struct containing the input data for validation
#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct ValidationCall {
    /// Validation settings
    #[serde(default)]
    pub validation_settings: ValidationSettings,
    /// Schema to use for validation
    #[cfg_attr(feature = "wasm", tsify(type = "Schema"))]
    pub schema: Schema,
    /// Policies to validate
    pub policy_set: PolicySet,
}

impl ValidationCall {
    fn get_components(
        self,
    ) -> WithWarnings<Result<(crate::PolicySet, crate::Schema), Vec<miette::Report>>> {
        let mut errs = vec![];
        let policies = match self.policy_set.parse(None) {
            Ok(policies) => policies,
            Err(e) => {
                errs.extend(e);
                crate::PolicySet::new()
            }
        };
        let pair = match self.schema.parse() {
            Ok((schema, warnings)) => Some((schema, warnings)),
            Err(e) => {
                errs.push(e);
                None
            }
        };
        match (errs.is_empty(), pair) {
            (true, Some((schema, warnings))) => WithWarnings {
                t: Ok((policies, schema)),
                warnings: warnings.map(miette::Report::new).collect(),
            },
            _ => WithWarnings {
                t: Err(errs),
                warnings: vec![],
            },
        }
    }
}

/// Configuration for the validation call
#[derive(Default, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct ValidationSettings {
    /// Whether validation is enabled
    enabled: ValidationEnabled,
}

/// String enum for validation mode
#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub enum ValidationEnabled {
    /// Setting for which policies will be validated against the schema
    #[serde(alias = "regular")]
    On,
    /// Setting for which no validation will be done
    Off,
}

impl Default for ValidationEnabled {
    fn default() -> Self {
        Self::On
    }
}

/// Error (or warning) for a specified policy after validation
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct ValidationError {
    /// Id of the policy where the error (or warning) occurred
    pub policy_id: SmolStr,
    /// Error (or warning) itself.
    /// You can look at the `severity` field to see whether it is actually an
    /// error or a warning.
    pub error: DetailedError,
}

/// Result struct for validation
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum ValidationAnswer {
    /// Represents a failure to parse or call the validator
    #[serde(rename_all = "camelCase")]
    Failure {
        /// Parsing errors
        errors: Vec<DetailedError>,
        /// Warnings encountered
        warnings: Vec<DetailedError>,
    },
    /// Represents a successful validation call
    #[serde(rename_all = "camelCase")]
    Success {
        /// Errors from any issues found during validation
        validation_errors: Vec<ValidationError>,
        /// Warnings from any issues found during validation
        validation_warnings: Vec<ValidationError>,
        /// Other warnings, not associated with specific policies.
        /// For instance, warnings about your schema itself.
        other_warnings: Vec<DetailedError>,
    },
}

// PANIC SAFETY unit tests
#[allow(clippy::panic)]
#[cfg(test)]
mod test {
    use super::*;
    use cool_asserts::assert_matches;
    use serde_json::json;
    use std::collections::HashMap;

    /// Assert that [`validate_json()`] returns Success with no errors
    #[track_caller]
    fn assert_validates_without_errors(json: serde_json::Value) {
        let ans_val = validate_json(json).unwrap();
        let result: Result<ValidationAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(ValidationAnswer::Success { validation_errors, validation_warnings: _, other_warnings: _ }) => {
            assert_eq!(validation_errors.len(), 0, "Unexpected validation errors: {validation_errors:?}");
        });
    }

    /// Assert that [`validate_json()`] returns Success with exactly
    /// `expected_num_errors` errors
    #[track_caller]
    fn assert_validates_with_errors(json: serde_json::Value, expected_num_errors: usize) {
        let ans_val = validate_json(json).unwrap();
        assert_matches!(ans_val.get("validationErrors"), Some(_)); // should be present, with this camelCased name
        assert_matches!(ans_val.get("validationWarnings"), Some(_)); // should be present, with this camelCased name
        let result: Result<ValidationAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(ValidationAnswer::Success { validation_errors, validation_warnings: _, other_warnings: _ }) => {
            assert_eq!(validation_errors.len(), expected_num_errors, "actual validation errors were: {validation_errors:?}");
        });
    }

    /// Assert that [`validate_json()`] returns `ValidationAnswer::Failure`
    /// where some error contains the expected error string `err` (in its main
    /// error message)
    #[track_caller]
    fn assert_is_failure(json: serde_json::Value, err: &str) {
        let ans_val =
            validate_json(json).expect("expected it to at least parse into ValidationCall");
        let result: Result<ValidationAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(ValidationAnswer::Failure { errors, .. }) => {
            assert!(
                errors.iter().any(|e| e.message.contains(err)),
                "Expected to see error(s) containing `{err}`, but saw {errors:?}",
            );
        });
    }

    #[test]
    fn test_validate_empty_policy() {
        let call = ValidationCall {
            validation_settings: ValidationSettings::default(),
            schema: Schema::Json(json!({}).into()),
            policy_set: PolicySet::Map(HashMap::new()),
        };

        assert_validates_without_errors(serde_json::to_value(&call).unwrap());

        let call = ValidationCall {
            validation_settings: ValidationSettings::default(),
            schema: Schema::Human(String::new()),
            policy_set: PolicySet::Map(HashMap::new()),
        };

        assert_validates_without_errors(serde_json::to_value(&call).unwrap());

        let call = json!({
            "schema": { "json": {} },
            "policySet": {}
        });

        assert_validates_without_errors(call);
    }

    #[test]
    fn test_nontrivial_correct_policy_validates_without_errors() {
        let json = json!({
        "schema": { "json": { "": {
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
        }}},
        "policySet": {
          "policy0": "permit(principal in UserGroup::\"alice_friends\", action == Action::\"viewPhoto\", resource);"
        }});

        assert_validates_without_errors(json);
    }

    #[test]
    fn test_policy_with_parse_error_fails_passing_on_errors() {
        let json = json!({
            "schema": { "json": { "": {
                "entityTypes": {},
                "actions": {}
            }}},
            "policySet": {
                "policy0": "azfghbjknnhbud"
            }
        });

        assert_is_failure(
            json,
            "failed to parse policy with id `policy0`: unexpected end of input",
        );
    }

    #[test]
    fn test_semantically_incorrect_policy_fails_with_errors() {
        let json = json!({
        "schema": { "json": { "": {
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
        }}},
        "policySet": {
          "policy0": "permit(principal == Photo::\"photo.jpg\", action == Action::\"viewPhoto\", resource == User::\"alice\");",
          "policy1": "permit(principal == Photo::\"photo2.jpg\", action == Action::\"viewPhoto\", resource == User::\"alice2\");"
        }});

        assert_validates_with_errors(json, 2);
    }

    #[test]
    fn test_nontrivial_correct_policy_validates_without_errors_concatenated_policies() {
        let json = json!({
        "schema": { "json": { "": {
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
        }}},
        "policySet": {
          "policy0": "permit(principal in UserGroup::\"alice_friends\", action == Action::\"viewPhoto\", resource);"
        }
        });

        assert_validates_without_errors(json);
    }

    #[test]
    fn test_policy_with_parse_error_fails_passing_on_errors_concatenated_policies() {
        let json = json!({
            "schema": { "json": { "": {
                "entityTypes": {},
                "actions": {}
            }}},
            "policySet": "azfghbjknnhbud"
        });

        assert_is_failure(
            json,
            "failed to parse policies from string: unexpected end of input",
        );
    }

    #[test]
    fn test_semantically_incorrect_policy_fails_with_errors_concatenated_policies() {
        let json = json!({
          "schema": { "json": { "": {
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
          }}},
          "policySet": "forbid(principal, action, resource);permit(principal == Photo::\"photo.jpg\", action == Action::\"viewPhoto\", resource == User::\"alice\");"
        });

        assert_validates_with_errors(json, 1);
    }

    #[test]
    fn test_policy_with_parse_error_fails_concatenated_policies() {
        let json = json!({
            "schema": { "json": { "": {
                "entityTypes": {},
                "actions": {}
            }}},
            "policySet": "permit(principal, action, resource);forbid"
        });

        assert_is_failure(
            json,
            "failed to parse policies from string: unexpected end of input",
        );
    }

    #[test]
    fn test_bad_call_format_fails() {
        assert_matches!(validate_json(json!("uerfheriufheiurfghtrg")), Err(e) => {
            assert!(e.to_string().contains("invalid type: string \"uerfheriufheiurfghtrg\", expected struct ValidationCall"), "actual error message was {e}");
        });
    }

    #[test]
    fn test_validate_fails_on_duplicate_namespace() {
        let json = r#"{
            "schema": { "json": {
              "foo": { "entityTypes": {}, "actions": {} },
              "foo": { "entityTypes": {}, "actions": {} }
            }},
            "policySet": ""
        }"#;

        assert_matches!(validate_json_str(json), Err(e) => {
          assert!(e.to_string().contains("the key `foo` occurs two or more times in the same JSON object"), "actual error message was {e}");
        });
    }

    #[test]
    fn test_validate_fails_on_duplicate_policy_id() {
        let json = r#"{
            "schema": { "json": { "": { "entityTypes": {}, "actions": {} } } },
            "policySet": {
              "ID0": "permit(principal, action, resource);",
              "ID0": "permit(principal, action, resource);"
            }
        }"#;

        assert_matches!(validate_json_str(json), Err(e) => {
          assert!(e.to_string().contains("policies as a concatenated string or multiple policies as a hashmap where the policy id is the key"), "actual error message was {e}");
        });
    }
}
