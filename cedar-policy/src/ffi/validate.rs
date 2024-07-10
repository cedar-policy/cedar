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
use crate::{PolicyId, ValidationMode, Validator};
use serde::{Deserialize, Serialize};

#[cfg(feature = "wasm")]
extern crate tsify;

/// Parse a policy set and optionally validate it against a provided schema
///
/// This is the basic validator interface, using [`ValidationCall`] and
/// [`ValidationAnswer`] types
pub fn validate(call: ValidationCall) -> ValidationAnswer {
    match call.get_components() {
        WithWarnings {
            t: Ok((policies, schema, settings)),
            warnings,
        } => {
            // if validation is not enabled, stop here
            if !settings.enabled {
                return ValidationAnswer::Success {
                    validation_errors: Vec::new(),
                    validation_warnings: Vec::new(),
                    other_warnings: warnings.into_iter().map(Into::into).collect(),
                };
            }
            // otherwise, call `Validator::validate`
            let validator = Validator::new(schema);
            let (validation_errors, validation_warnings) = validator
                .validate(&policies, settings.mode)
                .into_errors_and_warnings();
            let validation_errors: Vec<ValidationError> = validation_errors
                .map(|error| ValidationError {
                    policy_id: error.policy_id().clone(),
                    error: miette::Report::new(error).into(),
                })
                .collect();
            let validation_warnings: Vec<ValidationError> = validation_warnings
                .map(|error| ValidationError {
                    policy_id: error.policy_id().clone(),
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
///
/// # Errors
///
/// Will return `Err` if the input JSON cannot be deserialized as a
/// [`ValidationCall`].
pub fn validate_json(json: serde_json::Value) -> Result<serde_json::Value, serde_json::Error> {
    let ans = validate(serde_json::from_value(json)?);
    serde_json::to_value(ans)
}

/// Input and output are strings containing serialized JSON, in the shapes
/// expected by [`validate_json()`]
///
/// # Errors
///
/// Will return `Err` if the input cannot be converted to valid JSON or
/// deserialized as a [`ValidationCall`].
pub fn validate_json_str(json: &str) -> Result<String, serde_json::Error> {
    let ans = validate(serde_json::from_str(json)?);
    serde_json::to_string(&ans)
}

/// Struct containing the input data for validation
#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct ValidationCall {
    /// Validation settings
    #[serde(default)]
    pub validation_settings: ValidationSettings,
    /// Schema to use for validation
    #[cfg_attr(feature = "wasm", tsify(type = "Schema"))]
    pub schema: Schema,
    /// Policies to validate
    pub policies: PolicySet,
}

impl ValidationCall {
    fn get_components(
        self,
    ) -> WithWarnings<
        Result<(crate::PolicySet, crate::Schema, ValidationSettings), Vec<miette::Report>>,
    > {
        let mut errs = vec![];
        let policies = match self.policies.parse() {
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
                t: Ok((policies, schema, self.validation_settings)),
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
#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct ValidationSettings {
    /// Whether validation is enabled. If this flag is set to `false`, then
    /// only parsing is performed. The default value is `true`.
    enabled: bool,
    /// Used to control how a policy is validated. See comments on [`ValidationMode`].
    mode: ValidationMode,
}

impl Default for ValidationSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: ValidationMode::default(),
        }
    }
}

/// Error (or warning) for a specified policy after validation
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct ValidationError {
    /// Id of the policy where the error (or warning) occurred
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub policy_id: PolicyId,
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
#[allow(clippy::panic, clippy::indexing_slicing)]
#[cfg(test)]
mod test {
    use super::*;

    use crate::ffi::test_utils::*;
    use cool_asserts::assert_matches;
    use serde_json::json;

    /// Assert that [`validate_json()`] returns [`ValidationAnswer::Success`]
    /// with no errors
    #[track_caller]
    fn assert_validates_without_errors(json: serde_json::Value) {
        let ans_val = validate_json(json).unwrap();
        let result: Result<ValidationAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(ValidationAnswer::Success { validation_errors, validation_warnings: _, other_warnings: _ }) => {
            assert_eq!(validation_errors.len(), 0, "Unexpected validation errors: {validation_errors:?}");
        });
    }

    /// Assert that [`validate_json()`] returns [`ValidationAnswer::Success`]
    /// and return the enclosed errors
    #[track_caller]
    fn assert_validates_with_errors(json: serde_json::Value) -> Vec<ValidationError> {
        let ans_val = validate_json(json).unwrap();
        assert_matches!(ans_val.get("validationErrors"), Some(_)); // should be present, with this camelCased name
        assert_matches!(ans_val.get("validationWarnings"), Some(_)); // should be present, with this camelCased name
        let result: Result<ValidationAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(ValidationAnswer::Success { validation_errors, validation_warnings: _, other_warnings: _ }) => {
            validation_errors
        })
    }

    /// Assert that [`validate_json_str()`] returns a `serde_json::Error`
    /// error with a message that matches `msg`
    #[track_caller]
    fn assert_validate_json_str_is_failure(call: &str, msg: &str) {
        assert_matches!(validate_json_str(call), Err(e) => {
            assert_eq!(e.to_string(), msg);
        });
    }

    /// Assert that [`validate_json()`] returns [`ValidationAnswer::Failure`]
    /// and return the enclosed errors
    #[track_caller]
    fn assert_is_failure(json: serde_json::Value) -> Vec<DetailedError> {
        let ans_val =
            validate_json(json).expect("expected it to at least parse into ValidationCall");
        let result: Result<ValidationAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(ValidationAnswer::Failure { errors, .. }) => errors)
    }

    #[test]
    fn test_validate_empty_policy() {
        let call = ValidationCall {
            validation_settings: ValidationSettings::default(),
            schema: Schema::Json(json!({}).into()),
            policies: PolicySet::new(),
        };

        assert_validates_without_errors(serde_json::to_value(&call).unwrap());

        let call = ValidationCall {
            validation_settings: ValidationSettings::default(),
            schema: Schema::Human(String::new()),
            policies: PolicySet::new(),
        };

        assert_validates_without_errors(serde_json::to_value(&call).unwrap());

        let call = json!({
            "schema": {},
            "policies": {}
        });

        assert_validates_without_errors(call);
    }

    #[test]
    fn test_nontrivial_correct_policy_validates_without_errors() {
        let json = json!({
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
        "policies": {
          "staticPolicies": {
            "policy0": "permit(principal in UserGroup::\"alice_friends\", action == Action::\"viewPhoto\", resource);"
          }
        }});

        assert_validates_without_errors(json);
    }

    #[test]
    fn test_policy_with_parse_error_fails_passing_on_errors() {
        let json = json!({
            "schema": { "": {
                "entityTypes": {},
                "actions": {}
            }},
            "policies": {
                "staticPolicies": {
                  "policy0": "azfghbjknnhbud"
                }
            }
        });

        let errs = assert_is_failure(json);
        assert_exactly_one_error(
            &errs,
            "failed to parse policy with id `policy0` from string: unexpected end of input",
            None,
        );
    }

    #[test]
    fn test_semantically_incorrect_policy_fails_with_errors() {
        let json = json!({
        "schema": { "": {
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
        "policies": {
          "staticPolicies": {
            "policy0": "permit(principal == Photo::\"photo.jpg\", action == Action::\"viewPhoto\", resource == User::\"alice\");",
            "policy1": "permit(principal == Photo::\"photo2.jpg\", action == Action::\"viewPhoto\", resource == User::\"alice2\");"
          }
        }});

        let errs = assert_validates_with_errors(json);
        assert_length_matches(&errs, 2);
        for err in errs {
            if err.policy_id == PolicyId::new("policy0") {
                assert_error_matches(
                    &err.error,
                    "for policy `policy0`, unable to find an applicable action given the policy scope constraints",
                    None
                );
            } else if err.policy_id == PolicyId::new("policy1") {
                assert_error_matches(
                    &err.error,
                    "for policy `policy1`, unable to find an applicable action given the policy scope constraints",
                    None
                );
            } else {
                panic!("unexpected validation error: {err:?}");
            }
        }
    }

    #[test]
    fn test_nontrivial_correct_policy_validates_without_errors_concatenated_policies() {
        let json = json!({
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
        "policies": {
          "staticPolicies": {
            "policy0": "permit(principal in UserGroup::\"alice_friends\", action == Action::\"viewPhoto\", resource);"
          }
        }
        });

        assert_validates_without_errors(json);
    }

    #[test]
    fn test_policy_with_parse_error_fails_passing_on_errors_concatenated_policies() {
        let json = json!({
            "schema": { "": {
                "entityTypes": {},
                "actions": {}
            }},
            "policies": {
              "staticPolicies": "azfghbjknnhbud"
            }
        });

        let errs = assert_is_failure(json);
        assert_exactly_one_error(
            &errs,
            "failed to parse policies from string: unexpected end of input",
            None,
        );
    }

    #[test]
    fn test_semantically_incorrect_policy_fails_with_errors_concatenated_policies() {
        let json = json!({
          "schema": { "": {
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
          "policies": {
            "staticPolicies": "forbid(principal, action, resource);permit(principal == Photo::\"photo.jpg\", action == Action::\"viewPhoto\", resource == User::\"alice\");"
          }
        });

        let errs = assert_validates_with_errors(json);
        assert_length_matches(&errs, 1);
        assert_eq!(errs[0].policy_id, PolicyId::new("policy1"));
        assert_error_matches(
            &errs[0].error,
            "for policy `policy1`, unable to find an applicable action given the policy scope constraints",
            None
        );
    }

    #[test]
    fn test_policy_with_parse_error_fails_concatenated_policies() {
        let json = json!({
            "schema": { "": {
                "entityTypes": {},
                "actions": {}
            }},
            "policies": {
              "staticPolicies": "permit(principal, action, resource);forbid"
            }
        });

        let errs = assert_is_failure(json);
        assert_exactly_one_error(
            &errs,
            "failed to parse policies from string: unexpected end of input",
            None,
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
        let text = r#"{
            "schema": {
              "foo": { "entityTypes": {}, "actions": {} },
              "foo": { "entityTypes": {}, "actions": {} }
            },
            "policies": {}
        }"#;

        assert_validate_json_str_is_failure(
            text,
            "expected a schema in the Cedar or JSON policy format (with no duplicate keys) at line 5 column 13",
        );
    }

    #[test]
    fn test_validate_fails_on_duplicate_policy_id() {
        let text = r#"{
            "schema": { "": { "entityTypes": {}, "actions": {} } },
            "policies": {
              "staticPolicies": {
                "ID0": "permit(principal, action, resource);",
                "ID0": "permit(principal, action, resource);"
              }
            }
        }"#;

        assert_validate_json_str_is_failure(
            text,
            "expected a static policy set represented by a string, JSON array, or JSON object (with no duplicate keys) at line 8 column 13",
        );
    }

    #[test]
    fn test_validate_with_templates() {
        // Successful validation with templates and template links
        let json = json!({
            "schema": "entity User, Photo; action viewPhoto appliesTo { principal: User, resource: Photo };",
            "policies": {
              "staticPolicies": {
                "ID0": "permit(principal == User::\"alice\", action, resource);"
              },
              "templates": {
                "ID1": "permit(principal == ?principal, action, resource);"
              },
              "templateLinks": [{
                "templateId": "ID1",
                "newId": "ID2",
                "values": {
                    "?principal": { "type": "User", "id": "bob" }
                }
              }]
            }
        });
        assert_validates_without_errors(json);

        // Validation fails due to bad template
        let json = json!({
            "schema": "entity User, Photo; action viewPhoto appliesTo { principal: User, resource: Photo };",
            "policies": {
              "staticPolicies": {
                "ID0": "permit(principal == User::\"alice\", action, resource);"
              },
              "templates": {
                "ID1": "permit(principal == ?principal, action == Action::\"foo\", resource);"
              },
              "templateLinks": [{
                "templateId": "ID1",
                "newId": "ID2",
                "values": {
                    "?principal": { "type": "User", "id": "bob" }
                }
              }]
            }
        });
        let errs = assert_validates_with_errors(json);
        assert_length_matches(&errs, 3);
        for err in errs {
            if err.policy_id == PolicyId::new("ID1") {
                if err.error.message.contains("unrecognized action") {
                    assert_error_matches(
                        &err.error,
                        "for policy `ID1`, unrecognized action `Action::\"foo\"`",
                        Some("did you mean `Action::\"viewPhoto\"`?"),
                    );
                } else {
                    assert_error_matches(
                        &err.error,
                        "for policy `ID1`, unable to find an applicable action given the policy scope constraints",
                        None,
                    );
                }
            } else if err.policy_id == PolicyId::new("ID2") {
                assert_error_matches(
                    &err.error,
                    "for policy `ID2`, unable to find an applicable action given the policy scope constraints",
                    None,
                );
            } else {
                panic!("unexpected validation error: {err:?}");
            }
        }

        // Validation fails due to bad link
        let json = json!({
            "schema": "entity User, Photo; action viewPhoto appliesTo { principal: User, resource: Photo };",
            "policies": {
              "staticPolicies": {
                "ID0": "permit(principal == User::\"alice\", action, resource);"
              },
              "templates": {
                "ID1": "permit(principal == ?principal, action, resource);"
              },
              "templateLinks": [{
                "templateId": "ID1",
                "newId": "ID2",
                "values": {
                    "?principal": { "type": "Photo", "id": "bob" }
                }
              }]
            }
        });
        let errs = assert_validates_with_errors(json);
        assert_length_matches(&errs, 1);
        assert_eq!(errs[0].policy_id, PolicyId::new("ID2"));
        assert_error_matches(
            &errs[0].error,
            "for policy `ID2`, unable to find an applicable action given the policy scope constraints",
            None
        );
    }
}
