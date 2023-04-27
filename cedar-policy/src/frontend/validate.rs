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
                        .map(|pe| format!("{pe:?}")),
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
        .map_err(|e| format!("couldn't construct schema - {e}"))?;
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
struct ValidateCall {
    #[serde(default)]
    #[serde(rename = "validationSettings")]
    validation_settings: ValidationSettings,
    schema: cedar_policy_validator::SchemaFragment,
    #[serde(rename = "policySet")]
    policy_set: PolicySpecification,
}

#[derive(Default, Serialize, Deserialize)]
struct ValidationSettings {
    mode: ValidationMode,
}

#[derive(Serialize, Deserialize)]
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

#[cfg(test)]
mod test {
    use super::*;
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
        assert_fails_with_user_errors(result);
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
        assert_fails_with_user_errors(result);
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
        assert_fails_with_user_errors(result);
    }

    #[test]
    fn test_bad_call_format_fails() {
        let result = json_validate("uerfheriufheiurfghtrg");
        assert_fails(result);
    }

    fn assert_fails(result: InterfaceResult) {
        match result {
            InterfaceResult::Success { result } => {
                panic!("expected call to fail but got {:?}", &result)
            }
            InterfaceResult::Failure { .. } => {}
        }
    }

    fn assert_validates_without_notes(result: InterfaceResult) {
        match result {
            InterfaceResult::Success { result } => {
                let parsed_result: ValidateAnswer = serde_json::from_str(result.as_str()).unwrap();
                match parsed_result {
                    ValidateAnswer::ParseFailed { .. } => {
                        panic!("expected parse to succeed, but got {parsed_result:?}")
                    }
                    ValidateAnswer::Success { notes, .. } => {
                        assert_eq!(notes.len(), 0, "Unexpected validation notes: {notes:?}")
                    }
                }
            }
            InterfaceResult::Failure { .. } => {
                panic!("expected call to succeed but got {:?}", &result)
            }
        }
    }

    fn assert_validates_with_notes(result: InterfaceResult, expected_num_notes: usize) {
        match result {
            InterfaceResult::Success { result } => {
                let parsed_result: ValidateAnswer = serde_json::from_str(result.as_str()).unwrap();
                match parsed_result {
                    ValidateAnswer::ParseFailed { .. } => {
                        panic!("expected parse to succeed, but got {parsed_result:?}")
                    }
                    ValidateAnswer::Success { notes, .. } => {
                        assert_eq!(notes.len(), expected_num_notes)
                    }
                }
            }
            InterfaceResult::Failure { .. } => {
                panic!("expected call to succeed but got {:?}", &result)
            }
        }
    }

    fn assert_fails_with_user_errors(result: InterfaceResult) {
        dbg!(&result);
        match result {
            InterfaceResult::Success { result } => {
                panic!("expected call to fail but got {:?}", &result)
            }
            InterfaceResult::Failure {
                is_internal,
                errors,
            } => {
                assert!(!is_internal);
                assert_ne!(errors.len(), 0);
            }
        }
    }
}
