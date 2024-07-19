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

//! JSON FFI entry points for parsing various Cedar structures. The Cedar Wasm
//! parsing functions are generated from the functions in this file.

#![allow(clippy::module_name_repetitions)]

use super::{utils::DetailedError, Context, Entities, EntityUid, PolicySet, Schema};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(feature = "wasm")]
extern crate tsify;

/// Check whether a policy set successfully parses.
#[wasm_bindgen(js_name = "checkParsePolicySet")]
pub fn check_parse_policy_set(policies: PolicySet) -> CheckParseAnswer {
    policies.parse().into()
}

/// Check whether a policy set successfully parses. Input is a JSON encoding of
/// [`PolicySet`] and output is a JSON encoding of [`CheckParseAnswer`].
///
/// # Errors
///
/// Will return `Err` if the input JSON cannot be deserialized as a
/// [`PolicySet`].
pub fn check_parse_policy_set_json(
    json: serde_json::Value,
) -> Result<serde_json::Value, serde_json::Error> {
    let ans = check_parse_policy_set(serde_json::from_value(json)?);
    serde_json::to_value(ans)
}

/// Check whether a policy set successfully parses. Input and output are
/// strings containing serialized JSON, in the shapes expected by
/// [`check_parse_policy_set_json()`].
///
/// # Errors
///
/// Will return `Err` if the input cannot be converted to valid JSON or
/// deserialized as a [`PolicySet`].
pub fn check_parse_policy_set_json_str(json: &str) -> Result<String, serde_json::Error> {
    let ans = check_parse_policy_set(serde_json::from_str(json)?);
    serde_json::to_string(&ans)
}

/// Check whether a schema successfully parses.
#[wasm_bindgen(js_name = "checkParseSchema")]
pub fn check_parse_schema(schema: Schema) -> CheckParseAnswer {
    schema.parse().into()
}

/// Check whether a schema successfully parses. Input is a JSON encoding of
/// [`Schema`] and output is a JSON encoding of [`CheckParseAnswer`].
///
/// # Errors
///
/// Will return `Err` if the input JSON cannot be deserialized as a [`Schema`].
pub fn check_parse_schema_json(
    json: serde_json::Value,
) -> Result<serde_json::Value, serde_json::Error> {
    let ans = check_parse_schema(serde_json::from_value(json)?);
    serde_json::to_value(ans)
}

/// Check whether a schema successfully parses. Input and output are strings
/// containing serialized JSON, in the shapes expected by
/// [`check_parse_schema_json()`].
///
/// # Errors
///
/// Will return `Err` if the input cannot be converted to valid JSON or
/// deserialized as a [`Schema`].
pub fn check_parse_schema_json_str(json: &str) -> Result<String, serde_json::Error> {
    let ans = check_parse_schema(serde_json::from_str(json)?);
    serde_json::to_string(&ans)
}

/// Check whether a set of entities successfully parses.
#[wasm_bindgen(js_name = "checkParseEntities")]
pub fn check_parse_entities(call: EntitiesParsingCall) -> CheckParseAnswer {
    let schema = match call.schema.map(|s| s.parse().map(|res| res.0)).transpose() {
        Ok(schema) => schema,
        Err(err) => {
            return CheckParseAnswer::Failure {
                errors: vec![err.into()],
            };
        }
    };
    call.entities.parse(schema.as_ref()).into()
}

/// Check whether a set of entities successfully parses. Input is a JSON
/// encoding of [`EntitiesParsingCall`] and output is a JSON encoding of
/// [`CheckParseAnswer`].
///
/// # Errors
///
/// Will return `Err` if the input JSON cannot be deserialized as a
/// [`Entities`].
pub fn check_parse_entities_json(
    json: serde_json::Value,
) -> Result<serde_json::Value, serde_json::Error> {
    let ans = check_parse_entities(serde_json::from_value(json)?);
    serde_json::to_value(ans)
}

/// Check whether a set of entities successfully parses. Input and output are
/// strings containing serialized JSON, in the shapes expected by
/// [`check_parse_entities_json()`].
///
/// # Errors
///
/// Will return `Err` if the input cannot be converted to valid JSON or
/// deserialized as a [`Entities`].
pub fn check_parse_entities_json_str(json: &str) -> Result<String, serde_json::Error> {
    let ans = check_parse_entities(serde_json::from_str(json)?);
    serde_json::to_string(&ans)
}

/// Check whether a context successfully parses.
#[wasm_bindgen(js_name = "checkParseContext")]
pub fn check_parse_context(call: ContextParsingCall) -> CheckParseAnswer {
    let action = match call.action.map(|a| a.parse(Some("action"))).transpose() {
        Ok(action) => action,
        Err(err) => {
            return CheckParseAnswer::Failure {
                errors: vec![err.into()],
            };
        }
    };
    let schema = match call.schema.map(|s| s.parse().map(|res| res.0)).transpose() {
        Ok(schema) => schema,
        Err(err) => {
            return CheckParseAnswer::Failure {
                errors: vec![err.into()],
            };
        }
    };
    call.context.parse(schema.as_ref(), action.as_ref()).into()
}

/// Check whether a context successfully parses. Input is a JSON encoding of
/// [`ContextParsingCall`] and output is a JSON encoding of [`CheckParseAnswer`].
///
/// # Errors
///
/// Will return `Err` if the input JSON cannot be deserialized as a
/// [`Context`].
pub fn check_parse_context_json(
    json: serde_json::Value,
) -> Result<serde_json::Value, serde_json::Error> {
    let ans = check_parse_context(serde_json::from_value(json)?);
    serde_json::to_value(ans)
}

/// Check whether a context successfully parses. Input and output are
/// strings containing serialized JSON, in the shapes expected by
/// [`check_parse_context_json()`].
///
/// # Errors
///
/// Will return `Err` if the input cannot be converted to valid JSON or
/// deserialized as a [`Context`].
pub fn check_parse_context_json_str(json: &str) -> Result<String, serde_json::Error> {
    let ans = check_parse_context(serde_json::from_str(json)?);
    serde_json::to_string(&ans)
}

/// Result struct for syntax validation
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum CheckParseAnswer {
    /// Successfully parsed
    Success,
    /// Failed to parse
    Failure {
        /// Reported errors
        errors: Vec<DetailedError>,
    },
}

impl<T> From<Result<T, miette::Report>> for CheckParseAnswer {
    fn from(res: Result<T, miette::Report>) -> Self {
        match res {
            Ok(_) => Self::Success,
            Err(err) => Self::Failure {
                errors: vec![err.into()],
            },
        }
    }
}

impl<T> From<Result<T, Vec<miette::Report>>> for CheckParseAnswer {
    fn from(res: Result<T, Vec<miette::Report>>) -> Self {
        match res {
            Ok(_) => Self::Success,
            Err(errs) => Self::Failure {
                errors: errs.into_iter().map(Into::into).collect(),
            },
        }
    }
}

/// Struct containing the input data for [`check_parse_entities()`]
#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct EntitiesParsingCall {
    /// Input entities
    entities: Entities,
    /// Optional schema for schema-based parsing
    #[serde(default)]
    schema: Option<Schema>,
}

/// Struct containing the input data for [`check_parse_context()`]
#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct ContextParsingCall {
    /// Input context
    context: Context,
    /// Optional schema for schema-based parsing
    #[serde(default)]
    schema: Option<Schema>,
    /// Optional action entity for schema-based parsing
    #[serde(default)]
    action: Option<EntityUid>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ffi::test_utils::assert_exactly_one_error;
    use cool_asserts::assert_matches;
    use serde_json::json;

    #[track_caller]
    fn assert_check_parse_is_ok(parse_result: CheckParseAnswer) {
        assert_matches!(parse_result, CheckParseAnswer::Success)
    }

    #[track_caller]
    fn assert_check_parse_is_err(parse_result: CheckParseAnswer) -> Vec<DetailedError> {
        assert_matches!(
            parse_result,
            CheckParseAnswer::Failure { errors } => errors
        )
    }

    #[test]
    fn can_parse_1_policy() {
        let call = json!({
                "staticPolicies": "permit(principal, action, resource);"
        });
        let answer = serde_json::from_value(check_parse_policy_set_json(call).unwrap()).unwrap();
        assert_check_parse_is_ok(answer);
    }

    #[test]
    fn can_parse_multi_policy() {
        let call = json!({
            "staticPolicies": "forbid(principal, action, resource); permit(principal == User::\"alice\", action == Action::\"view\", resource in Albums::\"alice_albums\");"
        });
        let answer = serde_json::from_value(check_parse_policy_set_json(call).unwrap()).unwrap();
        assert_check_parse_is_ok(answer);
    }

    #[test]
    fn parse_policy_set_fails() {
        let call = json!({
            "staticPolicies": "forbid(principal, action, resource);permit(2pac, action, resource)"
        });
        let answer = serde_json::from_value(check_parse_policy_set_json(call).unwrap()).unwrap();
        let errs = assert_check_parse_is_err(answer);
        assert_exactly_one_error(
            &errs,
            "failed to parse policies from string: unexpected token `2`",
            None,
        );
    }

    #[test]
    fn can_parse_template() {
        let call = json!({
            "templates": {
                "ID0": "permit (principal == ?principal, action, resource == ?resource);"
            }
        });
        let answer = serde_json::from_value(check_parse_policy_set_json(call).unwrap()).unwrap();
        assert_check_parse_is_ok(answer);
    }

    #[test]
    fn check_parse_schema_succeeds_empty_schema() {
        let call = json!({});
        let answer = serde_json::from_value(check_parse_schema_json(call).unwrap()).unwrap();
        assert_check_parse_is_ok(answer);
    }

    #[test]
    fn check_parse_schema_succeeds_basic_schema() {
        let call = json!({
          "MyNamespace": {
            "entityTypes": {},
            "actions": {}
          }
        });
        let answer = serde_json::from_value(check_parse_schema_json(call).unwrap()).unwrap();
        assert_check_parse_is_ok(answer)
    }

    #[test]
    fn check_parse_schema_fails() {
        let call = json!({
          "MyNamespace": {
            "entityTypes": {}
          }
        });
        let answer = serde_json::from_value(check_parse_schema_json(call).unwrap()).unwrap();
        let errs = assert_check_parse_is_err(answer);
        assert_exactly_one_error(
            &errs,
            "failed to parse schema from JSON: missing field `actions`",
            None,
        );
    }

    #[test]
    fn check_parse_entities_succeeds() {
        let call = json!({
            "entities": [
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
            ],
            "schema": {
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
            }
        });
        let answer = serde_json::from_value(check_parse_entities_json(call).unwrap()).unwrap();
        assert_check_parse_is_ok(answer)
    }

    #[test]
    fn check_parse_entities_succeeds_with_no_schema() {
        let call = json!({
            "entities": [
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
            ]
        });
        let answer = serde_json::from_value(check_parse_entities_json(call).unwrap()).unwrap();
        assert_check_parse_is_ok(answer)
    }

    #[test]
    fn check_parse_entities_fails_on_bad_entity() {
        let call = json!({
            "entities": [
                {
                    "uid": "TheNamespace::User::\"alice\"",
                    "attrs": {
                        "benchPress": "doesn'tevenlift"
                    },
                    "parents": []
                }
            ],
            "schema": {
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
            }
        });
        let answer = serde_json::from_value(check_parse_entities_json(call).unwrap()).unwrap();
        let errs = assert_check_parse_is_err(answer);
        assert_exactly_one_error(
            &errs,
            "error during entity deserialization: in uid field of <unknown entity>, expected a literal entity reference, but got `\"TheNamespace::User::\\\"alice\\\"\"`",
            Some("literal entity references can be made with `{ \"type\": \"SomeType\", \"id\": \"SomeId\" }`")
        );
    }

    #[test]
    fn check_parse_context_succeeds() {
        let call = json!({
            "context": {
                "referrer": "Morpheus"
            },
            "action": {
                "type": "Ex::Action",
                "id": "Join"
            },
            "schema": {
                "Ex": {
                    "entityTypes": {
                        "User": {},
                        "Folder": {}
                    },
                    "actions": {
                        "Join": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["Folder"],
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
            }

        });
        let answer = serde_json::from_value(check_parse_context_json(call).unwrap()).unwrap();
        assert_check_parse_is_ok(answer)
    }

    #[test]
    fn check_parse_context_fails_for_bad_context() {
        let call = json!({
            "context": {
                "wrongAttr": true
            },
            "action": {
                "type": "Ex::Action",
                "id": "Join"
            },
            "schema": {
                "Ex": {
                    "entityTypes": {
                        "User": {},
                        "Folder": {}
                    },
                    "actions": {
                        "Join": {
                            "appliesTo": {
                                "principalTypes" : ["User"],
                                "resourceTypes": ["Folder"],
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
            }
        });
        let answer = serde_json::from_value(check_parse_context_json(call).unwrap()).unwrap();
        let errs = assert_check_parse_is_err(answer);
        assert_exactly_one_error(&errs, "while parsing context, expected the record to have an attribute `referrer`, but it does not", None);
    }
}
