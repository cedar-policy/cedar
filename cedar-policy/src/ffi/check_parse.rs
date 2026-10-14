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

#![allow(
    clippy::module_name_repetitions,
    reason = "the natural FFI function names"
)]

use super::{utils::DetailedError, Context, Entities, EntityUid, PolicySet, Schema};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::{Ts, Tsify as _};
#[cfg(feature = "wasm")]
use wasm_bindgen::{prelude::wasm_bindgen, JsError};

#[cfg(feature = "wasm")]
extern crate tsify;

/// Check whether a policy set successfully parses.
///
/// # Errors
///
/// Throws if `policies` does not match the `PolicySet` type, or if the answer
/// cannot be serialized back to JavaScript.
#[cfg(feature = "wasm")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "FFI function which conventionally takes owned arguments"
)]
#[wasm_bindgen(js_name = "checkParsePolicySet")]
pub fn check_parse_policy_set_wasm(
    policies: Ts<PolicySet>,
) -> Result<Ts<CheckParseAnswer>, JsError> {
    Ok(check_parse_policy_set(policies.to_rust()?).into_ts()?)
}

/// Check whether a policy set successfully parses.
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
///
/// # Errors
///
/// Throws if `schema` does not match the `Schema` type, or if the answer
/// cannot be serialized back to JavaScript.
#[cfg(feature = "wasm")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "FFI function which conventionally takes owned arguments"
)]
#[wasm_bindgen(js_name = "checkParseSchema")]
pub fn check_parse_schema_wasm(schema: Ts<Schema>) -> Result<Ts<CheckParseAnswer>, JsError> {
    Ok(check_parse_schema(schema.to_rust()?).into_ts()?)
}

/// Check whether a schema successfully parses.
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

/// Report whether a schema is free of `external` declarations.
///
/// # Errors
///
/// Throws if `schema` does not match the `Schema` type, or if the answer
/// cannot be serialized back to JavaScript.
#[cfg(feature = "wasm")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "FFI function which conventionally takes owned arguments"
)]
#[wasm_bindgen(js_name = "schemaCompleteness")]
pub fn schema_completeness_wasm(
    schema: Ts<Schema>,
) -> Result<Ts<SchemaCompletenessAnswer>, JsError> {
    Ok(schema_completeness(schema.to_rust()?).into_ts()?)
}

/// Report whether a schema is complete, and name the `external` declarations
/// that make it partial.
pub fn schema_completeness(schema: Schema) -> SchemaCompletenessAnswer {
    match schema.parse() {
        // Warnings are dropped, as `check_parse_schema` drops them.
        Ok((schema, _warnings)) => {
            // Sorted: the underlying iterators walk hash maps, and a wire
            // format should not vary between runs.
            let mut external_entity_types: Vec<String> = schema
                .external_entity_types()
                .map(ToString::to_string)
                .collect();
            external_entity_types.sort();
            let mut external_actions: Vec<String> =
                schema.external_actions().map(ToString::to_string).collect();
            external_actions.sort();
            SchemaCompletenessAnswer::Success {
                complete: schema.is_complete(),
                external_entity_types,
                external_actions,
            }
        }
        Err(err) => SchemaCompletenessAnswer::Failure {
            errors: vec![err.into()],
        },
    }
}

/// Report whether a schema is complete. Input is a JSON encoding of
/// [`Schema`] and output is a JSON encoding of [`SchemaCompletenessAnswer`].
///
/// # Errors
///
/// Will return `Err` if the input JSON cannot be deserialized as a [`Schema`].
pub fn schema_completeness_json(
    json: serde_json::Value,
) -> Result<serde_json::Value, serde_json::Error> {
    let ans = schema_completeness(serde_json::from_value(json)?);
    serde_json::to_value(ans)
}

/// Report whether a schema is complete. Input and output are strings
/// containing serialized JSON, in the shapes expected by
/// [`schema_completeness_json()`].
///
/// # Errors
///
/// Will return `Err` if the input cannot be converted to valid JSON or
/// deserialized as a [`Schema`].
pub fn schema_completeness_json_str(json: &str) -> Result<String, serde_json::Error> {
    let ans = schema_completeness(serde_json::from_str(json)?);
    serde_json::to_string(&ans)
}

/// Check whether a set of scope variables successfully parses.
pub fn check_parse_scope_variables(call: ScopeVariablesParsingCall) -> CheckParseAnswer {
    let schema_ref = match call.schema.parse() {
        Ok((schema, _)) => schema,
        Err(err) => {
            return CheckParseAnswer::Failure {
                errors: vec![err.into()],
            };
        }
    };
    let principal = match call.principal.parse(Some("principal")) {
        Ok(principal) => principal,
        Err(err) => {
            return CheckParseAnswer::Failure {
                errors: vec![err.into()],
            };
        }
    };

    let action = match call.action.parse(Some("action")) {
        Ok(action) => action,
        Err(err) => {
            return CheckParseAnswer::Failure {
                errors: vec![err.into()],
            };
        }
    };

    let resource = match call.resource.parse(Some("resource")) {
        Ok(resource) => resource,
        Err(err) => {
            return CheckParseAnswer::Failure {
                errors: vec![err.into()],
            };
        }
    };

    //all three should be provided, so just call validate
    if let Err(err) =
        crate::api::validate_scope_variables(&principal, &action, &resource, &schema_ref)
    {
        CheckParseAnswer::Failure {
            errors: vec![miette::Report::msg(err).into()],
        }
    } else {
        CheckParseAnswer::Success
    }
}

/// Check whether a set of scope variables successfully parses. Input is a JSON
/// encoding of [`ScopeVariablesParsingCall`] and output is a JSON encoding of
/// [`CheckParseAnswer`].
///
/// # Errors
///
/// Will return `Err` if the input JSON cannot be deserialized as
/// scope variables.
pub fn check_parse_scope_variables_json(
    json: serde_json::Value,
) -> Result<serde_json::Value, serde_json::Error> {
    let ans = check_parse_scope_variables(serde_json::from_value(json)?);
    serde_json::to_value(ans)
}

/// Check whether a set of entities successfully parses.
///
/// # Errors
///
/// Throws if `call` does not match the `EntitiesParsingCall` type, or if the
/// answer cannot be serialized back to JavaScript.
#[cfg(feature = "wasm")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "FFI function which conventionally takes owned arguments"
)]
#[wasm_bindgen(js_name = "checkParseEntities")]
pub fn check_parse_entities_wasm(
    call: Ts<EntitiesParsingCall>,
) -> Result<Ts<CheckParseAnswer>, JsError> {
    Ok(check_parse_entities(call.to_rust()?).into_ts()?)
}

/// Check whether a set of entities successfully parses.
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
///
/// # Errors
///
/// Throws if `call` does not match the `ContextParsingCall` type, or if the
/// answer cannot be serialized back to JavaScript.
#[cfg(feature = "wasm")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "FFI function which conventionally takes owned arguments"
)]
#[wasm_bindgen(js_name = "checkParseContext")]
pub fn check_parse_context_wasm(
    call: Ts<ContextParsingCall>,
) -> Result<Ts<CheckParseAnswer>, JsError> {
    Ok(check_parse_context(call.to_rust()?).into_ts()?)
}

/// Check whether a context successfully parses.
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

    let parse_result = call.context.parse(schema.as_ref(), action.as_ref());

    // Check if the parsed context is valid
    if let Ok(context) = &parse_result {
        if let (Some(schema_ref), Some(action_ref)) = (&schema, &action) {
            if let Err(err) = context.validate(schema_ref, action_ref) {
                return CheckParseAnswer::Failure {
                    errors: vec![miette::Report::msg(err).into()],
                };
            }
        }
    }
    // Return the parse result if all other checks pass
    parse_result.into()
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

/// Result struct for [`schema_completeness()`]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
pub enum SchemaCompletenessAnswer {
    /// The schema parsed, and this is what it says about its declarations
    #[serde(rename_all = "camelCase")]
    Success {
        /// Is every entity type and action defined, rather than only declared
        /// `external`? True exactly when both lists below are empty.
        complete: bool,
        /// Entity types declared `external` and not defined, sorted
        external_entity_types: Vec<String>,
        /// Actions declared `external` and not defined, sorted
        external_actions: Vec<String>,
    },
    /// The schema failed to parse
    #[serde(rename_all = "camelCase")]
    Failure {
        /// Reported errors
        errors: Vec<DetailedError>,
    },
}

/// Result struct for syntax validation
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
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
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct EntitiesParsingCall {
    /// Input entities
    entities: Entities,
    /// Optional schema for schema-based parsing
    #[serde(default)]
    schema: Option<Schema>,
}

/// Struct containing the input data for [`check_parse_scope_variables()`]
#[derive(Serialize, Deserialize, Debug)]
pub struct ScopeVariablesParsingCall {
    /// Principal entity for schema-based validation
    principal: EntityUid,
    /// Action entity for schema-based validation
    action: EntityUid,
    /// Resource entity for schema-based validation
    resource: EntityUid,
    /// Schema for schema-based validation
    schema: Schema,
}

/// Struct containing the input data for [`check_parse_context()`]
#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
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
    fn assert_check_parse_is_ok(parse_result: &CheckParseAnswer) {
        assert_matches!(parse_result, CheckParseAnswer::Success);
    }

    #[track_caller]
    fn assert_check_parse_is_err(parse_result: &CheckParseAnswer) -> &[DetailedError] {
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
        assert_check_parse_is_ok(&answer);
    }

    #[test]
    fn can_parse_multi_policy() {
        let call = json!({
            "staticPolicies": "forbid(principal, action, resource); permit(principal == User::\"alice\", action == Action::\"view\", resource in Albums::\"alice_albums\");"
        });
        let answer = serde_json::from_value(check_parse_policy_set_json(call).unwrap()).unwrap();
        assert_check_parse_is_ok(&answer);
    }

    #[test]
    fn parse_policy_set_fails() {
        let call = json!({
            "staticPolicies": "forbid(principal, action, resource);permit(2pac, action, resource)"
        });
        let answer = serde_json::from_value(check_parse_policy_set_json(call).unwrap()).unwrap();
        let errs = assert_check_parse_is_err(&answer);
        assert_exactly_one_error(
            errs,
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
        assert_check_parse_is_ok(&answer);
    }

    #[test]
    fn check_parse_schema_succeeds_empty_schema() {
        let call = json!({});
        let answer = serde_json::from_value(check_parse_schema_json(call).unwrap()).unwrap();
        assert_check_parse_is_ok(&answer);
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
        assert_check_parse_is_ok(&answer);
    }

    #[test]
    fn check_parse_schema_fails() {
        let call = json!({
          "MyNamespace": {
            "entityTypes": {}
          }
        });
        let answer = serde_json::from_value(check_parse_schema_json(call).unwrap()).unwrap();
        let errs = assert_check_parse_is_err(&answer);
        assert_exactly_one_error(
            errs,
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
        assert_check_parse_is_ok(&answer);
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
        assert_check_parse_is_ok(&answer);
    }

    #[test]
    fn check_parse_scope_variables_succeeds() {
        let call = json!({
            "principal": {
                "type": "PhotoApp::User",
                "id": "alice"
            },
            "action": {
                "type": "PhotoApp::Action",
                "id": "view"
            },
            "resource": {
                "type": "PhotoApp::Photo",
                "id": "photo1"
            },
            "schema": {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        },
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "userId": {
                                        "type": "String"
                                    },
                                    "personInformation": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "view": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["Photo"]
                            }
                        }
                    }
                }
            }
        });
        let answer =
            serde_json::from_value(check_parse_scope_variables_json(call).unwrap()).unwrap();
        assert_check_parse_is_ok(&answer);
    }

    #[test]
    fn check_parse_scope_variables_fails_on_invalid_principal() {
        let call = json!({
            "principal": {
                "type": "PhotoApp::Use",
                "id": "alice"
            },
            "action": {
                "type": "PhotoApp::Action",
                "id": "view"
            },
            "resource": {
                "type": "PhotoApp::Photo",
                "id": "photo1"
            },
            "schema": {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        },
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "userId": {
                                        "type": "String"
                                    },
                                    "personInformation": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "view": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["Photo"]
                            }
                        }
                    }
                }
            }
        });
        let answer =
            serde_json::from_value(check_parse_scope_variables_json(call).unwrap()).unwrap();
        let errs = assert_check_parse_is_err(&answer);
        assert_exactly_one_error(
            errs,
            "principal type `PhotoApp::Use` is not declared in the schema",
            None,
        );
    }

    #[test]
    fn check_parse_scope_variables_fails_on_invalid_action() {
        let call = json!({
            "principal": {
                "type": "PhotoApp::User",
                "id": "alice"
            },
            "action": {
                "type": "PhotoApp::Action",
                "id": "viewPhoto"
            },
            "resource": {
                "type": "PhotoApp::Photo",
                "id": "photo1"
            },
            "schema": {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        },
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "userId": {
                                        "type": "String"
                                    },
                                    "personInformation": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "view": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["Photo"]
                            }
                        }
                    }
                }
            }
        });
        let answer =
            serde_json::from_value(check_parse_scope_variables_json(call).unwrap()).unwrap();
        let errs = assert_check_parse_is_err(&answer);
        assert_exactly_one_error(
            errs,
            "request's action `PhotoApp::Action::\"viewPhoto\"` is not declared in the schema",
            None,
        );
    }

    #[test]
    fn check_parse_scope_variables_fails_on_invalid_resource() {
        let call = json!({
            "principal": {
                "type": "PhotoApp::User",
                "id": "alice"
            },
            "action": {
                "type": "PhotoApp::Action",
                "id": "view"
            },
            "resource": {
                "type": "PhotoApp::Album",
                "id": "photo1"
            },
            "schema": {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        },
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "userId": {
                                        "type": "String"
                                    },
                                    "personInformation": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "view": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["Photo"]
                            }
                        }
                    }
                }
            }
        });
        let answer =
            serde_json::from_value(check_parse_scope_variables_json(call).unwrap()).unwrap();
        let errs = assert_check_parse_is_err(&answer);
        assert_exactly_one_error(
            errs,
            "resource type `PhotoApp::Album` is not declared in the schema",
            None,
        );
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
        let errs = assert_check_parse_is_err(&answer);
        assert_exactly_one_error(
            errs,
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
        assert_check_parse_is_ok(&answer);
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
        let errs = assert_check_parse_is_err(&answer);
        assert_exactly_one_error(errs, "while parsing context, expected the record to have an attribute `referrer`, but it does not", None);
    }

    #[test]
    fn check_parse_context_fails_for_invalid_context_type() {
        let call = json!({
            "context": {
                "authenticated": "foo"
            },
            "action": {
                "type": "PhotoApp::Action",
                "id": "viewPhoto"
            },
            "schema": {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        },
                        "ContextType": {
                            "type": "Record",
                            "attributes": {
                                "ip": {
                                    "type": "Extension",
                                    "name": "ipaddr",
                                    "required": false
                                },
                                "authenticated": {
                                    "type": "Boolean",
                                    "required": true
                                }
                            }
                        }
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            },
                            "memberOfTypes": [
                                "UserGroup"
                            ]
                        },
                        "UserGroup": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            },
                        }
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        }
                    }
                }
            }
        });
        let answer = serde_json::from_value(check_parse_context_json(call).unwrap()).unwrap();
        let errs = assert_check_parse_is_err(&answer);
        assert_exactly_one_error(
            errs,
            "context `{authenticated: \"foo\"}` is not valid for `PhotoApp::Action::\"viewPhoto\"`",
            None,
        );
    }

    /// One partial schema, in Cedar syntax and in JSON.
    /// `schema_completeness` answers the same for both.
    #[test]
    fn schema_completeness_on_a_partial_schema() {
        let cedar = json!(
            "external entity User;\nexternal action audit;\nentity Document { owner: User };\naction view appliesTo { principal: [Document], resource: [Document] };"
        );
        let as_json = json!({ "": {
            "entityTypes": {
                "User": { "external": true },
                "Document": { "shape": { "type": "Record", "attributes": {
                    "owner": { "type": "EntityOrCommon", "name": "User" }
                } } }
            },
            "actions": {
                "audit": { "external": true },
                "view": { "appliesTo": {
                    "principalTypes": ["Document"], "resourceTypes": ["Document"]
                } }
            }
        } });

        for (syntax, call) in [("Cedar syntax", cedar), ("JSON syntax", as_json)] {
            let ans = schema_completeness_json(call).unwrap();
            assert_eq!(
                ans,
                json!({
                    "type": "success",
                    "complete": false,
                    "externalEntityTypes": ["User"],
                    "externalActions": ["Action::\"audit\""]
                }),
                "{syntax}"
            );
        }
    }

    #[test]
    fn schema_completeness_on_a_complete_schema() {
        // An enumerated entity type is a definition, not a declaration.
        let ans = schema_completeness_json(json!(
            "entity Color enum [\"red\"];\naction view appliesTo { principal: [Color], resource: [Color] };"
        ))
        .unwrap();
        assert_eq!(
            ans,
            json!({
                "type": "success",
                "complete": true,
                "externalEntityTypes": [],
                "externalActions": []
            })
        );
    }

    /// Neither `check_parse_schema` nor `validate` reports that a schema is
    /// partial.
    #[test]
    fn the_alternatives_do_not_answer_the_question() {
        let schema = json!("external entity User;\nentity Document { owner: User };");
        assert_eq!(
            check_parse_schema_json(schema.clone()).unwrap(),
            json!({ "type": "success" }),
            "a partial schema parses, so `check_parse_schema` says nothing"
        );
        let ans = crate::ffi::validate_json(json!({
            "schema": schema,
            "policies": { "staticPolicies": {} }
        }))
        .unwrap();
        assert_eq!(
            ans,
            json!({
                "type": "success",
                "validationErrors": [],
                "validationWarnings": [],
                "otherWarnings": []
            }),
            "an empty policy set has nothing to report against, so `validate` passes"
        );
    }

    #[test]
    fn schema_completeness_reports_a_parse_failure() {
        let answer: SchemaCompletenessAnswer =
            serde_json::from_value(schema_completeness_json(json!("external entity;")).unwrap())
                .unwrap();
        assert_matches!(answer, SchemaCompletenessAnswer::Failure { errors } => {
            assert_eq!(errors.len(), 1, "unexpected errors: {errors:?}");
        });
    }

    /// A declaration whose own reference is dangling is still a schema error,
    /// not an incomplete schema.
    #[test]
    fn a_dangling_reference_is_a_failure_not_an_incomplete_schema() {
        let answer: SchemaCompletenessAnswer = serde_json::from_value(
            schema_completeness_json(json!("external entity A in [Undeclared];")).unwrap(),
        )
        .unwrap();
        assert_matches!(answer, SchemaCompletenessAnswer::Failure { .. });
    }
}
