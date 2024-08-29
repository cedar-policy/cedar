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

//! JSON FFI entry points for converting between JSON and Cedar formats. The
//! Cedar Wasm conversion functions are generated from the functions in this
//! file.

use super::utils::JsonValueWithNoDuplicateKeys;
use super::{DetailedError, Policy, Schema, Template};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(feature = "wasm")]
extern crate tsify;

/// Return the Cedar (textual) representation of a policy.
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "policyToText"))]
pub fn policy_to_text(policy: Policy) -> PolicyToTextAnswer {
    match policy.parse(None) {
        Ok(policy) => PolicyToTextAnswer::Success {
            text: policy.to_string(),
        },
        Err(e) => PolicyToTextAnswer::Failure {
            errors: vec![e.into()],
        },
    }
}

/// Return the Cedar (textual) representation of a template.
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "templateToText"))]
pub fn template_to_text(template: Template) -> PolicyToTextAnswer {
    match template.parse(None) {
        Ok(template) => PolicyToTextAnswer::Success {
            text: template.to_string(),
        },
        Err(e) => PolicyToTextAnswer::Failure {
            errors: vec![e.into()],
        },
    }
}

/// Return the JSON representation of a policy.
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "policyToJson"))]
pub fn policy_to_json(policy: Policy) -> PolicyToJsonAnswer {
    match policy.parse(None) {
        Ok(policy) => match policy.to_json() {
            Ok(json) => PolicyToJsonAnswer::Success { json: json.into() },
            Err(e) => PolicyToJsonAnswer::Failure {
                errors: vec![miette::Report::new(e).into()],
            },
        },
        Err(e) => PolicyToJsonAnswer::Failure {
            errors: vec![e.into()],
        },
    }
}

/// Return the JSON representation of a template.
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "templateToJson"))]
pub fn template_to_json(template: Template) -> PolicyToJsonAnswer {
    match template.parse(None) {
        Ok(template) => match template.to_json() {
            Ok(json) => PolicyToJsonAnswer::Success { json: json.into() },
            Err(e) => PolicyToJsonAnswer::Failure {
                errors: vec![miette::Report::new(e).into()],
            },
        },
        Err(e) => PolicyToJsonAnswer::Failure {
            errors: vec![e.into()],
        },
    }
}

/// Return the Cedar (textual) representation of a schema.
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "schemaToText"))]
pub fn schema_to_text(schema: Schema) -> SchemaToTextAnswer {
    match schema.parse_schema_fragment() {
        Ok((schema_frag, warnings)) => {
            match schema_frag.to_cedarschema() {
                Ok(text) => {
                    // Before returning, check that the schema fragment corresponds to a valid schema
                    if let Err(e) = TryInto::<crate::Schema>::try_into(schema_frag) {
                        SchemaToTextAnswer::Failure {
                            errors: vec![miette::Report::new(e).into()],
                        }
                    } else {
                        SchemaToTextAnswer::Success {
                            text,
                            warnings: warnings.map(|e| miette::Report::new(e).into()).collect(),
                        }
                    }
                }
                Err(e) => SchemaToTextAnswer::Failure {
                    errors: vec![miette::Report::new(e).into()],
                },
            }
        }
        Err(e) => SchemaToTextAnswer::Failure {
            errors: vec![e.into()],
        },
    }
}

/// Return the JSON representation of a schema.
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "schemaToJson"))]
pub fn schema_to_json(schema: Schema) -> SchemaToJsonAnswer {
    match schema.parse_schema_fragment() {
        Ok((schema_frag, warnings)) => match schema_frag.to_json_value() {
            Ok(json) => {
                // Before returning, check that the schema fragment corresponds to a valid schema
                if let Err(e) = crate::Schema::from_json_value(json.clone()) {
                    SchemaToJsonAnswer::Failure {
                        errors: vec![miette::Report::new(e).into()],
                    }
                } else {
                    SchemaToJsonAnswer::Success {
                        json: json.into(),
                        warnings: warnings.map(|e| miette::Report::new(e).into()).collect(),
                    }
                }
            }
            Err(e) => SchemaToJsonAnswer::Failure {
                errors: vec![miette::Report::new(e).into()],
            },
        },
        Err(e) => SchemaToJsonAnswer::Failure {
            errors: vec![e.into()],
        },
    }
}

/// Result of converting a policy or template to the Cedar format
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum PolicyToTextAnswer {
    /// Represents a successful call
    Success {
        /// Cedar format policy
        text: String,
    },
    /// Represents a failed call (e.g., because the input is ill-formed)
    Failure {
        /// Errors
        errors: Vec<DetailedError>,
    },
}

/// Result of converting a policy or template to JSON
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum PolicyToJsonAnswer {
    /// Represents a successful call
    Success {
        /// JSON format policy
        #[cfg_attr(feature = "wasm", tsify(type = "PolicyJson"))]
        json: JsonValueWithNoDuplicateKeys,
    },
    /// Represents a failed call (e.g., because the input is ill-formed)
    Failure {
        /// Errors
        errors: Vec<DetailedError>,
    },
}

/// Result of converting a schema to the Cedar format
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum SchemaToTextAnswer {
    /// Represents a successful call
    Success {
        /// Cedar format schema
        text: String,
        /// Warnings
        warnings: Vec<DetailedError>,
    },
    /// Represents a failed call (e.g., because the input is ill-formed)
    Failure {
        /// Errors
        errors: Vec<DetailedError>,
    },
}

/// Result of converting a schema to JSON
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum SchemaToJsonAnswer {
    /// Represents a successful call
    Success {
        /// JSON format schema
        #[cfg_attr(feature = "wasm", tsify(type = "SchemaJson<string>"))]
        json: JsonValueWithNoDuplicateKeys,
        /// Warnings
        warnings: Vec<DetailedError>,
    },
    /// Represents a failed call (e.g., because the input is ill-formed)
    Failure {
        /// Errors
        errors: Vec<DetailedError>,
    },
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::ffi::test_utils::*;
    use cool_asserts::assert_matches;
    use serde_json::json;

    #[test]
    fn test_policy_to_json() {
        let text = r#"
            permit(principal, action, resource)
            when { principal has "Email" && principal.Email == "a@a.com" };
        "#;
        let result = policy_to_json(Policy::Cedar(text.into()));
        let expected = json!({
            "effect": "permit",
            "principal": {
                "op": "All"
            },
            "action": {
                "op": "All"
            },
            "resource": {
                "op": "All"
            },
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {
                                "has": {
                                    "left": {
                                        "Var": "principal"
                                    },
                                    "attr": "Email"
                                }
                            },
                            "right": {
                                "==": {
                                    "left": {
                                        ".": {
                                            "left": {
                                                "Var": "principal"
                                            },
                                            "attr": "Email"
                                        }
                                    },
                                    "right": {
                                        "Value": "a@a.com"
                                    }
                                }
                            }
                        }
                    }
                }
            ]
        });
        assert_matches!(result, PolicyToJsonAnswer::Success { json } =>
          assert_eq!(json, expected.into())
        );
    }

    #[test]
    fn test_policy_to_json_error() {
        let text = r#"
            permit(principal, action, resource)
            when { principal has "Email" && principal.Email == };
        "#;
        let result = policy_to_json(Policy::Cedar(text.into()));
        assert_matches!(result, PolicyToJsonAnswer::Failure { errors } => {
            assert_exactly_one_error(
                &errors,
                "failed to parse policy from string: unexpected token `}`",
                None,
            );
        });
    }

    #[test]
    fn test_policy_to_text() {
        let json = json!({
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
        });
        let result = policy_to_text(Policy::Json(json.into()));
        assert_matches!(result, PolicyToTextAnswer::Success { text } => {
            assert_eq!(
                &text,
                "permit(principal in UserGroup::\"DeathRowRecords\", action == Action::\"pop\", resource);"
            );
        });
    }

    #[test]
    fn test_template_to_json() {
        let text = r#"
            permit(principal in ?principal, action, resource);
        "#;
        let result = template_to_json(Template::Cedar(text.into()));
        let expected = json!({
            "effect": "permit",
            "principal": {
                "op": "in",
                "slot": "?principal"
            },
            "action": {
                "op": "All"
            },
            "resource": {
                "op": "All"
            },
            "conditions": []
        });
        assert_matches!(result, PolicyToJsonAnswer::Success { json } =>
          assert_eq!(json, expected.into())
        );
    }

    #[test]
    fn test_template_to_text() {
        let json = json!({
            "effect": "permit",
            "principal": {
                "op": "All"
            },
            "action": {
                "op": "All"
            },
            "resource": {
                "op": "in",
                "slot": "?resource"
            },
            "conditions": []
        });
        let result = template_to_text(Template::Json(json.into()));
        assert_matches!(result, PolicyToTextAnswer::Success { text } => {
            assert_eq!(
                &text,
                "permit(principal, action, resource in ?resource);"
            );
        });
    }

    #[test]
    fn test_template_to_text_error() {
        let json = json!({
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
        });
        let result = template_to_text(Template::Json(json.into()));
        assert_matches!(result, PolicyToTextAnswer::Failure { errors } => {
            assert_exactly_one_error(
                &errors,
                "failed to parse template from JSON: error deserializing a policy/template from JSON: expected a template, got a static policy",
                Some("a template should include slot(s) `?principal` or `?resource`"),
            );
        });
    }

    #[test]
    fn test_schema_to_json() {
        let text = r#"
            entity User = { "name": String };
            action sendMessage appliesTo {principal: User, resource: User};
        "#;
        let result = schema_to_json(Schema::Cedar(text.into()));
        let expected = json!({
        "": {
            "entityTypes": {
                "User": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "name": {"type": "EntityOrCommon", "name": "String"} // this will resolve to the builtin type `String` unless the user defines their own common or entity type `String` in the empty namespace, in another fragment
                        }
                    }
                }
            },
            "actions": {
                "sendMessage": {
                    "appliesTo": {
                        "resourceTypes": ["User"],
                        "principalTypes": ["User"]
                    }
                }}
            }
        });
        assert_matches!(result, SchemaToJsonAnswer::Success { json, warnings:_ } =>
          assert_eq!(json, expected.into())
        );
    }

    #[test]
    fn test_schema_to_json_error() {
        let text = r#"
            action sendMessage appliesTo {principal: User, resource: User};
        "#;
        let result = schema_to_json(Schema::Cedar(text.into()));
        assert_matches!(result, SchemaToJsonAnswer::Failure { errors } => {
            assert_exactly_one_error(
                &errors,
                "failed to resolve types: User, User",
                Some("`User` has not been declared as an entity type"),
            );
        });
    }

    #[test]
    fn test_schema_to_text() {
        let json = json!({
        "": {
            "entityTypes": {
                "User": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "name": {"type": "String"}
                        }
                    }
                }
            },
            "actions": {
                "sendMessage": {
                    "appliesTo": {
                        "resourceTypes": ["User"],
                        "principalTypes": ["User"]
                    }
                }}
            }
        });
        let result = schema_to_text(Schema::Json(json.into()));
        assert_matches!(result, SchemaToTextAnswer::Success { text, warnings:_ } => {
            assert_eq!(
                &text,
                "entity User = {\"name\": __cedar::String};\naction \"sendMessage\" appliesTo {\n  principal: [User],\n  resource: [User],\n  context: {}\n};\n"
            );
        });
    }
}
