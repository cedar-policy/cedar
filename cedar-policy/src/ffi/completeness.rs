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

//! JSON FFI entry points for reporting whether a schema is complete. The Cedar
//! Wasm `schemaCompleteness` function is generated from the
//! [`schema_completeness()`] function in this file.
//!
//! A schema is complete when every entity type and action it mentions is
//! defined. A schema that declares a name `external` without defining it is
//! partial, and parses successfully, so neither [`super::check_parse_schema()`]
//! nor [`super::validate()`] reports it.

#![allow(
    clippy::module_name_repetitions,
    reason = "the natural FFI function names"
)]

use super::{utils::DetailedError, Schema};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::{Ts, Tsify as _};
#[cfg(feature = "wasm")]
use wasm_bindgen::{prelude::wasm_bindgen, JsError};

#[cfg(feature = "wasm")]
extern crate tsify;

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
            let (external_entity_types, external_actions) = external_declarations(&schema);
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

/// Name the `external` declarations of a parsed schema. Both lists are sorted:
/// the underlying iterators walk hash maps, and a wire format should not vary
/// between runs.
pub(super) fn external_declarations(schema: &crate::Schema) -> (Vec<String>, Vec<String>) {
    let mut entity_types: Vec<String> = schema
        .external_entity_types()
        .map(ToString::to_string)
        .collect();
    entity_types.sort();
    let mut actions: Vec<String> = schema.external_actions().map(ToString::to_string).collect();
    actions.sort();
    (entity_types, actions)
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

#[cfg(test)]
mod test {
    use super::*;
    use cool_asserts::assert_matches;
    use serde_json::json;

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

    /// Every `external` declaration is named, in sorted order rather than
    /// declaration order.
    #[test]
    fn every_external_declaration_is_named() {
        let ans = schema_completeness_json(json!(
            "external entity Zebra;\nexternal entity Ant;\nexternal entity Mole;\nexternal action write;\nexternal action audit;\nentity Document { a: Ant, m: Mole, z: Zebra };"
        ))
        .unwrap();
        assert_eq!(
            ans,
            json!({
                "type": "success",
                "complete": false,
                "externalEntityTypes": ["Ant", "Mole", "Zebra"],
                "externalActions": ["Action::\"audit\"", "Action::\"write\""]
            })
        );
    }

    /// An `external` declaration in a namespace is named by its full path.
    #[test]
    fn a_namespaced_external_is_named_by_its_path() {
        let ans = schema_completeness_json(json!(
            "namespace N { external entity User; external action audit; }"
        ))
        .unwrap();
        assert_eq!(
            ans,
            json!({
                "type": "success",
                "complete": false,
                "externalEntityTypes": ["N::User"],
                "externalActions": ["N::Action::\"audit\""]
            })
        );
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
            crate::ffi::check_parse_schema_json(schema.clone()).unwrap(),
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

    /// The string entry point answers the same as the JSON one.
    #[test]
    fn the_string_entry_point_agrees() {
        let schema = "external entity User;";
        let got: serde_json::Value = serde_json::from_str(
            &schema_completeness_json_str(&serde_json::to_string(&json!(schema)).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(got, schema_completeness_json(json!(schema)).unwrap());
    }
}
