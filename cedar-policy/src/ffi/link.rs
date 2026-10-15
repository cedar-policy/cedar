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

//! JSON FFI entry points for linking schemas. The Cedar Wasm `linkSchemas`
//! function is generated from the [`link_schemas()`] function in this file.
//!
//! Linking resolves a name declared `external` in one schema against a
//! definition of the same name in another, and returns the one schema the
//! inputs link to. The returned schema is in Cedar's JSON schema format, so it
//! can be passed back in as an input to link again.
//!
//! The returned schema carries no annotations, and its common types are
//! inlined to their definitions. Linking operates on resolved schemas, which
//! do not record either.

#![allow(
    clippy::module_name_repetitions,
    reason = "the natural FFI function names"
)]

use super::utils::JsonValueWithNoDuplicateKeys;
use super::{completeness::external_declarations, DetailedError, Schema};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::{Ts, Tsify as _};
#[cfg(feature = "wasm")]
use wasm_bindgen::{prelude::wasm_bindgen, JsError};

#[cfg(feature = "wasm")]
extern crate tsify;

/// Link schemas, resolving `external` declarations against definitions.
///
/// # Errors
///
/// Throws if `call` does not match the `LinkSchemasCall` type, or if the answer
/// cannot be serialized back to JavaScript.
#[cfg(feature = "wasm")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "FFI function which conventionally takes owned arguments"
)]
#[wasm_bindgen(js_name = "linkSchemas")]
pub fn link_schemas_wasm(call: Ts<LinkSchemasCall>) -> Result<Ts<LinkSchemasAnswer>, JsError> {
    Ok(link_schemas(call.to_rust()?).into_ts()?)
}

/// Link schemas, resolving `external` declarations against definitions, and
/// return the schema they link to.
pub fn link_schemas(call: LinkSchemasCall) -> LinkSchemasAnswer {
    let mut parsed = Vec::with_capacity(call.schemas.len());
    let mut warnings = Vec::new();
    let mut errors = Vec::new();
    for schema in call.schemas {
        match schema.parse() {
            Ok((schema, new_warnings)) => {
                warnings.extend(new_warnings.map(|w| miette::Report::new(w).into()));
                parsed.push(schema);
            }
            // Every input that failed to parse is reported, not just the first.
            Err(err) => errors.push(err.into()),
        }
    }
    if !errors.is_empty() {
        return LinkSchemasAnswer::Failure { errors };
    }
    let linked = match crate::Schema::schema_link(parsed) {
        Ok(linked) => linked,
        Err(err) => {
            return LinkSchemasAnswer::Failure {
                errors: vec![(&err).into()],
            };
        }
    };
    let json = match linked
        .0
        .to_json_schema()
        .map_err(miette::Report::msg)
        .and_then(|fragment| serde_json::to_value(fragment).map_err(miette::Report::msg))
    {
        Ok(json) => json,
        Err(err) => {
            return LinkSchemasAnswer::Failure {
                errors: vec![err.into()],
            };
        }
    };
    let (external_entity_types, external_actions) = external_declarations(&linked);
    LinkSchemasAnswer::Success {
        json: json.into(),
        complete: linked.is_complete(),
        external_entity_types,
        external_actions,
        warnings,
    }
}

/// Link schemas. Input is a JSON encoding of [`LinkSchemasCall`] and output is
/// a JSON encoding of [`LinkSchemasAnswer`].
///
/// # Errors
///
/// Will return `Err` if the input JSON cannot be deserialized as a
/// [`LinkSchemasCall`].
pub fn link_schemas_json(json: serde_json::Value) -> Result<serde_json::Value, serde_json::Error> {
    let ans = link_schemas(serde_json::from_value(json)?);
    serde_json::to_value(ans)
}

/// Link schemas. Input and output are strings containing serialized JSON, in
/// the shapes expected by [`link_schemas_json()`].
///
/// # Errors
///
/// Will return `Err` if the input cannot be converted to valid JSON or
/// deserialized as a [`LinkSchemasCall`].
pub fn link_schemas_json_str(json: &str) -> Result<String, serde_json::Error> {
    let ans = link_schemas(serde_json::from_str(json)?);
    serde_json::to_string(&ans)
}

/// Struct containing the input data for linking schemas
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct LinkSchemasCall {
    /// Schemas to link, each in the Cedar or JSON schema format. Linking is
    /// commutative and associative, so neither the order nor the grouping of
    /// the schemas affects the answer. An empty list links to the empty schema.
    #[cfg_attr(feature = "wasm", tsify(type = "Schema[]"))]
    pub schemas: Vec<Schema>,
}

/// Result struct for [`link_schemas()`]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
pub enum LinkSchemasAnswer {
    /// The schemas linked, and this is the schema they link to
    #[serde(rename_all = "camelCase")]
    Success {
        /// The linked schema, in Cedar's JSON schema format
        #[cfg_attr(feature = "wasm", tsify(type = "SchemaJson<string>"))]
        json: JsonValueWithNoDuplicateKeys,
        /// whether the result is free of `external`.
        /// True when both lists below are empty
        complete: bool,
        /// Entity types declared `external` and not defined, sorted
        external_entity_types: Vec<String>,
        /// Actions declared `external` and not defined, sorted
        external_actions: Vec<String>,
        /// Warnings from parsing the inputs
        warnings: Vec<DetailedError>,
    },
    /// An input failed to parse, or the schemas do not link
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

    /// Link `schemas` and return the answer as JSON.
    #[track_caller]
    fn link(schemas: Vec<serde_json::Value>) -> serde_json::Value {
        link_schemas_json(json!({ "schemas": schemas })).unwrap()
    }

    /// Linking succeeded. Returns the linked schema and whether it is complete.
    #[track_caller]
    fn assert_links(schemas: Vec<serde_json::Value>) -> (serde_json::Value, bool) {
        let answer: LinkSchemasAnswer = serde_json::from_value(link(schemas)).unwrap();
        assert_matches!(answer, LinkSchemasAnswer::Success { json, complete, .. } => {
            (json.into(), complete)
        })
    }

    /// Linking is refused. Returns the reported errors.
    #[track_caller]
    fn assert_link_fails(schemas: Vec<serde_json::Value>) -> Vec<DetailedError> {
        let answer: LinkSchemasAnswer = serde_json::from_value(link(schemas)).unwrap();
        assert_matches!(answer, LinkSchemasAnswer::Failure { errors } => errors)
    }

    /// A definition replaces an external, and the linked schema comes back.
    #[test]
    fn an_entity_definition_replaces_an_external() {
        let (json, complete) = assert_links(vec![
            json!("external entity B;\nentity A { b: B };"),
            json!("entity B;"),
        ]);
        assert!(complete);
        assert_eq!(
            json,
            json!({ "": {
                "entityTypes": {
                    "A": { "shape": { "type": "Record", "attributes": {
                        "b": { "type": "EntityOrCommon", "name": "B" }
                    } } },
                    "B": {}
                },
                "actions": {}
            } })
        );
    }

    /// An unresolved external is still external in the linked schema.
    #[test]
    fn an_unresolved_external_remains_external() {
        let answer: LinkSchemasAnswer = serde_json::from_value(link(vec![
            json!("external entity B;\nentity A { b: B };"),
            json!("external entity B;\nentity D { b: B };"),
        ]))
        .unwrap();
        assert_matches!(answer, LinkSchemasAnswer::Success {
            complete, external_entity_types, external_actions, ..
        } => {
            assert!(!complete);
            assert_eq!(external_entity_types, ["B"]);
            assert!(external_actions.is_empty());
        });
    }

    /// Mutual externals resolve against each other.
    #[test]
    fn mutual_externals_resolve() {
        let (_, complete) = assert_links(vec![
            json!("external entity B;\nentity A { b: B };"),
            json!("external entity A;\nentity B { a: A };"),
        ]);
        assert!(complete);
    }

    /// An external action resolves to a definition with an `appliesTo`.
    #[test]
    fn an_external_action_links_to_a_definition() {
        let (_, complete) = assert_links(vec![
            json!("entity User;\nentity Doc;\nexternal action write;"),
            json!(
                "external entity User;\nexternal entity Doc;\naction write appliesTo { principal: User, resource: Doc };"
            ),
        ]);
        assert!(complete);
    }

    /// An input in Cedar syntax links against an input in JSON syntax.
    #[test]
    fn the_two_schema_syntaxes_link() {
        let (_, complete) = assert_links(vec![
            json!("external entity B;\nentity A { b: B };"),
            json!({ "": { "entityTypes": { "B": {} }, "actions": {} } }),
        ]);
        assert!(complete);
    }

    /// Order does not matter: linking is commutative.
    #[test]
    fn order_does_not_matter() {
        let p = json!("external entity B;\nexternal action audit;\nentity A { b: B };");
        let c = json!("entity B;");
        assert_eq!(
            link(vec![p.clone(), c.clone()]),
            link(vec![c, p]),
            "the same schemas in the other order"
        );
    }

    /// One schema links to itself.
    #[test]
    fn one_schema_links_to_itself() {
        let (_, complete) = assert_links(vec![json!("external entity B;\nentity A { b: B };")]);
        assert!(!complete);
    }

    /// No schemas link to the empty schema, which is complete.
    #[test]
    fn no_schemas_link_to_the_empty_schema() {
        let (json, complete) = assert_links(vec![]);
        assert!(complete);
        assert_eq!(json, json!({}));
    }

    /// Two definitions of the same name are refused.
    #[test]
    fn duplicate_entity_definitions_are_refused() {
        let errors = assert_link_fails(vec![json!("entity A;"), json!("entity A;")]);
        assert_eq!(errors.len(), 1, "unexpected errors: {errors:?}");
    }

    /// The string entry point answers the same as the JSON one.
    #[test]
    fn the_string_entry_point_agrees() {
        let call = json!({ "schemas": [
            "external entity B;\nentity A { b: B };",
            "entity B;"
        ] });
        let got: serde_json::Value = serde_json::from_str(
            &link_schemas_json_str(&serde_json::to_string(&call).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(got, link_schemas_json(call).unwrap());
    }

    /// An input that does not parse is a failure, reported before linking.
    #[test]
    fn an_unparseable_input_is_a_failure() {
        let errors = assert_link_fails(vec![json!("entity A;"), json!("external entity;")]);
        assert_eq!(errors.len(), 1, "unexpected errors: {errors:?}");
    }

    /// Every input that does not parse is reported, not just the first.
    #[test]
    fn every_unparseable_input_is_reported() {
        let errors = assert_link_fails(vec![
            json!("external entity;"),
            json!("entity A;"),
            json!("action;"),
        ]);
        assert_eq!(errors.len(), 2, "unexpected errors: {errors:?}");
    }

    /// A dangling reference within one input is a failure, as it is for a
    /// single schema.
    #[test]
    fn a_dangling_reference_is_a_failure() {
        let errors = assert_link_fails(vec![
            json!("entity A;"),
            json!("external entity B in [Undeclared];"),
        ]);
        assert_eq!(errors.len(), 1, "unexpected errors: {errors:?}");
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        assert_matches!(
            link_schemas_json(json!({ "schemas": [], "fragments": [] })),
            Err(_)
        );
    }
}
