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

//! Utility functions and types for JSON interface
use crate::{Policy, SchemaWarning, Template};
use miette::WrapErr;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr};

// Publicly expose the `JsonValueWithNoDuplicateKeys` type so that the
// `*_json_str` APIs will correctly error if the input JSON string contains
// duplicate keys.
pub use cedar_policy_core::jsonvalue::JsonValueWithNoDuplicateKeys;

#[cfg(feature = "wasm")]
extern crate tsify;

/// Structure of the JSON output representing one `miette` error
#[derive(Debug, PartialEq, Eq, Clone, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct DetailedError {
    /// Main error message, including both the `miette` "message" and the
    /// `miette` "causes" (uses `miette`'s default `Display` output)
    pub message: String,
    /// Help message, providing additional information about the error or help resolving it
    pub help: Option<String>,
    /// Error code
    pub code: Option<String>,
    /// URL for more information about the error
    pub url: Option<String>,
    /// Severity
    pub severity: Option<Severity>,
    /// Source labels (ranges)
    #[serde(default)]
    pub source_locations: Vec<SourceLabel>,
    /// Related errors
    #[serde(default)]
    pub related: Vec<DetailedError>,
}

/// Exactly like `miette::Severity` but implements `Hash`
///
/// If `miette::Severity` adds `derive(Hash)` in the future, we can remove this
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    /// Advice (the lowest severity)
    Advice,
    /// Warning
    Warning,
    /// Error (the highest severity)
    Error,
}

impl From<miette::Severity> for Severity {
    fn from(severity: miette::Severity) -> Self {
        match severity {
            miette::Severity::Advice => Self::Advice,
            miette::Severity::Warning => Self::Warning,
            miette::Severity::Error => Self::Error,
        }
    }
}

/// Structure of the JSON output representing a `miette` source label (range)
#[derive(Debug, PartialEq, Eq, Clone, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct SourceLabel {
    /// Text of the label (if any)
    pub label: Option<String>,
    /// Source location (range) of the label
    #[serde(flatten)]
    pub loc: SourceLocation,
}

/// A range of source code representing the location of an error or warning.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct SourceLocation {
    /// Start of the source location (in bytes)
    pub start: usize,
    /// End of the source location (in bytes)
    pub end: usize,
}

impl From<miette::LabeledSpan> for SourceLabel {
    fn from(span: miette::LabeledSpan) -> Self {
        Self {
            label: span.label().map(ToString::to_string),
            loc: SourceLocation {
                start: span.offset(),
                end: span.offset() + span.len(),
            },
        }
    }
}

impl<'a, E: miette::Diagnostic + ?Sized> From<&'a E> for DetailedError {
    fn from(diag: &'a E) -> Self {
        Self {
            message: {
                let mut s = diag.to_string();
                let mut source = diag.source();
                while let Some(e) = source {
                    s.push_str(": ");
                    s.push_str(&e.to_string());
                    source = e.source();
                }
                s
            },
            help: diag.help().map(|h| h.to_string()),
            code: diag.code().map(|c| c.to_string()),
            url: diag.url().map(|u| u.to_string()),
            severity: diag.severity().map(Into::into),
            source_locations: diag
                .labels()
                .map(|labels| labels.map(Into::into).collect())
                .unwrap_or_default(),
            related: diag
                .related()
                .map(|errs| errs.map(std::convert::Into::into).collect())
                .unwrap_or_default(),
        }
    }
}

impl From<miette::Report> for DetailedError {
    fn from(report: miette::Report) -> Self {
        let diag: &dyn miette::Diagnostic = report.as_ref();
        diag.into()
    }
}

/// Wrapper around a JSON value describing an entity uid in either explicit or
/// implicit `__entity` form. Expects the same format as [`crate::EntityUid::from_json`].
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[repr(transparent)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct EntityUid(
    #[cfg_attr(feature = "wasm", tsify(type = "EntityUidJson"))] JsonValueWithNoDuplicateKeys,
);

impl EntityUid {
    /// Parses the given [`EntityUid`] into a [`crate::EntityUid`].
    /// `category` is an optional note on the type of entity uid being parsed
    /// for better error messages.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input JSON cannot be deserialized as a
    /// [`crate::EntityUid`].
    pub fn parse(self, category: Option<&str>) -> Result<crate::EntityUid, miette::Report> {
        crate::EntityUid::from_json(self.0.into())
            .wrap_err_with(|| format!("failed to parse {}", category.unwrap_or("entity uid")))
    }
}

#[doc(hidden)]
impl From<serde_json::Value> for EntityUid {
    fn from(json: serde_json::Value) -> Self {
        Self(json.into())
    }
}

/// Wrapper around a JSON value describing a context. Expects the same format
/// as [`crate::Context::from_json_value`].
/// See <https://docs.cedarpolicy.com/auth/entities-syntax.html>
#[derive(Debug, Serialize, Deserialize)]
#[repr(transparent)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct Context(
    #[cfg_attr(feature = "wasm", tsify(type = "Record<string, CedarValueJson>"))]
    JsonValueWithNoDuplicateKeys,
);

impl Context {
    /// Parses the given [`Context`] into a [`crate::Context`]
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input JSON cannot be deserialized as a
    /// [`crate::Context`].
    pub fn parse(
        self,
        schema_ref: Option<&crate::Schema>,
        action_ref: Option<&crate::EntityUid>,
    ) -> Result<crate::Context, miette::Report> {
        crate::Context::from_json_value(
            self.0.into(),
            match (schema_ref, action_ref) {
                (Some(s), Some(a)) => Some((s, a)),
                _ => None,
            },
        )
        .map_err(Into::into)
    }
}

#[doc(hidden)]
impl From<serde_json::Value> for Context {
    fn from(json: serde_json::Value) -> Self {
        Self(json.into())
    }
}

/// Wrapper around a JSON value describing a set of entities. Expects the same
/// format as [`crate::Entities::from_json_value`].
/// See <https://docs.cedarpolicy.com/auth/entities-syntax.html>
#[derive(Debug, Serialize, Deserialize)]
#[repr(transparent)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct Entities(
    #[cfg_attr(feature = "wasm", tsify(type = "Array<EntityJson>"))] JsonValueWithNoDuplicateKeys,
);

impl Entities {
    /// Parses the given [`Entities`] into a [`crate::Entities`]
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input JSON cannot be deserialized as a
    /// [`crate::Entities`].
    pub fn parse(
        self,
        opt_schema: Option<&crate::Schema>,
    ) -> Result<crate::Entities, miette::Report> {
        crate::Entities::from_json_value(self.0.into(), opt_schema).map_err(Into::into)
    }
}

#[doc(hidden)]
impl From<serde_json::Value> for Entities {
    fn from(json: serde_json::Value) -> Self {
        Self(json.into())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(
    expecting = "policies as a concatenated string or multiple policies as a hashmap where the policy id is the key"
)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
/// Struct defining the two possible ways to pass a set of policies to `is_authorized_json` and `validate_json`
pub enum PolicySet {
    /// provides multiple policies as a concatenated string
    Concatenated(String),
    /// provides multiple policies as a hashmap where the policyId is the key
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    Map(HashMap<String, String>),
}

fn parse_policy_set_from_individual_policies(
    policies: &HashMap<String, String>,
    templates: Option<HashMap<String, String>>,
) -> Result<crate::PolicySet, Vec<miette::Report>> {
    let mut policy_set = crate::PolicySet::new();
    let mut errs = Vec::new();
    for (id, policy_src) in policies {
        match Policy::parse(Some(id.clone()), policy_src)
            .wrap_err_with(|| format!("failed to parse policy with id `{id}`"))
        {
            Ok(p) => match policy_set
                .add(p)
                .wrap_err_with(|| format!("failed to add policy with id `{id}` to policy set"))
            {
                Ok(()) => {}
                Err(e) => {
                    errs.push(e);
                }
            },
            Err(e) => {
                errs.push(e);
            }
        }
    }

    if let Some(templates) = templates {
        for (id, policy_src) in templates {
            match Template::parse(Some(id.clone()), policy_src)
                .wrap_err_with(|| format!("failed to parse template with id `{id}`"))
            {
                Ok(p) => match policy_set.add_template(p).wrap_err_with(|| {
                    format!("failed to add template with id `{id}` to policy set")
                }) {
                    Ok(()) => {}
                    Err(e) => {
                        errs.push(e);
                    }
                },
                Err(e) => errs.push(e),
            }
        }
    }

    if errs.is_empty() {
        Ok(policy_set)
    } else {
        Err(errs)
    }
}

impl PolicySet {
    /// Parse the `PolicySet` into a `crate::PolicySet`.
    pub(super) fn parse(
        self,
        templates: Option<HashMap<String, String>>,
    ) -> Result<crate::PolicySet, Vec<miette::Report>> {
        match self {
            Self::Concatenated(policies) => crate::PolicySet::from_str(&policies)
                .wrap_err("failed to parse policies from string")
                .map_err(|e| vec![e]),
            Self::Map(policies) => parse_policy_set_from_individual_policies(&policies, templates),
        }
    }
}

/// Represents a schema in either the Cedar or JSON schema format
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub enum Schema {
    /// Schema in the Cedar schema format. See <https://docs.cedarpolicy.com/schema/human-readable-schema.html>
    Human(String),
    /// Schema in Cedar's JSON schema format. See <https://docs.cedarpolicy.com/schema/json-schema.html>
    Json(JsonValueWithNoDuplicateKeys),
}

impl Schema {
    pub(super) fn parse(
        self,
    ) -> Result<(crate::Schema, Box<dyn Iterator<Item = SchemaWarning>>), miette::Report> {
        match self {
            Self::Human(str) => crate::Schema::from_str_natural(&str)
                .map(|(sch, warnings)| {
                    (
                        sch,
                        Box::new(warnings) as Box<dyn Iterator<Item = SchemaWarning>>,
                    )
                })
                .map_err(miette::Report::new),
            Self::Json(val) => crate::Schema::from_json_value(val.into())
                .map(|sch| {
                    (
                        sch,
                        Box::new(std::iter::empty()) as Box<dyn Iterator<Item = SchemaWarning>>,
                    )
                })
                .map_err(miette::Report::new),
        }
    }
}

pub(super) struct WithWarnings<T> {
    pub t: T,
    pub warnings: Vec<miette::Report>,
}

// PANIC SAFETY unit tests
#[allow(clippy::panic)]
#[cfg(test)]
mod test {
    use super::*;
    use cedar_policy_core::test_utils::*;
    use serde_json::json;

    #[test]
    fn test_schema_parser() {
        // Cedar syntax
        let schema_json = json!({
            "human": "entity User = { name: String};\nentity Photo;\naction viewPhoto appliesTo { principal: User, resource: Photo };"
        });
        let schema: Schema =
            serde_json::from_value(schema_json).expect("failed to parse from JSON");
        let _ = schema.parse().expect("failed to convert to schema");

        // JSON syntax
        let schema_json = json!({
            "json": {
                "": {
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "name": {
                                        "type": "String"
                                    }
                                }
                            }
                        },
                        "Photo": {}
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": [ "User" ],
                                "resourceTypes": [ "Photo" ]
                            }
                        }
                    }
                }
            }
        });
        let schema: Schema =
            serde_json::from_value(schema_json).expect("failed to parse from JSON");
        let _ = schema.parse().expect("failed to convert to schema");

        // Invalid syntax (the value is a policy)
        let schema_json = json!({
            "human": "permit(principal == User::\"alice\", action, resource);"
        });
        let schema: Schema =
            serde_json::from_value(schema_json).expect("failed to parse from JSON");
        let err = schema
            .parse()
            .map(|(s, _)| s)
            .expect_err("should have failed to convert to schema");
        expect_err(
            "permit(principal == User::\"alice\", action, resource);",
            &err,
            &ExpectedErrorMessageBuilder::error(
                r#"error parsing schema: unexpected token `permit`"#,
            )
            .exactly_one_underline_with_label(
                "permit",
                "expected `action`, `entity`, `namespace`, or `type`",
            )
            .build(),
        );
    }
}
