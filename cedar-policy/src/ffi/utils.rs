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
use cedar_policy_core::jsonvalue::JsonValueWithNoDuplicateKeys;
use miette::WrapErr;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr};

#[cfg(feature = "wasm")]
extern crate tsify;

thread_local!(
    /// miette JSON report handler
    static JSON_REPORT_HANDLER: miette::JSONReportHandler = miette::JSONReportHandler::new();
);

/// Structure of the JSON output representing one `miette` error, produced by
/// [`miette::JSONReportHandler`](https://docs.rs/miette/latest/miette/struct.JSONReportHandler.html).
#[derive(Debug, PartialEq, Eq, Clone, Hash, Deserialize, Serialize)]
pub struct MietteJsonError {
    /// Main error message. But see `full_error_message()`, which you might want to use instead
    pub message: String,
    /// Help message, providing additional information about the error or help resolving it
    pub help: Option<String>,
    /// Error code
    pub code: Option<String>,
    /// URL for more information about the error
    pub url: Option<String>,
    /// Severity
    pub severity: MietteSeverity,
    /// Causes
    pub causes: Vec<String>,
    /// Source labels (ranges)
    pub labels: Vec<MietteSourceLabel>,
    /// Related errors
    pub related: Vec<MietteJsonError>,
}

impl MietteJsonError {
    /// The full error message, including `message` and `causes` (but not
    /// `help`, which is often rendered separately)
    pub fn full_error_message(&self) -> String {
        let mut s = self.message.clone();
        for cause in &self.causes {
            s.push_str(": ");
            s.push_str(cause);
        }
        s
    }
}

/// Severity levels produced by `miette` in its JSON format
///
/// We can't just use `miette::Severity` because that serializes with
/// capitalized labels like `Error`, while miette's JSON format uses
/// uncapitalized ones like `error`
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Deserialize, Serialize)]
pub enum MietteSeverity {
    /// Advice (the lowest severity)
    #[serde(rename = "advice")]
    Advice,
    /// Warning
    #[serde(rename = "warning")]
    Warning,
    /// Error (the highest severity)
    #[serde(rename = "error")]
    Error,
}

/// Structure of the JSON output representing a `miette` source label (range), produced by
/// [`miette::JSONReportHandler`](https://docs.rs/miette/latest/miette/struct.JSONReportHandler.html).
#[derive(Debug, PartialEq, Eq, Clone, Hash, Deserialize, Serialize)]
pub struct MietteSourceLabel {
    /// Text of the label (may be empty)
    label: String,
    /// Source span (range) of the label
    span: MietteSourceSpan,
}

/// Structure of the JSON output representing a `miette` source span (range), produced by
/// [`miette::JSONReportHandler`](https://docs.rs/miette/latest/miette/struct.JSONReportHandler.html).
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Deserialize, Serialize)]
pub struct MietteSourceSpan {
    /// Start of the source span (presumably in bytes?)
    offset: usize,
    /// Length of the source span (presumably in bytes?)
    length: usize,
}

impl From<miette::Report> for MietteJsonError {
    fn from(report: miette::Report) -> Self {
        let mut json_str = String::new();
        JSON_REPORT_HANDLER.with(|json_handler| {
            json_handler
                .render_report(&mut json_str, report.as_ref())
                .expect("miette rendering as JSON should not fail")
        });
        serde_json::from_str(&json_str).unwrap_or_else(|e| {
            panic!("failed to parse miette JSON output: {e}\nJSON was {json_str}")
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(
    expecting = "policies as a concatenated string or multiple policies as a hashmap where the policy id is the key"
)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
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

/// Represents a schema in either schema format
#[derive(Debug, Serialize, Deserialize)]
pub enum Schema {
    /// Schema in the Cedar schema format. See <https://docs.cedarpolicy.com/schema/human-readable-schema.html>
    #[serde(rename = "human")]
    Human(String),
    /// Schema in Cedar's JSON schema format. See <https://docs.cedarpolicy.com/schema/json-schema.html>
    #[serde(rename = "json")]
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
