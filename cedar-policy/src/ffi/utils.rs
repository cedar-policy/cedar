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

/// Structure of the JSON output representing one `miette` error
#[derive(Debug, PartialEq, Eq, Clone, Hash, Deserialize, Serialize)]
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
    pub labels: Vec<SourceLabel>,
    /// Related errors
    pub related: Vec<DetailedError>,
}

/// Exactly like `miette::Severity` but implements `Hash`
///
/// If `miette::Severity` adds `derive(Hash)` in the future, we can remove this
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Deserialize, Serialize)]
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
pub struct SourceLabel {
    /// Text of the label (if any)
    pub label: Option<String>,
    /// Source span (range) of the label
    pub span: SourceSpan,
}

/// Structure of the JSON output representing a `miette` source span (range)
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Deserialize, Serialize)]
pub struct SourceSpan {
    /// Start of the source span (in bytes)
    pub offset: usize,
    /// Length of the source span (in bytes)
    pub length: usize,
}

impl From<miette::LabeledSpan> for SourceLabel {
    fn from(span: miette::LabeledSpan) -> Self {
        Self {
            label: span.label().map(ToString::to_string),
            span: SourceSpan {
                offset: span.offset(),
                length: span.len(),
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
            labels: diag
                .labels()
                .map(|labels| labels.map(Into::into).collect())
                .unwrap_or_else(|| vec![]),
            related: diag
                .related()
                .map(|errs| errs.map(|e| e.into()).collect())
                .unwrap_or_else(|| vec![]),
        }
    }
}

impl From<miette::Report> for DetailedError {
    fn from(report: miette::Report) -> Self {
        let diag: &dyn miette::Diagnostic = report.as_ref();
        diag.into()
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
