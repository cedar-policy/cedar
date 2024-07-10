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
use crate::{PolicyId, SchemaWarning, SlotId};
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// Represents a static policy in either the Cedar or JSON policy format
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(untagged)]
#[serde(
    expecting = "expected a static policy in the Cedar or JSON policy format (with no duplicate keys)"
)]
pub enum Policy {
    /// Policy in the Cedar policy format. See <https://docs.cedarpolicy.com/policies/syntax-policy.html>
    Human(String),
    /// Policy in Cedar's JSON policy format. See <https://docs.cedarpolicy.com/policies/json-format.html>
    Json(JsonValueWithNoDuplicateKeys),
}

impl Policy {
    /// Parse a [`Policy`] into a [`crate::Policy`]. Takes an optional id
    /// argument that sets the policy id. If the argument is `None` then a
    /// default id will be assigned.
    pub(super) fn parse(self, id: Option<PolicyId>) -> Result<crate::Policy, miette::Report> {
        let msg = id
            .clone()
            .map_or(String::new(), |id| format!(" with id `{id}`"));
        match self {
            Self::Human(str) => crate::Policy::parse(id, str)
                .wrap_err(format!("failed to parse policy{msg} from string")),
            Self::Json(json) => crate::Policy::from_json(id, json.into())
                .wrap_err(format!("failed to parse policy{msg} from JSON")),
        }
    }
}

/// Represents a policy template in either the Cedar or JSON policy format
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(untagged)]
#[serde(
    expecting = "expected a policy template in the Cedar or JSON policy format (with no duplicate keys)"
)]
pub enum Template {
    /// Template in the Cedar policy format. See <https://docs.cedarpolicy.com/policies/syntax-policy.html>
    Human(String),
    /// Template in Cedar's JSON policy format. See <https://docs.cedarpolicy.com/policies/json-format.html>
    Json(JsonValueWithNoDuplicateKeys),
}

impl Template {
    /// Parse a [`Template`] into a [`crate::Template`]. Takes an optional id
    /// argument that sets the template id. If the argument is `None` then a
    /// default id will be assigned.
    pub(super) fn parse(self, id: Option<PolicyId>) -> Result<crate::Template, miette::Report> {
        let msg = id
            .clone()
            .map(|id| format!(" with id `{id}`"))
            .unwrap_or_default();
        match self {
            Self::Human(str) => crate::Template::parse(id, str)
                .wrap_err(format!("failed to parse template{msg} from string")),
            Self::Json(json) => crate::Template::from_json(id, json.into())
                .wrap_err(format!("failed to parse template{msg} from JSON")),
        }
    }

    /// Parse a [`Template`] into a [`crate::Template`] and add it into the
    /// provided [`crate::PolicySet`].
    pub(super) fn parse_and_add_to_set(
        self,
        id: Option<PolicyId>,
        policies: &mut crate::PolicySet,
    ) -> Result<(), miette::Report> {
        let msg = id
            .clone()
            .map(|id| format!(" with id `{id}`"))
            .unwrap_or_default();
        let template = self.parse(id)?;
        policies
            .add_template(template)
            .wrap_err(format!("failed to add template{msg} to policy set"))
    }
}

/// Represents a set of static policies
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(untagged)]
#[serde(
    expecting = "expected a static policy set represented by a string, JSON array, or JSON object (with no duplicate keys)"
)]
pub enum StaticPolicySet {
    /// Multiple policies as a concatenated string. Requires policies in the
    /// Cedar (non-JSON) format.
    Concatenated(String),
    /// Multiple policies as a set
    Set(Vec<Policy>),
    /// Multiple policies as a hashmap where the policy id is the key
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    Map(HashMap<PolicyId, Policy>),
}

impl StaticPolicySet {
    /// Parse a [`StaticPolicySet`] into a [`crate::PolicySet`]
    pub(super) fn parse(self) -> Result<crate::PolicySet, Vec<miette::Report>> {
        match self {
            Self::Concatenated(str) => crate::PolicySet::from_str(&str)
                .wrap_err("failed to parse policies from string")
                .map_err(|e| vec![e]),
            Self::Set(set) => {
                let mut errs = Vec::new();
                let policies = set
                    .into_iter()
                    .map(|policy| policy.parse(None))
                    .filter_map(|r| r.map_err(|e| errs.push(e)).ok())
                    .collect::<Vec<_>>();
                if errs.is_empty() {
                    crate::PolicySet::from_policies(policies).map_err(|e| vec![e.into()])
                } else {
                    Err(errs)
                }
            }
            Self::Map(map) => {
                let mut errs = Vec::new();
                let policies = map
                    .into_iter()
                    .map(|(id, policy)| policy.parse(Some(id)))
                    .filter_map(|r| r.map_err(|e| errs.push(e)).ok())
                    .collect::<Vec<_>>();
                if errs.is_empty() {
                    crate::PolicySet::from_policies(policies).map_err(|e| vec![e.into()])
                } else {
                    Err(errs)
                }
            }
        }
    }
}

impl Default for StaticPolicySet {
    fn default() -> Self {
        Self::Set(Vec::new())
    }
}

/// Represents a template-linked policy
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct TemplateLink {
    /// Id of the template to link against
    template_id: PolicyId,
    /// Id of the generated policy
    new_id: PolicyId,
    /// Values for the slots; keys must be slot ids (i.e., `?principal` or `?resource`)
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    values: HashMap<SlotId, EntityUid>,
}

impl TemplateLink {
    /// Parse a [`TemplateLink`] and add the linked policy into the provided [`crate::PolicySet`]
    pub(super) fn parse_and_add_to_set(
        self,
        policies: &mut crate::PolicySet,
    ) -> Result<(), miette::Report> {
        let values: HashMap<_, _> = self
            .values
            .into_iter()
            .map(|(slot, euid)| euid.parse(None).map(|euid| (slot, euid)))
            .collect::<Result<HashMap<_, _>, _>>()
            .wrap_err("failed to parse link values")?;
        policies
            .link(self.template_id, self.new_id, values)
            .map_err(miette::Report::new)
    }
}

/// Represents a policy set, including static policies, templates, and template links
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PolicySet {
    /// static policies
    #[serde(default)]
    static_policies: StaticPolicySet,
    /// a map from template id to template content
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    #[serde(default)]
    templates: HashMap<PolicyId, Template>,
    /// template links
    #[serde(default)]
    template_links: Vec<TemplateLink>,
}

impl PolicySet {
    /// Parse a [`PolicySet`] into a [`crate::PolicySet`]
    pub(super) fn parse(self) -> Result<crate::PolicySet, Vec<miette::Report>> {
        let mut errs = Vec::new();
        // Parse static policies
        let mut policies = self.static_policies.parse().unwrap_or_else(|mut e| {
            errs.append(&mut e);
            crate::PolicySet::new()
        });
        // Parse templates & add them to the policy set
        self.templates.into_iter().for_each(|(id, template)| {
            template
                .parse_and_add_to_set(Some(id), &mut policies)
                .unwrap_or_else(|e| errs.push(e));
        });
        // Parse template links & add the resulting policies to the policy set
        self.template_links.into_iter().for_each(|link| {
            link.parse_and_add_to_set(&mut policies)
                .unwrap_or_else(|e| errs.push(e));
        });
        // Return an error or the final policy set
        if !errs.is_empty() {
            return Err(errs);
        }
        Ok(policies)
    }

    /// Create an empty [`PolicySet`]
    #[cfg(test)]
    pub(super) fn new() -> Self {
        Self {
            static_policies: StaticPolicySet::Set(Vec::new()),
            templates: HashMap::new(),
            template_links: Vec::new(),
        }
    }
}

/// Represents a schema in either the Cedar or JSON schema format
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(untagged)]
#[serde(
    expecting = "expected a schema in the Cedar or JSON policy format (with no duplicate keys)"
)]
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
                .wrap_err("failed to parse schema from string"),
            Self::Json(val) => crate::Schema::from_json_value(val.into())
                .map(|sch| {
                    (
                        sch,
                        Box::new(std::iter::empty()) as Box<dyn Iterator<Item = SchemaWarning>>,
                    )
                })
                .wrap_err("failed to parse schema from JSON"),
        }
    }
}

pub(super) struct WithWarnings<T> {
    pub t: T,
    pub warnings: Vec<miette::Report>,
}

// PANIC SAFETY unit tests
#[allow(clippy::panic, clippy::indexing_slicing)]
// Also disable some other clippy lints that are unimportant for testing code
#[allow(clippy::module_name_repetitions, clippy::missing_panics_doc)]
#[cfg(test)]
pub mod test_utils {
    use super::*;

    /// Assert that an error has the specified message and help fields.
    #[track_caller]
    pub fn assert_error_matches(err: &DetailedError, msg: &str, help: Option<&str>) {
        assert_eq!(err.message, msg, "did not see the expected error message");
        assert_eq!(
            err.help,
            help.map(Into::into),
            "did not see the expected help message"
        );
    }

    /// Assert that a vector (of errors) has the expected length
    #[track_caller]
    pub fn assert_length_matches<T: std::fmt::Debug>(errs: &[T], n: usize) {
        assert_eq!(
            errs.len(),
            n,
            "expected {n} error(s) but saw {}",
            errs.len()
        );
    }

    /// Assert that a vector contains exactly one error with the specified
    /// message and help text.
    #[track_caller]
    pub fn assert_exactly_one_error(errs: &[DetailedError], msg: &str, help: Option<&str>) {
        assert_length_matches(errs, 1);
        assert_error_matches(&errs[0], msg, help);
    }
}

// PANIC SAFETY unit tests
#[allow(clippy::panic, clippy::indexing_slicing)]
// Also disable some other clippy lints that are unimportant for testing code
#[allow(clippy::too_many_lines)]
#[cfg(test)]
mod test {
    use super::*;
    use cedar_policy_core::test_utils::*;
    use serde_json::json;
    use test_utils::assert_length_matches;

    #[test]
    fn test_policy_parser() {
        // A string literal will be parsed as a policy in the Cedar syntax
        let policy_json = json!("permit(principal == User::\"alice\", action, resource);");
        let policy: Policy =
            serde_json::from_value(policy_json).expect("failed to parse from JSON");
        policy.parse(None).expect("failed to convert to policy");

        // A JSON object will be parsed as a policy in the JSON syntax
        let policy_json = json!({
            "effect": "permit",
            "principal": {
                "op": "==",
                "entity": { "type": "User", "id": "alice" }
            },
            "action": {
                "op": "All"
            },
            "resource": {
                "op": "All"
            },
            "conditions": []
        });
        let policy: Policy =
            serde_json::from_value(policy_json).expect("failed to parse from JSON");
        policy.parse(None).expect("failed to convert to policy");

        // Invalid Cedar syntax
        let src = "foo(principal == User::\"alice\", action, resource);";
        let policy: Policy = serde_json::from_value(json!(src)).expect("failed to parse from JSON");
        let err = policy
            .parse(None)
            .expect_err("should have failed to convert to policy");
        expect_err(
            src,
            &err,
            &ExpectedErrorMessageBuilder::error("failed to parse policy from string")
                .source("invalid policy effect: foo")
                .exactly_one_underline("foo")
                .help("effect must be either `permit` or `forbid`")
                .build(),
        );

        // Not a static policy
        let src = "permit(principal == ?principal, action, resource);";
        let policy: Policy =
            serde_json::from_value(json!(src)).expect("failed to parse from string");
        let err = policy
            .parse(None)
            .expect_err("should have failed to convert to policy");
        expect_err(
            src,
            &err,
            &ExpectedErrorMessageBuilder::error("failed to parse policy from string")
                .source("expected a static policy, got a template containing the slot ?principal")
                .exactly_one_underline(src)
                .help("try removing the template slot(s) from this policy")
                .build(),
        );

        // Not a single policy
        let src = "permit(principal == User::\"alice\", action, resource); permit(principal == User::\"bob\", action, resource);";
        let policy: Policy =
            serde_json::from_value(json!(src)).expect("failed to parse from string");
        let err = policy
            .parse(None)
            .expect_err("should have failed to convert to policy");
        expect_err(
            src,
            &err,
            &ExpectedErrorMessageBuilder::error("failed to parse policy from string")
                .source("unexpected token `permit`")
                .exactly_one_underline("permit")
                .build(),
        );

        // Invalid JSON syntax (duplicate keys)
        // The error message comes from the `serde(expecting = ..)` annotation on `Policy`
        let policy_json_str = r#"{
            "effect": "permit",
            "effect": "forbid"
        }"#;
        let err = serde_json::from_str::<Policy>(policy_json_str)
            .expect_err("should have failed to parse from JSON");
        assert_eq!(
            err.to_string(),
            "expected a static policy in the Cedar or JSON policy format (with no duplicate keys)"
        );
    }

    #[test]
    fn test_template_parser() {
        // A string literal will be parsed as a template in the Cedar syntax
        let template_json = json!("permit(principal == ?principal, action, resource);");
        let template: Template =
            serde_json::from_value(template_json).expect("failed to parse from JSON");
        template.parse(None).expect("failed to convert to template");

        // A JSON object will be parsed as a template in the JSON syntax
        let template_json = json!({
            "effect": "permit",
            "principal": {
                "op": "==",
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
        let template: Template =
            serde_json::from_value(template_json).expect("failed to parse from JSON");
        template.parse(None).expect("failed to convert to template");

        // Invalid syntax
        let src = "permit(principal == ?foo, action, resource);";
        let template: Template =
            serde_json::from_value(json!(src)).expect("failed to parse from JSON");
        let err = template
            .parse(None)
            .expect_err("should have failed to convert to template");
        expect_err(
            src,
            &err,
            &ExpectedErrorMessageBuilder::error("failed to parse template from string")
                .source("expected an entity uid or matching template slot, found ?foo instead of ?principal")
                .exactly_one_underline("?foo")
                .build(),
        );

        // Static policies can also be parsed as templates
        let template_json = json!("permit(principal == User::\"alice\", action, resource);");
        let template: Template =
            serde_json::from_value(template_json).expect("failed to parse from JSON");
        template.parse(None).expect("failed to convert to template");
    }

    #[test]
    fn test_static_policy_set_parser() {
        // A string literal will be parsed as the `Concatenated` variant
        let policies_json = json!("permit(principal == User::\"alice\", action, resource);");
        let policies: StaticPolicySet =
            serde_json::from_value(policies_json).expect("failed to parse from JSON");
        policies
            .parse()
            .expect("failed to convert to static policy set");

        // A JSON array will be parsed as the `Set` variant
        let policies_json = json!([
            {
                "effect": "permit",
                "principal": {
                    "op": "==",
                    "entity": { "type": "User", "id": "alice" }
                },
                "action": {
                    "op": "All"
                },
                "resource": {
                    "op": "All"
                },
                "conditions": []
            },
            "permit(principal == User::\"bob\", action, resource);"
        ]);
        let policies: StaticPolicySet =
            serde_json::from_value(policies_json).expect("failed to parse from JSON");
        policies
            .parse()
            .expect("failed to convert to static policy set");

        // A JSON object will be parsed as the `Map` variant
        let policies_json = json!({
            "policy0": {
                "effect": "permit",
                "principal": {
                    "op": "==",
                    "entity": { "type": "User", "id": "alice" }
                },
                "action": {
                    "op": "All"
                },
                "resource": {
                    "op": "All"
                },
                "conditions": []
            },
            "policy1": "permit(principal == User::\"bob\", action, resource);"
        });
        let policies: StaticPolicySet =
            serde_json::from_value(policies_json).expect("failed to parse from JSON");
        policies
            .parse()
            .expect("failed to convert to static policy set");

        // Invalid static policy set - `policy0` is a template
        let policies_json = json!({
            "policy0": "permit(principal == ?principal, action, resource);",
            "policy1": "permit(principal == User::\"bob\", action, resource);"
        });
        let policies: StaticPolicySet =
            serde_json::from_value(policies_json).expect("failed to parse from JSON");
        let errs = policies
            .parse()
            .expect_err("should have failed to convert to static policy set");
        assert_length_matches(&errs, 1);
        expect_err(
            "permit(principal == ?principal, action, resource);",
            &errs[0],
            &ExpectedErrorMessageBuilder::error(
                "failed to parse policy with id `policy0` from string",
            )
            .source("expected a static policy, got a template containing the slot ?principal")
            .exactly_one_underline("permit(principal == ?principal, action, resource);")
            .help("try removing the template slot(s) from this policy")
            .build(),
        );

        // Invalid static policy set - `policy1` is actually multiple policies
        let policies_json = json!({
            "policy0": "permit(principal == User::\"alice\", action, resource);",
            "policy1": "permit(principal == User::\"bob\", action, resource); permit(principal, action, resource);"
        });
        let policies: StaticPolicySet =
            serde_json::from_value(policies_json).expect("failed to parse from JSON");
        let errs = policies
            .parse()
            .expect_err("should have failed to convert to static policy set");
        assert_length_matches(&errs, 1);
        expect_err(
            "permit(principal == User::\"bob\", action, resource); permit(principal, action, resource);",
            &errs[0],
            &ExpectedErrorMessageBuilder::error(
                "failed to parse policy with id `policy1` from string",
            )
            .source("unexpected token `permit`")
            .exactly_one_underline("permit")
            .build(),
        );

        // Invalid static policy set - both policies are ill-formed
        let policies_json = json!({
            "policy0": "permit(principal, action);",
            "policy1": "forbid(principal, action);"
        });
        let policies: StaticPolicySet =
            serde_json::from_value(policies_json).expect("failed to parse from JSON");
        let errs = policies
            .parse()
            .expect_err("should have failed to convert to static policy set");
        assert_length_matches(&errs, 2);
        for err in errs {
            // hack to account for nondeterministic error ordering
            if err
                .to_string()
                .contains("failed to parse policy with id `policy0`")
            {
                expect_err(
                "permit(principal, action);",
                &err,
                &ExpectedErrorMessageBuilder::error(
                        "failed to parse policy with id `policy0` from string",
                    )
                    .source("this policy is missing the `resource` variable in the scope")
                    .exactly_one_underline("")
                    .help("policy scopes must contain a `principal`, `action`, and `resource` element in that order")
                    .build(),
            );
            } else {
                expect_err(
                "forbid(principal, action);",
                &err,
                &ExpectedErrorMessageBuilder::error(
                        "failed to parse policy with id `policy1` from string",
                    )
                    .source("this policy is missing the `resource` variable in the scope")
                    .exactly_one_underline("")
                    .help("policy scopes must contain a `principal`, `action`, and `resource` element in that order")
                    .build(),
            );
            }
        }
    }

    #[test]
    fn test_policy_set_parser() {
        // Empty policy set
        let policies_json = json!({});
        let policies: PolicySet =
            serde_json::from_value(policies_json).expect("failed to parse from JSON");
        policies.parse().expect("failed to convert to policy set");

        // Example valid policy set
        let policies_json = json!({
            "staticPolicies": [
                {
                    "effect": "permit",
                    "principal": {
                        "op": "==",
                        "entity": { "type": "User", "id": "alice" }
                    },
                    "action": {
                        "op": "All"
                    },
                    "resource": {
                        "op": "All"
                    },
                    "conditions": []
                },
                "permit(principal == User::\"bob\", action, resource);"
            ],
            "templates": {
                "ID0": "permit(principal == ?principal, action, resource);"
            },
            "templateLinks": [
                {
                    "templateId": "ID0",
                    "newId": "ID1",
                    "values": { "?principal": { "type": "User", "id": "charlie" } }
                }
            ]
        });
        let policies: PolicySet =
            serde_json::from_value(policies_json).expect("failed to parse from JSON");
        policies.parse().expect("failed to convert to policy set");

        // Example policy set with a link error - `policy0` is already used
        let policies_json = json!({
            "staticPolicies": {
                "policy0": "permit(principal == User::\"alice\", action, resource);",
                "policy1": "permit(principal == User::\"bob\", action, resource);"
            },
            "templates": {
                "template": "permit(principal == ?principal, action, resource);"
            },
            "templateLinks": [
                {
                    "templateId": "template",
                    "newId": "policy0",
                    "values": { "?principal": { "type": "User", "id": "charlie" } }
                }
            ]
        });
        let policies: PolicySet =
            serde_json::from_value(policies_json).expect("failed to parse from JSON");
        let errs = policies
            .parse()
            .expect_err("should have failed to convert to policy set");
        assert_length_matches(&errs, 1);
        expect_err(
            "",
            &errs[0],
            &ExpectedErrorMessageBuilder::error("unable to link template")
                .source("template-linked policy id `policy0` conflicts with an existing policy id")
                .build(),
        );
    }

    #[test]
    fn policy_set_parser_is_compatible_with_est_parser() {
        // The `PolicySet::parse` function accepts the `est::PolicySet` JSON format
        let json = json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": {
                        "op": "==",
                        "entity": { "type": "User", "id": "alice" }
                    },
                    "action": {
                        "op": "==",
                        "entity": { "type": "Action", "id": "view" }
                    },
                    "resource": {
                        "op": "in",
                        "entity": { "type": "Folder", "id": "foo" }
                    },
                    "conditions": []
                }
            },
            "templates": {
                "template": {
                    "effect" : "permit",
                    "principal" : {
                        "op" : "==",
                        "slot" : "?principal"
                    },
                    "action" : {
                        "op" : "all"
                    },
                    "resource" : {
                        "op" : "all",
                    },
                    "conditions": []
                }
            },
            "templateLinks" : [
                {
                    "newId" : "link",
                    "templateId" : "template",
                    "values" : {
                        "?principal" : { "type" : "User", "id" : "bob" }
                    }
                }
            ]
        });

        // use `crate::PolicySet::from_json_value`
        let ast_from_est = crate::PolicySet::from_json_value(json.clone())
            .expect("failed to convert to policy set");

        // use `PolicySet::parse`
        let ffi_policy_set: PolicySet =
            serde_json::from_value(json).expect("failed to parse from JSON");
        let ast_from_ffi = ffi_policy_set
            .parse()
            .expect("failed to convert to policy set");

        // check that the produced policy sets match
        assert_eq!(ast_from_est, ast_from_ffi);
    }

    #[test]
    fn test_schema_parser() {
        // A string literal will be parsed as a schema in the Cedar syntax
        let schema_json = json!("entity User = {name: String};\nentity Photo;\naction viewPhoto appliesTo {principal: User, resource: Photo};");
        let schema: Schema =
            serde_json::from_value(schema_json).expect("failed to parse from JSON");
        let _ = schema.parse().expect("failed to convert to schema");

        // A JSON object will be parsed as a schema in the JSON syntax
        let schema_json = json!({
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
        });
        let schema: Schema =
            serde_json::from_value(schema_json).expect("failed to parse from JSON");
        let _ = schema.parse().expect("failed to convert to schema");

        // Invalid syntax (the value is a policy)
        let src = "permit(principal == User::\"alice\", action, resource);";
        let schema: Schema = serde_json::from_value(json!(src)).expect("failed to parse from JSON");
        let err = schema
            .parse()
            .map(|(s, _)| s)
            .expect_err("should have failed to convert to schema");
        expect_err(
            src,
            &err,
            &ExpectedErrorMessageBuilder::error("failed to parse schema from string")
                .exactly_one_underline_with_label(
                    "permit",
                    "expected `action`, `entity`, `namespace`, or `type`",
                )
                .source("error parsing schema: unexpected token `permit`")
                .build(),
        );
    }
}
