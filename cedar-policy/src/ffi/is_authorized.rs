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

//! This module contains the `is_authorized` entry points that other language
//! FFIs can call
#![allow(clippy::module_name_repetitions)]
use super::utils::{DetailedError, PolicySet, Schema, WithWarnings};
use crate::{
    Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, PolicyId,
    Request, SlotId,
};
use cedar_policy_core::jsonvalue::JsonValueWithNoDuplicateKeys;
use itertools::Itertools;
use miette::{miette, Diagnostic, WrapErr};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, MapPreventDuplicates};
use smol_str::{SmolStr, ToSmolStr};
use std::collections::{HashMap, HashSet};
#[cfg(feature = "partial-eval")]
use std::convert::Infallible;
use std::str::FromStr;
use thiserror::Error;

#[cfg(feature = "wasm")]
extern crate tsify;

thread_local!(
    /// Per-thread authorizer instance, initialized on first use
    static AUTHORIZER: Authorizer = Authorizer::new();
);

/// Basic interface, using [`AuthorizationCall`] and [`AuthorizationAnswer`] types
pub fn is_authorized(call: AuthorizationCall) -> AuthorizationAnswer {
    match call.get_components() {
        WithWarnings {
            t: Ok((request, policies, entities)),
            warnings,
        } => AuthorizationAnswer::Success {
            response: AUTHORIZER.with(|authorizer| {
                authorizer
                    .is_authorized(&request, &policies, &entities)
                    .into()
            }),
            warnings: warnings.into_iter().map(Into::into).collect(),
        },
        WithWarnings {
            t: Err(errors),
            warnings,
        } => AuthorizationAnswer::Failure {
            errors: errors.into_iter().map(Into::into).collect(),
            warnings: warnings.into_iter().map(Into::into).collect(),
        },
    }
}

/// Input is a JSON encoding of [`AuthorizationCall`] and output is a JSON
/// encoding of [`AuthorizationAnswer`]
pub fn is_authorized_json(json: serde_json::Value) -> Result<serde_json::Value, serde_json::Error> {
    let ans = is_authorized(serde_json::from_value(json)?);
    serde_json::to_value(ans)
}

/// Input and output are strings containing serialized JSON, in the shapes
/// expected by [`is_authorized_json()`]
pub fn is_authorized_json_str(json: &str) -> Result<String, serde_json::Error> {
    let ans = is_authorized(serde_json::from_str(json)?);
    serde_json::to_string(&ans)
}

/// Basic interface for partial evaluation, using `AuthorizationCall` and
/// `PartialAuthorizationAnswer` types
#[doc = include_str!("../../experimental_warning.md")]
#[cfg(feature = "partial-eval")]
pub fn is_authorized_partial(call: AuthorizationCall) -> PartialAuthorizationAnswer {
    match call.get_components_partial() {
        WithWarnings {
            t: Ok((request, policies, entities)),
            warnings,
        } => {
            let response = AUTHORIZER.with(|authorizer| {
                authorizer.is_authorized_partial(&request, &policies, &entities)
            });
            let warnings = warnings.into_iter().map(Into::into).collect();
            match ResidualResponse::try_from(response) {
                Ok(response) => PartialAuthorizationAnswer::Residuals {
                    response: Box::new(response),
                    warnings,
                },
                Err(e) => PartialAuthorizationAnswer::Failure {
                    errors: vec![miette::Report::new_boxed(e).into()],
                    warnings,
                },
            }
        }
        WithWarnings {
            t: Err(errors),
            warnings,
        } => PartialAuthorizationAnswer::Failure {
            errors: errors.into_iter().map(Into::into).collect(),
            warnings: warnings.into_iter().map(Into::into).collect(),
        },
    }
}

/// Input is a JSON encoding of [`AuthorizationCall`] and output is a JSON
/// encoding of [`PartialAuthorizationAnswer`]
#[doc = include_str!("../../experimental_warning.md")]
#[cfg(feature = "partial-eval")]
pub fn is_authorized_partial_json(
    json: serde_json::Value,
) -> Result<serde_json::Value, serde_json::Error> {
    let ans = is_authorized_partial(serde_json::from_value(json)?);
    serde_json::to_value(ans)
}

/// Input and output are strings containing serialized JSON, in the shapes
/// expected by [`is_authorized_partial_json()`]
#[doc = include_str!("../../experimental_warning.md")]
#[cfg(feature = "partial-eval")]
pub fn is_authorized_partial_json_str(json: &str) -> Result<String, serde_json::Error> {
    let ans = is_authorized_partial(serde_json::from_str(json)?);
    serde_json::to_string(&ans)
}

/// Interface version of a `Response` that uses the interface version of `Diagnostics`
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct Response {
    /// Authorization decision
    decision: Decision,
    /// Diagnostics providing more information on how this decision was reached
    diagnostics: Diagnostics,
}

/// Interface version of `Diagnostics` that stores error messages and warnings
/// in the `DetailedError` format
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct Diagnostics {
    /// `PolicyId`s of the policies that contributed to the decision.
    /// If no policies applied to the request, this set will be empty.
    #[cfg_attr(feature = "wasm", tsify(type = "Set<String>"))]
    reason: HashSet<PolicyId>,
    /// Set of errors that occurred
    errors: HashSet<AuthorizationError>,
}

impl Response {
    /// Construct a `Response`
    pub fn new(
        decision: Decision,
        reason: HashSet<PolicyId>,
        errors: HashSet<AuthorizationError>,
    ) -> Self {
        Self {
            decision,
            diagnostics: Diagnostics { reason, errors },
        }
    }

    /// Get the authorization decision
    pub fn decision(&self) -> Decision {
        self.decision
    }

    /// Get the authorization diagnostics
    pub fn diagnostics(&self) -> &Diagnostics {
        &self.diagnostics
    }
}

impl From<crate::Response> for Response {
    fn from(response: crate::Response) -> Self {
        let (reason, errors) = response.diagnostics.into_components();
        Self::new(
            response.decision,
            reason.collect(),
            errors.map(Into::into).collect(),
        )
    }
}

#[cfg(feature = "partial-eval")]
impl TryFrom<crate::PartialResponse> for Response {
    type Error = Infallible;

    fn try_from(partial_response: crate::PartialResponse) -> Result<Self, Self::Error> {
        Ok(partial_response.concretize().into())
    }
}

impl Diagnostics {
    /// Get the policies that contributed to the decision
    pub fn reason(&self) -> impl Iterator<Item = &PolicyId> {
        self.reason.iter()
    }

    /// Get the errors
    pub fn errors(&self) -> impl Iterator<Item = &AuthorizationError> + '_ {
        self.errors.iter()
    }
}

/// Error (or warning) which occurred in a particular policy during authorization
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationError {
    /// Id of the policy where the error (or warning) occurred
    pub policy_id: SmolStr,
    /// Error (or warning).
    /// You can look at the `severity` field to see whether it is actually an
    /// error or a warning.
    pub error: DetailedError,
}

impl AuthorizationError {
    /// Create an `AuthorizationError` from a policy ID and any `miette` error
    pub fn new(
        policy_id: impl Into<SmolStr>,
        error: impl miette::Diagnostic + Send + Sync + 'static,
    ) -> Self {
        Self::new_from_report(policy_id, miette::Report::new(error))
    }

    /// Create an `AuthorizationError` from a policy ID and a `miette::Report`
    pub fn new_from_report(policy_id: impl Into<SmolStr>, report: miette::Report) -> Self {
        Self {
            policy_id: policy_id.into(),
            error: report.into(),
        }
    }
}

impl From<crate::AuthorizationError> for AuthorizationError {
    fn from(e: crate::AuthorizationError) -> Self {
        match e {
            crate::AuthorizationError::PolicyEvaluationError { id, error } => {
                Self::new(id.to_smolstr(), error)
            }
        }
    }
}

#[doc(hidden)]
impl From<cedar_policy_core::authorizer::AuthorizationError> for AuthorizationError {
    fn from(e: cedar_policy_core::authorizer::AuthorizationError) -> Self {
        crate::AuthorizationError::from(e).into()
    }
}

/// FFI version of a [`crate::PartialResponse`]
#[doc = include_str!("../../experimental_warning.md")]
#[cfg(feature = "partial-eval")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct ResidualResponse {
    decision: Option<Decision>,
    satisfied: HashSet<PolicyId>,
    errored: HashSet<PolicyId>,
    may_be_determining: HashSet<PolicyId>,
    must_be_determining: HashSet<PolicyId>,
    residuals: HashMap<PolicyId, serde_json::Value>,
    nontrivial_residuals: HashSet<PolicyId>,
}

#[cfg(feature = "partial-eval")]
impl ResidualResponse {
    /// Tri-state decision
    pub fn decision(&self) -> Option<Decision> {
        self.decision
    }

    /// Set of all satisfied policy Ids
    pub fn satisfied(&self) -> impl Iterator<Item = &PolicyId> {
        self.satisfied.iter()
    }

    /// Set of all policy ids for policies that errored
    pub fn errored(&self) -> impl Iterator<Item = &PolicyId> {
        self.errored.iter()
    }

    /// Over approximation of policies that determine the auth decision
    pub fn may_be_determining(&self) -> impl Iterator<Item = &PolicyId> {
        self.may_be_determining.iter()
    }

    /// Under approximation of policies that determine the auth decision
    pub fn must_be_determining(&self) -> impl Iterator<Item = &PolicyId> {
        self.must_be_determining.iter()
    }

    /// (Borrowed) Iterator over the set of residual policies
    pub fn residuals(&self) -> impl Iterator<Item = &serde_json::Value> {
        self.residuals.values()
    }

    /// (Owned) Iterator over the set of residual policies
    pub fn into_residuals(self) -> impl Iterator<Item = serde_json::Value> {
        self.residuals.into_values()
    }

    /// Get the residual policy for a specified [`PolicyId`] if it exists
    pub fn residual(&self, p: &PolicyId) -> Option<&serde_json::Value> {
        self.residuals.get(p)
    }

    /// (Borrowed) Iterator over the set of non-trivial residual policies
    pub fn nontrivial_residuals(&self) -> impl Iterator<Item = &serde_json::Value> {
        self.residuals.iter().filter_map(|(id, policy)| {
            if self.nontrivial_residuals.contains(id) {
                Some(policy)
            } else {
                None
            }
        })
    }

    ///  Iterator over the set of non-trivial residual policy ids
    pub fn nontrivial_residual_ids(&self) -> impl Iterator<Item = &PolicyId> {
        self.nontrivial_residuals.iter()
    }
}

#[cfg(feature = "partial-eval")]
impl TryFrom<crate::PartialResponse> for ResidualResponse {
    type Error = Box<dyn miette::Diagnostic + Send + Sync + 'static>;

    fn try_from(partial_response: crate::PartialResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            decision: partial_response.decision(),
            satisfied: partial_response
                .definitely_satisfied()
                .map(|p| p.id().clone())
                .collect(),
            errored: partial_response.definitely_errored().cloned().collect(),
            may_be_determining: partial_response
                .may_be_determining()
                .map(|p| p.id().clone())
                .collect(),
            must_be_determining: partial_response
                .must_be_determining()
                .map(|p| p.id().clone())
                .collect(),
            nontrivial_residuals: partial_response
                .nontrivial_residuals()
                .map(|p| p.id().clone())
                .collect(),
            residuals: partial_response
                .all_residuals()
                .map(|e| e.to_json().map(|json| (e.id().clone(), json)))
                .collect::<Result<_, _>>()?,
        })
    }
}

/// Answer struct from authorization call
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub enum AuthorizationAnswer {
    /// Represents a failure to parse or call the authorizer entirely
    #[serde(rename_all = "camelCase")]
    Failure {
        /// Errors encountered
        errors: Vec<DetailedError>,
        /// Warnings encountered
        warnings: Vec<DetailedError>,
    },
    /// Represents a successful authorization call (although individual policy
    /// evaluation may still have errors)
    #[serde(rename_all = "camelCase")]
    Success {
        /// Authorization decision and diagnostics, which may include policy
        /// evaluation errors
        response: Response,
        /// Warnings encountered. These are all warnings not generated by
        /// authorization itself -- e.g. general warnings about your schema,
        /// entity data, etc. Warnings generated by authorization are part of
        /// `response`.
        warnings: Vec<DetailedError>,
    },
}

/// Answer struct from partial-authorization call
#[cfg(feature = "partial-eval")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub enum PartialAuthorizationAnswer {
    /// Represents a failure to parse or call the authorizer entirely
    #[serde(rename_all = "camelCase")]
    Failure {
        /// Errors encountered
        errors: Vec<DetailedError>,
        /// Warnings encountered
        warnings: Vec<DetailedError>,
    },
    /// Represents a successful authorization call with either a partial or
    /// concrete answer.  Individual policy evaluation may still have errors.
    #[serde(rename_all = "camelCase")]
    Residuals {
        /// Information about the authorization decision and residuals
        response: Box<ResidualResponse>,
        /// Warnings encountered. These are all warnings not generated by
        /// authorization itself -- e.g. general warnings about your schema,
        /// entity data, etc. Warnings generated by authorization are part of
        /// `response`.
        warnings: Vec<DetailedError>,
    },
}

/// Struct containing the input data for authorization
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationCall {
    /// The principal taking action
    #[cfg_attr(feature = "wasm", tsify(type = "{type: string, id: string}"))]
    principal: Option<JsonValueWithNoDuplicateKeys>,
    /// The action the principal is taking
    #[cfg_attr(feature = "wasm", tsify(type = "{type: string, id: string}"))]
    action: JsonValueWithNoDuplicateKeys,
    /// The resource being acted on by the principal
    #[cfg_attr(feature = "wasm", tsify(type = "{type: string, id: string}"))]
    resource: Option<JsonValueWithNoDuplicateKeys>,
    /// The context details specific to the request
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[cfg_attr(feature = "wasm", tsify(type = "Record<string, CedarValueJson>"))]
    /// The context details specific to the request
    context: HashMap<String, JsonValueWithNoDuplicateKeys>,
    /// Optional schema.
    /// If present, this will inform the parsing: for instance, it will allow
    /// `__entity` and `__extn` escapes to be implicit, and it will error if
    /// attributes have the wrong types (e.g., string instead of integer).
    #[cfg_attr(feature = "wasm", tsify(optional, type = "Schema"))]
    schema: Option<Schema>,
    /// If this is `true` and a schema is provided, perform request validation.
    /// If this is `false`, the schema will only be used for schema-based
    /// parsing of `context`, and not for request validation.
    /// If a schema is not provided, this option has no effect.
    #[serde(default = "constant_true")]
    enable_request_validation: bool,
    /// The slice containing entities and policies
    slice: RecvdSlice,
}

fn constant_true() -> bool {
    true
}

/// Parses the given JSON into an [`EntityUid`], or if it fails, adds an
/// appropriate error to `errs` and returns `None`.
fn parse_entity_uid(
    entity_uid_json: JsonValueWithNoDuplicateKeys,
    category: &str,
    errs: &mut Vec<miette::Report>,
) -> Option<EntityUid> {
    match EntityUid::from_json(entity_uid_json.into())
        .wrap_err_with(|| format!("Failed to parse {category}"))
    {
        Ok(euid) => Some(euid),
        Err(e) => {
            errs.push(e);
            None
        }
    }
}

/// Parses the given JSON context into a [`Context`], or if it fails, adds
/// appropriate error(s) to `errs` and returns an empty context.
fn parse_context(
    context_map: HashMap<String, JsonValueWithNoDuplicateKeys>,
    schema_ref: Option<&crate::Schema>,
    action_ref: Option<&EntityUid>,
    errs: &mut Vec<miette::Report>,
) -> Context {
    match serde_json::to_value(context_map) {
        Ok(json) => {
            match Context::from_json_value(
                json,
                match (schema_ref, action_ref) {
                    (Some(s), Some(a)) => Some((s, a)),
                    _ => None,
                },
            ) {
                Ok(context) => context,
                Err(e) => {
                    errs.push(miette::Report::new(e));
                    Context::empty()
                }
            }
        }
        Err(e) => {
            errs.push(miette!("Failed to parse context: {e}"));
            Context::empty()
        }
    }
}

impl AuthorizationCall {
    fn get_components(
        self,
    ) -> WithWarnings<Result<(Request, crate::PolicySet, Entities), Vec<miette::Report>>> {
        let mut errs = vec![];
        let mut warnings = vec![];
        let schema = match self.schema.map(Schema::parse).transpose() {
            Ok(None) => None,
            Ok(Some((schema, new_warnings))) => {
                warnings.extend(new_warnings.map(miette::Report::new));
                Some(schema)
            }
            Err(e) => {
                errs.push(e);
                None
            }
        };
        let principal = self
            .principal
            .and_then(|p| parse_entity_uid(p, "principal", &mut errs));
        let action = parse_entity_uid(self.action, "action", &mut errs);
        let resource = self
            .resource
            .and_then(|r| parse_entity_uid(r, "resource", &mut errs));
        let context = parse_context(self.context, schema.as_ref(), action.as_ref(), &mut errs);

        let request = match Request::new(
            principal,
            action,
            resource,
            context,
            if self.enable_request_validation {
                schema.as_ref()
            } else {
                None
            },
        ) {
            Ok(req) => Some(req),
            Err(e) => {
                errs.push(miette::Report::new(e));
                None
            }
        };
        let (policies, entities) = match self.slice.try_into(schema.as_ref()) {
            Ok((policies, entities)) => (Some(policies), Some(entities)),
            Err(es) => {
                errs.extend(es);
                (None, None)
            }
        };

        match (errs.is_empty(), request, policies, entities) {
            (true, Some(req), Some(policies), Some(entities)) => WithWarnings {
                t: Ok((req, policies, entities)),
                warnings,
            },
            _ => WithWarnings {
                t: Err(errs),
                warnings,
            },
        }
    }

    #[cfg(feature = "partial-eval")]
    fn get_components_partial(
        self,
    ) -> WithWarnings<Result<(Request, crate::PolicySet, Entities), Vec<miette::Report>>> {
        let mut errs = vec![];
        let mut warnings = vec![];
        let schema = match self.schema.map(Schema::parse).transpose() {
            Ok(None) => None,
            Ok(Some((schema, new_warnings))) => {
                warnings.extend(new_warnings.map(miette::Report::new));
                Some(schema)
            }
            Err(e) => {
                errs.push(e);
                None
            }
        };
        let principal = self
            .principal
            .and_then(|p| parse_entity_uid(p, "principal", &mut errs));
        let action = parse_entity_uid(self.action, "action", &mut errs);
        let resource = self
            .resource
            .and_then(|r| parse_entity_uid(r, "resource", &mut errs));
        let context = parse_context(self.context, schema.as_ref(), action.as_ref(), &mut errs);

        let mut b = Request::builder();
        if principal.is_some() {
            b = b.principal(principal);
        }
        if action.is_some() {
            b = b.action(action);
        }
        if resource.is_some() {
            b = b.resource(resource);
        }
        b = b.context(context);
        let request = if self.enable_request_validation {
            match schema.as_ref() {
                Some(schema_ref) => match b.schema(schema_ref).build() {
                    Ok(req) => Some(req),
                    Err(e) => {
                        errs.push(miette::Report::new(e));
                        None
                    }
                },
                None => Some(b.build()),
            }
        } else {
            Some(b.build())
        };
        let (policies, entities) = match self.slice.try_into(schema.as_ref()) {
            Ok((policies, entities)) => (Some(policies), Some(entities)),
            Err(e) => {
                errs.extend(e);
                (None, None)
            }
        };

        match (errs.is_empty(), request, policies, entities) {
            (true, Some(req), Some(policies), Some(entities)) => WithWarnings {
                t: Ok((req, policies, entities.partial())),
                warnings,
            },
            _ => WithWarnings {
                t: Err(errs),
                warnings,
            },
        }
    }
}

///
/// Entity UID as strings.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
struct EntityUIDStrings {
    ty: String,
    eid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
struct Link {
    slot: String,
    value: EntityUIDStrings,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
struct TemplateLink {
    /// Template ID to fill in
    template_id: String,

    /// Policy ID for resulting linked policy
    result_policy_id: String,

    /// Links for all slots in policy template `template_id`
    instantiations: Links,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "Vec<Link>")]
#[serde(into = "Vec<Link>")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
struct Links(Vec<Link>);

/// Error returned for duplicate slot ids
#[derive(Debug, Clone, Diagnostic, Error)]
pub enum DuplicateLinkError {
    /// Duplicate values for the same slot
    #[error("duplicate values for the slot(s): {}", .0.iter().map(|s| format!("`{s}`")).join(", "))]
    Duplicates(Vec<String>),
}

impl TryFrom<Vec<Link>> for Links {
    type Error = DuplicateLinkError;

    fn try_from(links: Vec<Link>) -> Result<Self, Self::Error> {
        let mut slots = links.iter().map(|link| &link.slot).collect::<Vec<_>>();
        slots.sort();
        let duplicates = slots
            .into_iter()
            .dedup_with_count()
            .filter_map(|(count, slot)| if count == 1 { None } else { Some(slot) })
            .cloned()
            .collect::<Vec<_>>();
        if duplicates.is_empty() {
            Ok(Self(links))
        } else {
            Err(DuplicateLinkError::Duplicates(duplicates))
        }
    }
}

impl From<Links> for Vec<Link> {
    fn from(value: Links) -> Self {
        value.0
    }
}

/// policies must either be a single policy per entry, or only one entry with more than one policy
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
struct RecvdSlice {
    policies: PolicySet,
    /// JSON object containing the entities data, in "natural JSON" form -- same
    /// format as expected by EntityJsonParser
    #[cfg_attr(feature = "wasm", tsify(type = "Array<EntityJson>"))]
    entities: JsonValueWithNoDuplicateKeys,

    /// Optional template policies.
    #[serde_as(as = "Option<MapPreventDuplicates<_, _>>")]
    templates: Option<HashMap<String, String>>,

    /// Optional template links
    template_instantiations: Option<Vec<TemplateLink>>,
}

fn parse_link(v: &Link) -> Result<(SlotId, EntityUid), miette::Report> {
    let slot = match v.slot.as_str() {
        "?principal" => SlotId::principal(),
        "?resource" => SlotId::resource(),
        _ => {
            return Err(miette!("Slot must be ?principal or ?resource"));
        }
    };
    let type_name = EntityTypeName::from_str(v.value.ty.as_str()).map_err(miette::Report::new)?;
    let eid = match EntityId::from_str(v.value.eid.as_str()) {
        Ok(eid) => eid,
        Err(err) => match err {},
    };
    let entity_uid = EntityUid::from_type_name_and_id(type_name, eid);
    Ok((slot, entity_uid))
}

fn parse_links(policies: &mut crate::PolicySet, link: TemplateLink) -> Result<(), miette::Report> {
    let template_id = PolicyId::from_str(link.template_id.as_str());
    let link_id = PolicyId::from_str(link.result_policy_id.as_str());
    match (template_id, link_id) {
        (Err(e), _) | (_, Err(e)) => return Err(miette::Report::new(e)),
        (Ok(template_id), Ok(link_id)) => {
            let mut vals = HashMap::new();
            for i in link.instantiations.0 {
                let (slot, euid) = parse_link(&i)?;
                vals.insert(slot, euid);
            }
            policies
                .link(template_id, link_id, vals)
                .map_err(miette::Report::new)
        }
    }
}

impl RecvdSlice {
    #[allow(clippy::too_many_lines)]
    fn try_into(
        self,
        schema: Option<&crate::Schema>,
    ) -> Result<(crate::PolicySet, Entities), Vec<miette::Report>> {
        let Self {
            policies,
            entities,
            templates,
            template_instantiations,
        } = self;

        let mut errs = Vec::new();

        let mut policies: crate::PolicySet = match policies.parse(templates) {
            Ok(policies) => policies,
            Err(e) => {
                errs.extend(e);
                crate::PolicySet::new()
            }
        };
        let entities = match Entities::from_json_value(entities.into(), schema) {
            Ok(entities) => entities,
            Err(e) => {
                errs.push(miette::Report::new(e));
                Entities::empty()
            }
        };

        if let Some(links) = template_instantiations {
            for link in links {
                match parse_links(&mut policies, link) {
                    Ok(()) => (),
                    Err(e) => errs.push(e),
                }
            }
        }

        if errs.is_empty() {
            Ok((policies, entities))
        } else {
            Err(errs)
        }
    }
}

// PANIC SAFETY unit tests
#[allow(clippy::panic)]
#[cfg(test)]
mod test {
    use super::*;
    use cool_asserts::assert_matches;
    use serde_json::json;

    /// Assert that `is_authorized_json()` returns Allow with no errors
    #[track_caller]
    fn assert_is_authorized_json(json: serde_json::Value) {
        let ans_val = is_authorized_json(json).unwrap();
        let result: Result<AuthorizationAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(AuthorizationAnswer::Success { response, .. }) => {
            assert_eq!(response.decision(), Decision::Allow);
            let errors: Vec<&AuthorizationError> = response.diagnostics().errors().collect();
            assert_eq!(errors.len(), 0, "{errors:?}");
        });
    }

    /// Assert that `is_authorized_json()` returns Deny with no errors
    #[track_caller]
    fn assert_is_not_authorized_json(json: serde_json::Value) {
        let ans_val = is_authorized_json(json).unwrap();
        let result: Result<AuthorizationAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(AuthorizationAnswer::Success { response, .. }) => {
            assert_eq!(response.decision(), Decision::Deny);
            let errors: Vec<&AuthorizationError> = response.diagnostics().errors().collect();
            assert_eq!(errors.len(), 0, "{errors:?}");
        });
    }

    /// Assert that `is_authorized_json()` returns
    /// `AuthorizationAnswer::Failure` where some error contains the expected
    /// string `err` (in its main error message)
    #[track_caller]
    fn assert_is_authorized_json_is_failure(json: serde_json::Value, err: &str) {
        let ans_val =
            is_authorized_json(json).expect("expected it to at least parse into AuthorizationCall");
        let result: Result<AuthorizationAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(AuthorizationAnswer::Failure { errors, .. }) => {
            assert!(
                errors.iter().any(|e| e.message.contains(err)),
                "Expected to see error(s) containing `{err}`, but saw {errors:?}",
            );
        });
    }

    #[test]
    fn test_slice_convert() {
        let entities = serde_json::json!(
            [
                {
                    "uid" : {
                        "type" : "user",
                        "id" : "alice"
                    },
                    "attrs": { "foo": "bar" },
                    "parents" : [
                        {
                            "type" : "user",
                            "id" : "bob"
                        }
                    ]
                },
                {
                    "uid" : {
                        "type" : "user",
                        "id" : "bob"
                    },
                    "attrs": {},
                    "parents": []
                }
            ]
        );
        let rslice = RecvdSlice {
            policies: PolicySet::Map(HashMap::new()),
            entities: entities.into(),
            templates: None,
            template_instantiations: None,
        };
        let (policies, entities) = rslice.try_into(None).expect("parse failed");
        assert!(policies.is_empty());
        entities
            .get(&EntityUid::from_type_name_and_id(
                "user".parse().unwrap(),
                "alice".parse().unwrap(),
            ))
            .map_or_else(
                || panic!("Missing user::alice Entity"),
                |alice| {
                    assert!(entities.is_ancestor_of(
                        &EntityUid::from_type_name_and_id(
                            "user".parse().unwrap(),
                            "bob".parse().unwrap()
                        ),
                        &alice.uid()
                    ));
                },
            );
    }

    #[test]
    fn test_failure_on_invalid_syntax() {
        assert_matches!(is_authorized_json_str("iefjieoafiaeosij"), Err(e) => {
            assert!(e.to_string().contains("expected value"));
        });
    }

    #[test]
    fn test_not_authorized_on_empty_slice() {
        let call = json!({
            "principal": {
             "type": "User",
             "id": "alice"
            },
            "action": {
             "type": "Photo",
             "id": "view"
            },
            "resource": {
             "type": "Photo",
             "id": "door"
            },
            "context": {},
            "slice": {
             "policies": {},
             "entities": []
            }
        });

        assert_is_not_authorized_json(call);
    }

    #[test]
    fn test_not_authorized_on_unspecified() {
        let call = json!({
            "principal": null,
            "action": {
             "type": "Photo",
             "id": "view"
            },
            "resource": {
             "type": "Photo",
             "id": "door"
            },
            "context": {},
            "slice": {
             "policies": {
              "ID1": "permit(principal == User::\"alice\", action, resource);"
             },
             "entities": []
            }
        });

        assert_is_not_authorized_json(call);
    }

    #[test]
    fn test_authorized_on_simple_slice() {
        let call = json!({
            "principal": {
             "type": "User",
             "id": "alice"
            },
            "action": {
             "type": "Photo",
             "id": "view"
            },
            "resource": {
             "type": "Photo",
             "id": "door"
            },
            "context": {},
            "slice": {
             "policies": {
              "ID1": "permit(principal == User::\"alice\", action, resource);"
             },
             "entities": []
            }
        });

        assert_is_authorized_json(call);
    }

    #[test]
    fn test_authorized_on_simple_slice_with_string_policies() {
        let call = json!({
            "principal": {
             "type": "User",
             "id": "alice"
            },
            "action": {
             "type": "Photo",
             "id": "view"
            },
            "resource": {
             "type": "Photo",
             "id": "door"
            },
            "context": {},
            "slice": {
             "policies": "permit(principal == User::\"alice\", action, resource);",
             "entities": []
            }
        });

        assert_is_authorized_json(call);
    }

    #[test]
    fn test_authorized_on_simple_slice_with_context() {
        let call = json!({
            "principal": {
             "type": "User",
             "id": "alice"
            },
            "action": {
             "type": "Photo",
             "id": "view"
            },
            "resource": {
             "type": "Photo",
             "id": "door"
            },
            "context": {
             "is_authenticated": true,
             "source_ip": {
                "__extn" : { "fn" : "ip", "arg" : "222.222.222.222" }
             }
            },
            "slice": {
             "policies": "permit(principal == User::\"alice\", action, resource) when { context.is_authenticated && context.source_ip.isInRange(ip(\"222.222.222.0/24\")) };",
             "entities": []
            }
        });

        assert_is_authorized_json(call);
    }

    #[test]
    fn test_authorized_on_simple_slice_with_attrs_and_parents() {
        let call = json!({
            "principal": {
             "type": "User",
             "id": "alice"
            },
            "action": {
             "type": "Photo",
             "id": "view"
            },
            "resource": {
             "type": "Photo",
             "id": "door"
            },
            "context": {},
            "slice": {
             "policies": "permit(principal, action, resource in Folder::\"house\") when { resource.owner == principal };",
             "entities": [
              {
               "uid": {
                "__entity": {
                 "type": "User",
                 "id": "alice"
                }
               },
               "attrs": {},
               "parents": []
              },
              {
               "uid": {
                "__entity": {
                 "type": "Photo",
                 "id": "door"
                }
               },
               "attrs": {
                "owner": {
                 "__entity": {
                  "type": "User",
                  "id": "alice"
                 }
                }
               },
               "parents": [
                {
                 "__entity": {
                  "type": "Folder",
                  "id": "house"
                 }
                }
               ]
              },
              {
               "uid": {
                "__entity": {
                 "type": "Folder",
                 "id": "house"
                }
               },
               "attrs": {},
               "parents": []
              }
             ]
            }
        });
        assert_is_authorized_json(call);
    }

    #[test]
    fn test_authorized_on_multi_policy_slice() {
        let call = json!({
            "principal": {
             "type": "User",
             "id": "alice"
            },
            "action": {
             "type": "Photo",
             "id": "view"
            },
            "resource": {
             "type": "Photo",
             "id": "door"
            },
            "context": {},
            "slice": {
             "policies": {
              "ID0": "permit(principal == User::\"jerry\", action, resource == Photo::\"doorx\");",
              "ID1": "permit(principal == User::\"tom\", action, resource == Photo::\"doory\");",
              "ID2": "permit(principal == User::\"alice\", action, resource == Photo::\"door\");"
             },
             "entities": []
            }
        });
        assert_is_authorized_json(call);
    }

    #[test]
    fn test_authorized_on_multi_policy_slice_with_string_policies() {
        let call = json!({
            "principal": {
             "type": "User",
             "id": "alice"
            },
            "action": {
             "type": "Photo",
             "id": "view"
            },
            "resource": {
             "type": "Photo",
             "id": "door"
            },
            "context": {},
            "slice": {
             "policies": "permit(principal, action, resource in Folder::\"house\") when { resource.owner == principal };",
             "entities": [
              {
               "uid": {
                "__entity": {
                 "type": "User",
                 "id": "alice"
                }
               },
               "attrs": {},
               "parents": []
              },
              {
               "uid": {
                "__entity": {
                 "type": "Photo",
                 "id": "door"
                }
               },
               "attrs": {
                "owner": {
                 "__entity": {
                  "type": "User",
                  "id": "alice"
                 }
                }
               },
               "parents": [
                {
                 "__entity": {
                  "type": "Folder",
                  "id": "house"
                 }
                }
               ]
              },
              {
               "uid": {
                "__entity": {
                 "type": "Folder",
                 "id": "house"
                }
               },
               "attrs": {},
               "parents": []
              }
             ]
            }
        });
        assert_is_authorized_json(call);
    }

    #[test]
    fn test_authorized_on_multi_policy_slice_denies_when_expected() {
        let call = json!({
            "principal": {
             "type": "User",
             "id": "alice"
            },
            "action": {
             "type": "Photo",
             "id": "view"
            },
            "resource": {
             "type": "Photo",
             "id": "door"
            },
            "context": {},
            "slice": {
             "policies": {
              "ID0": "permit(principal, action, resource);",
              "ID1": "forbid(principal == User::\"alice\", action, resource == Photo::\"door\");"
             },
             "entities": []
            }
        });
        assert_is_not_authorized_json(call);
    }

    #[test]
    fn test_authorized_on_multi_policy_slice_with_string_policies_denies_when_expected() {
        let call = json!({
            "principal": {
             "type": "User",
             "id": "alice"
            },
            "action": {
             "type": "Photo",
             "id": "view"
            },
            "resource": {
             "type": "Photo",
             "id": "door"
            },
            "context": {},
            "slice": {
             "policies": "permit(principal, action, resource);forbid(principal == User::\"alice\", action, resource);",
             "entities": []
            }
        });

        assert_is_not_authorized_json(call);
    }

    #[test]
    fn test_authorized_with_template_as_policy_should_fail() {
        let call = json!({
            "principal": {
             "type": "User",
             "id": "alice"
            },
            "action": {
             "type": "Photo",
             "id": "view"
            },
            "resource": {
             "type": "Photo",
             "id": "door"
            },
            "context": {},
            "slice": {
             "policies": "permit(principal == ?principal, action, resource);",
             "entities": [],
             "templates": {}
            }
        });
        assert_is_not_authorized_json(call);
    }

    #[test]
    fn test_authorized_with_template_should_fail() {
        let call = json!({
            "principal": {
             "type": "User",
             "id": "alice"
            },
            "action": {
             "type": "Photo",
             "id": "view"
            },
            "resource": {
             "type": "Photo",
             "id": "door"
            },
            "context": {},
            "slice": {
             "policies": {},
             "entities": [],
             "templates": {
              "ID0": "permit(principal == ?principal, action, resource);"
             }
            }
        });
        assert_is_not_authorized_json(call);
    }

    #[test]
    fn test_authorized_with_template_link() {
        let call = json!({
            "principal": {
             "type": "User",
             "id": "alice"
            },
            "action": {
             "type": "Photo",
             "id": "view"
            },
            "resource": {
             "type": "Photo",
             "id": "door"
            },
            "context": {},
            "slice": {
             "policies": {},
             "entities": [],
             "templates": {
              "ID0": "permit(principal == ?principal, action, resource);"
             },
             "templateInstantiations": [
              {
               "templateId": "ID0",
               "resultPolicyId": "ID0_User_alice",
               "instantiations": [
                {
                 "slot": "?principal",
                 "value": {
                  "ty": "User",
                  "eid": "alice"
                 }
                }
               ]
              }
             ]
            }
        });
        assert_is_authorized_json(call);
    }

    #[test]
    fn test_authorized_fails_on_policy_collision_with_template() {
        let call = json!({
            "principal" : {
                "type" : "User",
                "id" : "alice"
            },
            "action" : {
                "type" : "Action",
                "id" : "view"
            },
            "resource" : {
                "type" : "Photo",
                "id" : "door"
            },
            "context" : {},
            "slice" : {
                "policies" : { "ID0": "permit(principal, action, resource);" },
                "entities" : [],
                "templates" : { "ID0": "permit(principal == ?principal, action, resource);" },
                "templateInstantiations" : []
            }
        });
        assert_is_authorized_json_is_failure(
            call,
            "failed to add template with id `ID0` to policy set: duplicate template or policy id `ID0`",
        );
    }

    #[test]
    fn test_authorized_fails_on_duplicate_link_ids() {
        let call = json!({
            "principal" : {
                "type" : "User",
                "id" : "alice"
            },
            "action" : {
                "type" : "Action",
                "id" : "view"
            },
            "resource" : {
                "type" : "Photo",
                "id" : "door"
            },
            "context" : {},
            "slice" : {
                "policies" : {},
                "entities" : [],
                "templates" : { "ID0": "permit(principal == ?principal, action, resource);" },
                "templateInstantiations" : [
                    {
                        "templateId" : "ID0",
                        "resultPolicyId" : "ID1",
                        "instantiations" : [
                            {
                                "slot": "?principal",
                                "value": { "ty" : "User", "eid" : "alice" }
                            }
                        ]
                    },
                    {
                        "templateId" : "ID0",
                        "resultPolicyId" : "ID1",
                        "instantiations" : [
                            {
                                "slot": "?principal",
                                "value": { "ty" : "User", "eid" : "alice" }
                            }
                        ]
                    }
                ]
            }
        });
        assert_is_authorized_json_is_failure(
            call,
            "unable to link template: template-linked policy id `ID1` conflicts with an existing policy id",
        );
    }

    #[test]
    fn test_authorized_fails_on_template_link_collision_with_template() {
        let call = json!({
            "principal" : {
                "type" : "User",
                "id" : "alice"
            },
            "action" : {
                "type" : "Action",
                "id" : "view"
            },
            "resource" : {
                "type" : "Photo",
                "id" : "door"
            },
            "context" : {},
            "slice" : {
                "policies" : {},
                "entities" : [],
                "templates" : { "ID0": "permit(principal == ?principal, action, resource);" },
                "templateInstantiations" : [
                    {
                        "templateId" : "ID0",
                        "resultPolicyId" : "ID0",
                        "instantiations" : [
                            {
                                "slot": "?principal",
                                "value": { "ty" : "User", "eid" : "alice" }
                            }
                        ]
                    }
                ]
            }
        });
        assert_is_authorized_json_is_failure(
            call,
            "unable to link template: template-linked policy id `ID0` conflicts with an existing policy id",
        );
    }

    #[test]
    fn test_authorized_fails_on_template_link_collision_with_policy() {
        let call = json!({
            "principal" : {
                "type" : "User",
                "id" : "alice"
            },
            "action" : {
                "type" : "Action",
                "id" : "view"
            },
            "resource" : {
                "type" : "Photo",
                "id" : "door"
            },
            "context" : {},
            "slice" : {
                "policies" : { "ID1": "permit(principal, action, resource);" },
                "entities" : [],
                "templates" : { "ID0": "permit(principal == ?principal, action, resource);" },
                "templateInstantiations" : [
                    {
                        "templateId" : "ID0",
                        "resultPolicyId" : "ID1",
                        "instantiations" : [
                            {
                                "slot": "?principal",
                                "value": { "ty" : "User", "eid" : "alice" }
                            }
                        ]
                    }
                ]
            }
        });
        assert_is_authorized_json_is_failure(
            call,
            "unable to link template: template-linked policy id `ID1` conflicts with an existing policy id",
        );
    }

    #[test]
    fn test_authorized_fails_on_duplicate_policy_ids() {
        let call = r#"{
            "principal" : "User::\"alice\"",
            "action" : "Photo::\"view\"",
            "resource" : "Photo::\"door\"",
            "context" : {},
            "slice" : {
                "policies" : {
                  "ID0": "permit(principal, action, resource);",
                  "ID0": "permit(principal, action, resource);"
                },
                "entities" : [],
                "templates" : {},
                "templateInstantiations" : [ ]
            }
        }"#;
        assert_matches!(is_authorized_json_str(call), Err(e) => {
            assert!(e.to_string().contains("policies as a concatenated string or multiple policies as a hashmap where the policy id is the key"));
        });
    }

    #[test]
    fn test_authorized_fails_on_duplicate_template_ids() {
        let call = r#"{
            "principal" : "User::\"alice\"",
            "action" : "Photo::\"view\"",
            "resource" : "Photo::\"door\"",
            "context" : {},
            "slice" : {
                "policies" : {},
                "entities" : [],
                "templates" : {
                    "ID0": "permit(principal == ?principal, action, resource);",
                    "ID0": "permit(principal == ?principal, action, resource);"
                },
                "templateInstantiations" : [ ]
            }
        }"#;
        assert_matches!(is_authorized_json_str(call), Err(e) => {
            assert!(e.to_string().contains("found duplicate key"));
        });
    }

    #[test]
    fn test_authorized_fails_on_duplicate_slot_link1() {
        let call = json!({
            "principal" : "User::\"alice\"",
            "action" : "Photo::\"view\"",
            "resource" : "Photo::\"door\"",
            "context" : {},
            "slice" : {
                "policies" : {},
                "entities" : [],
                "templates" : { "ID0": "permit(principal == ?principal, action, resource);" },
                "templateInstantiations" : [
                    {
                        "templateId" : "ID0",
                        "resultPolicyId" : "ID1",
                        "instantiations" : [
                            {
                                "slot": "?principal",
                                "value": { "ty" : "User", "eid" : "alice" }
                            },
                            {
                                "slot": "?principal",
                                "value": { "ty" : "User", "eid" : "alice" }
                            }
                        ]
                    }
                ]
            }
        });
        assert_matches!(is_authorized_json(call), Err(e) => {
            assert!(e.to_string().contains("duplicate values for the slot(s): `?principal`"));
        });
    }

    #[test]
    fn test_authorized_fails_on_duplicate_slot_link2() {
        let call = json!({
            "principal" : "User::\"alice\"",
            "action" : "Photo::\"view\"",
            "resource" : "Photo::\"door\"",
            "context" : {},
            "slice" : {
                "policies" : {},
                "entities" : [],
                "templates" : { "ID0": "permit(principal == ?principal, action, resource);" },
                "templateInstantiations" : [
                    {
                        "templateId" : "ID0",
                        "resultPolicyId" : "ID1",
                        "instantiations" : [
                            {
                                "slot": "?principal",
                                "value": { "ty" : "User", "eid" : "alice" }
                            },
                            {
                                "slot" : "?resource",
                                "value" : { "ty" : "Box", "eid" : "box" }
                            },
                            {
                                "slot": "?principal",
                                "value": { "ty" : "User", "eid" : "alice" }
                            }
                        ]
                    }
                ]
            }
        });
        assert_matches!(is_authorized_json(call), Err(e) => {
            assert!(e.to_string().contains("duplicate values for the slot(s): `?principal`"));
        });
    }

    #[test]
    fn test_authorized_fails_on_duplicate_slot_link3() {
        let call = json!({
            "principal" : "User::\"alice\"",
            "action" : "Photo::\"view\"",
            "resource" : "Photo::\"door\"",
            "context" : {},
            "slice" : {
                "policies" : {},
                "entities" : [],
                "templates" : { "ID0": "permit(principal == ?principal, action, resource);" },
                "templateInstantiations" : [
                    {
                        "templateId" : "ID0",
                        "resultPolicyId" : "ID1",
                        "instantiations" : [
                            {
                                "slot": "?principal",
                                "value": { "ty" : "User", "eid" : "alice" }
                            },
                            {
                                "slot" : "?resource",
                                "value" : { "ty" : "Box", "eid" : "box" }
                            },
                            {
                                "slot": "?principal",
                                "value": { "ty" : "Team", "eid" : "bob" }
                            },
                            {
                                "slot" : "?resource",
                                "value" : { "ty" : "Box", "eid" : "box2" }
                            }
                        ]
                    }
                ]
            }
        });
        assert_matches!(is_authorized_json(call), Err(e) => {
            assert!(e.to_string().contains("duplicate values for the slot(s): `?principal`, `?resource`"));
        });
    }

    #[test]
    fn test_authorized_fails_duplicate_entity_uid() {
        let call = json!({
            "principal" : {
                "type" : "User",
                "id" : "alice"
            },
            "action" : {
                "type" : "Photo",
                "id" : "view"
            },
            "resource" : {
                "type" : "Photo",
                "id" : "door"
            },
            "context" : {},
            "slice" : {
                "policies" : {},
                "entities" : [
                    {
                        "uid": {
                            "type" : "User",
                            "id" : "alice"
                        },
                        "attrs": {},
                        "parents": []
                    },
                    {
                        "uid": {
                            "type" : "User",
                            "id" : "alice"
                        },
                        "attrs": {},
                        "parents": []
                    }
                ],
                "templates" : {},
                "templateInstantiations" : []
            }
        });
        assert_is_authorized_json_is_failure(call, r#"duplicate entity entry `User::"alice"`"#);
    }

    #[test]
    fn test_authorized_fails_duplicate_context_key() {
        let call = r#"{
            "principal" : {
                "type" : "User",
                "id" : "alice"
            },
            "action" : {
                "type" : "Photo",
                "id" : "view"
            },
            "resource" : {
                "type" : "Photo",
                "id" : "door"
            },
            "context" : {
                "is_authenticated": true,
                "is_authenticated": false
            },
            "slice" : {
                "policies" : {},
                "entities" : [],
                "templates" : {},
                "templateInstantiations" : []
            }
        }"#;
        assert_matches!(is_authorized_json_str(call), Err(e) => {
            assert!(e.to_string().contains("found duplicate key"));
        });
    }

    #[test]
    fn test_request_validation() {
        let good_call = json!({
            "principal" : {
                "type": "User",
                "id": "alice",
            },
            "action": {
                "type": "Action",
                "id": "view",
            },
            "resource": {
                "type": "Photo",
                "id": "door",
            },
            "context": {},
            "slice": {
                "policies": "permit(principal == User::\"alice\", action == Action::\"view\", resource);",
                "entities": [],
                "templates": {},
                "templateInstantiations": [],
            },
            "schema": {
                "human": "entity User, Photo; action view appliesTo { principal: User, resource: Photo };"
            },
        });
        let bad_call = json!({
            "principal" : {
                "type": "User",
                "id": "alice",
            },
            "action": {
                "type": "Action",
                "id": "view",
            },
            "resource": {
                "type": "User",
                "id": "bob",
            },
            "context": {},
            "slice": {
                "policies": "permit(principal == User::\"alice\", action == Action::\"view\", resource);",
                "entities": [],
                "templates": {},
                "templateInstantiations": [],
            },
            "schema": {
                "human": "entity User, Photo; action view appliesTo { principal: User, resource: Photo };"
            },
        });
        let bad_call_req_validation_disabled = json!({
            "principal" : {
                "type": "User",
                "id": "alice",
            },
            "action": {
                "type": "Action",
                "id": "view",
            },
            "resource": {
                "type": "User",
                "id": "bob",
            },
            "context": {},
            "slice": {
                "policies": "permit(principal == User::\"alice\", action == Action::\"view\", resource);",
                "entities": [],
                "templates": {},
                "templateInstantiations": [],
            },
            "schema": {
                "human": "entity User, Photo; action view appliesTo { principal: User, resource: Photo };"
            },
            "enableRequestValidation": false,
        });

        assert_is_authorized_json(good_call);
        assert_is_authorized_json_is_failure(
            bad_call,
            "resource type `User` is not valid for `Action::\"view\"`",
        );
        assert_is_authorized_json(bad_call_req_validation_disabled);
    }
}

#[cfg(feature = "partial-eval")]
#[cfg(test)]
mod partial_test {
    use super::*;
    use cool_asserts::assert_matches;
    use serde_json::json;

    #[track_caller]
    fn assert_is_authorized_json_partial(call: serde_json::Value) {
        let ans_val = is_authorized_partial_json(call).unwrap();
        let result: Result<PartialAuthorizationAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(PartialAuthorizationAnswer::Residuals { response, .. }) => {
            assert_eq!(response.decision(), Some(Decision::Allow));
            let errors: Vec<_> = response.errored().collect();
            assert_eq!(errors.len(), 0, "{errors:?}");
        });
    }

    #[track_caller]
    fn assert_is_not_authorized_json_partial(call: serde_json::Value) {
        let ans_val = is_authorized_partial_json(call).unwrap();
        let result: Result<PartialAuthorizationAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(PartialAuthorizationAnswer::Residuals { response, .. }) => {
            assert_eq!(response.decision(), Some(Decision::Deny));
            let errors: Vec<_> = response.errored().collect();
            assert_eq!(errors.len(), 0, "{errors:?}");
        });
    }

    #[track_caller]
    fn assert_is_residual(call: serde_json::Value, expected_residuals: HashSet<&str>) {
        let ans_val = is_authorized_partial_json(call).unwrap();
        let result: Result<PartialAuthorizationAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(PartialAuthorizationAnswer::Residuals { response, .. }) => {
            assert_eq!(response.decision(), None);
            let errors: Vec<_> = response.errored().collect();
            assert_eq!(errors.len(), 0, "{errors:?}");
            let actual_residuals: HashSet<_> = response.nontrivial_residual_ids().collect();
            for id in &expected_residuals {
                assert!(actual_residuals.contains(&PolicyId::from_str(id).ok().unwrap()), "expected nontrivial residual for {id}, but it's missing")
            }
            for id in &actual_residuals {
                assert!(expected_residuals.contains(id.to_string().as_str()),"found unexpected nontrivial residual for {id}")
            }
        });
    }

    #[test]
    fn test_authorized_partial_no_resource() {
        let call = json!({
            "principal": {
                "type": "User",
                "id": "alice"
            },
            "action": {
                "type": "Photo",
                "id": "view"
            },
            "context": {},
            "slice": {
                "policies": {
                "ID1": "permit(principal == User::\"alice\", action, resource);"
                },
                "entities": []
            },
            "partial_evaluation": true
        });

        assert_is_authorized_json_partial(call);
    }

    #[test]
    fn test_authorized_partial_not_authorized_no_resource() {
        let call = json!({
            "principal": {
                "type": "User",
                "id": "john"
            },
            "action": {
                "type": "Photo",
                "id": "view"
            },
            "context": {},
            "slice": {
                "policies": {
                "ID1": "permit(principal == User::\"alice\", action, resource);"
                },
                "entities": []
            },
            "partial_evaluation": true
        });

        assert_is_not_authorized_json_partial(call);
    }

    #[test]
    fn test_authorized_partial_residual_no_principal_scope() {
        let call = json!({
            "action": {
                "type": "Photo",
                "id": "view"
            },
            "resource" : {
                "type" : "Photo",
                "id" : "door"
            },
            "context": {},
            "slice": {
                "policies": {
                "ID1": "permit(principal == User::\"alice\", action, resource);"
                },
                "entities": []
            },
            "partial_evaluation": true
        });

        assert_is_residual(call, HashSet::from(["ID1"]));
    }

    #[test]
    fn test_authorized_partial_residual_no_principal_when() {
        let call = json!({
            "action": {
                "type": "Photo",
                "id": "view"
            },
            "resource" : {
                "type" : "Photo",
                "id" : "door"
            },
            "context": {},
            "slice": {
                "policies": {
                "ID1": "permit(principal, action, resource) when { principal == User::\"alice\" };"
                },
                "entities": []
            },
            "partial_evaluation": true
        });

        assert_is_residual(call, HashSet::from(["ID1"]));
    }

    #[test]
    fn test_authorized_partial_residual_no_principal_ignored_forbid() {
        let call = json!({
            "action": {
                "type": "Photo",
                "id": "view"
            },
            "resource" : {
                "type" : "Photo",
                "id" : "door"
            },
            "context": {},
            "slice": {
                "policies": {
                "ID1": "permit(principal, action, resource) when { principal == User::\"alice\" };",
                "ID2": "forbid(principal, action, resource) unless { resource == Photo::\"door\" };"
                },
                "entities": []
            },
            "partial_evaluation": true
        });

        assert_is_residual(call, HashSet::from(["ID1"]));
    }
}
