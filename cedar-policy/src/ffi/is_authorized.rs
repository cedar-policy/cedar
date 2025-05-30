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

//! JSON FFI entry points for the Cedar authorizer. The Cedar Wasm authorizer
//! is generated from the [`is_authorized()`] function in this file.

#![allow(clippy::module_name_repetitions)]
#[cfg(feature = "partial-eval")]
use super::utils::JsonValueWithNoDuplicateKeys;
use super::utils::{Context, DetailedError, Entities, EntityUid, PolicySet, Schema, WithWarnings};
use crate::{Authorizer, Decision, PolicyId, Request};
use cedar_policy_core::validator::cedar_schema::SchemaWarning;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
#[cfg(feature = "partial-eval")]
use std::collections::HashMap;
use std::collections::HashSet;
#[cfg(feature = "partial-eval")]
use std::convert::Infallible;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(feature = "wasm")]
extern crate tsify;

thread_local!(
    /// Per-thread authorizer instance, initialized on first use
    static AUTHORIZER: Authorizer = Authorizer::new();
);

/// Basic interface, using [`AuthorizationCall`] and [`AuthorizationAnswer`] types
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "isAuthorized"))]
pub fn is_authorized(call: AuthorizationCall) -> AuthorizationAnswer {
    match call.parse() {
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
///
/// # Errors
///
/// Will return `Err` if the input JSON cannot be deserialized as an
/// [`AuthorizationCall`].
pub fn is_authorized_json(json: serde_json::Value) -> Result<serde_json::Value, serde_json::Error> {
    let ans = is_authorized(serde_json::from_value(json)?);
    serde_json::to_value(ans)
}

/// Input and output are strings containing serialized JSON, in the shapes
/// expected by [`is_authorized_json()`]
///
/// # Errors
///
/// Will return `Err` if the input cannot be converted to valid JSON or
/// deserialized as an [`AuthorizationCall`].
pub fn is_authorized_json_str(json: &str) -> Result<String, serde_json::Error> {
    let ans = is_authorized(serde_json::from_str(json)?);
    serde_json::to_string(&ans)
}

/// Basic interface for partial evaluation, using [`AuthorizationCall`] and
/// [`PartialAuthorizationAnswer`] types
#[doc = include_str!("../../experimental_warning.md")]
#[cfg(feature = "partial-eval")]
pub fn is_authorized_partial(call: PartialAuthorizationCall) -> PartialAuthorizationAnswer {
    match call.parse() {
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
///
/// # Errors
///
/// Will return `Err` if the input JSON cannot be deserialized as an
/// [`AuthorizationCall`].
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
///
/// # Errors
///
/// Will return `Err` if the input cannot be converted to valid JSON or
/// deserialized as an [`AuthorizationCall`].
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct Diagnostics {
    /// Ids of the policies that contributed to the decision.
    /// If no policies applied to the request, this set will be empty.
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
#[serde(deny_unknown_fields)]
pub struct AuthorizationError {
    /// Id of the policy where the error (or warning) occurred
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub policy_id: PolicyId,
    /// Error (or warning).
    /// You can look at the `severity` field to see whether it is actually an
    /// error or a warning.
    pub error: DetailedError,
}

impl AuthorizationError {
    /// Create an `AuthorizationError` from a policy ID and any `miette` error
    pub fn new(
        policy_id: impl Into<PolicyId>,
        error: impl miette::Diagnostic + Send + Sync + 'static,
    ) -> Self {
        Self::new_from_report(policy_id, miette::Report::new(error))
    }

    /// Create an `AuthorizationError` from a policy ID and a `miette::Report`
    pub fn new_from_report(policy_id: impl Into<PolicyId>, report: miette::Report) -> Self {
        Self {
            policy_id: policy_id.into(),
            error: report.into(),
        }
    }
}

impl From<crate::AuthorizationError> for AuthorizationError {
    fn from(e: crate::AuthorizationError) -> Self {
        match e {
            crate::AuthorizationError::PolicyEvaluationError(e) => {
                Self::new(e.policy_id().clone(), e.into_inner())
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
#[serde(deny_unknown_fields)]
pub struct ResidualResponse {
    decision: Option<Decision>,
    satisfied: HashSet<PolicyId>,
    errored: HashSet<PolicyId>,
    may_be_determining: HashSet<PolicyId>,
    must_be_determining: HashSet<PolicyId>,
    residuals: HashMap<PolicyId, JsonValueWithNoDuplicateKeys>,
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
    pub fn residuals(&self) -> impl Iterator<Item = &JsonValueWithNoDuplicateKeys> {
        self.residuals.values()
    }

    /// (Owned) Iterator over the set of residual policies
    pub fn into_residuals(self) -> impl Iterator<Item = JsonValueWithNoDuplicateKeys> {
        self.residuals.into_values()
    }

    /// Get the residual policy for a specified id if it exists
    pub fn residual(&self, p: &PolicyId) -> Option<&JsonValueWithNoDuplicateKeys> {
        self.residuals.get(p)
    }

    /// (Borrowed) Iterator over the set of non-trivial residual policies
    pub fn nontrivial_residuals(&self) -> impl Iterator<Item = &JsonValueWithNoDuplicateKeys> {
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
                .map(|e| e.to_json().map(|json| (e.id().clone(), json.into())))
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
#[serde(deny_unknown_fields)]
pub struct AuthorizationCall {
    /// The principal taking action
    principal: EntityUid,
    /// The action the principal is taking
    action: EntityUid,
    /// The resource being acted on by the principal
    resource: EntityUid,
    /// The context details specific to the request
    context: Context,
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
    validate_request: bool,
    /// The set of policies to use during authorization
    policies: PolicySet,
    /// The set of entities to use during authorization
    entities: Entities,
}

/// Struct containing the input data for partial authorization
#[cfg(feature = "partial-eval")]
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PartialAuthorizationCall {
    /// The principal taking action. If this field is empty, then the principal is unknown.
    principal: Option<EntityUid>,
    /// The action the principal is taking. If this field is empty, then the action is unknown.
    action: Option<EntityUid>,
    /// The resource being acted on by the principal. If this field is empty, then the resource is unknown.
    resource: Option<EntityUid>,
    /// The context details specific to the request
    context: Context,
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
    validate_request: bool,
    /// The set of policies to use during authorization
    policies: PolicySet,
    /// The set of entities to use during authorization
    entities: Entities,
}

fn constant_true() -> bool {
    true
}

fn build_error<T>(
    errs: Vec<miette::Report>,
    warnings: Vec<SchemaWarning>,
) -> WithWarnings<Result<T, Vec<miette::Report>>> {
    WithWarnings {
        t: Err(errs),
        warnings: warnings.into_iter().map(Into::into).collect(),
    }
}

impl AuthorizationCall {
    fn parse(
        self,
    ) -> WithWarnings<Result<(Request, crate::PolicySet, crate::Entities), Vec<miette::Report>>>
    {
        let mut errs = vec![];
        let mut warnings = vec![];
        let maybe_schema = self
            .schema
            .map(|schema| {
                schema.parse().map(|(schema, new_warnings)| {
                    warnings.extend(new_warnings);
                    schema
                })
            })
            .transpose()
            .map_err(|e| errs.push(e));
        let maybe_principal = self
            .principal
            .parse(Some("principal"))
            .map_err(|e| errs.push(e));
        let maybe_action = self.action.parse(Some("action")).map_err(|e| errs.push(e));
        let maybe_resource = self
            .resource
            .parse(Some("resource"))
            .map_err(|e| errs.push(e));

        let (Ok(schema), Ok(principal), Ok(action), Ok(resource)) =
            (maybe_schema, maybe_principal, maybe_action, maybe_resource)
        else {
            // At least one of the `errs.push(e)` statements above must have been reached
            return build_error(errs, warnings);
        };

        let context = match self.context.parse(schema.as_ref(), Some(&action)) {
            Ok(context) => context,
            Err(e) => {
                return build_error(vec![e], warnings);
            }
        };

        let schema_opt = if self.validate_request {
            schema.as_ref()
        } else {
            None
        };
        let maybe_request = Request::new(principal, action, resource, context, schema_opt)
            .map_err(|e| errs.push(e.into()));
        let maybe_entities = self
            .entities
            .parse(schema.as_ref())
            .map_err(|e| errs.push(e));
        let maybe_policies = self.policies.parse().map_err(|es| errs.extend(es));

        match (maybe_request, maybe_policies, maybe_entities) {
            (Ok(request), Ok(policies), Ok(entities)) => WithWarnings {
                t: Ok((request, policies, entities)),
                warnings: warnings.into_iter().map(Into::into).collect(),
            },
            _ => {
                // At least one of the `errs.push(e)` statements above must have been reached
                build_error(errs, warnings)
            }
        }
    }
}

#[cfg(feature = "partial-eval")]
impl PartialAuthorizationCall {
    fn parse(
        self,
    ) -> WithWarnings<Result<(Request, crate::PolicySet, crate::Entities), Vec<miette::Report>>>
    {
        let mut errs = vec![];
        let mut warnings = vec![];
        let maybe_schema = self
            .schema
            .map(|schema| {
                schema.parse().map(|(schema, new_warnings)| {
                    warnings.extend(new_warnings);
                    schema
                })
            })
            .transpose()
            .map_err(|e| errs.push(e));
        let maybe_principal = self
            .principal
            .map(|uid| uid.parse(Some("principal")))
            .transpose()
            .map_err(|e| errs.push(e));
        let maybe_action = self
            .action
            .map(|uid| uid.parse(Some("action")))
            .transpose()
            .map_err(|e| errs.push(e));
        let maybe_resource = self
            .resource
            .map(|uid| uid.parse(Some("resource")))
            .transpose()
            .map_err(|e| errs.push(e));

        let (Ok(schema), Ok(principal), Ok(action), Ok(resource)) =
            (maybe_schema, maybe_principal, maybe_action, maybe_resource)
        else {
            // At least one of the `errs.push(e)` statements above must have been reached
            return build_error(errs, warnings);
        };

        let context = match self.context.parse(schema.as_ref(), action.as_ref()) {
            Ok(context) => context,
            Err(e) => {
                return build_error(vec![e], warnings);
            }
        };

        let maybe_entities = self
            .entities
            .parse(schema.as_ref())
            .map_err(|e| errs.push(e));
        let maybe_policies = self.policies.parse().map_err(|es| errs.extend(es));

        let mut b = Request::builder();
        if let Some(p) = principal {
            b = b.principal(p);
        }
        if let Some(a) = action {
            b = b.action(a);
        }
        if let Some(r) = resource {
            b = b.resource(r);
        }
        b = b.context(context);

        let maybe_request = match schema {
            Some(schema) if self.validate_request => {
                b.schema(&schema).build().map_err(|e| errs.push(e.into()))
            }
            _ => Ok(b.build()),
        };

        match (maybe_request, maybe_policies, maybe_entities) {
            (Ok(request), Ok(policies), Ok(entities)) => WithWarnings {
                t: Ok((request, policies, entities)),
                warnings: warnings.into_iter().map(Into::into).collect(),
            },
            _ => {
                // At least one of the `errs.push(e)` statements above must have been reached
                build_error(errs, warnings)
            }
        }
    }
}

// PANIC SAFETY unit tests
#[allow(clippy::panic)]
#[cfg(test)]
mod test {
    use super::*;

    use crate::ffi::test_utils::*;
    use cool_asserts::assert_matches;
    use serde_json::json;

    /// Assert that [`is_authorized_json()`] returns `Allow` with no errors
    #[track_caller]
    fn assert_is_authorized_json(json: serde_json::Value) {
        let ans_val =
            is_authorized_json(json).expect("expected input to parse as an `AuthorizationCall`");
        let result: Result<AuthorizationAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(AuthorizationAnswer::Success { response, .. }) => {
            assert_eq!(response.decision(), Decision::Allow);
            let errors: Vec<&AuthorizationError> = response.diagnostics().errors().collect();
            assert_eq!(errors.len(), 0, "{errors:?}");
        });
    }

    /// Assert that [`is_authorized_json()`] returns `Deny` with no errors
    #[track_caller]
    fn assert_is_not_authorized_json(json: serde_json::Value) {
        let ans_val =
            is_authorized_json(json).expect("expected input to parse as an `AuthorizationCall`");
        let result: Result<AuthorizationAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(AuthorizationAnswer::Success { response, .. }) => {
            assert_eq!(response.decision(), Decision::Deny);
            let errors: Vec<&AuthorizationError> = response.diagnostics().errors().collect();
            assert_eq!(errors.len(), 0, "{errors:?}");
        });
    }

    /// Assert that [`is_authorized_json_str()`] returns a `serde_json::Error`
    /// error with a message that matches `msg`
    #[track_caller]
    fn assert_is_authorized_json_str_is_failure(call: &str, msg: &str) {
        assert_matches!(is_authorized_json_str(call), Err(e) => {
            assert_eq!(e.to_string(), msg);
        });
    }

    /// Assert that [`is_authorized_json()`] returns [`AuthorizationAnswer::Failure`]
    /// and return the enclosed errors
    #[track_caller]
    fn assert_is_authorized_json_is_failure(json: serde_json::Value) -> Vec<DetailedError> {
        let ans_val =
            is_authorized_json(json).expect("expected input to parse as an `AuthorizationCall`");
        let result: Result<AuthorizationAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(AuthorizationAnswer::Failure { errors, .. }) => errors)
    }

    #[test]
    fn test_failure_on_invalid_syntax() {
        assert_is_authorized_json_str_is_failure(
            "iefjieoafiaeosij",
            "expected value at line 1 column 1",
        );
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
            "policies": {},
            "entities": []
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
            "policies": {
                "staticPolicies": {
                    "ID1": "permit(principal == User::\"alice\", action, resource);"
                }
            },
            "entities": []
        });
        // unspecified entities are no longer supported
        let errs = assert_is_authorized_json_is_failure(call);
        assert_exactly_one_error(
            &errs,
            "failed to parse principal: in uid field of <unknown entity>, expected a literal entity reference, but got `null`",
            Some("literal entity references can be made with `{ \"type\": \"SomeType\", \"id\": \"SomeId\" }`"),
        );
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
            "policies": {
                "staticPolicies": {
                    "ID1": "permit(principal == User::\"alice\", action, resource);"
                }
            },
            "entities": []
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
            "policies": {
                "staticPolicies": "permit(principal == User::\"alice\", action, resource);"
            },
            "entities": []
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
            "policies": {
                "staticPolicies": "permit(principal == User::\"alice\", action, resource) when { context.is_authenticated && context.source_ip.isInRange(ip(\"222.222.222.0/24\")) };"
            },
            "entities": []
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
            "policies": {
                "staticPolicies": "permit(principal, action, resource in Folder::\"house\") when { resource.owner == principal };"
            },
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
            "policies": {
                "staticPolicies": {
                    "ID0": "permit(principal == User::\"jerry\", action, resource == Photo::\"doorx\");",
                    "ID1": "permit(principal == User::\"tom\", action, resource == Photo::\"doory\");",
                    "ID2": "permit(principal == User::\"alice\", action, resource == Photo::\"door\");"
                }
            },
            "entities": []
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
            "policies": {
                "staticPolicies": "permit(principal, action, resource in Folder::\"house\") when { resource.owner == principal };"
            },
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
            "policies": {
                "staticPolicies": {
                    "ID0": "permit(principal, action, resource);",
                    "ID1": "forbid(principal == User::\"alice\", action, resource == Photo::\"door\");"
                }
            },
             "entities": []
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
            "policies": {
                "staticPolicies": "permit(principal, action, resource);\nforbid(principal == User::\"alice\", action, resource);"
            },
             "entities": []
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
            "policies": {
                "staticPolicies": "permit(principal == ?principal, action, resource);"
            },
            "entities": []
        });
        let errs = assert_is_authorized_json_is_failure(call);
        assert_exactly_one_error(&errs, "static policy set includes a template", None);
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
            "policies": {
                "templates": {
                    "ID0": "permit(principal == ?principal, action, resource);"
                }
            },
            "entities": [],
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
            "policies": {
                "templates": {
                    "ID0": "permit(principal == ?principal, action, resource);"
                },
                "templateLinks": [
                    {
                        "templateId": "ID0",
                        "newId": "ID0_User_alice",
                        "values": {
                            "?principal": { "type": "User", "id": "alice" }
                        }
                    }
                ]
            },
            "entities": []
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
            "policies": {
                "staticPolicies": {
                    "ID0": "permit(principal, action, resource);"
                },
                "templates": {
                    "ID0": "permit(principal == ?principal, action, resource);"
                }
            },
            "entities" : []
        });
        let errs = assert_is_authorized_json_is_failure(call);
        assert_exactly_one_error(
            &errs,
            "failed to add template with id `ID0` to policy set: duplicate template or policy id `ID0`",
            None,
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
            "policies" : {
                "templates": {
                    "ID0": "permit(principal == ?principal, action, resource);"
                },
                "templateLinks" : [
                    {
                        "templateId" : "ID0",
                        "newId" : "ID1",
                        "values" : { "?principal": { "type" : "User", "id" : "alice" } }
                    },
                    {
                        "templateId" : "ID0",
                        "newId" : "ID1",
                        "values" : { "?principal": { "type" : "User", "id" : "alice" } }
                    }
                ]
            },
            "entities" : [],
        });
        let errs = assert_is_authorized_json_is_failure(call);
        assert_exactly_one_error(
            &errs,
            "unable to link template: template-linked policy id `ID1` conflicts with an existing policy id",
            None,
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
            "policies" : {
                "templates": {
                    "ID0": "permit(principal == ?principal, action, resource);"
                },
                "templateLinks" : [
                    {
                        "templateId" : "ID0",
                        "newId" : "ID0",
                        "values" : { "?principal": { "type" : "User", "id" : "alice" } }
                    }
                ]
            },
            "entities" : []

        });
        let errs = assert_is_authorized_json_is_failure(call);
        assert_exactly_one_error(
            &errs,
            "unable to link template: template-linked policy id `ID0` conflicts with an existing policy id",
            None,
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
            "policies" : {
                "staticPolicies" : {
                    "ID1": "permit(principal, action, resource);"
                },
                "templates": {
                    "ID0": "permit(principal == ?principal, action, resource);"
                },
                "templateLinks" : [
                    {
                        "templateId" : "ID0",
                        "newId" : "ID1",
                        "values" : { "?principal": { "type" : "User", "id" : "alice" } }
                    }
                ]
            },
            "entities" : []
        });
        let errs = assert_is_authorized_json_is_failure(call);
        assert_exactly_one_error(
            &errs,
            "unable to link template: template-linked policy id `ID1` conflicts with an existing policy id",
            None,
        );
    }

    #[test]
    fn test_authorized_fails_on_duplicate_policy_ids() {
        let call = r#"{
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
            "policies" : {
                "staticPolicies" : {
                    "ID0": "permit(principal, action, resource);",
                    "ID0": "permit(principal, action, resource);"
                }
            },
            "entities" : [],
        }"#;
        assert_is_authorized_json_str_is_failure(
            call,
            "expected a static policy set represented by a string, JSON array, or JSON object (with no duplicate keys) at line 20 column 13",
        );
    }

    #[test]
    fn test_authorized_fails_on_duplicate_template_ids() {
        let call = r#"{
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
            "policies" : {
                "templates" : {
                    "ID0": "permit(principal == ?principal, action, resource);",
                    "ID0": "permit(principal == ?principal, action, resource);"
                }
            },
            "entities" : []
        }"#;
        assert_is_authorized_json_str_is_failure(
            call,
            "invalid entry: found duplicate key at line 19 column 17",
        );
    }

    #[test]
    fn test_authorized_fails_on_duplicate_slot_link() {
        let call = r#"{
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
            "policies" : {
                "templates" : {
                    "ID0": "permit(principal == ?principal, action, resource);"
                },
                "templateLinks" : [{
                    "templateId" : "ID0",
                    "newId" : "ID1",
                    "values" : {
                        "?principal": { "type" : "User", "id" : "alice" },
                        "?principal": { "type" : "User", "id" : "alice" }
                    }
                }]
            },
            "entities" : [],
        }"#;
        assert_is_authorized_json_str_is_failure(
            call,
            "invalid entry: found duplicate key at line 25 column 21",
        );
    }

    #[test]
    fn test_authorized_fails_inconsistent_duplicate_entity_uid() {
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
            "policies" : {},
            "entities" : [
                {
                    "uid": {
                        "type" : "User",
                        "id" : "alice"
                    },
                    "attrs": {"location": "Greenland"},
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
            ]
        });
        let errs = assert_is_authorized_json_is_failure(call);
        assert_exactly_one_error(&errs, r#"duplicate entity entry `User::"alice"`"#, None);
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
            "policies" : {},
            "entities" : [],
        }"#;
        assert_is_authorized_json_str_is_failure(
            call,
            "the key `is_authenticated` occurs two or more times in the same JSON object at line 17 column 13",
        );
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
            "policies": {
                "staticPolicies": "permit(principal == User::\"alice\", action == Action::\"view\", resource);"
            },
            "entities": [],
            "schema": "entity User, Photo; action view appliesTo { principal: User, resource: Photo };"
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
            "policies": {
                "staticPolicies": "permit(principal == User::\"alice\", action == Action::\"view\", resource);"
            },
            "entities": [],
            "schema": "entity User, Photo; action view appliesTo { principal: User, resource: Photo };"
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
            "policies": {
                "staticPolicies": "permit(principal == User::\"alice\", action == Action::\"view\", resource);"
            },
            "entities": [],
            "schema": "entity User, Photo; action view appliesTo { principal: User, resource: Photo };",
            "validateRequest": false,
        });

        assert_is_authorized_json(good_call);
        let errs = assert_is_authorized_json_is_failure(bad_call);
        assert_exactly_one_error(
            &errs,
            "resource type `User` is not valid for `Action::\"view\"`",
            Some("valid resource types for `Action::\"view\"`: `Photo`"),
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
    fn assert_is_residual(call: serde_json::Value, expected_residuals: &HashSet<&str>) {
        let ans_val = is_authorized_partial_json(call).unwrap();
        let result: Result<PartialAuthorizationAnswer, _> = serde_json::from_value(ans_val);
        assert_matches!(result, Ok(PartialAuthorizationAnswer::Residuals { response, .. }) => {
            assert_eq!(response.decision(), None);
            let errors: Vec<_> = response.errored().collect();
            assert_eq!(errors.len(), 0, "{errors:?}");
            let actual_residuals: HashSet<_> = response.nontrivial_residual_ids().collect();
            for id in expected_residuals {
                assert!(actual_residuals.contains(&PolicyId::new(id)), "expected nontrivial residual for {id}, but it's missing");
            }
            for id in &actual_residuals {
                assert!(expected_residuals.contains(id.to_string().as_str()),"found unexpected nontrivial residual for {id}");
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
            "policies": {
                "staticPolicies": {
                    "ID1": "permit(principal == User::\"alice\", action, resource);"
                }
            },
            "entities": []
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
            "policies": {
                "staticPolicies": {
                    "ID1": "permit(principal == User::\"alice\", action, resource);"
                }
            },
            "entities": []
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
            "policies": {
                "staticPolicies": {
                    "ID1": "permit(principal == User::\"alice\", action, resource);"
                }
            },
            "entities": []
        });

        assert_is_residual(call, &HashSet::from(["ID1"]));
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
            "policies" : {
                "staticPolicies" : {
                    "ID1": "permit(principal, action, resource) when { principal == User::\"alice\" };"
                }
            },
            "entities": []
        });

        assert_is_residual(call, &HashSet::from(["ID1"]));
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
            "policies" : {
                "staticPolicies" : {
                    "ID1": "permit(principal, action, resource) when { principal == User::\"alice\" };",
                    "ID2": "forbid(principal, action, resource) unless { resource == Photo::\"door\" };"
                }
            },
            "entities": []
        });

        assert_is_residual(call, &HashSet::from(["ID1"]));
    }
}
