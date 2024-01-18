/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

//! This module contains the `json_is_authorized` entry point that other language
//! FFI's can call in order to use Cedar functionality
#![allow(clippy::module_name_repetitions)]
use super::utils::{InterfaceResult, PolicySpecification};
use crate::api::EntityId;
use crate::api::EntityTypeName;
#[cfg(feature = "partial-eval")]
use crate::api::PartialResponse;
use crate::PolicyId;
use crate::{
    Authorizer, Context, Decision, Entities, EntityUid, Policy, PolicySet, Request, Response,
    Schema, SlotId, Template,
};
use cedar_policy_core::jsonvalue::JsonValueWithNoDuplicateKeys;
use itertools::Itertools;
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::MapPreventDuplicates;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use thiserror::Error;

thread_local!(
    /// Per-thread authorizer instance, initialized on first use
    static AUTHORIZER: Authorizer = Authorizer::new();
);

/// Construct and ask the authorizer the request.
fn is_authorized(call: AuthorizationCall) -> AuthorizationAnswer {
    match call.get_components() {
        Ok((request, policies, entities)) => {
            AUTHORIZER.with(|authorizer| AuthorizationAnswer::Success {
                response: authorizer
                    .is_authorized(&request, &policies, &entities)
                    .into(),
            })
        }
        Err(errors) => AuthorizationAnswer::ParseFailed { errors },
    }
}

/// public string-based JSON interfaced to be invoked by FFIs. In the policies portion of
/// the `RecvdSlice`, you can either pass a `Map<String, String>` where the values are all single policies,
/// or a single String which is a concatenation of multiple policies. If you choose the latter,
/// policy id's will be auto-generated for you in the format `policyX` where X is a Natural Number (zero or a positive int)
pub fn json_is_authorized(input: &str) -> InterfaceResult {
    serde_json::from_str::<AuthorizationCall>(input).map_or_else(
        |e| InterfaceResult::fail_internally(format!("error parsing call: {e:}")),
        |call| match is_authorized(call) {
            answer @ AuthorizationAnswer::Success { .. } => InterfaceResult::succeed(answer),
            AuthorizationAnswer::ParseFailed { errors } => {
                InterfaceResult::fail_bad_request(errors)
            }
        },
    )
}

#[cfg(feature = "partial-eval")]
fn is_authorized_partial(call: AuthorizationCall) -> PartialAuthorizationAnswer {
    match call.get_components_partial() {
        Ok((request, policies, entities)) => AUTHORIZER.with(|authorizer| {
            match authorizer.is_authorized_partial(&request, &policies, &entities) {
                concrete_response @ PartialResponse::Concrete(_) => {
                    match concrete_response.try_into() {
                        Ok(response) => PartialAuthorizationAnswer::Concrete { response },
                        Err(errors) => PartialAuthorizationAnswer::ParseFailed { errors },
                    }
                }
                residual_response @ PartialResponse::Residual(_) => {
                    match residual_response.try_into() {
                        Ok(response) => PartialAuthorizationAnswer::Residuals { response },
                        Err(errors) => PartialAuthorizationAnswer::ParseFailed { errors },
                    }
                }
            }
        }),
        Err(errors) => PartialAuthorizationAnswer::ParseFailed { errors },
    }
}

/// public string-based JSON interfaced to be invoked by FFIs. In the policies portion of
/// the `RecvdSlice`, you can either pass a `Map<String, String>` where the values are all single policies,
/// or a single String which is a concatenation of multiple policies. If you choose the latter,
/// policy id's will be auto-generated for you in the format `policyX` where X is a Natural Number (zero or a positive int)
#[cfg(feature = "partial-eval")]
pub fn json_is_authorized_partial(input: &str) -> InterfaceResult {
    serde_json::from_str::<AuthorizationCall>(input).map_or_else(
        |e| InterfaceResult::fail_internally(format!("error parsing call: {e:}")),
        |call| match is_authorized_partial(call) {
            answer @ (PartialAuthorizationAnswer::Concrete { .. }
            | PartialAuthorizationAnswer::Residuals { .. }) => InterfaceResult::succeed(answer),
            PartialAuthorizationAnswer::ParseFailed { errors } => {
                InterfaceResult::fail_bad_request(errors)
            }
        },
    )
}

/// Interface version of a `Response` that uses `InterfaceDiagnostics` for simpler (de)serialization
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceResponse {
    /// Authorization decision
    decision: Decision,
    /// Diagnostics providing more information on how this decision was reached
    diagnostics: InterfaceDiagnostics,
}

/// Interface version of `Diagnostics` that stores error messages as strings for simpler (de)serialization
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct InterfaceDiagnostics {
    /// `PolicyId`s of the policies that contributed to the decision.
    /// If no policies applied to the request, this set will be empty.
    reason: HashSet<PolicyId>,
    /// Set of error messages that occurred
    errors: HashSet<String>,
}

impl InterfaceResponse {
    /// Construct an `InterfaceResponse`
    pub fn new(decision: Decision, reason: HashSet<PolicyId>, errors: HashSet<String>) -> Self {
        Self {
            decision,
            diagnostics: InterfaceDiagnostics { reason, errors },
        }
    }

    /// Get the authorization decision
    pub fn decision(&self) -> Decision {
        self.decision
    }

    /// Get the authorization diagnostics
    pub fn diagnostics(&self) -> &InterfaceDiagnostics {
        &self.diagnostics
    }
}

impl From<Response> for InterfaceResponse {
    fn from(response: Response) -> Self {
        Self::new(
            response.decision(),
            response.diagnostics().reason().cloned().collect(),
            response
                .diagnostics()
                .errors()
                .map(ToString::to_string)
                .collect(),
        )
    }
}

#[cfg(feature = "partial-eval")]
impl TryFrom<PartialResponse> for InterfaceResponse {
    type Error = Vec<String>;

    fn try_from(partial_response: PartialResponse) -> Result<Self, Self::Error> {
        match partial_response {
            PartialResponse::Concrete(concrete) => Ok(Self::new(
                concrete.decision(),
                concrete.diagnostics().reason().cloned().collect(),
                concrete
                    .diagnostics()
                    .errors()
                    .map(ToString::to_string)
                    .collect(),
            )),
            PartialResponse::Residual(_) => Err(vec!["unsupported".into()]),
        }
    }
}

impl InterfaceDiagnostics {
    /// Get the policies that contributed to the decision
    pub fn reason(&self) -> impl Iterator<Item = &PolicyId> {
        self.reason.iter()
    }

    /// Get the errors
    pub fn errors(&self) -> impl Iterator<Item = &str> + '_ {
        self.errors.iter().map(String::as_str)
    }
}

/// Integration version of a `PartialResponse` that uses `InterfaceDiagnistics` for simpler (de)serialization
#[cfg(feature = "partial-eval")]
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct InterfaceResidualResponse {
    /// A residual set of policies. Determining the concrete response requires further processing.
    residuals: HashMap<PolicyId, serde_json::Value>,
    /// Diagnostics providing more information on how this decision was reached
    diagnostics: InterfaceDiagnostics,
}

#[cfg(feature = "partial-eval")]
impl InterfaceResidualResponse {
    /// Construct an `InterfaceResidualResponse`
    pub fn new(
        residuals: HashMap<PolicyId, serde_json::Value>,
        reason: HashSet<PolicyId>,
        errors: HashSet<String>,
    ) -> Self {
        Self {
            residuals,
            diagnostics: InterfaceDiagnostics { reason, errors },
        }
    }
}

#[cfg(feature = "partial-eval")]
impl TryFrom<PartialResponse> for InterfaceResidualResponse {
    type Error = Vec<String>;

    fn try_from(partial_response: PartialResponse) -> Result<Self, Self::Error> {
        match partial_response {
            PartialResponse::Residual(residual) => Ok(Self::new(
                residual
                    .residuals()
                    .policies()
                    .map(|policy| match policy.to_json() {
                        Ok(json) => Ok((policy.id().clone(), json)),
                        Err(errors) => Err(vec![errors.to_string()]),
                    })
                    .collect::<Result<Vec<(PolicyId, serde_json::Value)>, Self::Error>>()?
                    .into_iter()
                    .collect(),
                residual.diagnostics().reason().cloned().collect(),
                residual
                    .diagnostics()
                    .errors()
                    .map(ToString::to_string)
                    .collect(),
            )),
            PartialResponse::Concrete(_) => Err(vec!["unsupported".into()]),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum AuthorizationAnswer {
    ParseFailed { errors: Vec<String> },
    Success { response: InterfaceResponse },
}

#[cfg(feature = "partial-eval")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum PartialAuthorizationAnswer {
    ParseFailed { errors: Vec<String> },
    Concrete { response: InterfaceResponse },
    Residuals { response: InterfaceResidualResponse },
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
struct AuthorizationCall {
    principal: Option<JsonValueWithNoDuplicateKeys>,
    action: JsonValueWithNoDuplicateKeys,
    resource: Option<JsonValueWithNoDuplicateKeys>,
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    context: HashMap<String, JsonValueWithNoDuplicateKeys>,
    /// Optional schema in JSON format.
    /// If present, this will inform the parsing: for instance, it will allow
    /// `__entity` and `__extn` escapes to be implicit, and it will error if
    /// attributes have the wrong types (e.g., string instead of integer).
    #[serde(rename = "schema")]
    schema: Option<JsonValueWithNoDuplicateKeys>,
    /// If this is `true` and a schema is provided, perform request validation.
    /// If this is `false`, the schema will only be used for schema-based
    /// parsing of `context`, and not for request validation.
    /// If a schema is not provided, this option has no effect.
    #[serde(default = "constant_true")]
    enable_request_validation: bool,
    slice: RecvdSlice,
}

fn constant_true() -> bool {
    true
}

fn parse_schema(
    schema_json: Option<JsonValueWithNoDuplicateKeys>,
) -> Result<Option<Schema>, Vec<String>> {
    schema_json
        .map(|v| Schema::from_json_value(v.into()))
        .transpose()
        .map_err(|e| vec![e.to_string()])
}

fn parse_entity_uid(
    entity_uid_json: Option<JsonValueWithNoDuplicateKeys>,
    category: &str,
) -> Result<Option<EntityUid>, Vec<String>> {
    entity_uid_json
        .map(|v| EntityUid::from_json(v.into()))
        .transpose()
        .map_err(|e| vec![format!("Failed to parse {category}"), e.to_string()])
}

fn parse_action(entity_uid_json: JsonValueWithNoDuplicateKeys) -> Result<EntityUid, Vec<String>> {
    parse_entity_uid(Some(entity_uid_json), "action")?
        .map_or_else(|| Err(vec!["parsing action return none".into()]), Ok)
}

fn parse_context(
    context_map: HashMap<String, JsonValueWithNoDuplicateKeys>,
    schema_ref: Option<&Schema>,
    action_ref: &EntityUid,
) -> Result<Context, Vec<String>> {
    let context = serde_json::to_value(context_map)
        .map_err(|e| vec!["Failed to parse context".into(), e.to_string()])?;
    Context::from_json_value(context, schema_ref.map(|s| (s, action_ref)))
        .map_err(|e| vec![e.to_string()])
}

impl AuthorizationCall {
    fn get_components(self) -> Result<(Request, PolicySet, Entities), Vec<String>> {
        let schema = parse_schema(self.schema)?;
        let principal = parse_entity_uid(self.principal, "principal")?;
        let action = parse_action(self.action)?;
        let resource = parse_entity_uid(self.resource, "resource")?;
        let context = parse_context(self.context, schema.as_ref(), &action)?;
        let q = Request::new(
            principal,
            Some(action),
            resource,
            context,
            if self.enable_request_validation {
                schema.as_ref()
            } else {
                None
            },
        )
        .map_err(|e| [e.to_string()])?;
        let (policies, entities) = self.slice.try_into(schema.as_ref())?;
        Ok((q, policies, entities))
    }

    #[cfg(feature = "partial-eval")]
    fn get_components_partial(self) -> Result<(Request, PolicySet, Entities), Vec<String>> {
        let schema = parse_schema(self.schema)?;
        let principal = parse_entity_uid(self.principal, "principal")?;
        let action = parse_action(self.action)?;
        let resource = parse_entity_uid(self.resource, "resource")?;
        let context = parse_context(self.context, schema.as_ref(), &action)?;
        let mut b = Request::builder().action(Some(action)).context(context);
        if principal.is_some() {
            b = b.principal(principal);
        }
        if resource.is_some() {
            b = b.resource(resource);
        }
        if self.enable_request_validation {
            b = match schema.as_ref() {
                Some(schema_ref) => b.schema(schema_ref),
                None => b,
            }
        }
        let q = b.build().map_err(|e| [e.to_string()])?;
        let (policies, entities) = self.slice.try_into(schema.as_ref())?;
        Ok((q, policies, entities.partial()))
    }
}

///
/// Entity UID as strings.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EntityUIDStrings {
    ty: String,
    eid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Link {
    slot: String,
    value: EntityUIDStrings,
}

#[derive(Debug, Serialize, Deserialize)]
struct TemplateLink {
    /// Template ID to fill in
    template_id: String,

    /// Policy id for resulting concrete policy instance
    result_policy_id: String,

    /// List of strings to fill in all slots in policy template "template_id".
    /// (slot, String)
    instantiations: Links,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "Vec<Link>")]
#[serde(into = "Vec<Link>")]
struct Links(Vec<Link>);

/// Error returned for duplicate link ids in a template instantiation
#[derive(Debug, Clone, Diagnostic, Error)]
pub enum DuplicateLinkError {
    /// Duplicate instantiations for the same slot
    #[error("duplicate instantiations of the slot(s): {}", .0.iter().map(|s| format!("`{s}`")).join(", "))]
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
struct RecvdSlice {
    policies: PolicySpecification,
    /// JSON object containing the entities data, in "natural JSON" form -- same
    /// format as expected by EntityJsonParser
    entities: JsonValueWithNoDuplicateKeys,

    /// Optional template policies.
    #[serde_as(as = "Option<MapPreventDuplicates<_, _>>")]
    templates: Option<HashMap<String, String>>,

    /// Optional template instantiations.
    /// List of instantiations, one per
    /// If present, instantiate policies
    template_instantiations: Option<Vec<TemplateLink>>,
}

fn parse_instantiation(v: &Link) -> Result<(SlotId, EntityUid), Vec<String>> {
    let slot = match v.slot.as_str() {
        "?principal" => SlotId::principal(),
        "?resource" => SlotId::resource(),
        _ => {
            return Err(vec![
                "Slot must by \"?principal\" or \"?resource\"".to_string()
            ]);
        }
    };
    let type_name = EntityTypeName::from_str(v.value.ty.as_str());
    let eid = match EntityId::from_str(v.value.eid.as_str()) {
        Ok(eid) => eid,
        Err(err) => match err {},
    };
    match type_name {
        Ok(type_name) => {
            let entity_uid = EntityUid::from_type_name_and_id(type_name, eid);
            Ok((slot, entity_uid))
        }
        Err(e) => Err(e.errors_as_strings()),
    }
}

fn parse_instantiations(
    policies: &mut PolicySet,
    instantiation: TemplateLink,
) -> Result<(), Vec<String>> {
    let template_id = PolicyId::from_str(instantiation.template_id.as_str());
    let instance_id = PolicyId::from_str(instantiation.result_policy_id.as_str());
    match (template_id, instance_id) {
        (Err(never), _) | (_, Err(never)) => match never {},
        (Ok(template_id), Ok(instance_id)) => {
            let mut vals = HashMap::new();
            for i in instantiation.instantiations.0 {
                match parse_instantiation(&i) {
                    Err(e) => return Err(e),
                    Ok(val) => vals.insert(val.0, val.1),
                };
            }
            match policies.link(template_id, instance_id, vals) {
                Ok(()) => Ok(()),
                Err(e) => Err(vec![format!("Error instantiating template: {e}")]),
            }
        }
    }
}

impl RecvdSlice {
    #[allow(clippy::too_many_lines)]
    fn try_into(self, schema: Option<&Schema>) -> Result<(PolicySet, Entities), Vec<String>> {
        let Self {
            policies,
            entities,
            templates,
            template_instantiations,
        } = self;

        let policy_set = match policies {
            PolicySpecification::Concatenated(policies) => match PolicySet::from_str(&policies) {
                Ok(ps) => Ok(ps),
                Err(parse_errors) => Err(std::iter::once(
                    "couldn't parse concatenated policies string".to_string(),
                )
                .chain(parse_errors.errors_as_strings())
                .collect()),
            },
            PolicySpecification::Map(policies) => {
                parse_policy_set_from_individual_policies(&policies, templates)
            }
        };

        let mut errs = Vec::new();

        let (mut policies, entities) = match (
            Entities::from_json_value(entities.into(), schema),
            policy_set,
        ) {
            (Ok(entities), Ok(policies)) => (policies, entities),
            (Ok(_), Err(policy_parse_errors)) => {
                errs.extend(policy_parse_errors);
                (PolicySet::new(), Entities::empty())
            }
            (Err(e), Ok(_)) => {
                errs.push(e.to_string());
                (PolicySet::new(), Entities::empty())
            }
            (Err(e), Err(policy_parse_errors)) => {
                errs.push(e.to_string());
                errs.extend(policy_parse_errors);
                (PolicySet::new(), Entities::empty())
            }
        };

        if let Some(t_inst_list) = template_instantiations {
            for instantiation in t_inst_list {
                match parse_instantiations(&mut policies, instantiation) {
                    Ok(()) => (),
                    Err(err) => errs.extend(err),
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

fn parse_policy_set_from_individual_policies(
    policies: &HashMap<String, String>,
    templates: Option<HashMap<String, String>>,
) -> Result<PolicySet, Vec<String>> {
    let mut policy_set = PolicySet::new();
    let mut errs = Vec::new();
    for (id, policy_src) in policies {
        match Policy::parse(Some(id.clone()), policy_src) {
            Ok(p) => match policy_set.add(p) {
                Ok(()) => {}
                Err(err) => {
                    errs.push(format!("couldn't add policy to set due to error: {err}"));
                }
            },
            Err(pes) => errs.extend(
                std::iter::once(format!("couldn't parse policy with id `{id}`"))
                    .chain(pes.errors_as_strings().into_iter()),
            ),
        }
    }

    if let Some(templates) = templates {
        for (id, policy_src) in templates {
            match Template::parse(Some(id.clone()), policy_src) {
                Ok(p) => match policy_set.add_template(p) {
                    Ok(()) => {}
                    Err(err) => {
                        errs.push(format!("couldn't add policy to set due to error: {err}"));
                    }
                },
                Err(pes) => errs.extend(
                    std::iter::once(format!("couldn't parse policy with id `{id}`"))
                        .chain(pes.errors_as_strings().into_iter()),
                ),
            }
        }
    }

    if errs.is_empty() {
        Ok(policy_set)
    } else {
        Err(errs)
    }
}

// PANIC SAFETY unit tests
#[allow(clippy::panic)]
#[cfg(test)]
mod test {
    use super::*;
    use crate::{frontend::utils::assert_is_failure, EntityUid};
    use cool_asserts::assert_matches;
    use std::collections::HashMap;

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
            policies: PolicySpecification::Map(HashMap::new()),
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
        assert_is_failure(
            &json_is_authorized("iefjieoafiaeosij"),
            true,
            "expected value",
        );
    }

    #[test]
    fn test_not_authorized_on_empty_slice() {
        let call = r#"
        {
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
           }
        "#;

        assert_is_not_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_not_authorized_on_unspecified() {
        let call = r#"
        {
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
           }
        "#;

        assert_is_not_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_on_simple_slice() {
        let call = r#"
        {
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
           }
        "#;

        assert_is_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_on_simple_slice_with_string_policies() {
        let call = r#"
        {
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
           }
	         "#;

        assert_is_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_on_simple_slice_with_context() {
        let call = r#"
        {
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
           }
        "#;

        assert_is_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_on_simple_slice_with_attrs_and_parents() {
        let call = r#"
        {
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
           }
        "#;

        assert_is_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_on_multi_policy_slice() {
        let call = r#"
        {
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
           }
	         "#;
        assert_is_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_on_multi_policy_slice_with_string_policies() {
        let call = r#"
        {
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
           }
	         "#;
        assert_is_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_on_multi_policy_slice_denies_when_expected() {
        let call = r#"
        {
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
           }
	         "#;
        assert_is_not_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_on_multi_policy_slice_with_string_policies_denies_when_expected() {
        let call = r#"
        {
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
           }
	         "#;

        assert_is_not_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_with_template_as_policy_should_fail() {
        let call = r#"
        {
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
           }
	         "#;
        assert_is_not_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_with_template_should_fail() {
        let call = r#"
        {
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
           }
	         "#;
        assert_is_not_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_with_template_instantiation() {
        let call = r#"
        {
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
             "template_instantiations": [
              {
               "template_id": "ID0",
               "result_policy_id": "ID0_User_alice",
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
           }
	         "#;
        assert_is_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_fails_on_policy_collision_with_template() {
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
            "slice" : {
                "policies" : { "ID0": "permit(principal, action, resource);" },
                "entities" : [],
                "templates" : { "ID0": "permit(principal == ?principal, action, resource);" },
                "template_instantiations" : []
            }
        }"#;
        assert_is_failure(
            &json_is_authorized(call),
            false,
            "couldn't add policy to set due to error: duplicate template or policy id `ID0`",
        );
    }

    #[test]
    fn test_authorized_fails_on_duplicate_instantiations_ids() {
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
            "slice" : {
                "policies" : {},
                "entities" : [],
                "templates" : { "ID0": "permit(principal == ?principal, action, resource);" },
                "template_instantiations" : [
                    {
                        "template_id" : "ID0",
                        "result_policy_id" : "ID1",
                        "instantiations" : [
                            {
                                "slot": "?principal",
                                "value": { "ty" : "User", "eid" : "alice" }
                            }
                        ]
                    },
                    {
                        "template_id" : "ID0",
                        "result_policy_id" : "ID1",
                        "instantiations" : [
                            {
                                "slot": "?principal",
                                "value": { "ty" : "User", "eid" : "alice" }
                            }
                        ]
                    }
                ]
            }
        }"#;
        assert_is_failure(
            &json_is_authorized(call),
            false,
            "Error instantiating template: unable to link template: template-linked policy id `ID1` conflicts with an existing policy id",
        );
    }

    #[test]
    fn test_authorized_fails_on_template_instantiation_collision_with_template() {
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
            "slice" : {
                "policies" : {},
                "entities" : [],
                "templates" : { "ID0": "permit(principal == ?principal, action, resource);" },
                "template_instantiations" : [
                    {
                        "template_id" : "ID0",
                        "result_policy_id" : "ID0",
                        "instantiations" : [
                            {
                                "slot": "?principal",
                                "value": { "ty" : "User", "eid" : "alice" }
                            }
                        ]
                    }
                ]
            }
        }"#;
        assert_is_failure(
            &json_is_authorized(call),
            false,
            "Error instantiating template: unable to link template: template-linked policy id `ID0` conflicts with an existing policy id",
        );
    }

    #[test]
    fn test_authorized_fails_on_template_instantiation_collision_with_policy() {
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
            "slice" : {
                "policies" : { "ID1": "permit(principal, action, resource);" },
                "entities" : [],
                "templates" : { "ID0": "permit(principal == ?principal, action, resource);" },
                "template_instantiations" : [
                    {
                        "template_id" : "ID0",
                        "result_policy_id" : "ID1",
                        "instantiations" : [
                            {
                                "slot": "?principal",
                                "value": { "ty" : "User", "eid" : "alice" }
                            }
                        ]
                    }
                ]
            }
        }"#;
        assert_is_failure(
            &json_is_authorized(call),
            false,
            "Error instantiating template: unable to link template: template-linked policy id `ID1` conflicts with an existing policy id",
        );
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_is_authorized(result: InterfaceResult) {
        assert_matches!(result, InterfaceResult::Success { result } => {
            let parsed_result: AuthorizationAnswer =
                serde_json::from_str(result.as_str()).unwrap();
            assert_matches!(parsed_result, AuthorizationAnswer::Success { response } => {
                assert_eq!(response.decision(), Decision::Allow);
                assert_eq!(response.diagnostics().errors.len(), 0);
            });
        });
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_is_not_authorized(result: InterfaceResult) {
        assert_matches!(result, InterfaceResult::Success { result } => {
            let parsed_result: AuthorizationAnswer =
                serde_json::from_str(result.as_str()).unwrap();
            assert_matches!(parsed_result, AuthorizationAnswer::Success { response } => {
                assert_eq!(response.decision(), Decision::Deny);
                assert_eq!(response.diagnostics().errors.len(), 0);
            });
        });
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
                "template_instantiations" : [ ]
            }
        }"#;
        assert_is_failure(&json_is_authorized(call), true, "no duplicate IDs");
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
                "template_instantiations" : [ ]
            }
        }"#;
        assert_is_failure(&json_is_authorized(call), true, "found duplicate key");
    }

    #[test]
    fn test_authorized_fails_on_duplicate_slot_instantiation1() {
        let call = r#"{
            "principal" : "User::\"alice\"",
            "action" : "Photo::\"view\"",
            "resource" : "Photo::\"door\"",
            "context" : {},
            "slice" : {
                "policies" : {},
                "entities" : [],
                "templates" : { "ID0": "permit(principal == ?principal, action, resource);" },
                "template_instantiations" : [
                    {
                        "template_id" : "ID0",
                        "result_policy_id" : "ID1",
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
        }"#;
        assert_is_failure(
            &json_is_authorized(call),
            true,
            "duplicate instantiations of the slot(s): `?principal`",
        );
    }

    #[test]
    fn test_authorized_fails_on_duplicate_slot_instantiation2() {
        let call = r#"{
            "principal" : "User::\"alice\"",
            "action" : "Photo::\"view\"",
            "resource" : "Photo::\"door\"",
            "context" : {},
            "slice" : {
                "policies" : {},
                "entities" : [],
                "templates" : { "ID0": "permit(principal == ?principal, action, resource);" },
                "template_instantiations" : [
                    {
                        "template_id" : "ID0",
                        "result_policy_id" : "ID1",
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
        }"#;
        assert_is_failure(
            &json_is_authorized(call),
            true,
            "duplicate instantiations of the slot(s): `?principal`",
        );
    }

    #[test]
    fn test_authorized_fails_on_duplicate_slot_instantiation3() {
        let call = r#"{
            "principal" : "User::\"alice\"",
            "action" : "Photo::\"view\"",
            "resource" : "Photo::\"door\"",
            "context" : {},
            "slice" : {
                "policies" : {},
                "entities" : [],
                "templates" : { "ID0": "permit(principal == ?principal, action, resource);" },
                "template_instantiations" : [
                    {
                        "template_id" : "ID0",
                        "result_policy_id" : "ID1",
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
        }"#;
        assert_is_failure(
            &json_is_authorized(call),
            true,
            "duplicate instantiations of the slot(s): `?principal`, `?resource`",
        );
    }

    #[test]
    fn test_authorized_fails_duplicate_entity_uid() {
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
                "template_instantiations" : []
            }
        }"#;
        assert_is_failure(
            &json_is_authorized(call),
            false,
            r#"duplicate entity entry `User::"alice"`"#,
        );
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
                "template_instantiations" : []
            }
        }"#;
        assert_is_failure(&json_is_authorized(call), true, "found duplicate key");
    }

    #[cfg(feature = "partial-eval")]
    mod partial {
        use super::super::PartialAuthorizationAnswer;
        use crate::frontend::is_authorized::json_is_authorized_partial;
        use crate::frontend::utils::InterfaceResult;
        use crate::Decision;
        use crate::PolicyId;
        use cool_asserts::assert_matches;
        use std::collections::HashSet;
        use std::str::FromStr;

        #[test]
        fn test_authorized_partial_no_resource() {
            let call = r#"
              {
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
              }
            "#;
            assert_is_authorized(json_is_authorized_partial(call));
        }

        #[test]
        fn test_authorized_partial_not_authorized_no_resource() {
            let call = r#"
              {
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
              }
            "#;
            assert_is_not_authorized(json_is_authorized_partial(call));
        }

        #[test]
        fn test_authorized_partial_residual_no_principal_scope() {
            let call = r#"
              {
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
              }
            "#;
            assert_is_residual(json_is_authorized_partial(call), HashSet::from(["ID1"]));
        }

        #[test]
        fn test_authorized_partial_residual_no_principal_when() {
            let call = r#"
              {
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
              }
            "#;
            assert_is_residual(json_is_authorized_partial(call), HashSet::from(["ID1"]));
        }

        #[test]
        fn test_authorized_partial_residual_no_principal_ignored_forbid() {
            let call = r#"
              {
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
              }
            "#;
            assert_is_residual(json_is_authorized_partial(call), HashSet::from(["ID1"]));
        }

        #[track_caller] // report the caller's location as the location of the panic, not the location in this function
        fn assert_is_authorized(result: InterfaceResult) {
            assert_matches!(result, InterfaceResult::Success { result } => {
                let parsed_result: PartialAuthorizationAnswer = serde_json::from_str(result.as_str()).unwrap();
                assert_matches!(parsed_result, PartialAuthorizationAnswer::Concrete { response } => {
                    assert_eq!(response.decision(), Decision::Allow);
                    assert_eq!(response.diagnostics().errors.len(), 0);
                });
            });
        }

        #[track_caller] // report the caller's location as the location of the panic, not the location in this function
        fn assert_is_not_authorized(result: InterfaceResult) {
            assert_matches!(result, InterfaceResult::Success { result } => {
                let parsed_result: PartialAuthorizationAnswer = serde_json::from_str(result.as_str()).unwrap();
                assert_matches!(parsed_result, PartialAuthorizationAnswer::Concrete { response } => {
                    assert_eq!(response.decision(), Decision::Deny);
                    assert_eq!(response.diagnostics().errors.len(), 0);
                });
            });
        }

        #[track_caller] // report the caller's location as the location of the panic, not the location in this function
        fn assert_is_residual(result: InterfaceResult, residual_ids: HashSet<&str>) {
            assert_matches!(result, InterfaceResult::Success { result } => {
                let parsed_result: PartialAuthorizationAnswer = serde_json::from_str(result.as_str()).unwrap();
                assert_matches!(parsed_result, PartialAuthorizationAnswer::Residuals { response } => {
                    let num_errors = response.diagnostics.errors().count();
                    assert_eq!(num_errors, 0, "got {num_errors} errors");
                    let residuals = response.residuals;
                    for id in &residual_ids {
                        assert!(residuals.contains_key(&PolicyId::from_str(id).ok().unwrap()), "expected residual for {id}, but it's missing")
                    }
                    for key in residuals.keys() {
                        assert!(residual_ids.contains(key.to_string().as_str()),"found unexpected residual for {key}")
                    }
                })
            })
        }
    }
}
