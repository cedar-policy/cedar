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
use crate::PolicyId;
use crate::{
    Authorizer, Context, Decision, Entities, EntityUid, ParseErrors, Policy, PolicySet, Request,
    Response, Schema, SlotId, Template,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

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
/// policy id's will be auto-generated for you in the format `policyX` where X is a Whole Number (zero or a positive int)
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum AuthorizationAnswer {
    ParseFailed { errors: Vec<String> },
    Success { response: InterfaceResponse },
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthorizationCall {
    principal: Option<serde_json::Value>,
    action: serde_json::Value,
    resource: Option<serde_json::Value>,
    context: serde_json::Value,
    /// Optional schema in JSON format.
    /// If present, this will inform the parsing: for instance, it will allow
    /// `__entity` and `__extn` escapes to be implicit, and it will error if
    /// attributes have the wrong types (e.g., string instead of integer).
    #[serde(rename = "schema")]
    schema: Option<serde_json::Value>,
    slice: RecvdSlice,
}

impl AuthorizationCall {
    fn get_components(self) -> Result<(Request, PolicySet, Entities), Vec<String>> {
        let schema = self
            .schema
            .map(Schema::from_json_value)
            .transpose()
            .map_err(|e| [e.to_string()])?;
        let principal = match self.principal {
            Some(p) => Some(
                EntityUid::from_json(p)
                    .map_err(|e| ["Failed to parse principal".into(), e.to_string()])?,
            ),
            None => None,
        };
        let action = EntityUid::from_json(self.action)
            .map_err(|e| ["Failed to parse action".into(), e.to_string()])?;
        let resource = match self.resource {
            Some(r) => Some(
                EntityUid::from_json(r)
                    .map_err(|e| ["Failed to parse resource".into(), e.to_string()])?,
            ),
            None => None,
        };

        let context = Context::from_json_value(self.context, schema.as_ref().map(|s| (s, &action)))
            .map_err(|e| [e.to_string()])?;
        let q = Request::new(principal, Some(action), resource, context);
        let (policies, entities) = self.slice.try_into(schema.as_ref())?;
        Ok((q, policies, entities))
    }
}

///
/// Entity UID as strings.
///
#[derive(Debug, Serialize, Deserialize)]
struct EntityUIDStrings {
    ty: String,
    eid: String,
}

#[derive(Debug, Serialize, Deserialize)]
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
    instantiations: Vec<Link>,
}

/// policies must either be a single policy per entry, or only one entry with more than one policy
#[derive(Debug, Serialize, Deserialize)]
struct RecvdSlice {
    policies: PolicySpecification,
    /// JSON object containing the entities data, in "natural JSON" form -- same
    /// format as expected by EntityJsonParser
    entities: serde_json::Value,

    /// Optional template policies.
    templates: Option<HashMap<String, String>>,

    /// Optional template instantiations.
    /// List of instantiations, one per
    /// If present, instantiate policies
    template_instantiations: Option<Vec<TemplateLink>>,
}

impl RecvdSlice {
    #[allow(clippy::too_many_lines)]
    fn try_into(self, schema: Option<&Schema>) -> Result<(PolicySet, Entities), Vec<String>> {
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
            let eid = EntityId::from_str(v.value.eid.as_str());
            match (type_name, eid) {
                (Ok(type_name), Ok(eid)) => {
                    let entity_uid = EntityUid::from_type_name_and_id(type_name, eid);
                    Ok((slot, entity_uid))
                }
                (Ok(_), Err(e)) | (Err(e), Ok(_)) => Err(e.errors_as_strings()),
                (Err(mut e1), Err(mut e2)) => {
                    e1.0.append(&mut e2.0);
                    Err(ParseErrors(e1.0).errors_as_strings())
                }
            }
        }

        fn parse_instantiations(
            policies: &mut PolicySet,
            instantiation: TemplateLink,
        ) -> Result<(), Vec<String>> {
            let template_id = PolicyId::from_str(instantiation.template_id.as_str());
            let instance_id = PolicyId::from_str(instantiation.result_policy_id.as_str());
            match (template_id, instance_id) {
                (Ok(_), Err(e)) | (Err(e), Ok(_)) => Err(e.errors_as_strings()),
                (Err(mut e1), Err(mut e2)) => {
                    e1.0.append(&mut e2.0);
                    Err(ParseErrors(e1.0).errors_as_strings())
                }
                (Ok(template_id), Ok(instance_id)) => {
                    let mut vals = HashMap::new();
                    for i in instantiation.instantiations {
                        match parse_instantiation(&i) {
                            Err(e) => return Err(e),
                            Ok(val) => vals.insert(val.0, val.1),
                        };
                    }
                    match policies.link(template_id, instance_id, vals) {
                        Ok(_) => Ok(()),
                        Err(e) => Err(vec![format!("Error instantiating template: {e}")]),
                    }
                }
            }
        }

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
                .chain(parse_errors.errors_as_strings().into_iter())
                .collect()),
            },
            PolicySpecification::Map(policies) => {
                parse_policy_set_from_individual_policies(&policies, templates)
            }
        };

        let mut errs = Vec::new();

        let (mut policies, entities) =
            match (Entities::from_json_value(entities, schema), policy_set) {
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
                    Ok(_) => (),
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
                Ok(_) => {}
                Err(err) => {
                    errs.push(format!("couldn't add policy to set due to error: {err:?}"));
                }
            },
            Err(pes) => errs.extend(
                std::iter::once(format!("couldn't parse policy with id {id}"))
                    .chain(pes.errors_as_strings().into_iter()),
            ),
        }
    }

    if let Some(templates) = templates {
        for (id, policy_src) in templates {
            match Template::parse(Some(id.clone()), policy_src) {
                Ok(p) => match policy_set.add_template(p) {
                    Ok(_) => {}
                    Err(err) => {
                        errs.push(format!("couldn't add policy to set due to error: {err:?}"));
                    }
                },
                Err(pes) => errs.extend(
                    std::iter::once(format!("couldn't parse policy with id {id}"))
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::EntityUid;
    use std::collections::HashMap;

    #[test]
    fn test_slice_convert() {
        let entities = serde_json::json!(
            [
                {
                    "uid": { "__expr": "user::\"alice\"" },
                    "attrs": { "foo": "bar" },
                    "parents": [{ "__expr": "user::\"bob\"" }]
                },
                {
                    "uid": { "__expr": "user::\"bob\"" },
                    "attrs": {},
                    "parents": []
                }
            ]
        );
        let rslice = RecvdSlice {
            policies: PolicySpecification::Map(HashMap::new()),
            entities,
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
        assert_is_failure(&json_is_authorized("iefjieoafiaeosij"));
    }

    #[test]
    fn test_not_authorized_on_empty_slice() {
        let call = r#"
            { "principal": "User::\"alice\""
            , "action" : "Photo::\"view\""
            , "resource" : "Photo::\"door\""
            , "context" : {}
            , "slice" : {
                  "policies" : {}
                , "entities" : []
            }
         }
        "#;

        assert_is_not_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_on_simple_slice() {
        let call = r#"
            { "principal": "User::\"alice\""
            , "action" : "Photo::\"view\""
            , "resource" : "Photo::\"door\""
            , "context" : {}
            , "slice" : {
                  "policies" : {
                    "ID1": "permit(principal == User::\"alice\", action, resource);"
                  }
                , "entities" : []
            }
         }
        "#;

        assert_is_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_on_simple_slice_with_string_policies() {
        let call = r#"
	             { "principal": "User::\"alice\""
	             , "action" : "Photo::\"view\""
	             , "resource" : "Photo::\"door\""
	             , "context" : {}
	             , "slice" : {
	                   "policies" : "permit(principal == User::\"alice\", action, resource);"
	                 , "entities" : []
	             }
	          }
	         "#;

        assert_is_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_on_simple_slice_with_context() {
        let call = r#"
            { "principal": "User::\"alice\""
            , "action" : "Photo::\"view\""
            , "resource" : "Photo::\"door\""
            , "context" : {
                "is_authenticated": true,
                "source_ip": { "__expr": "ip(\"222.222.222.222\")" }
            }
            , "slice" : {
                  "policies" : "permit(principal == User::\"alice\", action, resource) when { context.is_authenticated && context.source_ip.isInRange(ip(\"222.222.222.0/24\")) };"
                , "entities" : []
            }
            }
        "#;

        assert_is_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_on_simple_slice_with_attrs_and_parents() {
        let call = r#"
            { "principal": "User::\"alice\""
            , "action" : "Photo::\"view\""
            , "resource" : "Photo::\"door\""
            , "context" : {}
            , "slice" : {
                  "policies" : "permit(principal, action, resource in Folder::\"house\") when { resource.owner == principal };"
                , "entities" : [
                    {
                        "uid": { "__expr": "User::\"alice\"" },
                        "attrs": {},
                        "parents": []
                    },
                    {
                        "uid": { "__expr": "Photo::\"door\"" },
                        "attrs": {
                            "owner": { "__expr": "User::\"alice\"" }
                        },
                        "parents": [{ "__expr": "Folder::\"house\"" }]
                    },
                    {
                        "uid": { "__expr": "Folder::\"house\"" },
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
	             { "principal": "User::\"alice\""
	             , "action" : "Photo::\"view\""
	             , "resource" : "Photo::\"door\""
	             , "context" : {}
	             , "slice" : {
	                   "policies" : {
	                     "ID0": "permit(principal == User::\"jerry\", action, resource == Photo::\"doorx\");",
	                     "ID1": "permit(principal == User::\"tom\", action, resource == Photo::\"doory\");",
	                     "ID2": "permit(principal == User::\"alice\", action, resource == Photo::\"door\");"
	                   }
	                 , "entities" : []
	             }
	          }
	         "#;
        assert_is_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_on_multi_policy_slice_with_string_policies() {
        let call = r#"
	             { "principal": "User::\"alice\""
	             , "action" : "Photo::\"view\""
	             , "resource" : "Photo::\"door\""
	             , "context" : {}
	             , "slice" : {
	                   "policies" : "permit(principal == User::\"jerry\", action, resource == Photo::\"doorx\");permit(principal == User::\"tom\", action, resource == Photo::\"doory\");permit(principal == User::\"alice\", action, resource == Photo::\"door\");"
	                 , "entities" : []
	             }
	          }
	         "#;
        assert_is_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_on_multi_policy_slice_denies_when_expected() {
        let call = r#"
	             { "principal": "User::\"alice\""
	             , "action" : "Photo::\"view\""
	             , "resource" : "Photo::\"door\""
	             , "context" : {}
	             , "slice" : {
	                   "policies" : {
	                     "ID0": "permit(principal, action, resource);",
	                     "ID1": "forbid(principal == User::\"alice\", action, resource == Photo::\"door\");"
	                   }
	                 , "entities" : []
	             }
	          }
	         "#;
        assert_is_not_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_on_multi_policy_slice_with_string_policies_denies_when_expected() {
        let call = r#"
	             { "principal": "User::\"alice\""
	             , "action" : "Photo::\"view\""
	             , "resource" : "Photo::\"door\""
	             , "context" : {}
	             , "slice" : {
	                   "policies": "permit(principal, action, resource);forbid(principal == User::\"alice\", action, resource);"
	                 , "entities" : []
	             }
	          }
	         "#;

        assert_is_not_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_with_template_as_policy_should_fail() {
        let call = r#"
	             { "principal": "User::\"alice\""
	             , "action" : "Photo::\"view\""
	             , "resource" : "Photo::\"door\""
	             , "context" : {}
	             , "slice" : {
	                   "policies" : "permit(principal == ?principal, action, resource);"
	                 , "entities" : []
                     , "templates" : {}
	             }
	          }
	         "#;
        assert_is_not_authorized(json_is_authorized(call));
    }

    #[test]
    fn test_authorized_with_template_should_fail() {
        let call = r#"
	             { "principal": "User::\"alice\""
	             , "action" : "Photo::\"view\""
	             , "resource" : "Photo::\"door\""
	             , "context" : {}
	             , "slice" : {
	                   "policies" : {}
	                 , "entities" : []
                     , "templates" : {
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
	             { "principal": "User::\"alice\""
	             , "action" : "Photo::\"view\""
	             , "resource" : "Photo::\"door\""
	             , "context" : {}
	             , "slice" : {
	                   "policies" : {}
	                 , "entities" : []
                     , "templates" : {
                        "ID0": "permit(principal == ?principal, action, resource);"
                      }
                     , "template_instantiations" : [
                        {
                            "template_id" : "ID0",
                            "result_policy_id" : "ID0_User_alice",
                            "instantiations" : [
                                {
                                    "slot": "?principal",
                                    "value": {
                                        "ty" : "User",
                                        "eid" : "alice"
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

    fn assert_is_authorized(result: InterfaceResult) {
        match result {
            InterfaceResult::Success { result } => {
                let parsed_result: AuthorizationAnswer =
                    serde_json::from_str(result.as_str()).unwrap();
                match parsed_result {
                    AuthorizationAnswer::ParseFailed { .. } => {
                        panic!("expected parse to succeed, but got {parsed_result:?}")
                    }
                    AuthorizationAnswer::Success { response } => {
                        assert_eq!(response.decision, Decision::Allow);
                        assert_eq!(response.diagnostics.errors.len(), 0);
                    }
                }
            }
            InterfaceResult::Failure { .. } => {
                panic!("Expected a successful response, not {result:?}");
            }
        }
    }

    fn assert_is_not_authorized(result: InterfaceResult) {
        match result {
            InterfaceResult::Success { result } => {
                let parsed_result: AuthorizationAnswer =
                    serde_json::from_str(result.as_str()).unwrap();
                match parsed_result {
                    AuthorizationAnswer::ParseFailed { .. } => {
                        panic!("expected parse to succeed, but got {parsed_result:?}")
                    }
                    AuthorizationAnswer::Success { response } => {
                        assert_eq!(response.decision, Decision::Deny);
                        assert_eq!(response.diagnostics.errors.len(), 0);
                    }
                }
            }
            InterfaceResult::Failure { .. } => {
                panic!("Expected a successful response, not {result:?}");
            }
        }
    }

    fn assert_is_failure(result: &InterfaceResult) {
        match result {
            InterfaceResult::Success { .. } => {
                panic!("Expected a failing response, not {result:?}")
            }
            InterfaceResult::Failure { .. } => {}
        }
    }
}
