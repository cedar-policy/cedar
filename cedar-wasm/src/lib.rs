#![forbid(unsafe_code)]

use wasm_bindgen::prelude::wasm_bindgen;

use cedar_policy::{
    Authorizer, Context, Entities, EntityUid, Policy, PolicySet, Request, Schema, ValidationMode,
    Validator,
};

use serde_json::json;

use std::collections::HashSet;
use std::str::FromStr;

#[wasm_bindgen(js_name = "getCedarVersion")]
pub fn get_cedar_version() -> String {
    std::env!("CEDAR_VERSION").to_string()
}

#[wasm_bindgen(js_name = "isAuthorized")]
pub fn is_authorized(
    principal_str: &str,
    action_str: &str,
    resource_str: &str,
    context_str: &str,
    policies_str: &str,
    entities_str: &str,
) -> String {
    let principal = match EntityUid::from_str(principal_str) {
        Ok(principal) => principal,
        Err(err) => {
            return json!({
                "code": 101,
                "message": format!("[PrincipalErr]: {}", err),
            })
            .to_string();
        }
    };

    let action = match EntityUid::from_str(action_str) {
        Ok(action) => action,
        Err(err) => {
            return json!({
                "code": 102,
                "message": format!("[ActionErr]: {}", err),
            })
            .to_string();
        }
    };

    let resource = match EntityUid::from_str(resource_str) {
        Ok(resource) => resource,
        Err(err) => {
            return json!({
                "code": 103,
                "message": format!("[ResourceErr]: {}", err),
            })
            .to_string();
        }
    };

    let context = match Context::from_json_str(context_str, None) {
        Ok(context) => context,
        Err(err) => {
            return json!({
                "code": 104,
                "message": format!("[ContextErr]: {}", err),
            })
            .to_string();
        }
    };

    let policies = match PolicySet::from_str(policies_str) {
        Ok(policies) => policies,
        Err(err) => {
            return json!({
                "code": 105,
                "message": format!("[PoliciesErr]: {}", err),
            })
            .to_string();
        }
    };

    let entities = match Entities::from_json_str(entities_str, None) {
        Ok(entities) => entities,
        Err(err) => {
            return json!({
                "code": 106,
                "message": format!("[EntitiesErr]: {}", err),
            })
            .to_string();
        }
    };

    let request = match Request::new(Some(principal), Some(action), Some(resource), context, None) {
        Ok(request) => request,
        Err(err) => {
            return json!({
                "code": 107,
                "message": format!("[RequestErr]: {}", err),
            })
            .to_string();
        }
    };

    let authorizer = Authorizer::new();
    let response = authorizer.is_authorized(&request, &policies, &entities);

    // change response to string
    let decision = response.decision();
    let diagnostics = response.diagnostics();

    let _reasons = diagnostics.reason();
    let mut reasons = HashSet::new();
    for reason in _reasons {
        reasons.insert(reason.to_string());
    }

    let _errors = diagnostics.errors();
    let mut errors = Vec::new();
    for err in _errors {
        let error = err.to_string();
        errors.push(error);
    }

    json!({
        "code": 0,
        "data": {
            "decision": decision,
            "reasons": reasons,
            "errors": errors,
        }
    })
    .to_string()
}

#[wasm_bindgen(js_name = "validate")]
pub fn validate(schema_str: &str, policy_str: &str) -> String {
    let schema = match Schema::from_str(schema_str) {
        Ok(schema) => schema,
        Err(err) => {
            return json!({
                "code": 201,
                "message": format!("[SchemaErr]: {}", err),
            })
            .to_string();
        }
    };

    let policy = match PolicySet::from_str(policy_str) {
        Ok(policy) => policy,
        Err(err) => {
            return json!({
                "code": 202,
                "message": format!("[PolicyErr]: {}", err),
            })
            .to_string();
        }
    };

    let validator = Validator::new(schema);

    let result = validator.validate(&policy, ValidationMode::default());

    json!({
        "code": 0,
        "data": format!("{}", result),
    })
    .to_string()
}

#[wasm_bindgen(js_name = "policyToJson")]
pub fn policy_to_json(policy_str: &str) -> String {
    let policy = match Policy::from_str(policy_str) {
        Ok(policy) => policy,
        Err(err) => {
            return json!({
                "code": 301,
                "message": format!("[PolicyErr]: {}", err),
            })
            .to_string();
        }
    };

    let policy_json = match policy.to_json() {
        Ok(policy_json) => policy_json,
        Err(err) => {
            return json!({
                "code": 302,
                "message": format!("[PolicyJsonErr]: {}", err),
            })
            .to_string();
        }
    };

    json!({
        "code": 0,
        "data": policy_json,
    })
    .to_string()
}

#[wasm_bindgen(js_name = "policyFromJson")]
pub fn policy_from_json(policy_str: &str) -> String {
    let policy_json = match serde_json::from_str(policy_str) {
        Ok(policy_json) => policy_json,
        Err(err) => {
            return json!({
                "code": 401,
                "message": format!("[PolicyJsonErr]: {}", err),
            })
            .to_string();
        }
    };

    let policy = match Policy::from_json(None, policy_json) {
        Ok(policy) => policy,
        Err(err) => {
            return json!({
                "code": 402,
                "message": format!("[PolicyErr]: {}", err),
            })
            .to_string();
        }
    };

    json!({
        "code": 0,
        "data": policy.to_string(),
    })
    .to_string()
}

#[wasm_bindgen(js_name = "validateSchema")]
pub fn validate_schema(schema_str: &str) -> String {
    match Schema::from_str(schema_str) {
        Ok(_) => {}
        Err(err) => {
            return json!({
                "code": 501,
                "message": format!("[SchemaErr]: {}", err),
            })
            .to_string();
        }
    };

    json!({
        "code": 0,
        "data": "no errors or warnings",
    })
    .to_string()
}
