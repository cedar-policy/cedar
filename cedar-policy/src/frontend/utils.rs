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
use crate::{Policy, PolicySet, Template};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr};

#[cfg(feature = "wasm")]
extern crate tsify;

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(
    expecting = "policies as a concatenated string or multiple policies as a hashmap where the policy id is the key"
)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
/// Struct defining the two possible ways to pass a set of policies to `json_is_authorized` and `json_validate`
pub enum PolicySpecification {
    /// provides multiple policies as a concatenated string
    Concatenated(String),
    /// provides multiple policies as a hashmap where the policyId is the key
    #[serde(with = "::serde_with::rust::maps_duplicate_key_is_error")]
    Map(HashMap<String, String>),
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

impl PolicySpecification {
    pub(crate) fn try_into(
        self,
        templates: Option<HashMap<String, String>>,
    ) -> Result<PolicySet, Vec<String>> {
        match self {
            Self::Concatenated(policies) => match PolicySet::from_str(&policies) {
                Ok(ps) => Ok(ps),
                Err(parse_errors) => Err(std::iter::once(
                    "couldn't parse concatenated policies string".to_string(),
                )
                .chain(parse_errors.errors_as_strings())
                .collect()),
            },
            Self::Map(policies) => parse_policy_set_from_individual_policies(&policies, templates),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "success")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
/// Result of a call to a JSON interface
pub enum InterfaceResult {
    /// The call succeeded
    #[serde(rename = "true")]
    Success {
        /// JSON containing the result of the call
        result: String,
    },
    #[serde(rename = "false")]
    /// The call failed
    Failure {
        /// Whether the failure is "internal".
        ///
        /// An "internal failure" is returned when there is a fault in the
        /// Cedar Rust code, or when there is a problem with the request in
        /// the parts which the Java library is responsible for (e.g. an
        /// unsupported operation).
        ///
        /// By contrast, a "bad request" is returned when there is an issue in the
        /// part of the request supplied by the ultimate user of the library, e.g. a
        /// syntax error in a policy.
        #[serde(rename = "isInternal")]
        is_internal: bool,
        /// String description of the error(s) that led to the failure
        errors: Vec<String>,
    },
}

impl InterfaceResult {
    /// A successful result
    pub fn succeed<T: Serialize>(value: T) -> Self {
        serde_json::to_string(&value).map_or_else(
            |e| Self::fail_internally(format!("error serializing result: {e:}")),
            |result| Self::Success { result },
        )
    }

    /// An "internal failure" result; see docs on [`InterfaceResult::Failure`]
    pub fn fail_internally(message: String) -> Self {
        Self::Failure {
            is_internal: true,
            errors: vec![message],
        }
    }

    /// A failure result that isn't internal; see docs on
    /// `InterfaceResult::Failure`
    pub fn fail_bad_request(errors: Vec<String>) -> Self {
        Self::Failure {
            is_internal: false,
            errors,
        }
    }
}

#[cfg(test)]
#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub(crate) fn assert_is_failure(result: &InterfaceResult, internal: bool, err: &str) {
    use cool_asserts::assert_matches;

    assert_matches!(result, InterfaceResult::Failure { is_internal, errors } => {
        assert!(
            errors.iter().any(|e| e.contains(err)),
            "Expected to see error(s) containing `{err}`, but saw {errors:?}");
        assert_eq!(is_internal, &internal, "Unexpected value for `is_internal`");
    });
}
