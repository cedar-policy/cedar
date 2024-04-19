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
) -> Result<crate::PolicySet, Vec<String>> {
    let mut policy_set = crate::PolicySet::new();
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

impl PolicySet {
    /// Parse the `PolicySet` into a `crate::PolicySet`.
    pub(super) fn parse(
        self,
        templates: Option<HashMap<String, String>>,
    ) -> Result<crate::PolicySet, Vec<String>> {
        match self {
            Self::Concatenated(policies) => match crate::PolicySet::from_str(&policies) {
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
    ) -> Result<(crate::Schema, Box<dyn Iterator<Item = SchemaWarning>>), String> {
        match self {
            Self::Human(str) => crate::Schema::from_str_natural(&str)
                .map(|(sch, warnings)| {
                    (
                        sch,
                        Box::new(warnings) as Box<dyn Iterator<Item = SchemaWarning>>,
                    )
                })
                .map_err(|e| e.to_string()),
            Self::Json(val) => crate::Schema::from_json_value(val.into())
                .map(|sch| {
                    (
                        sch,
                        Box::new(std::iter::empty()) as Box<dyn Iterator<Item = SchemaWarning>>,
                    )
                })
                .map_err(|e| e.to_string()),
        }
    }
}

pub(super) struct WithWarnings<T> {
    pub t: T,
    pub warnings: Vec<String>,
}
