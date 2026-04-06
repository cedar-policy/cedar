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

//! This module contains code for the original `partial-eval` partial evaluation
//! feature which is no longer being developed. It will be replaced by `tpe`
//! (type-aware partial evaluation) which you can find in the `tpe` module.

use clap::Args;
#[cfg(feature = "partial-eval")]
use miette::{IntoDiagnostic, Report, Result, WrapErr};
#[cfg(feature = "partial-eval")]
use serde::Deserialize;
#[cfg(feature = "partial-eval")]
use std::{path::Path, time::Instant};

#[cfg(feature = "partial-eval")]
use cedar_policy::*;

use crate::CedarExitCode;
#[cfg(feature = "partial-eval")]
use crate::{load_entities, OptionalSchemaArgs, PoliciesArgs};

#[cfg(feature = "partial-eval")]
#[derive(Args, Debug)]
pub struct PartiallyAuthorizeArgs {
    /// Request args (incorporated by reference)
    #[command(flatten)]
    pub request: PartialRequestArgs,
    /// Policies args (incorporated by reference)
    #[command(flatten)]
    pub policies: PoliciesArgs,
    /// Schema args (incorporated by reference)
    ///
    /// Used to populate the store with action entities and for schema-based
    /// parsing of entity hierarchy, if present
    #[command(flatten)]
    pub schema: OptionalSchemaArgs,
    /// File containing JSON representation of the Cedar entity hierarchy
    #[arg(long = "entities", value_name = "FILE")]
    pub entities_file: String,
    /// Time authorization and report timing information
    #[arg(short, long)]
    pub timing: bool,
}

#[cfg(not(feature = "partial-eval"))]
#[derive(Debug, Args)]
pub struct PartiallyAuthorizeArgs;

#[cfg(feature = "partial-eval")]
/// This struct contains the arguments that together specify a request.
#[derive(Args, Debug)]
pub struct PartialRequestArgs {
    /// Principal for the request, e.g., User::"alice"
    #[arg(short = 'l', long)]
    pub principal: Option<String>,
    /// Action for the request, e.g., Action::"view"
    #[arg(short, long)]
    pub action: Option<String>,
    /// Resource for the request, e.g., File::"myfile.txt"
    #[arg(short, long)]
    pub resource: Option<String>,
    /// File containing a JSON object representing the context for the request.
    /// Should be a (possibly empty) map from keys to values.
    #[arg(short, long = "context", value_name = "FILE")]
    pub context_json_file: Option<String>,
    /// File containing a JSON object representing the entire request. Must have
    /// fields "principal", "action", "resource", and "context", where "context"
    /// is a (possibly empty) map from keys to values. This option replaces
    /// --principal, --action, etc.
    #[arg(long = "request-json", value_name = "FILE", conflicts_with_all = &["principal", "action", "resource", "context_json_file"])]
    pub request_json_file: Option<String>,
}

#[cfg(feature = "partial-eval")]
impl PartialRequestArgs {
    fn get_request(&self, schema: Option<&Schema>) -> Result<Request> {
        let mut builder = RequestBuilder::default();
        let qjson: PartialRequestJSON = match self.request_json_file.as_ref() {
            Some(jsonfile) => {
                let jsonstring = std::fs::read_to_string(jsonfile)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to open request-json file {jsonfile}"))?;
                serde_json::from_str(&jsonstring)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to parse request-json file {jsonfile}"))?
            }
            None => PartialRequestJSON {
                principal: self.principal.clone(),
                action: self.action.clone(),
                resource: self.resource.clone(),
                context: self
                    .context_json_file
                    .as_ref()
                    .map(|jsonfile| {
                        let jsonstring = std::fs::read_to_string(jsonfile)
                            .into_diagnostic()
                            .wrap_err_with(|| {
                                format!("failed to open context-json file {jsonfile}")
                            })?;
                        serde_json::from_str(&jsonstring)
                            .into_diagnostic()
                            .wrap_err_with(|| {
                                format!("failed to parse context-json file {jsonfile}")
                            })
                    })
                    .transpose()?,
            },
        };

        if let Some(principal) = qjson
            .principal
            .map(|s| {
                s.parse()
                    .wrap_err_with(|| format!("failed to parse principal {s} as entity Uid"))
            })
            .transpose()?
        {
            builder = builder.principal(principal);
        }

        let action = qjson
            .action
            .map(|s| {
                s.parse::<EntityUid>()
                    .wrap_err_with(|| format!("failed to parse action {s} as entity Uid"))
            })
            .transpose()?;

        if let Some(action_ref) = &action {
            builder = builder.action(action_ref.clone());
        }

        if let Some(resource) = qjson
            .resource
            .map(|s| {
                s.parse()
                    .wrap_err_with(|| format!("failed to parse resource {s} as entity Uid"))
            })
            .transpose()?
        {
            builder = builder.resource(resource);
        }

        if let Some(context) = qjson
            .context
            .map(|json| {
                Context::from_json_value(
                    json.clone(),
                    schema.and_then(|s| Some((s, action.as_ref()?))),
                )
                .wrap_err_with(|| format!("fail to convert context json {json} to Context"))
            })
            .transpose()?
        {
            builder = builder.context(context);
        }

        if let Some(schema) = schema {
            builder
                .schema(schema)
                .build()
                .wrap_err_with(|| "failed to build request with validation".to_string())
        } else {
            Ok(builder.build())
        }
    }
}

#[cfg(feature = "partial-eval")]
/// This struct is the serde structure expected for --request-json
#[derive(Deserialize)]
struct PartialRequestJSON {
    /// Principal for the request
    pub(self) principal: Option<String>,
    /// Action for the request
    pub(self) action: Option<String>,
    /// Resource for the request
    pub(self) resource: Option<String>,
    /// Context for the request
    pub(self) context: Option<serde_json::Value>,
}

#[cfg(not(feature = "partial-eval"))]
pub fn partial_authorize(_: &PartiallyAuthorizeArgs) -> CedarExitCode {
    eprintln!("Error: option `partially-authorize` is experimental, but this executable was not built with `partial-eval` experimental feature enabled");
    CedarExitCode::Failure
}

#[cfg(feature = "partial-eval")]
pub fn partial_authorize(args: &PartiallyAuthorizeArgs) -> CedarExitCode {
    println!();
    let ans = execute_partial_request(
        &args.request,
        &args.policies,
        &args.entities_file,
        &args.schema,
        args.timing,
    );
    match ans {
        Ok(ans) => match ans.decision() {
            Some(Decision::Allow) => {
                println!("ALLOW");
                CedarExitCode::Success
            }
            Some(Decision::Deny) => {
                println!("DENY");
                CedarExitCode::AuthorizeDeny
            }
            None => {
                println!("UNKNOWN");
                println!("All policy residuals:");
                for p in ans.nontrivial_residuals() {
                    println!("{p}");
                }
                CedarExitCode::Unknown
            }
        },
        Err(errs) => {
            for err in errs {
                println!("{err:?}");
            }
            CedarExitCode::Failure
        }
    }
}

#[cfg(feature = "partial-eval")]
fn execute_partial_request(
    request: &PartialRequestArgs,
    policies: &PoliciesArgs,
    entities_filename: impl AsRef<Path>,
    schema: &OptionalSchemaArgs,
    compute_duration: bool,
) -> Result<PartialResponse, Vec<Report>> {
    let mut errs = vec![];
    let policies = match policies.get_policy_set() {
        Ok(pset) => pset,
        Err(e) => {
            errs.push(e);
            PolicySet::new()
        }
    };
    let schema = match schema.get_schema() {
        Ok(opt) => opt,
        Err(e) => {
            errs.push(e);
            None
        }
    };
    let entities = match load_entities(entities_filename, schema.as_ref()) {
        Ok(entities) => entities,
        Err(e) => {
            errs.push(e);
            Entities::empty()
        }
    };
    match request.get_request(schema.as_ref()) {
        Ok(request) if errs.is_empty() => {
            let authorizer = Authorizer::new();
            let auth_start = Instant::now();
            let ans = authorizer.is_authorized_partial(&request, &policies, &entities);
            let auth_dur = auth_start.elapsed();
            if compute_duration {
                println!(
                    "Authorization Time (micro seconds) : {}",
                    auth_dur.as_micros()
                );
            }
            Ok(ans)
        }
        Ok(_) => Err(errs),
        Err(e) => {
            errs.push(e.wrap_err("failed to parse request"));
            Err(errs)
        }
    }
}
