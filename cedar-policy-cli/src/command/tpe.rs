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

use crate::CedarExitCode;
use clap::Args;

#[cfg(feature = "tpe")]
use crate::{PoliciesArgs, SchemaArgs};
#[cfg(feature = "tpe")]
use cedar_policy::{
    Context, Decision, EntityId, EntityUid, PartialEntities, PartialEntityUid, PartialRequest,
    PolicySet, Schema,
};
#[cfg(feature = "tpe")]
use miette::{miette, IntoDiagnostic, Result, WrapErr};
#[cfg(feature = "tpe")]
use serde::Deserialize;
#[cfg(feature = "tpe")]
use std::{path::Path, time::Instant};

#[cfg(feature = "tpe")]
#[derive(Args, Debug)]
pub struct TpeArgs {
    /// Request args (incorporated by reference)
    #[command(flatten)]
    pub request: TpeRequestArgs,
    /// Policies args (incorporated by reference)
    #[command(flatten)]
    pub policies: PoliciesArgs,
    /// Schema args (incorporated by reference)
    ///
    /// Used to populate the store with action entities and for schema-based
    /// parsing of entity hierarchy, if present
    #[command(flatten)]
    pub schema: SchemaArgs,
    /// File containing JSON representation of the Cedar entity hierarchy
    #[arg(long = "entities", value_name = "FILE")]
    pub entities_file: String,
    /// Time authorization and report timing information
    #[arg(short, long)]
    pub timing: bool,
}

#[cfg(not(feature = "tpe"))]
#[derive(Debug, Args)]
pub struct TpeArgs;

#[cfg(feature = "tpe")]
/// This struct contains the arguments that together specify a request.
#[derive(Args, Debug)]
pub struct TpeRequestArgs {
    /// Principal type of the request, e.g., User
    #[arg(long)]
    pub principal_type: Option<String>,
    /// Optional principal eid
    #[arg(long)]
    pub principal_eid: Option<String>,
    /// Action for the request, e.g., Action::"view"
    #[arg(short, long)]
    pub action: Option<String>,
    /// Resource type of the request, e.g., File
    #[arg(long)]
    pub resource_type: Option<String>,
    /// Optional resource eid
    #[arg(long)]
    pub resource_eid: Option<String>,
    /// File containing a JSON object representing the context for the request.
    /// Should be a (possibly empty) map from keys to values.
    #[arg(short, long = "context", value_name = "FILE")]
    pub context_json_file: Option<String>,
    /// File containing a JSON object representing the entire request. Must have
    /// fields "principal", "action", "resource", and "context", where "context"
    /// is a (possibly empty) map from keys to values. This option replaces
    /// --principal*, --action, etc.
    #[arg(long = "request-json", value_name = "FILE", conflicts_with_all = &["principal_type", "principal_eid", "action", "resource_type", "resource_eid", "context_json_file"])]
    pub request_json_file: Option<String>,
}

#[cfg(feature = "tpe")]
// This struct is the serde structure expected for --request-json
#[derive(Deserialize)]
struct TpeRequestJSON {
    // Principal for the request
    pub(self) principal_type: String,
    // Optional principal eid
    pub(self) principal_eid: Option<String>,
    // Action for the request
    pub(self) action: String,
    // Resource for the request
    pub(self) resource_type: String,
    // Optional resource eid
    pub(self) resource_eid: Option<String>,
    // Context for the request
    pub(self) context: Option<serde_json::Value>,
}

#[cfg(feature = "tpe")]
impl TpeRequestArgs {
    fn get_request(&self, schema: &Schema) -> Result<PartialRequest> {
        let qjson: TpeRequestJSON = match self.request_json_file.as_ref() {
            Some(jsonfile) => {
                let jsonstring = std::fs::read_to_string(jsonfile)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to open request json file {jsonfile}"))?;
                serde_json::from_str(&jsonstring)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to parse context-json file {jsonfile}"))?
            }
            None => TpeRequestJSON {
                principal_type: self
                    .principal_type
                    .clone()
                    .ok_or_else(|| miette!("principal type must be specified"))?,
                principal_eid: self.principal_eid.clone(),
                action: self
                    .action
                    .clone()
                    .ok_or_else(|| miette!("action must be specified"))?,
                resource_type: self
                    .resource_type
                    .clone()
                    .ok_or_else(|| miette!("resource type must be specified"))?,
                resource_eid: self.resource_eid.clone(),
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
        let action: EntityUid = qjson.action.parse()?;
        Ok(PartialRequest::new(
            PartialEntityUid::new(
                qjson.principal_type.parse()?,
                qjson.principal_eid.as_ref().map(EntityId::new),
            ),
            action.clone(),
            PartialEntityUid::new(
                qjson.resource_type.parse()?,
                qjson.resource_eid.as_ref().map(EntityId::new),
            ),
            qjson
                .context
                .map(|val| Context::from_json_value(val, Some((schema, &action))))
                .transpose()?,
            schema,
        )?)
    }
}

#[cfg(not(feature = "tpe"))]
pub fn tpe(_: &TpeArgs) -> CedarExitCode {
    eprintln!("Error: option `tpe` is experimental, but this executable was not built with `partial-eval` experimental feature enabled");
    CedarExitCode::Failure
}

#[cfg(feature = "tpe")]
pub fn tpe(args: &TpeArgs) -> CedarExitCode {
    println!();
    let ret = |errs| {
        for err in errs {
            println!("{err:?}");
        }
        CedarExitCode::Failure
    };
    let mut errs = vec![];
    let policies = match args.policies.get_policy_set() {
        Ok(pset) => pset,
        Err(e) => {
            errs.push(e);
            PolicySet::new()
        }
    };
    let schema: Schema = match args.schema.get_schema() {
        Ok(opt) => opt,
        Err(e) => {
            errs.push(e);
            return ret(errs);
        }
    };

    let entities = match load_partial_entities(args.entities_file.clone(), &schema) {
        Ok(entities) => entities,
        Err(e) => {
            errs.push(e);
            PartialEntities::empty()
        }
    };

    match args.request.get_request(&schema) {
        Ok(request) if errs.is_empty() => {
            let auth_start = Instant::now();
            let ans = policies.tpe(&request, &entities, &schema);
            let auth_dur = auth_start.elapsed();
            match ans {
                Ok(ans) => {
                    if args.timing {
                        println!(
                            "Authorization Time (micro seconds) : {}",
                            auth_dur.as_micros()
                        );
                    }
                    match ans.decision() {
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
                            for p in ans.residual_policies() {
                                println!("{p}");
                            }
                            CedarExitCode::Unknown
                        }
                    }
                }
                Err(err) => {
                    errs.push(miette!("{err}"));
                    ret(errs)
                }
            }
        }
        Ok(_) => ret(errs),
        Err(e) => {
            errs.push(e.wrap_err("failed to parse request"));
            ret(errs)
        }
    }
}

#[cfg(feature = "tpe")]
/// Load an `PartialEntities` object from the given JSON filename and optional schema.
fn load_partial_entities(
    entities_filename: impl AsRef<Path>,
    schema: &Schema,
) -> Result<PartialEntities> {
    match std::fs::OpenOptions::new()
        .read(true)
        .open(entities_filename.as_ref())
    {
        Ok(f) => {
            PartialEntities::from_json_value(serde_json::from_reader(f).into_diagnostic()?, schema)
                .map_err(|e| miette!("{e}"))
                .wrap_err_with(|| {
                    format!(
                        "failed to parse entities from file {}",
                        entities_filename.as_ref().display()
                    )
                })
        }
        Err(e) => Err(e).into_diagnostic().wrap_err_with(|| {
            format!(
                "failed to open entities file {}",
                entities_filename.as_ref().display()
            )
        }),
    }
}
