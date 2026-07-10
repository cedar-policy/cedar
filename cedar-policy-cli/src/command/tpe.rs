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

use crate::{PoliciesArgs, SchemaArgs};
use cedar_policy::{
    Context, Decision, EntityId, EntityUid, PartialEntities, PartialEntityUid, PartialRequest,
    PolicySet, Schema,
};
use miette::{miette, IntoDiagnostic, Report, Result, WrapErr};
use serde::Deserialize;
use std::{path::Path, time::Instant};

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
        let action: EntityUid = qjson
            .action
            .parse()
            .wrap_err("failed to parse `action` as an entity UID")?;
        Ok(PartialRequest::new(
            PartialEntityUid::new(
                qjson
                    .principal_type
                    .parse()
                    .wrap_err("failed to parse `principal_type` as an entity type name")?,
                qjson.principal_eid.as_ref().map(EntityId::new),
            ),
            action.clone(),
            PartialEntityUid::new(
                qjson
                    .resource_type
                    .parse()
                    .wrap_err("failed to parse `resource_type` as an entity type name")?,
                qjson.resource_eid.as_ref().map(EntityId::new),
            ),
            qjson
                .context
                .map(|val| {
                    Context::from_json_value(val, Some((schema, &action)))
                        .wrap_err("failed to parse request context")
                })
                .transpose()?,
            schema,
        )?)
    }
}

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
                            for p in ans.policies() {
                                println!("{p}");
                            }
                            CedarExitCode::Unknown
                        }
                    }
                }
                Err(err) => {
                    errs.push(Report::new(err));
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

/// Load an `PartialEntities` object from the given JSON filename and optional schema.
fn load_partial_entities(
    entities_filename: impl AsRef<Path>,
    schema: &Schema,
) -> Result<PartialEntities> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .open(entities_filename.as_ref())
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to open entities file {}",
                entities_filename.as_ref().display()
            )
        })?;
    let json = serde_json::from_reader(f)
        .into_diagnostic()
        .wrap_err(format!(
            "failed to parse entities as JSON value from file {}",
            entities_filename.as_ref().display()
        ))?;
    PartialEntities::from_json_value(json, schema).wrap_err_with(|| {
        format!(
            "failed to parse entities from file {}",
            entities_filename.as_ref().display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{render_err, TEMPFILE_FILTER};
    use std::io::Write;

    fn test_schema() -> Schema {
        Schema::from_cedarschema_str(
            r#"entity User; entity Photo; action view appliesTo { principal: User, resource: Photo };"#,
        )
        .unwrap()
        .0
    }

    fn mk_tpe_request(
        principal_type: Option<&str>,
        action: Option<&str>,
        resource_type: Option<&str>,
        request_json_file: Option<&str>,
    ) -> TpeRequestArgs {
        TpeRequestArgs {
            principal_type: principal_type.map(String::from),
            principal_eid: Some("alice".to_string()),
            action: action.map(String::from),
            resource_type: resource_type.map(String::from),
            resource_eid: Some("pic".to_string()),
            context_json_file: None,
            request_json_file: request_json_file.map(String::from),
        }
    }

    #[test]
    fn tpe_request_bad_action() {
        let args = mk_tpe_request(Some("User"), Some("not_an_action"), Some("Photo"), None);
        let err = args.get_request(&test_schema()).unwrap_err();
        insta::assert_snapshot!(render_err(&err), @"
         × failed to parse `action` as an entity UID
         ╰─▶ unexpected end of input
          ╭────
        1 │ not_an_action
          ╰────
        ");
    }

    #[test]
    fn tpe_request_bad_principal_type() {
        let args = mk_tpe_request(
            Some("not a type!"),
            Some(r#"Action::"view""#),
            Some("Photo"),
            None,
        );
        let err = args.get_request(&test_schema()).unwrap_err();
        insta::assert_snapshot!(render_err(&err), @"
         × failed to parse `principal_type` as an entity type name
         ╰─▶ unexpected token `a`
          ╭────
        1 │ not a type!
          ·     ┬
          ·     ╰── expected `::`
          ╰────
        ");
    }

    #[test]
    fn tpe_request_bad_resource_type() {
        let args = mk_tpe_request(
            Some("User"),
            Some(r#"Action::"view""#),
            Some("not a type!"),
            None,
        );
        let err = args.get_request(&test_schema()).unwrap_err();
        insta::assert_snapshot!(render_err(&err), @"
         × failed to parse `resource_type` as an entity type name
         ╰─▶ unexpected token `a`
          ╭────
        1 │ not a type!
          ·     ┬
          ·     ╰── expected `::`
          ╰────
        ");
    }

    #[test]
    fn tpe_request_bad_context() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{"principal_type":"User","principal_eid":"alice","action":"Action::\"view\"","resource_type":"Photo","resource_eid":"pic","context":123}"#,
        )
        .unwrap();
        let args = mk_tpe_request(None, None, None, Some(f.path().to_str().unwrap()));
        let err = args.get_request(&test_schema()).unwrap_err();
        insta::with_settings!({filters => vec![TEMPFILE_FILTER]}, {
            insta::assert_snapshot!(render_err(&err), @"
            × failed to parse request context
            ╰─▶ while parsing context, type mismatch: value was expected to have type {  }, but it actually has type long: `123`
            ");
        });
    }
}
