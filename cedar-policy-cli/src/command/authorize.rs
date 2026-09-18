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

use std::time::Instant;

use cedar_policy::{Authorizer, Decision, Entities, PolicySet, Response};
use clap::Args;
use miette::Report;

use crate::{CedarExitCode, EntitiesArgs, OptionalSchemaArgs, PoliciesArgs, RequestArgs};

#[derive(Args, Debug)]
pub struct AuthorizeArgs {
    /// Request args (incorporated by reference)
    #[command(flatten)]
    pub request: RequestArgs,
    /// Policies args (incorporated by reference)
    #[command(flatten)]
    pub policies: PoliciesArgs,
    /// Schema args (incorporated by reference)
    ///
    /// Used to populate the store with action entities and for schema-based
    /// parsing of entity hierarchy, if present
    #[command(flatten)]
    pub schema: OptionalSchemaArgs,
    /// Entities args (incorporated by reference)
    #[command(flatten)]
    pub entities: EntitiesArgs,
    /// More verbose output. (For instance, indicate which policies applied to the request, if any.)
    #[arg(short, long)]
    pub verbose: bool,
    /// Time authorization and report timing information
    #[arg(short, long)]
    pub timing: bool,
}

pub fn authorize(args: &AuthorizeArgs) -> CedarExitCode {
    println!();
    let ans = execute_request(
        &args.request,
        &args.policies,
        &args.entities,
        &args.schema,
        args.timing,
    );
    match ans {
        Ok(ans) => {
            let status = match ans.decision() {
                Decision::Allow => {
                    println!("ALLOW");
                    CedarExitCode::Success
                }
                Decision::Deny => {
                    println!("DENY");
                    CedarExitCode::AuthorizeDeny
                }
            };
            if ans.diagnostics().errors().peekable().peek().is_some() {
                println!();
                for err in ans.diagnostics().errors() {
                    println!("{err}");
                }
            }
            if args.verbose {
                println!();
                if ans.diagnostics().reason().peekable().peek().is_none() {
                    println!("note: no policies applied to this request");
                } else {
                    println!("note: this decision was due to the following policies:");
                    for reason in ans.diagnostics().reason() {
                        println!("  {reason}");
                    }
                    println!();
                }
            }
            status
        }
        Err(errs) => {
            for err in errs {
                println!("{err:?}");
            }
            CedarExitCode::Failure
        }
    }
}

/// This uses the Cedar API to call the authorization engine.
fn execute_request(
    request: &RequestArgs,
    policies: &PoliciesArgs,
    entities: &EntitiesArgs,
    schema: &OptionalSchemaArgs,
    compute_duration: bool,
) -> Result<Response, Vec<Report>> {
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
    let entities = match entities.get_entities(schema.as_ref()) {
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
            let ans = authorizer.is_authorized(&request, &policies, &entities);
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
