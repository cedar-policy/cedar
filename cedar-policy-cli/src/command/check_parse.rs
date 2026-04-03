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

use std::{path::PathBuf, str::FromStr};

use cedar_policy::Expression;
use clap::Args;
use miette::Report;

use crate::{load_entities, CedarExitCode, OptionalPoliciesArgs, OptionalSchemaArgs, PoliciesArgs};

#[derive(Args, Debug)]
pub struct CheckParseArgs {
    /// Policies args (incorporated by reference)
    #[command(flatten)]
    pub policies: OptionalPoliciesArgs,
    /// Expression to parse
    #[arg(long)]
    pub expression: Option<String>,
    /// Schema args (incorporated by reference)
    #[command(flatten)]
    pub schema: OptionalSchemaArgs,
    /// File containing JSON representation of a Cedar entity hierarchy
    #[arg(long = "entities", value_name = "FILE")]
    pub entities_file: Option<PathBuf>,
}

pub fn check_parse(args: &CheckParseArgs) -> CedarExitCode {
    // for backwards compatibility: if no policies/schema/entities/expression
    // are provided, read policies from stdin and check that they parse
    if args.policies.policies_file.is_none()
        && args.schema.schema_file.is_none()
        && args.entities_file.is_none()
        && args.expression.is_none()
    {
        let pargs = PoliciesArgs {
            policies_file: None, // read from stdin
            policy_format: args.policies.policy_format,
            template_linked_file: args.policies.template_linked_file.clone(),
        };
        match pargs.get_policy_set() {
            Ok(_) => return CedarExitCode::Success,
            Err(e) => {
                println!("{e:?}");
                return CedarExitCode::Failure;
            }
        }
    }

    #[expect(
        clippy::useless_let_if_seq,
        reason = "exit_code is mutated by later expressions"
    )]
    let mut exit_code = CedarExitCode::Success;
    if let Err(e) = args.policies.get_policy_set() {
        println!("{e:?}");
        exit_code = CedarExitCode::Failure;
    }
    if let Some(e) = args
        .expression
        .as_ref()
        .and_then(|expr| Expression::from_str(expr).err())
    {
        println!("{:?}", Report::new(e));
        exit_code = CedarExitCode::Failure;
    }
    let schema = match args.schema.get_schema() {
        Ok(schema) => schema,
        Err(e) => {
            println!("{e:?}");
            exit_code = CedarExitCode::Failure;
            None
        }
    };
    if let Some(e) = args
        .entities_file
        .as_ref()
        .and_then(|e| load_entities(e, schema.as_ref()).err())
    {
        println!("{e:?}");
        exit_code = CedarExitCode::Failure;
    }
    exit_code
}
