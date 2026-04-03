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

use cedar_policy::{eval_expression, Entities, EvalResult, Expression};
use clap::Args;
use miette::WrapErr;
use std::str::FromStr;

use crate::{load_entities, CedarExitCode, OptionalSchemaArgs, RequestArgs};

#[derive(Args, Debug)]
pub struct EvaluateArgs {
    /// Request args (incorporated by reference)
    #[command(flatten)]
    pub request: RequestArgs,
    /// Schema args (incorporated by reference)
    ///
    /// Used to populate the store with action entities and for schema-based
    /// parsing of entity hierarchy, if present
    #[command(flatten)]
    pub schema: OptionalSchemaArgs,
    /// File containing JSON representation of the Cedar entity hierarchy.
    /// This is optional; if not present, we'll just use an empty hierarchy.
    #[arg(long = "entities", value_name = "FILE")]
    pub entities_file: Option<String>,
    /// Expression to evaluate
    #[arg(value_name = "EXPRESSION")]
    pub expression: String,
}

pub fn evaluate(args: &EvaluateArgs) -> (CedarExitCode, EvalResult) {
    println!();
    let schema = match args.schema.get_schema() {
        Ok(opt) => opt,
        Err(e) => {
            println!("{e:?}");
            return (CedarExitCode::Failure, EvalResult::Bool(false));
        }
    };
    let request = match args.request.get_request(schema.as_ref()) {
        Ok(q) => q,
        Err(e) => {
            println!("{e:?}");
            return (CedarExitCode::Failure, EvalResult::Bool(false));
        }
    };
    let expr =
        match Expression::from_str(&args.expression).wrap_err("failed to parse the expression") {
            Ok(expr) => expr,
            Err(e) => {
                println!("{:?}", e.with_source_code(args.expression.clone()));
                return (CedarExitCode::Failure, EvalResult::Bool(false));
            }
        };
    let entities = match &args.entities_file {
        None => Entities::empty(),
        Some(file) => match load_entities(file, schema.as_ref()) {
            Ok(entities) => entities,
            Err(e) => {
                println!("{e:?}");
                return (CedarExitCode::Failure, EvalResult::Bool(false));
            }
        },
    };
    match eval_expression(&request, &entities, &expr).wrap_err("failed to evaluate the expression")
    {
        Err(e) => {
            println!("{e:?}");
            (CedarExitCode::Failure, EvalResult::Bool(false))
        }
        Ok(result) => {
            println!("{result}");
            (CedarExitCode::Success, result)
        }
    }
}
