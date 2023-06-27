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

#![forbid(unsafe_code)]

use cedar_policy_cli::{
    authorize, check_parse, evaluate, format_policies, link, validate, CedarExitCode, Cli,
    Commands, ErrorFormat,
};

use clap::Parser;

fn main() -> CedarExitCode {
    let cli = Cli::parse();
    match cli.err_fmt {
        ErrorFormat::Human => (), // This is the default.
        ErrorFormat::Json => {
            miette::set_hook(Box::new(|_| Box::new(miette::JSONReportHandler::new())))
                .expect("failed to install JSON error-reporting hook");
        }
    }

    match cli.command {
        Commands::Authorize(args) => authorize(&args),
        Commands::Evaluate(args) => evaluate(&args).0,
        Commands::CheckParse(args) => check_parse(&args),
        Commands::Validate(args) => validate(&args),
        Commands::Format(args) => format_policies(&args),
        Commands::Link(args) => link(&args),
    }
}
