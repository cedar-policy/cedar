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

use clap::{Parser, ValueEnum};
use std::{
    fmt::{self, Display},
    process::{ExitCode, Termination},
};

/// Defines the different sub-commands implemented by the Cedar CLI
mod command;
pub use command::*;

/// Utilities for reading policies, schema, and entities from command line
/// arguments in a consistent format across the subcommands.
mod utils;
pub use utils::*;

/// Basic Cedar CLI for evaluating authorization queries
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)] // Pull from `Cargo.toml`
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    /// The output format to use for error reporting.
    #[arg(
        global = true,
        short = 'f',
        long = "error-format",
        env = "CEDAR_ERROR_FORMAT",
        default_value_t,
        value_enum
    )]
    pub err_fmt: ErrorFormat,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum ErrorFormat {
    /// Human-readable error messages with terminal graphics and inline code
    /// snippets.
    #[default]
    Human,
    /// Plain-text error messages without fancy graphics or colors, suitable for
    /// screen readers.
    Plain,
    /// Machine-readable JSON output.
    Json,
}

impl Display for ErrorFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ErrorFormat::Human => "human",
                ErrorFormat::Plain => "plain",
                ErrorFormat::Json => "json",
            }
        )
    }
}

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub enum CedarExitCode {
    // The command completed successfully with a result other than a
    // authorization deny or validation failure.
    Success,
    // The command failed to complete successfully.
    Failure,
    // The command completed successfully, but the result of the authorization
    // request was DENY.
    AuthorizeDeny,
    // The command completed successfully, but it detected a validation failure
    // in the given schema and policies.
    ValidationFailure,
    #[cfg(any(feature = "partial-eval", feature = "tpe"))]
    // The command completed successfully with an incomplete result, e.g.,
    // partial authorization result is not determining.
    Unknown,
}

impl Termination for CedarExitCode {
    fn report(self) -> ExitCode {
        match self {
            CedarExitCode::Success => ExitCode::SUCCESS,
            CedarExitCode::Failure => ExitCode::FAILURE,
            CedarExitCode::AuthorizeDeny => ExitCode::from(2),
            CedarExitCode::ValidationFailure => ExitCode::from(3),
            #[cfg(any(feature = "partial-eval", feature = "tpe"))]
            CedarExitCode::Unknown => ExitCode::SUCCESS,
        }
    }
}
