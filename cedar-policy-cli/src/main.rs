#![forbid(unsafe_code)]

use cedar_policy_cli::{
    authorize, check_parse, evaluate, format_policies, link, validate, CedarExitCode, Cli, Commands,
};

use clap::Parser;

fn main() -> CedarExitCode {
    match Cli::parse().command {
        Commands::Authorize(args) => authorize(&args),
        Commands::Evaluate(args) => evaluate(&args).0,
        Commands::CheckParse(args) => check_parse(&args),
        Commands::Validate(args) => validate(&args),
        Commands::Format(args) => format_policies(&args),
        Commands::Link(args) => link(&args),
    }
}
