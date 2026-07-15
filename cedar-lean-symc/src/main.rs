//! CLI for `cedar-lean-symc`: emit the Cedar Lean AST for a policy-set, with
//! optional stubbed property theorems.

use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;

use cedar_lean_symc::Property;

/// Emit the Cedar Lean AST for a Cedar policy-set.
#[derive(Parser)]
#[command(name = "cedar-lean-symc", about, long_about = None)]
struct Cli {
    /// Cedar policy-set file.
    #[arg(long, value_name = "FILE")]
    policy_file: String,

    /// Second policy-set file, required by binary properties (e.g. `equivalent`).
    #[arg(long, value_name = "FILE")]
    policy_file_b: Option<String>,

    /// Emit a stubbed Lean theorem for this property (repeatable).
    #[arg(long = "property", value_name = "NAME")]
    properties: Vec<Property>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(&cli) {
        Ok(lean) => {
            if io::stdout().lock().write_all(lean.as_bytes()).is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<String, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(&cli.policy_file)?;

    if cli.properties.iter().any(|p| p.is_binary()) {
        let path_b = cli
            .policy_file_b
            .as_deref()
            .ok_or("a binary property (e.g. `equivalent`) requires --policy-file-b")?;
        let text_b = std::fs::read_to_string(path_b)?;
        Ok(cedar_lean_symc::policysets_to_lean_with_properties(
            &text,
            &text_b,
            &cli.properties,
        )?)
    } else {
        if cli.policy_file_b.is_some() {
            return Err("--policy-file-b given but no binary property requested".into());
        }
        Ok(cedar_lean_symc::policyset_to_lean_with_properties(
            &text,
            &cli.properties,
        )?)
    }
}
