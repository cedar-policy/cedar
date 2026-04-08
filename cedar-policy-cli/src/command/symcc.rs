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

use cedar_policy::*;
use clap::{Args, Subcommand};
use itertools::Itertools;
use miette::{miette, Result};
use std::path::PathBuf;

use crate::CedarExitCode;
use crate::{read_cedar_policy_set, read_json_policy_set, PoliciesArgs};
use crate::{PolicyFormat, SchemaArgs};

#[derive(Args, Debug)]
pub struct SymccArgs {
    #[command(subcommand)]
    pub command: SymccCommands,
    /// Path to CVC5 solver executable
    #[arg(long, env = "CVC5")]
    pub cvc5_path: Option<PathBuf>,
    /// Principal entity type (e.g., 'User')
    #[arg(long)]
    pub principal_type: String,
    /// Action entity UID (e.g., 'Action::"view"')
    #[arg(long)]
    pub action: String,
    /// Resource entity type (e.g., 'Photo')
    #[arg(long)]
    pub resource_type: String,
    /// Schema args (shared across all subcommands)
    #[command(flatten)]
    pub schema: SchemaArgs,
    /// Generate counterexamples when verification fails
    #[arg(long, default_value_t = true, conflicts_with = "no_counterexample")]
    pub counterexample: bool,
    /// Don't generate counterexamples when verification fails
    #[arg(long, default_value_t = false, conflicts_with = "counterexample")]
    pub no_counterexample: bool,
    /// Verbose output showing verification details
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum SymccCommands {
    // --- Single-policy primitives ---
    /// Verify that a policy never produces runtime errors
    NeverErrors(SymccPoliciesArgs),
    /// Verify that a policy always matches (is always true)
    AlwaysMatches(SymccPoliciesArgs),
    /// Verify that a policy never matches (is always false)
    NeverMatches(SymccPoliciesArgs),

    // --- Two-policy comparison primitives ---
    /// Check if two individual policies have equivalent match conditions
    MatchesEquivalent(TwoPolicyArgs),
    /// Check if one policy's match condition implies another's
    MatchesImplies(TwoPolicyArgs),
    /// Check if two policies' match conditions are disjoint
    MatchesDisjoint(TwoPolicyArgs),

    // --- Single-policy-set primitives ---
    /// Verify that policy set always allows all well-formed requests
    AlwaysAllows(SymccPoliciesArgs),
    /// Verify that policy set always denies all well-formed requests
    AlwaysDenies(SymccPoliciesArgs),

    // --- Two-policy-set comparison primitives ---
    /// Verify that two policy sets are logically equivalent
    Equivalent(SymccTwoPoliciesArgs),
    /// Verify that one policy set implies another (subsumption)
    Implies(SymccTwoPoliciesArgs),
    /// Verify that two policy sets are disjoint (no overlapping permissions)
    Disjoint(SymccTwoPoliciesArgs),
}

/// This struct contains the arguments that together specify an input policy or policy set without linked policies.
#[derive(Args, Debug)]
pub struct SymccPoliciesArgs {
    /// File containing the Cedar policies. If not provided, read policies from stdin.
    #[arg(short, long = "policies", value_name = "FILE")]
    pub policies_file: Option<String>,
    /// Format of policies in the `--policies` file
    #[arg(long = "policy-format", default_value_t, value_enum)]
    pub policy_format: PolicyFormat,
}

impl SymccPoliciesArgs {
    /// Turn this `SymccPoliciesArgs` into the appropriate `PolicySet` object
    fn get_policy_set(&self) -> Result<PolicySet> {
        match self.policy_format {
            PolicyFormat::Cedar => read_cedar_policy_set(self.policies_file.as_ref()),
            PolicyFormat::Json => read_json_policy_set(self.policies_file.as_ref()),
        }
    }
}

/// Two-policy comparison: policy inputs
#[derive(Args, Debug)]
pub struct TwoPolicyArgs {
    /// File containing the first Cedar policy
    #[arg(long = "policy1", value_name = "FILE")]
    pub policy1_file: Option<String>,
    /// Format of the first policy file
    #[arg(long = "policy1-format", default_value_t, value_enum)]
    pub policy1_format: PolicyFormat,
    /// File containing the second Cedar policy
    #[arg(long = "policy2", value_name = "FILE")]
    pub policy2_file: Option<String>,
    /// Format of the second policy file
    #[arg(long = "policy2-format", default_value_t, value_enum)]
    pub policy2_format: PolicyFormat,
}

impl TwoPolicyArgs {
    fn get_policy_set_1(&self) -> Result<PolicySet> {
        let pargs = PoliciesArgs {
            policies_file: self.policy1_file.clone(),
            policy_format: self.policy1_format,
            template_linked_file: None,
        };
        pargs.get_policy_set()
    }

    fn get_policy_set_2(&self) -> Result<PolicySet> {
        let pargs = PoliciesArgs {
            policies_file: self.policy2_file.clone(),
            policy_format: self.policy2_format,
            template_linked_file: None,
        };
        pargs.get_policy_set()
    }
}

/// Two policy-set comparison: policy set inputs without linked policies.
#[derive(Args, Debug)]
pub struct SymccTwoPoliciesArgs {
    /// File containing the first policy set
    #[arg(long = "policies1", value_name = "FILE")]
    pub policies1_file: Option<String>,
    /// Format of the first policy set file
    #[arg(long = "policies1-format", default_value_t, value_enum)]
    pub policies1_format: PolicyFormat,
    /// File containing the second policy set
    #[arg(long = "policies2", value_name = "FILE")]
    pub policies2_file: Option<String>,
    /// Format of the second policy set file
    #[arg(long = "policies2-format", default_value_t, value_enum)]
    pub policies2_format: PolicyFormat,
}

impl SymccTwoPoliciesArgs {
    fn get_policy_set_1(&self) -> Result<PolicySet> {
        let pargs = SymccPoliciesArgs {
            policies_file: self.policies1_file.clone(),
            policy_format: self.policies1_format,
        };
        pargs.get_policy_set()
    }

    fn get_policy_set_2(&self) -> Result<PolicySet> {
        let pargs = SymccPoliciesArgs {
            policies_file: self.policies2_file.clone(),
            policy_format: self.policies2_format,
        };
        pargs.get_policy_set()
    }
}

pub fn symcc(args: &SymccArgs) -> CedarExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to initialize async runtime: {e}");
            return CedarExitCode::Failure;
        }
    };

    rt.block_on(async {
        match symcc_async(args).await {
            Ok(()) => CedarExitCode::Success,
            Err(e) => {
                eprintln!("Analysis failed: {e:?}");
                CedarExitCode::Failure
            }
        }
    })
}

fn initialize_solver(
    cvc5_path: Option<&PathBuf>,
) -> Result<cedar_policy_symcc::solver::LocalSolver> {
    match cvc5_path {
        Some(p) => cedar_policy_symcc::solver::LocalSolver::from_command(
            tokio::process::Command::new(p).args(["--lang", "smt", "--tlimit=60000"]),
        )
        .map_err(|e| {
            miette!(
                "CVC5 solver not found or failed to start at '{}': {e}",
                p.display()
            )
        }),
        None => cedar_policy_symcc::solver::LocalSolver::cvc5()
            .map_err(|e| miette!("CVC5 solver not found or failed to start: {e}")),
    }
}

fn warn_if_contains_templates(pset: &PolicySet, name: &str) {
    let num_templates = pset.templates().count();
    if num_templates > 0 {
        let report = miette!(
            severity = miette::Severity::Warning,
            "{name} contains {num_templates} policy template(s), which will be ignored by analysis"
        );
        eprintln!("{report:?}");
    }
}

fn load_single_policy(
    policies: &SymccPoliciesArgs,
    schema_args: &SchemaArgs,
) -> Result<(Policy, Schema)> {
    let pset = policies.get_policy_set()?;
    let schema = schema_args.get_schema()?;
    let policy = pset
        .policies()
        .exactly_one()
        .map_err(|e| miette!("Expected exactly one policy, found {}", e.count()))?
        .clone();
    Ok((policy, schema))
}

fn load_two_policies(
    args: &TwoPolicyArgs,
    schema_args: &SchemaArgs,
) -> Result<(Policy, Policy, Schema)> {
    let pset1 = args.get_policy_set_1()?;
    let pset2 = args.get_policy_set_2()?;
    let schema = schema_args.get_schema()?;
    let p1 = pset1
        .policies()
        .exactly_one()
        .map_err(|e| {
            miette!(
                "Expected exactly one policy in --policy1, found {}",
                e.count()
            )
        })?
        .clone();
    let p2 = pset2
        .policies()
        .exactly_one()
        .map_err(|e| {
            miette!(
                "Expected exactly one policy in --policy2, found {}",
                e.count()
            )
        })?
        .clone();
    Ok((p1, p2, schema))
}

fn load_policy_set(
    policies: &SymccPoliciesArgs,
    schema_args: &SchemaArgs,
) -> Result<(PolicySet, Schema)> {
    let pset = policies.get_policy_set()?;
    warn_if_contains_templates(&pset, "policy set");
    let schema = schema_args.get_schema()?;
    Ok((pset, schema))
}

fn load_two_policy_sets(
    args: &SymccTwoPoliciesArgs,
    schema_args: &SchemaArgs,
) -> Result<(PolicySet, PolicySet, Schema)> {
    let pset1 = args.get_policy_set_1()?;
    let pset2 = args.get_policy_set_2()?;
    warn_if_contains_templates(&pset1, "first policy set");
    warn_if_contains_templates(&pset2, "second policy set");
    let schema = schema_args.get_schema()?;
    Ok((pset1, pset2, schema))
}

fn format_bool_result(holds: bool, property: &str) {
    if holds {
        println!("✓ {property}: VERIFIED");
    } else {
        println!("✗ {property}: DOES NOT HOLD");
    }
}

fn format_counterexample_result(
    cex: Option<cedar_policy_symcc::Env>,
    property: &str,
    verbose: bool,
) {
    match cex {
        None => {
            println!("✓ {property}: VERIFIED");
            if verbose {
                println!("  No counterexample found — property holds for all well-formed inputs.");
            }
        }
        Some(env) => {
            println!("✗ {property}: DOES NOT HOLD");
            println!("  Counterexample found:");
            println!("{env}");
        }
    }
}

fn build_request_env(args: &SymccArgs) -> Result<RequestEnv> {
    let principal_type: EntityTypeName = args
        .principal_type
        .parse()
        .map_err(|e| miette!("Invalid --principal-type '{}': {e}", args.principal_type))?;
    let action: EntityUid = args
        .action
        .parse()
        .map_err(|e| miette!("Invalid --action '{}': {e}", args.action))?;
    let resource_type: EntityTypeName = args
        .resource_type
        .parse()
        .map_err(|e| miette!("Invalid --resource-type '{}': {e}", args.resource_type))?;
    Ok(RequestEnv::new(principal_type, action, resource_type))
}

async fn symcc_async(args: &SymccArgs) -> Result<()> {
    use cedar_policy_symcc::{CedarSymCompiler, CompiledPolicy, CompiledPolicySet};

    let solver = initialize_solver(args.cvc5_path.as_ref())?;
    let mut compiler = CedarSymCompiler::new(solver)
        .map_err(|e| miette!("Failed to initialize SymCC compiler: {e}"))?;
    let req_env = build_request_env(args)?;

    match &args.command {
        // --- Single-policy primitives ---
        SymccCommands::NeverErrors(cmd_args) => {
            let (policy, schema) = load_single_policy(cmd_args, &args.schema)?;
            let compiled = CompiledPolicy::compile(&policy, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy: {e}"))?;
            if args.counterexample && !args.no_counterexample {
                let result = compiler
                    .check_never_errors_with_counterexample_opt(&compiled)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_counterexample_result(result, "Policy never errors", args.verbose);
            } else {
                let holds = compiler
                    .check_never_errors_opt(&compiled)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_bool_result(holds, "Policy never errors");
            }
        }
        SymccCommands::AlwaysMatches(cmd_args) => {
            let (policy, schema) = load_single_policy(cmd_args, &args.schema)?;
            let compiled = CompiledPolicy::compile(&policy, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy: {e}"))?;
            if args.counterexample && !args.no_counterexample {
                let result = compiler
                    .check_always_matches_with_counterexample_opt(&compiled)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_counterexample_result(result, "Policy always matches", args.verbose);
            } else {
                let holds = compiler
                    .check_always_matches_opt(&compiled)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_bool_result(holds, "Policy always matches");
            }
        }
        SymccCommands::NeverMatches(cmd_args) => {
            let (policy, schema) = load_single_policy(cmd_args, &args.schema)?;
            let compiled = CompiledPolicy::compile(&policy, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy: {e}"))?;
            if args.counterexample && !args.no_counterexample {
                let result = compiler
                    .check_never_matches_with_counterexample_opt(&compiled)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_counterexample_result(result, "Policy never matches", args.verbose);
            } else {
                let holds = compiler
                    .check_never_matches_opt(&compiled)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_bool_result(holds, "Policy never matches");
            }
        }

        // --- Two-policy comparison primitives ---
        SymccCommands::MatchesEquivalent(cmd_args) => {
            let (p1, p2, schema) = load_two_policies(cmd_args, &args.schema)?;
            let compiled1 = CompiledPolicy::compile(&p1, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy1: {e}"))?;
            let compiled2 = CompiledPolicy::compile(&p2, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy2: {e}"))?;
            if args.counterexample && !args.no_counterexample {
                let result = compiler
                    .check_matches_equivalent_with_counterexample_opt(&compiled1, &compiled2)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_counterexample_result(
                    result,
                    "Policies have equivalent match conditions",
                    args.verbose,
                );
            } else {
                let holds = compiler
                    .check_matches_equivalent_opt(&compiled1, &compiled2)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_bool_result(holds, "Policies have equivalent match conditions");
            }
        }
        SymccCommands::MatchesImplies(cmd_args) => {
            let (p1, p2, schema) = load_two_policies(cmd_args, &args.schema)?;
            let compiled1 = CompiledPolicy::compile(&p1, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy1: {e}"))?;
            let compiled2 = CompiledPolicy::compile(&p2, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy2: {e}"))?;
            if args.counterexample && !args.no_counterexample {
                let result = compiler
                    .check_matches_implies_with_counterexample_opt(&compiled1, &compiled2)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_counterexample_result(
                    result,
                    "Policy1 match implies Policy2 match",
                    args.verbose,
                );
            } else {
                let holds = compiler
                    .check_matches_implies_opt(&compiled1, &compiled2)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_bool_result(holds, "Policy1 match implies Policy2 match");
            }
        }
        SymccCommands::MatchesDisjoint(cmd_args) => {
            let (p1, p2, schema) = load_two_policies(cmd_args, &args.schema)?;
            let compiled1 = CompiledPolicy::compile(&p1, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy1: {e}"))?;
            let compiled2 = CompiledPolicy::compile(&p2, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy2: {e}"))?;
            if args.counterexample && !args.no_counterexample {
                let result = compiler
                    .check_matches_disjoint_with_counterexample_opt(&compiled1, &compiled2)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_counterexample_result(
                    result,
                    "Policies have disjoint match conditions",
                    args.verbose,
                );
            } else {
                let holds = compiler
                    .check_matches_disjoint_opt(&compiled1, &compiled2)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_bool_result(holds, "Policies have disjoint match conditions");
            }
        }

        // --- Single-policy-set primitives ---
        SymccCommands::AlwaysAllows(cmd_args) => {
            let (pset, schema) = load_policy_set(cmd_args, &args.schema)?;
            let compiled = CompiledPolicySet::compile(&pset, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy set: {e}"))?;
            if args.counterexample && !args.no_counterexample {
                let result = compiler
                    .check_always_allows_with_counterexample_opt(&compiled)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_counterexample_result(result, "Policy set always allows", args.verbose);
            } else {
                let holds = compiler
                    .check_always_allows_opt(&compiled)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_bool_result(holds, "Policy set always allows");
            }
        }
        SymccCommands::AlwaysDenies(cmd_args) => {
            let (pset, schema) = load_policy_set(cmd_args, &args.schema)?;
            let compiled = CompiledPolicySet::compile(&pset, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy set: {e}"))?;
            if args.counterexample && !args.no_counterexample {
                let result = compiler
                    .check_always_denies_with_counterexample_opt(&compiled)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_counterexample_result(result, "Policy set always denies", args.verbose);
            } else {
                let holds = compiler
                    .check_always_denies_opt(&compiled)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_bool_result(holds, "Policy set always denies");
            }
        }

        // --- Two-policy-set primitives ---
        SymccCommands::Equivalent(cmd_args) => {
            let (pset1, pset2, schema) = load_two_policy_sets(cmd_args, &args.schema)?;
            let compiled1 = CompiledPolicySet::compile(&pset1, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy set 1: {e}"))?;
            let compiled2 = CompiledPolicySet::compile(&pset2, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy set 2: {e}"))?;
            if args.counterexample && !args.no_counterexample {
                let result = compiler
                    .check_equivalent_with_counterexample_opt(&compiled1, &compiled2)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_counterexample_result(result, "Policy sets are equivalent", args.verbose);
            } else {
                let holds = compiler
                    .check_equivalent_opt(&compiled1, &compiled2)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_bool_result(holds, "Policy sets are equivalent");
            }
        }
        SymccCommands::Implies(cmd_args) => {
            let (pset1, pset2, schema) = load_two_policy_sets(cmd_args, &args.schema)?;
            let compiled1 = CompiledPolicySet::compile(&pset1, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy set 1: {e}"))?;
            let compiled2 = CompiledPolicySet::compile(&pset2, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy set 2: {e}"))?;
            if args.counterexample && !args.no_counterexample {
                let result = compiler
                    .check_implies_with_counterexample_opt(&compiled1, &compiled2)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_counterexample_result(
                    result,
                    "Policy set 1 implies policy set 2",
                    args.verbose,
                );
            } else {
                let holds = compiler
                    .check_implies_opt(&compiled1, &compiled2)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_bool_result(holds, "Policy set 1 implies policy set 2");
            }
        }
        SymccCommands::Disjoint(cmd_args) => {
            let (pset1, pset2, schema) = load_two_policy_sets(cmd_args, &args.schema)?;
            let compiled1 = CompiledPolicySet::compile(&pset1, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy set 1: {e}"))?;
            let compiled2 = CompiledPolicySet::compile(&pset2, &req_env, &schema)
                .map_err(|e| miette!("Failed to compile policy set 2: {e}"))?;
            if args.counterexample && !args.no_counterexample {
                let result = compiler
                    .check_disjoint_with_counterexample_opt(&compiled1, &compiled2)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_counterexample_result(result, "Policy sets are disjoint", args.verbose);
            } else {
                let holds = compiler
                    .check_disjoint_opt(&compiled1, &compiled2)
                    .await
                    .map_err(|e| miette!("Verification failed: {e}"))?;
                format_bool_result(holds, "Policy sets are disjoint");
            }
        }
    }

    Ok(())
}
