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

// This modules makes use of `return` to exit early with a particular exit code.
// For consistency, it also uses `return` in some places where it could be
// omitted.
#![allow(clippy::needless_return)]

use cedar_policy::entities_errors::EntitiesError;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use miette::{miette, Diagnostic, IntoDiagnostic, NamedSource, Report, Result, WrapErr};
use owo_colors::OwoColorize;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;
use std::io::{BufReader, Write};
use std::{
    collections::HashMap,
    fmt::{self, Display},
    fs::OpenOptions,
    path::{Path, PathBuf},
    process::{ExitCode, Termination},
    str::FromStr,
    time::Instant,
};
use thiserror::Error;

use cedar_policy::*;
use cedar_policy_formatter::{policies_str_to_pretty, Config};

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

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Evaluate an authorization request
    Authorize(AuthorizeArgs),
    /// Evaluate a Cedar expression
    Evaluate(EvaluateArgs),
    /// Validate a policy set against a schema
    Validate(ValidateArgs),
    /// Check that policies, schema, and/or entities successfully parse.
    /// (All arguments are optional; this checks that whatever is provided parses)
    ///
    /// If no arguments are provided, reads policies from stdin and checks that they parse.
    CheckParse(CheckParseArgs),
    /// Link a template
    Link(LinkArgs),
    /// Format a policy set
    Format(FormatArgs),
    /// Translate Cedar policy syntax to JSON policy syntax (except comments)
    TranslatePolicy(TranslatePolicyArgs),
    /// Translate Cedar schema syntax to JSON schema syntax and vice versa (except comments)
    TranslateSchema(TranslateSchemaArgs),
    /// Visualize a set of JSON entities to the graphviz format.
    /// Warning: Entity visualization is best-effort and not well tested.
    Visualize(VisualizeArgs),
    /// Create a Cedar project
    New(NewArgs),
    /// Partially evaluate an authorization request
    PartiallyAuthorize(PartiallyAuthorizeArgs),
    /// Run test cases on a policy set
    RunTests(RunTestsArgs),
    /// Print Cedar language version
    LanguageVersion,
}

#[derive(Args, Debug)]
pub struct TranslatePolicyArgs {
    /// The direction of translation,
    #[arg(long)]
    pub direction: PolicyTranslationDirection,
    /// Filename to read the policies from.
    /// If not provided, will default to reading stdin.
    #[arg(short = 'p', long = "policies", value_name = "FILE")]
    pub input_file: Option<String>,
}

/// The direction of translation
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum PolicyTranslationDirection {
    /// Cedar policy syntax -> JSON
    CedarToJson,
    /// JSON -> Cedar policy syntax
    JsonToCedar,
}

#[derive(Args, Debug)]
pub struct TranslateSchemaArgs {
    /// The direction of translation,
    #[arg(long)]
    pub direction: SchemaTranslationDirection,
    /// Filename to read the schema from.
    /// If not provided, will default to reading stdin.
    #[arg(short = 's', long = "schema", value_name = "FILE")]
    pub input_file: Option<String>,
}

/// The direction of translation
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SchemaTranslationDirection {
    /// JSON -> Cedar schema syntax
    JsonToCedar,
    /// Cedar schema syntax -> JSON
    CedarToJson,
}

#[derive(Debug, Default, Clone, Copy, ValueEnum)]
pub enum SchemaFormat {
    /// the Cedar format
    #[default]
    Cedar,
    /// JSON format
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ValidationMode {
    /// Strict validation
    Strict,
    /// Permissive validation
    Permissive,
    /// Partial validation
    Partial,
}

#[derive(Args, Debug)]
pub struct ValidateArgs {
    /// Schema args (incorporated by reference)
    #[command(flatten)]
    pub schema: SchemaArgs,
    /// Policies args (incorporated by reference)
    #[command(flatten)]
    pub policies: PoliciesArgs,
    /// Report a validation failure for non-fatal warnings
    #[arg(long)]
    pub deny_warnings: bool,
    /// Validate the policy using this mode.
    /// The options `permissive` and `partial` are experimental
    /// and will cause the CLI to exit if it was not built with the
    /// experimental feature `permissive-validate` and `partial-validate`, respectively, enabled.
    #[arg(long, value_enum, default_value_t = ValidationMode::Strict)]
    pub validation_mode: ValidationMode,
    /// Validate the policy at this level.
    #[arg(long)]
    pub level: Option<u32>,
}

#[derive(Args, Debug)]
pub struct CheckParseArgs {
    /// Policies args (incorporated by reference)
    #[command(flatten)]
    pub policies: OptionalPoliciesArgs,
    /// Schema args (incorporated by reference)
    #[command(flatten)]
    pub schema: OptionalSchemaArgs,
    /// File containing JSON representation of a Cedar entity hierarchy
    #[arg(long = "entities", value_name = "FILE")]
    pub entities_file: Option<PathBuf>,
}

/// This struct contains the arguments that together specify a request.
#[derive(Args, Debug)]
pub struct RequestArgs {
    /// Principal for the request, e.g., User::"alice"
    #[arg(short = 'l', long)]
    pub principal: Option<String>,
    /// Action for the request, e.g., Action::"view"
    #[arg(short, long)]
    pub action: Option<String>,
    /// Resource for the request, e.g., File::"myfile.txt"
    #[arg(short, long)]
    pub resource: Option<String>,
    /// File containing a JSON object representing the context for the request.
    /// Should be a (possibly empty) map from keys to values.
    #[arg(short, long = "context", value_name = "FILE")]
    pub context_json_file: Option<String>,
    /// File containing a JSON object representing the entire request. Must have
    /// fields "principal", "action", "resource", and "context", where "context"
    /// is a (possibly empty) map from keys to values. This option replaces
    /// --principal, --action, etc.
    #[arg(long = "request-json", value_name = "FILE", conflicts_with_all = &["principal", "action", "resource", "context_json_file"])]
    pub request_json_file: Option<String>,
    /// Whether to enable request validation. This has no effect if a schema is
    /// not provided.
    #[arg(long = "request-validation", action = ArgAction::Set, default_value_t = true)]
    pub request_validation: bool,
}

#[cfg(feature = "partial-eval")]
/// This struct contains the arguments that together specify a request.
#[derive(Args, Debug)]
pub struct PartialRequestArgs {
    /// Principal for the request, e.g., User::"alice"
    #[arg(short = 'l', long)]
    pub principal: Option<String>,
    /// Action for the request, e.g., Action::"view"
    #[arg(short, long)]
    pub action: Option<String>,
    /// Resource for the request, e.g., File::"myfile.txt"
    #[arg(short, long)]
    pub resource: Option<String>,
    /// File containing a JSON object representing the context for the request.
    /// Should be a (possibly empty) map from keys to values.
    #[arg(short, long = "context", value_name = "FILE")]
    pub context_json_file: Option<String>,
    /// File containing a JSON object representing the entire request. Must have
    /// fields "principal", "action", "resource", and "context", where "context"
    /// is a (possibly empty) map from keys to values. This option replaces
    /// --principal, --action, etc.
    #[arg(long = "request-json", value_name = "FILE", conflicts_with_all = &["principal", "action", "resource", "context_json_file"])]
    pub request_json_file: Option<String>,
}

impl RequestArgs {
    /// Turn this `RequestArgs` into the appropriate `Request` object
    ///
    /// `schema` will be used for schema-based parsing of the context, and also
    /// (if `self.request_validation` is `true`) for request validation.
    ///
    /// `self.request_validation` has no effect if `schema` is `None`.
    fn get_request(&self, schema: Option<&Schema>) -> Result<Request> {
        match &self.request_json_file {
            Some(jsonfile) => {
                let jsonstring = std::fs::read_to_string(jsonfile)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to open request-json file {jsonfile}"))?;
                let qjson: RequestJSON = serde_json::from_str(&jsonstring)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to parse request-json file {jsonfile}"))?;
                let principal = qjson.principal.parse().wrap_err_with(|| {
                    format!("failed to parse principal in {jsonfile} as entity Uid")
                })?;
                let action = qjson.action.parse().wrap_err_with(|| {
                    format!("failed to parse action in {jsonfile} as entity Uid")
                })?;
                let resource = qjson.resource.parse().wrap_err_with(|| {
                    format!("failed to parse resource in {jsonfile} as entity Uid")
                })?;
                let context = Context::from_json_value(qjson.context, schema.map(|s| (s, &action)))
                    .wrap_err_with(|| format!("failed to create a context from {jsonfile}"))?;
                Request::new(
                    principal,
                    action,
                    resource,
                    context,
                    if self.request_validation {
                        schema
                    } else {
                        None
                    },
                )
                .map_err(|e| miette!("{e}"))
            }
            None => {
                let principal = self
                    .principal
                    .as_ref()
                    .map(|s| {
                        s.parse().wrap_err_with(|| {
                            format!("failed to parse principal {s} as entity Uid")
                        })
                    })
                    .transpose()?;
                let action = self
                    .action
                    .as_ref()
                    .map(|s| {
                        s.parse()
                            .wrap_err_with(|| format!("failed to parse action {s} as entity Uid"))
                    })
                    .transpose()?;
                let resource = self
                    .resource
                    .as_ref()
                    .map(|s| {
                        s.parse()
                            .wrap_err_with(|| format!("failed to parse resource {s} as entity Uid"))
                    })
                    .transpose()?;
                let context: Context = match &self.context_json_file {
                    None => Context::empty(),
                    Some(jsonfile) => match std::fs::OpenOptions::new().read(true).open(jsonfile) {
                        Ok(f) => Context::from_json_file(
                            f,
                            schema.and_then(|s| Some((s, action.as_ref()?))),
                        )
                        .wrap_err_with(|| format!("failed to create a context from {jsonfile}"))?,
                        Err(e) => Err(e).into_diagnostic().wrap_err_with(|| {
                            format!("error while loading context from {jsonfile}")
                        })?,
                    },
                };
                match (principal, action, resource) {
                    (Some(principal), Some(action), Some(resource)) => Request::new(
                        principal,
                        action,
                        resource,
                        context,
                        if self.request_validation {
                            schema
                        } else {
                            None
                        },
                    )
                    .map_err(|e| miette!("{e}")),
                    _ => Err(miette!(
                        "All three (`principal`, `action`, `resource`) variables must be specified"
                    )),
                }
            }
        }
    }
}

#[cfg(feature = "partial-eval")]
impl PartialRequestArgs {
    fn get_request(&self, schema: Option<&Schema>) -> Result<Request> {
        let mut builder = RequestBuilder::default();
        let qjson: PartialRequestJSON = match self.request_json_file.as_ref() {
            Some(jsonfile) => {
                let jsonstring = std::fs::read_to_string(jsonfile)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to open request-json file {jsonfile}"))?;
                serde_json::from_str(&jsonstring)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to parse request-json file {jsonfile}"))?
            }
            None => PartialRequestJSON {
                principal: self.principal.clone(),
                action: self.action.clone(),
                resource: self.resource.clone(),
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

        if let Some(principal) = qjson
            .principal
            .map(|s| {
                s.parse()
                    .wrap_err_with(|| format!("failed to parse principal {s} as entity Uid"))
            })
            .transpose()?
        {
            builder = builder.principal(principal);
        }

        let action = qjson
            .action
            .map(|s| {
                s.parse::<EntityUid>()
                    .wrap_err_with(|| format!("failed to parse action {s} as entity Uid"))
            })
            .transpose()?;

        if let Some(action_ref) = &action {
            builder = builder.action(action_ref.clone());
        }

        if let Some(resource) = qjson
            .resource
            .map(|s| {
                s.parse()
                    .wrap_err_with(|| format!("failed to parse resource {s} as entity Uid"))
            })
            .transpose()?
        {
            builder = builder.resource(resource);
        }

        if let Some(context) = qjson
            .context
            .map(|json| {
                Context::from_json_value(
                    json.clone(),
                    schema.and_then(|s| Some((s, action.as_ref()?))),
                )
                .wrap_err_with(|| format!("fail to convert context json {json} to Context"))
            })
            .transpose()?
        {
            builder = builder.context(context);
        }

        if let Some(schema) = schema {
            builder
                .schema(schema)
                .build()
                .wrap_err_with(|| "failed to build request with validation".to_string())
        } else {
            Ok(builder.build())
        }
    }
}

/// This struct contains the arguments that together specify an input policy or policy set.
#[derive(Args, Debug)]
pub struct PoliciesArgs {
    /// File containing the static Cedar policies and/or templates. If not provided, read policies from stdin.
    #[arg(short, long = "policies", value_name = "FILE")]
    pub policies_file: Option<String>,
    /// Format of policies in the `--policies` file
    #[arg(long = "policy-format", default_value_t, value_enum)]
    pub policy_format: PolicyFormat,
    /// File containing template-linked policies
    #[arg(short = 'k', long = "template-linked", value_name = "FILE")]
    pub template_linked_file: Option<String>,
}

impl PoliciesArgs {
    /// Turn this `PoliciesArgs` into the appropriate `PolicySet` object
    fn get_policy_set(&self) -> Result<PolicySet> {
        let mut pset = match self.policy_format {
            PolicyFormat::Cedar => read_cedar_policy_set(self.policies_file.as_ref()),
            PolicyFormat::Json => read_json_policy_set(self.policies_file.as_ref()),
        }?;
        if let Some(links_filename) = self.template_linked_file.as_ref() {
            add_template_links_to_set(links_filename, &mut pset)?;
        }
        Ok(pset)
    }
}

/// This struct contains the arguments that together specify an input policy or policy set,
/// for commands where policies are optional.
#[derive(Args, Debug)]
pub struct OptionalPoliciesArgs {
    /// File containing static Cedar policies and/or templates
    #[arg(short, long = "policies", value_name = "FILE")]
    pub policies_file: Option<String>,
    /// Format of policies in the `--policies` file
    #[arg(long = "policy-format", default_value_t, value_enum)]
    pub policy_format: PolicyFormat,
    /// File containing template-linked policies. Ignored if `--policies` is not
    /// present (because in that case there are no templates to link against)
    #[arg(short = 'k', long = "template-linked", value_name = "FILE")]
    pub template_linked_file: Option<String>,
}

impl OptionalPoliciesArgs {
    /// Turn this `OptionalPoliciesArgs` into the appropriate `PolicySet`
    /// object, or `None` if no policies were provided
    fn get_policy_set(&self) -> Result<Option<PolicySet>> {
        match &self.policies_file {
            None => Ok(None),
            Some(policies_file) => {
                let pargs = PoliciesArgs {
                    policies_file: Some(policies_file.clone()),
                    policy_format: self.policy_format,
                    template_linked_file: self.template_linked_file.clone(),
                };
                pargs.get_policy_set().map(Some)
            }
        }
    }
}

/// This struct contains the arguments that together specify an input schema.
#[derive(Args, Debug)]
pub struct SchemaArgs {
    /// File containing the schema
    #[arg(short, long = "schema", value_name = "FILE")]
    pub schema_file: PathBuf,
    /// Schema format
    #[arg(long, value_enum, default_value_t)]
    pub schema_format: SchemaFormat,
}

impl SchemaArgs {
    /// Turn this `SchemaArgs` into the appropriate `Schema` object
    fn get_schema(&self) -> Result<Schema> {
        read_schema_from_file(&self.schema_file, self.schema_format)
    }
}

/// This struct contains the arguments that together specify an input schema,
/// for commands where the schema is optional.
#[derive(Args, Debug)]
pub struct OptionalSchemaArgs {
    /// File containing the schema
    #[arg(short, long = "schema", value_name = "FILE")]
    pub schema_file: Option<PathBuf>,
    /// Schema format
    #[arg(long, value_enum, default_value_t)]
    pub schema_format: SchemaFormat,
}

impl OptionalSchemaArgs {
    /// Turn this `OptionalSchemaArgs` into the appropriate `Schema` object, or `None`
    fn get_schema(&self) -> Result<Option<Schema>> {
        let Some(schema_file) = &self.schema_file else {
            return Ok(None);
        };
        read_schema_from_file(schema_file, self.schema_format).map(Some)
    }
}

fn read_schema_from_file(path: impl AsRef<Path>, format: SchemaFormat) -> Result<Schema> {
    let path = path.as_ref();
    let schema_src = read_from_file(path, "schema")?;
    match format {
        SchemaFormat::Json => Schema::from_json_str(&schema_src)
            .wrap_err_with(|| format!("failed to parse schema from file {}", path.display())),
        SchemaFormat::Cedar => {
            let (schema, warnings) = Schema::from_cedarschema_str(&schema_src)
                .wrap_err_with(|| format!("failed to parse schema from file {}", path.display()))?;
            for warning in warnings {
                let report = miette::Report::new(warning);
                eprintln!("{report:?}");
            }
            Ok(schema)
        }
    }
}

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
    /// File containing JSON representation of the Cedar entity hierarchy
    #[arg(long = "entities", value_name = "FILE")]
    pub entities_file: String,
    /// More verbose output. (For instance, indicate which policies applied to the request, if any.)
    #[arg(short, long)]
    pub verbose: bool,
    /// Time authorization and report timing information
    #[arg(short, long)]
    pub timing: bool,
}

#[cfg(feature = "partial-eval")]
#[derive(Args, Debug)]
pub struct PartiallyAuthorizeArgs {
    /// Request args (incorporated by reference)
    #[command(flatten)]
    pub request: PartialRequestArgs,
    /// Policies args (incorporated by reference)
    #[command(flatten)]
    pub policies: PoliciesArgs,
    /// Schema args (incorporated by reference)
    ///
    /// Used to populate the store with action entities and for schema-based
    /// parsing of entity hierarchy, if present
    #[command(flatten)]
    pub schema: OptionalSchemaArgs,
    /// File containing JSON representation of the Cedar entity hierarchy
    #[arg(long = "entities", value_name = "FILE")]
    pub entities_file: String,
    /// Time authorization and report timing information
    #[arg(short, long)]
    pub timing: bool,
}

#[cfg(not(feature = "partial-eval"))]
#[derive(Debug, Args)]
pub struct PartiallyAuthorizeArgs;

#[derive(Args, Debug)]
pub struct RunTestsArgs {
    /// Policies args (incorporated by reference)
    #[command(flatten)]
    pub policies: PoliciesArgs,
    /// Tests in JSON format
    #[arg(long, value_name = "FILE")]
    pub tests: String,
}

#[derive(Args, Debug)]
pub struct VisualizeArgs {
    #[arg(long = "entities", value_name = "FILE")]
    pub entities_file: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum PolicyFormat {
    /// The standard Cedar policy format, documented at <https://docs.cedarpolicy.com/policies/syntax-policy.html>
    #[default]
    Cedar,
    /// Cedar's JSON policy format, documented at <https://docs.cedarpolicy.com/policies/json-format.html>
    Json,
}

#[derive(Args, Debug)]
pub struct LinkArgs {
    /// Policies args (incorporated by reference)
    #[command(flatten)]
    pub policies: PoliciesArgs,
    /// Id of the template to link
    #[arg(long)]
    pub template_id: String,
    /// Id for the new template linked policy
    #[arg(short, long)]
    pub new_id: String,
    /// Arguments to fill slots
    #[arg(short, long)]
    pub arguments: Arguments,
}

#[derive(Args, Debug)]
pub struct FormatArgs {
    /// File containing the static Cedar policies and/or templates. If not provided, read policies from stdin.
    #[arg(short, long = "policies", value_name = "FILE")]
    pub policies_file: Option<String>,

    /// Custom line width (default: 80).
    #[arg(short, long, value_name = "UINT", default_value_t = 80)]
    pub line_width: usize,

    /// Custom indentation width (default: 2).
    #[arg(short, long, value_name = "INT", default_value_t = 2)]
    pub indent_width: isize,

    /// Automatically write back the formatted policies to the input file.
    #[arg(short, long, group = "action", requires = "policies_file")]
    pub write: bool,

    /// Check that the policies formats without any changes. Mutually exclusive with `write`.
    #[arg(short, long, group = "action")]
    pub check: bool,
}

#[derive(Args, Debug)]
pub struct NewArgs {
    /// Name of the Cedar project
    #[arg(short, long, value_name = "DIR")]
    pub name: String,
}

/// Wrapper struct
#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "HashMap<String,String>")]
pub struct Arguments {
    pub data: HashMap<SlotId, String>,
}

impl TryFrom<HashMap<String, String>> for Arguments {
    type Error = String;

    fn try_from(value: HashMap<String, String>) -> Result<Self, Self::Error> {
        Ok(Self {
            data: value
                .into_iter()
                .map(|(k, v)| parse_slot_id(k).map(|slot_id| (slot_id, v)))
                .collect::<Result<HashMap<SlotId, String>, String>>()?,
        })
    }
}

impl FromStr for Arguments {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

/// This struct is the serde structure expected for --request-json
#[derive(Clone, Debug, Deserialize)]
struct RequestJSON {
    /// Principal for the request
    #[serde(default)]
    principal: String,
    /// Action for the request
    #[serde(default)]
    action: String,
    /// Resource for the request
    #[serde(default)]
    resource: String,
    /// Context for the request
    context: serde_json::Value,
}

#[cfg(feature = "partial-eval")]
/// This struct is the serde structure expected for --request-json
#[derive(Deserialize)]
struct PartialRequestJSON {
    /// Principal for the request
    pub(self) principal: Option<String>,
    /// Action for the request
    pub(self) action: Option<String>,
    /// Resource for the request
    pub(self) resource: Option<String>,
    /// Context for the request
    pub(self) context: Option<serde_json::Value>,
}

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
    #[cfg(feature = "partial-eval")]
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
            #[cfg(feature = "partial-eval")]
            CedarExitCode::Unknown => ExitCode::SUCCESS,
        }
    }
}

pub fn check_parse(args: &CheckParseArgs) -> CedarExitCode {
    // for backwards compatibility: if no policies/schema/entities are provided,
    // read policies from stdin and check that they parse
    if (
        &args.policies.policies_file,
        &args.schema.schema_file,
        &args.entities_file,
    ) == (&None, &None, &None)
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

    let mut exit_code = CedarExitCode::Success;
    match args.policies.get_policy_set() {
        Ok(_) => (),
        Err(e) => {
            println!("{e:?}");
            exit_code = CedarExitCode::Failure;
        }
    }
    let schema = match args.schema.get_schema() {
        Ok(schema) => schema,
        Err(e) => {
            println!("{e:?}");
            exit_code = CedarExitCode::Failure;
            None
        }
    };
    match &args.entities_file {
        None => (),
        Some(efile) => match load_entities(efile, schema.as_ref()) {
            Ok(_) => (),
            Err(e) => {
                println!("{e:?}");
                exit_code = CedarExitCode::Failure;
            }
        },
    }
    exit_code
}

pub fn validate(args: &ValidateArgs) -> CedarExitCode {
    let mode = match args.validation_mode {
        ValidationMode::Strict => cedar_policy::ValidationMode::Strict,
        ValidationMode::Permissive => {
            #[cfg(not(feature = "permissive-validate"))]
            {
                eprintln!("Error: arguments include the experimental option `--validation-mode permissive`, but this executable was not built with `permissive-validate` experimental feature enabled");
                return CedarExitCode::Failure;
            }
            #[cfg(feature = "permissive-validate")]
            cedar_policy::ValidationMode::Permissive
        }
        ValidationMode::Partial => {
            #[cfg(not(feature = "partial-validate"))]
            {
                eprintln!("Error: arguments include the experimental option `--validation-mode partial`, but this executable was not built with `partial-validate` experimental feature enabled");
                return CedarExitCode::Failure;
            }
            #[cfg(feature = "partial-validate")]
            cedar_policy::ValidationMode::Partial
        }
    };

    let pset = match args.policies.get_policy_set() {
        Ok(pset) => pset,
        Err(e) => {
            println!("{e:?}");
            return CedarExitCode::Failure;
        }
    };

    let schema = match args.schema.get_schema() {
        Ok(schema) => schema,
        Err(e) => {
            println!("{e:?}");
            return CedarExitCode::Failure;
        }
    };

    let validator = Validator::new(schema);

    let result = if let Some(level) = args.level {
        validator.validate_with_level(&pset, mode, level)
    } else {
        validator.validate(&pset, mode)
    };

    if !result.validation_passed()
        || (args.deny_warnings && !result.validation_passed_without_warnings())
    {
        println!(
            "{:?}",
            Report::new(result).wrap_err("policy set validation failed")
        );
        CedarExitCode::ValidationFailure
    } else {
        println!(
            "{:?}",
            Report::new(result).wrap_err("policy set validation passed")
        );
        CedarExitCode::Success
    }
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
            return (CedarExitCode::Failure, EvalResult::Bool(false));
        }
        Ok(result) => {
            println!("{result}");
            return (CedarExitCode::Success, result);
        }
    }
}

pub fn link(args: &LinkArgs) -> CedarExitCode {
    if let Err(err) = link_inner(args) {
        println!("{err:?}");
        CedarExitCode::Failure
    } else {
        CedarExitCode::Success
    }
}

pub fn visualize(args: &VisualizeArgs) -> CedarExitCode {
    match load_entities(&args.entities_file, None) {
        Ok(entities) => {
            println!("{}", entities.to_dot_str());
            CedarExitCode::Success
        }
        Err(report) => {
            eprintln!("{report:?}");
            CedarExitCode::Failure
        }
    }
}

/// Format the policies in the given file or stdin.
///
/// Returns a boolean indicating whether the formatted policies are the same as the original
/// policies.
fn format_policies_inner(args: &FormatArgs) -> Result<bool> {
    let policies_str = read_from_file_or_stdin(args.policies_file.as_ref(), "policy set")?;
    let config = Config {
        line_width: args.line_width,
        indent_width: args.indent_width,
    };
    let formatted_policy = policies_str_to_pretty(&policies_str, &config)?;
    let are_policies_equivalent = policies_str == formatted_policy;

    match &args.policies_file {
        Some(policies_file) if args.write => {
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(policies_file)
                .into_diagnostic()
                .wrap_err(format!("failed to open {policies_file} for writing"))?;
            file.write_all(formatted_policy.as_bytes())
                .into_diagnostic()
                .wrap_err(format!(
                    "failed to write formatted policies to {policies_file}"
                ))?;
        }
        _ => print!("{formatted_policy}"),
    }
    Ok(are_policies_equivalent)
}

pub fn format_policies(args: &FormatArgs) -> CedarExitCode {
    match format_policies_inner(args) {
        Ok(false) if args.check => CedarExitCode::Failure,
        Err(err) => {
            println!("{err:?}");
            CedarExitCode::Failure
        }
        _ => CedarExitCode::Success,
    }
}

fn translate_policy_to_cedar(
    json_src: Option<impl AsRef<Path> + std::marker::Copy>,
) -> Result<String> {
    let policy_set = read_json_policy_set(json_src)?;
    policy_set.to_cedar().ok_or_else(|| {
        miette!("Unable to translate policy set containing template linked policies.")
    })
}

fn translate_policy_to_json(
    cedar_src: Option<impl AsRef<Path> + std::marker::Copy>,
) -> Result<String> {
    let policy_set = read_cedar_policy_set(cedar_src)?;
    let output = policy_set.to_json()?.to_string();
    Ok(output)
}

fn translate_policy_inner(args: &TranslatePolicyArgs) -> Result<String> {
    let translate = match args.direction {
        PolicyTranslationDirection::CedarToJson => translate_policy_to_json,
        PolicyTranslationDirection::JsonToCedar => translate_policy_to_cedar,
    };
    translate(args.input_file.as_ref())
}

pub fn translate_policy(args: &TranslatePolicyArgs) -> CedarExitCode {
    match translate_policy_inner(args) {
        Ok(sf) => {
            println!("{sf}");
            CedarExitCode::Success
        }
        Err(err) => {
            eprintln!("{err:?}");
            CedarExitCode::Failure
        }
    }
}

fn translate_schema_to_cedar(json_src: impl AsRef<str>) -> Result<String> {
    let fragment = SchemaFragment::from_json_str(json_src.as_ref())?;
    let output = fragment.to_cedarschema()?;
    Ok(output)
}

fn translate_schema_to_json(cedar_src: impl AsRef<str>) -> Result<String> {
    let (fragment, warnings) = SchemaFragment::from_cedarschema_str(cedar_src.as_ref())?;
    for warning in warnings {
        let report = miette::Report::new(warning);
        eprintln!("{report:?}");
    }
    let output = fragment.to_json_string()?;
    Ok(output)
}

fn translate_schema_inner(args: &TranslateSchemaArgs) -> Result<String> {
    let translate = match args.direction {
        SchemaTranslationDirection::JsonToCedar => translate_schema_to_cedar,
        SchemaTranslationDirection::CedarToJson => translate_schema_to_json,
    };
    read_from_file_or_stdin(args.input_file.as_ref(), "schema").and_then(translate)
}

pub fn translate_schema(args: &TranslateSchemaArgs) -> CedarExitCode {
    match translate_schema_inner(args) {
        Ok(sf) => {
            println!("{sf}");
            CedarExitCode::Success
        }
        Err(err) => {
            eprintln!("{err:?}");
            CedarExitCode::Failure
        }
    }
}

/// Write a schema (in JSON format) to `path`
fn generate_schema(path: &Path) -> Result<()> {
    std::fs::write(
        path,
        serde_json::to_string_pretty(&serde_json::json!(
        {
            "": {
                "entityTypes": {
                    "A": {
                        "memberOfTypes": [
                            "B"
                        ]
                    },
                    "B": {
                        "memberOfTypes": []
                    },
                    "C": {
                        "memberOfTypes": []
                    }
                },
                "actions": {
                    "action": {
                        "appliesTo": {
                            "resourceTypes": [
                                "C"
                            ],
                            "principalTypes": [
                                "A",
                                "B"
                            ]
                        }
                    }
                }
            }
        }))
        .into_diagnostic()?,
    )
    .into_diagnostic()
}

fn generate_policy(path: &Path) -> Result<()> {
    std::fs::write(
        path,
        r#"permit (
  principal in A::"a",
  action == Action::"action",
  resource == C::"c"
) when { true };
"#,
    )
    .into_diagnostic()
}

fn generate_entities(path: &Path) -> Result<()> {
    std::fs::write(
        path,
        serde_json::to_string_pretty(&serde_json::json!(
        [
            {
                "uid": { "type": "A", "id": "a"} ,
                "attrs": {},
                "parents": [{"type": "B", "id": "b"}]
            },
            {
                "uid": { "type": "B", "id": "b"} ,
                "attrs": {},
                "parents": []
            },
            {
                "uid": { "type": "C", "id": "c"} ,
                "attrs": {},
                "parents": []
            }
        ]))
        .into_diagnostic()?,
    )
    .into_diagnostic()
}

fn new_inner(args: &NewArgs) -> Result<()> {
    let dir = &std::env::current_dir().into_diagnostic()?.join(&args.name);
    std::fs::create_dir(dir).into_diagnostic()?;
    let schema_path = dir.join("schema.cedarschema.json");
    let policy_path = dir.join("policy.cedar");
    let entities_path = dir.join("entities.json");
    generate_schema(&schema_path)?;
    generate_policy(&policy_path)?;
    generate_entities(&entities_path)
}

pub fn new(args: &NewArgs) -> CedarExitCode {
    if let Err(err) = new_inner(args) {
        println!("{err:?}");
        CedarExitCode::Failure
    } else {
        CedarExitCode::Success
    }
}

pub fn language_version() -> CedarExitCode {
    let version = get_lang_version();
    println!(
        "Cedar language version: {}.{}",
        version.major, version.minor
    );
    CedarExitCode::Success
}

fn create_slot_env(data: &HashMap<SlotId, String>) -> Result<HashMap<SlotId, EntityUid>> {
    data.iter()
        .map(|(key, value)| Ok(EntityUid::from_str(value).map(|euid| (key.clone(), euid))?))
        .collect::<Result<HashMap<SlotId, EntityUid>>>()
}

fn link_inner(args: &LinkArgs) -> Result<()> {
    let mut policies = args.policies.get_policy_set()?;
    let slotenv = create_slot_env(&args.arguments.data)?;
    policies.link(
        PolicyId::new(&args.template_id),
        PolicyId::new(&args.new_id),
        slotenv,
    )?;
    let linked = policies
        .policy(&PolicyId::new(&args.new_id))
        .ok_or_else(|| miette!("Failed to find newly-added template-linked policy"))?;
    println!("Template-linked policy added: {linked}");

    // If a `--template-linked` / `-k` option was provided, update that file with the new link
    if let Some(links_filename) = args.policies.template_linked_file.as_ref() {
        update_template_linked_file(
            links_filename,
            TemplateLinked {
                template_id: args.template_id.clone(),
                link_id: args.new_id.clone(),
                args: args.arguments.data.clone(),
            },
        )?;
    }

    Ok(())
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(try_from = "LiteralTemplateLinked")]
#[serde(into = "LiteralTemplateLinked")]
struct TemplateLinked {
    template_id: String,
    link_id: String,
    args: HashMap<SlotId, String>,
}

impl TryFrom<LiteralTemplateLinked> for TemplateLinked {
    type Error = String;

    fn try_from(value: LiteralTemplateLinked) -> Result<Self, Self::Error> {
        Ok(Self {
            template_id: value.template_id,
            link_id: value.link_id,
            args: value
                .args
                .into_iter()
                .map(|(k, v)| parse_slot_id(k).map(|slot_id| (slot_id, v)))
                .collect::<Result<HashMap<SlotId, String>, Self::Error>>()?,
        })
    }
}

fn parse_slot_id<S: AsRef<str>>(s: S) -> Result<SlotId, String> {
    match s.as_ref() {
        "?principal" => Ok(SlotId::principal()),
        "?resource" => Ok(SlotId::resource()),
        _ => Err(format!(
            "Invalid SlotId! Expected ?principal|?resource, got: {}",
            s.as_ref()
        )),
    }
}

#[derive(Serialize, Deserialize)]
struct LiteralTemplateLinked {
    template_id: String,
    link_id: String,
    args: HashMap<String, String>,
}

impl From<TemplateLinked> for LiteralTemplateLinked {
    fn from(i: TemplateLinked) -> Self {
        Self {
            template_id: i.template_id,
            link_id: i.link_id,
            args: i
                .args
                .into_iter()
                .map(|(k, v)| (format!("{k}"), v))
                .collect(),
        }
    }
}

/// Iterate over links in the template-linked file and add them to the set
fn add_template_links_to_set(path: impl AsRef<Path>, policy_set: &mut PolicySet) -> Result<()> {
    for template_linked in load_links_from_file(path)? {
        let slot_env = create_slot_env(&template_linked.args)?;
        policy_set.link(
            PolicyId::new(&template_linked.template_id),
            PolicyId::new(&template_linked.link_id),
            slot_env,
        )?;
    }
    Ok(())
}

/// Given a file containing template links, return a `Vec` of those links
fn load_links_from_file(path: impl AsRef<Path>) -> Result<Vec<TemplateLinked>> {
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => {
            // If the file doesn't exist, then give back the empty entity set
            return Ok(vec![]);
        }
    };
    if f.metadata()
        .into_diagnostic()
        .wrap_err("Failed to read metadata")?
        .len()
        == 0
    {
        // File is empty, return empty set
        Ok(vec![])
    } else {
        // File has contents, deserialize
        serde_json::from_reader(f)
            .into_diagnostic()
            .wrap_err("Deserialization error")
    }
}

/// Add a single template-linked policy to the linked file
fn update_template_linked_file(path: impl AsRef<Path>, new_linked: TemplateLinked) -> Result<()> {
    let mut template_linked = load_links_from_file(path.as_ref())?;
    template_linked.push(new_linked);
    write_template_linked_file(&template_linked, path.as_ref())
}

/// Write a slice of template-linked policies to the linked file
fn write_template_linked_file(linked: &[TemplateLinked], path: impl AsRef<Path>) -> Result<()> {
    let f = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(path)
        .into_diagnostic()?;
    serde_json::to_writer(f, linked).into_diagnostic()
}

pub fn authorize(args: &AuthorizeArgs) -> CedarExitCode {
    println!();
    let ans = execute_request(
        &args.request,
        &args.policies,
        &args.entities_file,
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

#[cfg(not(feature = "partial-eval"))]
pub fn partial_authorize(_: &PartiallyAuthorizeArgs) -> CedarExitCode {
    {
        eprintln!("Error: option `partially-authorize` is experimental, but this executable was not built with `partial-eval` experimental feature enabled");
        return CedarExitCode::Failure;
    }
}

#[cfg(feature = "partial-eval")]
pub fn partial_authorize(args: &PartiallyAuthorizeArgs) -> CedarExitCode {
    println!();
    let ans = execute_partial_request(
        &args.request,
        &args.policies,
        &args.entities_file,
        &args.schema,
        args.timing,
    );
    match ans {
        Ok(ans) => match ans.decision() {
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
                for p in ans.nontrivial_residuals() {
                    println!("{p}");
                }
                CedarExitCode::Unknown
            }
        },
        Err(errs) => {
            for err in errs {
                println!("{err:?}");
            }
            CedarExitCode::Failure
        }
    }
}

#[derive(Clone, Debug)]
enum TestResult {
    Pass,
    Fail(String),
}

/// Compare the test's expected decision against the actual decision
fn compare_test_decisions(test: &TestCase, ans: &Response) -> TestResult {
    if ans.decision() == test.decision.into() {
        let mut errors = Vec::new();
        let reason = ans.diagnostics().reason().collect::<BTreeSet<_>>();

        // Check that the declared reason is a subset of the actual reason
        let missing_reason = test
            .reason
            .iter()
            .filter(|r| !reason.contains(&PolicyId::new(r)))
            .collect::<Vec<_>>();

        if !missing_reason.is_empty() {
            errors.push(format!(
                "missing reason(s): {}",
                missing_reason
                    .into_iter()
                    .map(|r| format!("`{r}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        // Check that evaluation errors are expected
        let num_errors = ans.diagnostics().errors().count();
        if num_errors != test.num_errors {
            errors.push(format!(
                "expected {} error(s), but got {} runtime error(s){}",
                test.num_errors,
                num_errors,
                if num_errors == 0 {
                    "".to_string()
                } else {
                    format!(
                        ": {}",
                        ans.diagnostics()
                            .errors()
                            .map(|e| e.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                },
            ));
        }

        if errors.is_empty() {
            TestResult::Pass
        } else {
            TestResult::Fail(errors.join("; "))
        }
    } else {
        TestResult::Fail(format!(
            "expected {:?}, got {:?}",
            test.decision,
            ans.decision()
        ))
    }
}

/// Parse the test, validate against schema,
/// and then check the authorization decision
fn run_one_test(policies: &PolicySet, test: &serde_json::Value) -> Result<TestResult> {
    let test = TestCase::deserialize(test.clone()).into_diagnostic()?;
    let ans = Authorizer::new().is_authorized(&test.request, policies, &test.entities);
    Ok(compare_test_decisions(&test, &ans))
}

fn run_tests_inner(args: &RunTestsArgs) -> Result<CedarExitCode> {
    let policies = args.policies.get_policy_set()?;
    let tests = load_partial_tests(&args.tests)?;

    let mut total_fails: usize = 0;

    println!("running {} test(s)", tests.len());
    for test in tests.iter() {
        if let Some(name) = test["name"].as_str() {
            print!("  test {name} ... ");
        } else {
            print!("  test (unamed) ... ");
        }
        std::io::stdout().flush().into_diagnostic()?;

        match run_one_test(&policies, test) {
            Ok(TestResult::Pass) => {
                println!(
                    "{}",
                    "ok".if_supports_color(owo_colors::Stream::Stdout, |s| s.green())
                );
            }
            Ok(TestResult::Fail(reason)) => {
                total_fails += 1;
                println!(
                    "{}: {}",
                    "fail".if_supports_color(owo_colors::Stream::Stdout, |s| s.red()),
                    reason
                );
            }
            Err(e) => {
                total_fails += 1;
                println!(
                    "{}:\n  {:?}",
                    "error".if_supports_color(owo_colors::Stream::Stdout, |s| s.red()),
                    e
                );
            }
        }
    }

    println!(
        "results: {} {}, {} {}",
        tests.len() - total_fails,
        if total_fails == 0 {
            "passed"
                .if_supports_color(owo_colors::Stream::Stdout, |s| s.green())
                .to_string()
        } else {
            "passed".to_string()
        },
        total_fails,
        if total_fails != 0 {
            "failed"
                .if_supports_color(owo_colors::Stream::Stdout, |s| s.red())
                .to_string()
        } else {
            "failed".to_string()
        },
    );

    Ok(if total_fails != 0 {
        CedarExitCode::Failure
    } else {
        CedarExitCode::Success
    })
}

pub fn run_tests(args: &RunTestsArgs) -> CedarExitCode {
    match run_tests_inner(args) {
        Ok(status) => status,
        Err(e) => {
            println!("{e:?}");
            CedarExitCode::Failure
        }
    }
}

#[derive(Copy, Clone, Debug, Deserialize)]
enum ExpectedDecision {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "deny")]
    Deny,
}

impl From<ExpectedDecision> for Decision {
    fn from(value: ExpectedDecision) -> Self {
        match value {
            ExpectedDecision::Allow => Decision::Allow,
            ExpectedDecision::Deny => Decision::Deny,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct TestCase {
    #[serde(deserialize_with = "deserialize_request")]
    request: Request,
    #[serde(deserialize_with = "deserialize_entities")]
    entities: Entities,
    decision: ExpectedDecision,
    reason: Vec<String>,
    num_errors: usize,
}

/// Helper function to deserialize a `Request` from JSON (without schema)
fn deserialize_request<'de, D>(data: D) -> Result<Request, D::Error>
where
    D: Deserializer<'de>,
{
    let qjson = RequestJSON::deserialize(data)?;

    let principal = qjson.principal.parse().map_err(|e| {
        serde::de::Error::custom(format!(
            "failed to parse principal `{}`: {}",
            qjson.principal, e
        ))
    })?;

    let action = qjson.action.parse().map_err(|e| {
        serde::de::Error::custom(format!("failed to parse action `{}`: {}", qjson.action, e))
    })?;

    let resource = qjson.resource.parse().map_err(|e| {
        serde::de::Error::custom(format!(
            "failed to parse resource `{}`: {}",
            qjson.resource, e
        ))
    })?;

    let context = Context::from_json_value(qjson.context.clone(), None).map_err(|e| {
        serde::de::Error::custom(format!(
            "failed to parse context `{}`: {}",
            qjson.context, e
        ))
    })?;

    Request::new(principal, action, resource, context, None)
        .map_err(|e| serde::de::Error::custom(format!("failed to create request: {e}")))
}

/// Helper function to deserialize an `Entities` from JSON (without schema)
fn deserialize_entities<'de, D>(data: D) -> Result<Entities, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(data)?;
    Entities::from_json_value(value, None)
        .map_err(|e| serde::de::Error::custom(format!("failed to parse entities: {e}")))
}

#[derive(Error, Diagnostic, Debug)]
enum TestCaseError {
    #[error("error when parsing JSON")]
    JsonParseError(#[from] serde_json::Error),
    #[error("error when parsing entity UID")]
    EntityUidParseError(#[from] ParseErrors),
    #[error("error when parsing context JSON")]
    ContextJsonError(#[from] ContextJsonError),
    #[error("error when validating request against schema")]
    RequestValidationError(#[from] RequestValidationError),
    #[error("error when parsing entities")]
    EntitiesError(#[from] EntitiesError),
}

/// Load partially parsed tests from a JSON file
/// (as JSON values first without parsing to TestCase)
fn load_partial_tests(tests_filename: impl AsRef<Path>) -> Result<Vec<serde_json::Value>> {
    match std::fs::OpenOptions::new()
        .read(true)
        .open(tests_filename.as_ref())
    {
        Ok(f) => {
            let reader = BufReader::new(f);
            serde_json::from_reader(reader).map_err(|e| {
                miette!(
                    "failed to parse tests from file {}: {e}",
                    tests_filename.as_ref().display()
                )
            })
        }
        Err(e) => Err(e).into_diagnostic().wrap_err_with(|| {
            format!(
                "failed to open test file {}",
                tests_filename.as_ref().display()
            )
        }),
    }
}

/// Load an `Entities` object from the given JSON filename and optional schema.
fn load_entities(entities_filename: impl AsRef<Path>, schema: Option<&Schema>) -> Result<Entities> {
    match std::fs::OpenOptions::new()
        .read(true)
        .open(entities_filename.as_ref())
    {
        Ok(f) => Entities::from_json_file(f, schema).wrap_err_with(|| {
            format!(
                "failed to parse entities from file {}",
                entities_filename.as_ref().display()
            )
        }),
        Err(e) => Err(e).into_diagnostic().wrap_err_with(|| {
            format!(
                "failed to open entities file {}",
                entities_filename.as_ref().display()
            )
        }),
    }
}

/// Renames policies and templates based on (@id("new_id") annotation.
/// If no such annotation exists, it keeps the current id.
///
/// This will rename template-linked policies to the id of their template, which may
/// cause id conflicts, so only call this function before instancing
/// templates into the policy set.
fn rename_from_id_annotation(ps: &PolicySet) -> Result<PolicySet> {
    let mut new_ps = PolicySet::new();
    let t_iter = ps.templates().map(|t| match t.annotation("id") {
        None => Ok(t.clone()),
        Some(anno) => anno.parse().map(|a| t.new_id(a)),
    });
    for t in t_iter {
        let template = t.unwrap_or_else(|never| match never {});
        new_ps
            .add_template(template)
            .wrap_err("failed to add template to policy set")?;
    }
    let p_iter = ps.policies().map(|p| match p.annotation("id") {
        None => Ok(p.clone()),
        Some(anno) => anno.parse().map(|a| p.new_id(a)),
    });
    for p in p_iter {
        let policy = p.unwrap_or_else(|never| match never {});
        new_ps
            .add(policy)
            .wrap_err("failed to add template to policy set")?;
    }
    Ok(new_ps)
}

// Read from a file (when `filename` is a `Some`) or stdin (when `filename` is `None`) to a `String`
fn read_from_file_or_stdin(filename: Option<&impl AsRef<Path>>, context: &str) -> Result<String> {
    let mut src_str = String::new();
    match filename {
        Some(path) => {
            src_str = std::fs::read_to_string(path)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!("failed to open {context} file {}", path.as_ref().display())
                })?;
        }
        None => {
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut src_str)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read {context} from stdin"))?;
        }
    };
    Ok(src_str)
}

// Convenient wrapper around `read_from_file_or_stdin` to just read from a file
fn read_from_file(filename: impl AsRef<Path>, context: &str) -> Result<String> {
    read_from_file_or_stdin(Some(&filename), context)
}

/// Read a policy set, in Cedar syntax, from the file given in `filename`,
/// or from stdin if `filename` is `None`.
fn read_cedar_policy_set(
    filename: Option<impl AsRef<Path> + std::marker::Copy>,
) -> Result<PolicySet> {
    let context = "policy set";
    let ps_str = read_from_file_or_stdin(filename.as_ref(), context)?;
    let ps = PolicySet::from_str(&ps_str)
        .map_err(|err| {
            let name = filename.map_or_else(
                || "<stdin>".to_owned(),
                |n| n.as_ref().display().to_string(),
            );
            Report::new(err).with_source_code(NamedSource::new(name, ps_str))
        })
        .wrap_err_with(|| format!("failed to parse {context}"))?;
    rename_from_id_annotation(&ps)
}

/// Read a policy set, static policy or policy template, in Cedar JSON (EST) syntax, from the file given
/// in `filename`, or from stdin if `filename` is `None`.
fn read_json_policy_set(
    filename: Option<impl AsRef<Path> + std::marker::Copy>,
) -> Result<PolicySet> {
    let context = "JSON policy";
    let json_source = read_from_file_or_stdin(filename.as_ref(), context)?;
    let json = serde_json::from_str::<serde_json::Value>(&json_source).into_diagnostic()?;
    let policy_type = get_json_policy_type(&json)?;

    let add_json_source = |report: Report| {
        let name = filename.map_or_else(
            || "<stdin>".to_owned(),
            |n| n.as_ref().display().to_string(),
        );
        report.with_source_code(NamedSource::new(name, json_source.clone()))
    };

    match policy_type {
        JsonPolicyType::SinglePolicy => match Policy::from_json(None, json.clone()) {
            Ok(policy) => PolicySet::from_policies([policy])
                .wrap_err_with(|| format!("failed to create policy set from {context}")),
            Err(_) => match Template::from_json(None, json)
                .map_err(|err| add_json_source(Report::new(err)))
            {
                Ok(template) => {
                    let mut ps = PolicySet::new();
                    ps.add_template(template)?;
                    Ok(ps)
                }
                Err(err) => Err(err).wrap_err_with(|| format!("failed to parse {context}")),
            },
        },
        JsonPolicyType::PolicySet => PolicySet::from_json_value(json)
            .map_err(|err| add_json_source(Report::new(err)))
            .wrap_err_with(|| format!("failed to create policy set from {context}")),
    }
}

fn get_json_policy_type(json: &serde_json::Value) -> Result<JsonPolicyType> {
    let policy_set_properties = ["staticPolicies", "templates", "templateLinks"];
    let policy_properties = ["action", "effect", "principal", "resource", "conditions"];

    let json_has_property = |p| json.get(p).is_some();
    let has_any_policy_set_property = policy_set_properties.iter().any(json_has_property);
    let has_any_policy_property = policy_properties.iter().any(json_has_property);

    match (has_any_policy_set_property, has_any_policy_property) {
        (false, false) => Err(miette!("cannot determine if json policy is a single policy or a policy set. Found no matching properties from either format")),
        (true, true) => Err(miette!("cannot determine if json policy is a single policy or a policy set. Found matching properties from both formats")),
        (true, _) => Ok(JsonPolicyType::PolicySet),
        (_, true) => Ok(JsonPolicyType::SinglePolicy),
    }
}

enum JsonPolicyType {
    SinglePolicy,
    PolicySet,
}

/// This uses the Cedar API to call the authorization engine.
fn execute_request(
    request: &RequestArgs,
    policies: &PoliciesArgs,
    entities_filename: impl AsRef<Path>,
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
    let entities = match load_entities(entities_filename, schema.as_ref()) {
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

#[cfg(feature = "partial-eval")]
fn execute_partial_request(
    request: &PartialRequestArgs,
    policies: &PoliciesArgs,
    entities_filename: impl AsRef<Path>,
    schema: &OptionalSchemaArgs,
    compute_duration: bool,
) -> Result<PartialResponse, Vec<Report>> {
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
    let entities = match load_entities(entities_filename, schema.as_ref()) {
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
            let ans = authorizer.is_authorized_partial(&request, &policies, &entities);
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
