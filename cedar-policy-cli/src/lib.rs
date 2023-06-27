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

// This modules makes use of `return` to exit early with a particular exit code.
// For consistency, it also uses `return` in some places where it could be
// omitted.
#![allow(clippy::needless_return)]

use clap::{Args, Parser, Subcommand};
use miette::{miette, IntoDiagnostic, NamedSource, Report, Result, WrapErr};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    path::Path,
    process::{ExitCode, Termination},
    str::FromStr,
    time::Instant,
};

use cedar_policy::*;
use cedar_policy_formatter::{policies_str_to_pretty, Config};

/// Basic Cedar CLI for evaluating authorization queries
#[derive(Parser)]
#[command(author, version, about, long_about = None)] // Pull from `Cargo.toml`
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Evaluate an authorization request
    Authorize(AuthorizeArgs),
    /// Evaluate a Cedar expression
    Evaluate(EvaluateArgs),
    /// Validate a policy set against a schema
    Validate(ValidateArgs),
    /// Check that policies successfully parse
    CheckParse(CheckParseArgs),
    /// Link a template
    Link(LinkArgs),
    /// Format a policy set
    Format(FormatArgs),
}

#[derive(Args, Debug)]
pub struct ValidateArgs {
    /// File containing the schema
    #[arg(short, long = "schema", value_name = "FILE")]
    pub schema_file: String,
    /// File containing the policy set
    #[arg(short, long = "policies", value_name = "FILE")]
    pub policies_file: String,
}

#[derive(Args, Debug)]
pub struct CheckParseArgs {
    /// File containing the policy set
    #[clap(short, long = "policies", value_name = "FILE")]
    pub policies_file: Option<String>,
}

/// This struct contains the arguments that together specify a request.
#[derive(Args, Debug)]
pub struct RequestArgs {
    /// Principal for the request, e.g., User::"alice"
    #[arg(short, long)]
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
    fn get_request(&self, schema: Option<&Schema>) -> Result<Request> {
        match &self.request_json_file {
            Some(jsonfile) => {
                let jsonstring = std::fs::read_to_string(jsonfile)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to open request-json file {jsonfile}"))?;
                let qjson: RequestJSON = serde_json::from_str(&jsonstring)
                    .into_diagnostic()
                    .context(format!("failed to parse request-json file {jsonfile}"))?;
                let principal = qjson
                    .principal
                    .map(|s| {
                        s.parse().context(format!(
                            "failed to parse principal in {jsonfile} as entity Uid"
                        ))
                    })
                    .transpose()?;
                let action = qjson
                    .action
                    .map(|s| {
                        s.parse().context(format!(
                            "failed to parse action in {jsonfile} as entity Uid"
                        ))
                    })
                    .transpose()?;
                let resource = qjson
                    .resource
                    .map(|s| {
                        s.parse().context(format!(
                            "failed to parse resource in {jsonfile} as entity Uid"
                        ))
                    })
                    .transpose()?;
                let context = Context::from_json_value(
                    qjson.context,
                    schema.and_then(|s| Some((s, action.as_ref()?))),
                )
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to create a context from {jsonfile}"))?;
                Ok(Request::new(principal, action, resource, context))
            }
            None => {
                let principal = self
                    .principal
                    .as_ref()
                    .map(|s| {
                        s.parse()
                            .context(format!("failed to parse principal {s} as entity Uid"))
                    })
                    .transpose()?;
                let action = self
                    .action
                    .as_ref()
                    .map(|s| {
                        s.parse()
                            .context(format!("failed to parse action {s} as entity Uid"))
                    })
                    .transpose()?;
                let resource = self
                    .resource
                    .as_ref()
                    .map(|s| {
                        s.parse()
                            .context(format!("failed to parse resource {s} as entity Uid"))
                    })
                    .transpose()?;
                let context: Context = match &self.context_json_file {
                    None => Context::empty(),
                    Some(jsonfile) => match std::fs::OpenOptions::new().read(true).open(jsonfile) {
                        Ok(f) => Context::from_json_file(
                            f,
                            schema.and_then(|s| Some((s, action.as_ref()?))),
                        )
                        .into_diagnostic()
                        .wrap_err_with(|| format!("failed to create a context from {jsonfile}"))?,
                        Err(e) => Err(e).into_diagnostic().wrap_err_with(|| {
                            format!("error while loading context from {jsonfile}")
                        })?,
                    },
                };
                Ok(Request::new(principal, action, resource, context))
            }
        }
    }
}

#[derive(Args, Debug)]
pub struct AuthorizeArgs {
    /// Request args (incorporated by reference)
    #[command(flatten)]
    pub request: RequestArgs,
    /// File containing the static Cedar policies and templates to evaluate against
    #[arg(long = "policies", value_name = "FILE")]
    pub policies_file: String,
    /// File containing template linked policies
    #[arg(long = "template-linked", value_name = "FILE")]
    pub template_linked_file: Option<String>,
    /// File containing schema information
    /// Used to populate the store with action entities and for schema-based
    /// parsing of entity hierarchy, if present
    #[arg(long = "schema", value_name = "FILE")]
    pub schema_file: Option<String>,
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

#[derive(Args, Debug)]
pub struct LinkArgs {
    /// File containing static policies and templates.
    #[arg(short, long)]
    pub policies_file: String,
    /// File containing template-linked policies
    #[arg(short, long)]
    pub template_linked_file: String,
    /// Id of the template to instantiate
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
    /// Optional policy file name. If none is provided, read input from stdin.
    #[arg(value_name = "FILE")]
    pub file_name: Option<String>,

    /// Custom line width (default: 80).
    #[arg(short, long, value_name = "UINT", default_value_t = 80)]
    pub line_width: usize,

    /// Custom indentation width (default: 2).
    #[arg(short, long, value_name = "INT", default_value_t = 2)]
    pub indent_width: isize,
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
#[derive(Deserialize)]
struct RequestJSON {
    /// Principal for the request
    #[serde(default)]
    principal: Option<String>,
    /// Action for the request
    #[serde(default)]
    action: Option<String>,
    /// Resource for the request
    #[serde(default)]
    resource: Option<String>,
    /// Context for the request
    context: serde_json::Value,
}

#[derive(Args, Debug)]
pub struct EvaluateArgs {
    /// Request args (incorporated by reference)
    #[command(flatten)]
    pub request: RequestArgs,
    /// File containing schema information
    /// Used to populate the store with action entities and for schema-based
    /// parsing of entity hierarchy, if present
    #[arg(long = "schema", value_name = "FILE")]
    pub schema_file: Option<String>,
    /// File containing JSON representation of the Cedar entity hierarchy.
    /// This is optional; if not present, we'll just use an empty hierarchy.
    #[arg(long = "entities", value_name = "FILE")]
    pub entities_file: Option<String>,
    /// Expression to evaluate
    #[arg(value_name = "EXPRESSION")]
    pub expression: String,
}

#[derive(Eq, PartialEq, Debug)]
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
}

impl Termination for CedarExitCode {
    fn report(self) -> ExitCode {
        match self {
            CedarExitCode::Success => ExitCode::SUCCESS,
            CedarExitCode::Failure => ExitCode::FAILURE,
            CedarExitCode::AuthorizeDeny => ExitCode::from(2),
            CedarExitCode::ValidationFailure => ExitCode::from(3),
        }
    }
}

pub fn check_parse(args: &CheckParseArgs) -> CedarExitCode {
    match read_policy_set(args.policies_file.as_ref()) {
        Ok(_) => CedarExitCode::Success,
        Err(e) => {
            println!("{:?}", e);
            CedarExitCode::Failure
        }
    }
}

pub fn validate(args: &ValidateArgs) -> CedarExitCode {
    let pset = match read_policy_set(Some(&args.policies_file)) {
        Ok(pset) => pset,
        Err(e) => {
            println!("{:#}", e);
            return CedarExitCode::Failure;
        }
    };

    let schema = match read_schema_file(&args.schema_file) {
        Ok(schema) => schema,
        Err(e) => {
            println!("{:#}", e);
            return CedarExitCode::Failure;
        }
    };

    let validator = Validator::new(schema);
    let result = validator.validate(&pset, ValidationMode::default());
    if result.validation_passed() {
        println!("Validation Passed");
        return CedarExitCode::Success;
    } else {
        println!("Validation Results:");
        for note in result.validation_errors() {
            println!("{}", note);
        }
        return CedarExitCode::ValidationFailure;
    }
}

pub fn evaluate(args: &EvaluateArgs) -> (CedarExitCode, EvalResult) {
    println!();
    let schema = match args.schema_file.as_ref().map(read_schema_file) {
        None => None,
        Some(Ok(schema)) => Some(schema),
        Some(Err(e)) => {
            println!("{:#}", e);
            return (CedarExitCode::Failure, EvalResult::Bool(false));
        }
    };
    let request = match args.request.get_request(schema.as_ref()) {
        Ok(q) => q,
        Err(e) => {
            println!("error: {:#}", e);
            return (CedarExitCode::Failure, EvalResult::Bool(false));
        }
    };
    let expr = match Expression::from_str(&args.expression) {
        Ok(expr) => expr,
        Err(e) => {
            println!("error while parsing the expression: {e}");
            return (CedarExitCode::Failure, EvalResult::Bool(false));
        }
    };
    let entities = match &args.entities_file {
        None => Entities::empty(),
        Some(file) => match load_entities(file, schema.as_ref()) {
            Ok(entities) => entities,
            Err(e) => {
                println!("error: {:#}", e);
                return (CedarExitCode::Failure, EvalResult::Bool(false));
            }
        },
    };
    let entities = match load_actions_from_schema(entities, &schema) {
        Ok(entities) => entities,
        Err(e) => {
            println!("error: {:#}", e);
            return (CedarExitCode::Failure, EvalResult::Bool(false));
        }
    };
    match eval_expression(&request, &entities, &expr) {
        Err(e) => {
            println!("error while evaluating the expression: {e}");
            return (CedarExitCode::Failure, EvalResult::Bool(false));
        }
        Ok(result) => {
            println!("{result}");
            return (CedarExitCode::Success, result);
        }
    }
}

pub fn link(args: &LinkArgs) -> CedarExitCode {
    if let Err(msg) = link_inner(args) {
        eprintln!("{:#}", msg);
        CedarExitCode::Failure
    } else {
        CedarExitCode::Success
    }
}

fn format_policies_inner(args: &FormatArgs) -> Result<()> {
    let policies_str = read_from_file_or_stdin(args.file_name.as_ref(), "policy set")?;
    let config = Config {
        line_width: args.line_width,
        indent_width: args.indent_width,
    };
    println!("{}", policies_str_to_pretty(&policies_str, &config)?);
    Ok(())
}

pub fn format_policies(args: &FormatArgs) -> CedarExitCode {
    if let Err(msg) = format_policies_inner(args) {
        eprintln!("{:#}", msg);
        CedarExitCode::Failure
    } else {
        CedarExitCode::Success
    }
}

fn create_slot_env(data: &HashMap<SlotId, String>) -> Result<HashMap<SlotId, EntityUid>> {
    data.iter()
        .map(|(key, value)| Ok(EntityUid::from_str(value).map(|euid| (key.clone(), euid))?))
        .collect::<Result<HashMap<SlotId, EntityUid>>>()
}

fn link_inner(args: &LinkArgs) -> Result<()> {
    let mut policies = read_policy_set(Some(&args.policies_file))?;
    let slotenv = create_slot_env(&args.arguments.data)?;
    policies
        .link(
            PolicyId::from_str(&args.template_id)?,
            PolicyId::from_str(&args.new_id)?,
            slotenv,
        )
        .into_diagnostic()?;
    let linked = policies
        .policy(&PolicyId::from_str(&args.new_id)?)
        .ok_or_else(|| miette!("Failed to add template-linked policy"))?;
    println!("Template Linked Policy Added: {linked}");
    let linked = TemplateLinked {
        template_id: args.template_id.clone(),
        link_id: args.new_id.clone(),
        args: args.arguments.data.clone(),
    };

    update_template_linked_file(&args.template_linked_file, linked)
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
    for template_linked in load_liked_file(path)? {
        let slot_env = create_slot_env(&template_linked.args)?;
        policy_set
            .link(
                PolicyId::from_str(&template_linked.template_id)?,
                PolicyId::from_str(&template_linked.link_id)?,
                slot_env,
            )
            .into_diagnostic()?;
    }
    Ok(())
}

/// Read template linked set to a Vec
fn load_liked_file(path: impl AsRef<Path>) -> Result<Vec<TemplateLinked>> {
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
    let mut template_linked = load_liked_file(path.as_ref())?;
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
    Ok(serde_json::to_writer(f, linked).into_diagnostic()?)
}

pub fn authorize(args: &AuthorizeArgs) -> CedarExitCode {
    println!();
    let ans = execute_request(
        &args.request,
        &args.policies_file,
        args.template_linked_file.as_ref(),
        &args.entities_file,
        args.schema_file.as_ref(),
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
                    println!("{}", err);
                }
            }
            if args.verbose {
                println!();
                if ans.diagnostics().reason().peekable().peek().is_none() {
                    println!("note: no policies applied to this request");
                } else {
                    println!("note: this decision was due to the following policies:");
                    for reason in ans.diagnostics().reason() {
                        println!("  {}", reason);
                    }
                    println!();
                }
            }
            status
        }
        Err(errs) => {
            for err in errs {
                println!("{:#}", err);
            }
            CedarExitCode::Failure
        }
    }
}

/// Load an `Entities` object from the given JSON filename and optional schema.
fn load_entities(entities_filename: impl AsRef<Path>, schema: Option<&Schema>) -> Result<Entities> {
    match std::fs::OpenOptions::new()
        .read(true)
        .open(entities_filename.as_ref())
    {
        Ok(f) => Entities::from_json_file(f, schema)
            .into_diagnostic()
            .wrap_err_with(|| {
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
fn rename_from_id_annotation(ps: PolicySet) -> PolicySet {
    let mut new_ps = PolicySet::new();
    let t_iter = ps.templates().map(|t| match t.annotation("id") {
        None => t.clone(),
        Some(anno) => t.new_id(anno.parse().expect("id annotation should be valid id")),
    });
    for t in t_iter {
        new_ps.add_template(t).expect("should still be a template");
    }
    let p_iter = ps.policies().map(|p| match p.annotation("id") {
        None => p.clone(),
        Some(anno) => p.new_id(anno.parse().expect("id annotation should be valid id")),
    });
    for p in p_iter {
        new_ps.add(p).expect("should still be a policy");
    }
    new_ps
}

fn read_policy_and_links(
    policies_filename: impl AsRef<Path>,
    links_filename: Option<impl AsRef<Path>>,
) -> Result<PolicySet> {
    let mut pset = read_policy_set(Some(policies_filename.as_ref()))?;
    if let Some(links_filename) = links_filename {
        add_template_links_to_set(links_filename.as_ref(), &mut pset)?;
    }
    Ok(pset)
}

// Read from a file (when `filename` is a `Some`) or stdin (when `filename` is `None`)
fn read_from_file_or_stdin(filename: Option<impl AsRef<Path>>, context: &str) -> Result<String> {
    let mut src_str = String::new();
    match filename.as_ref() {
        Some(path) => {
            src_str = std::fs::read_to_string(path)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to open {} file {}",
                        context,
                        path.as_ref().display()
                    )
                })?;
        }
        None => {
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut src_str)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read {} from stdin", context))?;
        }
    };
    Ok(src_str)
}

// Convenient wrapper around `read_from_file_or_stdin` to just read from a file
fn read_from_file(filename: impl AsRef<Path>, context: &str) -> Result<String> {
    read_from_file_or_stdin(Some(filename), context)
}

fn read_policy_set(
    filename: Option<impl AsRef<Path> + std::marker::Copy>,
) -> miette::Result<PolicySet> {
    let context = "policy set";
    let ps_str = read_from_file_or_stdin(filename, context)?;
    let ps = PolicySet::from_str(&ps_str)
        .map_err(|err| {
            let name = filename.map_or_else(
                || "<stdin>".to_owned(),
                |n| n.as_ref().display().to_string(),
            );
            Report::from(err).with_source_code(NamedSource::new(name, ps_str))
        })
        .wrap_err_with(|| format!("failed to parse {context}"))?;
    Ok(rename_from_id_annotation(ps))
}

fn read_schema_file(filename: impl AsRef<Path> + std::marker::Copy) -> Result<Schema> {
    let schema_src = read_from_file(filename, "schema")?;
    Schema::from_str(&schema_src)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to parse schema from file {}",
                filename.as_ref().display()
            )
        })
}

fn load_actions_from_schema(entities: Entities, schema: &Option<Schema>) -> Result<Entities> {
    match schema {
        Some(schema) => match schema.action_entities() {
            Ok(action_entities) => Entities::from_entities(
                entities
                    .iter()
                    .cloned()
                    .chain(action_entities.iter().cloned()),
            )
            .into_diagnostic()
            .wrap_err("failed to merge action entities with entity file"),
            Err(e) => Err(e)
                .into_diagnostic()
                .wrap_err("failed to construct action entities"),
        },
        None => Ok(entities),
    }
}

/// This uses the Cedar API to call the authorization engine.
fn execute_request(
    request: &RequestArgs,
    policies_filename: impl AsRef<Path> + std::marker::Copy,
    links_filename: Option<impl AsRef<Path>>,
    entities_filename: impl AsRef<Path>,
    schema_filename: Option<impl AsRef<Path> + std::marker::Copy>,
    compute_duration: bool,
) -> Result<Response, Vec<Report>> {
    let mut errs = vec![];
    let policies = match read_policy_and_links(policies_filename.as_ref(), links_filename) {
        Ok(pset) => pset,
        Err(e) => {
            errs.push(e);
            PolicySet::new()
        }
    };
    let schema = match schema_filename.map(read_schema_file) {
        None => None,
        Some(Ok(schema)) => Some(schema),
        Some(Err(e)) => {
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
    let entities = match load_actions_from_schema(entities, &schema) {
        Ok(entities) => entities,
        Err(e) => {
            errs.push(e);
            Entities::empty()
        }
    };
    let request = match request.get_request(schema.as_ref()) {
        Ok(q) => Some(q),
        Err(e) => {
            errs.push(e.context("failed to parse request"));
            None
        }
    };
    if errs.is_empty() {
        let request = request.expect("if errs is empty, we should have a request");
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
    } else {
        Err(errs)
    }
}
