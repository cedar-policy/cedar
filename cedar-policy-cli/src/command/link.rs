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

use std::{collections::HashMap, fs::OpenOptions, path::Path, str::FromStr};

use cedar_policy::{PolicyId, SlotId};
use clap::Args;
use miette::{miette, IntoDiagnostic, Result};
use serde::Deserialize;

use crate::{
    create_slot_env, load_links_from_file, parse_slot_id, CedarExitCode, PoliciesArgs,
    TemplateLinked,
};

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

pub fn link(args: &LinkArgs) -> CedarExitCode {
    if let Err(err) = link_inner(args) {
        println!("{err:?}");
        CedarExitCode::Failure
    } else {
        CedarExitCode::Success
    }
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
