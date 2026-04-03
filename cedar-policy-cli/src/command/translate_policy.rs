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

use std::path::Path;

use clap::Args;
use miette::Result;

use crate::{read_cedar_policy_set, read_json_policy_set, CedarExitCode};

/// The direction of translation
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum PolicyTranslationDirection {
    /// Cedar policy syntax -> JSON
    CedarToJson,
    /// JSON -> Cedar policy syntax
    JsonToCedar,
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

fn translate_policy_inner(args: &TranslatePolicyArgs) -> Result<String> {
    let translate = match args.direction {
        PolicyTranslationDirection::CedarToJson => translate_policy_to_json,
        PolicyTranslationDirection::JsonToCedar => translate_policy_to_cedar,
    };
    translate(args.input_file.as_ref())
}

fn translate_policy_to_cedar(
    json_src: Option<impl AsRef<Path> + std::marker::Copy>,
) -> Result<String> {
    use miette::miette;
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
