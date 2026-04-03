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

use cedar_policy::SchemaFragment;
use clap::Args;
use miette::{IntoDiagnostic, Result};

use crate::{read_from_file_or_stdin, CedarExitCode};

/// The direction of translation
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum SchemaTranslationDirection {
    /// JSON -> Cedar schema syntax
    JsonToCedar,
    /// Cedar schema syntax -> JSON
    CedarToJson,
    /// Cedar schema syntax -> JSON with all types resolved to entity or common.
    ///
    /// In contrast to `cedar-to-json`, this option requires that every type
    /// referenced in the schema is also defined.
    CedarToJsonWithResolvedTypes,
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

fn translate_schema_inner(args: &TranslateSchemaArgs) -> Result<String> {
    let translate = match args.direction {
        SchemaTranslationDirection::JsonToCedar => translate_schema_to_cedar,
        SchemaTranslationDirection::CedarToJson => translate_schema_to_json,
        SchemaTranslationDirection::CedarToJsonWithResolvedTypes => {
            translate_schema_to_json_with_resolved_types
        }
    };
    read_from_file_or_stdin(args.input_file.as_ref(), "schema").and_then(translate)
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

fn translate_schema_to_json_with_resolved_types(cedar_src: impl AsRef<str>) -> Result<String> {
    match cedar_policy::schema_str_to_json_with_resolved_types(cedar_src.as_ref()) {
        Ok((json_value, warnings)) => {
            // Output warnings to stderr
            for warning in &warnings {
                eprintln!("{warning}");
            }

            // Serialize to JSON with pretty formatting
            serde_json::to_string_pretty(&json_value).into_diagnostic()
        }
        Err(error) => {
            // Convert CedarSchemaError to miette::Report to preserve all diagnostic information
            Err(miette::Report::new(error))
        }
    }
}
