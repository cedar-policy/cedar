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
use miette::{IntoDiagnostic, Result};

use crate::CedarExitCode;

#[derive(Args, Debug)]
pub struct NewArgs {
    /// Name of the Cedar project
    #[arg(short, long, value_name = "DIR")]
    pub name: String,
}

pub fn new(args: &NewArgs) -> CedarExitCode {
    if let Err(err) = new_inner(args) {
        println!("{err:?}");
        CedarExitCode::Failure
    } else {
        CedarExitCode::Success
    }
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
