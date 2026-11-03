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

//! Locating and loading the schema and policies from disk.

use cedar_tpe_explorer::Project;
use std::path::{Path, PathBuf};

/// Where the project's files live.
#[derive(Debug, Clone)]
pub struct Paths {
    pub schema: PathBuf,
    pub policies: Vec<PathBuf>,
}

fn files_with_suffix(dir: &Path, suffixes: &[&str]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| suffixes.iter().any(|s| n.ends_with(s)))
        })
        .collect();
    out.sort();
    out
}

/// Fill in whatever wasn't given explicitly by looking in `dir`: exactly one
/// `*.cedarschema` (or `*.cedarschema.json`) and all `*.cedar` policy files.
pub fn discover(
    dir: &Path,
    schema: Option<PathBuf>,
    policies: Vec<PathBuf>,
) -> Result<Paths, String> {
    let schema = match schema {
        Some(s) => s,
        None => {
            let found = files_with_suffix(dir, &[".cedarschema", ".cedarschema.json"]);
            match found.as_slice() {
                [one] => one.clone(),
                [] => {
                    return Err(format!(
                        "no *.cedarschema file found in {}; pass --schema",
                        dir.display()
                    ))
                }
                many => {
                    return Err(format!(
                        "several schema files found ({}); pass --schema",
                        many.iter()
                            .map(|p| p.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                }
            }
        }
    };
    let policies = if policies.is_empty() {
        let found = files_with_suffix(dir, &[".cedar"]);
        if found.is_empty() {
            return Err(format!(
                "no *.cedar policy files found in {}; pass --policies",
                dir.display()
            ));
        }
        found
    } else {
        policies
    };
    Ok(Paths { schema, policies })
}

pub fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Parse the schema and (concatenated) policy files.
pub fn load_project(paths: &Paths) -> Result<Project, String> {
    let schema = read(&paths.schema)?;
    let mut policies = String::new();
    for p in &paths.policies {
        policies.push_str(&read(p)?);
        policies.push('\n');
    }
    Project::new(&schema, &policies).map_err(|e| e.to_string())
}
