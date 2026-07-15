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

use std::path::{Path, PathBuf};

use cedar_policy::{Entities, Schema};
use clap::{Args, ValueEnum};
use miette::{IntoDiagnostic, Result, WrapErr};

/// Format for entity data files
/// JSON is default for backward compatibility.
#[derive(Debug, Default, Clone, Copy, ValueEnum)]
pub enum EntitiesFormat {
    /// JSON entity format
    #[default]
    Json,
    /// Cedar entity data syntax
    #[cfg(feature = "cedar-entity-syntax")]
    Cedar,
}

/// This struct contains the arguments that together specify an input entity hierarchy.
#[derive(Args, Debug)]
pub struct EntitiesArgs {
    /// File containing a Cedar entity hierarchy
    #[arg(long = "entities", value_name = "FILE")]
    pub entities_file: PathBuf,
    /// Entities format
    #[cfg(feature = "cedar-entity-syntax")]
    #[arg(long, value_enum, default_value_t)]
    pub entities_format: EntitiesFormat,
}

impl EntitiesArgs {
    /// Turn this `EntitiesArgs` into the appropriate `Entities` object
    pub(crate) fn get_entities(&self, schema: Option<&Schema>) -> Result<Entities> {
        let format = self.format();
        load_entities(&self.entities_file, format, schema)
    }

    fn format(&self) -> EntitiesFormat {
        #[cfg(feature = "cedar-entity-syntax")]
        {
            self.entities_format
        }
        #[cfg(not(feature = "cedar-entity-syntax"))]
        {
            EntitiesFormat::default()
        }
    }
}

/// This struct contains the arguments that together specify an input entity hierarchy,
/// for commands where the entities file is optional.
#[derive(Args, Debug)]
pub struct OptionalEntitiesArgs {
    /// File containing a Cedar entity hierarchy
    #[arg(long = "entities", value_name = "FILE")]
    pub entities_file: Option<PathBuf>,
    /// Entities format
    #[cfg(feature = "cedar-entity-syntax")]
    #[arg(long, value_enum, default_value_t)]
    pub entities_format: EntitiesFormat,
}

impl OptionalEntitiesArgs {
    /// Turn this `OptionalEntitiesArgs` into the appropriate `Entities` object, or empty
    pub(crate) fn get_entities(&self, schema: Option<&Schema>) -> Result<Option<Entities>> {
        let Some(entities_file) = &self.entities_file else {
            return Ok(None);
        };
        let format = self.format();
        load_entities(entities_file, format, schema).map(Some)
    }

    fn format(&self) -> EntitiesFormat {
        #[cfg(feature = "cedar-entity-syntax")]
        {
            self.entities_format
        }
        #[cfg(not(feature = "cedar-entity-syntax"))]
        {
            EntitiesFormat::default()
        }
    }
}

fn load_entities(
    path: impl AsRef<Path>,
    format: EntitiesFormat,
    schema: Option<&Schema>,
) -> Result<Entities> {
    let path = path.as_ref();
    match format {
        EntitiesFormat::Json => load_json_entities(path, schema),
        #[cfg(feature = "cedar-entity-syntax")]
        EntitiesFormat::Cedar => load_cedar_entities(path, schema),
    }
}

/// Load entities from a JSON file
fn load_json_entities(path: &Path, schema: Option<&Schema>) -> Result<Entities> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to open entities file {}", path.display()))?;
    Entities::from_json_file(f, schema)
        .wrap_err_with(|| format!("failed to parse entities from file {}", path.display()))
}

/// Load entities from a Cedar entity data syntax file
#[cfg(feature = "cedar-entity-syntax")]
fn load_cedar_entities(path: &Path, schema: Option<&Schema>) -> Result<Entities> {
    let src = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read entities file {}", path.display()))?;
    Entities::from_cedar_str(&src, schema)
        .wrap_err_with(|| format!("failed to parse entities from file {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{render_err, TEMPFILE_FILTER};
    use std::io::Write;

    #[test]
    fn error_on_invalid_entity_data() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"not valid json").unwrap();
        let err = load_entities(f.path(), EntitiesFormat::Json, None).unwrap_err();
        insta::with_settings!({filters => vec![TEMPFILE_FILTER]}, {
            insta::assert_snapshot!(render_err(&err), @r"
            × failed to parse entities from file <TEMPFILE>
            ├─▶ error during entity deserialization
            ╰─▶ expected ident at line 1 column 2
            ");
        });
    }

    #[test]
    fn error_on_ill_typed_entities() {
        let (schema, _) = Schema::from_cedarschema_str("entity Photo;").unwrap();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(br#"[{"uid":{"__entity":{"type":"Album","id":"a"}},"attrs":{},"parents":[]}]"#)
            .unwrap();
        let err = load_entities(f.path(), EntitiesFormat::Json, Some(&schema)).unwrap_err();
        insta::with_settings!({filters => vec![TEMPFILE_FILTER]}, {
            insta::assert_snapshot!(render_err(&err), @r#"
            × failed to parse entities from file <TEMPFILE>
            ├─▶ error during entity deserialization
            ╰─▶ entity `Album::"a"` has type `Album` which is not declared in the schema
            "#);
        });
    }

    #[test]
    fn error_on_missing_entity_file() {
        let err = load_entities(
            "/tmp/nonexistent_cedar_test_file.json",
            EntitiesFormat::Json,
            None,
        )
        .unwrap_err();
        insta::assert_snapshot!(render_err(&err), @r"
        × failed to open entities file /tmp/nonexistent_cedar_test_file.json
        ╰─▶ No such file or directory (os error 2)
        ");
    }

    #[cfg(feature = "cedar-entity-syntax")]
    #[test]
    fn load_cedar_entities_file() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(br#"instance User::"alice"; instance User::"bob";"#)
            .unwrap();
        let entities = load_entities(f.path(), EntitiesFormat::Cedar, None).unwrap();
        assert_eq!(entities.iter().count(), 2);
    }

    #[cfg(feature = "cedar-entity-syntax")]
    #[test]
    fn error_on_invalid_cedar_entities() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"this is not valid cedar entity syntax $$$$")
            .unwrap();
        let err = load_entities(f.path(), EntitiesFormat::Cedar, None).unwrap_err();
        let rendered = render_err(&err);
        assert!(
            rendered.contains("failed to parse entities from file"),
            "Expected error message, got: {rendered}"
        );
    }
}
