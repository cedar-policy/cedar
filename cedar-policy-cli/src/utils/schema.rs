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

use cedar_policy::Schema;
use clap::{Args, ValueEnum};
use miette::{Result, WrapErr};
use std::path::{Path, PathBuf};

use crate::utils::read_from_file;

#[derive(Debug, Default, Clone, Copy, ValueEnum)]
pub enum SchemaFormat {
    /// the Cedar format
    #[default]
    Cedar,
    /// JSON format
    Json,
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
    pub(crate) fn get_schema(&self) -> Result<Schema> {
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
    pub(crate) fn get_schema(&self) -> Result<Option<Schema>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{render_err, TEMPFILE_FILTER};
    use std::io::Write;

    #[test]
    fn cedar_schema_from_file_parse_error() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"not a valid schema").unwrap();
        let err = read_schema_from_file(f.path(), SchemaFormat::Cedar).unwrap_err();
        insta::with_settings!({filters => vec![TEMPFILE_FILTER]}, {
            insta::assert_snapshot!(render_err(&err), @r"
             × failed to parse schema from file <TEMPFILE>
             ╰─▶ error parsing schema: unexpected token `not`
              ╭────
            1 │ not a valid schema
              · ─┬─
              ·  ╰── expected `@`, `action`, `entity`, `namespace`, or `type`
              ╰────
            ");
        });
    }

    #[test]
    fn json_schema_from_file_parse_error() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"not json").unwrap();
        let err = read_schema_from_file(f.path(), SchemaFormat::Json).unwrap_err();
        insta::with_settings!({filters => vec![TEMPFILE_FILTER]}, {
            insta::assert_snapshot!(render_err(&err), @r"
            × failed to parse schema from file <TEMPFILE>
            ╰─▶ expected ident at line 1 column 2
            help: this API was expecting a schema in the JSON format; did you mean to use a different function, which expects the Cedar schema format?
            ");
        });
    }

    #[test]
    fn schema_from_missing_file() {
        let err = read_schema_from_file("/tmp/nonexistent_cedar_schema.json", SchemaFormat::Cedar)
            .unwrap_err();
        insta::assert_snapshot!(render_err(&err), @r"
        × failed to open schema file /tmp/nonexistent_cedar_schema.json
        ╰─▶ No such file or directory (os error 2)
        ");
    }
}
