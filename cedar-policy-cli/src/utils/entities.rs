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

use cedar_policy::{Entities, Schema};
use miette::{IntoDiagnostic, Result, WrapErr};

/// Load an `Entities` object from the given JSON filename and optional schema.
pub(crate) fn load_entities(
    entities_filename: impl AsRef<Path>,
    schema: Option<&Schema>,
) -> Result<Entities> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{render_err, TEMPFILE_FILTER};
    use std::io::Write;

    #[test]
    fn error_on_invalid_entity_data() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"not valid json").unwrap();
        let err = load_entities(f.path(), None).unwrap_err();
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
        let err = load_entities(f.path(), Some(&schema)).unwrap_err();
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
        let err = load_entities("/tmp/nonexistent_cedar_test_file.json", None).unwrap_err();
        insta::assert_snapshot!(render_err(&err), @r"
        × failed to open entities file /tmp/nonexistent_cedar_test_file.json
        ╰─▶ No such file or directory (os error 2)
        ");
    }
}
