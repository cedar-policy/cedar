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

//! Flags enumerated entity types that declare the same choice more than once.

use crate::{
    ast::Name,
    linter::{
        findings::{DuplicateEnumChoice, SchemaFinding},
        schema::shared::{duplicates, qualified},
    },
    validator::{
        json_schema::{EntityTypeKind, NamespaceDefinition},
        RawName,
    },
};

/// The choices are a set, so a repeat is inert.
pub(super) fn lint(
    namespace: Option<&Name>,
    def: &NamespaceDefinition<RawName>,
    findings: &mut Vec<SchemaFinding>,
) {
    for (name, entity) in &def.entity_types {
        if let EntityTypeKind::Enum { choices } = &entity.kind {
            let dups = duplicates(choices.iter().map(|c| c.as_ref().to_string()));
            for choice in dups {
                findings.push(
                    DuplicateEnumChoice {
                        loc: None,
                        entity_type: qualified(namespace, name.as_ref()),
                        choice: choice.into(),
                    }
                    .into(),
                );
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::linter::schema::shared::test_support::report;
    use crate::linter::Lint;

    #[track_caller]
    fn lint_report(src: &str) -> String {
        report(Lint::DuplicateEnumChoice, src)
    }

    #[test]
    fn duplicate_enum_choice() {
        insta::assert_snapshot!(lint_report(
            r#"entity Color enum ["red", "red", "blue"];"#), @r#"
        ⚠ enum type `Color` repeats the choice `"red"`
        help: the choices are a set, so the repeat has no effect; list each choice once
        "#);
    }

    #[test]
    fn distinct_enum_choices_are_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"entity Color enum ["red", "green", "blue"];"#), @"");
    }
}
