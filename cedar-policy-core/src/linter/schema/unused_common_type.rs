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

//! Flags common types that nothing references.

use crate::{
    ast::Name,
    linter::{
        findings::{SchemaFinding, UnusedCommonType},
        schema::shared::{qualified, referenced_type_names},
    },
    validator::{json_schema::NamespaceDefinition, RawName},
};

/// A common type is only ever a name for a type; if no entity attribute, action
/// context, or other common type refers to it, it has no effect.
pub(super) fn lint(
    namespace: Option<&Name>,
    def: &NamespaceDefinition<RawName>,
    findings: &mut Vec<SchemaFinding>,
) {
    let referenced = referenced_type_names(def);
    for name in def.common_types.keys() {
        let name = name.as_ref().as_ref();
        if !referenced.contains(name) {
            findings.push(
                UnusedCommonType {
                    loc: None,
                    common_type: qualified(namespace, name),
                }
                .into(),
            );
        }
    }
}

#[cfg(test)]
mod test {
    use crate::linter::schema::shared::test_support::report;
    use crate::linter::Lint;

    #[track_caller]
    fn lint_report(src: &str) -> String {
        report(Lint::UnusedCommonType, src)
    }

    /// A common type nothing refers to.
    #[test]
    fn unused_common_type() {
        insta::assert_snapshot!(lint_report(
            r#"
            type Age = Long;
            type Unused = String;
            entity User { age: Age };
            action view appliesTo { principal: [User], resource: [User] };
        "#), @"
        ⚠ common type `Unused` is declared but never used
        help: nothing refers to it, so it has no effect; remove it
        ");
    }

    /// A common type used in an attribute is fine.
    #[test]
    fn used_common_type_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"
            type Age = Long;
            entity User { age: Age };
            action view appliesTo { principal: [User], resource: [User] };
        "#), @"");
    }
}
