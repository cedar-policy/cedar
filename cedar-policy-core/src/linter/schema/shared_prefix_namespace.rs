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

//! Suggests a namespace when many entity types in one namespace share a name
//! prefix (`PhotoApp_User`, `PhotoApp_Album`, ...), which a `namespace` would
//! express more cleanly.

use std::collections::BTreeMap;

use smol_str::SmolStr;

use crate::{
    ast::Name,
    linter::findings::{SchemaFinding, SharedPrefixNamespace},
    validator::{
        json_schema::{EntityType, NamespaceDefinition},
        RawName,
    },
};

/// How many entity types must share a prefix before a namespace is suggested.
const SHARED_PREFIX_THRESHOLD: usize = 3;

/// The prefix is the part before the first `_`. When at least
/// [`SHARED_PREFIX_THRESHOLD`] types share one, a single finding is reported for
/// the group.
pub(super) fn lint(
    namespace: Option<&Name>,
    def: &NamespaceDefinition<RawName>,
    findings: &mut Vec<SchemaFinding>,
) {
    lint_entity_types(namespace, &def.entity_types, findings);
}

fn lint_entity_types(
    namespace: Option<&Name>,
    entity_types: &BTreeMap<crate::ast::UnreservedId, EntityType<RawName>>,
    findings: &mut Vec<SchemaFinding>,
) {
    // Group type names by their prefix, preserving one representative loc.
    let mut by_prefix: BTreeMap<&str, Vec<SmolStr>> = BTreeMap::new();
    for ty_name in entity_types.keys() {
        let name: &str = ty_name.as_ref();
        if let Some((prefix, _)) = name.split_once('_') {
            if !prefix.is_empty() {
                by_prefix
                    .entry(prefix)
                    .or_default()
                    .push(SmolStr::new(name));
            }
        }
    }
    for (prefix, members) in by_prefix {
        if members.len() >= SHARED_PREFIX_THRESHOLD {
            findings.push(
                SharedPrefixNamespace {
                    // Entity-type declarations don't carry a loc from JSON, so
                    // this finding is namespace-scoped rather than span-anchored.
                    loc: None,
                    namespace: namespace.map(ToString::to_string),
                    prefix: prefix.into(),
                    members,
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
        report(Lint::SharedPrefixNamespace, src)
    }

    #[test]
    fn shared_prefix() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity PhotoApp_User;
            entity PhotoApp_Album;
            entity PhotoApp_Photo;
        "#), @"
        ⚠ 3 entity types share the prefix `PhotoApp`
        help: consider a `namespace PhotoApp { ... }` with types `PhotoApp_Album`, `PhotoApp_Photo`, `PhotoApp_User` instead of the `PhotoApp_` prefix
        ");
    }

    /// Below the threshold, nothing is suggested.
    #[test]
    fn two_sharing_a_prefix_is_below_threshold() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity PhotoApp_User;
            entity PhotoApp_Album;
        "#), @"");
    }

    /// Types without the shared prefix don't count toward it.
    #[test]
    fn mixed_prefixes() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity PhotoApp_User;
            entity PhotoApp_Album;
            entity PhotoApp_Photo;
            entity Other;
            entity Unrelated;
        "#), @"
        ⚠ 3 entity types share the prefix `PhotoApp`
        help: consider a `namespace PhotoApp { ... }` with types `PhotoApp_Album`, `PhotoApp_Photo`, `PhotoApp_User` instead of the `PhotoApp_` prefix
        ");
    }

    /// Types with no `_` have no prefix to share.
    #[test]
    fn no_separator_no_prefix() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity User;
            entity Album;
            entity Photo;
        "#), @"");
    }

    /// Distinct prefixes each below the threshold are not reported.
    #[test]
    fn distinct_prefixes() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity PhotoApp_User;
            entity PhotoApp_Album;
            entity Billing_Invoice;
            entity Billing_Charge;
        "#), @"");
    }
}
