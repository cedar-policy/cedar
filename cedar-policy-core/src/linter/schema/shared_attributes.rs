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

//! Flags groups of entity types that share many attributes, which a common type
//! could factor out.

use std::collections::{BTreeMap, BTreeSet};

use smol_str::SmolStr;

use crate::{
    ast::Name,
    linter::{
        findings::{SchemaFinding, SharedAttributes},
        schema::shared::{entity_attributes, qualified},
    },
    validator::{json_schema::NamespaceDefinition, RawName},
};

/// Minimum number of entity types that must share an attribute block.
const SHARED_ATTRS_TYPE_THRESHOLD: usize = 3;
/// Minimum size of the shared block before it is worth factoring out.
const SHARED_ATTRS_COUNT_THRESHOLD: usize = 2;

/// Two attributes count as "the same" when their name, type, and required-ness all
/// match. The lint looks for a set of at least [`SHARED_ATTRS_TYPE_THRESHOLD`]
/// entity types whose attribute maps all *contain* a common block of at least
/// [`SHARED_ATTRS_COUNT_THRESHOLD`] attributes — a full duplicate when the block is
/// every type's whole shape, a partial overlap otherwise.
pub(super) fn lint(
    namespace: Option<&Name>,
    def: &NamespaceDefinition<RawName>,
    findings: &mut Vec<SchemaFinding>,
) {
    // (type name, its attribute key set).
    type AttrKey = (SmolStr, String);
    let types: Vec<(String, BTreeSet<AttrKey>)> = def
        .entity_types
        .iter()
        .filter_map(|(name, entity)| {
            let attrs = entity_attributes(entity)?;
            if attrs.is_empty() {
                return None;
            }
            let keys = attrs
                .iter()
                // Key an attribute by name plus a structural rendering of its
                // type and required-ness. `TypeOfAttribute`'s `Debug` is derived
                // and location-insensitive, so it is a stable structural key.
                .map(|(n, t)| (n.clone(), format!("{:?}", (&t.ty, t.required))))
                .collect::<BTreeSet<_>>();
            Some((qualified(namespace, name.as_ref()), keys))
        })
        .collect();

    if types.len() < SHARED_ATTRS_TYPE_THRESHOLD {
        return;
    }

    // Count, for each attribute key, which types have it. An attribute shared by
    // >= threshold types is part of a shared block.
    let mut holders: BTreeMap<&AttrKey, Vec<&str>> = BTreeMap::new();
    for (name, keys) in &types {
        for key in keys {
            holders.entry(key).or_default().push(name.as_str());
        }
    }

    // Group attributes by the exact set of types that hold them; a group of
    // attributes sharing one holder-set, with enough holders and enough
    // attributes, is a shared block.
    let mut block_by_holders: BTreeMap<Vec<&str>, Vec<&SmolStr>> = BTreeMap::new();
    for (key, mut who) in holders {
        if who.len() >= SHARED_ATTRS_TYPE_THRESHOLD {
            who.sort_unstable();
            who.dedup();
            block_by_holders.entry(who).or_default().push(&key.0);
        }
    }

    for (who, mut attrs) in block_by_holders {
        if attrs.len() < SHARED_ATTRS_COUNT_THRESHOLD {
            continue;
        }
        attrs.sort_unstable();
        // Full duplicate when every holder has exactly these attributes and no
        // more.
        let full = types
            .iter()
            .filter(|(n, _)| who.contains(&n.as_str()))
            .all(|(_, keys)| keys.len() == attrs.len());
        findings.push(
            SharedAttributes {
                loc: None,
                entity_types: who.iter().map(|s| s.to_string()).collect(),
                shared_count: attrs.len(),
                attrs: attrs
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                full,
            }
            .into(),
        );
    }
}

#[cfg(test)]
mod test {
    use crate::linter::schema::shared::test_support::report;
    use crate::linter::Lint;

    #[track_caller]
    fn lint_report(src: &str) -> String {
        report(Lint::SharedAttributes, src)
    }

    /// Three types with identical shapes: a full duplicate.
    #[test]
    fn shared_attributes_full() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity A { name: String, age: Long };
            entity B { name: String, age: Long };
            entity C { name: String, age: Long };
        "#), @"
        ⚠ 3 entity types share 2 attributes (age, name)
        help: these types have identical shapes; consider a common type they all use
        ");
    }

    /// Three types sharing a block but each with extra attributes: partial overlap.
    #[test]
    fn shared_attributes_partial() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity A { name: String, age: Long, x: Bool };
            entity B { name: String, age: Long, y: Bool };
            entity C { name: String, age: Long, z: Bool };
        "#), @"
        ⚠ 3 entity types share 2 attributes (age, name)
        help: these types share an attribute block; consider factoring it into a common type
        ");
    }

    /// Below the type threshold: two types sharing a block is not reported.
    #[test]
    fn two_types_sharing_is_below_threshold() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity A { name: String, age: Long };
            entity B { name: String, age: Long };
        "#), @"");
    }

    /// Below the attribute threshold: three types sharing a single attribute is
    /// not reported.
    #[test]
    fn single_shared_attribute_is_below_threshold() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity A { id: String, a: Long };
            entity B { id: String, b: Long };
            entity C { id: String, c: Bool };
        "#), @"");
    }

    /// Differing types for the same attribute name do not count as shared.
    #[test]
    fn same_name_different_type_is_not_shared() {
        insta::assert_snapshot!(lint_report(
            r#"
            entity A { x: String, y: Long };
            entity B { x: Long, y: Long };
            entity C { x: Bool, y: Long };
        "#), @"");
    }
}
