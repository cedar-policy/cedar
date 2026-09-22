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

//! Flags an attribute typed `Set<{key: String, value: T}>`, the idiom people used
//! to emulate tags before Cedar had a native `tags` construct.
//!
//! In the Cedar schema syntax, `String` parses as an entity-or-common-type
//! reference named `String`, not the built-in [`TypeVariant::String`] — the parser
//! cannot yet tell a primitive from a same-named common type. Only the JSON syntax
//! yields `TypeVariant::String`. This lint accepts both spellings.

use crate::{
    ast::Name,
    linter::{
        findings::{AttributeShouldBeTags, SchemaFinding},
        schema::shared::{qualified, shape_variant},
    },
    validator::{
        json_schema::{
            EntityType, EntityTypeKind, NamespaceDefinition, RecordType, Type, TypeVariant,
        },
        RawName,
    },
};

/// Report any attribute of any entity in `def` whose type is the tag-emulation
/// shape.
pub(super) fn lint(
    namespace: Option<&Name>,
    def: &NamespaceDefinition<RawName>,
    findings: &mut Vec<SchemaFinding>,
) {
    for (entity_name, entity) in &def.entity_types {
        lint_entity(namespace, entity_name.as_ref(), entity, findings);
    }
}

fn lint_entity(
    namespace: Option<&Name>,
    entity_name: &str,
    entity: &EntityType<RawName>,
    findings: &mut Vec<SchemaFinding>,
) {
    let EntityTypeKind::Standard(std) = &entity.kind else {
        // Enumerated entity types have no attributes.
        return;
    };
    let TypeVariant::Record(RecordType { attributes, .. }) = shape_variant(&std.shape.0) else {
        return;
    };
    for (attr, attr_ty) in attributes {
        if is_tag_emulation(&attr_ty.ty) {
            findings.push(
                AttributeShouldBeTags {
                    loc: attr_ty.ty.loc().cloned(),
                    entity_type: qualified(namespace, entity_name),
                    attribute: attr.clone(),
                }
                .into(),
            );
        }
    }
}

/// Is `ty` the shape `Set<{key: String, value: T}>`?
///
/// Requires exactly two attributes, `key` and `value`, with `key` a `String`.
/// `value`'s type is unconstrained: any `T` is the tag's value type. Extra
/// attributes, a missing one, or a non-string `key` all disqualify it.
fn is_tag_emulation(ty: &Type<RawName>) -> bool {
    let Type::Type {
        ty: TypeVariant::Set { element },
        ..
    } = ty
    else {
        return false;
    };
    let Type::Type {
        ty: TypeVariant::Record(RecordType { attributes, .. }),
        ..
    } = element.as_ref()
    else {
        return false;
    };
    if attributes.len() != 2 {
        return false;
    }
    let (Some(key), Some(_value)) = (attributes.get("key"), attributes.get("value")) else {
        return false;
    };
    is_string(&key.ty)
}

/// Is `ty` the `String` primitive?
///
/// Both spellings count: `TypeVariant::String` (JSON syntax) and an
/// entity-or-common reference named `String` (Cedar syntax, before resolution). A
/// user-declared common type also named `String` would be a false match, but that
/// name shadows the builtin and is already warned about at parse time.
fn is_string(ty: &Type<RawName>) -> bool {
    match ty {
        Type::Type {
            ty: TypeVariant::String,
            ..
        } => true,
        Type::Type {
            ty: TypeVariant::EntityOrCommon { type_name },
            ..
        } => type_name.is_unqualified() && type_name.to_string() == "String",
        _ => false,
    }
}

#[cfg(test)]
mod test {
    use crate::linter::schema::shared::test_support::report;
    use crate::linter::Lint;
    use crate::validator::{json_schema::Fragment, RawName};

    #[track_caller]
    fn lint_report(src: &str) -> String {
        report(Lint::AttributeShouldBeTags, src)
    }

    #[test]
    fn tag_emulation_string_value() {
        insta::assert_snapshot!(lint_report(
            r#"entity User { attrs: Set<{key: String, value: String}> };"#), @"
         ⚠ attribute `attrs` on `User` looks like emulated tags
          ╭────
        1 │ entity User { attrs: Set<{key: String, value: String}> };
          ·                      ─────────────────────────────────
          ╰────
         help: `Set<{key: String, value: T}>` emulates tags; consider declaring native `tags T` on the entity type instead
        ");
    }

    /// The value type is unconstrained — any `T`.
    #[test]
    fn tag_emulation_non_string_value() {
        insta::assert_snapshot!(lint_report(
            r#"entity User { labels: Set<{key: String, value: Long}> };"#), @"
         ⚠ attribute `labels` on `User` looks like emulated tags
          ╭────
        1 │ entity User { labels: Set<{key: String, value: Long}> };
          ·                       ───────────────────────────────
          ╰────
         help: `Set<{key: String, value: T}>` emulates tags; consider declaring native `tags T` on the entity type instead
        ");
    }

    /// The JSON syntax spells `String` as the builtin, which must also match.
    #[test]
    fn tag_emulation_json_syntax() {
        let json = r#"{"":{"entityTypes":{"User":{"shape":{"type":"Record","attributes":{"t":{"type":"Set","element":{"type":"Record","attributes":{"key":{"type":"String"},"value":{"type":"String"}}}}}}}},"actions":{}}}"#;
        let fragment = Fragment::<RawName>::from_json_str(json).expect("parse");
        let findings =
            crate::linter::SchemaLinter::new([Lint::AttributeShouldBeTags]).lint(&fragment);
        assert_eq!(findings.len(), 1, "should match the JSON-syntax String too");
    }

    /// A key that is not `String` is not the idiom.
    #[test]
    fn non_string_key_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"entity User { attrs: Set<{key: Long, value: String}> };"#), @"");
    }

    /// Extra attributes mean it is a real record, not a tag pair.
    #[test]
    fn extra_attribute_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"entity User { attrs: Set<{key: String, value: String, ts: Long}> };"#), @"");
    }

    /// A record that is not inside a set is not the idiom.
    #[test]
    fn record_not_in_set_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"entity User { kv: {key: String, value: String} };"#), @"");
    }

    /// An ordinary set attribute is fine.
    #[test]
    fn ordinary_set_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"entity User { roles: Set<String> };"#), @"");
    }

    /// A schema already using native tags is of course fine.
    #[test]
    fn native_tags_are_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"entity User tags String;"#), @"");
    }
}
