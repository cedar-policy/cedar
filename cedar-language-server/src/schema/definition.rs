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

use std::sync::Arc;

use cedar_policy_core::ast::EntityType;
use cedar_policy_core::validator::{
    types::{EntityRecordKind, Type},
    ValidatorActionId, ValidatorEntityType, ValidatorSchema,
};
use itertools::Itertools;
use lsp_types::{GotoDefinitionResponse, Location, Position, Range, Url};

use crate::utils::{get_word_at_position, position_within_loc, ToRange};

use super::SchemaInfo;

/// Provides "go to definition" functionality for references within a Cedar schema document.
///
/// This function analyzes a schema at the given cursor position and identifies
/// the definition location for entity types, actions, or common types being referenced.
/// It enables IDE navigation between references and their definitions within the same
/// schema document.
///
/// # Arguments
///
/// # Returns
///
/// An `Option<GotoDefinitionResponse>` containing:
/// - A location pointing to the definition of the referenced element
/// - `None` if no definition could be found at the cursor position
///
/// # Examples
///
/// For a schema with entity type references:
///
/// ```cedarschema
/// type Subscription = { ... };
/// entity Subscriber = {
///   subscription: Subscription, // Cursor here would navigate to the subscription type definition
///   profile: Profile,
///   age: Long
/// };
/// ```
///
/// # Supported References
///
/// The function can find definitions for:
/// - Entity type references in action declarations
/// - Parent entity types in inheritance declarations
/// - Common type references in attribute type declarations
/// - Action group references
pub(crate) fn schema_goto_definition(
    position: Position,
    schema: &SchemaInfo,
    schema_uri: &Url,
) -> Option<GotoDefinitionResponse> {
    let validator = ValidatorSchema::try_from(schema).ok().map(Arc::new)?;

    let word_under_cursor = get_word_at_position(position, &schema.text)?;

    let cx = FindDefinitionContext::new(&validator, position, word_under_cursor, &schema.text);
    let et_range = validator.find_definition(&cx)?;

    let location = Location {
        uri: schema_uri.clone(),
        range: et_range,
    };

    Some(GotoDefinitionResponse::Scalar(location))
}

pub(crate) struct FindDefinitionContext<'a> {
    schema: &'a ValidatorSchema,
    position: Position,
    cursor_word: &'a str,
    schema_src: &'a str,
}

impl<'a> FindDefinitionContext<'a> {
    #[must_use]
    pub(crate) fn new(
        schema: &'a ValidatorSchema,
        position: Position,
        cursor_word: &'a str,
        schema_src: &'a str,
    ) -> Self {
        Self {
            schema,
            position,
            cursor_word,
            schema_src,
        }
    }
}

trait FindDefinition {
    fn find_definition(&self, cx: &FindDefinitionContext<'_>) -> Option<Range>;
}

impl FindDefinition for ValidatorSchema {
    fn find_definition(&self, cx: &FindDefinitionContext<'_>) -> Option<Range> {
        self.action_ids()
            .find_map(|a| a.find_definition(cx))
            .or_else(|| {
                self.entity_type_names()
                    .find_map(|et| et.find_definition(cx))
            })
    }
}

impl FindDefinition for ValidatorActionId {
    fn find_definition(&self, cx: &FindDefinitionContext<'_>) -> Option<Range> {
        if !position_within_loc(cx.position, self.loc()) {
            return None;
        }

        self.resources()
            .chain(self.principals())
            .filter(|et| et.to_string() == cx.cursor_word)
            .find_map(|et| {
                let vet = cx.schema.get_entity_type(et)?;
                let loc = vet.loc.as_ref()?;
                Some(loc.to_range())
            })
            .or_else(|| self.context_type().find_definition(cx))
            .or_else(|| {
                cx.schema
                    .action_groups()
                    .filter_map(|a| cx.schema.get_action_id(a))
                    .filter(|a| a.descendants().contains(self.name()))
                    .find(|a| a.name().eid().escaped() == cx.cursor_word)
                    .and_then(|v| v.loc())
                    .map(super::super::utils::ToRange::to_range)
            })
    }
}

impl FindDefinition for ValidatorEntityType {
    fn find_definition(&self, cx: &FindDefinitionContext<'_>) -> Option<Range> {
        let loc = self.loc.as_ref()?;
        if !position_within_loc(cx.position, loc) {
            return None;
        }

        self.attributes()
            .iter()
            .find_map(|(_attr, ty)| ty.attr_type.find_definition(cx))
            .or_else(|| {
                cx.schema
                    .entity_types()
                    .filter(|et| et.has_descendant_entity_type(self.name()))
                    .filter(|et| et.name().to_string() == cx.cursor_word)
                    .filter_map(|et| et.loc.as_ref())
                    .map(super::super::utils::ToRange::to_range)
                    .next()
            })
    }
}

impl FindDefinition for EntityType {
    fn find_definition(&self, cx: &FindDefinitionContext<'_>) -> Option<Range> {
        let vet = cx.schema.get_entity_type(self)?;
        vet.find_definition(cx)
    }
}

impl FindDefinition for Type {
    fn find_definition(&self, cx: &FindDefinitionContext<'_>) -> Option<Range> {
        match self {
            Self::EntityOrRecord(entity_record_kind) => match entity_record_kind {
                EntityRecordKind::Record { .. } => {
                    find_common_type_definition(cx.cursor_word, cx.schema_src)
                }
                EntityRecordKind::Entity(entity_lub) => {
                    let et = entity_lub.get_single_entity()?;
                    if cx.cursor_word != et.to_string() {
                        return None;
                    }
                    let vet = cx.schema.get_entity_type(et)?;
                    let loc = vet.loc.as_ref()?;
                    Some(loc.to_range())
                }
                EntityRecordKind::AnyEntity | EntityRecordKind::ActionEntity { .. } => None,
            },
            Self::Set { element_type } => {
                element_type.as_ref().and_then(|el| el.find_definition(cx))
            }
            Self::Never
            | Self::True
            | Self::False
            | Self::Primitive { .. }
            | Self::ExtensionType { .. } => None,
        }
    }
}

pub(crate) fn find_common_type_definition(type_name: &str, schema_text: &str) -> Option<Range> {
    // Regex to match type declarations like "type TypeName = ..."
    let type_pattern = format!(r"type\s+{}\s*=", regex::escape(type_name));
    let re = regex::Regex::new(&type_pattern).ok()?;

    if let Some(mat) = re.find(schema_text) {
        // Found the type definition - now convert to Range
        let start_offset = mat.start();

        // Convert character offset to Position (line, character)
        let start = offset_to_position(schema_text, start_offset);

        // Find the end of the type definition (looking for semicolon or next type definition)
        let mut end_offset = schema_text[start_offset..]
            .find(';')
            .map(|pos| start_offset + pos + 1)
            .or_else(|| {
                schema_text[start_offset..]
                    .find("type ")
                    .map(|pos| start_offset + pos)
            })
            .unwrap_or(schema_text.len());

        // Ensure we don't go past the end of the schema
        end_offset = end_offset.min(schema_text.len());

        // Convert end offset to Position
        let end = offset_to_position(schema_text, end_offset);

        return Some(Range { start, end });
    }

    None
}

fn offset_to_position(text: &str, offset: usize) -> Position {
    let mut line = 0;
    let mut char = 0;

    for (i, c) in text.char_indices() {
        if i >= offset {
            break;
        }

        if c == '\n' {
            line += 1;
            char = 0;
        } else {
            char += 1;
        }
    }

    Position::new(line, char)
}

#[cfg(test)]
mod test {
    use std::sync::LazyLock;

    use lsp_types::{GotoDefinitionResponse, Url};

    use crate::{
        schema::SchemaInfo,
        utils::tests::{remove_caret_marker, slice_range},
    };

    use tracing_test::traced_test;

    static URL: LazyLock<Url> = LazyLock::new(|| Url::parse("https://example.net").ok().unwrap());

    #[track_caller]
    fn goto_def_test(schema: &str, expected: &str) {
        let (schema, position) = remove_caret_marker(schema);

        let GotoDefinitionResponse::Scalar(actual) = super::schema_goto_definition(
            position,
            &SchemaInfo::cedar_schema(schema.clone()),
            &URL,
        )
        .unwrap() else {
            panic!("Expected exactly one definition");
        };

        let actual_str = slice_range(&schema, actual.range);
        similar_asserts::assert_eq!(expected, actual_str);
    }

    macro_rules! goto_def_test {
        ($name:ident, $schema:expr, $expected:expr) => {
            #[test]
            #[traced_test]
            fn $name() {
                goto_def_test($schema, $expected);
            }
        };
    }

    goto_def_test!(
        entity_def_from_in,
        "entity User; entity Other in Us|caret|er;",
        "entity User;"
    );

    goto_def_test!(
        multi_entity_def_from_in,
        "entity Foo, User; entity Other in Us|caret|er;",
        "entity Foo, User;"
    );

    goto_def_test!(
        entity_def_from_applies_to_principal,
        "entity Other; entity User; action act appliesTo { principal: Use|caret|r, resource: Other };",
        "entity User;"
    );

    goto_def_test!(
        entity_def_from_applies_to_resource,
        "entity Other; entity User; action act appliesTo { principal: User, resource: Other|caret| };",
        "entity Other;"
    );

    goto_def_test!(
        action_def_from_in,
        "action act; action other in [act|caret|];",
        "action act;"
    );

    goto_def_test!(
        action_def_from_multi_in,
        "action foo; action act; action other in [foo, act|caret|];",
        "action act;"
    );

    goto_def_test!(
        multi_action_def,
        "action foo, act; action other in [act|caret|];",
        "action foo, act;"
    );

    goto_def_test!(
        entity_def_from_entity_attr,
        "entity Other { a: Other|caret| };",
        "entity Other { a: Other };"
    );

    goto_def_test!(
        from_def_in_set,
        "entity E; entity Other { a: Set<E|caret|> };",
        "entity E;"
    );

    goto_def_test!(
        common_type_from_entity_attr,
        "entity E { a: { b: ty|caret| } };\ntype ty = Long;",
        "type ty = Long;"
    );

    goto_def_test!(
        entity_def_from_context_attr,
        "entity Other; entity User; action act appliesTo { principal: User, resource: Other, context: {a: User|caret| } };",
        "entity User;"
    );
}
