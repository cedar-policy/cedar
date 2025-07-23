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

use cedar_policy_core::{parser::AsLocRef, validator::ValidatorSchema};
use itertools::Itertools;
use tower_lsp_server::lsp_types::{self, FoldingRange};

use crate::utils::ToRange;

use super::SchemaInfo;

/// Generates folding ranges for Cedar schema elements.
///
/// This function analyzes a Cedar schema document and identifies regions that
/// can be folded in an editor or IDE, including namespaces, entity types, actions,
/// and common types. Folding ranges allow users to collapse sections of the document
/// for better readability when working with large schemas.
///
/// # Returns
///
/// An `Option<Vec<FoldingRange>>` containing:
/// - A vector of folding ranges corresponding to schema elements
/// - `None` if the schema is in JSON format or couldn't be parsed as a valid schema
///
/// # Folding Structure
///
/// The function provides folding ranges for:
/// - Namespaces (allowing entire namespace blocks to be collapsed)
/// - Entity type definitions
/// - Action definitions
/// - Common type definitions
///
/// # Example
///
/// For a schema with a namespace:
///
/// ```cedar
/// namespace App {
///   // Types, entities and actions can be collapsed individually
///   type Profile = { isKid: Bool };
///   entity Movie = { isFree: Bool };
///   action watch appliesTo { /*...*/ };
/// }
/// // The entire namespace can also be collapsed
/// ```
///
/// # LSP Integration
///
/// These folding ranges can be returned directly in response to a
/// `textDocument/foldingRange` request in a language server implementation.
#[must_use]
pub(crate) fn fold_schema(schema_info: &SchemaInfo) -> Option<Vec<FoldingRange>> {
    if schema_info.is_json_schema() {
        return None;
    }

    let validator = ValidatorSchema::try_from(schema_info).ok()?;

    // Get namespace locations first (will contain other elements)
    let namespace_locs = validator
        .namespaces()
        .filter_map(|ns| ns.def_loc.as_loc_ref());

    // Get locations for all other elements
    let entity_type_locs = validator
        .entity_types()
        .filter_map(|et| et.loc.as_loc_ref());
    let action_locs = validator.action_ids().filter_map(|a| a.loc());
    let common_types = validator
        .common_types()
        .filter_map(|ct| ct.type_loc.as_loc_ref());

    // Combine all locations and create folding ranges
    let ranges = namespace_locs
        .chain(entity_type_locs)
        .chain(action_locs)
        .chain(common_types)
        .unique()
        .map(|loc| {
            let src_range = loc.to_range();

            FoldingRange {
                start_line: src_range.start.line,
                start_character: None,
                end_line: src_range.end.line,
                end_character: None,
                kind: Some(lsp_types::FoldingRangeKind::Region),
                collapsed_text: None,
            }
        })
        .collect();

    Some(ranges)
}

#[cfg(test)]
mod test {
    use itertools::Itertools;

    use crate::schema::{fold_schema, SchemaInfo, SchemaType};
    use tracing_test::traced_test;

    #[track_caller]
    fn assert_schema_folding_ranges(schema: &str, mut expected: Vec<(u32, u32)>) {
        let schema_info = SchemaInfo::new(SchemaType::CedarSchema, schema.to_string());
        let ranges = fold_schema(&schema_info).unwrap();
        let actual = ranges
            .iter()
            .map(|range| (range.start_line, range.end_line))
            .sorted()
            .collect_vec();
        expected.sort_unstable();
        similar_asserts::assert_eq!(expected, actual);
    }

    macro_rules! assert_schema_folding_ranges {
        ($name:ident, $schema:expr, $( $expected:expr ),* )=> {
            #[test]
            #[traced_test]
            fn $name() {
                assert_schema_folding_ranges($schema, vec![$( $expected, )*]);
            }
        };
    }

    assert_schema_folding_ranges!(
        empty_schema,
        "",
        // No folding ranges expected for empty schema
    );

    assert_schema_folding_ranges!(namespace_only, "namespace Test {}", (0, 0));

    assert_schema_folding_ranges!(
        namespace_with_entity,
        "namespace Test {\n  entity User {};\n}",
        (0, 2),
        (1, 1)
    );

    assert_schema_folding_ranges!(
        namespace_with_multiple_elements,
        "namespace Test {\n  entity User {};\n  action view;\n  type Role = {};\n}",
        (0, 4),
        (1, 1),
        (2, 2),
        (3, 3)
    );

    assert_schema_folding_ranges!(
        multiple_namespaces,
        "namespace NS1 {\n  entity E1 {};\n}\n\nnamespace NS2 {\n  entity E2 {};\n}",
        (0, 2),
        (1, 1),
        (4, 6),
        (5, 5)
    );

    assert_schema_folding_ranges!(
        entity_with_attributes,
        "entity User {\n  name: String,\n  age: Long\n};",
        (0, 3)
    );

    assert_schema_folding_ranges!(
        action_with_applies_to,
        "entity E;\naction view appliesTo {\n  principal: E,\n  resource: E\n};",
        (0, 0),
        (1, 4)
    );

    assert_schema_folding_ranges!(
        common_type_definition,
        "type Role = {\n  name: String,\n  permissions: Set<String>\n};",
        (0, 3)
    );

    #[test]
    #[traced_test]
    fn json_schema_returns_none() {
        let schema_info = SchemaInfo::new(SchemaType::Json, r#"{"entityTypes": {}}"#.to_string());
        let ranges = fold_schema(&schema_info);
        assert!(
            ranges.is_none(),
            "JSON schema should not have folding ranges"
        );
    }
}
