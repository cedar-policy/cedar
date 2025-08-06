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

use cedar_policy_core::validator::ValidatorSchema;
use tower_lsp_server::lsp_types::{DocumentSymbol, SymbolKind};

use crate::{
    lsp::new_symbol,
    utils::{extract_common_type_name, ranges_intersect, ToRange},
};

use super::SchemaInfo;

/// Generates document symbols for Cedar schema elements.
///
/// This function analyzes a Cedar schema document and creates a hierarchical structure
/// of document symbols for namespaces, entity types, actions, and common types. These
/// symbols are organized into a tree structure where elements are properly nested within
/// their containing namespaces.
///
/// # Example Schema Structure
///
/// For a schema like:
///
/// ```cedarschema
/// namespace App {
///   // Types
///   type Subscription = { tier: String };
///   type Profile = { isKid: Bool };
///
///   // Entities
///   entity Subscriber = { subscription: Subscription, age: Long };
///   entity Movie = { isFree: Bool };
///
///   // Actions
///   action "watch"
///     appliesTo {
///       principal: [Subscriber],
///       resource: [Movie]
///     };
/// }
/// ```
///
/// The function generates a hierarchical symbol structure:
///
/// - App (namespace)
///   - Subscription (type)
///   - Profile (type)
///   - Subscriber (entity)
///   - Movie (entity)
///   - watch (action)
///
/// # Returns
///
/// An `Option<Vec<DocumentSymbol>>` containing:
/// - A vector of document symbols organized hierarchically
/// - `None` if the schema is in JSON format or couldn't be parsed as a valid schema
///
/// # Symbol Types
///
/// The function categorizes schema elements into distinct symbol types:
/// - Namespaces: `SymbolKind::NAMESPACE`
/// - Entity types: `SymbolKind::CLASS`
/// - Actions: `SymbolKind::ENUM`
/// - Common types: `SymbolKind::CLASS`
///
/// # LSP Integration
///
/// These symbols can be returned directly in response to a
/// `textDocument/documentSymbol` request in a language server implementation.
/// They provide navigation targets for the document outline, breadcrumbs, and
/// "go to symbol" functionality in IDEs.
#[must_use]
pub(crate) fn schema_symbols(schema_info: &SchemaInfo) -> Option<Vec<DocumentSymbol>> {
    if schema_info.is_json_schema() {
        return None;
    }

    let validator = ValidatorSchema::try_from(schema_info).ok()?;

    // Create namespace symbols first
    let namespace_symbols: Vec<DocumentSymbol> = validator
        .namespaces()
        .filter_map(|ns| ns.def_loc.as_ref().map(|loc| (ns, loc)))
        .map(|(ns, loc)| {
            let src_range = loc.to_range();
            let mut symbol = new_symbol(ns.name.to_string(), src_range, SymbolKind::NAMESPACE);
            symbol.children = Some(Vec::new());
            symbol
        })
        .collect();

    // Create entity type symbols
    let entity_type_symbols: Vec<DocumentSymbol> = validator
        .entity_types()
        .filter_map(|et| et.loc.as_ref().map(|loc| (et, loc)))
        .map(|(et, loc)| {
            let src_range = loc.to_range();
            new_symbol(et.name().to_string(), src_range, SymbolKind::CLASS)
        })
        .collect();

    // Create action symbols
    let action_symbols: Vec<DocumentSymbol> = validator
        .actions()
        .filter_map(|a| a.loc().map(|loc| (a, loc)))
        .map(|(action, loc)| {
            let src_range = loc.to_range();
            new_symbol(action.to_string(), src_range, SymbolKind::ENUM)
        })
        .collect();

    // Create common type symbols
    let common_type_symbols: Vec<DocumentSymbol> = validator
        .common_types()
        .filter_map(|ct| {
            ct.name_loc
                .as_ref()
                .and_then(|loc| loc.snippet())
                .and_then(extract_common_type_name)
                .zip(ct.type_loc.as_ref())
                .map(|(name_snip, type_loc)| {
                    let src_range = type_loc.to_range();
                    new_symbol(name_snip, src_range, SymbolKind::CLASS)
                })
        })
        .collect();

    // Collect all entity types, actions and common types that don't belong to any namespace
    let mut top_level_symbols = namespace_symbols;
    let mut all_other_symbols = Vec::new();
    all_other_symbols.extend(entity_type_symbols);
    all_other_symbols.extend(action_symbols);
    all_other_symbols.extend(common_type_symbols);

    // Assign symbols to namespaces based on range intersection
    let mut remaining_symbols = Vec::new();

    for symbol in all_other_symbols {
        let mut added_to_namespace = false;

        for ns_symbol in &mut top_level_symbols {
            if ranges_intersect(&ns_symbol.range, &symbol.range) {
                // This symbol belongs in this namespace
                let Some(children) = ns_symbol.children.as_mut() else {
                    continue;
                };
                children.push(symbol.clone());
                added_to_namespace = true;
                break;
            }
        }

        if !added_to_namespace {
            // Symbol doesn't belong to any namespace, keep it at top level
            remaining_symbols.push(symbol);
        }
    }

    // Add remaining symbols to top level
    top_level_symbols.extend(remaining_symbols);

    Some(top_level_symbols)
}

#[cfg(test)]
mod test {
    use itertools::Itertools;

    use crate::{
        schema::{schema_symbols, SchemaInfo},
        utils::tests::slice_range,
    };
    use tracing_test::traced_test;

    #[track_caller]
    fn assert_symbols(schema: &str, mut expected: Vec<(&str, &str)>) {
        let syms = schema_symbols(&SchemaInfo::cedar_schema(schema.to_owned())).unwrap();
        let mut actual = syms
            .iter()
            .map(|sym| (sym.name.as_str(), slice_range(schema, sym.range)))
            .chain(syms.iter().flat_map(|sym| {
                sym.children
                    .iter()
                    .flatten()
                    .map(|sym| (sym.name.as_str(), slice_range(schema, sym.range)))
            }))
            .collect_vec();

        actual.sort_unstable();
        expected.sort_unstable();
        if expected.len() == 1 && actual.len() == 1 {
            similar_asserts::assert_eq!(expected[0].0, actual[0].0);
            similar_asserts::assert_eq!(expected[0].1, actual[0].1);
        } else {
            similar_asserts::assert_eq!(expected, actual);
        }
    }

    macro_rules! assert_symbols {
        ($name:ident, $schema:expr, $( $expected:expr ),* )=> {
            #[test]
            #[traced_test]
            fn $name() {
                assert_symbols($schema, vec![$( $expected, )*]);
            }
        };
    }

    assert_symbols!(empty_schema, "",);

    assert_symbols!(
        empty_namespace,
        "namespace Test {}",
        ("Test", "namespace Test {}")
    );

    assert_symbols!(
        multiple_namespaces,
        "namespace Test {} namespace Another {}",
        ("Test", "namespace Test {}"),
        ("Another", "namespace Another {}")
    );

    assert_symbols!(
        namespace_with_entity,
        "namespace Test { entity User; }",
        ("Test", "namespace Test { entity User; }"),
        ("Test::User", "entity User;")
    );

    assert_symbols!(
        namespace_with_common_type,
        "namespace Test { type Role = { name: String }; }",
        ("Test", "namespace Test { type Role = { name: String }; }"),
        ("Role", "{ name: String }")
    );

    assert_symbols!(
        namespace_with_action,
        "namespace Test { entity Person, Thing; action \"view\" appliesTo { principal: Person, resource: Thing }; }",
        ("Test", "namespace Test { entity Person, Thing; action \"view\" appliesTo { principal: Person, resource: Thing }; }"),
        ("Test::Action::\"view\"", "\"view\""),
        ("Test::Person", "entity Person, Thing;"),
        ("Test::Thing", "entity Person, Thing;")
    );

    assert_symbols!(
        namespace_with_multiple_elements,
        "namespace Test {
            type Role = { name: String };
            entity User = { role: Role };
            action \"view\" appliesTo { principal: User, resource: User };
        }",
        (
            "Test",
            "namespace Test {
            type Role = { name: String };
            entity User = { role: Role };
            action \"view\" appliesTo { principal: User, resource: User };
        }"
        ),
        ("Role", "{ name: String }"),
        ("Test::User", "entity User = { role: Role };"),
        ("Test::Action::\"view\"", "\"view\"",)
    );

    assert_symbols!(
        top_level_entity,
        "entity User = { name: String };",
        ("User", "entity User = { name: String };")
    );

    assert_symbols!(
        top_level_common_type,
        "type Role = { name: String };",
        ("Role", "{ name: String }")
    );

    assert_symbols!(
        top_level_action,
        "entity E; action \"view\" appliesTo { principal: E, resource: E };",
        ("Action::\"view\"", "\"view\""),
        ("E", "entity E;")
    );

    assert_symbols!(
        mixed_top_level_and_namespace,
        "entity OuterUser = { name: String };
         namespace App {
             entity User = { role: String };
         }",
        ("OuterUser", "entity OuterUser = { name: String };"),
        ("App::User", "entity User = { role: String };"),
        (
            "App",
            "namespace App {
             entity User = { role: String };
         }"
        )
    );

    assert_symbols!(
        two_elem_namespace,
        "namespace Outer::Inner {
            entity User;
            action Act;
        }",
        (
            "Outer::Inner",
            "namespace Outer::Inner {
            entity User;
            action Act;
        }"
        ),
        ("Outer::Inner::User", "entity User;"),
        ("Outer::Inner::Action::\"Act\"", "Act")
    );

    assert_symbols!(
        entity_with_attributes,
        "entity User = {
            name: String,
            email: String,
            age: Long,
            isActive: Bool
        };",
        (
            "User",
            "entity User = {
            name: String,
            email: String,
            age: Long,
            isActive: Bool
        };"
        )
    );

    assert_symbols!(
        action_with_context,
        "entity User, Book; action \"purchase\" appliesTo {
            principal: User,
            resource: Book,
            context: {
                amount: Long,
                currency: String
            }
        };",
        ("Action::\"purchase\"", "\"purchase\""),
        ("Book", "entity User, Book;"),
        ("User", "entity User, Book;")
    );

    assert_symbols!(
        common_type_with_record,
        "type Address = {
            street: String,
            city: String,
            zipCode: String,
            country: String
        };",
        (
            "Address",
            "{
            street: String,
            city: String,
            zipCode: String,
            country: String
        }"
        )
    );

    assert_symbols!(
        entity_with_parents,
        "entity User = {};
         entity Admin in User = {
            permissions: Set<String>
         };",
        ("User", "entity User = {};"),
        (
            "Admin",
            "entity Admin in User = {
            permissions: Set<String>
         };"
        )
    );

    assert_symbols!(
        entity_namespace_name_collision,
        "namespace N {}
         entity N;",
        ("N", "namespace N {}"),
        ("N", "entity N;")
    );

    assert_symbols!(
        entity_action_name_collision,
        "action N;
         entity N;",
        ("Action::\"N\"", "N"),
        ("N", "entity N;")
    );
}
