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

use std::str::FromStr;

use cedar_policy_core::{
    ast::{AnyId, Template},
    parser::text_to_cst::parse_policies_tolerant,
};
use tower_lsp_server::lsp_types::{DocumentSymbol, SymbolKind};

use crate::{lsp::new_symbol, utils::ToRange};

/// Generates document symbols for Cedar policies in a document.
///
/// This function analyzes a Cedar policy document and creates document symbols for
/// each policy it contains, making them available for navigation in IDEs and editors.
/// Policy symbols include their identifiers and locations within the document.
///
/// # Policy Identification
///
/// Policies are identified by:
/// 1. An explicit ID from an `@id` annotation if present
/// 2. The policy's internal ID if no annotation is provided
///
/// For example:
/// ```cedar
/// permit(principal, action, resource)  // Identified as "policy0" or similar
/// when { context.valid };
///
/// @id("myPolicy")
/// permit(principal, action, resource);  // Identified as "myPolicy"
/// ```
///
/// # Returns
///
/// An `Option<Vec<DocumentSymbol>>` containing:
/// - A vector of document symbols for each policy and policy template
/// - `None` if the document couldn't be parsed as a valid policy set
///
/// # LSP Integration
///
/// These symbols can be returned directly in response to a
/// `textDocument/documentSymbol` request in a language server implementation.
/// They provide navigation targets for the document outline and "go to symbol"
/// functionality in IDEs.
pub(crate) fn policy_set_symbols(policy_str: &str) -> Option<Vec<DocumentSymbol>> {
    let policies = parse_policies_tolerant(policy_str)
        .ok()
        .and_then(|policies| policies.to_policyset_tolerant().ok())?;

    let template_ranges = policies.templates().filter_map(to_symbol);

    let ranges = policies
        .policies()
        .filter_map(|policy| to_symbol(policy.template()))
        .chain(template_ranges)
        .collect::<Vec<_>>();

    Some(ranges)
}

fn to_symbol(policy: &Template) -> Option<DocumentSymbol> {
    let src_range = policy.loc()?.to_range();
    let id_annotation_key = AnyId::from_str("id").ok()?;
    let id = policy
        .annotation(&id_annotation_key)
        .map_or_else(|| policy.id().to_string(), |a| a.val.to_string());

    Some(new_symbol(id, src_range, SymbolKind::FUNCTION))
}

#[cfg(test)]
mod test {
    use itertools::Itertools;

    use crate::{policy::policy_set_symbols, utils::tests::slice_range};
    use tracing_test::traced_test;

    #[track_caller]
    fn assert_symbols(policy: &str, mut expected: Vec<(&str, &str)>) {
        let syms = policy_set_symbols(policy).unwrap();
        let mut actual = syms
            .iter()
            .map(|sym| (sym.name.as_str(), slice_range(policy, sym.range)))
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
        ($name:ident, $policy:expr, $( $expected:expr ),* )=> {
            #[test]
            #[traced_test]
            fn $name() {
                assert_symbols($policy, vec![$( $expected, )*]);
            }
        };
    }

    assert_symbols!(empty_policy_set, "",);

    assert_symbols!(
        single_empty_policy,
        "permit(principal, action, resource);",
        ("policy0", "permit(principal, action, resource);")
    );

    assert_symbols!(
        two_empty_policies,
        "permit(principal, action, resource);\npermit(principal, action, resource//comment\n);",
        ("policy0", "permit(principal, action, resource);"),
        ("policy1", "permit(principal, action, resource//comment\n);")
    );

    assert_symbols!(
        single_non_empty_policy,
        "permit(principal, action, resource) when {\n  principal.is_frobnicated || resource.borked\n};",
        ("policy0", "permit(principal, action, resource) when {\n  principal.is_frobnicated || resource.borked\n};")
    );

    assert_symbols!(
        single_empty_policy_with_id,
        "@id(\"\")permit(principal, action, resource);",
        ("", "@id(\"\")permit(principal, action, resource);")
    );

    assert_symbols!(
        two_empty_policies_with_id,
        "@id(\"\")permit(principal, action, resource);\n@id(\"another\")permit(principal, action, resource);",
        ("", "@id(\"\")permit(principal, action, resource);"),
        ("another", "@id(\"another\")permit(principal, action, resource);")
    );

    assert_symbols!(
        single_template,
        "permit(principal, action, resource == ?resource);",
        (
            "policy0",
            "permit(principal, action, resource == ?resource);"
        )
    );

    assert_symbols!(
        template_and_policy,
        "permit(principal, action, resource == ?resource);\npermit(principal, action, resource);",
        (
            "policy0",
            "permit(principal, action, resource == ?resource);"
        ),
        ("policy1", "permit(principal, action, resource);")
    );
}
