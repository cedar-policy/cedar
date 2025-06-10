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

use cedar_policy_core::parser::text_to_cst::parse_policies_tolerant;
use lsp_types::FoldingRange;

use crate::utils::ToRange;

/// Generates folding ranges for Cedar policies in a document.
///
/// This function analyzes a Cedar policy document and identifies regions that
/// can be folded in an editor or IDE, such as policy blocks. Folding ranges
/// allow users to collapse sections of the document for better readability
/// when working with large policy sets.
///
/// # Returns
///
/// An `Option<Vec<FoldingRange>>` containing:
/// - A vector of folding ranges corresponding to individual policies in the document
/// - `None` if the document couldn't be parsed or contains no valid policies
///
/// # Example
///
/// For a document containing multiple policies:
///
/// ```cedar
/// permit(principal, action, resource)
/// when { principal.department == "Engineering" };
///
/// forbid(principal, action, resource is Document)
/// when { resource.status == "Confidential" };
/// ```
///
/// The function will return folding ranges that allow collapsing each policy independently.
///
/// # LSP Integration
///
/// These folding ranges can be returned directly in response to a
/// `textDocument/foldingRange` request in a language server implementation.
/// Each range includes line information but not character positions, as Cedar
/// policy folding is typically done at the policy block level.
#[must_use]
pub(crate) fn fold_policy_set(policy_str: &str) -> Option<Vec<FoldingRange>> {
    let policies = parse_policies_tolerant(policy_str)
        .ok()
        .and_then(|policies| policies.node)?;

    let ranges = policies
        .0
        .into_iter()
        .filter_map(|policy| {
            let src_range = policy.loc?.to_range();

            Some(FoldingRange {
                start_line: src_range.start.line,
                start_character: None,
                end_line: src_range.end.line,
                end_character: None,
                kind: Some(lsp_types::FoldingRangeKind::Region),
                collapsed_text: None,
            })
        })
        .collect::<Vec<_>>();

    Some(ranges)
}

#[cfg(test)]
mod test {
    use crate::policy::fold_policy_set;
    use itertools::Itertools;
    use tracing_test::traced_test;

    #[track_caller]
    fn assert_folding_ranges(policy: &str, expected: Vec<(u32, u32)>) {
        let ranges = fold_policy_set(policy).unwrap();
        let actual = ranges
            .iter()
            .map(|range| (range.start_line, range.end_line))
            .sorted()
            .collect_vec();
        let expected = expected.into_iter().sorted().collect_vec();
        similar_asserts::assert_eq!(expected, actual);
    }

    macro_rules! assert_folding_ranges {
        ($name:ident, $policy:expr, $( $expected:expr ),* )=> {
            #[test]
            #[traced_test]
            fn $name() {
                assert_folding_ranges($policy, vec![$( $expected, )*]);
            }
        };
    }

    assert_folding_ranges!(
        single_line_policy,
        "permit(principal, action, resource);",
        (0, 0)
    );

    assert_folding_ranges!(
        single_line_policy_leading_newlines,
        "\n\npermit(principal, action, resource);",
        (2, 2)
    );

    assert_folding_ranges!(
        single_line_policy_trailing_newlines,
        "permit(principal, action, resource);\n\n",
        (0, 0)
    );

    assert_folding_ranges!(
        multi_line_policy,
        "permit(principal, action, resource)\nwhen { principal.department == \"Engineering\" };",
        (0, 1)
    );

    assert_folding_ranges!(
        multi_line_policy_with_annotation,
        "@id(\"foo\")\npermit(principal, action, resource);",
        (0, 1)
    );

    assert_folding_ranges!(
        two_policies,
        "permit(principal, action, resource);\nforbid(principal, action, resource);",
        (0, 0),
        (1, 1)
    );

    assert_folding_ranges!(
        complex_policy_with_conditions,
        "permit(principal, action, resource)\nwhen {\n  principal.is_frobnicated ||\n  resource.borked\n};",
        (0, 4)
    );

    assert_folding_ranges!(
        policy_with_comments,
        "// This is a policy\npermit(principal, action, resource)\n// with a condition\nwhen {\n  true\n};",
        (1, 5)
    );

    assert_folding_ranges!(
        policy_with_template,
        "permit(principal, action, resource == ?resource);",
        (0, 0)
    );

    assert_folding_ranges!(
        multiple_complex_policies,
        "permit(principal, action, resource)\nwhen {\n  principal.attr == \"value\"\n};\n\nforbid(principal, action, resource)\nwhen {\n  resource.sensitive == true\n};",
        (0, 3),
        (5, 8)
    );

    assert_folding_ranges!(
        same_line_policies,
        "permit(principal, action, resource); permit(principal, action, resource);",
        (0, 0),
        (0, 0)
    );

    assert_folding_ranges!(invalid_policy, "permit(foo, action, resource);", (0, 0));

    assert_folding_ranges!(empty_policy_set, "",);
}
