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

use cedar_policy_core::{ast::AnyId, parser::text_to_cst::parse_policies_tolerant};
use tower_lsp_server::lsp_types::Range;

use crate::utils::{ranges_intersect, ToRange};

#[derive(Debug, serde::Serialize)]
pub(crate) struct QuickPickItem {
    pub(crate) label: String,
    pub(crate) selected: bool,
    pub(crate) range: Range,
}

pub(crate) fn quickpick_list(
    policies: &str,
    selected_range: Range,
) -> anyhow::Result<Vec<QuickPickItem>> {
    let policies =
        parse_policies_tolerant(policies).and_then(|policies| policies.to_policyset_tolerant())?;

    let items = policies
        .into_policies()
        .filter_map(|policy| {
            let src_range = policy.loc()?.to_range();
            let id_annotation_key = AnyId::from_str("id").ok()?;
            let id = policy
                .annotation(&id_annotation_key)
                .map_or_else(|| policy.id().to_string(), |a| a.val.to_string());
            Some(QuickPickItem {
                label: id,
                selected: ranges_intersect(&selected_range, &src_range),
                range: src_range,
            })
        })
        .collect::<Vec<_>>();

    Ok(items)
}

#[cfg(test)]
mod test {
    use itertools::Itertools;
    use tower_lsp_server::lsp_types::{Position, Range};
    use tracing_test::traced_test;

    use super::quickpick_list;

    #[track_caller]
    fn assert_quickpick_selection(
        policies: &str,
        selection_line: u32,
        selection_char: u32,
        mut expected_selected_labels: Vec<&str>,
    ) {
        let selected_range = Range {
            start: Position::new(selection_line, selection_char),
            end: Position::new(selection_line, selection_char + 1),
        };

        let result = quickpick_list(policies, selected_range);
        assert!(
            result.is_ok(),
            "Expected Ok result, got Err: {:?}",
            result.err()
        );

        let items = result.unwrap();
        let actual_selected_labels = items
            .iter()
            .filter(|item| item.selected)
            .map(|item| item.label.as_str())
            .sorted()
            .collect_vec();
        expected_selected_labels.sort_unstable();

        assert_eq!(
            expected_selected_labels, actual_selected_labels,
            "Selected items don't match expected"
        );
    }

    macro_rules! assert_quickpick_selection {
        ($name:ident, $policies:expr, $line:expr, $char:expr, $( $expected:expr ),*  )=> {
            #[test]
            #[traced_test]
            fn $name() {
                assert_quickpick_selection($policies, $line, $char, vec![$( $expected, )*]);
            }
        };
    }

    assert_quickpick_selection!(empty_policy_set_returns_empty_list, "", 0, 0,);

    assert_quickpick_selection!(
        single_policy_without_id,
        "permit(principal, action, resource);",
        0,
        0,
        "policy0"
    );

    assert_quickpick_selection!(
        single_policy_with_id,
        "@id(\"my_policy\") permit(principal, action, resource);",
        0,
        0,
        "my_policy"
    );

    assert_quickpick_selection!(
        multiple_policies_with_selection_on_second,
        "\
            @id(\"policy_a\") permit(principal, action, resource);\n\
            @id(\"policy_b\") permit(principal, action, resource);\n\
            @id(\"policy_c\") permit(principal, action, resource);\
        ",
        1,
        5,
        "policy_b"
    );

    assert_quickpick_selection!(
        no_selection_in_range,
        "\
            @id(\"policy_a\") permit(principal, action, resource);\n\
            @id(\"policy_b\") permit(principal, action, resource);\
        ",
        3,
        0,
    );

    assert_quickpick_selection!(
        mixed_policies_with_and_without_ids,
        "\
            permit(principal, action, resource);\n\
            @id(\"named_policy\") permit(principal, action, resource);\n\
            forbid(principal, action, resource);\
        ",
        1,
        5,
        "named_policy"
    );
}
