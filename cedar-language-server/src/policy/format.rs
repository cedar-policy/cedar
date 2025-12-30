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

use cedar_policy_formatter::{policies_str_to_pretty, Config};
use tower_lsp_server::ls_types::{Position, Range, TextEdit};

/// Formats a Cedar policy according to standard style guidelines.
///
/// # Returns
/// - `Some(Vec<TextEdit>)` with a single edit covering the entire document when successful
/// - `None` if formatting fails due to invalid policy syntax
#[must_use]
pub(crate) fn format_policy(policy: &str) -> Option<Vec<TextEdit>> {
    let lines = policy.lines().count();
    let result = policies_str_to_pretty(
        policy,
        &Config {
            line_width: 80,
            indent_width: 4,
        },
    )
    .ok()?;
    let edit = TextEdit {
        range: Range {
            start: Position {
                line: 0,
                character: 0,
            },
            end: Position {
                line: lines as u32,
                character: 0,
            },
        },
        new_text: result,
    };

    Some(vec![edit])
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn format_policy_idempotent(policy in "permit\\(principal, action, resource\\);") {
            if let Some(edits) = format_policy(&policy) {
                let formatted = &edits[0].new_text;
                if let Some(edits2) = format_policy(formatted) {
                    prop_assert_eq!(&edits2[0].new_text, formatted, "formatting should be idempotent");
                }
            }
        }

        #[test]
        fn format_policy_range_covers_input(policy in "permit\\(principal, action, resource\\);\n?") {
            if let Some(edits) = format_policy(&policy) {
                let range = &edits[0].range;
                prop_assert_eq!(range.start.line, 0);
                prop_assert_eq!(range.start.character, 0);
                let input_lines = policy.lines().count() as u32;
                prop_assert!(range.end.line >= input_lines.saturating_sub(1),
                    "end line {} should cover input lines {}", range.end.line, input_lines);
            }
        }
    }
}
