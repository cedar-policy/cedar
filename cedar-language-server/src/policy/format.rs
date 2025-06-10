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
use lsp_types::{Position, Range, TextEdit};

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
