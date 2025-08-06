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

use tower_lsp_server::lsp_types::Position;

pub(crate) const LSP_MARKER: &str = "__CEDAR_LSP";

/// Preprocesses Cedar policy text to handle incomplete expressions for language server processing.
///
/// This function identifies trailing dot operators (`.`) that aren't followed by property names,
/// which typically occur when a user is typing a property access expression. It appends a special
/// marker token (`__CEDAR_LSP`) to these dots to transform incomplete property accesses into
/// syntactically valid expressions that can be processed by the Cedar parser.
///
/// # Arguments
///
/// * `original_text` - The raw Cedar policy text containing potential incomplete property accesses
/// * `original_position` - The cursor position in the editor, which will be adjusted if necessary
///
/// # Returns
///
/// A tuple containing:
/// * The modified policy text with the marker token added after trailing dots
/// * The adjusted cursor position accounting for any inserted tokens
///
/// # Example
///
/// For a policy statement like:
/// ```cedar
/// permit(principal, action, resource) when { principal.hello && action. };
/// ```
///
/// The function transforms it to:
/// ```cedar
/// permit(principal, action, resource) when { principal.hello && action.__CEDAR_LSP };
/// ```
///
/// If the cursor was positioned after the trailing dot, the position would be adjusted
/// to account for the inserted marker.
///
/// This is a preprocessing step for language server features and doesn't affect
/// actual Cedar policy execution.
pub(crate) fn preprocess_policy(
    original_text: &str,
    original_position: Position,
) -> (String, Position) {
    let mut phantom_text = original_text.to_string();
    let mut adjusted_position = original_position;

    // Find all trailing dots in the entire text
    let positions: Vec<(usize, usize)> = original_text
        .lines()
        .enumerate()
        .flat_map(|(line_num, line)| {
            let line_start = original_text
                .lines()
                .take(line_num)
                .map(|l| l.len() + 1)
                .sum::<usize>();

            line.char_indices()
                .filter(|(i, c)| {
                    *c == '.'
                        && line.chars().nth(i + 1).is_none_or(|next| {
                            next.is_whitespace() || next == '\n' || next == '}' || next == ')'
                        })
                })
                .map(move |(i, _)| (line_start + i, line_num))
        })
        .collect();

    // Insert phantom tokens and adjust position if needed
    let mut offset = 0;
    for (pos, line_num) in positions {
        let insert_pos = pos + 1 + offset;

        // Only adjust cursor position if we're on the same line
        if line_num as u32 == original_position.line {
            // Calculate the position relative to the line start
            let line_start = if original_text.lines().count() > 1 {
                original_text
                    .lines()
                    .take(line_num)
                    .map(|l| l.len() + 1)
                    .sum::<usize>()
            } else {
                0
            };

            let pos_in_line = pos - line_start + 1;

            if pos_in_line < original_position.character as usize {
                adjusted_position.character += LSP_MARKER.len() as u32;
            }
        }

        phantom_text.insert_str(insert_pos, LSP_MARKER);
        offset += LSP_MARKER.len();
    }

    (phantom_text, adjusted_position)
}

#[cfg(test)]
mod tests {
    use super::*;
    use similar_asserts::assert_eq;

    #[test]
    fn test_preprocess_behind_position() {
        let (new_policy, position) = preprocess_policy(
            r"permit(principal, action, resource) when { principal.hello && action. };",
            Position::new(0, 0),
        );
        assert_eq!(
            new_policy,
            r"permit(principal, action, resource) when { principal.hello && action.__CEDAR_LSP };"
        );

        assert_eq!(position, Position::new(0, 0));
    }

    #[test]
    fn test_preprocess_modify_position() {
        let (new_policy, position) = preprocess_policy(
            r"permit(principal, action, resource) when { principal.hello && action. };",
            Position::new(0, 69),
        );
        assert_eq!(
            new_policy,
            r"permit(principal, action, resource) when { principal.hello && action.__CEDAR_LSP };"
        );

        assert_eq!(position, Position::new(0, 69));
    }

    #[test]
    fn preprocess_multiple_dots_increment_position() {
        let (new_policy, position) = preprocess_policy(
            r"permit(principal, action, resource) when { principal.hello && action. && resource. };",
            Position::new(0, 82),
        );
        assert_eq!(
            new_policy,
            r"permit(principal, action, resource) when { principal.hello && action.__CEDAR_LSP && resource.__CEDAR_LSP };"
        );

        assert_eq!(position, Position::new(0, 82 + LSP_MARKER.len() as u32));
    }

    #[test]
    fn preprocess_multiple_dots_new_line() {
        let (new_policy, position) = preprocess_policy(
            r"permit(principal, action, resource) when { principal.hello && action. &&
            resource.
            };",
            Position::new(1, 22),
        );
        assert_eq!(
            new_policy,
            r"permit(principal, action, resource) when { principal.hello && action.__CEDAR_LSP &&
            resource.__CEDAR_LSP
            };"
        );

        assert_eq!(position, Position::new(1, 22 + LSP_MARKER.len() as u32));
    }

    #[test]
    fn preprocess_multiple_dots_on_same_new_line() {
        let (new_policy, position) = preprocess_policy(
            r"permit(principal, action, resource) when { principal.hello && action. &&
            resource. && context.
            };",
            Position::new(1, 106),
        );
        assert_eq!(
            new_policy,
            r"permit(principal, action, resource) when { principal.hello && action.__CEDAR_LSP &&
            resource.__CEDAR_LSP && context.__CEDAR_LSP
            };"
        );

        assert_eq!(
            position,
            Position::new(1, 106 + (LSP_MARKER.len() as u32 * 2))
        );
    }

    #[test]
    fn test_dot_with_comments() {
        let (new_policy, position) = preprocess_policy(
            "permit(principal, action, resource) when {\n    // A comment\n    principal. // Another comment\n}",
            Position::new(2, 13),
        );
        assert_eq!(
            new_policy,
            "permit(principal, action, resource) when {\n    // A comment\n    principal.__CEDAR_LSP // Another comment\n}"
        );
        assert_eq!(position, Position::new(2, 13));
    }

    #[test]
    fn test_many_consecutive_dots() {
        let (new_policy, position) = preprocess_policy(
            "permit(principal, action, resource) when { principal. . . . };",
            Position::new(0, 55),
        );
        assert_eq!(
            new_policy,
            "permit(principal, action, resource) when { principal.__CEDAR_LSP .__CEDAR_LSP .__CEDAR_LSP .__CEDAR_LSP };"
        );
        assert_eq!(position, Position::new(0, 55 + LSP_MARKER.len() as u32));
    }
}
