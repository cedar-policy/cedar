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

use std::borrow::Cow;

use lsp_types::Position;

// INVARIANT: The length of this marker in characters and bytes must be equal. All characters must be encoded in 1 byte.
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
) -> (Cow<'_, str>, Position) {
    let mut phantom_text = Cow::Borrowed(original_text);
    let mut adjusted_position = original_position;
    // Insert phantom tokens and adjust position if needed
    for (dot_number, dot_position) in incomplete_dot_positions(original_text).enumerate() {
        let insert_byte_offset = dot_position.byte_index + 1 + (dot_number * LSP_MARKER.len());
        phantom_text
            .to_mut()
            .insert_str(insert_byte_offset, LSP_MARKER);

        // Only adjust cursor position if we're on the same line
        if dot_position.line_number as u32 == original_position.line
            && dot_position.char_index_in_line + 1 < original_position.character as usize
        {
            adjusted_position.character += LSP_MARKER.len() as u32;
        }
    }

    (phantom_text, adjusted_position)
}

#[derive(Debug, Clone)]
struct DotPosition {
    /// Line number where we found the dot.
    line_number: usize,
    /// Byte index of the dot, _from the beginning of the string_.
    byte_index: usize,
    /// Character index of the dot, _in its line_
    char_index_in_line: usize,
}

// Returns an iterator over the position of "incomplete" `.` expressions. The
// expressions is considered incomplete followed by an identifier for the
// attribute being accessed.
fn incomplete_dot_positions(text: &str) -> impl Iterator<Item = DotPosition> + '_ {
    // `scan` accumulates the byte offset for the start of each line while
    // `enumerate` gives us the number of each line.
    let lines_with_number_and_byte_offset = text
        .lines()
        .scan(0_usize, |acc, line| {
            let line_start = *acc;
            *acc += line.len() + 1;
            Some((line_start, line))
        })
        .enumerate();

    lines_with_number_and_byte_offset.flat_map(|(line_number, (line_start_byte, line))| {
        // `char_indices` gives us the byte index of each character (in the line)
        // while `enumerate` gives us the number of characters into the line.
        // These are different if characters are encoded with multiple bytes.
        let chars_with_character_and_byte_offset = line.char_indices().enumerate();

        chars_with_character_and_byte_offset
            .zip(line.chars().skip(1).map(Some).chain(std::iter::once(None)))
            .filter(|((_, (_, c)), next_c)| {
                *c == '.'
                    && next_c
                        .is_none_or(|next_c| next_c.is_whitespace() || matches!(next_c, '}' | ')'))
            })
            .map(
                move |((char_index_in_line, (byte_offset_in_line, _)), _)| DotPosition {
                    line_number,
                    byte_index: line_start_byte + byte_offset_in_line,
                    char_index_in_line,
                },
            )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cool_asserts::assert_matches;
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
    fn test_preprocess_correct_unchanged() {
        let (new_policy, position) = preprocess_policy(
            r"permit(principal, action, resource) when { principal.hello && resource.bar };",
            Position::new(0, 0),
        );
        assert_eq!(
            new_policy,
            r"permit(principal, action, resource) when { principal.hello && resource.bar };"
        );
        assert_matches!(new_policy, Cow::Borrowed(_));
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

    #[test]
    fn test_preprocess_unicode() {
        // '¡' is encoded with 2 bytes, so this test will fail if we confuse byte index with character index
        let (new_policy, position) = preprocess_policy(
            "permit(principal, action, resource) when { principal[\"¡¡¡¡¡¡¡¡\"] && action. };",
            Position::new(0, 76),
        );
        assert_eq!(
            new_policy,
            "permit(principal, action, resource) when { principal[\"¡¡¡¡¡¡¡¡\"] && action.__CEDAR_LSP };",
        );
        assert_eq!(position, Position::new(0, 76 + LSP_MARKER.len() as u32));
    }
}
