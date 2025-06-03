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
