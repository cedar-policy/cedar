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

use std::fmt::Write;

use cedar_policy_core::{ast::Template, parser::Loc};
use lsp_types::{Position, Range};
use miette::SourceSpan;
use smol_str::SmolStr;

pub(crate) trait ToRange {
    fn to_range(&self) -> Range;
}

impl ToRange for Loc {
    fn to_range(&self) -> Range {
        to_range(&self.span, &self.src)
    }
}

impl ToRange for Box<Loc> {
    fn to_range(&self) -> Range {
        to_range(&self.span, &self.src)
    }
}

/// Defines the length-zero source range occurring at the start of the file.
/// Used as the source range we don't have anything better available.
pub(crate) const START_RANGE: Range = Range {
    start: Position {
        line: 0,
        character: 0,
    },
    end: Position {
        line: 0,
        character: 0,
    },
};

fn to_lsp_severity(severity: miette::Severity) -> lsp_types::DiagnosticSeverity {
    match severity {
        miette::Severity::Advice => lsp_types::DiagnosticSeverity::INFORMATION,
        miette::Severity::Warning => lsp_types::DiagnosticSeverity::WARNING,
        miette::Severity::Error => lsp_types::DiagnosticSeverity::ERROR,
    }
}

/// Generic routine for converting a `miette::Diagnostic` into a diagnostic for
/// the LSP. This function only return diagnostics constructed with `new_simple`
/// (a source range with a message). Errors wanting to provide more information
/// can use this function while building a richer diagnostic with something like
/// `to_lsp_diagnostic(error, src).map(|d| Diagnostic { data: my_data, ..d })`
pub(crate) fn to_lsp_diagnostics<'a>(
    diagnostic: &'a dyn miette::Diagnostic,
    src: &'a str,
) -> Vec<lsp_types::Diagnostic> {
    let mut message = diagnostic.to_string();
    if let Some(source) = diagnostic.source() {
        write!(&mut message, ". {source}").unwrap();
    }
    if let Some(help) = diagnostic.help() {
        write!(&mut message, ". {help}").unwrap();
    }

    let mut diagnostics = Vec::new();
    let severity = diagnostic.severity().map(to_lsp_severity);
    if let Some(labels) = diagnostic.labels() {
        diagnostics.extend(labels.map(move |l| lsp_types::Diagnostic {
            severity,
            ..lsp_types::Diagnostic::new_simple(to_range(l.inner(), src), message.clone())
        }));
    } else {
        diagnostics.push(lsp_types::Diagnostic {
            severity,
            ..lsp_types::Diagnostic::new_simple(START_RANGE, message)
        });
    }
    if let Some(related) = diagnostic.related() {
        diagnostics.extend(related.flat_map(|d| to_lsp_diagnostics(d, src)));
    }
    diagnostics
}

pub(crate) fn to_range(source_span: &SourceSpan, src: &str) -> Range {
    let text = &src[..source_span.offset()];
    let start_line = text.chars().filter(|&c| c == '\n').count();
    let start_col = text.chars().rev().take_while(|&c| c != '\n').count();

    let end = source_span.offset() + source_span.len();
    let text = &src[..end];
    let end_line = text.chars().filter(|&c| c == '\n').count();
    let end_col = text.chars().rev().take_while(|&c| c != '\n').count();

    Range {
        start: Position {
            line: start_line as u32,
            character: start_col as u32,
        },
        end: Position {
            line: end_line as u32,
            character: end_col as u32,
        },
    }
}

pub(crate) fn get_char_at_position(position: Position, src: &str) -> Option<char> {
    src.lines()
        .nth(position.line as usize)?
        .chars()
        .nth(position.character as usize)
}

pub(crate) fn position_within_loc<'a, R, I>(position: Position, range: I) -> bool
where
    R: ToRange + 'a,
    I: Into<Option<&'a R>>,
{
    let Some(range) = range.into() else {
        return false;
    };
    let range = range.to_range();
    position.line >= range.start.line
        && position.line <= range.end.line
        && (position.line != range.start.line || position.character >= range.start.character)
        && (position.line != range.end.line || position.character <= range.end.character)
}

pub(crate) fn get_word_at_position(position: Position, text: &str) -> Option<(&str, Range)> {
    // Get the line at the cursor position
    let line = text.lines().nth(position.line as usize)?;
    let char_pos = position.character as usize;

    // Check if we're within the line bounds
    if char_pos > line.len() {
        return None;
    }

    // Helper function to check if a character is part of a word
    let is_word_char = |c: char| c.is_alphanumeric() || c == '_' || c == ':' || c == '=';

    // Find the start of the word
    let start = line[..char_pos]
        .char_indices()
        .rev()
        .find(|(_, c)| !is_word_char(*c))
        .map_or(0, |(i, _)| i + 1);

    // Find the end of the word
    let end = line[char_pos..]
        .char_indices()
        .find(|(_, c)| !is_word_char(*c))
        .map_or(line.len(), |(i, _)| char_pos + i);

    // If we're not actually on a word, return None
    if start >= end {
        return None;
    }

    let word = &line[start..end];
    if word.is_empty() {
        return None;
    }

    let range = Range {
        start: Position {
            line: position.line,
            character: start as u32,
        },
        end: Position {
            line: position.line,
            character: end as u32,
        },
    };

    Some((word, range))
}

pub(crate) fn get_operator_at_position(position: Position, text: &str) -> Option<(&str, Range)> {
    // Get the line at the cursor position
    let line = text.lines().nth(position.line as usize)?;
    let char_pos = position.character as usize;

    // Check if we're within the line bounds
    if char_pos > line.len() {
        return None;
    }

    // Define all possible operators
    let operators = [
        "&&", "||", "!=", "==", ">=", "<=", "!", "+", "-", "*", "<", ">",
    ];

    // Helper function to check if a character could be part of an operator
    let is_operator_char = |c: char| "!&|=<>+-*".contains(c);

    // Find the start of the operator
    let start = line[..char_pos]
        .char_indices()
        .rev()
        .find(|(_, c)| !is_operator_char(*c))
        .map_or(0, |(i, _)| i + 1);

    // Find the end of the operator
    let end = line[char_pos..]
        .char_indices()
        .find(|(_, c)| !is_operator_char(*c))
        .map_or(line.len(), |(i, _)| char_pos + i);

    // If we're not actually on an operator, return None
    if start >= end {
        return None;
    }

    let potential_operator = line[start..end].to_string();

    // Check if the extracted string is a valid operator
    let valid_operator = operators.iter().find(|&&op| {
        // Check if our extracted string contains this operator
        if potential_operator.contains(op) {
            // Find the position of this operator in our extracted string
            if let Some(op_start) = potential_operator.find(op) {
                // Check if our cursor position is within this operator
                let absolute_op_start = start + op_start;
                let absolute_op_end = absolute_op_start + op.len();
                return char_pos >= absolute_op_start && char_pos <= absolute_op_end;
            }
        }
        false
    });

    valid_operator.map(|&op| {
        // Find the exact position of the operator
        let op_start = potential_operator.find(op).unwrap();
        let absolute_start = start + op_start;
        let absolute_end = absolute_start + op.len();

        let range = Range {
            start: Position {
                line: position.line,
                character: absolute_start as u32,
            },
            end: Position {
                line: position.line,
                character: absolute_end as u32,
            },
        };

        (op, range)
    })
}

pub(crate) fn is_cursor_within_policy_scope(policy_text: &str, cursor_position: Position) -> bool {
    // Parse the policy to find the scope boundaries
    let lines: Vec<&str> = policy_text.lines().collect();

    // Early return if the cursor is on a line that doesn't exist
    if (cursor_position.line as usize) >= lines.len() {
        return false;
    }

    // Track policy scope boundaries for all policies
    let mut policy_scopes: Vec<(Position, Position)> = Vec::new();
    let mut policy_start_pos: Option<Position> = None;
    let mut paren_depth = 0;
    let mut in_effect_keyword = false;

    // Identify effect keywords and their parentheses
    for (line_idx, line) in lines.iter().enumerate() {
        let mut char_idx = 0;

        while char_idx < line.len() {
            let substring = &line[char_idx..];

            // Check for effect keywords
            if !in_effect_keyword
                && (substring.starts_with("permit") || substring.starts_with("forbid"))
                && (char_idx == 0
                    || !line[..char_idx]
                        .trim_end()
                        .ends_with(|c: char| c.is_alphanumeric() || c == '_'))
            {
                in_effect_keyword = true;
                char_idx += 6;
                continue;
            }

            // If we've found an effect keyword, track parentheses
            if in_effect_keyword {
                match line.as_bytes()[char_idx] {
                    b'(' => {
                        paren_depth += 1;
                        if paren_depth == 1 {
                            policy_start_pos = Some(Position {
                                line: line_idx as u32,
                                character: char_idx as u32,
                            });
                        }
                    }
                    b')' => {
                        paren_depth -= 1;
                        if paren_depth == 0 && policy_start_pos.is_some() {
                            // Add this policy scope to our list
                            policy_scopes.push((
                                policy_start_pos.unwrap(),
                                Position {
                                    line: line_idx as u32,
                                    character: char_idx as u32,
                                },
                            ));
                            policy_start_pos = None;
                            in_effect_keyword = false;
                        }
                    }
                    _ => {}
                }
            }

            char_idx += 1;
        }
    }

    // Check if cursor is within any of the identified policy scopes
    for (start, end) in policy_scopes {
        // Cursor is after start position
        let after_start = cursor_position.line > start.line
            || (cursor_position.line == start.line && cursor_position.character > start.character);

        // Cursor is before end position
        let before_end = cursor_position.line < end.line
            || (cursor_position.line == end.line && cursor_position.character <= end.character);

        if after_start && before_end {
            return true;
        }
    }

    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyScopeVariable {
    Principal,
    Action,
    Resource,
    None,
}

#[derive(Debug, PartialEq)]
pub(crate) struct ScopeVariableInfo {
    pub(crate) variable_type: PolicyScopeVariable,
    pub(crate) text: SmolStr,
}

impl ScopeVariableInfo {
    pub(crate) fn is_in_principal_def(&self) -> bool {
        self.variable_type == PolicyScopeVariable::Principal
    }

    pub(crate) fn is_in_action_def(&self) -> bool {
        self.variable_type == PolicyScopeVariable::Action
    }

    pub(crate) fn is_in_resource_def(&self) -> bool {
        self.variable_type == PolicyScopeVariable::Resource
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn get_policy_scope_variable(
    policy_text: &str,
    cursor_position: Position,
) -> ScopeVariableInfo {
    let lines: Vec<&str> = policy_text.lines().collect();
    let cursor_line = cursor_position.line as usize;

    // First, identify all policy statements in the file
    let mut policy_scopes = Vec::new();
    let mut current_policy_start: Option<(usize, usize)> = None;
    let mut paren_depth = 0;
    let mut in_effect_keyword = false;

    for (line_idx, line) in lines.iter().enumerate() {
        let mut char_idx = 0;

        while char_idx < line.len() {
            let substring = &line[char_idx..];

            // Check for effect keywords
            if !in_effect_keyword
                && (substring.starts_with("permit") || substring.starts_with("forbid"))
                && (char_idx == 0
                    || !line[..char_idx]
                        .trim_end()
                        .ends_with(|c: char| c.is_alphanumeric() || c == '_'))
            {
                in_effect_keyword = true;
                char_idx += 6;
                continue;
            }

            // If we've found an effect keyword, track parentheses
            if in_effect_keyword {
                match line.as_bytes().get(char_idx) {
                    Some(b'(') => {
                        paren_depth += 1;
                        if paren_depth == 1 {
                            current_policy_start = Some((line_idx, char_idx));
                        }
                    }
                    Some(b')') => {
                        paren_depth -= 1;
                        if paren_depth == 0 && current_policy_start.is_some() {
                            // Add this policy scope to our list
                            policy_scopes
                                .push((current_policy_start.unwrap(), (line_idx, char_idx)));
                            current_policy_start = None;
                            in_effect_keyword = false;
                        }
                    }
                    _ => {}
                }
            }

            char_idx += 1;
        }
    }

    // Find the policy that contains the cursor
    let current_policy =
        policy_scopes
            .iter()
            .find(|&((start_line, start_char), (end_line, end_char))| {
                let after_start = cursor_line > *start_line
                    || (cursor_line == *start_line
                        && (cursor_position.character as usize) > *start_char);
                let before_end = cursor_line < *end_line
                    || (cursor_line == *end_line
                        && (cursor_position.character as usize) <= *end_char);
                after_start && before_end
            });

    if current_policy.is_none() {
        return ScopeVariableInfo {
            variable_type: PolicyScopeVariable::None,
            text: "".into(),
        };
    }

    let ((policy_start_line, policy_start_char), _) = *current_policy.unwrap();

    // Now find the commas within this policy to determine the variables
    let mut param_sections = Vec::new();
    let mut current_start = (policy_start_line, policy_start_char + 1); // +1 to skip the opening parenthesis
    let mut comma_positions = Vec::new();
    let mut paren_depth = 1; // Start at 1 because we're inside the opening parenthesis
    let mut bracket_depth = 0;

    'outer: for (line_num, line) in lines.iter().enumerate().skip(policy_start_line) {
        let start_char = if line_num == policy_start_line {
            policy_start_char + 1
        } else {
            0
        };

        for (char_pos, c) in line.chars().enumerate().skip(start_char) {
            match c {
                '(' => paren_depth += 1,
                ')' => {
                    paren_depth -= 1;
                    if paren_depth == 0 {
                        // Reached the closing parenthesis of this policy
                        param_sections.push((current_start, (line_num, char_pos)));
                        break 'outer;
                    }
                }
                '[' => bracket_depth += 1,
                ']' => bracket_depth -= 1,
                ',' if paren_depth == 1 && bracket_depth == 0 => {
                    // Only count commas at top level (not within arrays)
                    comma_positions.push((line_num, char_pos));
                    param_sections.push((current_start, (line_num, char_pos)));
                    current_start = (line_num, char_pos + 1);
                }
                _ => {}
            }
        }
    }

    // Determine which parameter section we're in based on cursor position
    let param_index = if comma_positions.is_empty() {
        0
    } else {
        let mut index = 0;
        for &(line, pos) in &comma_positions {
            if cursor_line < line
                || (cursor_line == line && cursor_position.character <= (pos as u32))
            {
                break;
            }
            index += 1;
        }
        index
    };

    // Extract the text for the current parameter section
    let text = if param_index < param_sections.len() {
        let ((start_line, start_pos), (end_line, end_pos)) = param_sections[param_index];
        if start_line == end_line {
            lines[start_line][start_pos..end_pos].trim().into()
        } else {
            // Handle multi-line parameters
            let mut text = String::new();
            for (line_num, item) in lines.iter().enumerate().take(end_line + 1).skip(start_line) {
                if line_num == start_line {
                    text.push_str(&item[start_pos..]);
                } else if line_num == end_line {
                    text.push_str(&item[..end_pos]);
                } else {
                    text.push_str(item);
                }
                text.push('\n');
            }
            text.trim().into()
        }
    } else {
        "".into()
    };

    let variable_type = match param_index {
        0 => PolicyScopeVariable::Principal,
        1 => PolicyScopeVariable::Action,
        2 => PolicyScopeVariable::Resource,
        _ => PolicyScopeVariable::None,
    };

    ScopeVariableInfo {
        variable_type,
        text,
    }
}

pub(crate) fn extract_common_type_name(type_dec_snippet: &str) -> Option<String> {
    // Find the type keyword at the beginning of the line
    if !type_dec_snippet.trim_start().starts_with("type ") {
        return None;
    }

    // Split the string by the '=' character
    let (type_name, _) = type_dec_snippet.split_once('=')?;

    // Extract the type name from the left part
    let type_name = type_name
        .trim()
        .strip_prefix("type ")? // Remove "type " prefix
        .trim(); // Trim any whitespace

    // Verify that the type name is valid
    if type_name.is_empty() {
        return None;
    }

    Some(type_name.to_string())
}

pub(crate) fn ranges_intersect(a: &Range, b: &Range) -> bool {
    a.start <= b.end && b.start <= a.end
}

pub(crate) trait GetPolicyText {
    fn get_text(&self) -> &str;
}

impl GetPolicyText for Template {
    fn get_text(&self) -> &str {
        self.loc()
            .map(|loc| &loc.src)
            .expect("Policy should have an LOC.")
    }
}

pub(crate) fn is_cursor_in_condition_braces(position: Position, source_text: &str) -> bool {
    #[derive(PartialEq)]
    enum State {
        Normal,
        InWhen,
        InUnless,
        InConditionBlock,
    }

    let mut state = State::Normal;
    let mut brace_level = 0;

    let line_pos = position.line as usize;
    let line_char = position.character as usize;

    // Convert to absolute position for easier processing
    let target_pos = source_text
        .lines()
        .take(line_pos)
        .map(|line| line.len() + 1) // +1 for the newline
        .sum::<usize>()
        + line_char;

    let mut pos = 0;
    let chars: Vec<char> = source_text.chars().collect();

    while pos < chars.len() && pos < target_pos {
        let c = chars[pos];

        match state {
            State::Normal => {
                // Check for when/unless keywords
                if pos + 4 <= chars.len()
                    && chars[pos..pos + 4] == ['w', 'h', 'e', 'n']
                    && (pos == 0 || !chars[pos - 1].is_alphanumeric())
                {
                    state = State::InWhen;
                    pos += 4; // Skip past "when"
                    continue; // Skip incrementing pos at the end of the loop
                } else if pos + 6 <= chars.len()
                    && chars[pos..pos + 6] == ['u', 'n', 'l', 'e', 's', 's']
                    && (pos == 0 || !chars[pos - 1].is_alphanumeric())
                {
                    state = State::InUnless;
                    pos += 6; // Skip past "unless"
                    continue; // Skip incrementing pos at the end of the loop
                }
            }
            State::InWhen | State::InUnless => {
                if c == '{' {
                    state = State::InConditionBlock;
                    brace_level = 1;
                } else if !c.is_whitespace() {
                    state = State::Normal; // Reset if non-whitespace and not '{'
                }
            }
            State::InConditionBlock => {
                if c == '{' {
                    brace_level += 1;
                } else if c == '}' {
                    brace_level -= 1;
                    if brace_level == 0 {
                        state = State::Normal;
                    }
                }
            }
        }

        pos += 1;
    }

    // If we've reached the cursor position, check if we're in a condition block
    state == State::InConditionBlock
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{fs::read_to_string, str::FromStr};

    use cedar_policy_core::ast::PolicyID;
    use cedar_policy_core::validator::ValidatorSchema;
    use tracing_test::traced_test;

    use crate::{
        policy::{DocumentContext, PolicyLanguageFeatures},
        schema::SchemaInfo,
    };

    use super::*;

    pub(crate) fn remove_caret_marker(policy: impl AsRef<str>) -> (String, Position) {
        let marker = "|caret|";
        let (before, after) = policy
            .as_ref()
            .split_once(marker)
            .expect("Caret marker not found");
        let position = if before.is_empty() {
            Position {
                line: 0,
                character: 0,
            }
        } else {
            Position {
                line: (before.lines().count() - 1).try_into().unwrap(),
                character: before.lines().last().unwrap().len().try_into().unwrap(),
            }
        };

        (format!("{before}{after}"), position)
    }

    /// Get the byte offset of a position (line and column) in a string,
    /// accounting for the actual position of newlines in the string.
    pub(crate) fn position_byte_offset(src: &str, pos: Position) -> usize {
        let line_offset = if pos.line == 0 {
            0
        } else {
            1 + src
                .char_indices()
                .filter(|(_, c)| c == &'\n')
                .nth((pos.line - 1).try_into().unwrap())
                .unwrap()
                .0
        };

        line_offset + TryInto::<usize>::try_into(pos.character).unwrap()
    }

    /// Given a range - a pair of (line, column) positions - extract the slice
    /// for this range from a string slice.
    pub(crate) fn slice_range(src: &str, range: Range) -> &str {
        let start_offset = position_byte_offset(src, range.start);
        let end_offset = position_byte_offset(src, range.end);
        &src[start_offset..end_offset]
    }

    pub(crate) fn schema() -> ValidatorSchema {
        let schema_str = read_to_string("test-data/policies.cedarschema").unwrap();

        ValidatorSchema::from_str(&schema_str).unwrap()
    }

    pub(crate) fn schema_info(schema_name: &str) -> SchemaInfo {
        let schema_str = read_to_string(format!("test-data/{schema_name}")).unwrap();

        SchemaInfo::cedar_schema(schema_str)
    }

    pub(crate) fn schema_document_context(policy: &str, position: Position) -> DocumentContext {
        let template =
            cedar_policy_core::parser::text_to_cst::parse_policy_tolerant(policy).unwrap();
        let ast = template
            .to_policy_template_tolerant(PolicyID::from_string("0"))
            .unwrap();
        DocumentContext::new(
            Some(schema().into()),
            ast.into(),
            position,
            PolicyLanguageFeatures::default(),
        )
    }

    #[test]
    fn test_get_operator_() {
        let test_cases = vec![
            ("a && b", 2, "&&"),
            ("x || y", 2, "||"),
            ("a != b", 2, "!="),
            ("x == y", 2, "=="),
            ("a >= b", 2, ">="),
            ("x <= y", 2, "<="),
            ("!true", 0, "!"),
            ("a + b", 2, "+"),
            ("x - y", 2, "-"),
            ("a * b", 2, "*"),
        ];

        for (text, char_pos, expected_op) in test_cases {
            let position = Position {
                line: 0,
                character: char_pos,
            };
            let result = get_operator_at_position(position, text);
            assert!(result.is_some());
            let (operator, _) = result.unwrap();
            assert_eq!(operator, expected_op);
        }
    }

    #[test]
    #[traced_test]
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::cognitive_complexity)]
    fn test_is_cursor_within_policy_scope() {
        // Test case 1: Single-line policy
        let policy1 = "permit(principal, action, resource) when { true };";

        // Inside the policy scope
        assert!(is_cursor_within_policy_scope(
            policy1,
            Position {
                line: 0,
                character: 10
            }
        )); // In 'principal'
        assert!(is_cursor_within_policy_scope(
            policy1,
            Position {
                line: 0,
                character: 20
            }
        )); // In 'action'
        assert!(is_cursor_within_policy_scope(
            policy1,
            Position {
                line: 0,
                character: 30
            }
        )); // In 'resource'

        // Outside the policy scope
        assert!(!is_cursor_within_policy_scope(
            policy1,
            Position {
                line: 0,
                character: 0
            }
        )); // Before 'permit('
        assert!(!is_cursor_within_policy_scope(
            policy1,
            Position {
                line: 0,
                character: 5
            }
        )); // In 'permit'
        assert!(!is_cursor_within_policy_scope(
            policy1,
            Position {
                line: 0,
                character: 35
            }
        )); // After ')'
        assert!(!is_cursor_within_policy_scope(
            policy1,
            Position {
                line: 1,
                character: 0
            }
        )); // Line out of bounds

        // Test case 2: Multi-line policy
        let policy2 = "\
permit(
    principal,
    action,
    resource
) when { true };";

        // Inside the policy scope
        assert!(is_cursor_within_policy_scope(
            policy2,
            Position {
                line: 0,
                character: 8
            }
        )); // After 'permit('
        assert!(is_cursor_within_policy_scope(
            policy2,
            Position {
                line: 1,
                character: 4
            }
        )); // In 'principal'
        assert!(is_cursor_within_policy_scope(
            policy2,
            Position {
                line: 2,
                character: 4
            }
        )); // In 'action'
        assert!(is_cursor_within_policy_scope(
            policy2,
            Position {
                line: 3,
                character: 4
            }
        )); // In 'resource'
        assert!(is_cursor_within_policy_scope(
            policy2,
            Position {
                line: 3,
                character: 12
            }
        )); // End of 'resource'

        // Outside the policy scope
        assert!(!is_cursor_within_policy_scope(
            policy2,
            Position {
                line: 0,
                character: 0
            }
        )); // Before 'permit'
        assert!(!is_cursor_within_policy_scope(
            policy2,
            Position {
                line: 0,
                character: 6
            }
        )); // In 'permit'
        assert!(!is_cursor_within_policy_scope(
            policy2,
            Position {
                line: 4,
                character: 1
            }
        )); // At closing ')'
        assert!(!is_cursor_within_policy_scope(
            policy2,
            Position {
                line: 4,
                character: 2
            }
        )); // After ')'
        assert!(!is_cursor_within_policy_scope(
            policy2,
            Position {
                line: 5,
                character: 0
            }
        )); // After policy

        // Test case 3: Forbid policy
        let policy3 = "forbid(principal, action, resource) when { false };";

        // Inside the policy scope
        assert!(is_cursor_within_policy_scope(
            policy3,
            Position {
                line: 0,
                character: 10
            }
        )); // In 'principal'
        assert!(is_cursor_within_policy_scope(
            policy3,
            Position {
                line: 0,
                character: 20
            }
        )); // In 'action'

        // Outside the policy scope
        assert!(!is_cursor_within_policy_scope(
            policy3,
            Position {
                line: 0,
                character: 0
            }
        )); // Before 'forbid'
        assert!(!is_cursor_within_policy_scope(
            policy3,
            Position {
                line: 0,
                character: 5
            }
        )); // In 'forbid'
        assert!(!is_cursor_within_policy_scope(
            policy3,
            Position {
                line: 0,
                character: 35
            }
        )); // After ')'

        // Test case 4: Complex nested policy
        let policy4 = "\
permit(
principal in [
User:\"alice\",
User:\"bob\"
],
action,
resource
) when { principal.department == \"engineering\" };";

        // Inside the policy scope
        assert!(is_cursor_within_policy_scope(
            policy4,
            Position {
                line: 1,
                character: 0
            }
        )); // Start of line after 'permit('
        assert!(is_cursor_within_policy_scope(
            policy4,
            Position {
                line: 2,
                character: 10
            }
        )); // In User:"alice"
        assert!(is_cursor_within_policy_scope(
            policy4,
            Position {
                line: 3,
                character: 10
            }
        )); // In User:"bob"
        assert!(is_cursor_within_policy_scope(
            policy4,
            Position {
                line: 5,
                character: 10
            }
        )); // In 'action'
        assert!(is_cursor_within_policy_scope(
            policy4,
            Position {
                line: 6,
                character: 10
            }
        )); // In 'resource'

        // Outside the policy scope
        assert!(!is_cursor_within_policy_scope(
            policy4,
            Position {
                line: 0,
                character: 0
            }
        )); // Before 'permit'
        assert!(!is_cursor_within_policy_scope(
            policy4,
            Position {
                line: 0,
                character: 5
            }
        )); // In 'permit'
        assert!(!is_cursor_within_policy_scope(
            policy4,
            Position {
                line: 7,
                character: 1
            }
        )); // At closing ')'
        assert!(!is_cursor_within_policy_scope(
            policy4,
            Position {
                line: 7,
                character: 2
            }
        )); // After ')'
        assert!(!is_cursor_within_policy_scope(
            policy4,
            Position {
                line: 8,
                character: 0
            }
        )); // After policy

        // Test case 5: Empty policy
        let policy5 = "permit() when { true };";

        // Outside the policy scope (empty policy has no "inside")
        assert!(!is_cursor_within_policy_scope(
            policy5,
            Position {
                line: 0,
                character: 8
            }
        )); // Between '(' and ')'
        assert!(!is_cursor_within_policy_scope(
            policy5,
            Position {
                line: 0,
                character: 0
            }
        )); // Before 'permit'
        assert!(!is_cursor_within_policy_scope(
            policy5,
            Position {
                line: 0,
                character: 5
            }
        )); // In 'permit'
        assert!(!is_cursor_within_policy_scope(
            policy5,
            Position {
                line: 0,
                character: 8
            }
        )); // After ')'

        // Test case 6: Comment before policy
        let policy6 = "// This is a comment\npermit(principal, action, resource) when { true };";

        // Inside the policy scope
        assert!(is_cursor_within_policy_scope(
            policy6,
            Position {
                line: 1,
                character: 10
            }
        )); // In 'principal'

        // Outside the policy scope
        assert!(!is_cursor_within_policy_scope(
            policy6,
            Position {
                line: 0,
                character: 5
            }
        )); // In comment
        assert!(!is_cursor_within_policy_scope(
            policy6,
            Position {
                line: 1,
                character: 0
            }
        )); // At start of 'permit'
        assert!(!is_cursor_within_policy_scope(
            policy6,
            Position {
                line: 1,
                character: 35
            }
        )); // After ')'

        // Test case 7: Invalid input
        let policy7 = "invalid policy without effect";

        // No policy scope, should always return false
        assert!(!is_cursor_within_policy_scope(
            policy7,
            Position {
                line: 0,
                character: 0
            }
        ));
        assert!(!is_cursor_within_policy_scope(
            policy7,
            Position {
                line: 0,
                character: 10
            }
        ));
    }
}
