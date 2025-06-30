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

use cedar_policy_core::parser::Loc;
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

pub(crate) fn get_word_at_position(position: Position, text: &str) -> Option<&str> {
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
    line.get(start..end).filter(|word| !word.is_empty())
}

pub(crate) fn get_operator_at_position(position: Position, text: &str) -> Option<&str> {
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

    let potential_operator = line.get(start..end)?;

    // Check if the extracted string is a valid operator
    operators.into_iter().find(|&op| {
        // Find the position of this operator in our extracted string
        potential_operator.find(op).is_some_and(|op_start| {
            // Check if our cursor position is within this operator
            let absolute_op_start = start + op_start;
            let absolute_op_end = absolute_op_start + op.len();
            char_pos >= absolute_op_start && char_pos <= absolute_op_end
        })
    })
}

fn get_policy_scope_ranges(policy_text: &str) -> Vec<Range> {
    // Track policy scope boundaries for all policies
    let mut policy_scopes: Vec<Range> = Vec::new();
    let mut policy_start_pos: Option<Position> = None;
    let mut paren_depth = 0;
    let mut in_effect_keyword = false;

    // Identify effect keywords and their parentheses
    for (line_idx, line) in policy_text.lines().enumerate() {
        for (char_idx, char) in line.char_indices() {
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
                continue;
            }

            // If we've found an effect keyword, track parentheses
            if in_effect_keyword {
                match char {
                    '(' => {
                        paren_depth += 1;
                        if paren_depth == 1 {
                            policy_start_pos = Some(Position {
                                line: line_idx as u32,
                                character: char_idx as u32,
                            });
                        }
                    }
                    ')' => {
                        paren_depth -= 1;
                        if let Some(policy_start_pos) =
                            policy_start_pos.take_if(|_| paren_depth == 0)
                        {
                            // Add this policy scope to our list
                            policy_scopes.push(Range {
                                start: policy_start_pos,
                                end: Position {
                                    line: line_idx as u32,
                                    character: char_idx as u32,
                                },
                            });
                            in_effect_keyword = false;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    policy_scopes
}

fn policy_scope_range_containing_cursor(
    policy_text: &str,
    cursor_position: Position,
) -> Option<Range> {
    get_policy_scope_ranges(policy_text)
        .into_iter()
        .find(|scope_range| {
            // Cursor is after start position
            let after_start = cursor_position.line > scope_range.start.line
                || (cursor_position.line == scope_range.start.line
                    && cursor_position.character > scope_range.start.character);

            // Cursor is before end position
            let before_end = cursor_position.line < scope_range.end.line
                || (cursor_position.line == scope_range.end.line
                    && cursor_position.character <= scope_range.end.character);

            after_start && before_end
        })
}

pub(crate) fn is_cursor_within_policy_scope(policy_text: &str, cursor_position: Position) -> bool {
    policy_scope_range_containing_cursor(policy_text, cursor_position).is_some()
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

#[allow(clippy::too_many_lines)]
pub(crate) fn get_policy_scope_variable(
    policy_text: &str,
    cursor_position: Position,
) -> ScopeVariableInfo {
    // Find the policy that contains the cursor
    let Some(policy_range) = policy_scope_range_containing_cursor(policy_text, cursor_position)
    else {
        return ScopeVariableInfo {
            variable_type: PolicyScopeVariable::None,
            text: "".into(),
        };
    };

    // Now find the commas within this policy to determine the variables
    let mut param_sections: Vec<((usize, usize), (usize, usize))> = Vec::new();
    let mut current_start = (
        policy_range.start.line as usize,
        policy_range.start.character as usize + 1,
    ); // +1 to skip the opening parenthesis
    let mut comma_positions = Vec::new();
    let mut paren_depth = 1; // Start at 1 because we're inside the opening parenthesis
    let mut bracket_depth = 0;

    'outer: for (line_num, line) in policy_text
        .lines()
        .enumerate()
        .skip(policy_range.start.line as usize)
    {
        let start_char = if line_num == policy_range.start.line as usize {
            policy_range.start.character + 1
        } else {
            0
        };

        for (char_pos, c) in line.chars().enumerate().skip(start_char as usize) {
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
            if (cursor_position.line as usize) < line
                || (cursor_position.line as usize == line
                    && (cursor_position.character as usize) <= pos)
            {
                break;
            }
            index += 1;
        }
        index
    };

    // Extract the text for the current parameter section
    let text = if let Some(((start_line, start_pos), (end_line, end_pos))) =
        param_sections.get(param_index)
    {
        if start_line == end_line {
            // PANIC SAFETY: Line numbers in `param_sections` are always indexes from enumerating `lines()`.
            #[allow(clippy::unwrap_used)]
            let line = policy_text.lines().nth(*start_line).unwrap();
            line[*start_pos..*end_pos].trim().into()
        } else {
            // Handle multi-line parameters
            let mut text = String::new();
            for (line_num, item) in policy_text
                .lines()
                .enumerate()
                .take(end_line + 1)
                .skip(*start_line)
            {
                if line_num == *start_line {
                    text.push_str(&item[*start_pos..]);
                } else if line_num == *end_line {
                    text.push_str(&item[..*end_pos]);
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
        // PANIC SAFETY: while loop guard ensures `pos` is in bounds
        #[allow(clippy::indexing_slicing)]
        let c = chars[pos];

        match state {
            State::Normal => {
                // PANIC SAFETY: indexing to `chars` is guarded by length check
                #[allow(clippy::indexing_slicing)]
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
    use similar_asserts::assert_eq;

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

    pub(crate) fn remove_all_caret_markers(src: impl AsRef<str>) -> (String, Vec<Position>) {
        let mut src = src.as_ref().to_owned();
        let mut caret_positions = Vec::new();
        while src.contains("|caret|") {
            let (new_src, pos) = remove_caret_marker(src);
            src = new_src;
            caret_positions.push(pos);
        }
        (src, caret_positions)
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

    pub(crate) fn insert_caret(src: &str, pos: Position) -> String {
        let offset = position_byte_offset(src, pos);
        format!("{}|caret|{}", &src[..offset], &src[offset..])
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

    pub(crate) fn schema_document_context(policy: &str, position: Position) -> DocumentContext<'_> {
        let template =
            cedar_policy_core::parser::text_to_cst::parse_policy_tolerant(policy).unwrap();
        let ast = template
            .to_policy_template_tolerant(PolicyID::from_string("0"))
            .unwrap();
        DocumentContext::new(
            Some(schema().into()),
            ast.into(),
            policy,
            position,
            PolicyLanguageFeatures::default(),
        )
    }

    #[test]
    fn test_get_operator() {
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
            assert_eq!(get_operator_at_position(position, text), Some(expected_op));
        }
    }

    fn assert_carets_in_scope(policy: &str) {
        let (policy, carets) = remove_all_caret_markers(policy);
        for p in carets {
            assert!(
                is_cursor_within_policy_scope(&policy, p),
                "{}",
                insert_caret(&policy, p)
            );
        }
    }

    fn assert_carets_not_in_scope(policy: &str) {
        let (policy, carets) = remove_all_caret_markers(policy);
        for p in carets {
            assert!(
                !is_cursor_within_policy_scope(&policy, p),
                "{}",
                insert_caret(&policy, p)
            );
        }
    }

    #[test]
    #[traced_test]
    fn single_line_policy_within_scope() {
        assert_carets_in_scope(
            "permit(|caret|pri|caret|ncipal, ac|caret|tion, re|caret|source|caret|) when { true };",
        );
    }

    #[test]
    #[traced_test]
    fn single_line_policy_outside_scope() {
        assert_carets_not_in_scope(
            "|caret|per|caret|mit|caret|(principal, action, resource)|caret| when { |caret|true };",
        );
    }

    #[test]
    #[traced_test]
    fn multi_line_policy_within_scope() {
        assert_carets_in_scope(
            "\
permit(
    prin|caret|ci|caret|pal,
    ac|caret|ti|caret|on,
    res|caret|our|caret|ce
)",
        );
    }

    #[test]
    #[traced_test]
    fn multi_line_policy_outside_scope() {
        assert_carets_not_in_scope(
            "\
|caret|per|caret|mit(
    principal,
    action,
    resource
)|caret| when { |caret|true };|caret|",
        );
    }

    #[test]
    #[traced_test]
    fn forbid_policy_within_scope() {
        assert_carets_in_scope(
            "forbid(prin|caret|ci|caret|pal, ac|caret|ti|caret|on, res|caret|our|caret|ce)",
        );
    }

    #[test]
    #[traced_test]
    fn forbid_policy_outside_scope() {
        assert_carets_not_in_scope(
            "|caret|for|caret|bid(principal, action, resource)|caret| when { |caret|false };|caret|"
        );
    }

    #[test]
    #[traced_test]
    fn complex_nested_policy_within_scope() {
        assert_carets_in_scope(
            "\
permit(
    principal in User:|caret|\"al|caret|ice\",
    action in Action::|caret|\"a|caret|ct\",
    resource in Resource::|caret|\"da|caret|ta\"
)",
        );
    }

    #[test]
    #[traced_test]
    fn complex_nested_policy_outside_scope() {
        assert_carets_not_in_scope(
            "\
|caret|per|caret|mit(
    principal in User:\"alice\",
    action in Action::\"act\",
    resource in Resource::\"data\"
)|caret| when { |caret|true };|caret|",
        );
    }

    #[test]
    #[traced_test]
    fn empty_policy() {
        assert_carets_not_in_scope("|caret|per|caret|mit()|caret| when { |caret|true };|caret|");
    }

    #[test]
    #[traced_test]
    fn policy_with_comments_within_scope() {
        assert_carets_in_scope(
            "// This is a comment\npermit(prin|caret|ci|caret|pal, ac|caret|ti|caret|on, res|caret|our|caret|ce)"
        );
    }

    #[test]
    #[traced_test]
    fn policy_with_comments_outside_scope() {
        assert_carets_not_in_scope(
            "|caret|// This is a comment|caret|\n|caret|permit(principal, action, resource)|caret| when { true };|caret|"
        );
    }

    #[test]
    #[traced_test]
    fn invalid_policy_input() {
        assert_carets_not_in_scope(
            "|caret|invalid|caret| policy|caret| without|caret| effect|caret|",
        );
    }

    fn assert_carets_in_condition(policy: &str) {
        let (policy, carets) = remove_all_caret_markers(policy);
        for p in carets {
            assert!(
                is_cursor_in_condition_braces(p, &policy),
                "{}",
                insert_caret(&policy, p)
            );
        }
    }

    fn assert_carets_not_in_condition(policy: &str) {
        let (policy, carets) = remove_all_caret_markers(policy);
        for p in carets {
            assert!(
                !is_cursor_in_condition_braces(p, &policy),
                "{}",
                insert_caret(&policy, p)
            );
        }
    }

    #[test]
    fn caret_in_condition() {
        assert_carets_in_condition(
            "permit(principal, action, resource) when { |caret| true && fa|caret|lse |caret| };",
        );
        assert_carets_in_condition(
            "permit(principal, action, resource) unless { |caret| true && fa|caret|lse |caret| };",
        );
        assert_carets_in_condition(
            "permit(principal, action, resource) when { \n|caret| true\n\n\n &&\n fa|caret|lse |caret|\n };",
        );
        assert_carets_in_condition(
            "permit(principal, action, resource) when { true |caret| } \n unless { |caret| false };",
        );
        assert_carets_in_condition(
            "permit(principal, action, resource) when { 1 + { a: |caret| {|caret| b: 1} |caret|} |caret|}; ",
        );
    }

    #[test]
    fn caret_not_in_cond() {
        assert_carets_not_in_condition(
            "permit(principal, action, resource) when { false } |caret|;|caret|",
        );
        assert_carets_not_in_condition(
            "permit(principal, action, resource) |caret|when|caret| { false };",
        );
        assert_carets_not_in_condition("|caret|permit(principal, action, |caret| resource);");
        assert_carets_not_in_condition(
            "permit(principal, action, resource) when { false } |caret| unless |caret| { true };",
        );
    }

    #[test]
    fn get_policy_scope_single_line() {
        let policy = "permit(principal, action, resource) when { true };";

        let result = get_policy_scope_variable(
            policy,
            Position {
                line: 0,
                character: 10,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, "principal");

        let result = get_policy_scope_variable(
            policy,
            Position {
                line: 0,
                character: 20,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Action);
        assert_eq!(result.text, "action");

        let result = get_policy_scope_variable(
            policy,
            Position {
                line: 0,
                character: 30,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Resource);
        assert_eq!(result.text, "resource");

        let result = get_policy_scope_variable(
            policy,
            Position {
                line: 0,
                character: 0,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::None);
        assert_eq!(result.text, "");
    }

    #[test]
    fn get_policy_scope_multi_line() {
        let policy = "permit(
            principal,
            action,
            resource
        );";

        // Test cursor in principal section
        let result = get_policy_scope_variable(
            policy,
            Position {
                line: 1,
                character: 4,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, "principal");

        // Test cursor in action section
        let result = get_policy_scope_variable(
            policy,
            Position {
                line: 2,
                character: 4,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Action);
        assert_eq!(result.text, "action");

        // Test cursor in resource section
        let result = get_policy_scope_variable(
            policy,
            Position {
                line: 3,
                character: 4,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Resource);
        assert_eq!(result.text, "resource");
    }

    #[test]
    fn get_policy_scope_in_operator() {
        let policy = r#"
        permit(
            principal in User:"alice",
            action in [Action::"act"],
            resource in Resource::"data"
        );"#;

        // Test cursor in complex principal section
        let result = get_policy_scope_variable(
            policy,
            Position {
                line: 2,
                character: 15,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, "principal in User:\"alice\"");

        // Test cursor in action section
        let result = get_policy_scope_variable(
            policy,
            Position {
                line: 3,
                character: 15,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Action);
        assert_eq!(result.text, "action in [Action::\"act\"]");

        // Test cursor in complex resource section
        let result = get_policy_scope_variable(
            policy,
            Position {
                line: 4,
                character: 15,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Resource);
        assert_eq!(result.text, "resource in Resource::\"data\"");
    }

    #[test]
    fn get_policy_scope_eq_operator() {
        let policy = r#"
        permit(
            principal == User:"alice",
            action == Action::"act",
            resource == Resource::"data"
        );"#;

        // Test cursor in complex principal section
        let result = get_policy_scope_variable(
            policy,
            Position {
                line: 2,
                character: 15,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, "principal == User:\"alice\"");

        // Test cursor in action section
        let result = get_policy_scope_variable(
            policy,
            Position {
                line: 3,
                character: 15,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Action);
        assert_eq!(result.text, "action == Action::\"act\"");

        // Test cursor in complex resource section
        let result = get_policy_scope_variable(
            policy,
            Position {
                line: 4,
                character: 15,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Resource);
        assert_eq!(result.text, "resource == Resource::\"data\"");
    }

    #[test]
    fn get_policy_scope_is_operator() {
        let policy = r#"
        permit(
            principal is User,
            action,
            resource is Resource
        );"#;

        // Test cursor in complex principal section
        let result = get_policy_scope_variable(
            policy,
            Position {
                line: 2,
                character: 15,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, "principal is User");

        // Test cursor in action section
        let result = get_policy_scope_variable(
            policy,
            Position {
                line: 3,
                character: 15,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Action);
        assert_eq!(result.text, "action");

        // Test cursor in complex resource section
        let result = get_policy_scope_variable(
            policy,
            Position {
                line: 4,
                character: 15,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Resource);
        assert_eq!(result.text, "resource is Resource");
    }

    #[test]
    fn test_multiple_policies() {
        let policies = "permit(principal, action, resource);\nforbid(principal, action, resource);";

        // Test cursor in first policy
        let result = get_policy_scope_variable(
            policies,
            Position {
                line: 0,
                character: 10,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, "principal");

        // Test cursor in second policy
        let result = get_policy_scope_variable(
            policies,
            Position {
                line: 1,
                character: 20,
            },
        );
        assert_eq!(result.variable_type, PolicyScopeVariable::Action);
        assert_eq!(result.text, "action");
    }
}
