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
use miette::SourceSpan;
use tower_lsp_server::lsp_types::{self, Position, Range};

pub(crate) trait ToRange {
    fn to_range(&self) -> Range;
}

impl ToRange for Loc {
    fn to_range(&self) -> Range {
        // Assumes that `span` is in bounds for `src`. This is true if
        // this `Loc` is constructed by our parser, but is easy to
        // violate if constructing a `Loc` manually.
        // PANIC_SAFETY: See above
        #[allow(clippy::unwrap_used)]
        to_range(&self.span, &self.src).unwrap()
    }
}

impl ToRange for Box<Loc> {
    fn to_range(&self) -> Range {
        // Assumes that `span` is in bounds for `src`. This is true if
        // this `Loc` is constructed by our parsers, but is easy to
        // violate if constructing a `Loc` manually.
        // PANIC_SAFETY: See above
        #[allow(clippy::unwrap_used)]
        to_range(&self.span, &self.src).unwrap()
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
        #[allow(clippy::unwrap_used, reason = "writing string cannot fail")]
        write!(&mut message, ". {source}").unwrap();
    }
    if let Some(help) = diagnostic.help() {
        #[allow(clippy::unwrap_used, reason = "writing string cannot fail")]
        write!(&mut message, ". {help}").unwrap();
    }

    let mut diagnostics = Vec::new();
    let severity = diagnostic.severity().map(to_lsp_severity);
    if let Some(labels) = diagnostic.labels() {
        diagnostics.extend(labels.map(move |l| lsp_types::Diagnostic {
            severity,
            ..lsp_types::Diagnostic::new_simple(
                to_range(l.inner(), src).unwrap_or(START_RANGE),
                message.clone(),
            )
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

pub(crate) fn to_range(source_span: &SourceSpan, src: &str) -> Option<Range> {
    Some(Range {
        start: offset_to_position(src, source_span.offset())?,
        end: offset_to_position(src, source_span.offset() + source_span.len())?,
    })
}

pub(crate) fn offset_to_position(text: &str, offset: usize) -> Option<Position> {
    let text = text.get(..offset)?;
    let line = text.chars().filter(|&c| c == '\n').count();
    let char = text.chars().rev().take_while(|&c| c != '\n').count();
    Some(Position::new(line as u32, char as u32))
}

/// Get the byte offset of a position (line and column) in a string,
/// accounting for the actual position of newlines in the string.
pub(crate) fn position_byte_offset(src: &str, pos: Position) -> Option<usize> {
    let mut line_offset = 0;
    for (line_num, line) in src.lines().enumerate() {
        if line_num == pos.line as usize {
            if let Some((char_offset_in_line, _)) = line.char_indices().nth(pos.character as usize)
            {
                return Some(line_offset + char_offset_in_line);
            } else if pos.character as usize == line.chars().count() {
                return Some(line_offset + line.len());
            }
        } else {
            // `+ 1` to skip past new line
            line_offset += line.len() + 1;
        }
    }
    None
}

pub(crate) fn get_char_at_position(position: Position, src: &str) -> Option<char> {
    let offset = position_byte_offset(src, position)?;
    Some(src[offset..].chars().next().unwrap())
}

pub(crate) fn get_text_before_position(text: &str, position: Position) -> Option<&str> {
    let offset = position_byte_offset(text, position)?;
    Some(&text[..offset])
}

pub(crate) fn get_text_in_range(text: &str, range: Range) -> Option<&str> {
    let start = position_byte_offset(text, range.start)?;
    let end = position_byte_offset(text, range.end)?;
    Some(&text[start..end])
}

pub(crate) fn is_position_in_range(position: Position, range: &Range) -> bool {
    position >= range.start && position <= range.end
}

pub(crate) fn position_within_loc<'a, R, I>(position: Position, range: I) -> bool
where
    R: ToRange + 'a,
    I: Into<Option<&'a R>>,
{
    let Some(range) = range.into() else {
        return false;
    };
    is_position_in_range(position, &range.to_range())
}

pub(crate) fn ranges_intersect(a: &Range, b: &Range) -> bool {
    a.start <= b.end && b.start <= a.end
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
pub(crate) struct ScopeVariableInfo<'a> {
    pub(crate) variable_type: PolicyScopeVariable,
    text: &'a str,
}

// PANIC SAFETY: These regex are valid and would panic immediately in test if not.
#[allow(clippy::unwrap_used)]
mod scope_regex {
    use regex::Regex;
    use std::sync::LazyLock;

    pub(super) static PRINCIPAL_IS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"principal\s+is\s*").unwrap());

    pub(super) static RESOURCE_IS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"resource\s+is\s*").unwrap());

    pub(super) static ACTION_IN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"action\s+in\s*").unwrap());
    pub(super) static ACTION_EQ: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"action\s+==\s*").unwrap());
    pub(super) static ACTION_IN_ARRAY: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"action\s+in\s+\[(?:\s*(?:[A-Za-z]+::)?Action::"[\w]+?"\s*,?)*\s*"#).unwrap()
    });
}

impl ScopeVariableInfo<'_> {
    pub(crate) fn is_principal_is(&self) -> bool {
        scope_regex::PRINCIPAL_IS.is_match(&self.text)
    }

    pub(crate) fn is_resource_is(&self) -> bool {
        scope_regex::RESOURCE_IS.is_match(&self.text)
    }

    pub(crate) fn is_action_in(&self) -> bool {
        scope_regex::ACTION_IN.is_match(&self.text)
    }

    pub(crate) fn is_action_eq(&self) -> bool {
        scope_regex::ACTION_EQ.is_match(&self.text)
    }

    pub(crate) fn is_action_in_array(&self) -> bool {
        scope_regex::ACTION_IN_ARRAY.is_match(&self.text)
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn get_policy_scope_variable(
    policy_text: &str,
    cursor_position: Position,
) -> ScopeVariableInfo<'_> {
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
        let param_range = Range::new(
            Position::new(*start_line as u32, *start_pos as u32),
            Position::new(*end_line as u32, *end_pos as u32),
        );
        // PANIC SAFETY: Positions in `param_section` as valid offsets into `policy_text`
        #[allow(clippy::unwrap_used)]
        get_text_in_range(policy_text, param_range).unwrap().trim()
    } else {
        ""
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

pub(crate) fn extract_common_type_name(type_dec_snippet: &str) -> Option<&str> {
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

    Some(type_name)
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

    use cedar_policy_core::{ast::PolicyID, validator::ValidatorSchema};
    use tracing_test::traced_test;

    use similar_asserts::assert_eq;

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

    pub(crate) fn insert_caret(src: &str, pos: Position) -> String {
        let offset = position_byte_offset(src, pos).unwrap();
        format!("{}|caret|{}", &src[..offset], &src[offset..])
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
            Some(schema()),
            ast,
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
        let (policy, carets) = remove_all_caret_markers(
            "permit(princ|caret|ipal, act|caret|ion, reso|caret|urce) when { true };|caret|",
        );

        let result = get_policy_scope_variable(&policy, carets[0]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, "principal");
        assert!(!result.is_principal_is());
        assert!(!result.is_resource_is());

        let result = get_policy_scope_variable(&policy, carets[1]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Action);
        assert_eq!(result.text, "action");
        assert!(!result.is_action_eq());
        assert!(!result.is_action_in());
        assert!(!result.is_action_in_array());

        let result = get_policy_scope_variable(&policy, carets[2]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Resource);
        assert_eq!(result.text, "resource");
        assert!(!result.is_principal_is());
        assert!(!result.is_resource_is());

        let result = get_policy_scope_variable(&policy, carets[3]);
        assert_eq!(result.variable_type, PolicyScopeVariable::None);
        assert_eq!(result.text, "");
        assert!(!result.is_principal_is());
        assert!(!result.is_resource_is());
    }

    #[test]
    fn get_policy_scope_multi_line() {
        let (policy, carets) = remove_all_caret_markers(
            "permit(
            princ|caret|ipal,
            act|caret|ion,
            reso|caret|urce
        );",
        );

        // Test cursor in principal section
        let result = get_policy_scope_variable(&policy, carets[0]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, "principal");

        // Test cursor in action section
        let result = get_policy_scope_variable(&policy, carets[1]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Action);
        assert_eq!(result.text, "action");

        // Test cursor in resource section
        let result = get_policy_scope_variable(&policy, carets[2]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Resource);
        assert_eq!(result.text, "resource");
    }

    #[test]
    fn get_policy_scope_in_operator() {
        let (policy, carets) = remove_all_caret_markers(
            r#"
        permit(
            princ|caret|ipal in User:"alice",
            act|caret|ion in Action::"act",
            reso|caret|urce in Resource::"data"
        );"#,
        );

        // Test cursor in complex principal section
        let result = get_policy_scope_variable(&policy, carets[0]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, "principal in User:\"alice\"");

        // Test cursor in action section
        let result = get_policy_scope_variable(&policy, carets[1]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Action);
        assert_eq!(result.text, "action in Action::\"act\"");
        assert!(result.is_action_in());
        assert!(!result.is_action_in_array());
        assert!(!result.is_action_eq());

        // Test cursor in complex resource section
        let result = get_policy_scope_variable(&policy, carets[2]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Resource);
        assert_eq!(result.text, "resource in Resource::\"data\"");
    }

    #[test]
    fn get_policy_scope_eq_operator() {
        let (policy, carets) = remove_all_caret_markers(
            r#"
        permit(
            princ|caret|ipal == User:"alice",
            act|caret|ion == Action::"act",
            reso|caret|urce == Resource::"data"
        );"#,
        );

        // Test cursor in complex principal section
        let result = get_policy_scope_variable(&policy, carets[0]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, "principal == User:\"alice\"");

        // Test cursor in action section
        let result = get_policy_scope_variable(&policy, carets[1]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Action);
        assert_eq!(result.text, "action == Action::\"act\"");
        assert!(result.is_action_eq());
        assert!(!result.is_action_in());
        assert!(!result.is_action_in_array());

        // Test cursor in complex resource section
        let result = get_policy_scope_variable(&policy, carets[2]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Resource);
        assert_eq!(result.text, "resource == Resource::\"data\"");
    }

    #[test]
    fn get_policy_scope_is_operator() {
        let (policy, carets) = remove_all_caret_markers(
            r"
        permit(
            pri|caret|ncipal is User,
            act|caret|ion,
            reso|caret|urce is Resource
        );",
        );

        // Test cursor in complex principal section
        let result = get_policy_scope_variable(&policy, carets[0]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, "principal is User");
        assert!(result.is_principal_is());

        // Test cursor in action section
        let result = get_policy_scope_variable(&policy, carets[1]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Action);
        assert_eq!(result.text, "action");

        // Test cursor in complex resource section
        let result = get_policy_scope_variable(&policy, carets[2]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Resource);
        assert_eq!(result.text, "resource is Resource");
        assert!(result.is_resource_is());
    }

    #[test]
    fn get_policy_scope_multi_line_var() {
        let (policy, carets) = remove_all_caret_markers(
            r#"
        permit(
            principal
                is
                    |caret|User,
            action in [
            |caret|
            ],
            reso|caret|urce ==
            Photo::""
        );"#,
        );

        // Test cursor in complex principal section
        let result = get_policy_scope_variable(&policy, carets[0]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(
            result.text,
            "principal\n                is\n                    User"
        );
        assert!(result.is_principal_is());

        // Test cursor in action section
        let result = get_policy_scope_variable(&policy, carets[1]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Action);
        assert_eq!(result.text, "action in [\n            \n            ]");
        assert!(result.is_action_in_array());

        // Test cursor in complex resource section
        let result = get_policy_scope_variable(&policy, carets[2]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Resource);
        assert_eq!(result.text, "resource ==\n            Photo::\"\"");
    }

    #[test]
    fn test_multiple_policies() {
        let (policies, carets) = remove_all_caret_markers("permit(princ|caret|ipal, action, resource);\nforbid(principal, actio|caret|n, resource);");

        // Test cursor in first policy
        let result = get_policy_scope_variable(&policies, carets[0]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, "principal");

        // Test cursor in second policy
        let result = get_policy_scope_variable(&policies, carets[1]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Action);
        assert_eq!(result.text, "action");
    }

    #[test]
    fn test_parens_in_policy_scope() {
        let (policies, carets) = remove_all_caret_markers(
            r#"permit(princ|caret|ipal == (User::"alice"), ac|caret|tion in [(Action::"bar")], res|caret|ource in ((Album::"foo")));"#,
        );

        let result = get_policy_scope_variable(&policies, carets[0]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, r#"principal == (User::"alice")"#);

        let result = get_policy_scope_variable(&policies, carets[1]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Action);
        assert_eq!(result.text, r#"action in [(Action::"bar")]"#);
        assert!(result.is_action_in_array());

        let result = get_policy_scope_variable(&policies, carets[2]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Resource);
        assert_eq!(result.text, r#"resource in ((Album::"foo"))"#);
    }

    #[test]
    fn test_incomplete_policy_scope() {
        let (policies, carets) = remove_all_caret_markers(r#"permit(|caret|);"#);
        let result = get_policy_scope_variable(&policies, carets[0]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, "");

        let (policies, carets) = remove_all_caret_markers(r#"permit(princi|caret|pal);"#);
        let result = get_policy_scope_variable(&policies, carets[0]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, "principal");

        let (policies, carets) = remove_all_caret_markers(r#"permit(princi|caret|pal, );"#);
        let result = get_policy_scope_variable(&policies, carets[0]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, "principal");

        let (policies, carets) =
            remove_all_caret_markers(r#"permit(princi|caret|pal, a|caret|ction, );"#);
        let result = get_policy_scope_variable(&policies, carets[0]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Principal);
        assert_eq!(result.text, "principal");
        let result = get_policy_scope_variable(&policies, carets[1]);
        assert_eq!(result.variable_type, PolicyScopeVariable::Action);
        assert_eq!(result.text, "action");
    }

    #[test]
    fn test_extract_common_type_name() {
        assert_eq!(
            extract_common_type_name("type SimpleType = String;"),
            Some("SimpleType")
        );
        assert_eq!(
            extract_common_type_name("type MyRecord = { name: String };"),
            Some("MyRecord")
        );
        assert_eq!(
            extract_common_type_name("type MySet = Set<String>;"),
            Some("MySet")
        );
        assert_eq!(
            extract_common_type_name("  type  SpacedType  =  Long;  "),
            Some("SpacedType")
        );

        // Multi-line type declarations
        let (multiline_type, _) = remove_all_caret_markers(
            "type \n NewLines \n = {\n  field1: String,\n  field2: Long\n};",
        );
        assert_eq!(extract_common_type_name(&multiline_type), Some("NewLines"));

        // Type with namespace
        assert_eq!(
            extract_common_type_name("type Namespace::TypeName = String;"),
            Some("Namespace::TypeName")
        );

        assert_eq!(extract_common_type_name("entity foo;"), None);
        assert_eq!(extract_common_type_name("entity foo;"), None);
    }

    #[test]
    fn test_get_word_at_position_basic() {
        let (text, position) = remove_caret_marker("he|caret|llo");
        assert_eq!(get_word_at_position(position, &text), Some("hello"));

        let (text, position) = remove_caret_marker("hello |caret|world");
        assert_eq!(get_word_at_position(position, &text), Some("world"));

        let (text, position) = remove_caret_marker("|caret|hello world");
        assert_eq!(get_word_at_position(position, &text), Some("hello"));

        let (text, position) = remove_caret_marker("hello wor|caret|ld");
        assert_eq!(get_word_at_position(position, &text), Some("world"));

        let (text, position) = remove_caret_marker("hello world|caret|");
        assert_eq!(get_word_at_position(position, &text), Some("world"));
    }

    #[test]
    fn test_get_word_at_position_word_characters() {
        let (text, position) = remove_caret_marker("test|caret|123");
        assert_eq!(get_word_at_position(position, &text), Some("test123"));

        let (text, position) = remove_caret_marker("my_|caret|variable");
        assert_eq!(get_word_at_position(position, &text), Some("my_variable"));

        let (text, position) = remove_caret_marker("User:|caret|:alice");
        assert_eq!(get_word_at_position(position, &text), Some("User::alice"));

        let (text, position) = remove_caret_marker("x |caret|== y");
        assert_eq!(get_word_at_position(position, &text), Some("=="));
    }

    #[test]
    fn test_get_word_at_position_none() {
        let (text, position) = remove_caret_marker("hello |caret| world");
        assert_eq!(get_word_at_position(position, &text), None);

        let (text, position) = remove_caret_marker("|caret|");
        assert_eq!(get_word_at_position(position, &text), None);

        let (text, position) = remove_caret_marker("   |caret|   ");
        assert_eq!(get_word_at_position(position, &text), None);

        let (text, position) = remove_caret_marker("line1\n\n|caret|\nline3");
        assert_eq!(get_word_at_position(position, &text), None);

        assert_eq!(
            get_word_at_position(
                Position {
                    line: 0,
                    character: 20
                },
                "hello world"
            ),
            None
        );
        assert_eq!(
            get_word_at_position(
                Position {
                    line: 2,
                    character: 0
                },
                "hello world"
            ),
            None
        );
    }

    #[test]
    fn test_get_word_at_position_multiline() {
        let (text, position) = remove_caret_marker("line1|caret|\nline2");
        assert_eq!(get_word_at_position(position, &text), Some("line1"));

        let (text, position) = remove_caret_marker("line1\nli|caret|ne2");
        assert_eq!(get_word_at_position(position, &text), Some("line2"));
    }

    #[test]
    fn test_get_word_at_position_cedar_syntax() {
        let (text, position) = remove_caret_marker("permit(|caret|principal, action, resource)");
        assert_eq!(get_word_at_position(position, &text), Some("principal"));

        let (text, position) = remove_caret_marker("User::|caret|\"alice\"");
        assert_eq!(get_word_at_position(position, &text), Some("User::"));

        let (text, position) = remove_caret_marker("principal |caret|== User::\"alice\"");
        assert_eq!(get_word_at_position(position, &text), Some("=="));

        let (text, position) = remove_caret_marker("resource in Photo::|caret|\"vacation.jpg\"");
        assert_eq!(get_word_at_position(position, &text), Some("Photo::"));

        let (text, position) = remove_caret_marker("principal.|caret|department");
        assert_eq!(get_word_at_position(position, &text), Some("department"));

        let (text, position) = remove_caret_marker("principal has |caret|department");
        assert_eq!(get_word_at_position(position, &text), Some("department"));
    }

    mod offset_to_position {
        use crate::utils::offset_to_position;
        use similar_asserts::assert_eq;
        use tower_lsp_server::lsp_types::Position;

        #[test]
        fn empty_string() {
            assert_eq!(offset_to_position("", 0).unwrap(), Position::new(0, 0));
        }

        #[test]
        fn single_line_all_ascii() {
            let text = "hello world";
            assert_eq!(offset_to_position(text, 0).unwrap(), Position::new(0, 0));
            assert_eq!(offset_to_position(text, 6).unwrap(), Position::new(0, 6));
            assert_eq!(
                offset_to_position(text, text.len()).unwrap(),
                Position::new(0, text.len() as u32)
            );
            assert_eq!(offset_to_position(text, 20), None);
        }

        #[test]
        fn multi_line_all_ascii() {
            let text = "line1\nline2\nline3";
            assert_eq!(offset_to_position(text, 0).unwrap(), Position::new(0, 0));
            assert_eq!(offset_to_position(text, 3).unwrap(), Position::new(0, 3));
            assert_eq!(offset_to_position(text, 5).unwrap(), Position::new(0, 5));
            assert_eq!(offset_to_position(text, 6).unwrap(), Position::new(1, 0));
            assert_eq!(offset_to_position(text, 14).unwrap(), Position::new(2, 2));
            assert_eq!(offset_to_position(text, 17).unwrap(), Position::new(2, 5));
        }

        #[test]
        fn empty_lines() {
            let text = "\n\n\n";
            assert_eq!(offset_to_position(text, 0).unwrap(), Position::new(0, 0));
            assert_eq!(offset_to_position(text, 1).unwrap(), Position::new(1, 0));
            assert_eq!(offset_to_position(text, 2).unwrap(), Position::new(2, 0));
            assert_eq!(offset_to_position(text, 3).unwrap(), Position::new(3, 0));
            assert_eq!(offset_to_position(text, 4), None);
        }

        #[test]
        fn unicode_characters() {
            let text = "_🚀_";
            assert_eq!(offset_to_position(text, 0).unwrap(), Position::new(0, 0));
            assert_eq!(offset_to_position(text, 1).unwrap(), Position::new(0, 1));
            assert_eq!(offset_to_position(text, 5).unwrap(), Position::new(0, 2));
            assert_eq!(offset_to_position(text, 7), None);
        }
    }

    mod to_range {
        use super::*;
        use similar_asserts::assert_eq;

        #[test]
        fn single_line_span() {
            let src = "hello world";
            let span = SourceSpan::new(6.into(), 5);
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position::new(0, 6),
                    end: Position::new(0, 11),
                }
            );
        }

        #[test]
        fn multiline_span_within_line() {
            let src = "line1\nline2\nline3";
            let span = SourceSpan::new(6.into(), 5); // "line2"
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position::new(1, 0),
                    end: Position::new(1, 5),
                }
            );
        }

        #[test]
        fn span_across_lines() {
            let src = "line1\nline2\nline3";
            let span = SourceSpan::new(3.into(), 8); // "e1\nline2"
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position::new(0, 3),
                    end: Position::new(1, 5),
                }
            );
        }

        #[test]
        fn empty_span() {
            let src = "hello world";
            let span = SourceSpan::new(5.into(), 0);
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position::new(0, 5),
                    end: Position::new(0, 5),
                }
            );
        }

        #[test]
        fn entire_string() {
            let src = "line1\nline2\nline3";
            let span = SourceSpan::new(0.into(), src.len());
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position::new(0, 0),
                    end: Position::new(2, 5),
                }
            );
        }

        #[test]
        fn empty_string() {
            let src = "";
            let span = SourceSpan::new(0.into(), 0);
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position::new(0, 0),
                    end: Position::new(0, 0),
                }
            );
        }

        #[test]
        fn zero_length_at_string_end() {
            let src = "hello world";
            let span = SourceSpan::new(11.into(), 0);
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position::new(0, 11),
                    end: Position::new(0, 11),
                }
            );
        }

        #[test]
        fn zero_length_at_line_end() {
            let src = "hello\nworld";
            let span = SourceSpan::new(5.into(), 0); // at newline
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position::new(0, 5),
                    end: Position::new(0, 5),
                }
            );
        }

        #[test]
        fn span_is_newline() {
            let src = "line1\nline2";
            let span = SourceSpan::new(5.into(), 1); // the newline character
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position::new(0, 5),
                    end: Position::new(1, 0),
                }
            );
        }

        #[test]
        fn multibyte_characters() {
            let src = "🚀 héllo 世界";
            let span = SourceSpan::new(5.into(), 6); // "héllo" (é is 2 bytes)
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position::new(0, 2),
                    end: Position::new(0, 7),
                }
            );
        }

        #[test]
        fn unicode_across_lines() {
            let src = "🚀\n世界";
            let span = SourceSpan::new(5.into(), 6);
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position::new(1, 0),
                    end: Position::new(1, 2),
                }
            );
        }

        #[test]
        fn offset_out_of_bounds() {
            let src = "hello";
            let span = SourceSpan::new(10.into(), 0);
            assert_eq!(to_range(&span, src), None);
            let span = SourceSpan::new(3.into(), 5);
            assert_eq!(to_range(&span, src), None);
        }
    }

    mod get_char_at_position {
        use super::*;
        use similar_asserts::assert_eq;

        #[test]
        fn valid_positions() {
            let src = "hello\nworld";
            assert_eq!(get_char_at_position(Position::new(0, 0), src), Some('h'));
            assert_eq!(get_char_at_position(Position::new(0, 4), src), Some('o'));
            assert_eq!(get_char_at_position(Position::new(0, 5), src), Some('\n'));
            assert_eq!(get_char_at_position(Position::new(1, 0), src), Some('w'));
            assert_eq!(get_char_at_position(Position::new(1, 4), src), Some('d'));
        }

        #[test]
        fn newlines() {
            assert_eq!(
                get_char_at_position(Position::new(1, 0), "hello\n\nworld"),
                Some('\n')
            );
            assert_eq!(get_char_at_position(Position::new(0, 0), "\n"), Some('\n'));
            assert_eq!(
                get_char_at_position(Position::new(0, 0), "\r\n"),
                Some('\r')
            );
            assert_eq!(get_char_at_position(Position::new(0, 0), "\r"), Some('\r'));
            assert_eq!(get_char_at_position(Position::new(0, 0), "\n"), Some('\n'));
            assert_eq!(
                get_char_at_position(Position::new(0, 0), "\n\n"),
                Some('\n')
            );
        }

        #[test]
        fn unicode_characters() {
            let src = "🚀héllo\nwörld";
            assert_eq!(get_char_at_position(Position::new(0, 0), src), Some('🚀'));
            assert_eq!(get_char_at_position(Position::new(0, 1), src), Some('h'));
            assert_eq!(get_char_at_position(Position::new(0, 2), src), Some('é'));
            assert_eq!(get_char_at_position(Position::new(0, 3), src), Some('l'));
            assert_eq!(get_char_at_position(Position::new(1, 1), src), Some('ö'));
            assert_eq!(get_char_at_position(Position::new(1, 2), src), Some('r'));
        }
    }

    mod get_text_before_position {
        use super::*;
        use similar_asserts::assert_eq;

        #[test]
        fn single_line() {
            let text = "hello world";
            assert_eq!(
                get_text_before_position(text, Position::new(0, 0)).unwrap(),
                ""
            );
            assert_eq!(
                get_text_before_position(text, Position::new(0, 5)).unwrap(),
                "hello"
            );
            assert_eq!(
                get_text_before_position(text, Position::new(0, 11)).unwrap(),
                "hello world"
            );
        }

        #[test]
        fn multi_line() {
            let text = "line1\nline2\nline3";
            assert_eq!(
                get_text_before_position(text, Position::new(0, 5)).unwrap(),
                "line1"
            );
            assert_eq!(
                get_text_before_position(text, Position::new(1, 5)).unwrap(),
                "line1\nline2"
            );
        }

        #[test]
        fn unicode_characters() {
            let text = "🚀H";
            assert_eq!(
                get_text_before_position(text, Position::new(0, 0)).unwrap(),
                ""
            );
            assert_eq!(
                get_text_before_position(text, Position::new(0, 1)).unwrap(),
                "🚀"
            );
            assert_eq!(
                get_text_before_position(text, Position::new(0, 2)).unwrap(),
                "🚀H"
            );
        }
    }

    mod get_text_in_range {
        use tower_lsp_server::lsp_types::{Position, Range};

        use crate::utils::get_text_in_range;

        #[test]
        fn single_line() {
            let text = "hello world";
            assert_eq!(
                get_text_in_range(text, Range::new(Position::new(0, 0), Position::new(0, 5)))
                    .unwrap(),
                "hello"
            );
            assert_eq!(
                get_text_in_range(text, Range::new(Position::new(0, 6), Position::new(0, 11)))
                    .unwrap(),
                "world"
            );
        }

        #[test]
        fn multi_line() {
            let text = "hello\nworld";
            assert_eq!(
                get_text_in_range(text, Range::new(Position::new(0, 4), Position::new(1, 1)))
                    .unwrap(),
                "o\nw"
            );
        }
    }
}
