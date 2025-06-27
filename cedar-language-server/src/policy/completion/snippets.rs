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

#![allow(clippy::literal_string_with_formatting_args)]
use lsp_types::{CompletionItem, CompletionItemKind, Position};

use crate::{
    policy::{
        completion::items::{
            ActionCompletionItem, BoolCompletionItem, ContextCompletionIem, DecimalCompletionItem,
            IpCompletionItem, PrincipalCompletionItem, ResourceCompletionItem,
        },
        items::{HasCompletionItem, IfCompletionItem, InCompletionItem, LikeCompletionItem},
    },
    utils::position_within_loc,
};

use crate::policy::DocumentContext;

pub(crate) fn should_show_policy_snippets(text: &str, cursor_position: Position) -> bool {
    if text.is_empty() {
        return true;
    }

    // Get the current line text up to the cursor
    let lines: Vec<&str> = text.split('\n').collect();

    // Guard against out of bounds
    let Some(current_line) = lines.get(cursor_position.line as usize) else {
        return false;
    };

    let line_prefix = current_line
        .get(..cursor_position.character as usize)
        .unwrap_or(current_line);

    // Check if the line prefix only contains whitespace or just policy effect keywords
    let trimmed_prefix = line_prefix.trim();
    let is_blank_or_just_effect = trimmed_prefix.is_empty()
        || trimmed_prefix == "p"
        || trimmed_prefix == "permit"
        || trimmed_prefix == "f"
        || trimmed_prefix == "forbid";

    if !is_blank_or_just_effect {
        // Check if we might be in the middle of typing a policy
        if trimmed_prefix.contains("permit(") || trimmed_prefix.contains("forbid(") {
            return false;
        }
    }

    // Check surrounding context for partial policies
    // Look at all text before cursor to check for unclosed parentheses
    let text_before_cursor = get_text_before_cursor(text, cursor_position);

    // If we have unclosed parentheses or any policy keyword with unclosed elements,
    // we're likely in the middle of typing a policy
    if has_unclosed_policy_elements(&text_before_cursor) {
        return false;
    }

    // Now check the policy context using the Cedar CST parser
    match cedar_policy_core::parser::text_to_cst::parse_policies(text) {
        Ok(cst) => {
            // If no policies exist, show snippets
            if cst.node.is_none() {
                return true;
            }

            // Check if we're not inside an existing policy
            let policies = cst.node.map(|p| p.0).unwrap_or_default();

            // If we have at least one policy, check if we're after the last one's terminating semicolon
            if !policies.is_empty() {
                // If none of the policies contain our cursor, we're ready to create a new one
                let within_existing_policy = policies
                    .iter()
                    .any(|p| position_within_loc(cursor_position, p.loc.as_ref()));

                return !within_existing_policy;
            }

            true
        }
        Err(_) => {
            // Even if parsing fails, we've already checked for unclosed policy elements above
            // So if we reach here, it's likely safe to show snippets
            is_blank_or_just_effect
        }
    }
}

/// Gets all text before the cursor position
fn get_text_before_cursor(text: &str, cursor_position: Position) -> String {
    let mut result = String::new();
    for (i, line) in text.lines().enumerate() {
        match i.cmp(&(cursor_position.line as usize)) {
            std::cmp::Ordering::Less => {
                result.push_str(line);
                result.push('\n');
            }
            std::cmp::Ordering::Equal => {
                if cursor_position.character as usize <= line.len() {
                    result.push_str(&line[..cursor_position.character as usize]);
                } else {
                    result.push_str(line);
                }
                break;
            }
            std::cmp::Ordering::Greater => {
                break;
            }
        }
    }

    result
}

/// Checks if there are unclosed policy elements in the text
fn has_unclosed_policy_elements(text: &str) -> bool {
    // Look for permit or forbid followed by unclosed parentheses
    let mut parens_count = 0;
    let mut in_policy_declaration = false;

    for (i, c) in text.char_indices() {
        if c == '(' {
            parens_count += 1;

            // Check if this opening parenthesis is part of a policy declaration
            if i >= 6 && matches!(&text[i - 6..=i], "permit(" | "forbid(") {
                in_policy_declaration = true;
            }
        } else if c == ')' {
            parens_count -= 1;
        } else if c == ';' && parens_count == 0 {
            // Reset policy declaration flag after a semicolon
            in_policy_declaration = false;
        }
    }

    // If we have unclosed parentheses and we detected a policy declaration, we're in a policy
    parens_count > 0 && in_policy_declaration
}

pub(crate) fn get_snippets() -> Vec<CompletionItem> {
    // Basic snippets always available
    let mut snippets = vec![
        new_policy_snippet(
            "permit",
            "Basic permit policy",
            "permit(principal${1}, action${2}, resource${3});",
        ),
        new_policy_snippet(
            "forbid",
            "Basic forbid policy",
            "forbid(principal${1}, action${2}, resource${3});",
        ),
    ];

    // Add more detailed snippets based on partial input
    snippets.extend(vec![
        new_policy_snippet(
            "permit when",
            "Permit policy with when condition",
            "permit(principal${1}, action${2}, resource${3})\nwhen {\n\t${4:true}\n};",
        ),
        new_policy_snippet(
            "permit unless",
            "Permit policy with unless condition",
            "permit(principal${1}, action${2}, resource${3})\nunless {\n\t${4:false}\n};",
        ),
    ]);
    snippets.extend(vec![
        new_policy_snippet(
            "forbid when",
            "Forbid policy with when condition",
            "forbid(principal${1}, action${2}, resource${3})\nwhen {\n\t${4:true}\n};",
        ),
        new_policy_snippet(
            "forbid unless",
            "Forbid policy with unless condition",
            "forbid(principal${1}, action${2}, resource${3})\nunless {\n\t${4:false}\n};",
        ),
    ]);

    snippets
}

fn new_policy_snippet(label: &str, detail: &str, new_text: &str) -> CompletionItem {
    CompletionItem {
        label: label.to_string(),
        kind: Some(CompletionItemKind::SNIPPET),
        detail: Some(detail.to_string()),
        insert_text: Some(new_text.to_string()),
        insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
        ..CompletionItem::default()
    }
}

pub(crate) fn equals_euid_snippet(curr_char: Option<char>) -> CompletionItem {
    CompletionItem {
        label: "Equals Entity UID".to_string(),
        kind: Some(CompletionItemKind::SNIPPET),
        insert_text: Some("${1:EntityType}::\"${2:id}\"".to_string()),
        insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
        preselect: Some(true),
        filter_text: curr_char.map(|c| c.to_string()),
        ..CompletionItem::default()
    }
}

pub(crate) fn equals_action_euid_snippet(curr_char: Option<char>) -> CompletionItem {
    CompletionItem {
        label: "Equals Action UID".to_string(),
        kind: Some(CompletionItemKind::SNIPPET),
        insert_text: Some("${1:Action}::\"${2:id}\"".to_string()),
        insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
        preselect: Some(true),
        filter_text: curr_char.map(|c| c.to_string()),
        ..CompletionItem::default()
    }
}

pub(crate) fn in_action_group_snippet(curr_char: Option<char>) -> CompletionItem {
    CompletionItem {
        label: "In Action Group".to_string(),
        kind: Some(CompletionItemKind::SNIPPET),
        insert_text: Some("${1:Action}::\"${2:id}\"".to_string()),
        insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
        preselect: Some(true),
        filter_text: curr_char.map(|c| c.to_string()),
        ..CompletionItem::default()
    }
}

pub(crate) fn in_action_set_snippet(curr_char: Option<char>) -> CompletionItem {
    CompletionItem {
        label: "In Action Set".to_string(),
        kind: Some(CompletionItemKind::SNIPPET),
        insert_text: Some("[${1:Action}::\"${2:id}\"${3}]".to_string()),
        insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
        preselect: Some(true),
        filter_text: curr_char.map(|c| c.to_string()),
        ..CompletionItem::default()
    }
}

pub(crate) fn in_entity_snippet(curr_char: Option<char>) -> CompletionItem {
    CompletionItem {
        label: "In Entity UID".to_string(),
        kind: Some(CompletionItemKind::SNIPPET),
        insert_text: Some("${1:EntityType}::\"${2:id}\"".to_string()),
        insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
        preselect: Some(true),
        filter_text: curr_char.map(|c| c.to_string()),
        ..CompletionItem::default()
    }
}

pub(crate) fn condition_completions(doc_cx: &DocumentContext<'_>) -> Vec<CompletionItem> {
    vec![
        PrincipalCompletionItem::from(doc_cx).into(),
        ActionCompletionItem::from(doc_cx).into(),
        ResourceCompletionItem::from(doc_cx).into(),
        ContextCompletionIem::from(doc_cx).into(),
        BoolCompletionItem(true).into(),
        BoolCompletionItem(false).into(),
        DecimalCompletionItem.into(),
        IpCompletionItem.into(),
        IfCompletionItem.into(),
        InCompletionItem.into(),
        HasCompletionItem.into(),
        LikeCompletionItem.into(),
    ]
}
