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

use super::SchemaInfo;
use regex::Regex;
use std::collections::HashMap;
use tower_lsp_server::lsp_types::{
    self, CompletionItem, CompletionItemKind, CompletionResponse, Position, Range,
};

// PANIC SAFETY: These regex are valid and would panic immediately in test if not.
#[allow(clippy::unwrap_used)]
mod regex_consts {
    use regex::Regex;
    use std::sync::LazyLock;
    pub(crate) static NAMESPACE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^namespace\s+(([_a-zA-Z][_a-zA-Z0-9]*::)*[_a-zA-Z][_a-zA-Z0-9]*)\s*\{")
            .unwrap()
    });

    pub(crate) static TYPE_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^type\s+([_a-zA-Z][_a-zA-Z0-9]*)\s*=").unwrap());

    pub(crate) static ENTITY: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^entity\s+(([_a-zA-Z][_a-zA-Z0-9]*, \s*)*[_a-zA-Z][_a-zA-Z0-9]*)\s*( in|=|\{|;|\$)",
        )
        .unwrap()
    });

    pub(crate) static ACTION: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"^action\s+([_a-zA-Z0-9, "]*)(?: in| appliesTo|;|\$)"#).unwrap()
    });
}

pub(crate) fn schema_completions(
    position: Position,
    schema: &SchemaInfo,
) -> Option<CompletionResponse> {
    let text = &schema.text;
    let p = CedarSchemaParser::new();

    p.provide_cedar_schema_completions(text, position)
        .map(CompletionResponse::Array)
}

#[derive(Debug, Clone)]
pub(crate) struct SchemaDefinitions {
    ranges: Vec<Range>,
}

impl SchemaDefinitions {
    pub(crate) fn new(ranges: Vec<Range>) -> Self {
        Self { ranges }
    }
}

/// Cedar Schema Parser implementation for LSP functionality.
///
/// This module provides parsing and completion functionality for Cedar Schema Language,
/// ported from the TypeScript implementation at
/// <https://github.com/cedar-policy/vscode-cedar/blob/main/src/parser.ts>.
///
/// The `CedarSchemaParser` struct provides methods to:
///
/// 1. Parse Cedar schema content and identify definition ranges
/// 2. Provide code completion items with snippets for common Cedar schema constructs
///
/// The parser handles Cedar schema-specific syntax including namespaces, type definitions,
/// entity declarations with inheritance, and action definitions with application contexts.
pub(crate) struct CedarSchemaParser {
    namespace: &'static Regex,
    r#type: &'static Regex,
    entity: &'static Regex,
    action: &'static Regex,
}

impl CedarSchemaParser {
    pub(crate) fn new() -> Self {
        Self {
            namespace: &regex_consts::NAMESPACE,
            r#type: &regex_consts::TYPE_REGEX,
            entity: &regex_consts::ENTITY,
            action: &regex_consts::ACTION,
        }
    }

    pub(crate) fn parse_cedar_schema(&self, doc_text: &str) -> SchemaDefinitions {
        let mut ranges = Vec::new();
        let mut namespace = String::new();
        let mut declarations = HashMap::new();
        let mut declaration_start_line = -1_isize;

        for (i, line) in doc_text.lines().enumerate() {
            let i = i as isize;
            let line_pre_comment = line.find("//").map_or(line, |pos| &line[..pos]).trim();

            if line_pre_comment.is_empty() {
                continue;
            }

            // Process namespace declaration
            if line_pre_comment.starts_with("namespace") {
                if let Some(captures) = self.namespace.captures(line_pre_comment) {
                    if let Some(ns_match) = captures.get(1) {
                        namespace = format!("{}::", ns_match.as_str());
                    }
                }
            } else if declaration_start_line == -1 && line_pre_comment == "}" {
                // End of namespace
                namespace.clear();
            }

            // Process type declarations
            if line_pre_comment.starts_with("type") && declaration_start_line == -1 {
                declaration_start_line = i;
                Self::process_declaration(
                    self.r#type,
                    line,
                    i,
                    line_pre_comment,
                    &namespace,
                    &mut declarations,
                );
            }

            // Process entity declarations
            if line_pre_comment.starts_with("entity") && declaration_start_line == -1 {
                declaration_start_line = i;
                Self::process_declaration(
                    self.entity,
                    line,
                    i,
                    line_pre_comment,
                    &namespace,
                    &mut declarations,
                );
            }

            // Process action declarations
            if line_pre_comment.starts_with("action") && declaration_start_line == -1 {
                declaration_start_line = i;
                self.process_action_declaration(
                    line,
                    i,
                    line_pre_comment,
                    &namespace,
                    &mut declarations,
                );
            }

            // Check for end of declaration
            if line_pre_comment.ends_with(';') && declaration_start_line != -1 {
                let declaration_range = Range {
                    start: Position::new(declaration_start_line as u32, 0),
                    end: Position::new(i as u32, line.len() as u32),
                };

                ranges.push(declaration_range);
                declaration_start_line = -1;
                declarations.clear();
            }
        }

        SchemaDefinitions::new(ranges)
    }

    fn process_declaration(
        regex: &Regex,
        line: &str,
        line_idx: isize,
        line_pre_comment: &str,
        namespace: &str,
        declarations: &mut HashMap<String, Option<Range>>,
    ) {
        if let Some(captures) = regex.captures(line_pre_comment) {
            if let Some(entities_match) = captures.get(1) {
                let entities = entities_match.as_str();

                for entity_type in entities.split(',') {
                    let trimmed_type = entity_type.trim();
                    if let Some(range) = find_range(line, line_idx as usize, trimmed_type) {
                        declarations.insert(format!("{namespace}{trimmed_type}"), Some(range));
                    }
                }
            }
        }
    }

    fn process_action_declaration(
        &self,
        line: &str,
        line_idx: isize,
        line_pre_comment: &str,
        namespace: &str,
        declarations: &mut HashMap<String, Option<Range>>,
    ) {
        if let Some(captures) = self.action.captures(line_pre_comment) {
            if let Some(actions_match) = captures.get(1) {
                let actions = actions_match.as_str();

                for action_id in actions.split(',') {
                    let trimmed_id = action_id.trim();
                    let is_quoted = trimmed_id.starts_with('"') && trimmed_id.ends_with('"');

                    if let Some(range) = find_range(line, line_idx as usize, trimmed_id) {
                        // Extract the actual action ID, removing quotes if present
                        let actual_id = if is_quoted && trimmed_id.len() >= 2 {
                            &trimmed_id[1..trimmed_id.len() - 1]
                        } else {
                            trimmed_id
                        };

                        declarations
                            .insert(format!("{namespace}Action::\"{actual_id}\""), Some(range));
                    }
                }
            }
        }
    }

    pub(crate) fn provide_cedar_schema_completions(
        &self,
        doc_text: &str,
        position: Position,
    ) -> Option<Vec<CompletionItem>> {
        let lines: Vec<&str> = doc_text.lines().collect();
        let line_index = position.line as usize;

        let line_text = lines.get(line_index)?;
        let line_prefix = if (position.character as usize) <= line_text.len() {
            &line_text[..position.character as usize]
        } else {
            line_text // Handle out-of-bounds case
        };

        let trimmed_prefix = line_prefix.trim();

        // Handle namespace snippet for 'n' at last line
        if line_index == lines.len() - 1 && trimmed_prefix == "n" {
            return Some(Self::create_namespace_snippet_items());
        }

        // Handle other snippets if they're single letters and not inside a definition
        if trimmed_prefix.len() == 1 {
            // Check we're not inside a definition range
            let schema_defs = self.parse_cedar_schema(doc_text);
            if schema_defs
                .ranges
                .iter()
                .any(|range| is_position_in_range(position, range))
            {
                return None;
            }

            // Return appropriate snippet based on the trigger character
            match trimmed_prefix {
                "a" => return Some(Self::create_action_snippet_items()),
                "e" => return Some(Self::create_entity_snippet_items()),
                "t" => return Some(Self::create_type_snippet_items()),
                _ => {}
            }
        }

        None
    }

    // Snippet creation functions
    fn create_namespace_snippet_items() -> Vec<CompletionItem> {
        vec![CompletionItem {
            label: "namespace".to_string(),
            kind: Some(CompletionItemKind::SNIPPET),
            insert_text: Some(NAMESPACE_SNIPPET.to_string()),
            insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
            ..CompletionItem::default()
        }]
    }

    fn create_entity_snippet_items() -> Vec<CompletionItem> {
        vec![
            CompletionItem {
                label: "entity".to_string(),
                kind: Some(CompletionItemKind::SNIPPET),
                insert_text: Some(ENTITY_SNIPPET.to_string()),
                insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
                ..CompletionItem::default()
            },
            CompletionItem {
                label: "entity in".to_string(),
                kind: Some(CompletionItemKind::SNIPPET),
                insert_text: Some(ENTITY_IN_SNIPPET.to_string()),
                insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
                ..CompletionItem::default()
            },
        ]
    }

    fn create_type_snippet_items() -> Vec<CompletionItem> {
        vec![CompletionItem {
            label: "type".to_string(),
            kind: Some(CompletionItemKind::SNIPPET),
            insert_text: Some(TYPE_SNIPPET.to_string()),
            insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
            ..CompletionItem::default()
        }]
    }

    fn create_action_snippet_items() -> Vec<CompletionItem> {
        vec![
            CompletionItem {
                label: "action".to_string(),
                kind: Some(CompletionItemKind::SNIPPET),
                insert_text: Some(ACTION_SNIPPET.to_string()),
                insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
                ..CompletionItem::default()
            },
            CompletionItem {
                label: "action in".to_string(),
                kind: Some(CompletionItemKind::SNIPPET),
                insert_text: Some(ACTION_IN_SNIPPET.to_string()),
                insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
                ..CompletionItem::default()
            },
        ]
    }
}

// Helper function to find a text match within a line and create a Range
fn find_range(line: &str, line_idx: usize, text: &str) -> Option<Range> {
    line.find(text).map(|start_pos| Range {
        start: Position::new(line_idx as u32, start_pos as u32),
        end: Position::new(line_idx as u32, (start_pos + text.len()) as u32),
    })
}

// Helper function to check if a position is within a range
fn is_position_in_range(position: Position, range: &Range) -> bool {
    // Check if position is between start and end lines
    if position.line < range.start.line || position.line > range.end.line {
        return false;
    }

    // Check character position if on boundary lines
    if position.line == range.start.line && position.character < range.start.character {
        return false;
    }

    if position.line == range.end.line && position.character > range.end.character {
        return false;
    }

    true
}

const ACTION_SNIPPET: &str = r#"action "${1}" appliesTo {
    principal: ${2:Principal},
    resource: ${3:Resource},
    context: {$0}
};
"#;

const ACTION_IN_SNIPPET: &str = r#"action "${1}" in [${2}] appliesTo {
    principal: ${3:Principal},
    resource: ${4:Resource},
    context: {$0}
};
"#;

const ENTITY_SNIPPET: &str = r"entity ${1} {
    ${0}
};
";

const ENTITY_IN_SNIPPET: &str = r"entity ${1} in [${2}] {
    ${0}
};
";

const TYPE_SNIPPET: &str = r"type ${1} {
    ${0}
};
";

const NAMESPACE_SNIPPET: &str = r"namespace ${1} {
    ${0}
}
";

#[allow(clippy::literal_string_with_formatting_args)]
#[cfg(test)]
mod test {
    use super::CedarSchemaParser;
    use crate::utils::tests::remove_caret_marker;
    use itertools::Itertools;
    use tracing_test::traced_test;

    macro_rules! completion_test {
        ($name:ident, $schema:expr, $expected:expr) => {
            #[test]
            #[traced_test]
            fn $name() {
                let (schema, position) = remove_caret_marker($schema);

                let completions = CedarSchemaParser::new()
                    .provide_cedar_schema_completions(&schema, position)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|item| item.insert_text.unwrap_or(item.label))
                    .sorted()
                    .collect_vec();

                assert_eq!($expected, completions);
            }
        };
    }

    completion_test!(
        complete_namespace,
        "n|caret|",
        vec!["namespace ${1} {\n    ${0}\n}\n"]
    );

    completion_test!(
        complete_namespace_after_entity_def,
        "entity User;\nn|caret|",
        vec!["namespace ${1} {\n    ${0}\n}\n"]
    );

    completion_test!(
        complete_namespace_after_ns_def,
        "namespace ns { };\nn|caret|",
        vec!["namespace ${1} {\n    ${0}\n}\n"]
    );

    completion_test!(
        complete_entity,
        "e|caret|",
        vec![
            "entity ${1} in [${2}] {\n    ${0}\n};\n",
            "entity ${1} {\n    ${0}\n};\n"
        ]
    );

    completion_test!(
        complete_entity_after_def,
        "action view;\ne|caret|",
        vec![
            "entity ${1} in [${2}] {\n    ${0}\n};\n",
            "entity ${1} {\n    ${0}\n};\n"
        ]
    );

    completion_test!(
        complete_entity_before_def,
        "e|caret|\ntype ty;",
        vec![
            "entity ${1} in [${2}] {\n    ${0}\n};\n",
            "entity ${1} {\n    ${0}\n};\n"
        ]
    );

    completion_test!(
        complete_entity_in_namespace,
        "namespace ns {\ne|caret|\n};",
        vec![
            "entity ${1} in [${2}] {\n    ${0}\n};\n",
            "entity ${1} {\n    ${0}\n};\n"
        ]
    );

    completion_test!(
        no_complete_in_attributes,
        "entity User {\n e|caret|\n};",
        Vec::<String>::new()
    );

    completion_test!(
        complete_action,
        "a|caret|",
        vec!["action \"${1}\" appliesTo {\n    principal: ${2:Principal},\n    resource: ${3:Resource},\n    context: {$0}\n};\n", "action \"${1}\" in [${2}] appliesTo {\n    principal: ${3:Principal},\n    resource: ${4:Resource},\n    context: {$0}\n};\n"]
    );

    completion_test!(
        complete_typedef,
        "t|caret|",
        vec!["type ${1} {\n    ${0}\n};\n"]
    );
}
