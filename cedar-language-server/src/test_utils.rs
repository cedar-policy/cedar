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

use std::{fs::read_to_string, str::FromStr};

use cedar_policy_core::ast::PolicyID;
use cedar_policy_core::validator::ValidatorSchema;
use tower_lsp_server::lsp_types::{Position, Range};

use crate::{
    policy::{DocumentContext, PolicyLanguageFeatures},
    schema::SchemaInfo,
};

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
    let template = cedar_policy_core::parser::text_to_cst::parse_policy_tolerant(policy).unwrap();
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
