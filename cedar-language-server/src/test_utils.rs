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
use tower_lsp_server::lsp_types::Position;

use crate::{
    policy::{DocumentContext, PolicyLanguageFeatures},
    position::position_byte_offset,
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
