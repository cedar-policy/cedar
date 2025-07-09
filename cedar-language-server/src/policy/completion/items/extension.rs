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

use tower_lsp_server::lsp_types::{self, CompletionItem, Documentation, MarkupContent};

use crate::documentation::{DecimalDocumentation, IpDocumentation, ToDocumentationString};

pub(crate) struct DecimalCompletionItem;

impl From<DecimalCompletionItem> for CompletionItem {
    fn from(_: DecimalCompletionItem) -> Self {
        Self {
            label: "decimal".to_string(),
            insert_text: Some("decimal(${1})".to_string()),
            insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: tower_lsp_server::lsp_types::MarkupKind::Markdown,
                value: DecimalDocumentation
                    .to_documentation_string(None)
                    .into_owned(),
            })),
            kind: Some(lsp_types::CompletionItemKind::FUNCTION),
            ..Self::default()
        }
    }
}

pub(crate) struct IpCompletionItem;

impl From<IpCompletionItem> for CompletionItem {
    fn from(_: IpCompletionItem) -> Self {
        Self {
            label: "ip".to_string(),
            kind: Some(lsp_types::CompletionItemKind::FUNCTION),
            insert_text: Some("ip(${1:\"127.0.0.1\"})".to_string()),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: tower_lsp_server::lsp_types::MarkupKind::Markdown,
                value: IpDocumentation.to_documentation_string(None).into_owned(),
            })),
            insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
            ..Self::default()
        }
    }
}
