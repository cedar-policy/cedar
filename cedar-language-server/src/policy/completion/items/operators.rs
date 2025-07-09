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
use tower_lsp_server::lsp_types::{self, CompletionItem, CompletionItemKind, InsertTextFormat};

pub(crate) struct IfCompletionItem;

impl From<IfCompletionItem> for CompletionItem {
    fn from(_: IfCompletionItem) -> Self {
        Self {
            label: "if".to_string(),
            kind: Some(CompletionItemKind::SNIPPET),
            insert_text: Some("if ${1:true} then ${2:true} else ${3:false}".to_string()),
            insert_text_format: Some(InsertTextFormat::SNIPPET),
            ..Self::default()
        }
    }
}

pub(crate) struct InCompletionItem;

impl From<InCompletionItem> for CompletionItem {
    fn from(_: InCompletionItem) -> Self {
        Self {
            label: "in".to_string(),
            kind: Some(CompletionItemKind::SNIPPET),
            insert_text: Some("in ${1:expression}".to_string()),
            insert_text_format: Some(InsertTextFormat::SNIPPET),
            ..Self::default()
        }
    }
}

pub(crate) struct HasCompletionItem;

impl From<HasCompletionItem> for CompletionItem {
    fn from(_: HasCompletionItem) -> Self {
        Self {
            label: "has".to_string(),
            kind: Some(CompletionItemKind::SNIPPET),
            insert_text: Some("has ${1:attribute}".to_string()),
            insert_text_format: Some(InsertTextFormat::SNIPPET),
            ..Self::default()
        }
    }
}

pub(crate) struct LikeCompletionItem;

impl From<LikeCompletionItem> for CompletionItem {
    fn from(_: LikeCompletionItem) -> Self {
        Self {
            label: "like".to_string(),
            kind: Some(CompletionItemKind::SNIPPET),
            insert_text: Some("like \"${1:pattern}\"".to_string()),
            insert_text_format: Some(InsertTextFormat::SNIPPET),
            ..Self::default()
        }
    }
}

pub(crate) struct IsCompletionItem;

impl From<IsCompletionItem> for CompletionItem {
    fn from(_: IsCompletionItem) -> Self {
        Self {
            label: "is".to_string(),
            insert_text: Some("is ${1:Entity}".to_string()),
            insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
            ..Self::default()
        }
    }
}

pub(crate) struct IsInCompletionItem;

impl From<IsInCompletionItem> for CompletionItem {
    fn from(_: IsInCompletionItem) -> Self {
        Self {
            label: "is in".to_string(),
            insert_text: Some("is ${1:Entity} in ${2:EntityId}".to_string()),
            insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
            ..Self::default()
        }
    }
}

pub(crate) struct EqCompletionItem;

impl From<EqCompletionItem> for CompletionItem {
    fn from(_: EqCompletionItem) -> Self {
        Self {
            label: "eq".to_string(),
            insert_text: Some("== ${1:EntityId}".to_string()),
            insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
            ..Self::default()
        }
    }
}
