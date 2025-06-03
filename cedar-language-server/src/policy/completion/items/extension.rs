use lsp_types::{CompletionItem, Documentation, MarkupContent};

use crate::markdown::{DecimalDocumentation, IpDocumentation, ToDocumentationString};

pub(crate) struct DecimalCompletionItem;

impl From<DecimalCompletionItem> for CompletionItem {
    fn from(_: DecimalCompletionItem) -> Self {
        Self {
            label: "decimal".to_string(),
            insert_text: Some("decimal(${1})".to_string()),
            insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: lsp_types::MarkupKind::Markdown,
                value: DecimalDocumentation.to_documentation_string(None),
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
                kind: lsp_types::MarkupKind::Markdown,
                value: IpDocumentation.to_documentation_string(None),
            })),
            insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
            ..Self::default()
        }
    }
}
