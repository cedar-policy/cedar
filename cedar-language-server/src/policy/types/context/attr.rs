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

use cedar_policy_core::validator::ValidatorSchema;
use itertools::Itertools;
use lsp_types::{
    CompletionItem, CompletionItemKind, Documentation, InsertTextFormat, MarkupContent, MarkupKind,
};

use crate::{
    documentation::ToDocumentationString,
    policy::{
        types::{
            cedar::{Attribute, CedarTypeKind},
            GetType,
        },
        DocumentContext,
    },
};

use super::ReceiverContext;

/// Represents a context for attribute access or attribute existence check expressions.
///
/// This context is used when the user is accessing properties of an entity (e.g., `principal.attr`)
/// or checking if a property exists (e.g., `resource has attr)`). It contains information about
/// the entity expression being accessed and the type of attribute operation being performed.
#[derive(Debug, PartialEq)]
pub(crate) struct AttrContext {
    /// The context of the expression whose attributes are being accessed.
    receiver_cx: ReceiverContext,
    /// Specifies whether this is a property access or existence check.
    kind: AttrContextKind,
}

impl AttrContext {
    #[must_use]
    pub(crate) fn new(receiver_cx: ReceiverContext, kind: AttrContextKind) -> Self {
        Self { receiver_cx, kind }
    }

    #[must_use]
    pub(crate) fn get_completions(
        &self,
        document_context: &DocumentContext<'_>,
    ) -> Vec<CompletionItem> {
        let Some(ty) = self.receiver_cx.get_type(document_context) else {
            return vec![];
        };
        let schema = document_context.schema();
        let items = AttributeCompletionItems::new(&ty, schema, self.kind);
        items.into()
    }
}

/// Identifies the type of attribute operation being performed.
///
/// This enum distinguishes between directly accessing an attribute value
/// and checking for the existence of an attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttrContextKind {
    /// Represents a direct attribute access (e.g., `principal.department`).
    Get,
    /// Represents an attribute existence check (e.g., `resource has owner`).
    Has,
}

struct AttributeCompletionItems<'a> {
    inner: &'a CedarTypeKind,
    schema: Option<&'a ValidatorSchema>,
    kind: AttrContextKind,
}

impl<'a> AttributeCompletionItems<'a> {
    pub(crate) fn new(
        inner: &'a CedarTypeKind,
        schema: Option<&'a ValidatorSchema>,
        kind: AttrContextKind,
    ) -> Self {
        Self {
            inner,
            schema,
            kind,
        }
    }
}

impl From<AttributeCompletionItems<'_>> for Vec<CompletionItem> {
    fn from(value: AttributeCompletionItems<'_>) -> Self {
        let attributes = value
            .inner
            .attributes(value.schema)
            .into_iter()
            .unique()
            .map(|attr| AttributeAndSchema::new(value.schema, attr))
            .map(Into::into)
            .collect::<Self>();

        match value.kind {
            AttrContextKind::Get => {
                let mut attributes = attributes;
                let methods = value
                    .inner
                    .methods()
                    .into_iter()
                    .map(Into::into)
                    .collect::<Self>();
                attributes.extend(methods);
                attributes
            }
            AttrContextKind::Has => attributes,
        }
    }
}

struct AttributeAndSchema<'a>(Option<&'a ValidatorSchema>, Attribute);

impl<'a> AttributeAndSchema<'a> {
    pub(crate) fn new(schema: Option<&'a ValidatorSchema>, attr: Attribute) -> Self {
        Self(schema, attr)
    }
}

impl<'a> From<AttributeAndSchema<'a>> for lsp_types::CompletionItem {
    fn from(attr: AttributeAndSchema<'a>) -> Self {
        Self {
            kind: Some(CompletionItemKind::FIELD),
            detail: Some(attr.1.detail().to_string()),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::Markdown,
                value: attr.1.to_documentation_string(attr.0).into_owned(),
            })),
            label: attr.1.to_label().to_string(),
            insert_text: Some(attr.1.name().to_string()),
            insert_text_format: Some(InsertTextFormat::PLAIN_TEXT),
            ..Self::default()
        }
    }
}
