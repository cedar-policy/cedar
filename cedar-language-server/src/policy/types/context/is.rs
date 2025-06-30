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

use cedar_policy_core::ast::EntityType;
use cedar_policy_core::validator::ValidatorSchema;
use itertools::Itertools;
use lsp_types::{CompletionItem, CompletionItemKind, InsertTextFormat};

use crate::policy::{
    types::{
        cedar::{CedarTypeKind, EntityTypeKind},
        GetType,
    },
    DocumentContext,
};

use super::ReceiverContext;

/// Represents a context for type-checking expressions using the `is` operator.
///
/// This context is used when the user is writing an expression that checks an entity's type
/// (e.g., `principal is User`). It contains information about the entity expression being
/// type-checked, which helps determine what entity types are valid completions.
#[derive(Debug, PartialEq)]
pub(crate) struct IsContext {
    /// The context of the entity expression whose type is being checked.
    receiver_cx: ReceiverContext,
}

impl IsContext {
    #[must_use]
    pub(crate) fn new(receiver_cx: ReceiverContext) -> Self {
        Self { receiver_cx }
    }

    #[must_use]
    pub(crate) fn get_completions(
        &self,
        document_context: &DocumentContext<'_>,
    ) -> Vec<CompletionItem> {
        let Some(ty) = self.receiver_cx.get_type(document_context) else {
            return vec![];
        };

        let is_completions = IsCompletionItems::new(&ty, document_context.schema());
        is_completions.into()
    }
}

struct IsCompletionItems<'a> {
    inner: &'a CedarTypeKind,
    schema: Option<&'a ValidatorSchema>,
}

impl<'a> IsCompletionItems<'a> {
    pub(crate) fn new(inner: &'a CedarTypeKind, schema: Option<&'a ValidatorSchema>) -> Self {
        Self { inner, schema }
    }

    fn entity_type_into(entity_type: &EntityType) -> CompletionItem {
        CompletionItem {
            kind: Some(CompletionItemKind::CLASS),
            insert_text: Some(entity_type.to_string()),
            insert_text_format: Some(InsertTextFormat::PLAIN_TEXT),
            label: entity_type.to_string(),
            ..CompletionItem::default()
        }
    }

    fn any_principal_into(&self) -> Vec<CompletionItem> {
        let Some(schema) = self.schema else {
            return vec![];
        };

        schema
            .principals()
            .unique()
            .map(Self::entity_type_into)
            .collect()
    }

    fn any_resource_into(&self) -> Vec<CompletionItem> {
        let Some(schema) = self.schema else {
            return vec![];
        };

        schema
            .resources()
            .unique()
            .map(Self::entity_type_into)
            .collect()
    }
}

impl<'a> From<IsCompletionItems<'a>> for Vec<CompletionItem> {
    fn from(value: IsCompletionItems<'a>) -> Self {
        match value.inner {
            CedarTypeKind::EntityType(EntityTypeKind::Set(set)) => set
                .iter()
                .map(|et| IsCompletionItems::entity_type_into(et))
                .collect(),
            CedarTypeKind::EntityType(EntityTypeKind::AnyPrincipal) => value.any_principal_into(),
            CedarTypeKind::EntityType(EntityTypeKind::AnyResource) => value.any_resource_into(),
            // not suggesting a concrete entity because its concrete?
            _ => vec![],
        }
    }
}
