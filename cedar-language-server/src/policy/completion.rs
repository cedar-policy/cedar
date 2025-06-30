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

use cedar_policy_core::ast::EntityUID;
use cedar_policy_core::validator::ValidatorSchema;
use lsp_types::{CompletionItem, CompletionItemKind, InsertTextFormat, Position};
use provider::PolicyCompletionProvider;

pub(crate) mod items;
mod provider;
pub(crate) mod snippets;

use snippets::condition_completions;

use std::{fmt::Display, sync::Arc};

use crate::schema::SchemaInfo;

use super::{
    context::{AttrContext, BinaryOpContext, IsContext},
    DocumentContext, PolicyLanguageFeatures,
};

/// Provides code completion suggestions for Cedar policies at a given cursor position.
///
/// This function is the main entry point for Cedar policy completion in the language server.
/// It analyzes the policy content at the specified position and generates appropriate
/// completion suggestions based on the policy structure, available schema information,
/// and the current context.
///
/// # Returns
///
/// An `Option<Vec<CompletionItem>>` containing appropriate LSP completion items for the
/// current context, or `None` if completions cannot be provided.
#[must_use]
pub fn policy_completions(
    position: Position,
    policy: &str,
    schema: Option<SchemaInfo>,
    features: PolicyLanguageFeatures,
) -> Option<Vec<CompletionItem>> {
    let validator = schema.and_then(|schema| ValidatorSchema::try_from(&schema).ok());

    let completions =
        PolicyCompletionProvider::get_completions(position, policy, validator, features);

    Some(completions)
}

/// Represents the different types of completion contexts that can occur in a Cedar policy.
///
/// This enum identifies the specific language context where code completion is requested,
/// allowing the language server to provide appropriate suggestions based on the cursor position
/// and surrounding expressions.
#[derive(Debug, PartialEq)]
pub(crate) enum CompletionContextKind {
    /// Context for attribute access expressions (e.g., `principal.department` or `resource has owner`).
    ///
    /// This occurs when the user is accessing properties of an entity and expects
    /// suggestions for valid attributes based on the entity's type.
    Attr(AttrContext),
    /// Context for entity literal completions (e.g., `Action::"get"`).
    ///
    /// This occurs when the user is typing or editing an entity UID,
    /// providing completions for action entity IDs.
    EntityLiteral { entity_uid: Arc<EntityUID> },
    /// Context for type-checking expressions (e.g., `resource is Photo`).
    ///
    /// This occurs when the user is using the 'is' operator and expects
    /// suggestions for valid entity types.
    Is(IsContext),
    /// Context for binary operations (e.g., `==`, `in`).
    ///
    /// This occurs when the user is typing the right-hand side of binary expressions
    /// and expects values appropriate for the operation and left-hand side.
    BinaryOp(BinaryOpContext),
    /// Represents an unidentified completion context.
    ///
    /// This occurs when the language server can't determine a specific context
    /// but might still provide general suggestions.
    Unknown,
    /// Context providing fixed, pre-defined completion items.
    ///
    /// This is used when a specific set of completion items should be
    /// offered regardless of other context.
    Identity(Vec<CompletionItem>),
    /// Default context for policy scope sections (before the `when` clause).
    ///
    /// This can be used to provide suggestions for the principal, action,
    /// and resource declarations at the beginning of a policy.
    ScopeDefault,
    /// Default context for policy condition expressions (inside the `when` block).
    ///
    /// This provides common completion suggestions for expressions within
    /// the condition block of a policy.
    ConditionDefault,
    /// Context where no completions should be provided.
    ///
    /// This is used to explicitly indicate that no suggestions are appropriate
    /// in the current context (e.g., inside a string literal).
    None,
}

impl CompletionContextKind {
    /// Converts the completion context into actual completion items based on the document context.
    ///
    /// This method transforms the abstract completion context into concrete LSP completion
    /// suggestions that can be presented to the user.
    #[must_use]
    pub(crate) fn into_completion_items(
        self,
        document_context: &DocumentContext<'_>,
    ) -> Vec<CompletionItem> {
        match self {
            Self::Attr(cx) => cx.get_completions(document_context),
            Self::Is(cx) => cx.get_completions(document_context),
            Self::EntityLiteral { entity_uid } => {
                EntityUIDCompletionItems::new(&entity_uid, document_context.schema()).into()
            }
            Self::BinaryOp(cx) => cx.get_completions(document_context),
            Self::Identity(completion_items) => completion_items,
            Self::ConditionDefault => condition_completions(document_context),
            _ => Vec::new(),
        }
    }
}

impl Display for CompletionContextKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Attr { .. } => write!(f, "Attr"),
            Self::EntityLiteral { entity_uid } => {
                write!(f, "EntityLiteral<{entity_uid}>")
            }
            Self::Is { .. } => write!(f, "Is"),
            Self::Unknown => write!(f, "Unknown"),
            Self::BinaryOp(binary_op) => write!(f, "{binary_op:?}"),
            Self::Identity(completion_items) => write!(f, "{completion_items:?}"),
            Self::None => write!(f, "None"),
            Self::ScopeDefault => write!(f, "ScopeDefault"),
            Self::ConditionDefault => write!(f, "ConditionDefault"),
        }
    }
}

struct EntityUIDCompletionItems<'a> {
    inner: &'a EntityUID,
    schema: Option<&'a ValidatorSchema>,
}

impl<'a> EntityUIDCompletionItems<'a> {
    pub(crate) fn new(inner: &'a EntityUID, schema: Option<&'a ValidatorSchema>) -> Self {
        Self { inner, schema }
    }
}

impl<'a> From<EntityUIDCompletionItems<'a>> for Vec<CompletionItem> {
    fn from(value: EntityUIDCompletionItems<'a>) -> Self {
        match value.schema {
            Some(schema) if value.inner.is_action() => schema
                .actions()
                .map(cedar_policy_core::ast::EntityUID::eid)
                .map(cedar_policy_core::ast::Eid::escaped)
                .map(|a| CompletionItem {
                    kind: Some(CompletionItemKind::CONSTANT),
                    insert_text: Some(a.to_string()),
                    insert_text_format: Some(InsertTextFormat::PLAIN_TEXT),
                    label: a.to_string(),
                    ..CompletionItem::default()
                })
                .collect(),
            _ => vec![],
        }
    }
}
