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
use std::{collections::HashSet, iter::once, sync::Arc};

use crate::policy::{
    cedar::{CedarTypeKind, EntityTypeKind},
    completion::snippets::{
        condition_completions, equals_action_euid_snippet, equals_euid_snippet,
        in_action_group_snippet, in_action_set_snippet, in_entity_snippet,
    },
    DocumentContext, GetType,
};
use cedar_policy_core::ast::{EntityUID, Expr, ExprKind, Literal};
use itertools::Itertools;
use lsp_types::{CompletionItem, CompletionItemKind};

/// Represents the context for completing a binary operation expression.
///
/// This context is used when the user is typing a binary operation (like equality or membership)
/// and provides information about the operation being performed and both sides of the expression.
/// It helps determine appropriate completions for the side that needs to be filled in.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BinaryOpContext {
    /// The binary operator being used in the expression.
    pub(crate) op: Op,
    /// The expression on the side where completion is needed.
    ///
    /// This represents the expression that the user is currently typing
    /// or editing and needs completion suggestions for.
    pub(crate) complete_side_expr: Arc<Expr>,
    /// The expression on the other side of the binary operation.
    ///
    /// This already-typed expression provides context for determining
    /// appropriate completions for the side being completed.
    pub(crate) other_side_expr: Arc<Expr>,
}

/// Represents the type of binary operator in a binary operation.
///
/// This enum identifies which binary operator is being used in an expression,
/// which affects what kind of completions should be offered.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Op {
    Eq,
    In(InKind),
}

impl Op {
    #[must_use]
    pub(crate) fn eq() -> Self {
        Self::Eq
    }

    #[must_use]
    pub(crate) fn in_array() -> Self {
        Self::In(InKind::ArrayLiteral)
    }

    #[must_use]
    pub(crate) fn in_entity() -> Self {
        Self::In(InKind::Entity)
    }
}

/// Specifies the kind of container used in an `in` operation.
///
/// This enum distinguishes between membership tests involving entity sets
/// and those involving array literals, which require different completion strategies.
#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum InKind {
    Entity,
    ArrayLiteral,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CompletionType {
    // Completion of an entity id notably for actions i.e Action::"{{action id completion}}"
    EntityId,
    // Completion of an entity euid, applies for all variables. When not an action returns an euid snippet
    Euid,
    Unknown,
}

impl CompletionType {
    pub(crate) fn is_euid(self) -> bool {
        matches!(self, Self::Euid)
    }

    pub(crate) fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }
}

impl BinaryOpContext {
    #[must_use]
    pub(crate) fn new(op: Op, other_side_expr: Arc<Expr>, completion_side_expr: Arc<Expr>) -> Self {
        Self {
            op,
            other_side_expr,
            complete_side_expr: completion_side_expr,
        }
    }

    #[must_use]
    pub(crate) fn get_completions(
        &self,
        document_context: &DocumentContext,
    ) -> Vec<CompletionItem> {
        let completion_side_type = self
            .complete_side_expr
            .expr_kind()
            .get_type(document_context);
        let other_side_type = self.other_side_expr.expr_kind().get_type(document_context);
        let Some((other_side_type, completion_side_type)) =
            other_side_type.zip(completion_side_type)
        else {
            return vec![];
        };

        match (&self.op, document_context.schema.as_ref()) {
            (Op::Eq, Some(_)) => {
                self.eq_completions(other_side_type, completion_side_type, document_context)
            }
            (Op::Eq, None) => Self::schemaless_eq(&other_side_type, document_context),
            (Op::In(InKind::ArrayLiteral), Some(_)) => {
                self.in_array_completions(other_side_type, document_context)
            }
            (Op::In(InKind::Entity), Some(_)) => {
                self.in_completions(other_side_type, document_context)
            }
            (Op::In(..), None) => {
                Self::schemaless_in_completions(&other_side_type, document_context)
            }
        }
    }

    fn eq_completions(
        &self,
        other_side: CedarTypeKind,
        _completion_side: CedarTypeKind,
        document_context: &DocumentContext,
    ) -> Vec<CompletionItem> {
        let Some(schema) = document_context.schema.as_ref() else {
            return vec![];
        };
        let complete_type = get_completion_type(&self.complete_side_expr, document_context);

        if complete_type.is_unknown() {
            return vec![];
        }

        match other_side {
            CedarTypeKind::EntityType(EntityTypeKind::AnyPrincipal) if complete_type.is_euid() => {
                schema
                    .principals()
                    .map(cedar_policy_core::ast::EntityType::name)
                    .unique()
                    .map(|p| CompletionItem {
                        label: p.to_string(),
                        kind: Some(CompletionItemKind::CLASS),
                        insert_text: Some(format!("{p}::\"${{1:entityId}}\"")),
                        insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
                        ..CompletionItem::default()
                    })
                    .chain(document_context.get_variable_completions())
                    .collect()
            }
            CedarTypeKind::EntityType(EntityTypeKind::AnyResource) if complete_type.is_euid() => {
                schema
                    .resources()
                    .map(cedar_policy_core::ast::EntityType::name)
                    .unique()
                    .map(|p| CompletionItem {
                        label: p.to_string(),
                        kind: Some(CompletionItemKind::CLASS),
                        insert_text: Some(format!("{p}::\"${{1:entityId}}\"")),
                        insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
                        ..CompletionItem::default()
                    })
                    .chain(document_context.get_variable_completions())
                    .collect()
            }
            CedarTypeKind::EntityType(EntityTypeKind::Concrete(et)) if complete_type.is_euid() => {
                document_context
                    .get_variable_completions()
                    .into_iter()
                    .chain(vec![CompletionItem {
                        label: et.to_string(),
                        kind: Some(CompletionItemKind::SNIPPET),
                        insert_text: Some(format!("{et}::\"${{1:entityId}}\"")),
                        insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
                        ..CompletionItem::default()
                    }])
                    .collect()
            }
            CedarTypeKind::EntityType(EntityTypeKind::Set(set)) if complete_type.is_euid() => set
                .into_iter()
                .map(|et| CompletionItem {
                    label: et.to_string(),
                    kind: Some(CompletionItemKind::SNIPPET),
                    insert_text: Some(format!("{et}::\"${{1:entityId}}\"")),
                    insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
                    ..CompletionItem::default()
                })
                .chain(document_context.get_variable_completions())
                .collect(),
            CedarTypeKind::Action => schema
                .actions()
                .filter(|euid| !schema.action_groups().contains(euid))
                .map(|euid| {
                    let text = if complete_type.is_euid() {
                        euid.to_string()
                    } else {
                        euid.eid().escaped().to_string()
                    };
                    CompletionItem {
                        label: text.clone(),
                        documentation: Some(lsp_types::Documentation::String(euid.to_string())),
                        kind: Some(CompletionItemKind::ENUM_MEMBER),
                        insert_text: Some(text),
                        ..CompletionItem::default()
                    }
                })
                .chain(document_context.get_variable_completions())
                .collect(),
            _ => condition_completions(document_context),
        }
    }

    fn schemaless_eq(
        other_side: &CedarTypeKind,
        document_context: &DocumentContext,
    ) -> Vec<CompletionItem> {
        let curr_char = document_context.get_previous_char();
        match other_side {
            CedarTypeKind::EntityType(..) => vec![equals_euid_snippet(curr_char)]
                .into_iter()
                .chain(document_context.get_variable_completions())
                .collect(),
            CedarTypeKind::Action => vec![equals_action_euid_snippet(curr_char)]
                .into_iter()
                .chain(document_context.get_variable_completions())
                .collect(),
            _ => condition_completions(document_context),
        }
    }

    fn in_array_completions(
        &self,
        other_side: CedarTypeKind,
        document_context: &DocumentContext,
    ) -> Vec<CompletionItem> {
        let Some(schema) = document_context.schema.as_ref() else {
            return vec![];
        };

        let complete_type = get_completion_type(&self.complete_side_expr, document_context);

        if complete_type.is_unknown() {
            return vec![];
        }

        match other_side {
            CedarTypeKind::Action => schema
                .actions()
                .map(|euid| {
                    let text = if complete_type.is_euid() {
                        euid.to_string()
                    } else {
                        euid.eid().escaped().to_string()
                    };
                    CompletionItem {
                        label: text.clone(),
                        kind: Some(CompletionItemKind::ENUM_MEMBER),
                        insert_text: Some(text),
                        ..CompletionItem::default()
                    }
                })
                .chain(document_context.get_variable_completions())
                .collect(),
            CedarTypeKind::EntityType(..) if !document_context.is_in_scope_block() => {
                self.in_completions(other_side, document_context)
            }
            _ => vec![],
        }
    }

    #[allow(clippy::too_many_lines)]
    fn in_completions(
        &self,
        other_side: CedarTypeKind,
        document_context: &DocumentContext,
    ) -> Vec<CompletionItem> {
        let Some(schema) = document_context.schema.as_ref() else {
            return vec![];
        };
        let complete_type = get_completion_type(&self.complete_side_expr, document_context);

        if complete_type.is_unknown() {
            return vec![];
        }

        match other_side {
            CedarTypeKind::EntityType(EntityTypeKind::AnyPrincipal) if complete_type.is_euid() => {
                let principals = schema.principals().cloned().collect::<HashSet<_>>();
                schema
                    .entity_types()
                    .filter(|v| v.descendants.intersection(&principals).count() > 0)
                    .map(cedar_policy_core::validator::ValidatorEntityType::name)
                    .chain(principals.iter())
                    .unique()
                    .map(|p| CompletionItem {
                        label: p.to_string(),
                        kind: Some(CompletionItemKind::CLASS),
                        insert_text: Some(format!("{p}::\"${{1:entityId}}\"")),
                        insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
                        ..CompletionItem::default()
                    })
                    .chain(document_context.get_variable_completions())
                    .collect()
            }
            CedarTypeKind::EntityType(EntityTypeKind::AnyResource) if complete_type.is_euid() => {
                let resources = schema.resources().cloned().collect::<HashSet<_>>();
                schema
                    .entity_types()
                    .filter(|v| v.descendants.intersection(&resources).count() > 0)
                    .map(cedar_policy_core::validator::ValidatorEntityType::name)
                    .chain(resources.iter())
                    .unique()
                    .map(|p| CompletionItem {
                        label: p.to_string(),
                        kind: Some(CompletionItemKind::CLASS),
                        insert_text: Some(format!("{p}::\"${{1:entityId}}\"")),
                        insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
                        ..CompletionItem::default()
                    })
                    .chain(document_context.get_variable_completions())
                    .collect()
            }
            CedarTypeKind::EntityType(EntityTypeKind::Concrete(et)) if complete_type.is_euid() => {
                schema
                    .entity_types()
                    .filter(|v| v.descendants.contains(&et))
                    .map(cedar_policy_core::validator::ValidatorEntityType::name)
                    .chain(once(et.as_ref()))
                    .unique()
                    .map(|p| CompletionItem {
                        label: p.to_string(),
                        kind: Some(CompletionItemKind::CLASS),
                        insert_text: Some(format!("{p}::\"${{1:entityId}}\"")),
                        insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
                        ..CompletionItem::default()
                    })
                    .chain(document_context.get_variable_completions())
                    .collect()
            }
            CedarTypeKind::EntityType(EntityTypeKind::Set(set)) if complete_type.is_euid() => {
                let parent_entity_types = schema
                    .entity_types()
                    .filter(|v| !v.descendants.is_empty())
                    .collect_vec();
                set.iter()
                    .flat_map(|et| {
                        parent_entity_types
                            .iter()
                            .filter(move |parent| parent.has_descendant_entity_type(et))
                    })
                    .map(|vet| vet.name())
                    .chain(set.iter().map(std::convert::AsRef::as_ref))
                    .map(|vet| CompletionItem {
                        label: vet.name().to_string(),
                        kind: Some(CompletionItemKind::CLASS),
                        insert_text: Some(format!("{}::\"${{1:entityId}}\"", vet.name())),
                        insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
                        ..CompletionItem::default()
                    })
                    .chain(document_context.get_variable_completions())
                    .collect()
            }
            CedarTypeKind::Action => {
                let completion_kind =
                    get_completion_type(&self.complete_side_expr, document_context);
                schema
                    .action_groups()
                    .map(|euid| {
                        let text = if completion_kind.is_euid() {
                            euid.to_string()
                        } else {
                            euid.eid().escaped().to_string()
                        };
                        CompletionItem {
                            label: text.clone(),
                            kind: Some(CompletionItemKind::ENUM_MEMBER),
                            insert_text: Some(text),
                            ..CompletionItem::default()
                        }
                    })
                    .chain(document_context.get_variable_completions())
                    .collect()
            }
            _ => vec![],
        }
    }

    fn schemaless_in_completions(
        other_side: &CedarTypeKind,
        document_context: &DocumentContext,
    ) -> Vec<CompletionItem> {
        let curr_char = document_context.get_previous_char();
        let iter = match other_side {
            CedarTypeKind::EntityType(..) => vec![in_entity_snippet(curr_char)].into_iter(),
            CedarTypeKind::Action => vec![
                in_action_group_snippet(curr_char),
                in_action_set_snippet(curr_char),
            ]
            .into_iter(),
            _ => vec![].into_iter(),
        };
        iter.chain(document_context.get_variable_completions())
            .collect_vec()
    }
}

fn get_completion_type(completion_expr: &Expr, document: &DocumentContext) -> CompletionType {
    match completion_expr.expr_kind() {
        // Likely trying to type an entire action euid
        ExprKind::Error { .. } => CompletionType::Euid,
        // Empty set implies we want the entire Action euid
        ExprKind::Set(set) if set.is_empty() => CompletionType::Euid,
        // If cursor is over an error and we are in a set then we are likely trying to type the entire action euid
        ExprKind::Set(set)
            if set
                .iter()
                .filter(|expr| matches!(expr.expr_kind(), ExprKind::Error { .. }))
                .any(|euid| document.is_cursor_over_loc(euid.source_loc())) =>
        {
            CompletionType::Euid
        }
        ExprKind::Set(set)
            if set
                .iter()
                .filter_map(|expr| {
                    let ExprKind::Lit(Literal::EntityUID(euid)) = expr.expr_kind() else {
                        return None;
                    };
                    Some(euid)
                })
                .any(|euid| document.is_cursor_over_loc(euid.loc())) =>
        {
            CompletionType::EntityId
        }
        ExprKind::Lit(Literal::EntityUID(euid)) if **euid == EntityUID::Error => {
            CompletionType::Euid
        }
        ExprKind::Lit(Literal::EntityUID(euid))
            if euid.is_action()
                && document.get_word_under_cursor().unwrap_or_default() == euid.eid().escaped() =>
        {
            CompletionType::EntityId
        }
        _ => CompletionType::Unknown,
    }
}
