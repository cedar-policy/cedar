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
use std::{collections::HashSet, sync::Arc};

use crate::policy::{
    cedar::{CedarTypeKind, EntityTypeKind},
    completion::snippets::{
        condition_completions, equals_action_euid_snippet, equals_euid_snippet,
        in_action_group_snippet, in_action_set_snippet, in_entity_snippet,
    },
    DocumentContext, GetType,
};
use cedar_policy_core::{
    ast::{EntityType, EntityUID, Expr, ExprKind, Literal},
    validator::{ValidatorEntityType, ValidatorSchema},
};
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

fn entity_type_completion(entity_type: &EntityType) -> CompletionItem {
    CompletionItem {
        label: entity_type.to_string(),
        kind: Some(CompletionItemKind::CLASS),
        insert_text: Some(format!("{entity_type}::\"${{1:entityId}}\"")),
        insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
        ..CompletionItem::default()
    }
}

fn action_completion(entity_uid: &EntityUID, completion_type: CompletionType) -> CompletionItem {
    let text = if completion_type.is_euid() {
        entity_uid.to_string()
    } else {
        entity_uid.eid().escaped().to_string()
    };
    CompletionItem {
        label: text.clone(),
        kind: Some(CompletionItemKind::ENUM_MEMBER),
        insert_text: Some(text),
        ..CompletionItem::default()
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
        document_context: &DocumentContext<'_>,
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

        match (&self.op, document_context.schema()) {
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
        document_context: &DocumentContext<'_>,
    ) -> Vec<CompletionItem> {
        let Some(schema) = document_context.schema() else {
            return vec![];
        };
        let complete_type = get_completion_type(&self.complete_side_expr, document_context);

        if complete_type.is_unknown() {
            return vec![];
        }

        match other_side {
            CedarTypeKind::EntityType(EntityTypeKind::AnyPrincipal) if complete_type.is_euid() => {
                let mut completions = document_context.get_variable_completions();
                completions.extend(schema.principals().unique().map(entity_type_completion));
                completions
            }
            CedarTypeKind::EntityType(EntityTypeKind::AnyResource) if complete_type.is_euid() => {
                let mut completions = document_context.get_variable_completions();
                completions.extend(schema.resources().unique().map(entity_type_completion));
                completions
            }
            CedarTypeKind::EntityType(EntityTypeKind::Concrete(et)) if complete_type.is_euid() => {
                let mut completions = document_context.get_variable_completions();
                completions.push(entity_type_completion(&et));
                completions
            }
            CedarTypeKind::EntityType(EntityTypeKind::Set(set)) if complete_type.is_euid() => {
                let mut completions = document_context.get_variable_completions();
                completions.extend(
                    set.into_iter()
                        .map(|et| entity_type_completion(et.as_ref())),
                );
                completions
            }
            CedarTypeKind::Action => {
                let mut completions = document_context.get_variable_completions();
                completions.extend(
                    schema
                        .actions()
                        .filter(|euid| !schema.action_groups().contains(euid))
                        .map(|euid| action_completion(euid, complete_type)),
                );
                completions
            }
            _ => condition_completions(document_context),
        }
    }

    fn schemaless_eq(
        other_side: &CedarTypeKind,
        document_context: &DocumentContext<'_>,
    ) -> Vec<CompletionItem> {
        match other_side {
            CedarTypeKind::EntityType(..) => {
                let curr_char = document_context.get_previous_char();
                let mut completions = document_context.get_variable_completions();
                completions.push(equals_euid_snippet(curr_char));
                completions
            }
            CedarTypeKind::Action => {
                let curr_char = document_context.get_previous_char();
                let mut completions = document_context.get_variable_completions();
                completions.push(equals_action_euid_snippet(curr_char));
                completions
            }
            _ => condition_completions(document_context),
        }
    }

    fn in_array_completions(
        &self,
        other_side: CedarTypeKind,
        document_context: &DocumentContext<'_>,
    ) -> Vec<CompletionItem> {
        let Some(schema) = document_context.schema() else {
            return vec![];
        };

        let complete_type = get_completion_type(&self.complete_side_expr, document_context);

        if complete_type.is_unknown() {
            return vec![];
        }

        match other_side {
            CedarTypeKind::Action => {
                let mut completions = document_context.get_variable_completions();
                completions.extend(
                    schema
                        .actions()
                        .map(|euid| action_completion(euid, complete_type)),
                );
                completions
            }
            CedarTypeKind::EntityType(..) if !document_context.is_in_scope_block() => {
                self.in_completions(other_side, document_context)
            }
            _ => vec![],
        }
    }

    fn in_any_completions<'a>(
        schema: &'a ValidatorSchema,
        var_entity_types: &'a HashSet<EntityType>,
    ) -> impl Iterator<Item = CompletionItem> + 'a {
        schema
            .entity_types()
            .filter(|v| v.descendants.intersection(var_entity_types).count() > 0)
            .map(ValidatorEntityType::name)
            .chain(var_entity_types)
            .unique()
            .map(entity_type_completion)
    }

    fn in_completions(
        &self,
        other_side: CedarTypeKind,
        document_context: &DocumentContext<'_>,
    ) -> Vec<CompletionItem> {
        let Some(schema) = document_context.schema() else {
            return vec![];
        };
        let complete_type = get_completion_type(&self.complete_side_expr, document_context);

        if complete_type.is_unknown() {
            return vec![];
        }

        match other_side {
            CedarTypeKind::EntityType(EntityTypeKind::AnyPrincipal) if complete_type.is_euid() => {
                let principals = schema.principals().cloned().collect::<HashSet<_>>();
                let mut completions = document_context.get_variable_completions();
                completions.extend(Self::in_any_completions(schema, &principals));
                completions
            }
            CedarTypeKind::EntityType(EntityTypeKind::AnyResource) if complete_type.is_euid() => {
                let resources = schema.resources().cloned().collect::<HashSet<_>>();
                let mut completions = document_context.get_variable_completions();
                completions.extend(Self::in_any_completions(schema, &resources));
                completions
            }
            CedarTypeKind::EntityType(EntityTypeKind::Concrete(et)) if complete_type.is_euid() => {
                let mut completions = document_context.get_variable_completions();
                completions.extend(
                    schema
                        .entity_types()
                        .filter(|v| v.descendants.contains(&et))
                        .map(ValidatorEntityType::name)
                        .chain(std::iter::once(et.as_ref()))
                        .unique()
                        .map(entity_type_completion),
                );
                completions
            }
            CedarTypeKind::EntityType(EntityTypeKind::Set(set)) if complete_type.is_euid() => {
                let parent_entity_types = schema
                    .entity_types()
                    .filter(|v| !v.descendants.is_empty())
                    .collect_vec();
                let mut completions = document_context.get_variable_completions();
                completions.extend(
                    set.iter()
                        .flat_map(|et| {
                            parent_entity_types
                                .iter()
                                .filter(move |parent| parent.has_descendant_entity_type(et))
                        })
                        .map(|vet| vet.name())
                        .chain(set.iter().map(AsRef::as_ref))
                        .map(entity_type_completion),
                );
                completions
            }
            CedarTypeKind::Action => {
                let completion_kind =
                    get_completion_type(&self.complete_side_expr, document_context);
                let mut completions = document_context.get_variable_completions();
                completions.extend(
                    schema
                        .action_groups()
                        .map(|euid| action_completion(euid, completion_kind)),
                );
                completions
            }
            _ => vec![],
        }
    }

    fn schemaless_in_completions(
        other_side: &CedarTypeKind,
        document_context: &DocumentContext<'_>,
    ) -> Vec<CompletionItem> {
        let mut completions = document_context.get_variable_completions();
        let curr_char = document_context.get_previous_char();
        match other_side {
            CedarTypeKind::EntityType(..) => completions.push(in_entity_snippet(curr_char)),
            CedarTypeKind::Action => {
                completions.push(in_action_group_snippet(curr_char));
                completions.push(in_action_set_snippet(curr_char));
            }
            _ => {}
        }
        completions
    }
}

fn get_completion_type(completion_expr: &Expr, document: &DocumentContext<'_>) -> CompletionType {
    match completion_expr.expr_kind() {
        // Likely trying to type an entire action euid
        ExprKind::Error { .. } => CompletionType::Euid,
        // Empty set implies we want the entire Action euid
        ExprKind::Set(set) if set.is_empty() => CompletionType::Euid,
        // If cursor is over an error and we are in a set then we are likely trying to type the entire action euid
        ExprKind::Set(set)
            if set.iter().any(|expr| {
                matches!(expr.expr_kind(), ExprKind::Error { .. })
                    && document.is_cursor_over_loc(expr.source_loc())
            }) =>
        {
            CompletionType::Euid
        }
        ExprKind::Set(set)
            if set.iter().any(|expr| {
                if let ExprKind::Lit(Literal::EntityUID(euid)) = expr.expr_kind() {
                    document.is_cursor_over_loc(euid.loc())
                } else {
                    false
                }
            }) =>
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
