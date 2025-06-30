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

use std::sync::Arc;

use cedar_policy_core::ast::{
    ActionConstraint, EntityUID, Expr, Literal, PrincipalOrResourceConstraint, SlotId, Template,
    Var,
};
use lsp_types::{CompletionItem, Position};

use crate::{
    policy::{
        context::{BinaryOpContext, IsContext, Op, ReceiverContext},
        items::{EqCompletionItem, InCompletionItem, IsCompletionItem, IsInCompletionItem},
        CompletionContextKind,
    },
    utils::{
        get_policy_scope_variable, get_word_at_position, PolicyScopeVariable, ScopeVariableInfo,
    },
};
use regex_consts::{
    ACTION_EQ_REGEX, ACTION_IN_ARRAY, ACTION_IN_REGEX, PRINCIPAL_IS_REGEX, RESOURCE_IS_REGEX,
};

// PANIC SAFETY: These regex are valid and would panic immediately in test if not.
#[allow(clippy::unwrap_used)]
mod regex_consts {
    use std::sync::LazyLock;

    use regex::Regex;

    pub(crate) static PRINCIPAL_IS_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"principal\s+is\s*").unwrap());

    pub(crate) static ACTION_IN_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"action\s+in\s*").unwrap());
    pub(crate) static ACTION_EQ_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"action\s+==\s*").unwrap());
    pub(crate) static ACTION_IN_ARRAY: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"action\s+in\s+\[(?:\s*(?:[A-Za-z]+::)?Action::"[\w]+?"\s*,?)*\s*"#).unwrap()
    });

    pub(crate) static RESOURCE_IS_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"resource\s+is\s*").unwrap());
}

pub(crate) fn get_scope_completions(
    position: Position,
    policy: &Template,
    policy_str: &str,
) -> CompletionContextKind {
    let info = get_policy_scope_variable(policy_str, position);

    if get_word_at_position(position, policy_str).is_some_and(|w| w.ends_with(':')) {
        return CompletionContextKind::None;
    }

    match info.variable_type {
        PolicyScopeVariable::Principal => handle_principal_scope(policy, &info),
        PolicyScopeVariable::Resource => handle_resource_scope(policy, &info),
        PolicyScopeVariable::Action => handle_action_scope(policy, &info),
        PolicyScopeVariable::None => CompletionContextKind::ScopeDefault,
    }
}

fn handle_principal_scope(policy: &Template, info: &ScopeVariableInfo) -> CompletionContextKind {
    let principal_var = Expr::var(Var::Principal).into();

    match policy.principal_constraint().as_inner() {
        PrincipalOrResourceConstraint::In(entity_reference)
        | PrincipalOrResourceConstraint::IsIn(_, entity_reference) => create_binary_op_context(
            Op::in_entity(),
            principal_var,
            entity_reference.into_expr(SlotId::principal()).into(),
        ),

        PrincipalOrResourceConstraint::Eq(entity_reference) => create_binary_op_context(
            Op::eq(),
            principal_var,
            entity_reference.into_expr(SlotId::principal()).into(),
        ),

        PrincipalOrResourceConstraint::Is(..) => create_is_context(principal_var),

        PrincipalOrResourceConstraint::Any if PRINCIPAL_IS_REGEX.is_match(&info.text) => {
            create_is_context(principal_var)
        }

        PrincipalOrResourceConstraint::Any => create_identity_context(get_standard_operators()),
    }
}

fn handle_resource_scope(policy: &Template, info: &ScopeVariableInfo) -> CompletionContextKind {
    let resource_var = Expr::var(Var::Resource).into();

    match policy.resource_constraint().as_inner() {
        PrincipalOrResourceConstraint::In(entity_reference)
        | PrincipalOrResourceConstraint::IsIn(_, entity_reference) => create_binary_op_context(
            Op::in_entity(),
            resource_var,
            entity_reference.into_expr(SlotId::principal()).into(),
        ),

        PrincipalOrResourceConstraint::Eq(entity_reference) => create_binary_op_context(
            Op::Eq,
            resource_var,
            entity_reference.into_expr(SlotId::resource()).into(),
        ),

        PrincipalOrResourceConstraint::Is(..) => create_is_context(resource_var),

        PrincipalOrResourceConstraint::Any if RESOURCE_IS_REGEX.is_match(&info.text) => {
            create_is_context(resource_var)
        }

        PrincipalOrResourceConstraint::Any => create_identity_context(get_standard_operators()),
    }
}

fn handle_action_scope(policy: &Template, info: &ScopeVariableInfo) -> CompletionContextKind {
    let action_var = Expr::var(Var::Action).into();

    match policy.action_constraint() {
        ActionConstraint::Eq(entity_uid) => create_binary_op_context(
            Op::eq(),
            action_var,
            Expr::val(Literal::EntityUID(entity_uid.clone())).into(),
        ),

        ActionConstraint::In(entity_uids) if ACTION_IN_ARRAY.is_match(&info.text) => {
            let expr_set = Expr::set(entity_uids.iter().map(|euid| Expr::val(euid.clone()))).into();
            create_binary_op_context(Op::in_array(), action_var, expr_set)
        }

        ActionConstraint::In(entity_uids) => {
            let expr_set = Expr::set(entity_uids.iter().map(|euid| Expr::val(euid.clone()))).into();
            create_binary_op_context(Op::in_entity(), action_var, expr_set)
        }

        ActionConstraint::ErrorConstraint if ACTION_IN_ARRAY.is_match(&info.text) => {
            let error_expr = Expr::val(Literal::EntityUID(EntityUID::Error.into())).into();
            create_binary_op_context(Op::in_array(), action_var, error_expr)
        }

        ActionConstraint::ErrorConstraint if ACTION_IN_REGEX.is_match(&info.text) => {
            let error_expr = Expr::val(Literal::EntityUID(EntityUID::Error.into())).into();
            create_binary_op_context(Op::in_entity(), action_var, error_expr)
        }

        ActionConstraint::ErrorConstraint if ACTION_EQ_REGEX.is_match(&info.text) => {
            let error_expr = Expr::val(Literal::EntityUID(EntityUID::Error.into())).into();
            create_binary_op_context(Op::eq(), action_var, error_expr)
        }

        ActionConstraint::Any => create_identity_context(get_action_operators()),

        ActionConstraint::ErrorConstraint => CompletionContextKind::None,
    }
}

// Helper functions to create context objects
fn create_binary_op_context(op: Op, left: Arc<Expr>, right: Arc<Expr>) -> CompletionContextKind {
    CompletionContextKind::BinaryOp(BinaryOpContext::new(op, left, right))
}

fn create_is_context(receiver: Arc<Expr>) -> CompletionContextKind {
    CompletionContextKind::Is(IsContext::new(ReceiverContext::new(receiver)))
}

fn create_identity_context(items: Vec<CompletionItem>) -> CompletionContextKind {
    CompletionContextKind::Identity(items)
}

// Returns standard operator completion items for principal and resource
fn get_standard_operators() -> Vec<CompletionItem> {
    vec![
        IsCompletionItem.into(),
        InCompletionItem.into(),
        IsInCompletionItem.into(),
        EqCompletionItem.into(),
    ]
}

fn get_action_operators() -> Vec<CompletionItem> {
    vec![
        CompletionItem {
            label: "in action group".to_string(),
            insert_text: Some("in ${1:ActionGroup::\"\"}".to_string()),
            insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
            ..CompletionItem::default()
        },
        CompletionItem {
            label: "in array".to_string(),
            insert_text: Some("in [${1}]".to_string()),
            insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
            ..CompletionItem::default()
        },
        CompletionItem {
            label: "eq".to_string(),
            insert_text: Some("== ${1:Action::\"\"}".to_string()),
            insert_text_format: Some(lsp_types::InsertTextFormat::SNIPPET),
            ..CompletionItem::default()
        },
    ]
}
