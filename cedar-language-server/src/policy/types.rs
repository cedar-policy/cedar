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

use std::collections::BTreeSet;
use std::sync::Arc;
use std::vec;

use cedar::{ContextKind, EntityTypeKind};
use cedar_policy_core::ast::{
    ActionConstraint, EntityReference, EntityType, EntityUID, PrincipalOrResourceConstraint,
    Template,
};
use cedar_policy_core::parser::Loc;
use cedar_policy_core::validator::ValidatorSchema;
use cedar_policy_core::validator::{
    types::{AttributeType, Attributes, EntityRecordKind, Type},
    ValidatorEntityType,
};
use itertools::Itertools;
use lsp_types::{CompletionItem, Position};
use serde::{Deserialize, Serialize};

use crate::policy::completion::items::{
    ActionCompletionItem, ContextCompletionIem, PrincipalCompletionItem, ResourceCompletionItem,
};
use crate::utils::{
    get_char_at_position, get_operator_at_position, get_policy_scope_variable,
    get_word_at_position, is_cursor_in_condition_braces, is_cursor_within_policy_scope,
    position_within_loc, PolicyScopeVariable, ScopeVariableInfo,
};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(feature = "wasm")]
extern crate tsify;

mod get_type;

pub(crate) use get_type::*;
pub(crate) mod cedar;
pub(crate) mod context;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct PolicyLanguageFeatures {
    pub allow_templates: bool,
    pub allow_multiple_policies: bool,
}

#[cfg(test)]
impl PolicyLanguageFeatures {
    #[must_use]
    pub(crate) fn new(allow_templates: bool, allow_multiple_policies: bool) -> Self {
        Self {
            allow_templates,
            allow_multiple_policies,
        }
    }
}

impl Default for PolicyLanguageFeatures {
    fn default() -> Self {
        Self {
            allow_templates: true,
            allow_multiple_policies: true,
        }
    }
}

#[derive(Debug)]
pub(crate) struct DocumentContext<'a> {
    pub(crate) schema: Option<ValidatorSchema>,
    pub(crate) policy: Template,
    pub(crate) cursor_position: Position,
    is_in_scope: bool,
    pub(crate) policy_text: &'a str,
    features: PolicyLanguageFeatures,
}

impl<'a> DocumentContext<'a> {
    #[must_use]
    pub(crate) fn new(
        schema: Option<ValidatorSchema>,
        policy: Template,
        policy_text: &'a str,
        cursor_position: Position,
        features: PolicyLanguageFeatures,
    ) -> Self {
        let is_in_scope = is_cursor_within_policy_scope(policy_text, cursor_position);
        let is_in_cond = is_cursor_in_condition_braces(cursor_position, policy_text);
        Self {
            schema,
            is_in_scope: is_in_scope && !is_in_cond,
            policy_text,
            policy,
            cursor_position,
            features,
        }
    }

    pub(crate) fn schema(&self) -> Option<&ValidatorSchema> {
        self.schema.as_ref()
    }

    #[must_use]
    pub(crate) fn get_word_under_cursor(&self) -> Option<&str> {
        get_word_at_position(self.cursor_position, &self.policy_text)
    }

    #[must_use]
    pub(crate) fn get_operator_under_cursor(&self) -> Option<&str> {
        get_operator_at_position(self.cursor_position, &self.policy_text)
    }

    #[must_use]
    pub(crate) fn get_token_under_cursor(&self) -> Option<Token<'_>> {
        // Try to get operator first as they're more specific
        if let Some(operator) = self.get_operator_under_cursor() {
            return Some(Token::Operator(operator));
        }

        // If no operator found, try to get word
        if let Some(word) = self.get_word_under_cursor() {
            return Some(Token::Word(word.to_string()));
        }

        None
    }

    pub(crate) fn is_cursor_over_loc<'b, T>(&self, loc: T) -> bool
    where
        T: Into<Option<&'b Loc>>,
    {
        position_within_loc(self.cursor_position, loc.into())
    }

    #[must_use]
    pub(crate) fn get_previous_char(&self) -> Option<char> {
        let p = Position::new(
            self.cursor_position.line,
            self.cursor_position.character - 1,
        );
        get_char_at_position(p, self.policy_text)
    }

    #[must_use]
    pub(crate) fn get_char_at_position(&self) -> Option<char> {
        get_char_at_position(self.cursor_position, self.policy_text)
    }

    #[must_use]
    pub(crate) fn is_in_scope_block(&self) -> bool {
        self.is_in_scope
    }

    #[must_use]
    pub(crate) fn get_scope_variable_info(&self) -> ScopeVariableInfo {
        get_policy_scope_variable(self.policy_text, self.cursor_position)
    }

    #[must_use]
    pub(crate) fn resolve_principal_type(&self) -> EntityTypeKind {
        let principal_type = self.type_from_constraint(
            self.policy.principal_constraint().as_inner(),
            EntityTypeKind::AnyPrincipal,
        );
        match principal_type {
            EntityTypeKind::AnyPrincipal => self.principal_type_from_action_constraint(),
            entity_type => entity_type,
        }
    }

    #[must_use]
    pub(crate) fn resolve_resource_type(&self) -> EntityTypeKind {
        let resource_types = self.type_from_constraint(
            self.policy.resource_constraint().as_inner(),
            EntityTypeKind::AnyResource,
        );

        match resource_types {
            EntityTypeKind::AnyResource => self.resource_type_from_action_constraint(),
            entity_type => entity_type,
        }
    }

    #[must_use]
    pub(crate) fn resolve_context_type(&self) -> ContextKind {
        let action_constraint = self.policy.action_constraint();
        match action_constraint {
            ActionConstraint::Any => ContextKind::any(),
            ActionConstraint::In(entity_uids) => {
                ContextKind::action_set(entity_uids.iter().cloned())
            }
            ActionConstraint::Eq(entity_uid) => ContextKind::action(entity_uid.clone()),
            ActionConstraint::ErrorConstraint => ContextKind::AnyContext,
        }
    }

    fn type_from_constraint(
        &self,
        constraint: &PrincipalOrResourceConstraint,
        any_type: EntityTypeKind,
    ) -> EntityTypeKind {
        match constraint {
            PrincipalOrResourceConstraint::IsIn(entity_type, _) => {
                if **entity_type == EntityType::ErrorEntityType
                    || self.get_schema_type(entity_type).is_none()
                {
                    return any_type;
                }
                EntityTypeKind::Concrete(entity_type.clone())
            }
            PrincipalOrResourceConstraint::Eq(EntityReference::EUID(entity_uid)) => {
                if *entity_uid.entity_type() == EntityType::ErrorEntityType
                    || self.get_schema_type(entity_uid.entity_type()).is_none()
                {
                    return any_type;
                }
                EntityTypeKind::Concrete(entity_uid.entity_type().clone().into())
            }
            PrincipalOrResourceConstraint::In(EntityReference::EUID(entity_uid)) => {
                let Some(schema) = self.schema() else {
                    return any_type;
                };
                let Some(entity_type) = schema.get_entity_type(entity_uid.entity_type()) else {
                    return any_type;
                };
                let mut entity_types = entity_type
                    .descendants
                    .iter()
                    .cloned()
                    .map(Arc::new)
                    .collect::<BTreeSet<_>>();

                // For reflexive in statements
                let is_p_or_r = if matches!(any_type, EntityTypeKind::AnyPrincipal) {
                    schema.principals().any(|s| s == entity_type.name())
                } else {
                    schema.resources().any(|s| s == entity_type.name())
                };

                if is_p_or_r {
                    entity_types.insert(Arc::new(entity_type.name().clone()));
                }

                if entity_types.len() == 1 {
                    // PANIC SAFETY: If condition ensures there is an element
                    #[allow(clippy::unwrap_used)]
                    return EntityTypeKind::Concrete(entity_types.into_iter().next().unwrap());
                }

                EntityTypeKind::Set(entity_types)
            }
            PrincipalOrResourceConstraint::Is(entity_type) => {
                if self.get_schema_type(entity_type).is_none() {
                    return any_type;
                }
                EntityTypeKind::Concrete(entity_type.clone())
            }
            PrincipalOrResourceConstraint::Any
            | PrincipalOrResourceConstraint::Eq(EntityReference::Slot(..))
            | PrincipalOrResourceConstraint::In(EntityReference::Slot(..)) => any_type,
        }
    }

    fn principal_type_from_action_constraint(&self) -> EntityTypeKind {
        self.entity_type_from_action_constraint(
            |schema, euid| schema.principals_for_action(euid),
            EntityTypeKind::AnyPrincipal,
        )
    }

    fn resource_type_from_action_constraint(&self) -> EntityTypeKind {
        self.entity_type_from_action_constraint(
            |schema, euid| schema.resources_for_action(euid),
            EntityTypeKind::AnyResource,
        )
    }
    fn entity_type_from_action_constraint<'b, F, I>(
        &'b self,
        entity_extractor: F,
        any_type: EntityTypeKind,
    ) -> EntityTypeKind
    where
        I: Iterator<Item = &'b EntityType>,
        F: Fn(&'b ValidatorSchema, &EntityUID) -> Option<I>,
    {
        match self.policy.action_constraint() {
            ActionConstraint::Any | ActionConstraint::ErrorConstraint => any_type,
            ActionConstraint::In(entity_uids) => {
                let Some(schema) = &self.schema else {
                    return any_type;
                };

                let entities = entity_uids
                    .iter()
                    .filter_map(|euid| entity_extractor(schema, euid))
                    .flatten()
                    .unique()
                    .cloned()
                    .map(Arc::new)
                    .collect::<BTreeSet<_>>();

                if entities.is_empty() {
                    return any_type;
                }

                // Handle single-element optimization for resources
                if any_type == EntityTypeKind::AnyResource && entities.len() == 1 {
                    // PANIC SAFETY: If condition ensures there is an element
                    #[allow(clippy::unwrap_used)]
                    return EntityTypeKind::Concrete(entities.into_iter().next().unwrap());
                }

                EntityTypeKind::Set(entities)
            }
            ActionConstraint::Eq(entity_uid) => {
                let Some(schema) = self.schema() else {
                    return any_type;
                };

                let Some(entities_for_action) = entity_extractor(schema, entity_uid) else {
                    return any_type;
                };

                let entities = entities_for_action
                    .cloned()
                    .map(Arc::new)
                    .collect::<BTreeSet<_>>();

                if entities.is_empty() {
                    return any_type;
                }

                // Handle single-element optimization for resources
                if any_type == EntityTypeKind::AnyResource && entities.len() == 1 {
                    // PANIC SAFETY: If condition ensures there is an element
                    #[allow(clippy::unwrap_used)]
                    return EntityTypeKind::Concrete(entities.into_iter().next().unwrap());
                }

                EntityTypeKind::Set(entities)
            }
        }
    }

    fn get_schema_type<'b>(&'b self, entity_type: &EntityType) -> Option<&'b ValidatorEntityType> {
        self.schema
            .as_ref()
            .and_then(|s| s.get_entity_type(entity_type))
    }

    #[must_use]
    pub(crate) fn get_variable_completions(&self) -> Vec<CompletionItem> {
        if self.is_in_scope_block() {
            let scope_info = self.get_scope_variable_info();
            match scope_info.variable_type {
                PolicyScopeVariable::Principal => {
                    return if self.features.allow_templates {
                        vec![PrincipalCompletionItem::template(self).into()]
                    } else {
                        vec![]
                    }
                }
                PolicyScopeVariable::Action => return vec![],
                PolicyScopeVariable::Resource => {
                    return if self.features.allow_templates {
                        vec![ResourceCompletionItem::template(self).into()]
                    } else {
                        vec![]
                    };
                }
                PolicyScopeVariable::None => {}
            }
        }

        vec![
            PrincipalCompletionItem::from(self).into(),
            ActionCompletionItem::from(self).into(),
            ResourceCompletionItem::from(self).into(),
            ContextCompletionIem::from(self).into(),
        ]
    }
}

#[must_use]
pub(crate) fn format_attributes(attrs: &Attributes) -> String {
    let mut lines = Vec::new();

    for (name, attr_type) in attrs.iter() {
        lines.push(format_attribute(name, attr_type, 0));
    }

    if lines.is_empty() {
        "No attributes defined.".to_string()
    } else {
        lines.join("\n")
    }
}

#[must_use]
pub(crate) fn format_attribute(
    name: &str,
    attr_type: &AttributeType,
    indent_level: usize,
) -> String {
    let indent = "    ".repeat(indent_level);
    let ty = &attr_type.attr_type;

    match ty {
        Type::EntityOrRecord(EntityRecordKind::Record { attrs: fields, .. }) => {
            let mut lines = vec![format!("{}{}: {{", indent, name)];

            // Format each field in the record
            for (field_name, field_type) in fields.iter() {
                lines.push(format_attribute(field_name, field_type, indent_level + 1));
            }

            // Close the record
            lines.push(format!("{indent}}}"));
            lines.join("\n")
        }
        _ => format!("{indent}{name}: {ty}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Token<'a> {
    Word(String),
    Operator(&'a str),
}

impl Token<'_> {
    #[must_use]
    pub(crate) fn inner(&self) -> &str {
        match self {
            Self::Word(w) => w,
            Self::Operator(o) => o,
        }
    }
}

impl PartialEq<&str> for Token<'_> {
    fn eq(&self, other: &&str) -> bool {
        match self {
            Self::Word(w) => w == other,
            Self::Operator(o) => o == other,
        }
    }
}

impl PartialEq<String> for Token<'_> {
    fn eq(&self, other: &String) -> bool {
        match self {
            Self::Word(w) => w == other,
            Self::Operator(o) => o == other,
        }
    }
}

impl PartialEq<Token<'_>> for &str {
    fn eq(&self, other: &Token<'_>) -> bool {
        other == self
    }
}

impl PartialEq<Token<'_>> for String {
    fn eq(&self, other: &Token<'_>) -> bool {
        other == self
    }
}
