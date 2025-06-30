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

use std::borrow::Cow;

use cedar_policy_core::ast::{ActionConstraint, EntityUID};

use super::ToDocumentationString;
use crate::{
    markdown::MarkdownBuilder,
    policy::{format_attributes, DocumentContext},
};
use cedar_policy_core::validator::{
    types::{EntityRecordKind, Type},
    ValidatorSchema,
};
use itertools::Itertools;

pub(crate) struct ActionDocumentation<'a> {
    constraint: Option<&'a ActionConstraint>,
}

impl<'a> ActionDocumentation<'a> {
    pub(crate) fn new(constraint: Option<&'a ActionConstraint>) -> Self {
        Self { constraint }
    }
}

impl<'a> From<&'a ActionConstraint> for ActionDocumentation<'a> {
    fn from(value: &'a ActionConstraint) -> Self {
        Self::new(Some(value))
    }
}

impl<'a> From<&'a DocumentContext<'_>> for ActionDocumentation<'a> {
    fn from(value: &'a DocumentContext<'_>) -> Self {
        value.policy.action_constraint().into()
    }
}

impl ToDocumentationString for ActionDocumentation<'_> {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> Cow<'static, str> {
        let static_docs = include_str!("markdown/action.md");
        let Some(constraint) = &self.constraint else {
            return static_docs.into();
        };
        let mut builder = MarkdownBuilder::new();
        builder.push_str(static_docs);

        match constraint {
            ActionConstraint::Any => {
                builder.header("Available Actions");
                if let Some(schema) = schema {
                    format_action_list(&mut builder, schema.actions().sorted());
                } else {
                    builder.paragraph("*Schema not available - any action permitted*");
                }
            }
            ActionConstraint::In(entity_uids) => {
                builder
                    .header("Permitted Actions")
                    .paragraph("This policy applies to the following actions:");

                let entity_uids = entity_uids.iter().sorted().map(AsRef::as_ref);
                format_action_list(&mut builder, entity_uids);
            }
            ActionConstraint::Eq(entity_uid) => {
                builder
                    .header("Specific Action")
                    .paragraph("This policy applies only to the following action:")
                    .code_block("cedar", &entity_uid.to_string());

                // Add context details from schema if available
                if let Some(schema) = schema {
                    if let Some(action) = schema.get_action_id(entity_uid) {
                        if let Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) =
                            action.context()
                        {
                            builder
                                .header("Context Attributes")
                                .code_block("cedarschema", &format_attributes(attrs));
                        }
                    }
                }
            }
            ActionConstraint::ErrorConstraint => {
                builder
                    .header("Error")
                    .paragraph("Invalid action constraint");
            }
        }

        builder.build().into()
    }
}

fn format_action_list<'a>(
    builder: &mut MarkdownBuilder,
    actions: impl ExactSizeIterator<Item = &'a EntityUID>,
) {
    const MAX_ACTIONS_TO_SHOW: usize = 10;
    let actions_len = actions.len();
    if actions_len == 0 {
        builder.paragraph("*No actions specified*");
        return;
    }

    let shown_actions = actions.take(MAX_ACTIONS_TO_SHOW);
    let remaining = if shown_actions.len() == MAX_ACTIONS_TO_SHOW {
        actions_len - MAX_ACTIONS_TO_SHOW
    } else {
        0
    };

    builder.code_block("cedar", &shown_actions.map(ToString::to_string).join("\n"));

    if remaining > 0 {
        builder.paragraph(&format!("*... and {remaining} more actions defined*"));
    }
}
