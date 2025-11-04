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
use std::{collections::BTreeSet, fmt::Display, hash::Hash, sync::Arc};

use cedar_policy_core::ast::EntityUID;
use cedar_policy_core::validator::types::{AttributeType, Attributes};
use cedar_policy_core::validator::ValidatorActionId;
use cedar_policy_core::validator::{types::Type, ValidatorSchema};
use itertools::Itertools;
use smol_str::SmolStr;

use crate::documentation::ToDocumentationString;
use crate::{markdown::MarkdownBuilder, policy::types::format_attributes};

use super::{Attribute, CedarTypeKind};

const MAX_ACTIONS_TO_DISPLAY: usize = 5;

/// Represents the type of the `context` variable in Cedar policies.
///
/// The `context` variable provides additional information about the authorization request,
/// and its structure can vary depending on the action being authorized. This enum
/// captures the different possible types the context might have based on the policy's
/// action constraints.
///
/// In Cedar policies, the context is accessed using expressions like:
/// ```cedar
/// context.user.authenticated == true
/// context.request.timestamp > datetime("2023-01-01T00:00:00Z")
/// ```
///
/// The available attributes on the context object are determined by:
/// 1. The Cedar schema definition
/// 2. The specific action(s) relevant to the policy
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum ContextKind {
    /// Represents an unconstrained context type that could have any attributes.
    ///
    /// This is used when the policy's action constraint is `Any` or when
    /// no schema information is available to determine the context structure.
    AnyContext,
    /// Represents a context type for a specific action.
    ///
    /// This is used when the policy's action constraint is an equality constraint
    /// (`action == Action::"read"`). The context structure is determined by
    /// the schema definition for this specific action.
    Action(Arc<EntityUID>),
    /// Represents a context type for a set of possible actions.
    ///
    /// This is used when the policy's action constraint is a membership constraint
    /// (`action in [Action::"read", Action::"write"]`). The context structure includes
    /// all unique attributes from the specified actions, with uniqueness determined
    /// by both attribute name and type.
    ActionSet(BTreeSet<Arc<EntityUID>>),
}

impl ContextKind {
    #[must_use]
    pub(crate) fn any() -> Self {
        Self::AnyContext
    }

    pub(crate) fn action_set(actions: impl Iterator<Item = Arc<EntityUID>>) -> Self {
        Self::ActionSet(actions.into_iter().collect())
    }

    #[must_use]
    pub(crate) fn action(action_euid: Arc<EntityUID>) -> Self {
        Self::Action(action_euid)
    }

    #[must_use]
    pub(crate) fn attributes(&self, schema: Option<&ValidatorSchema>) -> Vec<Attribute> {
        let Some(schema) = schema else {
            return Vec::new();
        };
        self.schema_attributes(schema)
            .into_iter()
            .map(std::convert::Into::into)
            .collect()
    }

    #[must_use]
    pub(crate) fn attribute_type(
        &self,
        schema: &ValidatorSchema,
        attr: &str,
    ) -> Option<CedarTypeKind> {
        self.attributes(Some(schema))
            .iter()
            .find(|a| a.name() == attr)
            .and_then(super::attribute::Attribute::cedar_type)
    }

    fn actions_iter<'a>(
        &'a self,
        schema: &'a ValidatorSchema,
    ) -> Box<dyn Iterator<Item = &'a ValidatorActionId> + 'a> {
        match self {
            Self::AnyContext => Box::new(schema.action_ids()),
            Self::Action(entity_uid) => {
                let action_id = schema.get_action_id(entity_uid);
                Box::new(action_id.into_iter())
            }
            Self::ActionSet(btree_set) => Box::new(
                btree_set
                    .iter()
                    .filter_map(|entity_uid| schema.get_action_id(entity_uid)),
            ),
        }
    }

    fn schema_attributes<'a>(
        &'a self,
        schema: &'a ValidatorSchema,
    ) -> Vec<(&'a SmolStr, &'a AttributeType)> {
        self.actions_iter(schema)
            .map(ValidatorActionId::context_type)
            .filter_map(|c| match c {
                Type::Record { attrs, .. } => Some(attrs),
                _ => None,
            })
            .flat_map(Attributes::iter)
            .unique()
            .sorted()
            .collect()
    }
}

impl Display for ContextKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AnyContext => write!(f, "?"),
            Self::Action(..) => write!(f, "record"),
            Self::ActionSet(actions) => {
                let action_strs = actions
                    .iter()
                    .map(std::string::ToString::to_string)
                    .join(", ");
                write!(f, "Actions<{action_strs}>")
            }
        }
    }
}

impl ToDocumentationString for ContextKind {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> Cow<'static, str> {
        let mut builder = MarkdownBuilder::new();

        match self {
            Self::AnyContext => {
                builder.header("Available Context Attributes");

                if let Some(schema) = schema {
                    let attrs = self.schema_attributes(schema);
                    if attrs.is_empty() {
                        builder.paragraph("No context attributes defined in the schema.");
                    } else {
                        builder
                            .paragraph("The following context attributes are available:")
                            .code_block("cedarschema", &format_attributes(attrs.into_iter()));
                    }
                } else {
                    builder.paragraph("*Schema not available - context structure unknown*");
                }
            }

            Self::Action(action_euid) => {
                builder
                    .header(&format!("Context for Action `{action_euid}`"))
                    .paragraph(&format!(
                        "Context attributes available for the action `{action_euid}`:"
                    ));

                if let Some(schema) = schema {
                    let attrs = self.schema_attributes(schema);
                    if attrs.is_empty() {
                        builder.paragraph("No context attributes defined for this action.");
                    } else {
                        builder.code_block("cedarschema", &format_attributes(attrs.into_iter()));
                    }
                } else {
                    builder.paragraph("*Schema not available - context structure unknown*");
                }
            }

            Self::ActionSet(actions) => {
                builder.header("Context for Multiple Actions");

                if actions.is_empty() {
                    builder.paragraph("No actions specified.");
                    return builder.build().into();
                }

                // Truncate the list if it's too long
                let total_actions = actions.len();

                let action_names: Vec<String> = actions
                    .iter()
                    .take(MAX_ACTIONS_TO_DISPLAY)
                    .map(|a| format!("`{a}`"))
                    .collect();

                let action_list = if total_actions <= MAX_ACTIONS_TO_DISPLAY {
                    action_names.join(", ")
                } else {
                    format!(
                        "{} and {} more...",
                        action_names.join(", "),
                        total_actions - MAX_ACTIONS_TO_DISPLAY
                    )
                };

                builder.paragraph(&format!(
                    "Context attributes available for actions: {action_list}"
                ));

                // Add total count if truncated
                if total_actions > MAX_ACTIONS_TO_DISPLAY {
                    builder.paragraph(&format!(
                        "**Note**: Showing common attributes for {total_actions} actions"
                    ));
                }

                if let Some(schema) = schema {
                    let attrs = self.schema_attributes(schema);
                    if attrs.is_empty() {
                        builder.paragraph("No context attributes defined for these actions.");
                    } else {
                        builder.code_block("cedarschema", &format_attributes(attrs.into_iter()));
                    }
                } else {
                    builder.paragraph("*Schema not available - context structure unknown*");
                }
            }
        }

        builder.build().into()
    }
}
