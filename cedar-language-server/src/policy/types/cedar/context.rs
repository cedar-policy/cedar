use std::{collections::BTreeSet, fmt::Display, hash::Hash, sync::Arc};

use cedar_policy_core::ast::EntityUID;
use cedar_policy_core::validator::{
    types::{Attributes, EntityRecordKind, Type},
    ValidatorSchema,
};
use itertools::Itertools;

use crate::{
    markdown::{MarkdownBuilder, ToDocumentationString},
    policy::types::format_attributes,
};

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
        self.schema_attributes(schema)
            .iter()
            .flat_map(cedar_policy_core::validator::types::Attributes::iter)
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

    fn schema_attributes(&self, schema: Option<&ValidatorSchema>) -> Option<Attributes> {
        let schema = schema?;

        match self {
            Self::AnyContext => {
                let iter = schema
                    .action_ids()
                    .map(cedar_policy_core::validator::ValidatorActionId::context_type)
                    .filter_map(|c| match c {
                        Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) => Some(attrs),
                        _ => None,
                    })
                    .flat_map(cedar_policy_core::validator::types::Attributes::iter)
                    .unique()
                    .map(|(k, v)| (k.clone(), v.clone()));
                Some(Attributes::with_attributes(iter))
            }
            Self::Action(entity_uid) => {
                let action_id = schema.get_action_id(entity_uid);
                let iter = action_id
                    .iter()
                    .map(|a| a.context_type())
                    .filter_map(|c| match c {
                        Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) => Some(attrs),
                        _ => None,
                    })
                    .flat_map(cedar_policy_core::validator::types::Attributes::iter)
                    .unique()
                    .map(|(k, v)| (k.clone(), v.clone()));
                Some(Attributes::with_attributes(iter))
            }
            Self::ActionSet(btree_set) => {
                let iter = btree_set
                    .iter()
                    .filter_map(|entity_uid| schema.get_action_id(entity_uid))
                    .map(cedar_policy_core::validator::ValidatorActionId::context_type)
                    .filter_map(|c| match c {
                        Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) => Some(attrs),
                        _ => None,
                    })
                    .flat_map(cedar_policy_core::validator::types::Attributes::iter)
                    .unique()
                    .map(|(k, v)| (k.clone(), v.clone()));
                Some(Attributes::with_attributes(iter))
            }
        }
    }
}

impl Display for ContextKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::AnyContext => "?".to_string(),
            Self::Action(..) => "record".to_string(),
            Self::ActionSet(actions) => {
                let action_strs = actions
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect_vec();
                format!("Actions<{}>", action_strs.join(", "))
            }
        };
        write!(f, "{s}")
    }
}

impl ToDocumentationString for ContextKind {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> String {
        let mut builder = MarkdownBuilder::new();

        match self {
            Self::AnyContext => {
                builder.header("Available Context Attributes");

                if let Some(attrs) = self.schema_attributes(schema) {
                    if attrs.keys().peekable().peek().is_none() {
                        builder.paragraph("No context attributes defined in the schema.");
                    } else {
                        builder
                            .paragraph("The following context attributes are available:")
                            .code_block("cedarschema", &format_attributes(&attrs));
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

                if let Some(attrs) = self.schema_attributes(schema) {
                    if attrs.keys().peekable().peek().is_none() {
                        builder.paragraph("No context attributes defined for this action.");
                    } else {
                        builder.code_block("cedarschema", &format_attributes(&attrs));
                    }
                } else {
                    builder.paragraph("*Schema not available - context structure unknown*");
                }
            }

            Self::ActionSet(actions) => {
                builder.header("Context for Multiple Actions");

                if actions.is_empty() {
                    builder.paragraph("No actions specified.");
                    return builder.build();
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

                if let Some(attrs) = self.schema_attributes(schema) {
                    if attrs.iter().peekable().peek().is_none() {
                        builder.paragraph("No context attributes defined for these actions.");
                    } else {
                        builder.code_block("cedarschema", &format_attributes(&attrs));
                    }
                } else {
                    builder.paragraph("*Schema not available - context structure unknown*");
                }
            }
        }

        builder.build()
    }
}
