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

use cedar_policy_core::validator::ValidatorSchema;

use super::ToDocumentationString;
use crate::{
    markdown::MarkdownBuilder,
    policy::{cedar::ContextKind, DocumentContext},
};

#[derive(Debug, Default)]
pub(crate) struct ContextDocumentation {
    context_kind: Option<ContextKind>,
}

impl ContextDocumentation {
    pub(crate) fn new(context_kind: Option<ContextKind>) -> Self {
        Self { context_kind }
    }
}

impl ToDocumentationString for ContextDocumentation {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> Cow<'static, str> {
        let static_docs = include_str!("markdown/context.md");
        let Some(context_kind) = &self.context_kind else {
            return static_docs.into();
        };

        let mut builder = MarkdownBuilder::new();
        builder.push_str(static_docs);
        let context_kind_doc = context_kind.to_documentation_string(schema);
        builder.push_with_new_line(&context_kind_doc);
        builder.build().into()
    }
}

impl From<&DocumentContext<'_>> for ContextDocumentation {
    fn from(value: &DocumentContext<'_>) -> Self {
        Self::new(Some(value.resolve_context_type()))
    }
}

impl From<Option<&DocumentContext<'_>>> for ContextDocumentation {
    fn from(value: Option<&DocumentContext<'_>>) -> Self {
        value.map(Into::into).unwrap_or_default()
    }
}

#[cfg(test)]
mod test {
    use cedar_policy_core::ast::EntityUID;
    use cedar_policy_core::validator::ValidatorSchema;
    use insta::assert_snapshot;
    use std::sync::Arc;

    use super::*;
    use crate::policy::cedar::ContextKind;

    fn test_schema() -> ValidatorSchema {
        r#"
          entity Photo;
          entity User {
            name: String,
            age: Long
          };

          action Act appliesTo {
             principal: User,
             resource: Photo,
             context: {
                authenticated: Bool,
                request: {
                   timestamp: datetime
                }
             }
          };
          
          action View appliesTo {
             principal: User,
             resource: Photo,
             context: {
                ip_address: String,
                request: {
                   path: String
                }
             }
          };

          action NoContext appliesTo {
             principal: User,
             resource: Photo
          };
        "#
        .parse()
        .unwrap()
    }

    #[test]
    fn test_context_documentation_default_no_schema() {
        let context_doc = ContextDocumentation::default();
        assert_snapshot!(context_doc.to_documentation_string(None));
    }

    #[test]
    fn test_context_documentation_default_with_schema() {
        let schema = test_schema();
        let context_doc = ContextDocumentation::default();
        assert_snapshot!(context_doc.to_documentation_string(Some(&schema)));
    }

    #[test]
    fn test_context_documentation_any_context_no_schema() {
        let context_kind = ContextKind::any();
        let context_doc = ContextDocumentation::new(Some(context_kind));
        assert_snapshot!(context_doc.to_documentation_string(None));
    }

    #[test]
    fn test_context_documentation_any_context_with_schema() {
        let context_kind = ContextKind::any();
        let context_doc = ContextDocumentation::new(Some(context_kind));
        let schema = test_schema();
        assert_snapshot!(context_doc.to_documentation_string(Some(&schema)));
    }

    #[test]
    fn test_context_documentation_action_no_schema() {
        let action_euid: EntityUID = "Action::\"Act\"".parse().unwrap();
        let context_kind = ContextKind::action(Arc::new(action_euid));
        let context_doc = ContextDocumentation::new(Some(context_kind));
        assert_snapshot!(context_doc.to_documentation_string(None));
    }

    #[test]
    fn test_context_documentation_action_with_schema() {
        let action_euid: EntityUID = "Action::\"Act\"".parse().unwrap();
        let context_kind = ContextKind::action(Arc::new(action_euid));
        let context_doc = ContextDocumentation::new(Some(context_kind));
        let schema = test_schema();
        assert_snapshot!(context_doc.to_documentation_string(Some(&schema)));
    }

    #[test]
    fn test_context_documentation_action_set_empty_no_schema() {
        let actions = std::iter::empty();
        let context_kind = ContextKind::action_set(actions);
        let context_doc = ContextDocumentation::new(Some(context_kind));
        assert_snapshot!(context_doc.to_documentation_string(None));
    }

    #[test]
    fn test_context_documentation_action_set_empty_with_schema() {
        let actions = std::iter::empty();
        let context_kind = ContextKind::action_set(actions);
        let context_doc = ContextDocumentation::new(Some(context_kind));
        let schema = test_schema();
        assert_snapshot!(context_doc.to_documentation_string(Some(&schema)));
    }

    #[test]
    fn test_context_documentation_action_set_single_no_schema() {
        let action_euid: EntityUID = "Action::\"Act\"".parse().unwrap();
        let actions = std::iter::once(Arc::new(action_euid));
        let context_kind = ContextKind::action_set(actions);
        let context_doc = ContextDocumentation::new(Some(context_kind));
        assert_snapshot!(context_doc.to_documentation_string(None));
    }

    #[test]
    fn test_context_documentation_action_set_single_with_schema() {
        let action_euid: EntityUID = "Action::\"Act\"".parse().unwrap();
        let actions = std::iter::once(Arc::new(action_euid));
        let context_kind = ContextKind::action_set(actions);
        let context_doc = ContextDocumentation::new(Some(context_kind));
        let schema = test_schema();
        assert_snapshot!(context_doc.to_documentation_string(Some(&schema)));
    }

    #[test]
    fn test_context_documentation_action_set_multiple_no_schema() {
        let act_euid: EntityUID = "Action::\"Act\"".parse().unwrap();
        let view_euid: EntityUID = "Action::\"View\"".parse().unwrap();
        let actions = vec![Arc::new(act_euid), Arc::new(view_euid)].into_iter();
        let context_kind = ContextKind::action_set(actions);
        let context_doc = ContextDocumentation::new(Some(context_kind));
        assert_snapshot!(context_doc.to_documentation_string(None));
    }

    #[test]
    fn test_context_documentation_action_set_multiple_with_schema() {
        let act_euid: EntityUID = "Action::\"Act\"".parse().unwrap();
        let view_euid: EntityUID = "Action::\"View\"".parse().unwrap();
        let actions = vec![Arc::new(act_euid), Arc::new(view_euid)].into_iter();
        let context_kind = ContextKind::action_set(actions);
        let context_doc = ContextDocumentation::new(Some(context_kind));
        let schema = test_schema();
        assert_snapshot!(context_doc.to_documentation_string(Some(&schema)));
    }

    #[test]
    fn test_context_documentation_no_context_action() {
        let action_euid: EntityUID = "Action::\"NoContext\"".parse().unwrap();
        let context_kind = ContextKind::action(Arc::new(action_euid));
        let context_doc = ContextDocumentation::new(Some(context_kind));
        let schema = test_schema();
        assert_snapshot!(context_doc.to_documentation_string(Some(&schema)));
    }

    #[test]
    fn test_context_documentation_action_set_no_context() {
        let action_euid: EntityUID = "Action::\"NoContext\"".parse().unwrap();
        let actions = std::iter::once(Arc::new(action_euid));
        let context_kind = ContextKind::action_set(actions);
        let context_doc = ContextDocumentation::new(Some(context_kind));
        let schema = test_schema();
        assert_snapshot!(context_doc.to_documentation_string(Some(&schema)));
    }

    #[test]
    fn test_context_documentation_action_set_mixed_context() {
        let no_context_euid: EntityUID = "Action::\"NoContext\"".parse().unwrap();
        let act_euid: EntityUID = "Action::\"Act\"".parse().unwrap();
        let actions = vec![Arc::new(no_context_euid), Arc::new(act_euid)].into_iter();
        let context_kind = ContextKind::action_set(actions);
        let context_doc = ContextDocumentation::new(Some(context_kind));
        let schema = test_schema();
        assert_snapshot!(context_doc.to_documentation_string(Some(&schema)));
    }
}
