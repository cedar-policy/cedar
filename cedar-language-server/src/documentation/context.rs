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

use cedar_policy_core::validator::ValidatorSchema;
use indoc::indoc;

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
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> String {
        let mut builder = MarkdownBuilder::new();

        // Add documentation header and general description
        builder
            .header("Context")
            .paragraph(indoc! {"
                The context element in a Cedar policy provides additional information about the
                circumstances of the request being evaluated. This includes details such as the
                date and time, IP address, authentication methods, or any custom data relevant
                to authorization decisions.
            "})
            .paragraph(indoc! {"
                Context attributes are passed at evaluation time and can be referenced in policy conditions.
                These attributes are not persisted within Cedar but are provided with each request.
            "});

        // If we have a specific context kind, add its documentation
        if let Some(context_kind) = &self.context_kind {
            let context_kind_doc = context_kind.to_documentation_string(schema);
            builder.push_with_new_line(&context_kind_doc);
        }

        builder.build()
    }
}

impl From<&DocumentContext> for ContextDocumentation {
    fn from(value: &DocumentContext) -> Self {
        Self::new(Some(value.resolve_context_type()))
    }
}

impl From<Option<&DocumentContext>> for ContextDocumentation {
    fn from(value: Option<&DocumentContext>) -> Self {
        value.map(Into::into).unwrap_or_default()
    }
}
