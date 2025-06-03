use cedar_policy_core::validator::ValidatorSchema;
use indoc::indoc;

use crate::{
    markdown::{MarkdownBuilder, ToDocumentationString},
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

        builder
            .header("Using Context in Conditions")
            .paragraph("Context attributes can be referenced in policy conditions:")
            .code_block(
                "cedar",
                indoc! {"
            permit(principal, action, resource)
            when {
                // Examples of using context
                context.authentication.mfa_authenticated == true &&
                context.request.timestamp > \"2023-01-01T00:00:00Z\" &&
                context.source.ip in IPRange(\"10.0.0.0/24\")
            };
            "},
            );

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
