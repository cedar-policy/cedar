use cedar_policy_core::validator::ValidatorSchema;

use crate::{
    markdown::{MarkdownBuilder, ToDocumentationString},
    policy::{cedar::EntityTypeKind, DocumentContext},
};

use indoc::indoc;

#[derive(Debug, Clone, Default)]
pub(crate) struct PrincipalDocumentation {
    entity_type: Option<EntityTypeKind>,
}

impl PrincipalDocumentation {
    pub(crate) fn new(entity_type: EntityTypeKind) -> Self {
        Self {
            entity_type: Some(entity_type),
        }
    }
}

impl From<EntityTypeKind> for PrincipalDocumentation {
    fn from(value: EntityTypeKind) -> Self {
        Self::new(value)
    }
}

impl<'a, T> From<T> for PrincipalDocumentation
where
    T: Into<Option<&'a DocumentContext>>,
{
    fn from(value: T) -> Self {
        let value = value.into();
        value.map_or_else(Self::default, |context| {
            context.resolve_principal_type().into()
        })
    }
}

impl ToDocumentationString for PrincipalDocumentation {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> String {
        let mut builder = MarkdownBuilder::new();

        // Add documentation
        builder
            .header("Principal")
            .paragraph(indoc! {"
                The principal element in a Cedar policy represents a user, service, or other identity
                that can make a request to perform an action on a resource in your application. If the
                principal making the request matches the principal defined in this policy statement,
                then this element matches."
            })
            .paragraph(indoc! {"
                The principal element must be present. If you specify only principal without an expression
                that constrains its scope, then the policy applies to any principal."
            });

        let Some(entity_type) = &self.entity_type else {
            return builder.build();
        };

        let entity_type_doc = entity_type.to_documentation_string(schema);
        builder.push_with_new_line(&entity_type_doc);

        builder.build()
    }
}
