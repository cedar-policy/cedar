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
    policy::{cedar::EntityTypeKind, DocumentContext},
};

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
    T: Into<Option<&'a DocumentContext<'a>>>,
{
    fn from(value: T) -> Self {
        let value = value.into();
        value.map_or_else(Self::default, |context| {
            context.resolve_principal_type().into()
        })
    }
}

impl ToDocumentationString for PrincipalDocumentation {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> Cow<'static, str> {
        let static_docs = include_str!("markdown/principal.md");
        let Some(entity_type) = &self.entity_type else {
            return static_docs.into();
        };

        let mut builder = MarkdownBuilder::new();
        builder.push_str(static_docs);
        let entity_type_doc = entity_type.to_documentation_string(schema);
        builder.push_with_new_line(&entity_type_doc);
        builder.build().into()
    }
}
