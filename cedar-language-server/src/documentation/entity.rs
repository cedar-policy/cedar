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
use std::{collections::BTreeSet, fmt::Display, ops::Deref};

use cedar_policy_core::ast::{EntityType, EntityUID};
use cedar_policy_core::validator::ValidatorSchema;
use itertools::Itertools;

use super::ToDocumentationString;
use crate::{
    markdown::MarkdownBuilder,
    policy::{cedar::EntityTypeKind, format_attributes},
};

impl ToDocumentationString for EntityType {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> Cow<'static, str> {
        let mut builder = MarkdownBuilder::new();
        builder
            .header("Type")
            .paragraph(&format!("Entity Type: `{self}`"));

        if let Some(schema_type) = schema.and_then(|schema| schema.get_entity_type(self)) {
            let attrs = schema_type.attributes();
            if !attrs.keys().count() > 0 {
                builder
                    .paragraph("Attributes:")
                    .code_block("cedarschema", &format_attributes(attrs.iter()));
            }
        }

        builder.build().into()
    }
}

impl ToDocumentationString for EntityUID {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> Cow<'static, str> {
        let mut builder = MarkdownBuilder::new();
        builder
            .header("Entity")
            .paragraph(&format!("Entity: `{self}`"))
            .paragraph(&format!("Type: `{}`", self.entity_type()));

        if let Some(schema) = schema {
            if let Some(schema_type) = schema.get_entity_type(self.entity_type()) {
                let attrs = schema_type.attributes();
                if !attrs.keys().count() > 0 {
                    builder
                        .paragraph("Available Attributes:")
                        .code_block("cedarschema", &format_attributes(attrs.iter()));
                }
            }
        }

        builder.build().into()
    }
}

impl<D> ToDocumentationString for BTreeSet<D>
where
    D: Deref<Target = EntityType> + Display,
{
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> Cow<'static, str> {
        if self.is_empty() {
            return "".into();
        }

        if let Ok(entity_type) = self.iter().exactly_one() {
            return entity_type.to_documentation_string(schema);
        }

        let mut builder = MarkdownBuilder::new();
        builder
            .header("Possible Types")
            .paragraph("This entity can be any of the following entity types:");

        for entity_type in self {
            builder.header(&format!("Type: `{entity_type}`"));

            // Add attribute information for each type if schema is available
            if let Some(schema_type) = schema.and_then(|schema| schema.get_entity_type(entity_type))
            {
                let attrs = schema_type.attributes();
                if !attrs.keys().count() > 0 {
                    builder
                        .paragraph("Attributes:")
                        .code_block("cedarschema", &format_attributes(attrs.iter()));
                }
            }
        }
        builder.build().into()
    }
}

impl ToDocumentationString for EntityTypeKind {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> Cow<'static, str> {
        match self {
            Self::Concrete(entity_type) => entity_type.to_documentation_string(schema),
            Self::Set(set) => set.to_documentation_string(schema),
            Self::AnyPrincipal => {
                let Some(schema) = schema else {
                    let mut builder = MarkdownBuilder::new();
                    builder.paragraph("*Schema not available - any principal permitted*");
                    return builder.build().into();
                };
                let set = schema.principals().collect::<BTreeSet<_>>();

                set.to_documentation_string(Some(schema))
            }
            Self::AnyResource => {
                let Some(schema) = schema else {
                    let mut builder = MarkdownBuilder::new();
                    builder.paragraph("*Schema not available - any resource permitted*");
                    return builder.build().into();
                };
                let set = schema.resources().collect::<BTreeSet<_>>();

                set.to_documentation_string(Some(schema))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::*;
    use cedar_policy_core::validator::ValidatorSchema;
    use insta::assert_snapshot;

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
          };
        "#
        .parse()
        .unwrap()
    }

    #[test]
    fn test_entity_uid_no_schema() {
        let uid: EntityUID = "User::\"alice\"".parse().unwrap();
        assert_snapshot!(uid.to_documentation_string(None));
    }

    #[test]
    fn test_entity_uid_with_schema() {
        let uid: EntityUID = "User::\"alice\"".parse().unwrap();
        let schema = test_schema();
        assert_snapshot!(uid.to_documentation_string(Some(&schema)));
    }

    #[test]
    fn test_entity_type_no_schema() {
        let et: EntityType = "User".parse().unwrap();
        assert_snapshot!(et.to_documentation_string(None));
    }

    #[test]
    fn test_entity_type_with_schema() {
        let et: EntityType = "User".parse().unwrap();
        let schema = test_schema();
        assert_snapshot!(et.to_documentation_string(Some(&schema)));
    }

    #[test]
    fn test_entity_type_kind_concrete() {
        let et: EntityType = "User".parse().unwrap();
        let entity_type_kind = EntityTypeKind::Concrete(Arc::new(et));
        let schema = test_schema();
        assert_snapshot!(entity_type_kind.to_documentation_string(Some(&schema)));
    }

    #[test]
    fn test_entity_type_kind_concrete_no_schema() {
        let et: EntityType = "User".parse().unwrap();
        let entity_type_kind = EntityTypeKind::Concrete(Arc::new(et));
        assert_snapshot!(entity_type_kind.to_documentation_string(None));
    }

    #[test]
    fn test_entity_type_kind_set_empty() {
        let set = BTreeSet::from([Arc::new("User".parse().unwrap())]);
        let entity_type_kind = EntityTypeKind::Set(set);
        let schema = test_schema();
        assert_snapshot!(entity_type_kind.to_documentation_string(Some(&schema)));
    }

    #[test]
    fn test_entity_type_kind_set_single() {
        let set = BTreeSet::from([Arc::new("User".parse().unwrap())]);
        let entity_type_kind = EntityTypeKind::Set(set);
        let schema = test_schema();
        assert_snapshot!(entity_type_kind.to_documentation_string(Some(&schema)));
    }

    #[test]
    fn test_entity_type_kind_set_multiple() {
        let set = BTreeSet::from([
            Arc::new("User".parse().unwrap()),
            Arc::new("Photo".parse().unwrap()),
        ]);
        let entity_type_kind = EntityTypeKind::Set(set);
        let schema = test_schema();
        assert_snapshot!(entity_type_kind.to_documentation_string(Some(&schema)));
    }

    #[test]
    fn test_entity_type_kind_set_multiple_no_schema() {
        let set = BTreeSet::from([
            Arc::new("User".parse().unwrap()),
            Arc::new("Photo".parse().unwrap()),
        ]);
        let entity_type_kind = EntityTypeKind::Set(set);
        assert_snapshot!(entity_type_kind.to_documentation_string(None));
    }

    #[test]
    fn test_entity_type_kind_any_principal_no_schema() {
        let entity_type_kind = EntityTypeKind::AnyPrincipal;
        assert_snapshot!(entity_type_kind.to_documentation_string(None));
    }

    #[test]
    fn test_entity_type_kind_any_principal_with_schema() {
        let entity_type_kind = EntityTypeKind::AnyPrincipal;
        let schema = test_schema();
        assert_snapshot!(entity_type_kind.to_documentation_string(Some(&schema)));
    }

    #[test]
    fn test_entity_type_kind_any_resource_no_schema() {
        let entity_type_kind = EntityTypeKind::AnyResource;
        assert_snapshot!(entity_type_kind.to_documentation_string(None));
    }

    #[test]
    fn test_entity_type_kind_any_resource_with_schema() {
        let entity_type_kind = EntityTypeKind::AnyResource;
        let schema = test_schema();
        assert_snapshot!(entity_type_kind.to_documentation_string(Some(&schema)));
    }
}
