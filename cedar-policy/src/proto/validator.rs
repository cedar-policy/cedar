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

#![allow(clippy::use_self)]

use super::models;
use cedar_policy_core::validator::types;
use cedar_policy_core::{ast, parser::IntoMaybeLoc};
use nonempty::NonEmpty;
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashMap};

impl From<&cedar_policy_core::validator::ValidatorSchema> for models::Schema {
    fn from(v: &cedar_policy_core::validator::ValidatorSchema) -> Self {
        Self {
            entity_decls: v.entity_types().map(models::EntityDecl::from).collect(),
            action_decls: v.action_ids().map(models::ActionDecl::from).collect(),
        }
    }
}

impl From<&models::Schema> for cedar_policy_core::validator::ValidatorSchema {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::Schema) -> Self {
        Self::new(
            v.entity_decls
                .iter()
                .map(cedar_policy_core::validator::ValidatorEntityType::from),
            v.action_decls
                .iter()
                .map(cedar_policy_core::validator::ValidatorActionId::from),
        )
    }
}

impl From<&cedar_policy_core::validator::ValidationMode> for models::ValidationMode {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::unimplemented)]
    fn from(v: &cedar_policy_core::validator::ValidationMode) -> Self {
        match v {
            cedar_policy_core::validator::ValidationMode::Strict => models::ValidationMode::Strict,
            cedar_policy_core::validator::ValidationMode::Permissive => {
                models::ValidationMode::Permissive
            }
            #[cfg(feature = "partial-validate")]
            cedar_policy_core::validator::ValidationMode::Partial => {
                models::ValidationMode::Partial
            }
        }
    }
}

impl From<&models::ValidationMode> for cedar_policy_core::validator::ValidationMode {
    fn from(v: &models::ValidationMode) -> Self {
        match v {
            models::ValidationMode::Strict => cedar_policy_core::validator::ValidationMode::Strict,
            models::ValidationMode::Permissive => {
                cedar_policy_core::validator::ValidationMode::Permissive
            }
            #[cfg(feature = "partial-validate")]
            models::ValidationMode::Partial => {
                cedar_policy_core::validator::ValidationMode::Partial
            }
            #[cfg(not(feature = "partial-validate"))]
            models::ValidationMode::Partial => {
                panic!("Protobuf specifies partial validation, but `partial-validate` feature not enabled in this build")
            }
        }
    }
}

// PANIC SAFETY: experimental feature
#[allow(clippy::fallible_impl_from)]
impl From<&cedar_policy_core::validator::ValidatorActionId> for models::ActionDecl {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::panic)]
    fn from(v: &cedar_policy_core::validator::ValidatorActionId) -> Self {
        debug_assert_eq!(
            v.attribute_types().keys().collect::<Vec<&SmolStr>>(),
            Vec::<&SmolStr>::new(),
            "action attributes are not currently supported in protobuf"
        );
        debug_assert_eq!(
            v.attributes().collect::<Vec<_>>(),
            vec![],
            "action attributes are not currently supported in protobuf"
        );
        let ctx_attrs = match v.context() {
            types::Type::EntityOrRecord(types::EntityRecordKind::Record {
                attrs,
                open_attributes: types::OpenTag::ClosedAttributes,
            }) => attrs,
            ty => panic!("expected context to be a closed record, but got {ty:?}"),
        };
        Self {
            name: Some(models::EntityUid::from(v.name())),
            principal_types: v.applies_to_principals().map(models::Name::from).collect(),
            resource_types: v.applies_to_resources().map(models::Name::from).collect(),
            descendants: v.descendants().map(models::EntityUid::from).collect(),
            context: attributes_to_model(ctx_attrs),
        }
    }
}

impl From<&models::ActionDecl> for cedar_policy_core::validator::ValidatorActionId {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::ActionDecl) -> Self {
        Self::new(
            ast::EntityUID::from(v.name.as_ref().expect("name field should exist")),
            v.principal_types.iter().map(ast::EntityType::from),
            v.resource_types.iter().map(ast::EntityType::from),
            v.descendants.iter().map(ast::EntityUID::from),
            types::Type::EntityOrRecord(types::EntityRecordKind::Record {
                attrs: model_to_attributes(&v.context),
                open_attributes: types::OpenTag::default(),
            }),
            // protobuf formats do not include action attributes, so we
            // translate into a `ValidatorActionId` with no action attributes
            types::Attributes::with_attributes([]),
            BTreeMap::new(),
            None,
        )
    }
}

impl From<&cedar_policy_core::validator::ValidatorEntityType> for models::EntityDecl {
    fn from(v: &cedar_policy_core::validator::ValidatorEntityType) -> Self {
        let name = Some(models::Name::from(v.name()));
        let descendants = v.descendants.iter().map(models::Name::from).collect();
        let attributes = attributes_to_model(v.attributes());
        let tags = v.tag_type().map(models::Type::from);
        match &v.kind {
            cedar_policy_core::validator::ValidatorEntityTypeKind::Standard(_) => Self {
                name,
                descendants,
                attributes,
                tags,
                enum_choices: vec![],
            },
            cedar_policy_core::validator::ValidatorEntityTypeKind::Enum(enum_choices) => Self {
                name,
                descendants,
                attributes,
                tags,
                enum_choices: enum_choices.into_iter().map(ToString::to_string).collect(),
            },
        }
    }
}

impl From<&models::EntityDecl> for cedar_policy_core::validator::ValidatorEntityType {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::EntityDecl) -> Self {
        let name = ast::EntityType::from(v.name.as_ref().expect("name field should exist"));
        let descendants = v.descendants.iter().map(ast::EntityType::from);
        match NonEmpty::collect(v.enum_choices.iter().map(SmolStr::from)) {
            // `enum_choices` is empty, so `v` represents a standard entity type
            None => Self::new_standard(
                name,
                descendants,
                model_to_attributes(&v.attributes),
                types::OpenTag::default(),
                v.tags.as_ref().map(types::Type::from),
                None,
            ),
            Some(enum_choices) => {
                // `enum_choices` is not empty, so `v` represents an enumerated entity type.
                // enumerated entity types must have no attributes or tags.
                assert_eq!(&v.attributes, &HashMap::new());
                assert_eq!(&v.tags, &None);
                Self::new_enum(
                    name.clone(),
                    descendants,
                    enum_choices,
                    name.loc().into_maybe_loc(),
                )
            }
        }
    }
}

impl From<&models::Type> for types::Type {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::Type) -> Self {
        match v.data.as_ref().expect("data field should exist") {
            models::r#type::Data::Prim(vt) => {
                match models::r#type::Prim::try_from(vt.to_owned()).expect("decode should succeed")
                {
                    models::r#type::Prim::Bool => types::Type::primitive_boolean(),
                    models::r#type::Prim::String => types::Type::primitive_string(),
                    models::r#type::Prim::Long => types::Type::primitive_long(),
                }
            }
            models::r#type::Data::SetElem(elty) => types::Type::Set {
                element_type: Some(Box::new(types::Type::from(elty.as_ref()))),
            },
            models::r#type::Data::Entity(e) => {
                types::Type::EntityOrRecord(types::EntityRecordKind::Entity(
                    types::EntityLUB::single_entity(ast::EntityType::from(e)),
                ))
            }
            models::r#type::Data::Record(r) => {
                types::Type::EntityOrRecord(types::EntityRecordKind::Record {
                    attrs: model_to_attributes(&r.attrs),
                    open_attributes: types::OpenTag::default(),
                })
            }
            models::r#type::Data::Ext(name) => types::Type::ExtensionType {
                name: ast::Name::from(name),
            },
        }
    }
}

// PANIC SAFETY: experimental feature
#[allow(clippy::fallible_impl_from)]
impl From<&types::Type> for models::Type {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used, clippy::panic)]
    fn from(v: &types::Type) -> Self {
        match v {
            types::Type::Never => panic!("can't encode Never type in protobuf; Never should never appear in a Schema"),
            types::Type::True | types::Type::False => panic!("can't encode singleton boolean type in protobuf; singleton boolean types should never appear in a Schema"),
            types::Type::Primitive { primitive_type } => match primitive_type {
                types::Primitive::Bool => Self {
                    data: Some(models::r#type::Data::Prim(models::r#type::Prim::Bool.into())),
                },
                types::Primitive::Long => Self {
                    data: Some(models::r#type::Data::Prim(models::r#type::Prim::Long.into())),
                },
                types::Primitive::String => Self {
                    data: Some(models::r#type::Data::Prim(models::r#type::Prim::String.into())),
                },
            },
            types::Type::Set { element_type } => Self {
                data: Some(models::r#type::Data::SetElem(Box::new(models::Type::from(
                    element_type
                        .as_ref()
                        .expect("can't encode Set without element type in protobuf; Set-without-element-type should never appear in a Schema")
                        .as_ref(),
                )))),
            },
            types::Type::EntityOrRecord(types::EntityRecordKind::Entity(lub)) => Self {
                data: Some(models::r#type::Data::Entity(models::Name::from(lub.get_single_entity().expect("can't encode non-singleton LUB in protobuf; non-singleton LUB types should never appear in a Schema").as_ref()))),
            },
            types::Type::EntityOrRecord(types::EntityRecordKind::Record { attrs, open_attributes }) => {
                assert_eq!(open_attributes, &types::OpenTag::ClosedAttributes, "can't encode open record in protobuf");
                Self {
                    data: Some(models::r#type::Data::Record(models::r#type::Record { attrs: attributes_to_model(attrs) })),
                }
            }
            types::Type::EntityOrRecord(types::EntityRecordKind::ActionEntity { name, attrs }) => {
                debug_assert_eq!(attrs.keys().collect::<Vec<&SmolStr>>(), Vec::<&SmolStr>::new(), "can't encode action attributes in protobuf");
                Self {
                    data: Some(models::r#type::Data::Entity(models::Name::from(name.as_ref()))),
                }
            }
            types::Type::EntityOrRecord(types::EntityRecordKind::AnyEntity) => panic!("can't encode AnyEntity type in protobuf; AnyEntity should never appear in a Schema"),
            types::Type::ExtensionType { name } => Self {
                data: Some(models::r#type::Data::Ext(models::Name::from(name))),
            },
        }
    }
}

fn model_to_attributes(v: &HashMap<String, models::AttributeType>) -> types::Attributes {
    types::Attributes::with_attributes(v.iter().map(|(k, v)| (k.into(), v.into())))
}

fn attributes_to_model(v: &types::Attributes) -> HashMap<String, models::AttributeType> {
    v.iter()
        .map(|(k, v)| (k.to_string(), models::AttributeType::from(v)))
        .collect()
}

impl From<&models::AttributeType> for types::AttributeType {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::AttributeType) -> Self {
        Self {
            attr_type: types::Type::from(
                v.attr_type.as_ref().expect("attr_type field should exist"),
            ),
            is_required: v.is_required,
            #[cfg(feature = "extended-schema")]
            loc: None,
        }
    }
}

impl From<&types::AttributeType> for models::AttributeType {
    fn from(v: &types::AttributeType) -> Self {
        Self {
            attr_type: Some(models::Type::from(&v.attr_type)),
            is_required: v.is_required,
        }
    }
}
