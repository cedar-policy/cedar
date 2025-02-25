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
use cedar_policy_core::ast;
use cedar_policy_validator::types;
use nonempty::NonEmpty;
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashMap};

impl From<&cedar_policy_validator::ValidatorSchema> for models::Schema {
    fn from(v: &cedar_policy_validator::ValidatorSchema) -> Self {
        Self {
            entity_decls: v
                .entity_types()
                .map(|ety| models::EntityTypeToEntityDeclMap {
                    key: Some(models::Name::from(ety.name())),
                    value: Some(models::EntityDecl::from(ety)),
                })
                .collect(),
            action_decls: v
                .action_ids()
                .map(|id| models::EntityUidToActionDeclMap {
                    key: Some(models::EntityUid::from(id.name())),
                    value: Some(models::ActionDecl::from(id)),
                })
                .collect(),
        }
    }
}

impl From<&models::Schema> for cedar_policy_validator::ValidatorSchema {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::Schema) -> Self {
        Self::new(
            v.entity_decls
                .iter()
                .map(|models::EntityTypeToEntityDeclMap { key, value }| {
                    let key = key.as_ref().expect("key field should exist");
                    let value = value.as_ref().expect("value field should exist");
                    assert_eq!(key, value.name.as_ref().expect("name field should exist"));
                    cedar_policy_validator::ValidatorEntityType::from(value)
                }),
            v.action_decls
                .iter()
                .map(|models::EntityUidToActionDeclMap { key, value }| {
                    let key = key.as_ref().expect("key field should exist");
                    let value = value.as_ref().expect("value field should exist");
                    assert_eq!(key, value.name.as_ref().expect("name field should exist"));
                    cedar_policy_validator::ValidatorActionId::from(value)
                }),
        )
    }
}

impl From<&cedar_policy_validator::ValidationMode> for models::ValidationMode {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::unimplemented)]
    fn from(v: &cedar_policy_validator::ValidationMode) -> Self {
        match v {
            cedar_policy_validator::ValidationMode::Strict => models::ValidationMode::Strict,
            cedar_policy_validator::ValidationMode::Permissive => {
                models::ValidationMode::Permissive
            }
            #[cfg(feature = "partial-validate")]
            cedar_policy_validator::ValidationMode::Partial => unimplemented!(),
        }
    }
}

impl From<&models::ValidationMode> for cedar_policy_validator::ValidationMode {
    fn from(v: &models::ValidationMode) -> Self {
        match v {
            models::ValidationMode::Strict => cedar_policy_validator::ValidationMode::Strict,
            models::ValidationMode::Permissive => {
                cedar_policy_validator::ValidationMode::Permissive
            }
        }
    }
}

impl From<&cedar_policy_validator::ValidatorActionId> for models::ActionDecl {
    fn from(v: &cedar_policy_validator::ValidatorActionId) -> Self {
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
        Self {
            name: Some(models::EntityUid::from(v.name())),
            principal_types: v.applies_to_principals().map(models::Name::from).collect(),
            resource_types: v.applies_to_resources().map(models::Name::from).collect(),
            descendants: v.descendants().map(models::EntityUid::from).collect(),
            context: Some(models::Type::from(v.context())),
        }
    }
}

impl From<&models::ActionDecl> for cedar_policy_validator::ValidatorActionId {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::ActionDecl) -> Self {
        Self::new(
            ast::EntityUID::from(v.name.as_ref().expect("name field should exist")),
            v.principal_types.iter().map(ast::EntityType::from),
            v.resource_types.iter().map(ast::EntityType::from),
            v.descendants.iter().map(ast::EntityUID::from),
            types::Type::from(v.context.as_ref().expect("context field should exist")),
            // protobuf formats do not include action attributes, so we
            // translate into a `ValidatorActionId` with no action attributes
            types::Attributes::with_attributes([]),
            BTreeMap::new(),
        )
    }
}

impl From<&cedar_policy_validator::ValidatorEntityType> for models::EntityDecl {
    fn from(v: &cedar_policy_validator::ValidatorEntityType) -> Self {
        let name = Some(models::Name::from(v.name()));
        let descendants = v.descendants.iter().map(models::Name::from).collect();
        let attributes = attributes_to_model(v.attributes());
        let open_attributes = models::OpenTag::from(&v.open_attributes()).into();
        let tags = v.tag_type().map(models::Type::from);
        match &v.kind {
            cedar_policy_validator::ValidatorEntityTypeKind::Standard(_) => Self {
                name,
                descendants,
                attributes,
                open_attributes,
                tags,
                enum_choices: vec![],
            },
            cedar_policy_validator::ValidatorEntityTypeKind::Enum(enum_choices) => Self {
                name,
                descendants,
                attributes,
                open_attributes,
                tags,
                enum_choices: enum_choices.into_iter().map(ToString::to_string).collect(),
            },
        }
    }
}

impl From<&models::EntityDecl> for cedar_policy_validator::ValidatorEntityType {
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
                types::OpenTag::from(
                    &models::OpenTag::try_from(v.open_attributes).expect("decode should succeed"),
                ),
                v.tags.as_ref().map(types::Type::from),
            ),
            Some(enum_choices) => {
                // `enum_choices` is not empty, so `v` represents an enumerated entity type.
                // enumerated entity types must have no attributes or tags.
                assert_eq!(&v.attributes, &HashMap::new());
                assert_eq!(&v.tags, &None);
                Self::new_enum(name, descendants, enum_choices)
            }
        }
    }
}

impl From<&models::Type> for types::Type {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::Type) -> Self {
        match v.data.as_ref().expect("data field should exist") {
            models::r#type::Data::Ty(vt) => {
                match models::r#type::Ty::try_from(vt.to_owned()).expect("decode should succeed") {
                    models::r#type::Ty::Never => types::Type::Never,
                    models::r#type::Ty::True => types::Type::True,
                    models::r#type::Ty::False => types::Type::False,
                    models::r#type::Ty::EmptySetType => types::Type::Set { element_type: None },
                    models::r#type::Ty::Bool => types::Type::primitive_boolean(),
                    models::r#type::Ty::String => types::Type::primitive_string(),
                    models::r#type::Ty::Long => types::Type::primitive_long(),
                }
            }
            models::r#type::Data::SetType(tt) => types::Type::Set {
                element_type: Some(Box::new(types::Type::from(tt.as_ref()))),
            },
            models::r#type::Data::EntityOrRecord(er) => {
                types::Type::EntityOrRecord(types::EntityRecordKind::from(er))
            }
            models::r#type::Data::Name(name) => types::Type::ExtensionType {
                name: ast::Name::from(name),
            },
        }
    }
}

impl From<&types::Type> for models::Type {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &types::Type) -> Self {
        match v {
            types::Type::Never => Self {
                data: Some(models::r#type::Data::Ty(models::r#type::Ty::Never.into())),
            },
            types::Type::True => Self {
                data: Some(models::r#type::Data::Ty(models::r#type::Ty::True.into())),
            },

            types::Type::False => Self {
                data: Some(models::r#type::Data::Ty(models::r#type::Ty::False.into())),
            },
            types::Type::Primitive { primitive_type } => match primitive_type {
                types::Primitive::Bool => Self {
                    data: Some(models::r#type::Data::Ty(models::r#type::Ty::Bool.into())),
                },
                types::Primitive::Long => Self {
                    data: Some(models::r#type::Data::Ty(models::r#type::Ty::Long.into())),
                },
                types::Primitive::String => Self {
                    data: Some(models::r#type::Data::Ty(models::r#type::Ty::String.into())),
                },
            },
            types::Type::Set { element_type } => Self {
                data: Some(models::r#type::Data::SetType(Box::new(models::Type::from(
                    element_type
                        .as_ref()
                        .expect("element_type field should exist")
                        .as_ref(),
                )))),
            },
            types::Type::EntityOrRecord(er) => Self {
                data: Some(models::r#type::Data::EntityOrRecord(
                    models::EntityRecordKind::from(er),
                )),
            },
            types::Type::ExtensionType { name } => Self {
                data: Some(models::r#type::Data::Name(models::Name::from(name))),
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

impl From<&models::OpenTag> for types::OpenTag {
    fn from(v: &models::OpenTag) -> Self {
        match v {
            models::OpenTag::OpenAttributes => types::OpenTag::OpenAttributes,
            models::OpenTag::ClosedAttributes => types::OpenTag::ClosedAttributes,
        }
    }
}

impl From<&types::OpenTag> for models::OpenTag {
    fn from(v: &types::OpenTag) -> Self {
        match v {
            types::OpenTag::OpenAttributes => models::OpenTag::OpenAttributes,
            types::OpenTag::ClosedAttributes => models::OpenTag::ClosedAttributes,
        }
    }
}

impl From<&models::EntityRecordKind> for types::EntityRecordKind {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::EntityRecordKind) -> Self {
        match v.data.as_ref().expect("data field should exist") {
            models::entity_record_kind::Data::AnyEntity(x) => {
                match models::entity_record_kind::AnyEntity::try_from(*x)
                    .expect("decode should succeed")
                {
                    models::entity_record_kind::AnyEntity::X => Self::AnyEntity,
                }
            }
            models::entity_record_kind::Data::Record(r) => Self::Record {
                attrs: model_to_attributes(&r.attrs),
                open_attributes: types::OpenTag::from(
                    &models::OpenTag::try_from(r.open_attributes).expect("decode should succeed"),
                ),
            },
            models::entity_record_kind::Data::Entity(name) => {
                Self::Entity(types::EntityLUB::single_entity(ast::EntityType::from(name)))
            }
            models::entity_record_kind::Data::ActionEntity(act) => Self::ActionEntity {
                name: ast::EntityType::from(act.name.as_ref().expect("name field should exist")),
                attrs: model_to_attributes(&act.attrs),
            },
        }
    }
}

impl From<&types::EntityRecordKind> for models::EntityRecordKind {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &types::EntityRecordKind) -> Self {
        let data = match v {
            types::EntityRecordKind::Record {
                attrs,
                open_attributes,
            } => models::entity_record_kind::Data::Record(models::entity_record_kind::Record {
                attrs: attributes_to_model(attrs),
                open_attributes: models::OpenTag::from(open_attributes).into(),
            }),
            types::EntityRecordKind::AnyEntity => models::entity_record_kind::Data::AnyEntity(
                models::entity_record_kind::AnyEntity::X.into(),
            ),
            types::EntityRecordKind::Entity(e) => {
                models::entity_record_kind::Data::Entity(models::Name::from(
                    &e.clone()
                        .into_single_entity()
                        .expect("will be single EntityType"),
                ))
            }
            types::EntityRecordKind::ActionEntity { name, attrs } => {
                models::entity_record_kind::Data::ActionEntity(
                    models::entity_record_kind::ActionEntity {
                        name: Some(models::Name::from(name)),
                        attrs: attributes_to_model(attrs),
                    },
                )
            }
        };
        Self { data: Some(data) }
    }
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
