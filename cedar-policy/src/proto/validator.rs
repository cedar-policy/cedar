#![allow(clippy::use_self)]

use super::models;
use cedar_policy_core::{ast, evaluator, extensions};
use cedar_policy_validator::types;
use nonempty::NonEmpty;
use smol_str::SmolStr;
use std::collections::HashMap;

impl From<&cedar_policy_validator::ValidatorSchema> for models::ValidatorSchema {
    fn from(v: &cedar_policy_validator::ValidatorSchema) -> Self {
        Self {
            entity_types: v
                .entity_types()
                .map(|ety| models::EntityTypeWithTypesMap {
                    key: Some(models::EntityType::from(ety.name())),
                    value: Some(models::ValidatorEntityType::from(ety)),
                })
                .collect(),
            action_ids: v
                .action_ids()
                .map(|id| models::EntityUidWithActionIdsMap {
                    key: Some(models::EntityUid::from(id.name())),
                    value: Some(models::ValidatorActionId::from(id)),
                })
                .collect(),
        }
    }
}

impl From<&models::ValidatorSchema> for cedar_policy_validator::ValidatorSchema {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::ValidatorSchema) -> Self {
        Self::new(
            v.entity_types
                .iter()
                .map(|models::EntityTypeWithTypesMap { key, value }| {
                    let key = key.as_ref().expect("key field should exist");
                    let value = value.as_ref().expect("value field should exist");
                    assert_eq!(key, value.name.as_ref().expect("name field should exist"));
                    cedar_policy_validator::ValidatorEntityType::from(value)
                }),
            v.action_ids
                .iter()
                .map(|models::EntityUidWithActionIdsMap { key, value }| {
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

impl From<&cedar_policy_validator::ValidatorActionId> for models::ValidatorActionId {
    fn from(v: &cedar_policy_validator::ValidatorActionId) -> Self {
        Self {
            name: Some(models::EntityUid::from(v.name())),
            applies_to: Some(models::ValidatorApplySpec {
                principal_apply_spec: v
                    .applies_to_principals()
                    .map(models::EntityType::from)
                    .collect(),
                resource_apply_spec: v
                    .applies_to_resources()
                    .map(models::EntityType::from)
                    .collect(),
            }),
            descendants: v.descendants().map(models::EntityUid::from).collect(),
            context: Some(models::Type::from(v.context())),
            attribute_types: Some(models::Attributes::from(v.attribute_types())),
            attributes: v
                .attributes()
                .map(|(k, v)| {
                    let value =
                        models::Expr::from(&ast::Expr::from(ast::PartialValue::from(v.to_owned())));
                    (k.to_string(), value)
                })
                .collect(),
        }
    }
}

impl From<&models::ValidatorActionId> for cedar_policy_validator::ValidatorActionId {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::ValidatorActionId) -> Self {
        let extensions_none = extensions::Extensions::none();
        let eval = evaluator::RestrictedEvaluator::new(extensions_none);
        Self::new(
            ast::EntityUID::from(v.name.as_ref().expect("name field should exist")),
            v.applies_to
                .as_ref()
                .expect("applies_to field should exist")
                .principal_apply_spec
                .iter()
                .map(ast::EntityType::from),
            v.applies_to
                .as_ref()
                .expect("applies_to field should exist")
                .resource_apply_spec
                .iter()
                .map(ast::EntityType::from),
            v.descendants.iter().map(ast::EntityUID::from),
            types::Type::from(v.context.as_ref().expect("context field should exist")),
            types::Attributes::from(
                v.attribute_types
                    .as_ref()
                    .expect("attribute_types field should exist"),
            ),
            v.attributes
                .iter()
                .map(|(k, v)| {
                    let pval = eval
                        .partial_interpret(
                            ast::BorrowedRestrictedExpr::new(&ast::Expr::from(v))
                                .expect("RestrictedExpr"),
                        )
                        .expect("interpret on RestrictedExpr");
                    (k.into(), pval.into())
                })
                .collect(),
        )
    }
}

impl From<&cedar_policy_validator::ValidatorEntityType> for models::ValidatorEntityType {
    fn from(v: &cedar_policy_validator::ValidatorEntityType) -> Self {
        let name = Some(models::EntityType::from(v.name()));
        let descendants = v.descendants.iter().map(models::EntityType::from).collect();
        let attributes = Some(models::Attributes::from(v.attributes()));
        let open_attributes = models::OpenTag::from(&v.open_attributes()).into();
        let tags = v.tag_type().map(|tags| models::Tag {
            optional_type: Some(models::Type::from(tags)),
        });
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

impl From<&models::ValidatorEntityType> for cedar_policy_validator::ValidatorEntityType {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::ValidatorEntityType) -> Self {
        let name = ast::EntityType::from(v.name.as_ref().expect("name field should exist"));
        let descendants = v.descendants.iter().map(ast::EntityType::from);
        match NonEmpty::collect(v.enum_choices.iter().map(SmolStr::from)) {
            None => Self::new_standard(
                name,
                descendants,
                types::Attributes::from(
                    v.attributes
                        .as_ref()
                        .expect("attributes field should exist"),
                ),
                types::OpenTag::from(
                    &models::OpenTag::try_from(v.open_attributes).expect("decode should succeed"),
                ),
                v.tags
                    .as_ref()
                    .and_then(|tags| tags.optional_type.as_ref().map(types::Type::from)),
            ),
            Some(enum_choices) => {
                if let Some(vec) = &v.attributes {
                    assert_eq!(
                        vec,
                        &models::Attributes {
                            attrs: HashMap::new()
                        }
                    );
                }
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

impl From<&models::Attributes> for types::Attributes {
    fn from(v: &models::Attributes) -> Self {
        Self::with_attributes(
            v.attrs
                .iter()
                .map(|(k, v)| (k.into(), types::AttributeType::from(v))),
        )
    }
}

impl From<&types::Attributes> for models::Attributes {
    fn from(v: &types::Attributes) -> Self {
        Self {
            attrs: v
                .iter()
                .map(|(k, v)| (k.to_string(), models::AttributeType::from(v)))
                .collect(),
        }
    }
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
            models::entity_record_kind::Data::Ty(ty) => {
                match models::entity_record_kind::Ty::try_from(ty.to_owned())
                    .expect("decode should succeed")
                {
                    models::entity_record_kind::Ty::AnyEntity => Self::AnyEntity,
                }
            }
            models::entity_record_kind::Data::Record(p_record) => Self::Record {
                attrs: types::Attributes::from(
                    p_record.attrs.as_ref().expect("attrs field should exist"),
                ),
                open_attributes: types::OpenTag::from(
                    &models::OpenTag::try_from(p_record.open_attributes)
                        .expect("decode should succeed"),
                ),
            },
            models::entity_record_kind::Data::Entity(p_entity) => {
                Self::Entity(types::EntityLUB::single_entity(ast::EntityType::from(
                    p_entity.e.as_ref().expect("e field should exist"),
                )))
            }
            models::entity_record_kind::Data::ActionEntity(p_action_entity) => Self::ActionEntity {
                name: ast::EntityType::from(
                    p_action_entity
                        .name
                        .as_ref()
                        .expect("name field should exist"),
                ),
                attrs: types::Attributes::from(
                    p_action_entity
                        .attrs
                        .as_ref()
                        .expect("attrs field should exist"),
                ),
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
                attrs: Some(models::Attributes::from(attrs)),
                open_attributes: models::OpenTag::from(open_attributes).into(),
            }),
            types::EntityRecordKind::AnyEntity => models::entity_record_kind::Data::Ty(
                models::entity_record_kind::Ty::AnyEntity.into(),
            ),
            types::EntityRecordKind::Entity(e) => {
                models::entity_record_kind::Data::Entity(models::entity_record_kind::Entity {
                    e: Some(models::EntityType::from(
                        &e.clone()
                            .into_single_entity()
                            .expect("will be single EntityType"),
                    )),
                })
            }
            types::EntityRecordKind::ActionEntity { name, attrs } => {
                models::entity_record_kind::Data::ActionEntity(
                    models::entity_record_kind::ActionEntity {
                        name: Some(models::EntityType::from(name)),
                        attrs: Some(models::Attributes::from(attrs)),
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
