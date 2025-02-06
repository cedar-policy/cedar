use std::collections::HashMap;

use super::*;
use cedar_policy_core::{ast, evaluator, extensions};
use cedar_policy_validator::types;
use nonempty::NonEmpty;
use smol_str::SmolStr;

impl From<&cedar_policy_validator::ValidatorSchema> for ValidatorSchema {
    fn from(v: &cedar_policy_validator::ValidatorSchema) -> Self {
        Self {
            entity_types: v
                .entity_types()
                .map(|ety| EntityTypeWithTypesMap {
                    key: Some(EntityType::from(ety.name())),
                    value: Some(ValidatorEntityType::from(ety)),
                })
                .collect(),
            action_ids: v
                .action_ids()
                .map(|id| EntityUidWithActionIdsMap {
                    key: Some(EntityUid::from(id.name())),
                    value: Some(ValidatorActionId::from(id)),
                })
                .collect(),
        }
    }
}

impl From<&ValidatorSchema> for cedar_policy_validator::ValidatorSchema {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &ValidatorSchema) -> Self {
        let action_ids = v
            .action_ids
            .iter()
            .map(|kvp| {
                let k = ast::EntityUID::from(kvp.key.as_ref().expect("key field should exist"));
                let v = cedar_policy_validator::ValidatorActionId::from(
                    kvp.value.as_ref().expect("value field should exist"),
                );
                (k, v)
            })
            .collect();

        Self::new(
            v.entity_types
                .iter()
                .map(|EntityTypeWithTypesMap { key, value }| {
                    let key = key.as_ref().expect("key field should exist");
                    let value = value.as_ref().expect("value field should exist");
                    assert_eq!(key, value.name);
                    cedar_policy_validator::ValidatorEntityType::from(value)
                })
                .collect(),
            v.action_ids
                .iter()
                .map(|EntityUidWithActionIdsMap { key, value }| {
                    let key = key.as_ref().expect("key field should exist");
                    let value = value.as_ref().expect("value field should exist");
                    assert_eq!(key, value.name);
                    cedar_policy_validator::ValidatorActionId::from(value)
                }),
        )
    }
}

impl From<&cedar_policy_validator::ValidationMode> for ValidationMode {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::unimplemented)]
    fn from(v: &cedar_policy_validator::ValidationMode) -> Self {
        match v {
            cedar_policy_validator::ValidationMode::Strict => ValidationMode::Strict,
            cedar_policy_validator::ValidationMode::Permissive => ValidationMode::Permissive,
            #[cfg(feature = "partial-validate")]
            cedar_policy_validator::ValidationMode::Partial => unimplemented!(),
        }
    }
}

impl From<&ValidationMode> for cedar_policy_validator::ValidationMode {
    fn from(v: &ValidationMode) -> Self {
        match v {
            ValidationMode::Strict => cedar_policy_validator::ValidationMode::Strict,
            ValidationMode::Permissive => cedar_policy_validator::ValidationMode::Permissive,
        }
    }
}

impl From<&cedar_policy_validator::ValidatorActionId> for ValidatorActionId {
    fn from(v: &cedar_policy_validator::ValidatorActionId) -> Self {
        Self {
            name: Some(EntityUid::from(v.name())),
            applies_to: Some(ValidatorApplySpec {
                principal_apply_spec: v.applies_to_principals().map(EntityType::from),
                resource_apply_spec: v.applies_to_resources().map(EntityType::from),
            }),
            descendants: v.descendants().map(EntityUid::from).collect(),
            context: Some(Type::from(v.context())),
            attribute_types: Some(Attributes::from(v.attribute_types())),
            attributes: v
                .attributes()
                .map(|(k, v)| {
                    let value = Expr::from(&ast::Expr::from(ast::PartialValue::from(v.to_owned())));
                    (k.to_string(), value)
                })
                .collect(),
        }
    }
}

impl From<&ValidatorActionId> for cedar_policy_validator::ValidatorActionId {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &ValidatorActionId) -> Self {
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
            v.descendants.iter().map(ast::EntityUID::from).collect(),
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

impl From<&cedar_policy_validator::ValidatorEntityType> for ValidatorEntityType {
    fn from(v: &cedar_policy_validator::ValidatorEntityType) -> Self {
        let name = Some(EntityType::from(v.name()));
        let descendants = v.descendants.iter().map(EntityType::from).collect();
        let attributes = Some(Attributes::from(v.attributes()));
        let open_attributes = OpenTag::from(&v.open_attributes()).into();
        let tags = v.tag_type().map(|tags| Tag {
            optional_type: Some(Type::from(tags)),
        });
        match v.kind {
            cedar_policy_validator::ValidatorEntityTypeKind::Standard(ty) => Self {
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
                enum_choices: enum_choices.into_iter().map(Into::into).collect(),
            },
        }
    }
}

impl From<&ValidatorEntityType> for cedar_policy_validator::ValidatorEntityType {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &ValidatorEntityType) -> Self {
        let name = ast::EntityType::from(v.name.as_ref().expect("name field should exist"));
        let descendants = v.descendants.iter().map(ast::EntityType::from);
        match NonEmpty::collect(v.enum_choices.into_iter().map(SmolStr::from)) {
            None => Self::new_standard(
                name,
                descendants,
                types::Attributes::from(
                    v.attributes
                        .as_ref()
                        .expect("attributes field should exist"),
                ),
                types::OpenTag::from(
                    &OpenTag::try_from(v.open_attributes).expect("decode should succeed"),
                ),
                v.tags
                    .and_then(|tags| tags.optional_type.as_ref().map(types::Type::from)),
            ),
            Some(enum_choices) => {
                if let Some(vec) = &v.attributes {
                    assert_eq!(
                        vec,
                        &Attributes {
                            attrs: HashMap::new()
                        }
                    );
                }
                Self::new_enum(name, descendants, enum_choices)
            }
        }
    }
}

impl From<&Type> for types::Type {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &Type) -> Self {
        match v.data.as_ref().expect("data field should exist") {
            r#type::Data::Ty(vt) => {
                match r#type::Ty::try_from(vt.to_owned()).expect("decode should succeed") {
                    r#type::Ty::Never => types::Type::Never,
                    r#type::Ty::True => types::Type::True,
                    r#type::Ty::False => types::Type::False,
                    r#type::Ty::EmptySetType => types::Type::Set { element_type: None },
                    r#type::Ty::Bool => types::Type::primitive_boolean(),
                    r#type::Ty::String => types::Type::primitive_string(),
                    r#type::Ty::Long => types::Type::primitive_long(),
                }
            }
            r#type::Data::SetType(tt) => types::Type::Set {
                element_type: Some(Box::new(types::Type::from(tt.as_ref()))),
            },
            r#type::Data::EntityOrRecord(er) => {
                types::Type::EntityOrRecord(types::EntityRecordKind::from(er))
            }
            r#type::Data::Name(name) => types::Type::ExtensionType {
                name: ast::Name::from(name),
            },
        }
    }
}

impl From<&types::Type> for Type {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &types::Type) -> Self {
        match v {
            types::Type::Never => Self {
                data: Some(r#type::Data::Ty(r#type::Ty::Never.into())),
            },
            types::Type::True => Self {
                data: Some(r#type::Data::Ty(r#type::Ty::True.into())),
            },

            types::Type::False => Self {
                data: Some(r#type::Data::Ty(r#type::Ty::False.into())),
            },
            types::Type::Primitive { primitive_type } => match primitive_type {
                types::Primitive::Bool => Self {
                    data: Some(r#type::Data::Ty(r#type::Ty::Bool.into())),
                },
                types::Primitive::Long => Self {
                    data: Some(r#type::Data::Ty(r#type::Ty::Long.into())),
                },
                types::Primitive::String => Self {
                    data: Some(r#type::Data::Ty(r#type::Ty::String.into())),
                },
            },
            types::Type::Set { element_type } => Self {
                data: Some(r#type::Data::SetType(Box::new(Type::from(
                    element_type
                        .as_ref()
                        .expect("element_type field should exist")
                        .as_ref(),
                )))),
            },
            types::Type::EntityOrRecord(er) => Self {
                data: Some(r#type::Data::EntityOrRecord(EntityRecordKind::from(er))),
            },
            types::Type::ExtensionType { name } => Self {
                data: Some(r#type::Data::Name(Name::from(name))),
            },
        }
    }
}

impl From<&Attributes> for types::Attributes {
    fn from(v: &Attributes) -> Self {
        Self::with_attributes(
            v.attrs
                .iter()
                .map(|(k, v)| (k.into(), types::AttributeType::from(v))),
        )
    }
}

impl From<&types::Attributes> for Attributes {
    fn from(v: &types::Attributes) -> Self {
        Self {
            attrs: v
                .iter()
                .map(|(k, v)| (k.to_string(), AttributeType::from(v)))
                .collect(),
        }
    }
}

impl From<&OpenTag> for types::OpenTag {
    fn from(v: &OpenTag) -> Self {
        match v {
            OpenTag::OpenAttributes => types::OpenTag::OpenAttributes,
            OpenTag::ClosedAttributes => types::OpenTag::ClosedAttributes,
        }
    }
}

impl From<&types::OpenTag> for OpenTag {
    fn from(v: &types::OpenTag) -> Self {
        match v {
            types::OpenTag::OpenAttributes => OpenTag::OpenAttributes,
            types::OpenTag::ClosedAttributes => OpenTag::ClosedAttributes,
        }
    }
}

impl From<&EntityRecordKind> for types::EntityRecordKind {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &EntityRecordKind) -> Self {
        match v.data.as_ref().expect("data field should exist") {
            entity_record_kind::Data::Ty(ty) => {
                match entity_record_kind::Ty::try_from(ty.to_owned())
                    .expect("decode should succeed")
                {
                    entity_record_kind::Ty::AnyEntity => Self::AnyEntity,
                }
            }
            entity_record_kind::Data::Record(p_record) => Self::Record {
                attrs: types::Attributes::from(
                    p_record.attrs.as_ref().expect("attrs field should exist"),
                ),
                open_attributes: types::OpenTag::from(
                    &OpenTag::try_from(p_record.open_attributes).expect("decode should succeed"),
                ),
            },
            entity_record_kind::Data::Entity(p_entity) => {
                Self::Entity(types::EntityLUB::single_entity(ast::EntityType::from(
                    p_entity.e.as_ref().expect("e field should exist"),
                )))
            }
            entity_record_kind::Data::ActionEntity(p_action_entity) => Self::ActionEntity {
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

impl From<&types::EntityRecordKind> for EntityRecordKind {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &types::EntityRecordKind) -> Self {
        let data = match v {
            types::EntityRecordKind::Record {
                attrs,
                open_attributes,
            } => entity_record_kind::Data::Record(entity_record_kind::Record {
                attrs: Some(Attributes::from(attrs)),
                open_attributes: OpenTag::from(open_attributes).into(),
            }),
            types::EntityRecordKind::AnyEntity => {
                entity_record_kind::Data::Ty(entity_record_kind::Ty::AnyEntity.into())
            }
            types::EntityRecordKind::Entity(e) => {
                entity_record_kind::Data::Entity(entity_record_kind::Entity {
                    e: Some(EntityType::from(
                        &e.clone()
                            .into_single_entity()
                            .expect("will be single EntityType"),
                    )),
                })
            }
            types::EntityRecordKind::ActionEntity { name, attrs } => {
                entity_record_kind::Data::ActionEntity(entity_record_kind::ActionEntity {
                    name: Some(EntityType::from(name)),
                    attrs: Some(Attributes::from(attrs)),
                })
            }
        };
        Self { data: Some(data) }
    }
}

impl From<&AttributeType> for types::AttributeType {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &AttributeType) -> Self {
        Self {
            attr_type: types::Type::from(
                v.attr_type.as_ref().expect("attr_type field should exist"),
            ),
            is_required: v.is_required,
        }
    }
}

impl From<&types::AttributeType> for AttributeType {
    fn from(v: &types::AttributeType) -> Self {
        Self {
            attr_type: Some(Type::from(&v.attr_type)),
            is_required: v.is_required,
        }
    }
}
