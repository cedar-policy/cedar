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

#![allow(clippy::use_self, reason = "readability")]

use super::ast::ProtobufConversionError;
use super::models;
use cedar_policy_core::ast::{self, Eid};
use cedar_policy_core::validator::{self, types};
use nonempty::NonEmpty;
use smol_str::SmolStr;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

impl From<&validator::ValidatorSchema> for models::Schema {
    fn from(v: &validator::ValidatorSchema) -> Self {
        Self {
            entity_decls: v.entity_types().map(models::EntityDecl::from).collect(),
            action_decls: v.action_ids().map(models::ActionDecl::from).collect(),
        }
    }
}

impl TryFrom<models::Schema> for validator::ValidatorSchema {
    type Error = ProtobufConversionError;
    fn try_from(v: models::Schema) -> Result<Self, Self::Error> {
        let mut entity_type_names: HashSet<ast::EntityType> = HashSet::new();
        let entity_types = v
            .entity_decls
            .into_iter()
            .map(|decl| {
                let ety = validator::ValidatorEntityType::try_from(decl)?;
                if !entity_type_names.insert(ety.name().clone()) {
                    return Err(ProtobufConversionError::InvalidValue(format!(
                        "duplicate entity type `{}` in `entity_decls`",
                        ety.name()
                    )));
                }
                Ok(ety)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut action_names: HashSet<ast::EntityUID> = HashSet::new();
        let action_ids = v
            .action_decls
            .into_iter()
            .map(|decl| {
                let action = validator::ValidatorActionId::try_from(decl)?;
                if !action_names.insert(action.name().clone()) {
                    return Err(ProtobufConversionError::InvalidValue(format!(
                        "duplicate action `{}` in `action_decls`",
                        action.name()
                    )));
                }
                Ok(action)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self::new(entity_types, action_ids))
    }
}

impl From<&validator::ValidationMode> for models::ValidationMode {
    fn from(v: &validator::ValidationMode) -> Self {
        match v {
            validator::ValidationMode::Strict => models::ValidationMode::Strict,
            validator::ValidationMode::Permissive => models::ValidationMode::Permissive,
            #[cfg(feature = "partial-validate")]
            validator::ValidationMode::Partial => models::ValidationMode::Partial,
        }
    }
}

impl TryFrom<models::ValidationMode> for validator::ValidationMode {
    type Error = ProtobufConversionError;
    fn try_from(v: models::ValidationMode) -> Result<Self, Self::Error> {
        match v {
            models::ValidationMode::Strict => Ok(validator::ValidationMode::Strict),
            models::ValidationMode::Permissive => Ok(validator::ValidationMode::Permissive),
            #[cfg(feature = "partial-validate")]
            models::ValidationMode::Partial => Ok(validator::ValidationMode::Partial),
            #[cfg(not(feature = "partial-validate"))]
            models::ValidationMode::Partial => Err(ProtobufConversionError::missing(
                "partial-validate feature (required for partial validation mode)",
            )),
        }
    }
}

#[expect(clippy::fallible_impl_from, reason = "experimental feature")]
impl From<&validator::ValidatorActionId> for models::ActionDecl {
    #[expect(clippy::panic, reason = "experimental feature")]
    fn from(v: &validator::ValidatorActionId) -> Self {
        let ctx_attrs = match v.context() {
            types::Type::Record {
                attrs,
                open_attributes: types::OpenTag::ClosedAttributes,
            } => attrs,
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

impl TryFrom<models::ActionDecl> for validator::ValidatorActionId {
    type Error = ProtobufConversionError;
    fn try_from(v: models::ActionDecl) -> Result<Self, Self::Error> {
        Ok(Self::new(
            ast::EntityUID::try_from(
                v.name
                    .ok_or_else(|| ProtobufConversionError::missing("name"))?,
            )?,
            v.principal_types
                .into_iter()
                .map(ast::EntityType::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            v.resource_types
                .into_iter()
                .map(ast::EntityType::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            v.descendants
                .into_iter()
                .map(ast::EntityUID::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            types::Type::Record {
                attrs: model_to_attributes(v.context)?,
                open_attributes: types::OpenTag::default(),
            },
            None,
        ))
    }
}

impl From<&validator::ValidatorEntityType> for models::EntityDecl {
    fn from(v: &validator::ValidatorEntityType) -> Self {
        let name = Some(models::Name::from(v.name()));
        let descendants = v.descendants.iter().map(models::Name::from).collect();
        let attributes = attributes_to_model(v.attributes());
        let tags = v.tag_type().map(models::Type::from);
        match &v.kind {
            validator::ValidatorEntityTypeKind::Standard(_) => Self {
                name,
                descendants,
                attributes,
                tags,
                enum_choices: vec![],
            },
            validator::ValidatorEntityTypeKind::Enum(enum_choices) => Self {
                name,
                descendants,
                attributes,
                tags,
                enum_choices: enum_choices
                    .into_iter()
                    .map(|eid| eid.as_ref().to_string())
                    .collect(),
            },
        }
    }
}

impl TryFrom<models::EntityDecl> for validator::ValidatorEntityType {
    type Error = ProtobufConversionError;
    fn try_from(v: models::EntityDecl) -> Result<Self, Self::Error> {
        let name = ast::EntityType::try_from(
            v.name
                .ok_or_else(|| ProtobufConversionError::missing("name"))?,
        )?;
        let descendants = v
            .descendants
            .into_iter()
            .map(ast::EntityType::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        match NonEmpty::collect(v.enum_choices.into_iter().map(SmolStr::from)) {
            // `enum_choices` is empty, so `v` represents a standard entity type
            None => Ok(Self::new_standard(
                name,
                descendants,
                model_to_attributes(v.attributes)?,
                types::OpenTag::default(),
                v.tags.map(types::Type::try_from).transpose()?,
                None,
            )),
            Some(enum_choices) => {
                // `enum_choices` is not empty, so `v` represents an enumerated entity type.
                // enumerated entity types must have no attributes or tags.
                if !v.attributes.is_empty() {
                    Err(ProtobufConversionError::InvalidValue(format!(
                        "enum type {name} should not have attributes"
                    )))
                } else if v.tags.is_some() {
                    Err(ProtobufConversionError::InvalidValue(format!(
                        "enum type {name} should not have tags"
                    )))
                } else {
                    Ok(Self::new_enum(
                        name,
                        descendants,
                        enum_choices.map(Eid::new),
                        None,
                    ))
                }
            }
        }
    }
}

impl TryFrom<models::Type> for types::Type {
    type Error = ProtobufConversionError;
    fn try_from(v: models::Type) -> Result<Self, Self::Error> {
        match v
            .data
            .ok_or_else(|| ProtobufConversionError::missing("data"))?
        {
            models::r#type::Data::Prim(vt) => {
                match models::r#type::Prim::try_from(vt).map_err(|e| {
                    ProtobufConversionError::missing(&format!("valid prim variant: {e}"))
                })? {
                    models::r#type::Prim::Bool => Ok(types::Type::primitive_boolean()),
                    models::r#type::Prim::String => Ok(types::Type::primitive_string()),
                    models::r#type::Prim::Long => Ok(types::Type::primitive_long()),
                }
            }
            models::r#type::Data::SetElem(elty) => Ok(types::Type::Set {
                element_type: Some(Arc::new(types::Type::try_from(*elty)?)),
            }),
            models::r#type::Data::Entity(e) => Ok(types::Type::Entity(types::EntityKind::Entity(
                types::EntityLUB::single_entity(ast::EntityType::try_from(e)?),
            ))),
            models::r#type::Data::Record(r) => Ok(types::Type::Record {
                attrs: model_to_attributes(r.attrs)?,
                open_attributes: types::OpenTag::default(),
            }),
            models::r#type::Data::Ext(name) => Ok(types::Type::ExtensionType {
                name: ast::Name::try_from(name)?,
            }),
        }
    }
}

#[expect(clippy::fallible_impl_from, reason = "experimental feature")]
impl From<&types::Type> for models::Type {
    #[expect(clippy::expect_used, clippy::panic, reason = "experimental feature")]
    fn from(v: &types::Type) -> Self {
        match v {
            types::Type::Never => panic!("can't encode Never type in protobuf; Never should never appear in a Schema"),
            types::Type::Bool(types::BoolType::True | types::BoolType::False) => panic!("can't encode singleton boolean type in protobuf; singleton boolean types should never appear in a Schema"),
            types::Type::Bool(types::BoolType::AnyBool) => Self {
                data: Some(models::r#type::Data::Prim(models::r#type::Prim::Bool.into())),
            },
            types::Type::Long => Self {
                data: Some(models::r#type::Data::Prim(models::r#type::Prim::Long.into())),
            },
            types::Type::String => Self {
                data: Some(models::r#type::Data::Prim(models::r#type::Prim::String.into())),
            },
            types::Type::Set { element_type } => Self {
                data: Some(models::r#type::Data::SetElem(Box::new(models::Type::from(
                    element_type
                        .as_ref()
                        .expect("can't encode Set without element type in protobuf; Set-without-element-type should never appear in a Schema")
                        .as_ref(),
                )))),
            },
            types::Type::Entity(types::EntityKind::Entity(lub)) => Self {
                data: Some(models::r#type::Data::Entity(models::Name::from(lub.get_single_entity().expect("can't encode non-singleton LUB in protobuf; non-singleton LUB types should never appear in a Schema").as_ref()))),
            },
            types::Type::Record{ attrs, open_attributes } => {
                assert_eq!(open_attributes, &types::OpenTag::ClosedAttributes, "can't encode open record in protobuf");
                Self {
                    data: Some(models::r#type::Data::Record(models::r#type::Record { attrs: attributes_to_model(attrs) })),
                }
            }
            types::Type::Entity(types::EntityKind::AnyEntity) => panic!("can't encode AnyEntity type in protobuf; AnyEntity should never appear in a Schema"),
            types::Type::ExtensionType { name } => Self {
                data: Some(models::r#type::Data::Ext(models::Name::from(name))),
            },
        }
    }
}

fn model_to_attributes(
    v: HashMap<String, models::AttributeType>,
) -> Result<types::Attributes, ProtobufConversionError> {
    Ok(types::Attributes::with_attributes(
        v.into_iter()
            .map(|(k, v)| Ok((k.into(), types::AttributeType::try_from(v)?)))
            .collect::<Result<Vec<_>, ProtobufConversionError>>()?,
    ))
}

fn attributes_to_model(v: &types::Attributes) -> HashMap<String, models::AttributeType> {
    v.iter()
        .map(|(k, v)| (k.to_string(), models::AttributeType::from(v)))
        .collect()
}

impl TryFrom<models::AttributeType> for types::AttributeType {
    type Error = ProtobufConversionError;
    fn try_from(v: models::AttributeType) -> Result<Self, Self::Error> {
        Ok(Self {
            attr_type: types::Type::try_from(
                v.attr_type
                    .ok_or_else(|| ProtobufConversionError::missing("attr_type"))?,
            )?
            .into(),
            is_required: v.is_required,
            #[cfg(feature = "extended-schema")]
            loc: None,
        })
    }
}

impl From<&types::AttributeType> for models::AttributeType {
    fn from(v: &types::AttributeType) -> Self {
        Self {
            attr_type: Some(models::Type::from(v.attr_type.as_ref())),
            is_required: v.is_required,
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::models;
    use super::ProtobufConversionError;
    use cedar_policy_core::validator::{
        self,
        types::{AttributeType, BoolType, EntityKind, EntityLUB, OpenTag, Type},
        SchemaError, ValidatorSchema,
    };
    use cool_asserts::assert_matches;
    use similar_asserts::assert_eq;

    /// Helper: create a simple entity decl with no descendants, attributes, or tags.
    fn simple_entity_decl(name: &str) -> models::EntityDecl {
        let n: cedar_policy_core::ast::Name = name.parse().unwrap();
        models::EntityDecl {
            name: Some(models::Name::from(&n)),
            descendants: vec![],
            attributes: Default::default(),
            tags: None,
            enum_choices: vec![],
        }
    }

    /// Helper: create a models::Name from a string.
    fn name(s: &str) -> models::Name {
        let n: cedar_policy_core::ast::Name = s.parse().unwrap();
        models::Name::from(&n)
    }

    /// Helper: create a models::EntityUid for an action.
    fn action_uid(eid: &str) -> models::EntityUid {
        let uid = cedar_policy_core::ast::EntityUID::with_eid_and_type("Action", eid).unwrap();
        models::EntityUid::from(&uid)
    }

    #[test]
    fn type_roundtrip() {
        #[track_caller]
        fn assert_type_roundtrip(ty: Type) {
            assert_eq!(ty, Type::try_from(models::Type::from(&ty)).unwrap());
        }

        assert_type_roundtrip(Type::Bool(BoolType::AnyBool));
        assert_type_roundtrip(Type::Long);
        assert_type_roundtrip(Type::String);
        assert_type_roundtrip(Type::Entity(EntityKind::Entity(EntityLUB::single_entity(
            "User".parse().unwrap(),
        ))));
        assert_type_roundtrip(Type::set(Arc::new(Type::Long)));
        assert_type_roundtrip(Type::record_with_attributes(
            None,
            OpenTag::ClosedAttributes,
        ));
        assert_type_roundtrip(Type::ExtensionType {
            name: "decimal".parse().unwrap(),
        });
        assert_type_roundtrip(Type::record_with_attributes(
            [(
                "a".into(),
                AttributeType::optional_attribute(Arc::new(Type::String)),
            )],
            OpenTag::ClosedAttributes,
        ));
        assert_type_roundtrip(Type::record_with_attributes(
            [(
                "a".into(),
                AttributeType::required_attribute(Arc::new(Type::String)),
            )],
            OpenTag::ClosedAttributes,
        ));
        assert_type_roundtrip(Type::record_with_attributes(
            [
                (
                    "".into(),
                    AttributeType::required_attribute(Arc::new(Type::String)),
                ),
                (
                    "\0".into(),
                    AttributeType::required_attribute(Arc::new(Type::String)),
                ),
                (
                    r#"\0"#.into(),
                    AttributeType::required_attribute(Arc::new(Type::String)),
                ),
                (
                    "\n".into(),
                    AttributeType::required_attribute(Arc::new(Type::String)),
                ),
                (
                    "🐈".into(),
                    AttributeType::required_attribute(Arc::new(Type::String)),
                ),
            ],
            OpenTag::ClosedAttributes,
        ));
    }

    #[track_caller]
    fn assert_schema_roundtrip(src: &str) {
        let schema: ValidatorSchema = src.parse().expect("failed to parse cedar schema");
        assert_eq!(
            schema,
            ValidatorSchema::try_from(models::Schema::from(&schema)).unwrap()
        );
    }

    #[test]
    fn schema_roundtrip_empty() {
        assert_schema_roundtrip("");
    }

    #[test]
    fn schema_roundtrip_entities() {
        assert_schema_roundtrip("entity User;");
        assert_schema_roundtrip("entity Group; entity User in [Group];");
        assert_schema_roundtrip("entity User { foo : Long };");
        assert_schema_roundtrip("entity User tags String;");
        assert_schema_roundtrip(r#"entity User enum ["0"];"#);
        assert_schema_roundtrip(r#"entity User enum ["", "\0", "🐈"];"#);
        assert_schema_roundtrip(r#"entity E enum ["0"]; entity D in E;"#);
    }

    #[test]
    fn schema_roundtrip_actions() {
        assert_schema_roundtrip("action a;");
        assert_schema_roundtrip(r#"action "\0", "", "🐈";"#);
        assert_schema_roundtrip("action a; action b in [a];");
        assert_schema_roundtrip(r#"action "🐈"; action a in ["🐈"];"#);
        assert_schema_roundtrip(
            "entity E0, E1; action a appliesTo { principal: E0, resource: E1};",
        );
        assert_schema_roundtrip(
            "entity E0, E1; action a appliesTo { principal: [E0, E1], resource: [E0, E1]};",
        );
        assert_schema_roundtrip("entity E0, E1; action a appliesTo { principal: E0, resource: E1, context: { foo: String } };");
    }

    #[test]
    fn schema_roundtrip_namespace() {
        assert_schema_roundtrip("namespace n { entity E; }");
        assert_schema_roundtrip("namespace n { action A; }");
    }

    #[test]
    fn schema_roundtrip_complex() {
        assert_schema_roundtrip(
            r#"
        entity Doc;
        namespace Foo::Bar::Baz {
          entity Group enum ["admin"];
          entity User in [Group] { name: String };
        }
        namespace Other {
          action Act in [Another::Action::"Do"] appliesTo {
            principal: [Foo::Bar::Baz::User],
            resource: Doc
          };
        }
        namespace Another {
          action Do;
        }"#,
        );
    }

    #[test]
    fn validation_mode_roundtrip() {
        use validator::ValidationMode;
        assert_eq!(
            ValidationMode::Strict,
            ValidationMode::try_from(models::ValidationMode::from(&ValidationMode::Strict))
                .unwrap()
        );
        assert_eq!(
            ValidationMode::Permissive,
            ValidationMode::try_from(models::ValidationMode::from(&ValidationMode::Permissive))
                .unwrap()
        );
    }

    #[test]
    fn action_decl_try_from_missing_name() {
        let bad = models::ActionDecl {
            name: None,
            principal_types: vec![],
            resource_types: vec![],
            descendants: vec![],
            context: Default::default(),
        };
        assert_matches!(
            validator::ValidatorActionId::try_from(bad),
            Err(ProtobufConversionError::MissingField(f)) if f == "name"
        );
    }

    #[test]
    fn entity_decl_try_from_missing_name() {
        let bad = models::EntityDecl {
            name: None,
            descendants: vec![],
            attributes: Default::default(),
            tags: None,
            enum_choices: vec![],
        };
        assert_matches!(
            validator::ValidatorEntityType::try_from(bad),
            Err(ProtobufConversionError::MissingField(f)) if f == "name"
        );
    }

    #[test]
    fn type_try_from_missing_data() {
        let bad = models::Type { data: None };
        assert_matches!(
            Type::try_from(bad),
            Err(ProtobufConversionError::MissingField(f)) if f == "data"
        );
    }

    #[test]
    fn attribute_type_try_from_missing_attr_type() {
        let bad = models::AttributeType {
            attr_type: None,
            is_required: true,
        };
        assert_matches!(
            validator::types::AttributeType::try_from(bad),
            Err(ProtobufConversionError::MissingField(f)) if f == "attr_type"
        );
    }

    #[test]
    fn entity_decl_enum_with_attributes() {
        let name: cedar_policy_core::ast::Name = "Foo".parse().unwrap();
        let bad = models::EntityDecl {
            name: Some(models::Name::from(&name)),
            descendants: vec![],
            attributes: [(
                "a".to_string(),
                models::AttributeType {
                    attr_type: Some(models::Type {
                        data: Some(models::r#type::Data::Prim(
                            models::r#type::Prim::Long.into(),
                        )),
                    }),
                    is_required: true,
                },
            )]
            .into(),
            tags: None,
            enum_choices: vec!["x".to_string()],
        };
        assert_matches!(
            validator::ValidatorEntityType::try_from(bad),
            Err(ProtobufConversionError::InvalidValue(msg)) if msg.contains("should not have attributes")
        );
    }

    #[test]
    fn entity_decl_enum_with_tags() {
        let name: cedar_policy_core::ast::Name = "Foo".parse().unwrap();
        let bad = models::EntityDecl {
            name: Some(models::Name::from(&name)),
            descendants: vec![],
            attributes: Default::default(),
            tags: Some(models::Type {
                data: Some(models::r#type::Data::Prim(
                    models::r#type::Prim::String.into(),
                )),
            }),
            enum_choices: vec!["x".to_string()],
        };
        assert_matches!(
            validator::ValidatorEntityType::try_from(bad),
            Err(ProtobufConversionError::InvalidValue(msg)) if msg.contains("should not have tags")
        );
    }

    fn validator_try_from_ok_return_validate(
        schema: models::Schema,
    ) -> Result<ValidatorSchema, SchemaError> {
        ValidatorSchema::try_from(schema).unwrap().try_validate()
    }

    #[test]
    fn schema_try_from_invalid_entity_decl() {
        let bad = models::Schema {
            entity_decls: vec![models::EntityDecl {
                name: None,
                descendants: vec![],
                attributes: Default::default(),
                tags: None,
                enum_choices: vec![],
            }],
            action_decls: vec![],
        };
        assert_matches!(
            ValidatorSchema::try_from(bad),
            Err(ProtobufConversionError::MissingField(f)) if f == "name"
        );
    }

    #[test]
    fn schema_try_from_invalid_entity_hierarchy() {
        // The Cedar schema: entity E enum ["0"] in D;  entity D; should not decode.
        // But modelled as "entity E enum ["0"]; entity D has_descendant E; it decodes.
        let e_name: cedar_policy_core::ast::Name = "E".parse().unwrap();
        let d_name: cedar_policy_core::ast::Name = "D".parse().unwrap();
        let bad = models::Schema {
            entity_decls: vec![
                models::EntityDecl {
                    name: Some(models::Name::from(&e_name)),
                    descendants: vec![],
                    attributes: Default::default(),
                    tags: None,
                    enum_choices: vec!["0".to_string()],
                },
                models::EntityDecl {
                    name: Some(models::Name::from(&d_name)),
                    descendants: vec![models::Name::from(&e_name)],
                    attributes: Default::default(),
                    tags: None,
                    enum_choices: vec![],
                },
            ],
            action_decls: vec![],
        };
        // Schema validation rejects enum entities as descendants of other entities.
        assert_matches!(
            validator_try_from_ok_return_validate(bad),
            Err(SchemaError::EnumEntityInHierarchy(_))
        );
    }

    #[test]
    fn schema_try_from_has_undeclared_entity() {
        // The schema has an undeclared entity
        let e_name: cedar_policy_core::ast::Name = "E".parse().unwrap();
        let c_name: cedar_policy_core::ast::Name = "D".parse().unwrap();
        let d_name: cedar_policy_core::ast::Name = "C".parse().unwrap();
        let bad = models::Schema {
            entity_decls: vec![
                models::EntityDecl {
                    name: Some(models::Name::from(&c_name)),
                    descendants: vec![],
                    attributes: Default::default(),
                    tags: None,
                    enum_choices: vec!["0".to_string()],
                },
                models::EntityDecl {
                    name: Some(models::Name::from(&d_name)),
                    descendants: vec![models::Name::from(&e_name)],
                    attributes: Default::default(),
                    tags: None,
                    enum_choices: vec![],
                },
            ],
            action_decls: vec![],
        };
        // Schema validation rejects undeclared entity types in descendants.
        assert_matches!(
            validator_try_from_ok_return_validate(bad),
            Err(SchemaError::UndeclaredEntityTypes(_))
        );
    }

    #[test]
    fn schema_try_from_undeclared_principal_type() {
        // Action references an entity type that is not declared
        let bad = models::Schema {
            entity_decls: vec![],
            action_decls: vec![models::ActionDecl {
                name: Some(action_uid("act")),
                principal_types: vec![name("A")],
                resource_types: vec![],
                descendants: vec![],
                context: Default::default(),
            }],
        };
        assert_matches!(
            validator_try_from_ok_return_validate(bad),
            Err(SchemaError::UndeclaredEntityTypes(_))
        );
    }

    #[test]
    fn schema_try_from_shadowing_entity_types() {
        // Entity type `r::r` shadows unqualified entity type `r` (RFC 70)
        let bad = models::Schema {
            entity_decls: vec![simple_entity_decl("r"), simple_entity_decl("r::r")],
            action_decls: vec![],
        };
        assert_matches!(
            validator_try_from_ok_return_validate(bad),
            Err(SchemaError::TypeShadowing(_))
        );
    }

    #[test]
    fn schema_try_from_undeclared_entity_in_attribute() {
        // Entity type `A` has an attribute referencing undeclared entity type `B::B::B`
        let bad = models::Schema {
            entity_decls: vec![models::EntityDecl {
                name: Some(name("A")),
                descendants: vec![],
                attributes: [(
                    "attr".to_string(),
                    models::AttributeType {
                        attr_type: Some(models::Type {
                            data: Some(models::r#type::Data::Entity(name("B::B::B"))),
                        }),
                        is_required: false,
                    },
                )]
                .into(),
                tags: None,
                enum_choices: vec![],
            }],
            action_decls: vec![],
        };
        assert_matches!(
            validator_try_from_ok_return_validate(bad),
            Err(SchemaError::UndeclaredEntityTypes(_))
        );
    }

    #[test]
    fn schema_try_from_unknown_extension_type_in_tags() {
        // Entity type `A` has tags with unknown extension type `q`
        let bad = models::Schema {
            entity_decls: vec![models::EntityDecl {
                name: Some(name("A")),
                descendants: vec![],
                attributes: Default::default(),
                tags: Some(models::Type {
                    data: Some(models::r#type::Data::Ext(name("q"))),
                }),
                enum_choices: vec![],
            }],
            action_decls: vec![],
        };
        assert_matches!(
            validator_try_from_ok_return_validate(bad),
            Err(SchemaError::UnknownExtensionType(_))
        );
    }

    #[test]
    fn schema_try_from_action_hierarchy_cycle() {
        // Action lists itself as a descendant (cycle)
        let bad = models::Schema {
            entity_decls: vec![simple_entity_decl("A")],
            action_decls: vec![models::ActionDecl {
                name: Some(action_uid("")),
                principal_types: vec![name("A")],
                resource_types: vec![name("A")],
                descendants: vec![action_uid("")],
                context: Default::default(),
            }],
        };
        assert_matches!(
            validator_try_from_ok_return_validate(bad),
            Err(SchemaError::CycleInActionHierarchy(_))
        );
    }

    #[test]
    fn schema_try_from_undeclared_action_descendant() {
        // Action references an undeclared action as a descendant
        let bad = models::Schema {
            entity_decls: vec![simple_entity_decl("A")],
            action_decls: vec![models::ActionDecl {
                name: Some(action_uid("act")),
                principal_types: vec![name("A")],
                resource_types: vec![name("A")],
                descendants: vec![action_uid("nonexistent")],
                context: Default::default(),
            }],
        };
        assert_matches!(
            validator_try_from_ok_return_validate(bad),
            Err(SchemaError::UndeclaredActionDescendants(_))
        );
    }

    #[test]
    fn schema_try_from_invalid_action_entity_type() {
        // Action with entity type `h` (basename is not `Action`)
        let bad_uid = cedar_policy_core::ast::EntityUID::with_eid_and_type("h", "act").unwrap();
        let bad = models::Schema {
            entity_decls: vec![simple_entity_decl("A")],
            action_decls: vec![models::ActionDecl {
                name: Some(models::EntityUid::from(&bad_uid)),
                principal_types: vec![name("A")],
                resource_types: vec![name("A")],
                descendants: vec![],
                context: Default::default(),
            }],
        };
        assert_matches!(
            validator_try_from_ok_return_validate(bad),
            Err(SchemaError::InvalidActionType(_))
        );
    }

    #[test]
    fn schema_try_from_duplicate_entity_type() {
        let bad = models::Schema {
            entity_decls: vec![simple_entity_decl("A"), simple_entity_decl("A")],
            action_decls: vec![],
        };
        assert_matches!(
            ValidatorSchema::try_from(bad),
            Err(ProtobufConversionError::InvalidValue(msg)) if msg.contains("duplicate entity type")
        );
    }

    #[test]
    fn schema_try_from_duplicate_action() {
        let bad = models::Schema {
            entity_decls: vec![simple_entity_decl("A")],
            action_decls: vec![
                models::ActionDecl {
                    name: Some(action_uid("act")),
                    principal_types: vec![name("A")],
                    resource_types: vec![name("A")],
                    descendants: vec![],
                    context: Default::default(),
                },
                models::ActionDecl {
                    name: Some(action_uid("act")),
                    principal_types: vec![name("A")],
                    resource_types: vec![],
                    descendants: vec![],
                    context: Default::default(),
                },
            ],
        };
        assert_matches!(
            ValidatorSchema::try_from(bad),
            Err(ProtobufConversionError::InvalidValue(msg)) if msg.contains("duplicate action")
        );
    }
}
