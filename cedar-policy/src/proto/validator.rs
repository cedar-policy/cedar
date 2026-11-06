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
use super::traits::PROST_RECURSION_LIMIT;
use cedar_policy_core::ast::{self, Eid};
use cedar_policy_core::validator::{self, types};
use nonempty::NonEmpty;
use smol_str::SmolStr;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Records shared in `v` (see [`types::SharedRecords`]) are encoded once in
/// `type_defs` and referred to by `type_ref`.
///
/// # Panics
/// If `v` has a type with no protobuf encoding, e.g. `Never` or an open record.
impl From<&validator::ValidatorSchema> for models::Schema {
    fn from(v: &validator::ValidatorSchema) -> Self {
        let mut encoder = TypeEncoder::for_schema(v);
        let entity_decls = v
            .entity_types()
            .map(|ety| encoder.encode_entity_decl(ety))
            .collect();
        let action_decls = v
            .action_ids()
            .map(|action| encoder.encode_action_decl(action))
            .collect();
        Self {
            entity_decls,
            action_decls,
            type_defs: encoder.type_defs,
        }
    }
}

/// Fails if a `type_ref` does not refer to an earlier entry of `type_defs`, or
/// if expanding the `type_ref`s exceeds prost's recursion limit.
impl TryFrom<models::Schema> for validator::ValidatorSchema {
    type Error = ProtobufConversionError;
    fn try_from(v: models::Schema) -> Result<Self, Self::Error> {
        // Prost bounds the depth of the message, not of its expansion.
        if !v.type_defs.is_empty()
            && !super::traits::schema_expansion_within_depth(&v, 1, PROST_RECURSION_LIMIT)
        {
            return Err(ProtobufConversionError::InvalidValue(format!(
                "expanding the `type_ref`s in the schema gives types nested deeper than \
                 {PROST_RECURSION_LIMIT} levels"
            )));
        }
        let mut decoder = TypeDecoder::default();
        for def in v.type_defs {
            // Forward references are out of range here.
            let ty = decoder.decode_type(def)?;
            decoder.type_defs.push(ty);
        }

        let mut entity_type_names: HashSet<ast::EntityType> = HashSet::new();
        let entity_types = v
            .entity_decls
            .into_iter()
            .map(|decl| {
                let ety = decoder.decode_entity_decl(decl)?;
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
                let action = decoder.decode_action_decl(decl)?;
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

struct TypeEncoder<'a> {
    shared: types::SharedRecords<'a>,
    def_index: HashMap<types::RecordId<'a>, u32>,
    /// Children are encoded first, so entries only refer to earlier entries.
    type_defs: Vec<models::Type>,
}

impl<'a> TypeEncoder<'a> {
    /// An encoder that shares nothing, for types outside a `Schema`.
    fn inline() -> Self {
        Self {
            shared: types::SharedRecords::default(),
            def_index: HashMap::new(),
            type_defs: Vec::new(),
        }
    }

    fn for_schema(schema: &'a validator::ValidatorSchema) -> Self {
        Self {
            shared: types::SharedRecords::of_schema(schema),
            ..Self::inline()
        }
    }

    /// # Panics
    /// If `ty` has no protobuf encoding, e.g. `Never` or an open record.
    #[expect(clippy::expect_used, clippy::panic, reason = "experimental feature")]
    fn encode_type(&mut self, ty: &'a types::Type) -> models::Type {
        match ty {
            types::Type::Never => panic!("can't encode Never type in protobuf; Never should never appear in a Schema"),
            types::Type::Bool(types::BoolType::True | types::BoolType::False) => panic!("can't encode singleton boolean type in protobuf; singleton boolean types should never appear in a Schema"),
            types::Type::Bool(types::BoolType::AnyBool) => models::Type {
                data: Some(models::r#type::Data::Prim(models::r#type::Prim::Bool.into())),
            },
            types::Type::Long => models::Type {
                data: Some(models::r#type::Data::Prim(models::r#type::Prim::Long.into())),
            },
            types::Type::String => models::Type {
                data: Some(models::r#type::Data::Prim(models::r#type::Prim::String.into())),
            },
            types::Type::Set { element_type } => models::Type {
                data: Some(models::r#type::Data::SetElem(Box::new(self.encode_type(
                    element_type
                        .as_ref()
                        .expect("can't encode Set without element type in protobuf; Set-without-element-type should never appear in a Schema"),
                )))),
            },
            types::Type::Entity(types::EntityKind::Entity(lub)) => models::Type {
                data: Some(models::r#type::Data::Entity(models::Name::from(lub.get_single_entity().expect("can't encode non-singleton LUB in protobuf; non-singleton LUB types should never appear in a Schema").as_ref()))),
            },
            types::Type::Record { attrs, open_attributes } => {
                assert_eq!(open_attributes, &types::OpenTag::ClosedAttributes, "can't encode open record in protobuf");
                let id = attrs.id();
                if !self.shared.is_shared(attrs) {
                    return models::Type {
                        data: Some(models::r#type::Data::Record(models::r#type::Record { attrs: self.encode_attrs(attrs) })),
                    };
                }
                let index = if let Some(index) = self.def_index.get(&id) {
                    *index
                } else {
                    let def = models::Type {
                        data: Some(models::r#type::Data::Record(models::r#type::Record { attrs: self.encode_attrs(attrs) })),
                    };
                    let index = u32::try_from(self.type_defs.len())
                        .expect("a schema has fewer than 2^32 record types");
                    self.type_defs.push(def);
                    self.def_index.insert(id, index);
                    index
                };
                models::Type {
                    data: Some(models::r#type::Data::TypeRef(index)),
                }
            }
            types::Type::Entity(types::EntityKind::AnyEntity) => panic!("can't encode AnyEntity type in protobuf; AnyEntity should never appear in a Schema"),
            types::Type::ExtensionType { name } => models::Type {
                data: Some(models::r#type::Data::Ext(models::Name::from(name))),
            },
        }
    }

    fn encode_attrs(
        &mut self,
        attrs: &'a types::Attributes,
    ) -> HashMap<String, models::AttributeType> {
        attrs
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    models::AttributeType {
                        attr_type: Some(self.encode_type(&v.attr_type)),
                        is_required: v.is_required,
                    },
                )
            })
            .collect()
    }

    #[expect(clippy::panic, reason = "ValidatorActionId invariant")]
    fn encode_action_decl(&mut self, v: &'a validator::ValidatorActionId) -> models::ActionDecl {
        if v.is_external() {
            return models::ActionDecl {
                name: Some(models::EntityUid::from(v.name())),
                principal_types: vec![],
                resource_types: vec![],
                descendants: v.descendants().map(models::EntityUid::from).collect(),
                context: HashMap::new(),
                external: true,
            };
        }
        let Some(context) = v.context() else {
            panic!("non-external action `{}` has no context type", v.name());
        };
        let ctx_attrs = match context {
            types::Type::Record {
                attrs,
                open_attributes: types::OpenTag::ClosedAttributes,
            } => attrs,
            ty => panic!("expected context to be a closed record, but got {ty:?}"),
        };
        models::ActionDecl {
            name: Some(models::EntityUid::from(v.name())),
            principal_types: v.applies_to_principals().map(models::Name::from).collect(),
            resource_types: v.applies_to_resources().map(models::Name::from).collect(),
            descendants: v.descendants().map(models::EntityUid::from).collect(),
            context: self.encode_attrs(ctx_attrs),
            external: false,
        }
    }

    fn encode_entity_decl(&mut self, v: &'a validator::ValidatorEntityType) -> models::EntityDecl {
        let name = Some(models::Name::from(v.name()));
        let descendants = v.descendants.iter().map(models::Name::from).collect();
        let (attributes, tags, enum_choices, external) = match &v.kind {
            validator::ValidatorEntityTypeKind::Standard(_) => (
                self.encode_attrs(v.attributes()),
                v.tag_type().map(|ty| self.encode_type(ty)),
                vec![],
                false,
            ),
            validator::ValidatorEntityTypeKind::Enum(choices) => (
                self.encode_attrs(v.attributes()),
                v.tag_type().map(|ty| self.encode_type(ty)),
                choices.iter().map(|eid| eid.as_ref().to_string()).collect(),
                false,
            ),
            validator::ValidatorEntityTypeKind::External => (HashMap::new(), None, vec![], true),
        };
        models::EntityDecl {
            name,
            descendants,
            attributes,
            tags,
            enum_choices,
            external,
        }
    }
}

/// Resolves `type_ref`s against the entries of `type_defs` decoded so far.
#[derive(Default)]
struct TypeDecoder {
    type_defs: Vec<types::Type>,
}

impl TypeDecoder {
    fn decode_type(&self, v: models::Type) -> Result<types::Type, ProtobufConversionError> {
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
                element_type: Some(Arc::new(self.decode_type(*elty)?)),
            }),
            models::r#type::Data::Entity(e) => Ok(types::Type::Entity(types::EntityKind::Entity(
                types::EntityLUB::single_entity(ast::EntityType::try_from(e)?),
            ))),
            models::r#type::Data::Record(r) => Ok(types::Type::Record {
                attrs: self.decode_attrs(r.attrs)?,
                open_attributes: types::OpenTag::default(),
            }),
            models::r#type::Data::Ext(name) => Ok(types::Type::ExtensionType {
                name: ast::Name::try_from(name)?,
            }),
            // The clone shares the attribute map.
            models::r#type::Data::TypeRef(index) => usize::try_from(index)
                .ok()
                .and_then(|index| self.type_defs.get(index))
                .cloned()
                .ok_or_else(|| {
                    ProtobufConversionError::InvalidValue(format!(
                        "`type_ref` {index} does not refer to an earlier entry of `type_defs`"
                    ))
                }),
        }
    }

    fn decode_attrs(
        &self,
        v: HashMap<String, models::AttributeType>,
    ) -> Result<types::Attributes, ProtobufConversionError> {
        Ok(types::Attributes::with_attributes(
            v.into_iter()
                .map(|(k, v)| Ok((k.into(), self.decode_attribute_type(v)?)))
                .collect::<Result<Vec<_>, ProtobufConversionError>>()?,
        ))
    }

    fn decode_attribute_type(
        &self,
        v: models::AttributeType,
    ) -> Result<types::AttributeType, ProtobufConversionError> {
        Ok(types::AttributeType {
            attr_type: self
                .decode_type(
                    v.attr_type
                        .ok_or_else(|| ProtobufConversionError::missing("attr_type"))?,
                )?
                .into(),
            is_required: v.is_required,
            #[cfg(feature = "extended-schema")]
            loc: None,
        })
    }

    fn decode_action_decl(
        &self,
        v: models::ActionDecl,
    ) -> Result<validator::ValidatorActionId, ProtobufConversionError> {
        let name = ast::EntityUID::try_from(
            v.name
                .ok_or_else(|| ProtobufConversionError::missing("name"))?,
        )?;
        let descendants = v
            .descendants
            .into_iter()
            .map(ast::EntityUID::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        if v.external {
            if !v.principal_types.is_empty()
                || !v.resource_types.is_empty()
                || !v.context.is_empty()
            {
                return Err(ProtobufConversionError::InvalidValue(format!(
                    "action `{name}` is declared `external`, so it should have no \
                     `principal_types`, `resource_types`, or `context`"
                )));
            }
            return Ok(validator::ValidatorActionId::new_external(
                name,
                descendants,
                None,
            ));
        }
        Ok(validator::ValidatorActionId::new_defined(
            name,
            v.principal_types
                .into_iter()
                .map(ast::EntityType::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            v.resource_types
                .into_iter()
                .map(ast::EntityType::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            descendants,
            types::Type::Record {
                attrs: self.decode_attrs(v.context)?,
                open_attributes: types::OpenTag::default(),
            },
            None,
        ))
    }

    fn decode_entity_decl(
        &self,
        v: models::EntityDecl,
    ) -> Result<validator::ValidatorEntityType, ProtobufConversionError> {
        let name = ast::EntityType::try_from(
            v.name
                .ok_or_else(|| ProtobufConversionError::missing("name"))?,
        )?;
        let descendants = v
            .descendants
            .into_iter()
            .map(ast::EntityType::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        if v.external {
            if !v.attributes.is_empty() || v.tags.is_some() || !v.enum_choices.is_empty() {
                return Err(ProtobufConversionError::InvalidValue(format!(
                    "entity type `{name}` is declared `external`, so it should have no \
                     `attributes`, `tags`, or `enum_choices`"
                )));
            }
            return Ok(validator::ValidatorEntityType::new_external(
                name,
                descendants,
                None,
            ));
        }
        match NonEmpty::collect(v.enum_choices.into_iter().map(SmolStr::from)) {
            // `enum_choices` is empty, so `v` represents a standard entity type
            None => Ok(validator::ValidatorEntityType::new_standard(
                name,
                descendants,
                self.decode_attrs(v.attributes)?,
                types::OpenTag::default(),
                v.tags.map(|ty| self.decode_type(ty)).transpose()?,
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
                    Ok(validator::ValidatorEntityType::new_enum(
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

// Outside a `Schema` there are no `type_defs`: types are encoded inline and
// `type_ref`s are rejected.

/// # Panics
/// If `v` has a type with no protobuf encoding, e.g. an open record.
impl From<&validator::ValidatorActionId> for models::ActionDecl {
    fn from(v: &validator::ValidatorActionId) -> Self {
        TypeEncoder::inline().encode_action_decl(v)
    }
}

impl TryFrom<models::ActionDecl> for validator::ValidatorActionId {
    type Error = ProtobufConversionError;
    fn try_from(v: models::ActionDecl) -> Result<Self, Self::Error> {
        TypeDecoder::default().decode_action_decl(v)
    }
}

/// # Panics
/// If `v` has a type with no protobuf encoding, e.g. an open record.
impl From<&validator::ValidatorEntityType> for models::EntityDecl {
    fn from(v: &validator::ValidatorEntityType) -> Self {
        TypeEncoder::inline().encode_entity_decl(v)
    }
}

impl TryFrom<models::EntityDecl> for validator::ValidatorEntityType {
    type Error = ProtobufConversionError;
    fn try_from(v: models::EntityDecl) -> Result<Self, Self::Error> {
        TypeDecoder::default().decode_entity_decl(v)
    }
}

impl TryFrom<models::Type> for types::Type {
    type Error = ProtobufConversionError;
    fn try_from(v: models::Type) -> Result<Self, Self::Error> {
        TypeDecoder::default().decode_type(v)
    }
}

/// # Panics
/// If `v` has no protobuf encoding, e.g. `Never` or an open record.
impl From<&types::Type> for models::Type {
    fn from(v: &types::Type) -> Self {
        TypeEncoder::inline().encode_type(v)
    }
}

impl TryFrom<models::AttributeType> for types::AttributeType {
    type Error = ProtobufConversionError;
    fn try_from(v: models::AttributeType) -> Result<Self, Self::Error> {
        TypeDecoder::default().decode_attribute_type(v)
    }
}

/// # Panics
/// If `v` has no protobuf encoding, e.g. `Never` or an open record.
impl From<&types::AttributeType> for models::AttributeType {
    fn from(v: &types::AttributeType) -> Self {
        Self {
            attr_type: Some(TypeEncoder::inline().encode_type(&v.attr_type)),
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
            external: false,
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

    /// A declaration is distinct from a definition with no
    /// attributes/`appliesTo`, and the two do not collapse across a round trip.
    #[test]
    fn schema_roundtrip_external_declarations() {
        assert_schema_roundtrip("external entity User;");
        assert_schema_roundtrip("external action audit;");
        assert_schema_roundtrip("external entity User; entity Document { owner: User };");
        assert_schema_roundtrip("external entity Group; external entity User in [Group];");
        assert_schema_roundtrip("action write; external action audit in [write];");
        // `external` as an identifier rather than a keyword is unaffected.
        assert_schema_roundtrip("entity external; entity Foo in [external];");
    }

    #[test]
    fn external_flag_is_exclusive() {
        let bad = models::EntityDecl {
            name: Some(name("Doc")),
            descendants: vec![],
            attributes: Default::default(),
            tags: None,
            enum_choices: vec!["x".into()],
            external: true,
        };
        assert_matches!(
            validator::ValidatorEntityType::try_from(bad),
            Err(ProtobufConversionError::InvalidValue(msg)) => {
                assert_eq!(
                    msg,
                    "entity type `Doc` is declared `external`, so it should have no `attributes`, `tags`, or `enum_choices`"
                );
            }
        );

        let bad = models::ActionDecl {
            name: Some(action_uid("a")),
            descendants: vec![],
            context: Default::default(),
            principal_types: vec![name("Doc")],
            resource_types: vec![],
            external: true,
        };
        assert_matches!(
            validator::ValidatorActionId::try_from(bad),
            Err(ProtobufConversionError::InvalidValue(msg)) => {
                assert_eq!(
                    msg,
                    "action `Action::\"a\"` is declared `external`, so it should have no `principal_types`, `resource_types`, or `context`"
                );
            }
        );
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
            external: false,
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
            external: false,
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
            external: false,
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
            external: false,
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
                external: false,
            }],
            action_decls: vec![],
            type_defs: vec![],
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
                    external: false,
                },
                models::EntityDecl {
                    name: Some(models::Name::from(&d_name)),
                    descendants: vec![models::Name::from(&e_name)],
                    attributes: Default::default(),
                    tags: None,
                    enum_choices: vec![],
                    external: false,
                },
            ],
            action_decls: vec![],
            type_defs: vec![],
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
                    external: false,
                },
                models::EntityDecl {
                    name: Some(models::Name::from(&d_name)),
                    descendants: vec![models::Name::from(&e_name)],
                    attributes: Default::default(),
                    tags: None,
                    enum_choices: vec![],
                    external: false,
                },
            ],
            action_decls: vec![],
            type_defs: vec![],
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
                external: false,
            }],
            type_defs: vec![],
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
            type_defs: vec![],
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
                external: false,
            }],
            action_decls: vec![],
            type_defs: vec![],
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
                external: false,
            }],
            action_decls: vec![],
            type_defs: vec![],
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
                external: false,
            }],
            type_defs: vec![],
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
                external: false,
            }],
            type_defs: vec![],
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
                external: false,
            }],
            type_defs: vec![],
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
            type_defs: vec![],
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
                    external: false,
                },
                models::ActionDecl {
                    name: Some(action_uid("act")),
                    principal_types: vec![name("A")],
                    resource_types: vec![],
                    descendants: vec![],
                    context: Default::default(),
                    external: false,
                },
            ],
            type_defs: vec![],
        };
        assert_matches!(
            ValidatorSchema::try_from(bad),
            Err(ProtobufConversionError::InvalidValue(msg)) if msg.contains("duplicate action")
        );
    }

    /// `T0 = {a: Long}` and `Ti = {a: T(i-1), b: T(i-1)}`.
    fn shared_schema(n: usize) -> ValidatorSchema {
        let mut src = "type T0 = { a: Long };\n".to_string();
        for i in 1..=n {
            src += &format!("type T{i} = {{ a: T{p}, b: T{p} }};\n", p = i - 1);
        }
        src += &format!(
            "entity E {{ x: T{n} }};\n\
             action act appliesTo {{ principal: E, resource: E, context: {{ c: T{n} }} }};\n"
        );
        src.parse().expect("failed to parse cedar schema")
    }

    fn type_ref(index: u32) -> models::Type {
        models::Type {
            data: Some(models::r#type::Data::TypeRef(index)),
        }
    }

    fn long_type() -> models::Type {
        models::Type {
            data: Some(models::r#type::Data::Prim(
                models::r#type::Prim::Long.into(),
            )),
        }
    }

    fn set_type(element: models::Type) -> models::Type {
        models::Type {
            data: Some(models::r#type::Data::SetElem(Box::new(element))),
        }
    }

    fn entity_decl_with_attr(ty: models::Type) -> models::EntityDecl {
        models::EntityDecl {
            attributes: [(
                "x".to_string(),
                models::AttributeType {
                    attr_type: Some(ty),
                    is_required: true,
                },
            )]
            .into(),
            ..simple_entity_decl("E")
        }
    }

    #[test]
    fn shared_schema_encodes_linearly_and_roundtrips() {
        use prost::Message;
        // The largest `n` that fits in `MAX_ENCODE_DEPTH`.
        let n = 20;
        let schema = shared_schema(n);
        let encoded = models::Schema::from(&schema);
        assert_eq!(encoded.type_defs.len(), n + 1);
        let bytes = encoded.encode_to_vec();
        assert!(bytes.len() < 100 * n, "{} bytes", bytes.len());

        let decoded =
            ValidatorSchema::try_from(models::Schema::decode(&bytes[..]).unwrap()).unwrap();
        assert_eq!(decoded, schema);
        assert_eq!(models::Schema::from(&decoded).type_defs.len(), n + 1);
    }

    #[test]
    fn shared_context_is_encoded_once() {
        use prost::Message;
        let (k, w) = (50, 50);
        let mut src = "entity E;\ntype Ctx = {\n".to_string();
        for i in 0..w {
            src += &format!("  f{i}: {{ x: Long, y: String }},\n");
        }
        src += "};\naction ";
        src += &(0..k)
            .map(|i| format!("a{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        src += " appliesTo { principal: E, resource: E, context: Ctx };\n";
        let schema: ValidatorSchema = src.parse().unwrap();
        let encoded = models::Schema::from(&schema);
        assert_eq!(encoded.type_defs.len(), w);
        // Each action has `w` references, and the records are encoded once.
        let bytes = encoded.encode_to_vec();
        assert!(bytes.len() < 20 * k * w, "{} bytes", bytes.len());
        assert_eq!(
            ValidatorSchema::try_from(models::Schema::decode(&bytes[..]).unwrap()).unwrap(),
            schema
        );
    }

    #[test]
    fn unshared_schema_has_no_type_defs() {
        let schema: ValidatorSchema = "type T = { a: Long }; entity E { x: T, y: { b: Long } };"
            .parse()
            .unwrap();
        assert!(models::Schema::from(&schema).type_defs.is_empty());
        let schema: ValidatorSchema = "type T = { a: Long }; entity E { x: T }; entity F { y: T };"
            .parse()
            .unwrap();
        assert_eq!(models::Schema::from(&schema).type_defs.len(), 1);
    }

    #[test]
    fn type_ref_must_refer_backwards() {
        let bad = models::Schema {
            entity_decls: vec![entity_decl_with_attr(type_ref(0))],
            action_decls: vec![],
            type_defs: vec![set_type(type_ref(0))],
        };
        assert_matches!(
            ValidatorSchema::try_from(bad),
            Err(ProtobufConversionError::InvalidValue(msg)) if msg.contains("`type_ref` 0")
        );
        let bad = models::Schema {
            entity_decls: vec![entity_decl_with_attr(type_ref(1))],
            action_decls: vec![],
            type_defs: vec![long_type()],
        };
        assert_matches!(
            ValidatorSchema::try_from(bad),
            Err(ProtobufConversionError::InvalidValue(msg)) if msg.contains("`type_ref` 1")
        );
        assert_matches!(
            Type::try_from(type_ref(0)),
            Err(ProtobufConversionError::InvalidValue(_))
        );
        let good = models::Schema {
            entity_decls: vec![entity_decl_with_attr(type_ref(1))],
            action_decls: vec![],
            type_defs: vec![long_type(), set_type(type_ref(0))],
        };
        let schema = ValidatorSchema::try_from(good).unwrap();
        let expected: ValidatorSchema = "entity E { x: Set<Long> };".parse().unwrap();
        assert_eq!(schema, expected);
    }

    #[test]
    fn expansion_depth_is_bounded() {
        use super::super::traits::{EncodeCheck, EncodeError};
        // `type_defs[i]` is 10 sets around `type_defs[i - 1]`.
        let defs = |k: usize| {
            let mut defs = vec![long_type()];
            for i in 1..k {
                let mut ty = type_ref(u32::try_from(i - 1).unwrap());
                for _ in 0..10 {
                    ty = set_type(ty);
                }
                defs.push(ty);
            }
            defs
        };
        let schema = |k: usize| models::Schema {
            entity_decls: vec![entity_decl_with_attr(type_ref(
                u32::try_from(k - 1).unwrap(),
            ))],
            action_decls: vec![],
            type_defs: defs(k),
        };
        // An attribute type starts at depth 6.
        assert!(ValidatorSchema::try_from(schema(10)).is_ok());
        assert_matches!(
            ValidatorSchema::try_from(schema(11)),
            Err(ProtobufConversionError::InvalidValue(msg)) if msg.contains("nested deeper")
        );

        assert!(models::Schema::from(&shared_schema(20))
            .check_for_encode()
            .is_ok());
        assert_matches!(
            models::Schema::from(&shared_schema(21)).check_for_encode(),
            Err(EncodeError::MaxDepthExceeded)
        );
    }
}
