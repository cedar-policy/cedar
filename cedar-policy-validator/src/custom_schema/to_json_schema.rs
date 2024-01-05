use std::collections::{HashMap, HashSet};

use cedar_policy_core::{
    ast::{Id, Name},
    parser::Node,
};
use itertools::Either;
use nonempty::NonEmpty;
use smol_str::SmolStr;

use crate::{
    ActionEntityUID, ActionType, ApplySpec, AttributesOrContext, EntityType, NamespaceDefinition,
    SchemaFragment, SchemaType, SchemaTypeVariant, TypeOfAttribute,
};

use super::{
    ast::{
        ActionDecl, AppDecl, AttrDecl, Declaration, EntityDecl, Namespace, PRAppDecl, Path, Ref,
        Schema, Str, Type, PR,
    },
    err::ToValidatorSchemaError,
};

#[derive(Debug, Clone)]
pub struct Context {
    pub common_types: HashSet<Name>,
    pub entity_types: HashSet<Name>,
}
#[derive(Debug, Clone)]
pub enum PrimitiveType {
    Bool,
    Long,
    String,
}
#[derive(Debug, Clone)]
pub enum NamedType {
    Common(SmolStr),
    Entity(SmolStr),
    Extension(SmolStr),
    Primitive(PrimitiveType),
}

impl From<NamedType> for SchemaType {
    fn from(value: NamedType) -> Self {
        match value {
            NamedType::Common(type_name) => Self::TypeDef { type_name },
            NamedType::Entity(name) => Self::Type(SchemaTypeVariant::Entity { name }),
            NamedType::Extension(name) => Self::Type(SchemaTypeVariant::Extension { name }),
            NamedType::Primitive(PrimitiveType::Bool) => Self::Type(SchemaTypeVariant::Boolean),
            NamedType::Primitive(PrimitiveType::Long) => Self::Type(SchemaTypeVariant::Long),
            NamedType::Primitive(PrimitiveType::String) => Self::Type(SchemaTypeVariant::String),
        }
    }
}

impl Context {
    pub fn lookup(&self, node: &Path) -> Option<NamedType> {
        let name = <Path as Into<Name>>::into(node.clone());
        if node.is_decimal_extension() || node.is_ipaddr_extension() {
            Some(NamedType::Extension(node.base.node.clone().to_smolstr()))
        } else if node.is_builtin_bool() {
            Some(NamedType::Primitive(PrimitiveType::Bool))
        } else if node.is_builtin_long() {
            Some(NamedType::Primitive(PrimitiveType::Long))
        } else if node.is_builtin_string() {
            Some(NamedType::Primitive(PrimitiveType::String))
        } else if self.common_types.contains(&name) {
            Some(NamedType::Common(node.clone().to_smolstr()))
        } else if self.entity_types.contains(&name) {
            Some(NamedType::Entity(node.clone().to_smolstr()))
        } else if node.is_unqualified_bool() {
            Some(NamedType::Primitive(PrimitiveType::Bool))
        } else if node.is_unqualified_long() {
            Some(NamedType::Primitive(PrimitiveType::Long))
        } else if node.is_unqualified_string() {
            Some(NamedType::Primitive(PrimitiveType::String))
        } else if node.is_unqualified_decimal() || node.is_unqualified_ipaddr() {
            Some(NamedType::Extension(node.clone().to_smolstr()))
        } else {
            None
        }
    }
}

fn name_to_str(name: super::ast::Name) -> Str {
    match name {
        Either::Left(id) => Node {
            node: id.node.to_smolstr(),
            loc: id.loc,
        },
        Either::Right(s) => s,
    }
}

fn ref_to_action_euid(name: Ref) -> ActionEntityUID {
    let Ref { ty, id } = name;
    ActionEntityUID {
        id: name_to_str(id).node,
        ty: ty.map(|p| p.to_smolstr()),
    }
}

// We delay the handling of duplicate keys so that this function is total
fn build_context(namespace: &Namespace) -> Context {
    let mut common_types: HashSet<Node<Name>> = HashSet::new();
    let mut entity_types: HashSet<Node<Name>> = HashSet::new();
    for decl in &namespace.decls {
        match &decl.node {
            Declaration::Entity(et_decl) => {
                entity_types.extend(
                    et_decl
                        .names
                        .iter()
                        .map(|id| id.clone().map(Name::unqualified_name)),
                );
            }
            Declaration::Type(id, _) => {
                common_types.insert(id.clone().map(Name::unqualified_name));
            }
            _ => {}
        }
    }
    Context {
        common_types: common_types.into_iter().map(|n| n.node).collect(),
        entity_types: entity_types.into_iter().map(|n| n.node).collect(),
    }
}

pub trait TryFrom<T>: Sized {
    type Error;

    // Required method
    fn try_from(value: T, context: &Context) -> Result<Self, Self::Error>;
}

pub trait TryInto<T>: Sized {
    type Error;

    fn try_into(self, context: &Context) -> Result<T, Self::Error>;
}

impl<T, U> TryInto<U> for T
where
    U: TryFrom<T>,
{
    type Error = U::Error;

    fn try_into(self, context: &Context) -> Result<U, U::Error> {
        U::try_from(self, context)
    }
}

impl TryFrom<Type> for SchemaType {
    type Error = ToValidatorSchemaError;
    fn try_from(value: Type, context: &Context) -> Result<Self, Self::Error> {
        Ok(match value {
            Type::Ident(id) => match context.lookup(&id) {
                Some(ty) => ty.into(),
                None => Err(ToValidatorSchemaError::InvalidTypeName(id.to_smolstr()))?,
            },
            Type::Record(attrs) => Self::Type(TryInto::try_into(attrs, context)?),
            Type::Set(b) => Self::Type(SchemaTypeVariant::Set {
                element: Box::new(TryInto::try_into(b.node, context)?),
            }),
        })
    }
}

impl TryFrom<EntityDecl> for EntityType {
    type Error = ToValidatorSchemaError;
    fn try_from(value: EntityDecl, context: &Context) -> Result<Self, Self::Error> {
        Ok(Self {
            member_of_types: value.member_of_types.map_or(vec![], |ns| {
                ns.into_iter().map(|n| n.node.to_smolstr()).collect()
            }),
            shape: AttributesOrContext(SchemaType::Type(TryInto::try_into(value.attrs, context)?)),
        })
    }
}

impl TryFrom<Vec<Node<AttrDecl>>> for SchemaTypeVariant {
    type Error = ToValidatorSchemaError;
    fn try_from(value: Vec<Node<AttrDecl>>, context: &Context) -> Result<Self, Self::Error> {
        let mut attrs: HashMap<Str, crate::TypeOfAttribute> = HashMap::new();
        for n in value {
            let attr_decl = n.node;
            let name_str = name_to_str(attr_decl.name);
            if let Some((ns, _)) = attrs.get_key_value(&name_str) {
                return Err(ToValidatorSchemaError::DuplicateKeys(name_str, ns.clone()));
            }
            attrs.insert(
                name_str,
                TypeOfAttribute {
                    ty: TryInto::try_into(attr_decl.ty.node, context)?,
                    required: attr_decl.required.is_none(),
                },
            );
        }
        Ok(Self::Record {
            attributes: attrs.into_iter().map(|(n, ty)| (n.node, ty)).collect(),
            additional_attributes: false,
        })
    }
}

impl TryFrom<NonEmpty<Node<AppDecl>>> for ApplySpec {
    type Error = ToValidatorSchemaError;
    fn try_from(value: NonEmpty<Node<AppDecl>>, context: &Context) -> Result<Self, Self::Error> {
        let mut resource_types = Vec::new();
        let mut principal_types = Vec::new();
        let mut attr_context: Option<AttributesOrContext> = None;
        for decl in value {
            match decl.node {
                AppDecl::PR(PRAppDecl { ty, entity_tys }) => match ty.node {
                    PR::Principal => {
                        principal_types
                            .extend(entity_tys.into_iter().map(|et| et.node.to_smolstr()));
                    }
                    PR::Resource => {
                        resource_types
                            .extend(entity_tys.into_iter().map(|et| et.node.to_smolstr()));
                    }
                },
                AppDecl::Context(attrs) => {
                    if attr_context.is_some() {
                        return Err(Self::Error::MultipleContext);
                    }
                    attr_context = Some(AttributesOrContext(SchemaType::Type(TryInto::try_into(
                        attrs, context,
                    )?)));
                }
            }
        }
        Ok(Self {
            // In JSON schema format, unspecified resource is represented by a None field
            resource_types: if !resource_types.is_empty() {
                Some(resource_types)
            } else {
                None
            },
            // In JSON schema format, unspecified principal is represented by a None field
            principal_types: if !principal_types.is_empty() {
                Some(principal_types)
            } else {
                None
            },
            context: attr_context.unwrap_or_default(),
        })
    }
}

impl TryFrom<ActionDecl> for ActionType {
    type Error = ToValidatorSchemaError;
    fn try_from(value: ActionDecl, context: &Context) -> Result<Self, Self::Error> {
        let applies_to: Option<ApplySpec> = match value.app_decls {
            Some(decls) => Some(TryInto::try_into(decls, context)?),
            None => Some(ApplySpec {
                resource_types: Some(vec![]),
                principal_types: Some(vec![]),
                context: AttributesOrContext::default(),
            }),
        };
        let member_of = value
            .parents
            .map(|ps| ps.iter().map(|n| ref_to_action_euid(n.clone())).collect());
        Ok(ActionType {
            applies_to,
            // TODO: it should error instead!
            attributes: None,
            member_of,
        })
    }
}

impl std::convert::TryFrom<Schema> for SchemaFragment {
    type Error = ToValidatorSchemaError;
    fn try_from(value: Schema) -> Result<Self, Self::Error> {
        let mut validator_schema = HashMap::new();
        for ns_def in value {
            let mut entity_types: HashMap<Node<Id>, EntityType> = HashMap::new();
            let mut actions: HashMap<Str, ActionType> = HashMap::new();
            let mut common_types: HashMap<Node<Id>, SchemaType> = HashMap::new();
            let ns_def = ns_def.node;
            let ns = &ns_def
                .name
                .as_ref()
                .map(|ns| ns.node.clone().to_smolstr())
                .unwrap_or_default();
            let context = &build_context(&ns_def);
            for decl in ns_def.decls {
                match decl.node {
                    Declaration::Action(action_decl) => {
                        let mut ids: HashSet<Str> = HashSet::new();
                        action_decl.names.iter().try_for_each(|id| {
                            let id_str = name_to_str(id.clone());
                            if let Some(existing_id) = ids.get(&id_str) {
                                return Err(ToValidatorSchemaError::DuplicateKeys(
                                    id_str,
                                    existing_id.clone(),
                                ));
                            }
                            if let Some((existing_id, _)) = actions.get_key_value(&id_str) {
                                return Err(ToValidatorSchemaError::DuplicateKeys(
                                    id_str,
                                    existing_id.clone(),
                                ));
                            }
                            ids.insert(id_str);
                            Ok(())
                        })?;
                        let at: ActionType = TryInto::try_into(action_decl, context)?;
                        actions.extend(ids.iter().map(|n| (n.clone(), at.clone())));
                    }
                    Declaration::Entity(entity_decl) => {
                        let mut names: HashSet<Node<Id>> = HashSet::new();
                        entity_decl.names.iter().try_for_each(|name| {
                            if let Some(existing_name) = names.get(name) {
                                return Err(ToValidatorSchemaError::DuplicateKeys(
                                    existing_name.clone().map(Id::to_smolstr),
                                    name.clone().map(Id::to_smolstr),
                                ));
                            }
                            if let Some((existing_name, _)) = entity_types.get_key_value(name) {
                                return Err(ToValidatorSchemaError::DuplicateKeys(
                                    existing_name.clone().map(Id::to_smolstr),
                                    name.clone().map(Id::to_smolstr),
                                ));
                            }
                            names.insert(name.clone());
                            Ok(())
                        })?;
                        let et: EntityType = TryInto::try_into(entity_decl, context)?;
                        entity_types.extend(names.iter().map(|n| (n.clone(), et.clone())));
                    }
                    Declaration::Type(id, ty) => {
                        if let Some((existing_id, _)) = common_types.get_key_value(&id) {
                            return Err(ToValidatorSchemaError::DuplicateKeys(
                                id.clone().map(Id::to_smolstr),
                                existing_id.clone().map(Id::to_smolstr),
                            ));
                        } else {
                            common_types.insert(id.clone(), TryInto::try_into(ty.node, context)?);
                        }
                    }
                }
            }
            if validator_schema.contains_key(ns) {
                return Err(ToValidatorSchemaError::DuplicateNSIds(ns.clone()));
            } else {
                validator_schema.insert(
                    ns.clone(),
                    NamespaceDefinition {
                        entity_types: entity_types
                            .into_iter()
                            .map(|(n, et)| (n.node.to_smolstr(), et))
                            .collect(),
                        actions: actions.into_iter().map(|(n, a)| (n.node, a)).collect(),
                        common_types: common_types
                            .into_iter()
                            .map(|(n, ct)| (n.node.to_smolstr(), ct))
                            .collect(),
                    },
                );
            }
        }
        Ok(SchemaFragment(validator_schema))
    }
}
