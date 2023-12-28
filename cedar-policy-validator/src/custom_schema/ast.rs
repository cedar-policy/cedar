use std::collections::{HashMap, HashSet};

use cedar_policy_core::{
    ast::{Id, Name as CName},
    parser::Node,
};
use itertools::Either;
use nonempty::NonEmpty;
use smol_str::SmolStr;

use crate::{
    ActionEntityUID, ActionType, ApplySpec, AttributesOrContext, EntityType, NamespaceDefinition,
    SchemaFragment, SchemaType, SchemaTypeVariant, TypeOfAttribute,
};

use super::err::ToValidatorSchemaError;

pub type Ident = Node<Id>;
pub type Str = Node<SmolStr>;
pub type Name = Either<Ident, Str>;
pub type Schema = Vec<Node<Namespace>>;

fn name_to_str(name: Name) -> Str {
    match name {
        Either::Left(id) => Node {
            node: id.node.to_smolstr(),
            loc: id.loc,
        },
        Either::Right(s) => s,
    }
}

// TODO: cross namespace action EUID reference
fn name_to_action_euid(name: Name) -> ActionEntityUID {
    match name {
        Either::Left(id) => ActionEntityUID {
            id: id.node.to_smolstr(),
            ty: None,
        },
        Either::Right(s) => ActionEntityUID {
            id: s.node,
            ty: None,
        },
    }
}

fn path_to_str(name: Path) -> SmolStr {
    <Path as Into<CName>>::into(name).to_string().into()
}

#[derive(Debug, Clone)]
pub struct Path {
    pub base: Ident,
    pub prefix: Vec<Ident>,
}

// Convert `Path` to `cedar_policy_core::ast::Name` and drop all its source locations
impl From<Path> for CName {
    fn from(value: Path) -> Self {
        CName::new(
            value.base.node,
            value.prefix.iter().map(|id| id.node.clone()),
        )
    }
}

#[derive(Debug, Clone)]
pub struct Namespace {
    pub name: Option<Node<Path>>,
    pub decls: Vec<Node<Declaration>>,
}

#[derive(Debug, Clone)]
pub enum Declaration {
    Entity(EntityDecl),
    Action(ActionDecl),
    Type(Ident, Node<Type>),
}

#[derive(Debug, Clone)]
pub struct EntityDecl {
    pub names: Vec<Ident>,
    pub member_of_types: Option<Vec<Node<Path>>>,
    pub attrs: Vec<Node<AttrDecl>>,
}

impl TryFrom<EntityDecl> for EntityType {
    type Error = ToValidatorSchemaError;
    fn try_from(value: EntityDecl) -> Result<Self, Self::Error> {
        Ok(Self {
            member_of_types: value.member_of_types.map_or(vec![], |ns| {
                ns.into_iter().map(|n| path_to_str(n.node)).collect()
            }),
            shape: AttributesOrContext(SchemaType::Type(value.attrs.try_into()?)),
        })
    }
}

#[derive(Debug, Clone)]
pub enum Type {
    Long,
    Bool,
    String,
    Set(Box<Node<Type>>),
    Ident(Ident),
    Record(Vec<Node<AttrDecl>>),
}

impl TryFrom<Type> for SchemaType {
    type Error = ToValidatorSchemaError;
    fn try_from(value: Type) -> Result<Self, Self::Error> {
        Ok(match value {
            Type::Bool => Self::Type(SchemaTypeVariant::Boolean),
            Type::Ident(id) => Self::TypeDef {
                type_name: id.node.to_smolstr(),
            },
            Type::Long => Self::Type(SchemaTypeVariant::Long),
            Type::Record(attrs) => Self::Type(attrs.try_into()?),
            Type::Set(b) => Self::Type(SchemaTypeVariant::Set {
                element: Box::new(b.node.try_into()?),
            }),
            Type::String => Self::Type(SchemaTypeVariant::String),
        })
    }
}

#[derive(Debug, Clone)]
pub struct AttrDecl {
    pub name: Name,
    pub required: Option<()>,
    pub ty: Node<Type>,
}

impl TryFrom<Vec<Node<AttrDecl>>> for SchemaTypeVariant {
    type Error = ToValidatorSchemaError;
    fn try_from(value: Vec<Node<AttrDecl>>) -> Result<Self, Self::Error> {
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
                    ty: attr_decl.ty.node.try_into()?,
                    required: attr_decl.required.is_some(),
                },
            );
        }
        Ok(Self::Record {
            attributes: attrs.into_iter().map(|(n, ty)| (n.node, ty)).collect(),
            additional_attributes: false,
        })
    }
}

#[derive(Debug, Clone)]
pub enum PR {
    Principal,
    Resource,
}

#[derive(Debug, Clone)]
pub struct PRAppDecl {
    pub ty: Node<PR>,
    pub entity_tys: NonEmpty<Node<Path>>,
}

#[derive(Debug, Clone)]
pub enum AppDecl {
    PR(PRAppDecl),
    Context(Vec<Node<AttrDecl>>),
}

#[derive(Debug, Clone)]
pub struct ActionDecl {
    pub names: Vec<Name>,
    pub parents: Option<Vec<Name>>,
    pub app_decls: Option<NonEmpty<Node<AppDecl>>>,
    pub attrs: Vec<Node<AttrDecl>>,
}

impl TryFrom<NonEmpty<Node<AppDecl>>> for ApplySpec {
    type Error = ToValidatorSchemaError;
    fn try_from(value: NonEmpty<Node<AppDecl>>) -> Result<Self, Self::Error> {
        let mut resource_types = Vec::new();
        let mut principal_types = Vec::new();
        let mut context: Option<AttributesOrContext> = None;
        for decl in value {
            match decl.node {
                AppDecl::PR(PRAppDecl { ty, entity_tys }) if matches!(ty.node, PR::Principal) => {
                    principal_types.extend(entity_tys.into_iter().map(|et| path_to_str(et.node)))
                }
                AppDecl::PR(PRAppDecl { ty, entity_tys }) if matches!(ty.node, PR::Resource) => {
                    resource_types.extend(entity_tys.into_iter().map(|et| path_to_str(et.node)))
                }
                AppDecl::Context(attrs) => {
                    if context.is_some() {
                        return Err(Self::Error::MultipleContext);
                    }
                    context = Some(AttributesOrContext(SchemaType::Type(attrs.try_into()?)));
                }
                _ => {
                    unreachable!("")
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
            context: context.unwrap_or_default(),
        })
    }
}

impl TryFrom<ActionDecl> for ActionType {
    type Error = ToValidatorSchemaError;
    fn try_from(value: ActionDecl) -> Result<Self, Self::Error> {
        let applies_to: Option<ApplySpec> = match value.app_decls {
            Some(decls) => Some(decls.try_into()?),
            None => Some(ApplySpec {
                resource_types: Some(vec![]),
                principal_types: Some(vec![]),
                context: AttributesOrContext::default(),
            }),
        };
        let member_of = value
            .parents
            .map(|ps| ps.iter().map(|n| name_to_action_euid(n.clone())).collect());
        Ok(ActionType {
            applies_to,
            // TODO: it should error instead!
            attributes: None,
            member_of,
        })
    }
}

impl TryFrom<Schema> for SchemaFragment {
    type Error = ToValidatorSchemaError;
    fn try_from(value: Schema) -> Result<Self, Self::Error> {
        let mut validator_schema = HashMap::new();
        for ns_def in value {
            let mut entity_types: HashMap<Node<Id>, EntityType> = HashMap::new();
            let mut actions: HashMap<Str, ActionType> = HashMap::new();
            let mut common_types: HashMap<Node<Id>, SchemaType> = HashMap::new();
            let ns_def = ns_def.node;
            let ns = ns_def
                .name
                .map(|ns| path_to_str(ns.node))
                .unwrap_or_default();
            for decl in ns_def.decls {
                match decl.node {
                    Declaration::Action(action_decl) => {
                        let mut ids: HashSet<Str> = HashSet::new();
                        let _ = action_decl
                            .names
                            .iter()
                            .map(|id| {
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
                            })
                            .collect::<Result<(), Self::Error>>()?;
                        let at: ActionType = action_decl.try_into()?;
                        actions.extend(ids.iter().map(|n| (n.clone(), at.clone())));
                    }
                    Declaration::Entity(entity_decl) => {
                        let mut names: HashSet<Node<Id>> = HashSet::new();
                        let _ = entity_decl
                            .names
                            .iter()
                            .map(|name| {
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
                            })
                            .collect::<Result<(), Self::Error>>()?;
                        let et: EntityType = entity_decl.try_into()?;
                        entity_types.extend(names.iter().map(|n| (n.clone(), et.clone())));
                    }
                    Declaration::Type(id, ty) => {
                        if let Some((existing_id, _)) = common_types.get_key_value(&id) {
                            return Err(ToValidatorSchemaError::DuplicateKeys(
                                id.clone().map(Id::to_smolstr),
                                existing_id.clone().map(Id::to_smolstr),
                            ));
                        } else {
                            common_types.insert(id.clone(), ty.node.try_into()?);
                        }
                    }
                }
            }
            if validator_schema.contains_key(&ns) {
                return Err(ToValidatorSchemaError::DuplicateNSIds(ns));
            } else {
                validator_schema.insert(
                    ns,
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
