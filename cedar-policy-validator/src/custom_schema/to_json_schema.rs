use std::collections::{HashMap, HashSet};

use cedar_policy_core::{
    ast::{Id, Name},
    parser::{Loc, Node},
};
use itertools::{Either, Itertools};
use nonempty::NonEmpty;
use smol_str::SmolStr;

use crate::{
    ActionEntityUID, ActionType, ApplySpec, AttributesOrContext, EntityType, NamespaceDefinition,
    SchemaFragment, SchemaType, SchemaTypeVariant, TypeOfAttribute,
};

use super::{
    ast::{
        ActionDecl, AppDecl, AttrDecl, Declaration, EntityDecl, Namespace, PRAppDecl, Path,
        PathKind, PrimOrExtension, Ref, Schema, Str, Type, CEDAR_NAMESPACE, PR,
    },
    err::ToJsonSchemaError,
};

#[derive(Debug, Clone)]
pub(super) struct Resolver {
    global_common_types: HashSet<Node<Name>>,
    global_entity_types: HashSet<Node<Name>>,
}

pub(super) type LookupFn<'a> = Box<dyn Fn(&Path) -> Option<NamedType> + 'a>;

impl Resolver {
    pub(super) fn new(schema: &Schema) -> Self {
        let mut common_tys = HashSet::new();
        let mut ets = HashSet::new();
        for ns_def in schema {
            let prefix: Vec<super::ast::Ident> = if let Some(ns) = ns_def.node.name.clone() {
                [ns.node.prefix, vec![ns.node.base]].concat()
            } else {
                vec![]
            };
            for decl in &ns_def.node.decls {
                match &decl.node {
                    Declaration::Type(id, _) => {
                        let path = Path::new(id.clone(), prefix.clone());
                        common_tys
                            .insert(Node::with_source_loc(path.clone().into(), path.get_loc()));
                    }
                    Declaration::Entity(decl) => {
                        ets.extend(decl.names.iter().map(|id| {
                            let path = Path::new(id.clone(), prefix.clone());
                            Node::with_source_loc(path.clone().into(), path.get_loc())
                        }));
                    }
                    _ => {}
                }
            }
        }
        Resolver {
            global_common_types: common_tys,
            global_entity_types: ets,
        }
    }

    pub(super) fn get_lookup_fn(&self, namespace: &Namespace) -> (LookupFn, TypeNameCollisions) {
        let mut collisions = Vec::new();
        let mut common_types: HashSet<Node<Name>> = HashSet::new();
        let mut entity_types: HashSet<Node<Name>> = HashSet::new();
        for decl in &namespace.decls {
            match &decl.node {
                Declaration::Entity(et_decl) => {
                    et_decl.names.iter().for_each(|id| {
                        let path: Path = id.clone().into();
                        if path.is_unqualified_builtin() {
                            collisions
                                .push(TypeNameCollision::Builtin(id.clone().map(Id::to_smolstr)));
                        }
                        entity_types.insert(id.clone().map(Name::unqualified_name));
                    });
                }
                Declaration::Type(id, _) => {
                    let path: Path = id.clone().into();
                    if path.is_unqualified_builtin() {
                        collisions.push(TypeNameCollision::Builtin(id.clone().map(Id::to_smolstr)));
                    }
                    common_types.insert(id.clone().map(Name::unqualified_name));
                }
                _ => {}
            }
        }

        let (smaller_set, larger_set) = if common_types.len() < entity_types.len() {
            (&common_types, &entity_types)
        } else {
            (&entity_types, &common_types)
        };
        for an in smaller_set {
            if let Some(bn) = larger_set.get(an) {
                collisions.push(TypeNameCollision::CommonTypeAndEntityType(
                    an.clone().map(|n| n.to_string().into()),
                    bn.clone().map(|n| n.to_string().into()),
                ))
            }
        }

        (
            Box::new(move |node| {
                let name = Node::with_source_loc(Name::from(node.clone()), node.get_loc());
                // Resolve naming. See the spec here: https://github.com/cedar-policy/rfcs/blob/main/text/0024-schema-syntax.md
                match &node.kind {
                    // Resolve things in the builtin `__cedar` namespace, this includes primitives and extension functions
                    PathKind::CedarBuiltin(Some(
                        PrimOrExtension::Decimal | PrimOrExtension::IpAddr,
                    )) => Some(NamedType::Extension(node.base.node.clone().to_smolstr())),
                    PathKind::CedarBuiltin(Some(PrimOrExtension::Prim(prim))) => {
                        Some(NamedType::Primitive(*prim))
                    }
                    // Anything else in the builtin `__cedar` namespace does not exist, so fail
                    PathKind::CedarBuiltin(None) => None,
                    // Next check for things in the unqualified namespace.
                    // By default, this includes primitive types and extension functions,
                    // but can be shadowed by entities and common types
                    PathKind::Unqualified(Some(prim_or_ext)) => {
                        // Check if shadowed by common type or entity types
                        if let Some(typ) =
                            self.lookup_common_or_entity(&name, node, &common_types, &entity_types)
                        {
                            Some(typ)
                        } else {
                            // Not shadowed, return the builtin type
                            match prim_or_ext {
                                PrimOrExtension::Decimal | PrimOrExtension::IpAddr => {
                                    Some(NamedType::Extension(node.base.node.clone().to_smolstr()))
                                }
                                PrimOrExtension::Prim(prim) => Some(NamedType::Primitive(*prim)),
                            }
                        }
                    }
                    PathKind::Other | PathKind::Unqualified(None) => {
                        self.lookup_common_or_entity(&name, node, &common_types, &entity_types)
                    }
                }
            }),
            collisions,
        )
    }

    /// Extract the type corresponding to [`name`] if it exists in the common types or entity types
    fn lookup_common_or_entity(
        &self,
        name: &Node<Name>,
        node: &Path,
        common_types: &HashSet<Node<Name>>,
        entity_types: &HashSet<Node<Name>>,
    ) -> Option<NamedType> {
        if common_types.contains(name) || self.global_common_types.contains(name) {
            Some(NamedType::Common(node.clone().into()))
        } else if entity_types.contains(name) || self.global_entity_types.contains(name) {
            Some(NamedType::Entity(node.clone().into()))
        } else {
            None
        }
    }
}

pub type TypeNameCollisions = Vec<TypeNameCollision>;

#[derive(Debug, Clone)]
pub enum TypeNameCollision {
    CommonTypeAndEntityType(Str, Str),
    Builtin(Str),
}

#[derive(Debug, Clone, Copy)]
pub(super) enum PrimitiveType {
    Bool,
    Long,
    String,
}
#[derive(Debug, Clone)]
pub(super) enum NamedType {
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
        ty: ty.map(|p| p.into()),
    }
}

pub(super) trait TryFrom<T>: Sized {
    type Error;

    // Required method
    fn try_from(value: T, lookup_func: &LookupFn) -> Result<Self, Self::Error>;
}

pub(super) trait TryInto<T>: Sized {
    type Error;

    fn try_into(self, lookup_func: &LookupFn) -> Result<T, Self::Error>;
}

impl<T, U> TryInto<U> for T
where
    U: TryFrom<T>,
{
    type Error = U::Error;

    fn try_into(self, lookup_func: &LookupFn) -> Result<U, U::Error> {
        U::try_from(self, lookup_func)
    }
}

impl TryFrom<Type> for SchemaType {
    type Error = ToJsonSchemaError;
    fn try_from(value: Type, lookup_func: &LookupFn) -> Result<Self, Self::Error> {
        Ok(match value {
            Type::Ident(id) => match lookup_func(&id) {
                Some(ty) => ty.into(),
                None => Err(ToJsonSchemaError::UnknownTypeName(Node::with_source_loc(
                    id.clone().into(),
                    id.get_loc(),
                )))?,
            },
            Type::Record(attrs) => Self::Type(TryInto::try_into(attrs, lookup_func)?),
            Type::Set(b) => Self::Type(SchemaTypeVariant::Set {
                element: Box::new(TryInto::try_into(b.node, lookup_func)?),
            }),
        })
    }
}

impl TryFrom<EntityDecl> for EntityType {
    type Error = ToJsonSchemaError;
    fn try_from(value: EntityDecl, lookup_func: &LookupFn) -> Result<Self, Self::Error> {
        Ok(Self {
            member_of_types: value
                .member_of_types
                .map_or(vec![], |ns| ns.into_iter().map(|n| n.node.into()).collect()),
            shape: AttributesOrContext(SchemaType::Type(TryInto::try_into(
                value.attrs,
                lookup_func,
            )?)),
        })
    }
}

impl TryFrom<Vec<Node<AttrDecl>>> for SchemaTypeVariant {
    type Error = ToJsonSchemaError;
    fn try_from(value: Vec<Node<AttrDecl>>, lookup_func: &LookupFn) -> Result<Self, Self::Error> {
        let mut attrs: HashMap<Str, crate::TypeOfAttribute> = HashMap::new();
        for n in value {
            let attr_decl = n.node;
            let name_str = name_to_str(attr_decl.name);
            if let Some((ns, _)) = attrs.get_key_value(&name_str) {
                return Err(ToJsonSchemaError::DuplicateKeys(
                    name_str.node,
                    (name_str.loc, ns.loc.clone()),
                ));
            }
            attrs.insert(
                name_str,
                TypeOfAttribute {
                    ty: TryInto::try_into(attr_decl.ty.node, lookup_func)?,
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
    type Error = ToJsonSchemaError;
    fn try_from(
        value: NonEmpty<Node<AppDecl>>,
        lookup_func: &LookupFn,
    ) -> Result<Self, Self::Error> {
        // Sort out the context decls from the principal/resource decls
        let (prs, contexts): (Vec<_>, Vec<_>) =
            value.into_iter().partition_map(|node| match node.node {
                AppDecl::PR(pr) => Either::Left((pr, node.loc)),
                AppDecl::Context(context) => Either::Right((context, node.loc)),
            });

        // Sort the principal decls from the resource decls
        let (principals, resources): (Vec<_>, Vec<_>) =
            prs.into_iter()
                .partition_map(|(app_decl, loc)| match app_decl.ty.node {
                    PR::Principal => Either::Left((app_decl, loc)),
                    PR::Resource => Either::Right((app_decl, loc)),
                });

        let principal_types = process_pr_decls(principals, "principal")?;

        let resource_types = process_pr_decls(resources, "resource")?;

        let attr_lookup_func = match exactly_once(contexts, "lookup_func")? {
            Some(attrs) => Some(AttributesOrContext(SchemaType::Type(TryInto::try_into(
                attrs,
                lookup_func,
            )?))),
            None => None,
        };

        Ok(Self {
            // In JSON schema format, unspecified resource is represented by a None field
            resource_types: if let Some(resource_types) = resource_types {
                Some(resource_types.into())
            } else {
                None
            },
            // In JSON schema format, unspecified principal is represented by a None field
            principal_types: if let Some(principal_types) = principal_types {
                Some(principal_types.into())
            } else {
                None
            },
            context: attr_lookup_func.map_or(AttributesOrContext::default(), |attrs| attrs),
        })
    }
}

/// If there is exactly one PRDecl here, map it to it's list of entity types
fn process_pr_decls(
    input: Vec<(PRAppDecl, Loc)>,
    name: &'static str,
) -> Result<Option<NonEmpty<SmolStr>>, ToJsonSchemaError> {
    Ok(exactly_once(input, name)?.map(|decl| decl.entity_tys.map(|et| et.node.into())))
}

/// Fold over the list, producing the following:
///
/// * Err(_) -> if there is more than one element in the array
/// * Ok(None) -> if there are no elements in the array
/// * Ok(Some(_)) -> if there is exactly one element in the array
fn exactly_once<A>(
    input: Vec<(A, Loc)>,
    name: &'static str,
) -> Result<Option<A>, ToJsonSchemaError> {
    Ok(input
        .into_iter()
        .fold(Ok(None), exactly_one(name))?
        .map(|(a, _)| a))
}

fn exactly_one<X>(
    name: &'static str,
) -> impl Fn(
    Result<Option<(X, Loc)>, ToJsonSchemaError>,
    (X, Loc),
) -> Result<Option<(X, Loc)>, ToJsonSchemaError> {
    move |acc, (next_decl, next_loc)| match acc? {
        // This our first find
        None => Ok(Some((next_decl, next_loc))),
        Some((_, exiting_loc)) => Err(ToJsonSchemaError::DuplicateKeys(
            name.into(),
            (exiting_loc, next_loc),
        )),
    }
}

impl TryFrom<ActionDecl> for ActionType {
    type Error = ToJsonSchemaError;
    fn try_from(value: ActionDecl, lookup_func: &LookupFn) -> Result<Self, Self::Error> {
        let applies_to: Option<ApplySpec> = match value.app_decls {
            Some(decls) => Some(TryInto::try_into(decls, lookup_func)?),
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

fn ns_to_ns_def(
    ns_def: Namespace,
    resolver: &Resolver,
) -> Result<(NamespaceDefinition, TypeNameCollisions), ToJsonSchemaError> {
    let mut entity_types: HashMap<Node<Id>, EntityType> = HashMap::new();
    let mut actions: HashMap<Str, ActionType> = HashMap::new();
    let mut common_types: HashMap<Node<Id>, SchemaType> = HashMap::new();
    let (lookup_func, collisions) = resolver.get_lookup_fn(&ns_def);
    for decl in ns_def.decls {
        match decl.node {
            Declaration::Action(action_decl) => {
                let mut ids: HashSet<Str> = HashSet::new();
                action_decl.names.iter().try_for_each(|id| {
                    let id_str = name_to_str(id.clone());
                    if let Some((existing_id, _)) = actions.get_key_value(&id_str) {
                        return Err(ToJsonSchemaError::DuplicateDeclarations(
                            id_str.node.clone(),
                            (id_str.loc, existing_id.loc.clone()),
                        ));
                    }
                    ids.insert(id_str);
                    Ok(())
                })?;
                let at: ActionType = TryInto::try_into(action_decl, &lookup_func)?;
                actions.extend(ids.iter().map(|n| (n.clone(), at.clone())));
            }
            Declaration::Entity(entity_decl) => {
                let mut names: HashSet<Node<Id>> = HashSet::new();
                entity_decl.names.iter().try_for_each(|name| {
                    if let Some((existing_name, _)) = entity_types.get_key_value(name) {
                        return Err(ToJsonSchemaError::DuplicateDeclarations(
                            existing_name.node.clone().to_smolstr(),
                            (existing_name.loc.clone(), name.loc.clone()),
                        ));
                    }
                    names.insert(name.clone());
                    Ok(())
                })?;
                let et: EntityType = TryInto::try_into(entity_decl, &lookup_func)?;
                entity_types.extend(names.iter().map(|n| (n.clone(), et.clone())));
            }
            Declaration::Type(id, ty) => {
                if let Some((existing_id, _)) = common_types.get_key_value(&id) {
                    return Err(ToJsonSchemaError::DuplicateDeclarations(
                        id.node.to_smolstr(),
                        (id.loc.clone(), existing_id.loc.clone()),
                    ));
                } else {
                    common_types.insert(id.clone(), TryInto::try_into(ty.node, &lookup_func)?);
                }
            }
        }
    }
    Ok((
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
        collisions,
    ))
}

fn deduplicate_ns(schema: Schema) -> Result<HashMap<SmolStr, Namespace>, ToJsonSchemaError> {
    let mut namespaces: HashMap<Str, Namespace> = HashMap::new();
    for ns_node in schema {
        let ns = ns_node.node;
        let name: Str = Node::with_source_loc(
            ns.name
                .clone()
                .map_or(SmolStr::default(), |name| name.node.into()),
            ns_node.loc.clone(),
        );
        if name.node == CEDAR_NAMESPACE {
            // PANIC SAFETY: The name field is a `Some` when the `name` is not empty
            #[allow(clippy::unwrap_used)]
            return Err(ToJsonSchemaError::UseReservedNamespace(
                ns.name.unwrap().loc,
            ));
        }

        match namespaces.entry(name.clone()) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let existing_name = entry.key();
                if existing_name.node.is_empty() {
                    entry.get_mut().decls.extend(ns.decls);
                } else {
                    // Duplicate `namespace` constructs are not allowed
                    return Err(ToJsonSchemaError::DuplicateNSIds(
                        existing_name.node.clone(),
                        (name.loc, existing_name.loc.clone()),
                    ));
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(ns);
            }
        }
    }
    Ok(namespaces
        .into_iter()
        .map(|(name, def)| (name.node, def))
        .collect())
}

pub fn custom_schema_to_json_schema(
    schema: Schema,
) -> Result<(SchemaFragment, TypeNameCollisions), ToJsonSchemaError> {
    let mut collisions = vec![];
    let mut json_schema = HashMap::new();
    let resolver = Resolver::new(&schema);
    let deduplicated_ns = deduplicate_ns(schema)?;
    for (name, ns) in deduplicated_ns {
        let (ns_def, ns_tn_collisions) = ns_to_ns_def(ns, &resolver)?;
        json_schema.insert(name, ns_def);
        collisions.extend(ns_tn_collisions);
    }
    Ok((SchemaFragment(json_schema), collisions))
}
