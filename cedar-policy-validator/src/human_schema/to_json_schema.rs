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

use std::collections::HashMap;

use cedar_policy_core::{
    ast::{Id, Name},
    parser::{Loc, Node},
};
use itertools::Either;
use nonempty::NonEmpty;
use smol_str::{SmolStr, ToSmolStr};
use std::collections::hash_map::Entry;

use crate::{
    human_schema::ast::Path, ActionEntityUID, ActionType, ApplySpec, AttributesOrContext,
    EntityType, NamespaceDefinition, SchemaFragment, SchemaType, SchemaTypeVariant,
    TypeOfAttribute,
};

use super::{
    ast::{
        ActionDecl, AppDecl, AttrDecl, Decl, Declaration, EntityDecl, Namespace, PRAppDecl,
        QualName, Schema, Type, TypeDecl, BUILTIN_TYPES, CEDAR_NAMESPACE, EXTENSIONS, PR,
    },
    err::{
        SchemaWarning, ShadowsBuiltinWarning, ShadowsEntityWarning, ToJsonSchemaError,
        ToJsonSchemaErrors,
    },
};

/// Convert a custom schema AST into the JSON representation
/// This will let you subsequently decode that into the Validator AST for Schemas (`[ValidatorSchema]`)
/// On success, this function returns a tuple containing:
///     * The SchemaFragment
///     * A vector of name collisions, that are essentially warnings
pub fn custom_schema_to_json_schema(
    schema: Schema,
) -> Result<(SchemaFragment, impl Iterator<Item = SchemaWarning>), ToJsonSchemaErrors> {
    // First pass, figure out what each name is bound to

    let (qualified_namespaces, unqualified_namespace) =
        split_unqualified_namespace(schema.into_iter().map(|n| n.node));
    let all_namespaces = qualified_namespaces
        .chain(unqualified_namespace)
        .collect::<Vec<_>>();

    let names = build_namespace_bindings(all_namespaces.iter())?;
    let warnings = compute_namespace_warnings(&names).collect::<Vec<_>>();
    let fragment = collect_all_errors(
        all_namespaces
            .into_iter()
            .map(|ns| convert_namespace(&names, ns)),
    )?
    .collect();
    Ok((SchemaFragment(fragment), warnings.into_iter()))
}

/// Convert a custom type AST into the JSON representation of the type.
/// Conversion is done in an empty context.
pub fn custom_type_to_json_type(ty: Node<Type>) -> Result<SchemaType, ToJsonSchemaErrors> {
    let names = HashMap::from([(None, NamespaceRecord::default())]);
    let context = ConversionContext::new(
        &names,
        &Namespace {
            name: None,
            decls: vec![],
        },
    );
    context.convert_type(ty)
}

fn split_unqualified_namespace(
    namespaces: impl IntoIterator<Item = Namespace>,
) -> (impl Iterator<Item = Namespace>, Option<Namespace>) {
    let (qualified, unqualified): (Vec<_>, Vec<_>) =
        namespaces.into_iter().partition(|n| n.name.is_some());
    let mut unqualified_decls = vec![];
    for mut unqualified_namespace in unqualified.into_iter() {
        unqualified_decls.append(&mut unqualified_namespace.decls);
    }

    if unqualified_decls.is_empty() {
        (qualified.into_iter(), None)
    } else {
        let unqual = Namespace {
            name: None,
            decls: unqualified_decls,
        };
        (qualified.into_iter(), Some(unqual))
    }
}

/// Converts a CST namespace to the JSON namespace
fn convert_namespace(
    names: &HashMap<Option<Name>, NamespaceRecord>,
    namespace: Namespace,
) -> Result<(Option<Name>, NamespaceDefinition), ToJsonSchemaErrors> {
    let r = ConversionContext::new(names, &namespace);
    let def = r.convert_namespace(namespace)?;
    Ok((r.current_namespace_name, def))
}

/// The "context" for converting a piece of schema syntax into the JSON representation
/// It's primary purpose is implementing the procedure for looking up a type name
/// and resolving it to a type.
struct ConversionContext<'a> {
    names: &'a HashMap<Option<Name>, NamespaceRecord>,
    current_namespace_name: Option<Name>,
    cedar_namespace: NamespaceRecord,
}

impl<'a> ConversionContext<'a> {
    /// Create a context, needs the entire schemas name map, as well as the current namespace we are converting
    fn new(
        names: &'a HashMap<Option<Name>, NamespaceRecord>,
        current_namespace: &Namespace,
    ) -> Self {
        let current_namespace_name = current_namespace
            .name
            .as_ref()
            .map(|path| path.clone().node.into());
        Self {
            names,
            current_namespace_name,
            cedar_namespace: NamespaceRecord::default(), // The `__cedar` namespace is empty (besides primitives)
        }
    }

    /// Convert a cst namespace
    fn convert_namespace(&self, n: Namespace) -> Result<NamespaceDefinition, ToJsonSchemaErrors> {
        // Ensure we aren't using a reserved namespace
        match n.name.as_ref() {
            Some(name) if name.node.is_cedar() || name.node.is_in_cedar() => {
                Err(ToJsonSchemaError::UseReservedNamespace(name.loc.clone()))
            }
            _ => Ok(()),
        }?;

        // Partition the decls into entities, actions, and common types
        let (entity_types, action, common_types) = into_partition_decls(n.decls);
        // Convert entity type decls, collecting all errors
        let entity_types = collect_all_errors(
            entity_types
                .into_iter()
                .map(|decl| self.convert_entity_decl(decl)),
        )?
        .collect::<Vec<_>>();
        let entity_types = entity_types.into_iter().flatten().collect();

        // Convert entity type decls, collecting all errors
        let actions = collect_all_errors(
            action
                .into_iter()
                .map(|decl| self.convert_action_decl(decl)),
        )?
        .collect::<Vec<_>>();
        let actions = actions.into_iter().flatten().collect();

        // Convert entity type decls, collecting all errors
        let common_types = collect_all_errors(
            common_types
                .into_iter()
                .map(|decl| self.convert_common_types(decl)),
        )?
        .collect();

        Ok(NamespaceDefinition {
            common_types,
            entity_types,
            actions,
        })
    }

    /// Converts common type decls
    fn convert_common_types(&self, decl: TypeDecl) -> Result<(Id, SchemaType), ToJsonSchemaErrors> {
        let TypeDecl { name, def } = decl;
        let ty = self.convert_type(def)?;
        Ok((name.node, ty))
    }

    /// Converts action type decls
    fn convert_action_decl(
        &self,
        a: ActionDecl,
    ) -> Result<impl Iterator<Item = (SmolStr, ActionType)>, ToJsonSchemaErrors> {
        let ActionDecl {
            names,
            parents,
            app_decls,
        } = a;
        // Create the internal type from the 'applies_to' clause and 'member_of'
        let applies_to = app_decls
            .map(|decls| self.convert_app_decls(decls))
            .transpose()?
            .unwrap_or_else(|| ApplySpec {
                resource_types: Some(vec![]),
                principal_types: Some(vec![]),
                context: AttributesOrContext::default(),
            });
        let member_of = parents.map(|parents| self.convert_parents(parents));
        let ty = ActionType {
            attributes: None, // Action attributes are currently unsupported in the natural schema
            applies_to: Some(applies_to),
            member_of,
        };
        // Then map that type across all of the bound names
        Ok(names.into_iter().map(move |name| (name.node, ty.clone())))
    }

    fn convert_parents(&self, parents: NonEmpty<Node<QualName>>) -> Vec<ActionEntityUID> {
        parents.into_iter().map(Self::convert_qual_name).collect()
    }

    fn convert_qual_name(qn: Node<QualName>) -> ActionEntityUID {
        let qn = qn.node;
        ActionEntityUID {
            id: qn.eid,
            ty: qn.path.map(|p| p.into()),
        }
    }

    // Convert the applies to decls
    fn convert_app_decls(
        &self,
        decls: Node<NonEmpty<Node<AppDecl>>>,
    ) -> Result<ApplySpec, ToJsonSchemaErrors> {
        // Split AppDecl's into context/principal/resource decls
        let (decls, _) = decls.into_inner();
        let mut principal_types: Option<Node<Vec<Name>>> = None;
        let mut resource_types: Option<Node<Vec<Name>>> = None;
        let mut context: Option<Node<AttributesOrContext>> = None;

        for decl in decls {
            match decl {
                Node {
                    node: AppDecl::Context(context_decl),
                    loc,
                } => match context {
                    Some(existing_context) => {
                        return Err(ToJsonSchemaError::DuplicateContext {
                            loc1: existing_context.loc,
                            loc2: loc,
                        }
                        .into());
                    }
                    None => {
                        context = Some(Node::with_source_loc(
                            self.convert_context_decl(context_decl)?,
                            loc,
                        ));
                    }
                },
                Node {
                    node:
                        AppDecl::PR(PRAppDecl {
                            kind:
                                Node {
                                    node: PR::Principal,
                                    ..
                                },
                            entity_tys,
                        }),
                    loc,
                } => match principal_types {
                    Some(existing_tys) => {
                        return Err(ToJsonSchemaError::DuplicatePR {
                            kind: PR::Principal,
                            loc1: existing_tys.loc,
                            loc2: loc,
                        }
                        .into())
                    }
                    None => {
                        principal_types = Some(Node::with_source_loc(
                            entity_tys.iter().map(|n| n.clone().into()).collect(),
                            loc,
                        ))
                    }
                },
                Node {
                    node:
                        AppDecl::PR(PRAppDecl {
                            kind:
                                Node {
                                    node: PR::Resource, ..
                                },
                            entity_tys,
                        }),
                    loc,
                } => match resource_types {
                    Some(existing_tys) => {
                        return Err(ToJsonSchemaError::DuplicatePR {
                            kind: PR::Resource,
                            loc1: existing_tys.loc,
                            loc2: loc,
                        }
                        .into())
                    }
                    None => {
                        resource_types = Some(Node::with_source_loc(
                            entity_tys.iter().map(|n| n.clone().into()).collect(),
                            loc,
                        ))
                    }
                },
            }
        }
        Ok(ApplySpec {
            resource_types: resource_types.map(|tys| tys.node),
            principal_types: principal_types.map(|tys| tys.node),
            context: context.map(|c| c.node).unwrap_or_default(),
        })
    }

    /// Convert Entity declarations, trivial recursive conversion
    fn convert_entity_decl(
        &self,
        e: EntityDecl,
    ) -> Result<impl Iterator<Item = (Id, EntityType)>, ToJsonSchemaErrors> {
        let EntityDecl {
            names,
            member_of_types,
            attrs,
        } = e;
        // First build up the defined entity type
        let member_of_types = member_of_types.into_iter().map(|p| p.into()).collect();
        let shape = self.convert_attr_decls(attrs)?;
        let etype = EntityType {
            member_of_types,
            shape,
        };

        // Then map over all of the bound names
        Ok(names
            .into_iter()
            .map(move |name| (name.node, etype.clone())))
    }

    /// Create a Record Type from a vector of AttrDecl's
    fn convert_attr_decls(
        &self,
        attrs: Vec<Node<AttrDecl>>,
    ) -> Result<AttributesOrContext, ToJsonSchemaErrors> {
        Ok(AttributesOrContext(SchemaType::Type(
            SchemaTypeVariant::Record {
                attributes: collect_all_errors(
                    attrs.into_iter().map(|attr| self.convert_attr_decl(attr)),
                )?
                .collect(),
                additional_attributes: false,
            },
        )))
    }

    /// Create a context decl
    fn convert_context_decl(
        &self,
        decl: Either<Path, Vec<Node<AttrDecl>>>,
    ) -> Result<AttributesOrContext, ToJsonSchemaErrors> {
        Ok(AttributesOrContext(match decl {
            Either::Left(p) => SchemaType::TypeDef {
                type_name: p.into(),
            },
            Either::Right(attrs) => SchemaType::Type(SchemaTypeVariant::Record {
                attributes: collect_all_errors(
                    attrs.into_iter().map(|attr| self.convert_attr_decl(attr)),
                )?
                .collect(),
                additional_attributes: false,
            }),
        }))
    }

    /// Convert an attribute type from an AttrDecl
    fn convert_attr_decl(
        &self,
        attr: Node<AttrDecl>,
    ) -> Result<(SmolStr, TypeOfAttribute), ToJsonSchemaErrors> {
        let AttrDecl { name, required, ty } = attr.node;
        Ok((
            name.node,
            TypeOfAttribute {
                ty: self.convert_type(ty)?,
                required,
            },
        ))
    }

    /// Convert a type recursively
    fn convert_type(&self, ty: Node<Type>) -> Result<SchemaType, ToJsonSchemaErrors> {
        match ty.node {
            Type::Set(t) => Ok(SchemaType::Type(SchemaTypeVariant::Set {
                element: Box::new(self.convert_type(*t)?),
            })),
            Type::Ident(p) => self.dereference_name(p).map_err(|e| e.into()),
            Type::Record(fields) => {
                let attributes = collect_all_errors(
                    fields
                        .into_iter()
                        .map(|field| self.convert_attr_decl(field)),
                )?
                .collect();

                Ok(SchemaType::Type(SchemaTypeVariant::Record {
                    attributes,
                    additional_attributes: false,
                }))
            }
        }
    }

    /// Dereference a type name to get it's type
    /// This follows the procedure from RFC 24.
    fn dereference_name(&self, p: Path) -> Result<SchemaType, ToJsonSchemaError> {
        // First determine what namespace we are searching
        let name: Name = p.clone().into();
        let is_unqualified_or_cedar = p.is_in_unqualified_or_cedar();
        let loc = p.loc().clone();
        let (prefix, base) = p.split_last();
        let namespace_to_search = match prefix.split_last() {
            Some((prefix_base, prefix_prefix)) => self.lookup_namespace(
                loc.clone(),
                &Some(Name::new(
                    prefix_base.clone(),
                    prefix_prefix.iter().cloned(),
                    None,
                )),
            ),
            None =>
            // We search the current namespace
            {
                self.lookup_namespace(loc.clone(), &self.current_namespace_name)
            }
        }?;
        // Now we search that namespace according to Rule 3
        // (https://github.com/cedar-policy/rfcs/blob/main/text/0024-schema-syntax.md#rule-3-resolve-name-references-in-a-priority-order)
        // That's this order:
        // 1. Common Types
        // 2. Entity Types
        // 3. Primitive types
        // 4. Extension Types
        if namespace_to_search.common_types.contains_key(&base) {
            Ok(SchemaType::TypeDef { type_name: name })
        } else if namespace_to_search.entities.contains_key(&base) {
            Ok(SchemaType::Type(SchemaTypeVariant::Entity { name }))
        } else if is_unqualified_or_cedar {
            search_cedar_namespace(base, loc)
        } else {
            Err(ToJsonSchemaError::UnknownTypeName(Node::with_source_loc(
                name.to_smolstr(),
                loc,
            )))
        }
    }

    fn lookup_namespace(
        &self,
        loc: Loc,
        name: &Option<Name>,
    ) -> Result<&NamespaceRecord, ToJsonSchemaError> {
        if &name.as_ref().map_or(SmolStr::default(), |n| n.to_smolstr()) == CEDAR_NAMESPACE {
            Ok(&self.cedar_namespace)
        } else {
            self.names.get(name).ok_or_else(|| {
                ToJsonSchemaError::UnknownTypeName(Node::with_source_loc(
                    self.current_namespace_name
                        .as_ref()
                        .map_or("".into(), |n| n.to_smolstr()),
                    loc,
                ))
            })
        }
    }
}

/// Takes a collection of results returning multiple errors
/// Behaves similarly to `::collect()` over results, except instead of failing
/// on the first error, keeps going to ensure all of the errors are accumulated
fn collect_all_errors<A, E>(
    iter: impl IntoIterator<Item = Result<A, E>>,
) -> Result<impl Iterator<Item = A>, ToJsonSchemaErrors>
where
    E: IntoIterator<Item = ToJsonSchemaError>,
{
    let mut answers = vec![];
    let mut errs = vec![];
    for r in iter.into_iter() {
        match r {
            Ok(a) => {
                answers.push(a);
            }
            Err(e) => {
                let mut v = e.into_iter().collect::<Vec<_>>();
                errs.append(&mut v)
            }
        }
    }
    match NonEmpty::collect(errs) {
        None => Ok(answers.into_iter()),
        Some(errs) => Err(ToJsonSchemaErrors::new(errs)),
    }
}

/// Search the cedar namespace, the things that live here are cedar builtins, unless overridden within a context.
fn search_cedar_namespace(name: Id, loc: Loc) -> Result<SchemaType, ToJsonSchemaError> {
    match name.as_ref() {
        "Long" => Ok(SchemaType::Type(SchemaTypeVariant::Long)),
        "String" => Ok(SchemaType::Type(SchemaTypeVariant::String)),
        "Bool" => Ok(SchemaType::Type(SchemaTypeVariant::Boolean)),
        other if EXTENSIONS.contains(&other) => {
            Ok(SchemaType::Type(SchemaTypeVariant::Extension { name }))
        }
        _ => Err(ToJsonSchemaError::UnknownTypeName(Node::with_source_loc(
            name.to_smolstr(),
            loc,
        ))),
    }
}

#[derive(Default)]
struct NamespaceRecord {
    entities: HashMap<Id, Node<()>>,
    common_types: HashMap<Id, Node<()>>,
    loc: Option<Loc>,
}

impl NamespaceRecord {
    fn new(namespace: &Namespace) -> Result<(Option<Name>, Self), ToJsonSchemaErrors> {
        let (entities, actions, types) = partition_decls(&namespace.decls);
        let name = namespace.name.as_ref().map(|n| n.node.clone().into());

        let entities = collect_decls(
            entities
                .into_iter()
                .flat_map(|decl| decl.names.clone())
                .map(extract_name),
        )?;
        // Ensure no duplicate actions
        collect_decls(
            actions
                .into_iter()
                .flat_map(ActionDecl::names)
                .map(extract_name),
        )?;
        let common_types = collect_decls(
            types
                .into_iter()
                .flat_map(|decl| std::iter::once(decl.name.clone()))
                .map(extract_name),
        )?;

        let record = NamespaceRecord {
            entities,
            common_types,
            loc: namespace.name.as_ref().map(|n| n.loc.clone()),
        };

        Ok((name, record))
    }
}

fn collect_decls<N>(
    i: impl Iterator<Item = (N, Node<()>)>,
) -> Result<HashMap<N, Node<()>>, ToJsonSchemaErrors>
where
    N: std::cmp::Eq + std::hash::Hash + Clone + ToSmolStr,
{
    let mut map: HashMap<N, Node<()>> = HashMap::new();
    for (key, node) in i {
        match map.entry(key.clone()) {
            Entry::Occupied(entry) => Err(ToJsonSchemaError::DuplicateDeclarations {
                decl: key.to_smolstr(),
                loc1: entry.get().loc.clone(),
                loc2: node.loc,
            }),
            Entry::Vacant(entry) => {
                entry.insert(node);
                Ok(())
            }
        }?;
    }
    Ok(map)
}

fn compute_namespace_warnings(
    fragment: &HashMap<Option<Name>, NamespaceRecord>,
) -> impl Iterator<Item = SchemaWarning> + '_ {
    fragment.values().flat_map(make_warning_for_shadowing)
}

fn make_warning_for_shadowing(n: &NamespaceRecord) -> impl Iterator<Item = SchemaWarning> {
    let mut warnings = vec![];
    for (common_name, common_src_node) in n.common_types.iter() {
        // Check if it shadows a entity name in the same namespace
        if let Some(entity_src_node) = n.entities.get(common_name) {
            let warning = ShadowsEntityWarning {
                name: common_name.to_smolstr(),
                entity_loc: entity_src_node.loc.clone(),
                common_loc: common_src_node.loc.clone(),
            }
            .into();
            warnings.push(warning);
        }
        // Check if it shadows a bultin
        if let Some(warning) = shadows_builtin((common_name, common_src_node)) {
            warnings.push(warning);
        }
    }
    let entity_shadows = n.entities.iter().filter_map(shadows_builtin);
    warnings
        .into_iter()
        .chain(entity_shadows)
        .collect::<Vec<_>>()
        .into_iter()
}

fn extract_name<N: Clone>(n: Node<N>) -> (N, Node<()>) {
    (n.node.clone(), n.map(|_| ()))
}

fn shadows_builtin((name, node): (&Id, &Node<()>)) -> Option<SchemaWarning> {
    if EXTENSIONS.contains(&name.as_ref()) || BUILTIN_TYPES.contains(&name.as_ref()) {
        Some(
            ShadowsBuiltinWarning {
                name: name.to_smolstr(),
                loc: node.loc.clone(),
            }
            .into(),
        )
    } else {
        None
    }
}

fn build_namespace_bindings<'a>(
    namespaces: impl Iterator<Item = &'a Namespace>,
) -> Result<HashMap<Option<Name>, NamespaceRecord>, ToJsonSchemaErrors> {
    let mut map = HashMap::new();
    for (name, record) in collect_all_errors(namespaces.map(NamespaceRecord::new))? {
        update_namespace_record(&mut map, name, record)?;
    }
    Ok(map)
}

fn update_namespace_record(
    map: &mut HashMap<Option<Name>, NamespaceRecord>,
    name: Option<Name>,
    record: NamespaceRecord,
) -> Result<(), ToJsonSchemaErrors> {
    match map.entry(name.clone()) {
        Entry::Occupied(entry) => Err(ToJsonSchemaError::DuplicateNameSpaces {
            namespace_id: name.map_or("".into(), |n| n.to_smolstr()),
            loc1: record.loc,
            loc2: entry.get().loc.clone(),
        }
        .into()),
        Entry::Vacant(entry) => {
            entry.insert(record);
            Ok(())
        }
    }
}

fn partition_decls(
    decls: &[Node<Declaration>],
) -> (Vec<&EntityDecl>, Vec<&ActionDecl>, Vec<&TypeDecl>) {
    let mut entities = vec![];
    let mut actions = vec![];
    let mut types = vec![];

    for decl in decls.iter() {
        match &decl.node {
            Declaration::Entity(e) => entities.push(e),
            Declaration::Action(a) => actions.push(a),
            Declaration::Type(t) => types.push(t),
        }
    }

    (entities, actions, types)
}

fn into_partition_decls(
    decls: Vec<Node<Declaration>>,
) -> (Vec<EntityDecl>, Vec<ActionDecl>, Vec<TypeDecl>) {
    let mut entities = vec![];
    let mut actions = vec![];
    let mut types = vec![];

    for decl in decls.into_iter() {
        match decl.node {
            Declaration::Entity(e) => entities.push(e),
            Declaration::Action(a) => actions.push(a),
            Declaration::Type(t) => types.push(t),
        }
    }

    (entities, actions, types)
}
