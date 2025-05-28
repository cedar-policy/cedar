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

//! Convert a schema into the JSON format

use std::collections::HashMap;

use cedar_policy_core::{
    ast::{Annotations, Id, Name, UnreservedId},
    extensions::Extensions,
    parser::{AsLocRef, IntoMaybeLoc, Loc, MaybeLoc, Node},
};
use itertools::Either;
use nonempty::NonEmpty;
use smol_str::{SmolStr, ToSmolStr};
use std::collections::hash_map::Entry;

use super::{
    ast::{
        ActionDecl, Annotated, AppDecl, AttrDecl, Decl, Declaration, EntityDecl, Namespace,
        PRAppDecl, Path, QualName, Schema, Type, TypeDecl, BUILTIN_TYPES, PR,
    },
    err::{schema_warnings, SchemaWarning, ToJsonSchemaError, ToJsonSchemaErrors},
};
use crate::{
    cedar_schema,
    json_schema::{self, CommonType},
    RawName,
};

impl From<cedar_schema::Path> for RawName {
    fn from(p: cedar_schema::Path) -> Self {
        RawName::from_name(p.into())
    }
}

/// Convert a schema AST into the JSON representation.
/// This will let you subsequently decode that into the Validator AST for Schemas ([`crate::ValidatorSchema`]).
/// On success, this function returns a tuple containing:
///     * The `json_schema::Fragment`
///     * An iterator of warnings that were generated
///
/// TODO(#1085): These warnings should be generated later in the process, such
/// that we apply the same checks to JSON and Cedar schemas
pub fn cedar_schema_to_json_schema(
    schema: Schema,
    extensions: &Extensions<'_>,
) -> Result<
    (
        json_schema::Fragment<RawName>,
        impl Iterator<Item = SchemaWarning>,
    ),
    ToJsonSchemaErrors,
> {
    // combine all of the declarations in unqualified (empty) namespaces into a
    // single unqualified namespace
    //
    // TODO(#1086): If we want to allow reopening a namespace within the same
    // (Cedar) schema fragment, then in this step we would also need to combine
    // namespaces with matching non-empty names, so that all definitions from
    // that namespace make it into the JSON schema structure under that
    // namespace's key.
    let (qualified_namespaces, unqualified_namespace) = split_unqualified_namespace(schema);
    // Create a single iterator for all namespaces
    let all_namespaces = qualified_namespaces
        .chain(unqualified_namespace)
        .collect::<Vec<_>>();

    let names = build_namespace_bindings(all_namespaces.iter().map(|ns| &ns.data))?;
    let warnings = compute_namespace_warnings(&names, extensions);
    let fragment = collect_all_errors(all_namespaces.into_iter().map(convert_namespace))?.collect();
    Ok((
        json_schema::Fragment(fragment),
        warnings.collect::<Vec<_>>().into_iter(),
    ))
}

/// Is the given [`Id`] the name of a valid extension type, given the currently active [`Extensions`]
fn is_valid_ext_type(ty: &Id, extensions: &Extensions<'_>) -> bool {
    extensions
        .ext_types()
        .filter(|ext_ty| ext_ty.as_ref().is_unqualified()) // if there are any qualified extension type names, we don't care, because we're looking for an unqualified name `ty`
        .any(|ext_ty| ty == ext_ty.basename_as_ref())
}

/// Convert a `Type` into the JSON representation of the type.
pub fn cedar_type_to_json_type(ty: Node<Type>) -> json_schema::Type<RawName> {
    let variant = match ty.node {
        Type::Set(t) => json_schema::TypeVariant::Set {
            element: Box::new(cedar_type_to_json_type(*t)),
        },
        Type::Ident(p) => json_schema::TypeVariant::EntityOrCommon {
            type_name: RawName::from(p),
        },
        Type::Record(fields) => json_schema::TypeVariant::Record(json_schema::RecordType {
            attributes: fields.into_iter().map(convert_attr_decl).collect(),
            additional_attributes: false,
        }),
    };
    json_schema::Type::Type {
        ty: variant,
        loc: ty.loc,
    }
}

// Split namespaces into two groups: named namespaces and the implicit unqualified namespace
// The rhs of the tuple will be [`None`] if there are no items in the unqualified namespace.
fn split_unqualified_namespace(
    namespaces: impl IntoIterator<Item = Annotated<Namespace>>,
) -> (
    impl Iterator<Item = Annotated<Namespace>>,
    Option<Annotated<Namespace>>,
) {
    // First split every namespace into those with explicit names and those without
    let (qualified, unqualified): (Vec<_>, Vec<_>) =
        namespaces.into_iter().partition(|n| n.data.name.is_some());

    // Now combine all the decls in namespaces without names into one unqualified namespace
    let mut unqualified_decls = vec![];
    for mut unqualified_namespace in unqualified.into_iter() {
        unqualified_decls.append(&mut unqualified_namespace.data.decls);
    }

    if unqualified_decls.is_empty() {
        (qualified.into_iter(), None)
    } else {
        let unqual = Namespace {
            name: None,
            decls: unqualified_decls,
            loc: None,
        };
        (
            qualified.into_iter(),
            Some(Annotated {
                data: unqual,
                annotations: Annotations::new(),
            }),
        )
    }
}

/// Converts a CST namespace to a JSON namespace
fn convert_namespace(
    namespace: Annotated<Namespace>,
) -> Result<(Option<Name>, json_schema::NamespaceDefinition<RawName>), ToJsonSchemaErrors> {
    let ns_name = namespace
        .data
        .name
        .clone()
        .map(|p| {
            let internal_name = RawName::from(p.clone()).qualify_with(None); // namespace names are always written already-fully-qualified in the Cedar schema syntax
            Name::try_from(internal_name)
                .map_err(|e| ToJsonSchemaError::reserved_name(e.name(), p.loc().into_maybe_loc()))
        })
        .transpose()?;
    let def = namespace.try_into()?;
    Ok((ns_name, def))
}

impl TryFrom<Annotated<Namespace>> for json_schema::NamespaceDefinition<RawName> {
    type Error = ToJsonSchemaErrors;

    fn try_from(
        n: Annotated<Namespace>,
    ) -> Result<json_schema::NamespaceDefinition<RawName>, Self::Error> {
        // Partition the decls into entities, actions, and common types
        let (entity_types, action, common_types) = into_partition_decls(n.data.decls);

        // Convert entity type decls, collecting all errors
        let entity_types = collect_all_errors(entity_types.into_iter().map(convert_entity_decl))?
            .flatten()
            .collect();

        // Convert action decls, collecting all errors
        let actions = collect_all_errors(action.into_iter().map(convert_action_decl))?
            .flatten()
            .collect();

        // Convert common type decls
        let common_types = common_types
            .into_iter()
            .map(|decl| {
                let name_loc = decl.data.node.name.loc.clone();
                let id = UnreservedId::try_from(decl.data.node.name.node)
                    .map_err(|e| ToJsonSchemaError::reserved_name(e.name(), name_loc.clone()))?;
                let ctid = json_schema::CommonTypeId::new(id)
                    .map_err(|e| ToJsonSchemaError::reserved_keyword(&e.id, name_loc))?;
                Ok((
                    ctid,
                    CommonType {
                        ty: cedar_type_to_json_type(decl.data.node.def),
                        annotations: decl.annotations.into(),
                        loc: decl.data.loc,
                    },
                ))
            })
            .collect::<Result<_, ToJsonSchemaError>>()?;

        Ok(json_schema::NamespaceDefinition {
            common_types,
            entity_types,
            actions,
            annotations: n.annotations.into(),
            #[cfg(feature = "extended-schema")]
            loc: n.data.loc,
        })
    }
}

/// Converts action type decls
fn convert_action_decl(
    a: Annotated<Node<ActionDecl>>,
) -> Result<impl Iterator<Item = (SmolStr, json_schema::ActionType<RawName>)>, ToJsonSchemaErrors> {
    let ActionDecl {
        names,
        parents,
        app_decls,
    } = a.data.node;
    // Create the internal type from the 'applies_to' clause and 'member_of'
    let applies_to = app_decls
        .map(|decls| convert_app_decls(&names.first().node, names.first().loc.as_loc_ref(), decls))
        .transpose()?
        .unwrap_or_else(|| json_schema::ApplySpec {
            resource_types: vec![],
            principal_types: vec![],
            context: json_schema::AttributesOrContext::default(),
        });
    let member_of = parents.map(|parents| parents.into_iter().map(convert_qual_name).collect());

    Ok(names.into_iter().map(move |name| {
        let ty = json_schema::ActionType {
            attributes: None, // Action attributes are currently unsupported in the Cedar schema format
            applies_to: Some(applies_to.clone()),
            member_of: member_of.clone(),
            annotations: a.annotations.clone().into(),
            loc: a.data.loc.clone(),
            #[cfg(feature = "extended-schema")]
            defn_loc: name.loc,
        };
        (name.node, ty)
    }))
}

fn convert_qual_name(qn: Node<QualName>) -> json_schema::ActionEntityUID<RawName> {
    json_schema::ActionEntityUID::new(qn.node.path.map(Into::into), qn.node.eid)
}

/// Convert the applies to decls
/// # Arguments
/// * `name` - The (first) name of the action being declared
/// * `name_loc` - The location of that first name
fn convert_app_decls(
    name: &SmolStr,
    name_loc: Option<&Loc>,
    decls: Node<NonEmpty<Node<AppDecl>>>,
) -> Result<json_schema::ApplySpec<RawName>, ToJsonSchemaErrors> {
    // Split AppDecl's into context/principal/resource decls
    let (decls, _) = decls.into_inner();
    let mut principal_types: Option<Node<Vec<RawName>>> = None;
    let mut resource_types: Option<Node<Vec<RawName>>> = None;
    let mut context: Option<Node<json_schema::AttributesOrContext<RawName>>> = None;

    for decl in decls {
        match decl {
            Node {
                node: AppDecl::Context(context_decl),
                loc,
            } => match context {
                Some(existing_context) => {
                    return Err(ToJsonSchemaError::duplicate_context(
                        name,
                        existing_context.loc,
                        loc,
                    )
                    .into());
                }
                None => {
                    context = Some(Node::with_maybe_source_loc(
                        convert_context_decl(context_decl),
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
                    return Err(ToJsonSchemaError::duplicate_principal(
                        name,
                        existing_tys.loc,
                        loc,
                    )
                    .into());
                }
                None => match entity_tys {
                    None => {
                        return Err(ToJsonSchemaError::empty_principal(
                            name,
                            name_loc.into_maybe_loc(),
                            loc,
                        )
                        .into())
                    }
                    Some(entity_tys) => {
                        principal_types = Some(Node::with_maybe_source_loc(
                            entity_tys.iter().map(|n| n.clone().into()).collect(),
                            loc,
                        ))
                    }
                },
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
                    return Err(
                        ToJsonSchemaError::duplicate_resource(name, existing_tys.loc, loc).into(),
                    );
                }
                None => match entity_tys {
                    None => {
                        return Err(ToJsonSchemaError::empty_resource(
                            name,
                            name_loc.into_maybe_loc(),
                            loc,
                        )
                        .into())
                    }
                    Some(entity_tys) => {
                        resource_types = Some(Node::with_maybe_source_loc(
                            entity_tys.iter().map(|n| n.clone().into()).collect(),
                            loc,
                        ))
                    }
                },
            },
        }
    }
    Ok(json_schema::ApplySpec {
        resource_types: resource_types
            .map(|node| node.node)
            .ok_or_else(|| ToJsonSchemaError::no_resource(&name, name_loc.into_maybe_loc()))?,
        principal_types: principal_types
            .map(|node| node.node)
            .ok_or_else(|| ToJsonSchemaError::no_principal(&name, name_loc.into_maybe_loc()))?,
        context: context.map(|c| c.node).unwrap_or_default(),
    })
}

fn convert_id(node: Node<Id>) -> Result<UnreservedId, ToJsonSchemaError> {
    UnreservedId::try_from(node.node)
        .map_err(|e| ToJsonSchemaError::reserved_name(e.name(), node.loc))
}

/// Convert Entity declarations
fn convert_entity_decl(
    e: Annotated<Node<EntityDecl>>,
) -> Result<
    impl Iterator<Item = (UnreservedId, json_schema::EntityType<RawName>)>,
    ToJsonSchemaErrors,
> {
    // 2025-02-28: this Clippy nursery lint is bugged, makes a suggestion that does not compile
    #[allow(clippy::needless_collect)]
    let names: Vec<Node<Id>> = e.data.node.names().cloned().collect();
    let etype = json_schema::EntityType {
        kind: match e.data.node {
            EntityDecl::Enum(d) => json_schema::EntityTypeKind::Enum {
                choices: d.choices.map(|n| n.node),
            },
            EntityDecl::Standard(d) => {
                // First build up the defined entity type
                json_schema::EntityTypeKind::Standard(json_schema::StandardEntityType {
                    member_of_types: d.member_of_types.into_iter().map(RawName::from).collect(),
                    shape: convert_attr_decls(d.attrs),
                    tags: d.tags.map(cedar_type_to_json_type),
                })
            }
        },
        annotations: e.annotations.into(),
        loc: e.data.loc,
    };

    // Then map over all of the bound names
    collect_all_errors(
        names
            .into_iter()
            .map(move |name| -> Result<_, ToJsonSchemaErrors> {
                Ok((convert_id(name)?, etype.clone()))
            }),
    )
}

/// Create a [`json_schema::AttributesOrContext`] from a series of `AttrDecl`s
fn convert_attr_decls(
    attrs: Node<impl IntoIterator<Item = Node<Annotated<AttrDecl>>>>,
) -> json_schema::AttributesOrContext<RawName> {
    json_schema::AttributesOrContext(json_schema::Type::Type {
        ty: json_schema::TypeVariant::Record(json_schema::RecordType {
            attributes: attrs.node.into_iter().map(convert_attr_decl).collect(),
            additional_attributes: false,
        }),
        loc: attrs.loc,
    })
}

/// Create a context decl
fn convert_context_decl(
    decl: Either<Path, Node<Vec<Node<Annotated<AttrDecl>>>>>,
) -> json_schema::AttributesOrContext<RawName> {
    json_schema::AttributesOrContext(match decl {
        Either::Left(p) => json_schema::Type::CommonTypeRef {
            loc: p.loc().into_maybe_loc(),
            type_name: p.into(),
        },
        Either::Right(attrs) => json_schema::Type::Type {
            ty: json_schema::TypeVariant::Record(json_schema::RecordType {
                attributes: attrs.node.into_iter().map(convert_attr_decl).collect(),
                additional_attributes: false,
            }),
            loc: attrs.loc,
        },
    })
}

/// Convert an attribute type from an `AttrDecl`
fn convert_attr_decl(
    attr: Node<Annotated<AttrDecl>>,
) -> (SmolStr, json_schema::TypeOfAttribute<RawName>) {
    (
        attr.node.data.name.node,
        json_schema::TypeOfAttribute {
            ty: cedar_type_to_json_type(attr.node.data.ty),
            required: attr.node.data.required,
            annotations: attr.node.annotations.into(),
            #[cfg(feature = "extended-schema")]
            loc: attr.loc,
        },
    )
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

#[derive(Default)]
struct NamespaceRecord {
    entities: HashMap<Id, Node<()>>,
    common_types: HashMap<Id, Node<()>>,
    loc: MaybeLoc,
}

impl NamespaceRecord {
    fn new(namespace: &Namespace) -> Result<(Option<Name>, Self), ToJsonSchemaErrors> {
        let ns = namespace
            .name
            .clone()
            .map(|n| {
                let internal_name = RawName::from(n.clone()).qualify_with(None); // namespace names are already fully-qualified
                Name::try_from(internal_name).map_err(|e| {
                    ToJsonSchemaError::reserved_name(e.name(), n.loc().into_maybe_loc())
                })
            })
            .transpose()?;
        let (entities, actions, types) = partition_decls(&namespace.decls);

        let entities = collect_decls(
            entities
                .into_iter()
                .flat_map(|decl| decl.names().cloned())
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
            loc: namespace
                .name
                .as_ref()
                .and_then(|n| n.loc().into_maybe_loc()),
        };

        Ok((ns, record))
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
            Entry::Occupied(entry) => Err(ToJsonSchemaError::duplicate_decls(
                &key,
                entry.get().loc.clone(),
                node.loc,
            )),
            Entry::Vacant(entry) => {
                entry.insert(node);
                Ok(())
            }
        }?;
    }
    Ok(map)
}

fn compute_namespace_warnings<'a>(
    fragment: &'a HashMap<Option<Name>, NamespaceRecord>,
    extensions: &'a Extensions<'a>,
) -> impl Iterator<Item = SchemaWarning> + 'a {
    fragment
        .values()
        .flat_map(move |nr| make_warning_for_shadowing(nr, extensions))
}

fn make_warning_for_shadowing<'a>(
    n: &'a NamespaceRecord,
    extensions: &'a Extensions<'a>,
) -> impl Iterator<Item = SchemaWarning> + 'a {
    let mut warnings = vec![];
    for (common_name, common_src_node) in n.common_types.iter() {
        // Check if it shadows a entity name in the same namespace
        if let Some(entity_src_node) = n.entities.get(common_name) {
            let warning = schema_warnings::ShadowsEntityWarning {
                name: common_name.to_smolstr(),
                entity_loc: entity_src_node.loc.clone(),
                common_loc: common_src_node.loc.clone(),
            }
            .into();
            warnings.push(warning);
        }
        // Check if it shadows a builtin
        if let Some(warning) = shadows_builtin(common_name, common_src_node, extensions) {
            warnings.push(warning);
        }
    }
    let entity_shadows = n
        .entities
        .iter()
        .filter_map(move |(name, node)| shadows_builtin(name, node, extensions));
    warnings.into_iter().chain(entity_shadows)
}

fn extract_name<N: Clone>(n: Node<N>) -> (N, Node<()>) {
    (n.node.clone(), n.map(|_| ()))
}

fn shadows_builtin(
    name: &Id,
    node: &Node<()>,
    extensions: &Extensions<'_>,
) -> Option<SchemaWarning> {
    if is_valid_ext_type(name, extensions) || BUILTIN_TYPES.contains(&name.as_ref()) {
        Some(
            schema_warnings::ShadowsBuiltinWarning {
                name: name.to_smolstr(),
                loc: node.loc.clone(),
            }
            .into(),
        )
    } else {
        None
    }
}

// Essentially index `NamespaceRecord`s by the namespace
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
        Entry::Occupied(entry) => Err(ToJsonSchemaError::duplicate_namespace(
            &name.map_or("".into(), |n| n.to_smolstr()),
            record.loc,
            entry.get().loc.clone(),
        )
        .into()),
        Entry::Vacant(entry) => {
            entry.insert(record);
            Ok(())
        }
    }
}

fn partition_decls(
    decls: &[Annotated<Node<Declaration>>],
) -> (Vec<&EntityDecl>, Vec<&ActionDecl>, Vec<&TypeDecl>) {
    let mut entities = vec![];
    let mut actions = vec![];
    let mut types = vec![];

    for decl in decls.iter() {
        match &decl.data.node {
            Declaration::Entity(e) => entities.push(e),
            Declaration::Action(a) => actions.push(a),
            Declaration::Type(t) => types.push(t),
        }
    }

    (entities, actions, types)
}

#[allow(clippy::type_complexity)]
fn into_partition_decls(
    decls: impl IntoIterator<Item = Annotated<Node<Declaration>>>,
) -> (
    Vec<Annotated<Node<EntityDecl>>>,
    Vec<Annotated<Node<ActionDecl>>>,
    Vec<Annotated<Node<TypeDecl>>>,
) {
    let mut entities = vec![];
    let mut actions = vec![];
    let mut types = vec![];

    for decl in decls.into_iter() {
        let loc = decl.data.loc;
        match decl.data.node {
            Declaration::Entity(e) => entities.push(Annotated {
                data: Node { node: e, loc },
                annotations: decl.annotations,
            }),
            Declaration::Action(a) => actions.push(Annotated {
                data: Node { node: a, loc },
                annotations: decl.annotations,
            }),
            Declaration::Type(t) => types.push(Annotated {
                data: Node { node: t, loc },
                annotations: decl.annotations,
            }),
        }
    }

    (entities, actions, types)
}

#[cfg(test)]
mod preserves_source_locations {
    use super::*;
    use cool_asserts::assert_matches;
    use json_schema::{EntityType, EntityTypeKind};

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn entity_action_and_common_type_decls() {
        let (schema, _) = json_schema::Fragment::from_cedarschema_str(
            r#"
        namespace NS {
            type S = String;
            entity A;
            entity B in A;
            entity C in A {
                bool: Bool,
                s: S,
                a: Set<A>,
                b: { inner: B },
            };
            type AA = A;
            action Read, Write;
            action List in Read appliesTo {
                principal: [A],
                resource: [B, C],
                context: {
                    s: Set<S>,
                    ab: { a: AA, b: B },
                }
            };
        }
        "#,
            Extensions::all_available(),
        )
        .unwrap();
        let ns = schema
            .0
            .get(&Some(Name::parse_unqualified_name("NS").unwrap()))
            .expect("couldn't find namespace NS");

        let entity_a = ns
            .entity_types
            .get(&"A".parse().unwrap())
            .expect("couldn't find entity A");
        let entity_b = ns
            .entity_types
            .get(&"B".parse().unwrap())
            .expect("couldn't find entity B");
        let entity_c = ns
            .entity_types
            .get(&"C".parse().unwrap())
            .expect("couldn't find entity C");
        let ctype_s = ns
            .common_types
            .get(&json_schema::CommonTypeId::new("S".parse().unwrap()).unwrap())
            .expect("couldn't find common type S");
        let ctype_aa = ns
            .common_types
            .get(&json_schema::CommonTypeId::new("AA".parse().unwrap()).unwrap())
            .expect("couldn't find common type AA");
        let action_read = ns.actions.get("Read").expect("couldn't find action Read");
        let action_write = ns.actions.get("Write").expect("couldn't find action Write");
        let action_list = ns.actions.get("List").expect("couldn't find action List");

        assert_matches!(&entity_a.loc, Some(loc) => assert_matches!(loc.snippet(),
            Some("entity A;")
        ));
        assert_matches!(&entity_b.loc, Some(loc) => assert_matches!(loc.snippet(),
            Some("entity B in A;")
        ));
        assert_matches!(&entity_c.loc, Some(loc) => assert_matches!(loc.snippet(),
            Some("entity C in A {\n                bool: Bool,\n                s: S,\n                a: Set<A>,\n                b: { inner: B },\n            };")
        ));
        assert_matches!(&ctype_s.loc, Some(loc) => assert_matches!(loc.snippet(),
            Some("type S = String;")
        ));
        assert_matches!(&ctype_aa.loc, Some(loc) => assert_matches!(loc.snippet(),
            Some("type AA = A;")
        ));
        assert_matches!(&action_read.loc, Some(loc) => assert_matches!(loc.snippet(),
            Some("action Read, Write;")
        ));
        assert_matches!(&action_write.loc, Some(loc) => assert_matches!(loc.snippet(),
            Some("action Read, Write;")
        ));
        assert_matches!(&action_list.loc, Some(loc) => assert_matches!(loc.snippet(),
            Some("action List in Read appliesTo {\n                principal: [A],\n                resource: [B, C],\n                context: {\n                    s: Set<S>,\n                    ab: { a: AA, b: B },\n                }\n            };")
        ));
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn types() {
        let (schema, _) = json_schema::Fragment::from_cedarschema_str(
            r#"
        namespace NS {
            type S = String;
            entity A;
            entity B in A;
            entity C in A {
                bool: Bool,
                s: S,
                a: Set<A>,
                b: { inner: B },
            };
            type AA = A;
            action Read, Write;
            action List in Read appliesTo {
                principal: [A],
                resource: [B, C],
                context: {
                    s: Set<S>,
                    ab: { a: AA, b: B },
                }
            };
        }
        "#,
            Extensions::all_available(),
        )
        .unwrap();
        let ns = schema
            .0
            .get(&Some(Name::parse_unqualified_name("NS").unwrap()))
            .expect("couldn't find namespace NS");

        assert_matches!(ns
            .entity_types
            .get(&"C".parse().unwrap())
            .expect("couldn't find entity C"), EntityType { kind: EntityTypeKind::Standard(entityC), ..} => {
        assert_matches!(entityC.member_of_types.first().unwrap().loc(), Some(loc) => {
            assert_matches!(loc.snippet(), Some("A"));
        });
        assert_matches!(entityC.shape.0.loc(), Some(loc) => {
            assert_matches!(loc.snippet(), Some("{\n                bool: Bool,\n                s: S,\n                a: Set<A>,\n                b: { inner: B },\n            }"));
        });
        assert_matches!(&entityC.shape.0, json_schema::Type::Type { ty: json_schema::TypeVariant::Record(rty), .. } => {
            let b = rty.attributes.get("bool").expect("couldn't find attribute `bool` on entity C");
            assert_matches!(b.ty.loc(), Some(loc) => {
                assert_matches!(loc.snippet(), Some("Bool"));
            });
            let s = rty.attributes.get("s").expect("couldn't find attribute `s` on entity C");
            assert_matches!(s.ty.loc(), Some(loc) => {
                assert_matches!(loc.snippet(), Some("S"));
            });
            let a = rty.attributes.get("a").expect("couldn't find attribute `a` on entity C");
            assert_matches!(a.ty.loc(), Some(loc) => {
                assert_matches!(loc.snippet(), Some("Set<A>"));
            });
            assert_matches!(&a.ty, json_schema::Type::Type { ty: json_schema::TypeVariant::Set { element }, .. } => {
                assert_matches!(element.loc(), Some(loc) => {
                    assert_matches!(loc.snippet(), Some("A"));
                });
            });
            let b = rty.attributes.get("b").expect("couldn't find attribute `b` on entity C");
            assert_matches!(b.ty.loc(), Some(loc) => {
                assert_matches!(loc.snippet(), Some("{ inner: B }"));
            });
            assert_matches!(&b.ty, json_schema::Type::Type { ty: json_schema::TypeVariant::Record(b_rty), .. } => {
                let inner = b_rty.attributes.get("inner").expect("couldn't find inner attribute");
                assert_matches!(inner.ty.loc(), Some(loc) => {
                    assert_matches!(loc.snippet(), Some("B"));
                });
            });
        });});

        let ctype_aa = ns
            .common_types
            .get(&json_schema::CommonTypeId::new("AA".parse().unwrap()).unwrap())
            .expect("couldn't find common type AA");
        assert_matches!(ctype_aa.ty.loc(), Some(loc) => {
            assert_matches!(loc.snippet(), Some("A"));
        });

        let action_list = ns.actions.get("List").expect("couldn't find action List");
        assert_matches!(&action_list.applies_to, Some(appliesto) => {
            assert_matches!(appliesto.principal_types.first().expect("principal types were empty").loc(), Some(loc) => {
                assert_matches!(loc.snippet(), Some("A"));
            });
            assert_matches!(appliesto.resource_types.first().expect("resource types were empty").loc(), Some(loc) => {
                assert_matches!(loc.snippet(), Some("B"));
            });
            assert_matches!(appliesto.context.loc(), Some(loc) => {
                assert_matches!(loc.snippet(), Some("{\n                    s: Set<S>,\n                    ab: { a: AA, b: B },\n                }"));
            });
            assert_matches!(&appliesto.context.0, json_schema::Type::Type { ty: json_schema::TypeVariant::Record(rty), .. } => {
                let s = rty.attributes.get("s").expect("couldn't find attribute `s` on context");
                assert_matches!(s.ty.loc(), Some(loc) => {
                    assert_matches!(loc.snippet(), Some("Set<S>"));
                });
                let ab = rty.attributes.get("ab").expect("couldn't find attribute `ab` on context");
                assert_matches!(ab.ty.loc(), Some(loc) => {
                    assert_matches!(loc.snippet(), Some("{ a: AA, b: B }"));
                });
            });
        });
    }
}
