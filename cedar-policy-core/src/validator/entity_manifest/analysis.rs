use std::{collections::HashMap, rc::Rc};

use smol_str::SmolStr;

use crate::ast::{BinaryOp, Expr, ExprKind, Literal, UnaryOp, Var};
use crate::validator::{
    entity_manifest::{
        AccessDag, AccessPath, AccessPathVariant, AccessPaths, EntityManifestError, EntityRoot,
        PartialExpressionError, UnsupportedCedarFeatureError,
    },
    types::{EntityRecordKind, Type},
};

/// Represents [`AccessPath`]s possibly
/// wrapped in record or set literals.
///
/// This allows the Entity Manifest to soundly handle
/// data that is wrapped in record or set literals, then used in equality
/// operators or dereferenced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum WrappedAccessPaths {
    /// No access paths are needed.
    #[default]
    Empty,
    /// A single access path, starting with a cedar variable.
    AccessPath(AccessPath),
    /// The union of two [`WrappedAccessPaths`], denoting that
    /// all access paths from both are required.
    /// This is useful for join points in the analysis (`if`, set literals, etc.)
    Union(Rc<WrappedAccessPaths>, Rc<WrappedAccessPaths>),
    /// A record literal, each field having access paths.
    RecordLiteral(HashMap<SmolStr, Rc<WrappedAccessPaths>>),
    /// A set literal containing access paths.
    /// Used to note that this type is wrapped in a literal set.
    SetLiteral(Rc<WrappedAccessPaths>),
    /// Intermediate values like if conditions may not be returned,
    /// but we still need to load them into the entity store.
    WithDroppedPaths {
        paths: Rc<WrappedAccessPaths>,
        dropped: Rc<WrappedAccessPaths>,
    },
}

impl WrappedAccessPaths {
    /// Create an analysis result that starts with a cedar variable
    pub fn from_root(root: EntityRoot, store: &mut AccessDag) -> Self {
        // Create a new AccessPath from the root
        let variant = match &root {
            EntityRoot::Literal(euid) => AccessPathVariant::Literal(euid.clone()),
            EntityRoot::Var(var) => AccessPathVariant::Var(*var),
        };

        // Add the path to the store
        let path = store.add_path(variant);

        WrappedAccessPaths::AccessPath(path.clone())
    }

    /// Add an ancestors required path for each of the wrapped access paths given.
    /// This function converts the ancestors_trie to AccessPaths and adds ancestor
    /// requirements to the current paths.
    ///
    /// Panics if access_paths contains a record or set literal. The typechecker
    /// should prevent this, since ancestors are required of literals.
    pub(crate) fn with_ancestors_required(
        self: Rc<Self>,
        // The access paths for the ancestors
        access_paths: &Rc<WrappedAccessPaths>,
        store: &mut AccessDag,
    ) -> Rc<Self> {
        // compute cross product of the access paths and the ancestors
        let of_access_paths = self.returned_access_paths().expect(
            "Ancestors required paths should not be record or set literals, typechecker should prevent this",
        );
        let ancestors_access_paths = access_paths
            .returned_access_paths()
            .expect("Ancestors required paths should not be record or set literals, typechecker should prevent this");
        let mut access_paths = vec![];
        // cross product of the access paths
        for of_path in of_access_paths.paths() {
            for ancestor_path in ancestors_access_paths.paths() {
                // Create a new ancestor required path
                let ancestor_variant = AccessPathVariant::Ancestor {
                    of: of_path.clone(),
                    ancestor: ancestor_path.clone(),
                };
                // Add the new path to the store
                let new_path = store.add_path(ancestor_variant);
                // Add the new path to the access paths
                access_paths.push(new_path);
            }
        }
        // Return the new wrapped access paths with a drop
        let mut access_paths_wrapped = Rc::new(WrappedAccessPaths::Empty);
        // Add the new access paths to the result
        for path in access_paths {
            access_paths_wrapped = access_paths_wrapped
                .with_dropped_paths(Rc::new(WrappedAccessPaths::AccessPath(path)));
        }
        self.with_dropped_paths(access_paths_wrapped)
    }

    pub(crate) fn with_dropped_paths(
        self: &Rc<Self>,
        // The paths that were dropped
        dropped: Rc<Self>,
    ) -> Rc<Self> {
        Rc::new(WrappedAccessPaths::WithDroppedPaths {
            paths: self.clone(),
            dropped,
        })
    }

    /// Union this analysis result with another, taking the union of the resulting paths.
    /// Takes ownership of self and returns self after mutating it.
    pub(crate) fn union(self: Rc<Self>, other: Rc<Self>) -> Rc<Self> {
        // Create a union of the resulting paths
        Rc::new(WrappedAccessPaths::Union(self, other))
    }

    /// Convert the [`WrappedAccessPaths`] to a [`AccessPaths`].
    /// Returns [`None`] when the wrapped access paths represent a record or set literal.
    fn returned_access_paths(self: &Rc<Self>) -> Option<AccessPaths> {
        let mut access_paths = AccessPaths::default();
        if self.add_to_access_paths(&mut access_paths, false) {
            Some(access_paths)
        } else {
            None
        }
    }

    /// Get all access paths from this wrapped access paths,
    /// including dropped paths.
    fn all_access_paths(self: &Rc<Self>) -> AccessPaths {
        let mut access_paths = AccessPaths::default();
        self.add_to_access_paths(&mut access_paths, true);
        access_paths
    }

    fn add_to_access_paths(
        self: &Rc<Self>,
        add_to: &mut AccessPaths,
        include_dropped: bool,
    ) -> bool {
        match &**self {
            WrappedAccessPaths::Empty => true,
            WrappedAccessPaths::AccessPath(path) => {
                add_to.paths.insert(path.clone());
                true
            }
            WrappedAccessPaths::Union(left, right) => {
                // Both must succeed for the operation to be successful
                left.add_to_access_paths(add_to, include_dropped)
                    && right.add_to_access_paths(add_to, include_dropped)
            }
            WrappedAccessPaths::RecordLiteral(_) => false,
            WrappedAccessPaths::SetLiteral(_) => false,
            WrappedAccessPaths::WithDroppedPaths { paths, dropped } => {
                // If include_dropped is true, we include the dropped paths
                if include_dropped {
                    dropped.add_to_access_paths(add_to, include_dropped);
                }
                // We always add the paths, even if we don't include the dropped paths
                paths.add_to_access_paths(add_to, include_dropped)
            }
        }
    }

    /// Add accessing this attribute to all access paths
    fn get_or_has_attr(self: Rc<Self>, attr: &SmolStr, store: &mut AccessDag) -> Rc<Self> {
        Rc::new(match &*self {
            WrappedAccessPaths::AccessPath(access_path) => {
                // Create a new attribute access path
                let attr_variant = AccessPathVariant::Attribute {
                    of: access_path.clone(),
                    attr: attr.clone(),
                };
                // Add the new path to the store
                let new_path = store.add_path(attr_variant);
                // Return the new wrapped access path
                WrappedAccessPaths::AccessPath(new_path)
            }
            WrappedAccessPaths::RecordLiteral(record) => {
                if let Some(field) = record.get(attr) {
                    return Rc::clone(field);
                } else {
                    // otherwise, this is a `has` expression
                    // but the record literal didn't have it.
                    // do nothing in this case
                    WrappedAccessPaths::RecordLiteral(record.clone())
                }
            }
            #[allow(clippy::panic)]
            WrappedAccessPaths::SetLiteral(_) => {
                panic!("Attempted to dereference a set literal.")
            }
            WrappedAccessPaths::WithDroppedPaths { paths, dropped } => {
                WrappedAccessPaths::WithDroppedPaths {
                    paths: Rc::clone(paths).get_or_has_attr(attr, store),
                    dropped: Rc::clone(dropped),
                }
            }
            WrappedAccessPaths::Empty => WrappedAccessPaths::Empty,
            WrappedAccessPaths::Union(left, right) => WrappedAccessPaths::Union(
                Rc::clone(left).get_or_has_attr(attr, store),
                Rc::clone(right).get_or_has_attr(attr, store),
            ),
        })
    }

    /// For equality or containment checks, all paths in the type
    /// are required.
    /// This function extends the paths with the fields mentioned
    /// by the type, dropping them afterwards since type checks result in boolean values.
    fn require_full_type(self: &Rc<Self>, ty: &Type, store: &mut AccessDag) -> Rc<Self> {
        match &**self {
            WrappedAccessPaths::AccessPath(path) => {
                // Use type_to_access_paths to compute the full access paths for the type
                // and add them to the store
                self.with_dropped_paths(type_to_access_paths(ty, store, path))
            }
            WrappedAccessPaths::RecordLiteral(literal_fields) => match ty {
                Type::EntityOrRecord(EntityRecordKind::Record {
                    attrs: record_attrs,
                    ..
                }) => {
                    let mut res = self.clone();
                    for (attr, attr_ty) in record_attrs.iter() {
                        // PANIC SAFETY: Record literals should have attributes that match the type.
                        #[allow(clippy::panic)]
                        if let Some(field) = literal_fields.get(attr) {
                            res = res.with_dropped_paths(
                                field.require_full_type(&attr_ty.attr_type, store),
                            )
                        } else {
                            panic!("Missing field {attr} in record literal");
                        }
                    }
                    res
                }
                // PANIC SAFETY: Typechecking should identify record literals as record types.
                #[allow(clippy::panic)]
                _ => {
                    panic!("Found record literal when expected {} type", ty);
                }
            },
            WrappedAccessPaths::SetLiteral(elements) => match ty {
                Type::Set { element_type } => {
                    // PANIC SAFETY: Typechecking should give concrete types for set elements.
                    #[allow(clippy::expect_used)]
                    let ele_type = element_type
                        .as_ref()
                        .expect("Expected concrete set type after typechecking");
                    self.with_dropped_paths(
                        self.with_dropped_paths(elements.require_full_type(ele_type, store)),
                    )
                }
                // PANIC SAFETY: Typechecking should identify set literals as set types.
                #[allow(clippy::panic)]
                _ => {
                    panic!("Found set literal when expected {} type", ty);
                }
            },
            WrappedAccessPaths::Empty => self.clone(),
            WrappedAccessPaths::Union(left, right) => self
                .with_dropped_paths(left.require_full_type(ty, store))
                .with_dropped_paths(right.require_full_type(ty, store)),
            WrappedAccessPaths::WithDroppedPaths { paths, dropped: _dropped } => {
                self.with_dropped_paths(paths.require_full_type(ty, store))
            }
           
        }
    }
}

/// Compute the full access paths required for the type and add them to the the wrapped access paths as dropped paths.
fn type_to_access_paths(
    ty: &Type,
    store: &mut AccessDag,
    path: &AccessPath,
) -> Rc<WrappedAccessPaths> {
    match ty {
        // if it's not an entity or record, slice ends here
        Type::ExtensionType { .. }
        | Type::Never
        | Type::True
        | Type::False
        | Type::Primitive { .. }
        | Type::Set { .. } => Rc::new(WrappedAccessPaths::Empty),
        Type::EntityOrRecord(record_type) => {
            entity_or_record_to_access_paths(record_type, store, path)
        }
    }
}

/// Compute the full access paths for the given entity or record type and add them to the store.
fn entity_or_record_to_access_paths(
    ty: &EntityRecordKind,
    store: &mut AccessDag,
    path: &AccessPath,
) -> Rc<WrappedAccessPaths> {
    match ty {
        EntityRecordKind::ActionEntity { attrs, .. } | EntityRecordKind::Record { attrs, .. } => {
            let mut paths = Rc::new(WrappedAccessPaths::default());
            for (attr_name, attr_type) in attrs.iter() {
                // Create a new path for this attribute
                let attr_variant = AccessPathVariant::Attribute {
                    of: path.clone(),
                    attr: attr_name.clone(),
                };
                let attr_path = store.add_path(attr_variant);

                paths = paths.with_dropped_paths(
                    Rc::new(WrappedAccessPaths::AccessPath(attr_path.clone())),
                );

                // Recursively process the attribute's type
                let attr_paths = type_to_access_paths(&attr_type.attr_type, store, &attr_path);
                paths = paths.with_dropped_paths(attr_paths);
            }
            paths
        }
        EntityRecordKind::Entity(_) | EntityRecordKind::AnyEntity => {
            // no need to load data for entities, which are compared using ids
            WrappedAccessPaths::Empty.into()
        }
    }
}
