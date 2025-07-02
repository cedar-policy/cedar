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
}

/// During Entity Manifest analysis, each sub-expression
/// produces an [`EntityManifestAnalysisResult`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct EntityManifestAnalysisResult {
    /// Stores all of the paths that were accessed.
    ///
    /// Intermediate paths may be used in
    /// auxiliary computation of the expression (an if statement's condition for example),
    /// so it's important to consider all the paths in the store.
    pub(crate) accessed_paths: AccessPaths,
    /// `resulting_paths` stores the set of values this expression could evaluate to
    /// represented symbolically as data paths.
    /// See [`WrappedAccessPaths`] for more details.
    pub(crate) resulting_paths: Rc<WrappedAccessPaths>,
}

impl EntityManifestAnalysisResult {
    /// Drop the resulting paths part of the analysis.
    /// This is necessary when the expression is a primitive value, so it
    /// can't be dereferenced.
    pub fn empty_paths(mut self) -> Self {
        self.resulting_paths = Default::default();
        self
    }

    /// Create an analysis result that starts with a cedar variable
    pub fn from_root(root: EntityRoot, store: &mut AccessDag) -> Self {
        // Create a new AccessPath from the root
        let variant = match &root {
            EntityRoot::Literal(euid) => AccessPathVariant::Literal(euid.clone()),
            EntityRoot::Var(var) => AccessPathVariant::Var(*var),
        };

        // Add the path to the store
        let path = store.add_path(variant);

        // Create the resulting_paths
        let resulting_paths = Rc::new(WrappedAccessPaths::AccessPath(path.clone()));
        let accessed_paths = AccessPaths::from_path(path);

        Self {
            accessed_paths,
            resulting_paths,
        }
    }

    /// Extend all the access paths with this attribute,
    /// adding all the new paths to the global store.
    pub fn get_or_has_attr(mut self, attr: &SmolStr, store: &mut AccessDag) -> Self {
        self.resulting_paths = self.resulting_paths.get_or_has_attr(attr, store);

        // ensure that all the resulting access paths are in the accessed set
        if let Some(paths) = self.resulting_paths.to_access_paths() {
            self.accessed_paths.extend(paths)
        }

        self
    }

    /// Add an ancestors required path for each of the wrapped access paths given.
    /// This function converts the ancestors_trie to AccessPaths and adds ancestor
    /// requirements to the current paths.
    ///
    /// Panics if access_paths contains a record or set literal. The typechecker
    /// should prevent this, since ancestors are required of literals.
    pub(crate) fn with_ancestors_required(
        mut self,
        // The access paths for the ancestors
        access_paths: &Rc<WrappedAccessPaths>,
        store: &mut AccessDag,
    ) -> Self {
        // Convert the ancestors_trie to AccessPaths
        // PANIC SAFETY: The typechecker should ensure that the rhs of `in` is entity typed,
        // and so can be converted to AccessPaths (i.e., it doesn't contain record or set literals).
        #[allow(clippy::unwrap_used)]
        let access_paths = access_paths.to_access_paths().unwrap();

        // PANIC SAFETY: The typechecker shoudl ensure the lhs of `in` is entity typed.
        #[allow(clippy::unwrap_used)]
        let my_paths = self.resulting_paths.to_access_paths().unwrap();

        // For each path in the resulting_paths, add an ancestor relationship with each path from ancestors_trie
        for of in &my_paths.paths {
            for ancestor_path in &access_paths.paths {
                // Create an Ancestor variant that links the self_path to the ancestor_path
                let ancestor_variant = AccessPathVariant::Ancestor {
                    of: of.clone(),
                    ancestor: ancestor_path.clone(),
                };

                // Add this new path to the store
                let res = store.add_path(ancestor_variant);
                // Add the path to accessed_paths
                self.accessed_paths.insert(res);
            }
        }

        self
    }

    /// For equality or containment checks, all paths in the type
    /// are required.
    /// This function extends the paths with the fields mentioned
    /// by the type, adding these to the internal store.
    ///
    /// It also drops the resulting paths, since these checks result
    /// in booleans.
    pub(crate) fn full_type_required(&mut self, ty: &Type, store: &mut AccessDag) {
        let type_paths = self.resulting_paths.full_type_required(ty, store);
        self.accessed_paths.extend(type_paths);
        self.resulting_paths = Default::default();
    }

    /// Union this analysis result with another, taking the union of the resulting paths.
    /// Takes ownership of self and returns self after mutating it.
    pub(crate) fn union(mut self, other: Self) -> Self {
        // Extend the accessed paths
        self.accessed_paths.extend(other.accessed_paths);

        // Create a union of the resulting paths
        self.resulting_paths = Rc::new(WrappedAccessPaths::Union(
            Rc::clone(&self.resulting_paths),
            other.resulting_paths,
        ));

        self
    }
}

impl WrappedAccessPaths {
    /// Convert the [`WrappedAccessPaths`] to a [`AccessPaths`].
    /// Returns [`None`] when the wrapped access paths represent a record or set literal.
    fn to_access_paths(self: &Rc<Self>) -> Option<AccessPaths> {
        let mut access_paths = AccessPaths::default();
        if self.add_to_access_paths(&mut access_paths) {
            Some(access_paths)
        } else {
            None
        }
    }

    /// Adds the access paths from this WrappedAccessPaths to the provided AccessPaths collection.
    /// Returns true if successful (no record or set literals encountered), false otherwise.
    fn add_to_access_paths(self: &Rc<Self>, paths: &mut AccessPaths) -> bool {
        match &**self {
            WrappedAccessPaths::Empty => true,
            WrappedAccessPaths::AccessPath(path) => {
                paths.paths.insert(path.clone());
                true
            }
            WrappedAccessPaths::Union(left, right) => {
                // Both must succeed for the operation to be successful
                left.add_to_access_paths(paths) && right.add_to_access_paths(paths)
            }
            // Record and set literals cannot be directly added to access paths
            WrappedAccessPaths::RecordLiteral(_) => false,
            WrappedAccessPaths::SetLiteral(_) => false,
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
            // PANIC SAFETY: Type checker should prevent using `.` operator on a set type.
            #[allow(clippy::panic)]
            WrappedAccessPaths::SetLiteral(_) => {
                panic!("Attempted to dereference a set literal.")
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
    /// This function returns all the paths the type specifies, starting from
    /// these wrapped access paths.
    fn full_type_required(self: &Rc<Self>, ty: &Type, store: &mut AccessDag) -> AccessPaths {
        match &**self {
            WrappedAccessPaths::AccessPath(path) => {
                // Use type_to_access_paths to compute the full access paths for the type
                // and add them to the store
                type_to_access_paths(ty, store, path)
            }
            WrappedAccessPaths::RecordLiteral(literal_fields) => match ty {
                Type::EntityOrRecord(EntityRecordKind::Record {
                    attrs: record_attrs,
                    ..
                }) => {
                    let mut res = AccessPaths::default();
                    for (attr, attr_ty) in record_attrs.iter() {
                        // PANIC SAFETY: Record literals should have attributes that match the type.
                        #[allow(clippy::panic)]
                        if let Some(field) = literal_fields.get(attr) {
                            res.extend(field.full_type_required(&attr_ty.attr_type, store));
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
                    elements.full_type_required(ele_type, store)
                }
                // PANIC SAFETY: Typechecking should identify set literals as set types.
                #[allow(clippy::panic)]
                _ => {
                    panic!("Found set literal when expected {} type", ty);
                }
            },
            WrappedAccessPaths::Empty => AccessPaths::default(),
            WrappedAccessPaths::Union(left, right) => left
                .full_type_required(ty, store)
                .extend_owned(right.full_type_required(ty, store)),
        }
    }
}

/// Compute the full access paths required for the type and add them to the store.
fn type_to_access_paths(ty: &Type, store: &mut AccessDag, path: &AccessPath) -> AccessPaths {
    match ty {
        // if it's not an entity or record, slice ends here
        Type::ExtensionType { .. }
        | Type::Never
        | Type::True
        | Type::False
        | Type::Primitive { .. }
        | Type::Set { .. } => AccessPaths::default(),
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
) -> AccessPaths {
    match ty {
        EntityRecordKind::ActionEntity { attrs, .. } | EntityRecordKind::Record { attrs, .. } => {
            let mut paths = AccessPaths::default();
            for (attr_name, attr_type) in attrs.iter() {
                // Create a new path for this attribute
                let attr_variant = AccessPathVariant::Attribute {
                    of: path.clone(),
                    attr: attr_name.clone(),
                };
                let attr_path = store.add_path(attr_variant);

                // Add this path to the result
                paths.insert(attr_path.clone());

                // Recursively process the attribute's type
                let attr_paths = type_to_access_paths(&attr_type.attr_type, store, &attr_path);
                paths.extend(attr_paths);
            }
            paths
        }
        EntityRecordKind::Entity(_) | EntityRecordKind::AnyEntity => {
            // no need to load data for entities, which are compared using ids
            AccessPaths::default()
        }
    }
}
