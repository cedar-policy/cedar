use std::{collections::HashMap, rc::Rc};

use smol_str::SmolStr;

use crate::validator::{
    entity_manifest::{AccessPath, AccessPathDag, AccessPathVariant, AccessPaths, EntityRoot},
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
    /// This is useful for join points in the analysis (`if`, set literals, ect)
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
    /// The `store` stores all of the data paths this sub-expression
    /// including those in `resulting_paths`.
    ///
    /// Intermediate paths may be using in
    /// auxillery computation of the expression (an if statement's condition for example),
    /// so it's important to consider all the paths in the store.
    pub(crate) store: AccessPathDag,
    /// `resulting_paths` stores a the set of values this expression could evaluate to
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
    pub fn from_root(root: EntityRoot) -> Self {
        // Create a new AccessPath from the root
        let variant = match &root {
            EntityRoot::Literal(euid) => AccessPathVariant::Literal(euid.clone()),
            EntityRoot::Var(var) => AccessPathVariant::Var(*var),
        };

        // Create a new AccessPathDag
        let mut store = AccessPathDag::default();

        // Add the path to the store
        let path = store.add_path(variant);

        // Create the resulting_paths
        let resulting_paths = Rc::new(WrappedAccessPaths::AccessPath(path));

        Self {
            store,
            resulting_paths,
        }
    }

    /// Extend all the access paths with this attr,
    /// adding all the new paths to the global trie.
    pub fn get_or_has_attr(mut self, attr: &SmolStr) -> Self {
        self.resulting_paths = self.resulting_paths.get_or_has_attr(attr);
        self
    }

    /// Add an ancestors required path for each of the wrapped access paths given.
    pub(crate) fn with_ancestors_required(
        mut self,
        ancestors_trie: &Rc<WrappedAccessPaths>,
    ) -> Self {
    }

    /// For equality or containment checks, all paths in the type
    /// are required.
    /// This function extends the paths with the fields mentioned
    /// by the type, adding these to the internal store.
    ///
    /// It also drops the resulting paths, since these checks result
    /// in booleans.
    pub(crate) fn full_type_required(&mut self, ty: &Type) {
        self.resulting_paths.full_type_required(ty, &mut self.store);
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

    /// Returns if true if it was successful (no struct or set literals encountered.
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

    /// Add accessting this attribute to all access paths
    fn get_or_has_attr(self: Rc<Self>, attr: &SmolStr) -> Rc<Self> {
        Rc::new(match self {
            WrappedAccessPaths::AccessPath(mut access_path) => {
                access_path.path.push(attr.clone());
                WrappedAccessPaths::AccessPath(access_path)
            }
            WrappedAccessPaths::RecordLiteral(mut record) => {
                if let Some(field) = record.remove(attr) {
                    *field
                } else {
                    // otherwise, this is a `has` expression
                    // but the record literal didn't have it.
                    // do nothing in this case
                    WrappedAccessPaths::RecordLiteral(record)
                }
            }
            // PANIC SAFETY: Type checker should prevent using `.` operator on a set type.
            #[allow(clippy::panic)]
            WrappedAccessPaths::SetLiteral(_) => {
                panic!("Attempted to dereference a set literal.")
            }
            WrappedAccessPaths::Empty => WrappedAccessPaths::Empty,
            WrappedAccessPaths::Union(left, right) => {
                WrappedAccessPaths::Union(left.get_or_has_attr(attr), right.get_or_has_attr(attr))
            }
        })
    }

    fn full_type_required(self, ty: &Type) -> AccessDag {
        match self {
            WrappedAccessPaths::AccessPath(path) => {
                let leaf_trie = type_to_access_trie(ty);
                path.to_root_access_trie_with_leaf(leaf_trie)
            }
            WrappedAccessPaths::RecordLiteral(mut literal_fields) => match ty {
                Type::EntityOrRecord(EntityRecordKind::Record {
                    attrs: record_attrs,
                    ..
                }) => {
                    let mut res = AccessDag::new();
                    for (attr, attr_ty) in record_attrs.iter() {
                        // PANIC SAFETY: Record literals should have attributes that match the type.
                        #[allow(clippy::panic)]
                        let field = literal_fields
                            .remove(attr)
                            .unwrap_or_else(|| panic!("Missing field {attr} in record literal"));

                        res = res.union(field.full_type_required(&attr_ty.attr_type));
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
                    elements.full_type_required(ele_type)
                }
                // PANIC SAFETY: Typechecking should identify set literals as set types.
                #[allow(clippy::panic)]
                _ => {
                    panic!("Found set literal when expected {} type", ty);
                }
            },
            WrappedAccessPaths::Empty => AccessDag::new(),
            WrappedAccessPaths::Union(left, right) => left
                .full_type_required(ty)
                .union(right.full_type_required(ty)),
        }
    }

    pub(crate) fn to_ancestor_access_trie(&self) -> AccessDag {
        let mut trie = AccessDag::default();
        trie.add_wrapped_access_paths(self, true, &Default::default());
        trie
    }
}

impl AccessDag {
    pub(crate) fn add_wrapped_access_paths(
        &mut self,
        path: &WrappedAccessPaths,
        is_ancestor: bool,
        ancestors_trie: &AccessDag,
    ) {
        match path {
            WrappedAccessPaths::AccessPath(access_path) => {
                let mut leaf = AccessTrie::new();
                leaf.is_ancestor = is_ancestor;
                leaf.ancestors_trie = ancestors_trie.clone();
                self.add_access_path(access_path, leaf);
            }
            WrappedAccessPaths::RecordLiteral(record) => {
                for field in record.values() {
                    self.add_wrapped_access_paths(field, is_ancestor, ancestors_trie);
                }
            }
            WrappedAccessPaths::SetLiteral(elements) => {
                self.add_wrapped_access_paths(elements, is_ancestor, ancestors_trie)
            }
            WrappedAccessPaths::Empty => (),
            WrappedAccessPaths::Union(left, right) => {
                self.add_wrapped_access_paths(left, is_ancestor, ancestors_trie);
                self.add_wrapped_access_paths(right, is_ancestor, ancestors_trie);
            }
        }
    }

    pub(crate) fn add_access_path(&mut self, access_path: &AccessPath, leaf_trie: AccessTrie) {
        // could be more efficient by mutating self
        // instead we use the existing union function.
        let other_trie = access_path.to_root_access_trie_with_leaf(leaf_trie);
        self.union_mut(other_trie)
    }
}

/// Compute the full access paths required for the type and add them to the store.
fn type_to_access_paths(ty: &Type, store: &mut AccessPathDag, path: &AccessPath) -> AccessPaths {
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
    store: &mut AccessPathDag,
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
                paths = paths.add_paths(attr_paths);
            }
            paths
        }
        EntityRecordKind::Entity(_) | EntityRecordKind::AnyEntity => {
            // no need to load data for entities, which are compared using ids
            AccessPaths::default()
        }
    }
}
