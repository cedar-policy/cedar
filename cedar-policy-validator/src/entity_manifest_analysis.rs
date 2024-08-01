use std::collections::HashMap;

use smol_str::SmolStr;

use crate::{
    entity_manifest::{AccessPath, AccessTrie, EntityRoot, RootAccessTrie},
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
    Union(Box<WrappedAccessPaths>, Box<WrappedAccessPaths>),
    /// A record literal, each field having access paths.
    RecordLiteral(HashMap<SmolStr, Box<WrappedAccessPaths>>),
    /// A set literal containing access paths.
    /// Used to note that this type is wrapped in a literal set.
    SetLiteral(Box<WrappedAccessPaths>),
}

/// During Entity Manifest analysis, each sub-expression
/// produces an [`EntityManifestAnalysisResult`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct EntityManifestAnalysisResult {
    /// INVARIANT: The `global_trie` stores all of the data paths this sub-expression
    /// could have accessed, including all those in `resulting_paths`.
    pub(crate) global_trie: RootAccessTrie,
    /// `resulting_paths` stores a list of `AccessPathRecord`,
    /// Each representing a data path
    /// (possibly wrapped in a record literal)
    /// that could be accessed using the `.` operator.
    pub(crate) resulting_paths: WrappedAccessPaths,
}

impl EntityManifestAnalysisResult {
    /// Drop the resulting paths part of the analysis.
    /// This is sound when the expression is a primitive value, so it
    /// can't be dereferenced.
    pub fn empty_paths(mut self) -> Self {
        self.resulting_paths = Default::default();
        self
    }

    /// Union two [`EntityManifestAnalysisResult`]s together,
    /// keeping the paths from both global tries and concatenating
    /// the resulting paths.
    pub fn union(mut self, other: &Self) -> Self {
        self.global_trie = self.global_trie.union(&other.global_trie);
        self.resulting_paths = WrappedAccessPaths::Union(
            Box::new(self.resulting_paths),
            Box::new(other.resulting_paths.clone()),
        );
        self
    }

    /// Create an analysis result that starts with a cedar variable
    pub fn from_root(root: EntityRoot) -> Self {
        let path = AccessPath {
            root,
            path: vec![],
            ancestors_required: false,
        };
        Self {
            global_trie: path.to_root_access_trie(),
            resulting_paths: WrappedAccessPaths::AccessPath(path),
        }
    }

    /// Extend all the access paths with this attr,
    /// adding all the new paths to the global trie.
    pub fn get_attr(mut self, attr: &SmolStr) -> Self {
        self.resulting_paths = self.resulting_paths.get_attr(attr);

        self.restore_global_trie_invariant()
    }

    /// Restores the `global_trie` invariant by adding all paths
    /// in `resulting_paths` to the `global_trie`.
    /// This is necessary after modifying the `resulting_paths`.
    pub(crate) fn restore_global_trie_invariant(mut self) -> Self {
        self.global_trie
            .add_wrapped_access_paths(&self.resulting_paths);
        self
    }

    /// Add the ancestors required flag to all of the
    /// resulting paths for this analysis result, but only set it
    /// for entity types.
    pub(crate) fn ancestors_required(mut self, ty: &Type) -> Self {
        self.resulting_paths.ancestors_required(ty);
        self.restore_global_trie_invariant()
    }

    /// For equality or containment checks, all paths in the type
    /// are required.
    /// This function extends the paths with the fields mentioned
    /// by the type, adding these to the global trie.
    ///
    /// It also drops the resulting paths, since these checks result
    /// in booleans.
    pub(crate) fn full_type_required(mut self, ty: &Type) -> Self {
        let mut paths = Default::default();
        std::mem::swap(&mut self.resulting_paths, &mut paths);

        self.global_trie = self.global_trie.union(&paths.full_type_required(ty));

        self
    }
}

impl WrappedAccessPaths {
    /// Add accessting this attribute to all access paths
    fn get_attr(self, attr: &SmolStr) -> Self {
        match self {
            WrappedAccessPaths::AccessPath(mut access_path) => {
                access_path.path.push(attr.clone());
                WrappedAccessPaths::AccessPath(access_path)
            }
            WrappedAccessPaths::RecordLiteral(mut record) => {
                let Some(field) = record.remove(attr) else {
                    panic!("Record literal lacks dereferenced field, but the typechecker failed to catch it.");
                };

                *field
            }
            WrappedAccessPaths::SetLiteral(_) => {
                // PANIC SAFETY: Type checker should prevent using `.` operator on a set type.
                panic!("Attempted to dereference a set literal.")
            }
            WrappedAccessPaths::Empty => WrappedAccessPaths::Empty,
            WrappedAccessPaths::Union(left, right) => WrappedAccessPaths::Union(
                Box::new(left.get_attr(attr)),
                Box::new(right.get_attr(attr)),
            ),
        }
    }
    /// Add the ancestors required flag to all of the resulting
    /// paths for this path record.
    fn ancestors_required(&mut self, ty: &Type) {
        match self {
            WrappedAccessPaths::AccessPath(path) => {
                if let Type::EntityOrRecord(EntityRecordKind::Entity { .. }) = ty {
                    eprintln!("here");
                    path.ancestors_required = true;
                }
            }
            WrappedAccessPaths::RecordLiteral(record) => match ty {
                Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) => {
                    for (field, value) in record.iter_mut() {
                        let field_ty = &attrs
                            .get_attr(field)
                            .expect("Missing field in record type")
                            .attr_type;
                        value.ancestors_required(field_ty);
                    }
                }
                _ => {
                    panic!("Found record literal when expected {} type", ty);
                }
            },
            WrappedAccessPaths::SetLiteral(elements) => {
                let Type::Set { element_type } = ty else {
                    panic!("Found set literal when expected {} type", ty);
                };
                let ele_type = element_type
                    .as_ref()
                    .expect("Expected concrete set type after typechecking");

                elements.ancestors_required(ele_type);
            }
            WrappedAccessPaths::Empty => (),
            WrappedAccessPaths::Union(left, right) => {
                left.ancestors_required(ty);
                right.ancestors_required(ty);
            }
        }
    }

    fn full_type_required(self, ty: &Type) -> RootAccessTrie {
        match self {
            WrappedAccessPaths::AccessPath(path) => {
                let leaf_trie = type_to_access_trie(ty);
                path.to_root_access_trie_with_leaf(leaf_trie)
            }
            WrappedAccessPaths::RecordLiteral(literal_fields) => match ty {
                Type::EntityOrRecord(EntityRecordKind::Record {
                    attrs: record_attrs,
                    ..
                }) => {
                    let mut res = RootAccessTrie::new();
                    for (attr, attr_ty) in &record_attrs.attrs {
                        // TODO is there a way to avoid this clone?
                        let field = (*literal_fields
                            .get(attr)
                            .unwrap_or_else(|| panic!("Missing field {attr} in record literal")))
                        .clone();

                        res = res.union(&field.full_type_required(&attr_ty.attr_type));
                    }

                    res
                }
                _ => {
                    panic!("Found record literal when expected {} type", ty);
                }
            },
            WrappedAccessPaths::SetLiteral(elements) => match ty {
                Type::Set { element_type } => {
                    let ele_type = element_type
                        .as_ref()
                        .expect("Expected concrete set type after typechecking");
                    elements.full_type_required(ele_type)
                }
                _ => {
                    panic!("Found set literal when expected {} type", ty);
                }
            },
            WrappedAccessPaths::Empty => RootAccessTrie::new(),
            WrappedAccessPaths::Union(left, right) => left
                .full_type_required(ty)
                .union(&right.full_type_required(ty)),
        }
    }
}

impl RootAccessTrie {
    pub(crate) fn add_wrapped_access_paths(&mut self, path: &WrappedAccessPaths) {
        match path {
            WrappedAccessPaths::AccessPath(access_path) => {
                self.add_access_path(access_path, &AccessTrie::new());
            }
            WrappedAccessPaths::RecordLiteral(record) => {
                for field in record.values() {
                    self.add_wrapped_access_paths(field);
                }
            }
            WrappedAccessPaths::SetLiteral(elements) => self.add_wrapped_access_paths(elements),
            WrappedAccessPaths::Empty => (),
            WrappedAccessPaths::Union(left, right) => {
                self.add_wrapped_access_paths(left);
                self.add_wrapped_access_paths(right);
            }
        }
    }

    pub(crate) fn add_access_path(&mut self, access_path: &AccessPath, leaf_trie: &AccessTrie) {
        // could be more efficient by mutating self
        // instead we use the existing union function.
        let other_trie = access_path.to_root_access_trie_with_leaf(leaf_trie.clone());
        *self = self.union(&other_trie);
    }
}

// TODO move analysis code here

/// Compute the full [`AccessTrie`] required for the type.
fn type_to_access_trie(ty: &Type) -> AccessTrie {
    match ty {
        // if it's not an entity or record, slice ends here
        Type::ExtensionType { .. }
        | Type::Never
        | Type::True
        | Type::False
        | Type::Primitive { .. }
        | Type::Set { .. } => AccessTrie::new(),
        Type::EntityOrRecord(record_type) => entity_or_record_to_access_trie(record_type),
    }
}

/// Compute the full [`AccessTrie`] for the given entity or record type.
fn entity_or_record_to_access_trie(ty: &EntityRecordKind) -> AccessTrie {
    match ty {
        EntityRecordKind::ActionEntity { attrs, .. } | EntityRecordKind::Record { attrs, .. } => {
            let mut fields = HashMap::new();
            for (attr_name, attr_type) in attrs.iter() {
                fields.insert(
                    attr_name.clone(),
                    Box::new(type_to_access_trie(&attr_type.attr_type)),
                );
            }
            AccessTrie {
                children: fields,
                ancestors_required: false,
                data: (),
            }
        }

        EntityRecordKind::Entity(_) | EntityRecordKind::AnyEntity => {
            // no need to load data for entities, which are compared
            // using ids
            AccessTrie::new()
        }
    }
}
