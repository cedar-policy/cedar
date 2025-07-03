use std::{collections::HashMap, rc::Rc};

use smol_str::SmolStr;

use crate::{
    ast::Expr,
    validator::{
        entity_manifest::{
            AccessDag, AccessTerm, AccessTermVariant, AccessTerms, EntityManifestError, EntityRoot,
            PartialExpressionError, UnsupportedCedarFeatureError,
        },
        types::{EntityRecordKind, Type},
    },
};

use crate::ast::{BinaryOp, ExprKind, Literal, UnaryOp, Var};

/// Represents [`AccessTerm`]s possibly
/// wrapped in record or set literals.
///
/// This allows the Entity Manifest to soundly handle
/// data that is wrapped in record or set literals, then used in equality
/// operators or dereferenced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum WrappedAccessTerms {
    /// No access paths are needed.
    #[default]
    Empty,
    /// A single access path, starting with a cedar variable.
    AccessTerm(AccessTerm),
    /// The union of two [`WrappedAccessTerms`], denoting that
    /// all access paths from both are required.
    /// This is useful for join points in the analysis (`if`, set literals, etc.)
    /// TODO change Rc to box now that we don't need multiple references to same one
    Union(Rc<WrappedAccessTerms>, Rc<WrappedAccessTerms>),
    /// A record literal, each field having access paths.
    RecordLiteral(HashMap<SmolStr, Rc<WrappedAccessTerms>>),
    /// A set literal containing access paths.
    /// Used to note that this type is wrapped in a literal set.
    SetLiteral(Rc<WrappedAccessTerms>),
    /// Intermediate values like if conditions may not be returned,
    /// but we still need to load them into the entity store.
    WithDroppedPaths {
        paths: Rc<WrappedAccessTerms>,
        dropped: Rc<WrappedAccessTerms>,
    },
}

impl WrappedAccessTerms {
    /// Create an analysis result that starts with a cedar variable
    pub fn from_root(root: EntityRoot, store: &mut AccessDag) -> Rc<Self> {
        // Create a new AccessTerm from the root
        let variant = match &root {
            EntityRoot::Literal(euid) => AccessTermVariant::Literal(euid.clone()),
            EntityRoot::Var(var) => AccessTermVariant::Var(*var),
        };

        // Add the path to the store
        let path = store.add_path(variant);

        Rc::new(WrappedAccessTerms::AccessTerm(path.clone()))
    }

    /// Add an ancestors required path for each of the wrapped access paths given.
    /// This function converts the `ancestors_trie` to `AccessTerms` and adds ancestor
    /// requirements to the current paths.
    ///
    /// Panics if `access_paths` contains a record or set literal. The typechecker
    /// should prevent this, since ancestors are required of literals.
    pub(crate) fn with_ancestors_required(
        self: Rc<Self>,
        // The access paths for the ancestors
        access_paths: &Rc<WrappedAccessTerms>,
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
                let ancestor_variant = AccessTermVariant::Ancestor {
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
        let mut access_paths_wrapped = Rc::new(WrappedAccessTerms::Empty);
        // Add the new access paths to the result
        for path in access_paths {
            access_paths_wrapped = access_paths_wrapped
                .with_dropped_paths(Rc::new(WrappedAccessTerms::AccessTerm(path)));
        }
        self.with_dropped_paths(access_paths_wrapped)
    }

    pub(crate) fn with_dropped_paths(
        self: Rc<Self>,
        // The paths that were dropped
        dropped: Rc<Self>,
    ) -> Rc<Self> {
        Rc::new(WrappedAccessTerms::WithDroppedPaths {
            paths: self,
            dropped,
        })
    }

    /// Convert the [`WrappedAccessTerms`] to a [`AccessTerms`].
    /// Returns [`None`] when the wrapped access paths represent a record or set literal.
    fn returned_access_paths(self: &Rc<Self>) -> Option<AccessTerms> {
        let mut access_paths = AccessTerms::default();
        if self.add_resulting_access_paths(&mut access_paths) {
            Some(access_paths)
        } else {
            None
        }
    }

    /// Union this analysis result with another, taking the union of the resulting paths.
    /// Takes ownership of self and returns self after mutating it.
    pub(crate) fn union(self: Rc<Self>, other: Rc<Self>) -> Rc<Self> {
        Rc::new(WrappedAccessTerms::Union(self, other))
    }

    /// Get all access paths from this wrapped access paths,
    /// including dropped paths.
    pub(crate) fn all_access_paths(self: &Rc<Self>) -> AccessTerms {
        let mut access_paths = AccessTerms::default();
        self.add_all_access_paths(&mut access_paths);
        access_paths
    }

    fn add_all_access_paths(self: &Rc<Self>, add_to: &mut AccessTerms) {
        match &**self {
            WrappedAccessTerms::Empty => (),
            WrappedAccessTerms::AccessTerm(path) => {
                add_to.paths.insert(path.clone());
            }
            WrappedAccessTerms::Union(left, right) => {
                // Both must succeed for the operation to be successful
                left.add_all_access_paths(add_to);
                right.add_all_access_paths(add_to);
            }
            WrappedAccessTerms::RecordLiteral(fields) => {
                for field in fields.values() {
                    // Add the access paths of each field
                    field.add_all_access_paths(add_to);
                }
            }
            WrappedAccessTerms::SetLiteral(elements) => {
                // Add the access paths of the set elements
                elements.add_all_access_paths(add_to);
            }
            WrappedAccessTerms::WithDroppedPaths { paths, dropped } => {
                dropped.add_all_access_paths(add_to);
                // We always add the paths, even if we don't include the dropped paths
                paths.add_all_access_paths(add_to);
            }
        }
    }

    fn add_resulting_access_paths(self: &Rc<Self>, add_to: &mut AccessTerms) -> bool {
        match &**self {
            WrappedAccessTerms::Empty => true,
            WrappedAccessTerms::AccessTerm(path) => {
                add_to.paths.insert(path.clone());
                true
            }
            WrappedAccessTerms::Union(left, right) => {
                // Both must succeed for the operation to be successful
                left.add_resulting_access_paths(add_to) && right.add_resulting_access_paths(add_to)
            }
            WrappedAccessTerms::RecordLiteral(_) => false,
            WrappedAccessTerms::SetLiteral(_) => false,
            WrappedAccessTerms::WithDroppedPaths { paths, dropped: _ } => {
                paths.add_resulting_access_paths(add_to)
            }
        }
    }

    /// Get or has tag access paths.
    /// We can safely assume that self is entity typed.
    pub(crate) fn get_or_has_tag(
        self: Rc<Self>,
        tag_paths: Rc<Self>,
        store: &mut AccessDag,
    ) -> Rc<Self> {
        eprintln!(
            "get_or_has_tag: self = {:?}, tag_paths = {:?}",
            self, tag_paths
        );
        // compute cross product of the access paths and the tag paths
        let of_access_paths = self.returned_access_paths().expect(
            "Tag access paths should not be record or set literals, typechecker should prevent this",
        );
        let tag_access_paths = tag_paths
            .returned_access_paths()
            .expect("Tag access paths should not be record or set literals, typechecker should prevent this");
        let mut access_paths = vec![];
        // cross product of the access paths
        for of_path in of_access_paths.paths() {
            for tag_path in tag_access_paths.paths() {
                // Create a new tag access path
                let tag_variant = AccessTermVariant::Tag {
                    of: of_path.clone(),
                    tag: tag_path.clone(),
                };
                // Add the new path to the store
                let new_path = store.add_path(tag_variant);
                // Add the new path to the access paths
                access_paths.push(new_path);
            }
        }

        // now compute the union of all these paths
        let mut res = Rc::new(WrappedAccessTerms::Empty);
        // Add the new access paths to the result
        for path in access_paths {
            res = res.union(Rc::new(WrappedAccessTerms::AccessTerm(path)));
        }
        // don't forget to drop self and tag paths, since they represent more paths than just returned access paths
        res.with_dropped_paths(self).with_dropped_paths(tag_paths)
    }

    /// Add accessing this attribute to all access paths
    pub(crate) fn get_or_has_attr(
        self: Rc<Self>,
        attr: &SmolStr,
        store: &mut AccessDag,
    ) -> Rc<Self> {
        match &*self {
            WrappedAccessTerms::AccessTerm(access_path) => {
                // Create a new attribute access path
                let attr_variant = AccessTermVariant::Attribute {
                    of: access_path.clone(),
                    attr: attr.clone(),
                };
                // Add the new path to the store
                let new_path = store.add_path(attr_variant);
                // Return the new wrapped access path
                Rc::new(WrappedAccessTerms::AccessTerm(new_path))
            }
            WrappedAccessTerms::RecordLiteral(record) => {
                if let Some(field) = record.get(attr) {
                    // drop the rest of the record, since we don't want to forget those paths
                    field.clone().with_dropped_paths(self)
                } else {
                    self
                }
            }
            #[allow(clippy::panic)]
            WrappedAccessTerms::SetLiteral(_) => {
                panic!("Attempted to dereference a set literal.")
            }
            WrappedAccessTerms::WithDroppedPaths { paths, dropped } => {
                Rc::new(WrappedAccessTerms::WithDroppedPaths {
                    paths: Rc::clone(paths).get_or_has_attr(attr, store),
                    dropped: Rc::clone(dropped),
                })
            }
            WrappedAccessTerms::Empty => Rc::new(WrappedAccessTerms::Empty),
            WrappedAccessTerms::Union(left, right) => Rc::new(WrappedAccessTerms::Union(
                Rc::clone(left).get_or_has_attr(attr, store),
                Rc::clone(right).get_or_has_attr(attr, store),
            )),
        }
    }

    /// For equality or containment checks, all paths in the type
    /// are required.
    /// This function extends the paths with the fields mentioned
    /// by the type, dropping them afterwards since type checks result in boolean values.
    pub(crate) fn require_full_type(self: Rc<Self>, ty: &Type, store: &mut AccessDag) -> Rc<Self> {
        match &*self {
            WrappedAccessTerms::AccessTerm(path) => {
                // Use type_to_access_paths to compute the full access paths for the type
                // and add them to the store
                self.clone()
                    .with_dropped_paths(type_to_access_paths(ty, store, path))
            }
            WrappedAccessTerms::RecordLiteral(literal_fields) => match ty {
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
                                field.clone().require_full_type(&attr_ty.attr_type, store),
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
            WrappedAccessTerms::SetLiteral(elements) => match ty {
                Type::Set { element_type } => {
                    // PANIC SAFETY: Typechecking should give concrete types for set elements.
                    #[allow(clippy::expect_used)]
                    let ele_type = element_type
                        .as_ref()
                        .expect("Expected concrete set type after typechecking");
                    self.clone().with_dropped_paths(
                        self.clone().with_dropped_paths(
                            elements.clone().require_full_type(ele_type, store),
                        ),
                    )
                }
                // PANIC SAFETY: Typechecking should identify set literals as set types.
                #[allow(clippy::panic)]
                _ => {
                    panic!("Found set literal when expected {} type", ty);
                }
            },
            WrappedAccessTerms::Empty => self.clone(),
            WrappedAccessTerms::Union(left, right) => self
                .clone()
                .with_dropped_paths(left.clone().require_full_type(ty, store))
                .with_dropped_paths(right.clone().require_full_type(ty, store)),
            WrappedAccessTerms::WithDroppedPaths {
                paths,
                dropped: _dropped,
            } => self
                .clone()
                .with_dropped_paths(paths.clone().require_full_type(ty, store)),
        }
    }
}

/// Compute the full access paths required for the type and add them to the the wrapped access paths as dropped paths.
fn type_to_access_paths(
    ty: &Type,
    store: &mut AccessDag,
    path: &AccessTerm,
) -> Rc<WrappedAccessTerms> {
    match ty {
        // if it's not an entity or record, slice ends here
        Type::ExtensionType { .. }
        | Type::Never
        | Type::True
        | Type::False
        | Type::Primitive { .. }
        | Type::Set { .. } => Rc::new(WrappedAccessTerms::Empty),
        Type::EntityOrRecord(record_type) => {
            entity_or_record_to_access_paths(record_type, store, path)
        }
    }
}

/// Compute the full access paths for the given entity or record type and add them to the store.
fn entity_or_record_to_access_paths(
    ty: &EntityRecordKind,
    store: &mut AccessDag,
    path: &AccessTerm,
) -> Rc<WrappedAccessTerms> {
    match ty {
        EntityRecordKind::ActionEntity { attrs, .. } | EntityRecordKind::Record { attrs, .. } => {
            let mut paths = Rc::new(WrappedAccessTerms::default());
            for (attr_name, attr_type) in attrs.iter() {
                // Create a new path for this attribute
                let attr_variant = AccessTermVariant::Attribute {
                    of: path.clone(),
                    attr: attr_name.clone(),
                };
                let attr_path = store.add_path(attr_variant);

                paths = paths
                    .with_dropped_paths(Rc::new(WrappedAccessTerms::AccessTerm(attr_path.clone())));

                // Recursively process the attribute's type
                let attr_paths = type_to_access_paths(&attr_type.attr_type, store, &attr_path);
                paths = paths.with_dropped_paths(attr_paths);
            }
            paths
        }
        EntityRecordKind::Entity(_) | EntityRecordKind::AnyEntity => {
            // no need to load data for entities, which are compared using ids
            WrappedAccessTerms::Empty.into()
        }
    }
}

/// A static analysis on type-annotated cedar expressions.
/// Computes the access paths required to evaluate the expression.
///
/// This function populates the provided `AccessDag` store with paths
/// and returns an `WrappedAccessTerms` analysis result.
/// The [`WrappedAccessTerms`] contains the result's access paths
/// and any access paths encountered during the analysis.
pub(crate) fn analyze_expr_access_paths(
    expr: &Expr<Option<Type>>,
    store: &mut AccessDag,
) -> Result<Rc<WrappedAccessTerms>, EntityManifestError> {
    Ok(match expr.expr_kind() {
        ExprKind::Slot(slot_id) => {
            if slot_id.is_principal() {
                WrappedAccessTerms::from_root(EntityRoot::Var(Var::Principal), store)
            } else {
                assert!(slot_id.is_resource());
                WrappedAccessTerms::from_root(EntityRoot::Var(Var::Resource), store)
            }
        }

        ExprKind::Var(var) => WrappedAccessTerms::from_root(EntityRoot::Var(*var), store),

        ExprKind::Lit(Literal::EntityUID(literal)) => {
            WrappedAccessTerms::from_root(EntityRoot::Literal((**literal).clone()), store)
        }

        ExprKind::Unknown(_) => Err(PartialExpressionError {})?,

        // We only care about strings so that we can handle
        // getting tags.
        ExprKind::Lit(lit) => {
            match lit {
                Literal::String(str) => {
                    let variant = AccessTermVariant::String(SmolStr::from(str.clone()));
                    let path = store.add_path(variant);
                    Rc::new(WrappedAccessTerms::AccessTerm(path))
                }
                _ => {
                    // empty paths for other literals
                    return Ok(Rc::new(WrappedAccessTerms::Empty));
                }
            }
        }

        ExprKind::If {
            test_expr,
            then_expr,
            else_expr,
        } => {
            // For if expressions, the test condition is accessed but not part of the result
            let test_result = analyze_expr_access_paths(test_expr, store)?;
            let then_result = analyze_expr_access_paths(then_expr, store)?;
            let else_result = analyze_expr_access_paths(else_expr, store)?;

            then_result
                .union(else_result)
                .with_dropped_paths(test_result)
        }

        ExprKind::And { left, right }
        | ExprKind::Or { left, right }
        | ExprKind::BinaryApp {
            op: BinaryOp::Less | BinaryOp::LessEq | BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul,
            arg1: left,
            arg2: right,
        } => {
            // For these operations, both sides are accessed but the result is a primitive
            analyze_expr_access_paths(left, store)?.union(analyze_expr_access_paths(right, store)?)
        }

        ExprKind::UnaryApp { op, arg } => {
            match op {
                // These unary ops are on primitive types
                UnaryOp::Not | UnaryOp::Neg => analyze_expr_access_paths(arg, store)?,

                UnaryOp::IsEmpty => {
                    let arg_result = analyze_expr_access_paths(arg, store)?;

                    // PANIC SAFETY: Typechecking succeeded, so type annotations are present
                    #[allow(clippy::expect_used)]
                    let ty = arg
                        .data()
                        .as_ref()
                        .expect("Expected annotated types after typechecking");

                    // For isEmpty, we need all fields of the type
                    arg_result.require_full_type(ty, store)
                }
            }
        }

        ExprKind::BinaryApp {
            op:
                op @ (BinaryOp::Eq
                | BinaryOp::In
                | BinaryOp::Contains
                | BinaryOp::ContainsAll
                | BinaryOp::ContainsAny),
            arg1,
            arg2,
        } => {
            // First, find the data paths for each argument
            let mut arg1_result = analyze_expr_access_paths(arg1, store)?;
            let arg2_result = analyze_expr_access_paths(arg2, store)?;

            // PANIC SAFETY: Typechecking succeeded, so type annotations are present
            #[allow(clippy::expect_used)]
            let ty1 = arg1
                .data()
                .as_ref()
                .expect("Expected annotated types after typechecking");

            #[allow(clippy::expect_used)]
            let ty2 = arg2
                .data()
                .as_ref()
                .expect("Expected annotated types after typechecking");

            // For the `in` operator, we need to handle ancestors
            if matches!(op, BinaryOp::In) {
                arg1_result = arg1_result.with_ancestors_required(&arg2_result, store);
            }

            arg1_result
                .with_dropped_paths(arg2_result.require_full_type(ty2, store))
                .require_full_type(ty1, store)
        }

        ExprKind::BinaryApp {
            op: BinaryOp::GetTag | BinaryOp::HasTag,
            arg1,
            arg2,
        } => {
            let arg1_result = analyze_expr_access_paths(arg1, store)?;
            let arg2_result = analyze_expr_access_paths(arg2, store)?;

            arg1_result.get_or_has_tag(arg2_result, store)
        }

        ExprKind::ExtensionFunctionApp { fn_name: _, args } => {
            // Collect paths from all arguments
            let mut result = Rc::new(WrappedAccessTerms::default());

            for arg in args.iter() {
                result = result.union(analyze_expr_access_paths(arg, store)?);
            }

            result
        }

        ExprKind::Like { expr, pattern: _ }
        | ExprKind::Is {
            expr,
            entity_type: _,
        } => analyze_expr_access_paths(expr, store)?,

        ExprKind::Set(contents) => {
            let mut combined_paths = Rc::new(WrappedAccessTerms::default());

            // Collect paths from all set elements
            for expr in &**contents {
                let element_result = analyze_expr_access_paths(expr, store)?;
                combined_paths = combined_paths.union(element_result.clone());
            }

            // Wrap the combined paths in a SetLiteral
            Rc::new(WrappedAccessTerms::SetLiteral(combined_paths))
        }

        ExprKind::Record(content) => {
            let mut record_contents = HashMap::new();

            // Collect paths from all record fields
            for (key, child_expr) in content.iter() {
                let field_result = analyze_expr_access_paths(child_expr, store)?;
                record_contents.insert(key.clone(), field_result);
            }

            Rc::new(WrappedAccessTerms::RecordLiteral(record_contents))
        }

        ExprKind::GetAttr { expr, attr } => {
            let base_result = analyze_expr_access_paths(expr, store)?;
            base_result.get_or_has_attr(attr, store)
        }

        ExprKind::HasAttr { expr, attr } => {
            let base_result = analyze_expr_access_paths(expr, store)?;
            base_result.get_or_has_attr(attr, store)
        }

        #[cfg(feature = "tolerant-ast")]
        ExprKind::Error { .. } => {
            return Err(EntityManifestError::UnsupportedCedarFeature(
                UnsupportedCedarFeatureError {
                    feature: "No support for AST error nodes".into(),
                },
            ))
        }
    })
}
