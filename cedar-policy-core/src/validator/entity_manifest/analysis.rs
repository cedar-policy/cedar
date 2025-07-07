use std::{collections::HashMap, rc::Rc};

use smol_str::SmolStr;

#[cfg(feature = "tolerant-ast")]
use crate::validator::entity_manifest::errors::ErrorExpressionError;
use crate::{
    ast::{EntityUID, Expr},
    validator::{
        entity_manifest::{
            errors::PartialExpressionError, AccessDag, AccessTerm, AccessTermVariant, AccessTerms,
            EntityManifestError,
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
    /// No access terms are needed.
    #[default]
    Empty,
    /// A single access term, starting with a cedar variable.
    AccessTerm(AccessTerm),
    /// The union of two [`WrappedAccessTerms`], denoting that
    /// all access terms from both are required.
    /// This is useful for join points in the analysis (`if`, set literals, etc.)
    /// TODO change Rc to box now that we don't need multiple references to same one
    Union(Rc<WrappedAccessTerms>, Rc<WrappedAccessTerms>),
    /// A record literal, each field having access terms.
    RecordLiteral(HashMap<SmolStr, Rc<WrappedAccessTerms>>),
    /// A set literal containing access terms.
    /// Used to note that this type is wrapped in a literal set.
    SetLiteral(Rc<WrappedAccessTerms>),
    /// Intermediate values like if conditions may not be returned,
    /// but we still need to load them into the entity store.
    WithDroppedTerms {
        terms: Rc<WrappedAccessTerms>,
        dropped: Rc<WrappedAccessTerms>,
    },
}

impl WrappedAccessTerms {
    /// Create an analysis result that starts with a cedar variable
    pub fn from_var(var: Var, store: &mut AccessDag) -> Rc<Self> {
        let variant = AccessTermVariant::Var(var);
        let term = store.add_term(variant);
        Rc::new(WrappedAccessTerms::AccessTerm(term.clone()))
    }

    /// Create an analysis result starting with a cedar entity euid
    pub fn from_euid(euid: EntityUID, store: &mut AccessDag) -> Rc<Self> {
        let variant = AccessTermVariant::Literal(euid);
        let term = store.add_term(variant);
        Rc::new(WrappedAccessTerms::AccessTerm(term.clone()))
    }

    /// Add an ancestors required term for each of the wrapped access terms given.
    /// This function converts the `ancestors_trie` to `AccessTerms` and adds ancestor
    /// requirements to the current terms.
    ///
    /// Panics if `access_terms` contains a record or set literal. The typechecker
    /// should prevent this, since ancestors are required of literals.
    pub(crate) fn with_ancestors_required(
        self: Rc<Self>,
        // The access terms for the ancestors
        access_terms: &Rc<WrappedAccessTerms>,
        store: &mut AccessDag,
    ) -> Rc<Self> {
        // compute cross product of the access terms and the ancestors
        let of_access_terms = self.returned_access_terms().expect(
            "Ancestors required terms should not be record or set literals, typechecker should prevent this",
        );
        let ancestors_access_terms = access_terms
            .returned_access_terms()
            .expect("Ancestors required terms should not be record or set literals, typechecker should prevent this");
        let mut access_terms = vec![];
        // cross product of the access terms
        for of_term in of_access_terms.terms() {
            for ancestor_term in ancestors_access_terms.terms() {
                // Create a new ancestor required term
                let ancestor_variant = AccessTermVariant::Ancestor {
                    of: of_term.clone(),
                    ancestor: ancestor_term.clone(),
                };
                // Add the new term to the store
                let new_term = store.add_term(ancestor_variant);
                // Add the new term to the access terms
                access_terms.push(new_term);
            }
        }
        // Return the new wrapped access terms with a drop
        let mut access_terms_wrapped = Rc::new(WrappedAccessTerms::Empty);
        // Add the new access terms to the result
        for term in access_terms {
            access_terms_wrapped = access_terms_wrapped
                .with_dropped_terms(Rc::new(WrappedAccessTerms::AccessTerm(term)));
        }
        self.with_dropped_terms(access_terms_wrapped)
    }

    pub(crate) fn with_dropped_terms(
        self: Rc<Self>,
        // The terms that were dropped
        dropped: Rc<Self>,
    ) -> Rc<Self> {
        Rc::new(WrappedAccessTerms::WithDroppedTerms {
            terms: self,
            dropped,
        })
    }

    /// Convert the [`WrappedAccessTerms`] to a [`AccessTerms`].
    /// Returns [`None`] when the wrapped access terms represent a record or set literal.
    fn returned_access_terms(self: &Rc<Self>) -> Option<AccessTerms> {
        let mut access_terms = AccessTerms::default();
        if self.add_resulting_access_terms(&mut access_terms) {
            Some(access_terms)
        } else {
            None
        }
    }

    /// Union this analysis result with another, taking the union of the resulting terms.
    /// Takes ownership of self and returns self after mutating it.
    pub(crate) fn union(self: Rc<Self>, other: Rc<Self>) -> Rc<Self> {
        Rc::new(WrappedAccessTerms::Union(self, other))
    }

    /// Get all access terms from this wrapped access terms,
    /// including dropped terms.
    pub(crate) fn all_access_paths(self: &Rc<Self>) -> AccessTerms {
        let mut access_terms = AccessTerms::default();
        self.add_all_access_terms(&mut access_terms);
        access_terms
    }

    fn add_all_access_terms(self: &Rc<Self>, add_to: &mut AccessTerms) {
        match &**self {
            WrappedAccessTerms::Empty => (),
            WrappedAccessTerms::AccessTerm(term) => {
                add_to.terms.insert(term.clone());
            }
            WrappedAccessTerms::Union(left, right) => {
                // Both must succeed for the operation to be successful
                left.add_all_access_terms(add_to);
                right.add_all_access_terms(add_to);
            }
            WrappedAccessTerms::RecordLiteral(fields) => {
                for field in fields.values() {
                    // Add the access terms of each field
                    field.add_all_access_terms(add_to);
                }
            }
            WrappedAccessTerms::SetLiteral(elements) => {
                // Add the access terms of the set elements
                elements.add_all_access_terms(add_to);
            }
            WrappedAccessTerms::WithDroppedTerms { terms, dropped } => {
                dropped.add_all_access_terms(add_to);
                // We always add the terms, even if we don't include the dropped terms
                terms.add_all_access_terms(add_to);
            }
        }
    }

    fn add_resulting_access_terms(self: &Rc<Self>, add_to: &mut AccessTerms) -> bool {
        match &**self {
            WrappedAccessTerms::Empty => true,
            WrappedAccessTerms::AccessTerm(term) => {
                add_to.terms.insert(term.clone());
                true
            }
            WrappedAccessTerms::Union(left, right) => {
                // Both must succeed for the operation to be successful
                left.add_resulting_access_terms(add_to) && right.add_resulting_access_terms(add_to)
            }
            WrappedAccessTerms::RecordLiteral(_) => false,
            WrappedAccessTerms::SetLiteral(_) => false,
            WrappedAccessTerms::WithDroppedTerms { terms, dropped: _ } => {
                terms.add_resulting_access_terms(add_to)
            }
        }
    }

    /// Get or has tag access terms.
    /// We can safely assume that self is entity typed.
    pub(crate) fn get_or_has_tag(
        self: Rc<Self>,
        tag_terms: Rc<Self>,
        store: &mut AccessDag,
    ) -> Rc<Self> {
        // compute cross product of the access terms and the tag terms
        let of_access_terms = self.returned_access_terms().expect(
            "Tag access terms should not be record or set literals, typechecker should prevent this",
        );
        let tag_access_terms = tag_terms
            .returned_access_terms()
            .expect("Tag access terms should not be record or set literals, typechecker should prevent this");
        let mut access_terms = vec![];
        // cross product of the access terms
        for of_term in of_access_terms.terms() {
            for tag_term in tag_access_terms.terms() {
                // Create a new tag access term
                let tag_variant = AccessTermVariant::Tag {
                    of: of_term.clone(),
                    tag: tag_term.clone(),
                };
                // Add the new term to the store
                let new_term = store.add_term(tag_variant);
                // Add the new term to the access terms
                access_terms.push(new_term);
            }
        }

        // now compute the union of all these terms
        let mut res = Rc::new(WrappedAccessTerms::Empty);
        // Add the new access terms to the result
        for term in access_terms {
            res = res.union(Rc::new(WrappedAccessTerms::AccessTerm(term)));
        }
        // don't forget to drop self and tag terms, since they represent more terms than just returned access terms
        res.with_dropped_terms(self).with_dropped_terms(tag_terms)
    }

    /// Add accessing this attribute to all access terms
    pub(crate) fn get_or_has_attr(
        self: Rc<Self>,
        attr: &SmolStr,
        store: &mut AccessDag,
    ) -> Rc<Self> {
        match &*self {
            WrappedAccessTerms::AccessTerm(access_term) => {
                // Create a new attribute access term
                let attr_variant = AccessTermVariant::Attribute {
                    of: access_term.clone(),
                    attr: attr.clone(),
                };
                // Add the new term to the store
                let new_term = store.add_term(attr_variant);
                // Return the new wrapped access term
                Rc::new(WrappedAccessTerms::AccessTerm(new_term))
            }
            WrappedAccessTerms::RecordLiteral(record) => {
                if let Some(field) = record.get(attr) {
                    // drop the rest of the record, since we don't want to forget those terms
                    field.clone().with_dropped_terms(self)
                } else {
                    self
                }
            }
            #[allow(clippy::panic)]
            WrappedAccessTerms::SetLiteral(_) => {
                panic!("Attempted to dereference a set literal.")
            }
            WrappedAccessTerms::WithDroppedTerms { terms, dropped } => {
                Rc::new(WrappedAccessTerms::WithDroppedTerms {
                    terms: Rc::clone(terms).get_or_has_attr(attr, store),
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

    /// For equality or containment checks, all terms in the type
    /// are required.
    /// This function extends the terms with the fields mentioned
    /// by the type, dropping them afterwards since type checks result in boolean values.
    pub(crate) fn require_full_type(self: Rc<Self>, ty: &Type, store: &mut AccessDag) -> Rc<Self> {
        match &*self {
            WrappedAccessTerms::AccessTerm(term) => {
                // Use type_to_access_terms to compute the full access terms for the type
                // and add them to the store
                self.clone()
                    .with_dropped_terms(type_to_access_terms(ty, store, *term))
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
                            res = res.with_dropped_terms(
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
                    self.clone().with_dropped_terms(
                        self.clone().with_dropped_terms(
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
                .with_dropped_terms(left.clone().require_full_type(ty, store))
                .with_dropped_terms(right.clone().require_full_type(ty, store)),
            WrappedAccessTerms::WithDroppedTerms {
                terms,
                dropped: _dropped,
            } => self
                .clone()
                .with_dropped_terms(terms.clone().require_full_type(ty, store)),
        }
    }
}

/// Compute the full access terms required for the type and add them to the the wrapped access terms as dropped terms.
fn type_to_access_terms(
    ty: &Type,
    store: &mut AccessDag,
    term: AccessTerm,
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
            entity_or_record_to_access_terms(record_type, store, term)
        }
    }
}

/// Compute the full access terms for the given entity or record type and add them to the store.
fn entity_or_record_to_access_terms(
    ty: &EntityRecordKind,
    store: &mut AccessDag,
    term: AccessTerm,
) -> Rc<WrappedAccessTerms> {
    match ty {
        EntityRecordKind::ActionEntity { attrs, .. } | EntityRecordKind::Record { attrs, .. } => {
            let mut terms = Rc::new(WrappedAccessTerms::default());
            for (attr_name, attr_type) in attrs.iter() {
                // Create a new term for this attribute
                let attr_variant = AccessTermVariant::Attribute {
                    of: term.clone(),
                    attr: attr_name.clone(),
                };
                let attr_term = store.add_term(attr_variant);

                terms = terms
                    .with_dropped_terms(Rc::new(WrappedAccessTerms::AccessTerm(attr_term.clone())));

                // Recursively process the attribute's type
                let attr_terms = type_to_access_terms(&attr_type.attr_type, store, attr_term);
                terms = terms.with_dropped_terms(attr_terms);
            }
            terms
        }
        EntityRecordKind::Entity(_) | EntityRecordKind::AnyEntity => {
            // no need to load data for entities, which are compared using ids
            WrappedAccessTerms::Empty.into()
        }
    }
}

/// A static analysis on type-annotated cedar expressions.
/// Computes the access terms required to evaluate the expression.
///
/// This function populates the provided `AccessDag` store with terms
/// and returns an `WrappedAccessTerms` analysis result.
/// The [`WrappedAccessTerms`] contains the result's access terms
/// and any access terms encountered during the analysis.
pub(crate) fn analyze_expr_access_paths(
    expr: &Expr<Option<Type>>,
    store: &mut AccessDag,
) -> Result<Rc<WrappedAccessTerms>, EntityManifestError> {
    Ok(match expr.expr_kind() {
        ExprKind::Slot(slot_id) => {
            if slot_id.is_principal() {
                WrappedAccessTerms::from_var(Var::Principal, store)
            } else {
                assert!(slot_id.is_resource());
                WrappedAccessTerms::from_var(Var::Resource, store)
            }
        }

        ExprKind::Var(var) => WrappedAccessTerms::from_var(*var, store),

        ExprKind::Lit(Literal::EntityUID(literal)) => {
            WrappedAccessTerms::from_euid((**literal).clone(), store)
        }

        ExprKind::Unknown(_) => Err(PartialExpressionError {})?,

        // We only care about strings so that we can handle
        // getting tags.
        ExprKind::Lit(lit) => {
            match lit {
                Literal::String(str) => {
                    let variant = AccessTermVariant::String(SmolStr::from(str.clone()));
                    let term = store.add_term(variant);
                    Rc::new(WrappedAccessTerms::AccessTerm(term))
                }
                _ => {
                    // empty terms for other literals
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
                .with_dropped_terms(test_result)
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
                .with_dropped_terms(arg2_result.require_full_type(ty2, store))
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
            // Collect terms from all arguments
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
            let mut combined_terms = Rc::new(WrappedAccessTerms::default());

            // Collect terms from all set elements
            for expr in &**contents {
                let element_result = analyze_expr_access_paths(expr, store)?;
                combined_terms = combined_terms.union(element_result.clone());
            }

            // Wrap the combined terms in a SetLiteral
            Rc::new(WrappedAccessTerms::SetLiteral(combined_terms))
        }

        ExprKind::Record(content) => {
            let mut record_contents = HashMap::new();

            // Collect terms from all record fields
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
        ExprKind::Error { .. } => return Err(ErrorExpressionError { expr: expr.clone() }.into()),
    })
}
