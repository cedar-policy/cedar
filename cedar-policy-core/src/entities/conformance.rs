use super::{
    schematype_of_restricted_expr, EntityTypeDescription, GetSchemaTypeError,
    HeterogeneousSetError, Schema, SchemaType, TypeMismatchError,
};
use crate::ast::{
    BorrowedRestrictedExpr, Entity, EntityType, EntityUID, PartialValue,
    PartialValueToRestrictedExprError, RestrictedExpr,
};
use crate::extensions::{ExtensionFunctionLookupError, Extensions};
use either::Either;
use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

/// Errors raised when entities do not conform to the schema
#[derive(Debug, Diagnostic, Error)]
pub enum EntitySchemaConformanceError {
    /// Encountered attribute that shouldn't exist on entities of this type
    #[error("attribute `{attr}` on `{uid}` should not exist according to the schema")]
    UnexpectedEntityAttr {
        /// Entity that had the unexpected attribute
        uid: EntityUID,
        /// Name of the attribute that was unexpected
        attr: SmolStr,
    },
    /// Didn't encounter attribute that should exist
    #[error("expected entity `{uid}` to have attribute `{attr}`, but it does not")]
    MissingRequiredEntityAttr {
        /// Entity that is missing a required attribute
        uid: EntityUID,
        /// Name of the attribute which was expected
        attr: SmolStr,
    },
    /// The given attribute on the given entity had a different type than the
    /// schema indicated
    #[error("in attribute `{attr}` on `{uid}`, {err}")]
    TypeMismatch {
        /// Entity where the type mismatch occurred
        uid: EntityUID,
        /// Name of the attribute where the type mismatch occurred
        attr: SmolStr,
        /// Underlying error
        #[diagnostic(transparent)]
        err: TypeMismatchError,
    },
    /// Found a set whose elements don't all have the same type. This doesn't match
    /// any possible schema.
    #[error("in attribute `{attr}` on `{uid}`, {err}")]
    HeterogeneousSet {
        /// Entity where the error occurred
        uid: EntityUID,
        /// Name of the attribute where the error occurred
        attr: SmolStr,
        /// Underlying error
        #[diagnostic(transparent)]
        err: HeterogeneousSetError,
    },
    /// Found an ancestor of a type that's not allowed for that entity
    #[error(
        "`{uid}` is not allowed to have an ancestor of type `{ancestor_ty}` according to the schema"
    )]
    InvalidAncestorType {
        /// Entity that has an invalid ancestor type
        uid: EntityUID,
        /// Ancestor type which was invalid
        ancestor_ty: Box<EntityType>, // boxed to avoid this variant being very large (and thus all EntitySchemaConformanceErrors being large)
    },
    /// Encountered an entity of a type which is not declared in the schema.
    /// Note that this error is only used for non-Action entity types.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnexpectedEntityType(#[from] UnexpectedEntityTypeError),
    /// Encountered an action which was not declared in the schema
    #[error("found action entity `{uid}`, but it was not declared as an action in the schema")]
    UndeclaredAction {
        /// Action which was not declared in the schema
        uid: EntityUID,
    },
    /// Encountered an action whose definition doesn't precisely match the
    /// schema's declaration of that action
    #[error("definition of action `{uid}` does not match its schema declaration")]
    #[diagnostic(help(
        "to use the schema's definition of `{uid}`, simply omit it from the entities input data"
    ))]
    ActionDeclarationMismatch {
        /// Action whose definition mismatched between entity data and schema
        uid: EntityUID,
    },
    /// Error looking up an extension function. This error can occur when
    /// checking entity conformance because that may require getting information
    /// about any extension functions referenced in entity attribute values.
    #[error("in attribute `{attr}` on `{uid}`, {err}")]
    ExtensionFunctionLookup {
        /// Entity where the error occurred
        uid: EntityUID,
        /// Name of the attribute where the error occurred
        attr: SmolStr,
        /// Underlying error
        #[diagnostic(transparent)]
        err: ExtensionFunctionLookupError,
    },
}

/// Encountered an entity of a type which is not declared in the schema.
/// Note that this error is only used for non-Action entity types.
#[derive(Debug, Error)]
#[error("entity `{uid}` has type `{}` which is not declared in the schema", .uid.entity_type())]
pub struct UnexpectedEntityTypeError {
    /// Entity that had the unexpected type
    pub uid: EntityUID,
    /// Suggested similar entity types that actually are declared in the schema (if any)
    pub suggested_types: Vec<EntityType>,
}

impl Diagnostic for UnexpectedEntityTypeError {
    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        match self.suggested_types.as_slice() {
            [] => None,
            [ty] => Some(Box::new(format!("did you mean `{ty}`?"))),
            tys => Some(Box::new(format!(
                "did you mean one of {:?}?",
                tys.iter().map(ToString::to_string).collect::<Vec<String>>()
            ))),
        }
    }
}

/// Struct used to check whether entities conform to a schema
#[derive(Debug, Clone)]
pub struct EntitySchemaConformanceChecker<'a, S: Schema> {
    /// Schema to check conformance with
    schema: &'a S,
    /// Extensions which are active for the conformance checks
    extensions: Extensions<'a>,
}

impl<'a, S: Schema> EntitySchemaConformanceChecker<'a, S> {
    /// Create a new checker
    pub fn new(schema: &'a S, extensions: Extensions<'a>) -> Self {
        Self { schema, extensions }
    }

    /// Validate an entity against the schema, returning an
    /// [`EntitySchemaConformanceError`] if it does not comply.
    pub fn validate_entity(&self, entity: &Entity) -> Result<(), EntitySchemaConformanceError> {
        let uid = entity.uid();
        let etype = uid.entity_type();
        if etype.is_action() {
            let schema_action = self
                .schema
                .action(uid)
                .ok_or(EntitySchemaConformanceError::UndeclaredAction { uid: uid.clone() })?;
            // check that the action exactly matches the schema's definition
            if !entity.deep_eq(&schema_action) {
                return Err(EntitySchemaConformanceError::ActionDeclarationMismatch {
                    uid: uid.clone(),
                });
            }
        } else {
            let schema_etype = self.schema.entity_type(etype).ok_or_else(|| {
                let suggested_types = match etype {
                    EntityType::Specified(name) => self
                        .schema
                        .entity_types_with_basename(name.basename())
                        .collect(),
                    EntityType::Unspecified => vec![],
                };
                UnexpectedEntityTypeError {
                    uid: uid.clone(),
                    suggested_types,
                }
            })?;
            // Ensure that all required attributes for `etype` are actually
            // included in `entity`
            for required_attr in schema_etype.required_attrs() {
                if entity.get(&required_attr).is_none() {
                    return Err(EntitySchemaConformanceError::MissingRequiredEntityAttr {
                        uid: uid.clone(),
                        attr: required_attr,
                    });
                }
            }
            // For each attribute that actually appears in `entity`, ensure it
            // complies with the schema
            for (attr, val) in entity.attrs() {
                match schema_etype.attr_type(attr) {
                    None => {
                        // `None` indicates the attribute shouldn't exist -- see
                        // docs on the `attr_type()` trait method
                        if !schema_etype.open_attributes() {
                            return Err(EntitySchemaConformanceError::UnexpectedEntityAttr {
                                uid: uid.clone(),
                                attr: attr.clone(),
                            });
                        }
                    }
                    Some(expected_ty) => {
                        // typecheck: ensure that the entity attribute value matches
                        // the expected type
                        match typecheck_value_against_schematype(val, &expected_ty, self.extensions)
                        {
                            Ok(()) => {} // typecheck passes
                            Err(TypecheckError::TypeMismatch(err)) => {
                                return Err(EntitySchemaConformanceError::TypeMismatch {
                                    uid: uid.clone(),
                                    attr: attr.clone(),
                                    err,
                                });
                            }
                            Err(TypecheckError::HeterogeneousSet(err)) => {
                                return Err(EntitySchemaConformanceError::HeterogeneousSet {
                                    uid: uid.clone(),
                                    attr: attr.clone(),
                                    err,
                                });
                            }
                            Err(TypecheckError::ExtensionFunctionLookup(err)) => {
                                return Err(
                                    EntitySchemaConformanceError::ExtensionFunctionLookup {
                                        uid: uid.clone(),
                                        attr: attr.clone(),
                                        err,
                                    },
                                );
                            }
                        }
                    }
                }
            }
            // For each ancestor that actually appears in `entity`, ensure the
            // ancestor type is allowed by the schema
            for ancestor_euid in entity.ancestors() {
                let ancestor_type = ancestor_euid.entity_type();
                if schema_etype.allowed_parent_types().contains(ancestor_type) {
                    // note that `allowed_parent_types()` was transitively
                    // closed, so it's actually `allowed_ancestor_types()`
                    //
                    // thus, the check passes in this case
                } else {
                    return Err(EntitySchemaConformanceError::InvalidAncestorType {
                        uid: uid.clone(),
                        ancestor_ty: Box::new(ancestor_type.clone()),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Check whether the given `PartialValue` typechecks with the given `SchemaType`.
/// If the typecheck passes, return `Ok(())`.
/// If the typecheck fails, return an appropriate `Err`.
pub fn typecheck_value_against_schematype(
    value: &PartialValue,
    expected_ty: &SchemaType,
    extensions: Extensions<'_>,
) -> Result<(), TypecheckError> {
    match RestrictedExpr::try_from(value.clone()) {
        Ok(expr) => typecheck_restricted_expr_against_schematype(
            expr.as_borrowed(),
            expected_ty,
            extensions,
        ),
        Err(PartialValueToRestrictedExprError::NontrivialResidual { .. }) => {
            // this case should be unreachable for the case of `PartialValue`s
            // which are entity attributes, because a `PartialValue` computed
            // from a `RestrictedExpr` should only have trivial residuals.
            // And as of this writing, there are no callers of this function that
            // pass anything other than entity attributes.
            // Nonetheless, rather than relying on these delicate invariants,
            // it's safe to consider this as passing.
            Ok(())
        }
    }
}

/// Check whether the given `RestrictedExpr` typechecks with the given `SchemaType`.
/// If the typecheck passes, return `Ok(())`.
/// If the typecheck fails, return an appropriate `Err`.
pub fn typecheck_restricted_expr_against_schematype(
    expr: BorrowedRestrictedExpr<'_>,
    expected_ty: &SchemaType,
    extensions: Extensions<'_>,
) -> Result<(), TypecheckError> {
    // TODO(#440): instead of computing the `SchemaType` of `expr` and then
    // checking whether the schematypes are "consistent", wouldn't it be less
    // confusing, more efficient, and maybe even more precise to just typecheck
    // directly?
    match schematype_of_restricted_expr(expr, extensions) {
        Ok(actual_ty) => {
            if actual_ty.is_consistent_with(expected_ty) {
                // typecheck passes
                Ok(())
            } else {
                Err(TypecheckError::TypeMismatch(TypeMismatchError {
                    expected: Box::new(expected_ty.clone()),
                    actual_ty: Some(Box::new(actual_ty)),
                    actual_val: Either::Right(Box::new(expr.to_owned())),
                }))
            }
        }
        Err(GetSchemaTypeError::UnknownInsufficientTypeInfo { .. }) => {
            // in this case we just don't have the information to know whether
            // the attribute value (an unknown) matches the expected type.
            // For now we consider this as passing -- we can't really report a
            // type error.
            Ok(())
        }
        Err(GetSchemaTypeError::NontrivialResidual { .. }) => {
            // this case is unreachable according to the invariant in the comments
            // on `schematype_of_restricted_expr()`.
            // Nonetheless, rather than relying on that invariant, it's safe to
            // treat this case like the case above and consider this as passing.
            Ok(())
        }
        Err(GetSchemaTypeError::HeterogeneousSet(err)) => {
            Err(TypecheckError::HeterogeneousSet(err))
        }
        Err(GetSchemaTypeError::ExtensionFunctionLookup(err)) => {
            Err(TypecheckError::ExtensionFunctionLookup(err))
        }
    }
}

/// Errors returned by [`typecheck_value_against_schematype()`] and
/// [`typecheck_restricted_expr_against_schematype()`]
#[derive(Debug, Diagnostic, Error)]
pub enum TypecheckError {
    /// The given value had a type different than what was expected
    #[error(transparent)]
    #[diagnostic(transparent)]
    TypeMismatch(#[from] TypeMismatchError),
    /// The given value contained a heterogeneous set, which doesn't conform to
    /// any possible `SchemaType`
    #[error(transparent)]
    #[diagnostic(transparent)]
    HeterogeneousSet(#[from] HeterogeneousSetError),
    /// Error looking up an extension function. This error can occur when
    /// typechecking a `RestrictedExpr` because that may require getting
    /// information about any extension functions referenced in the
    /// `RestrictedExpr`; and it can occur when typechecking a `PartialValue`
    /// because that may require getting information about any extension
    /// functions referenced in residuals.
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExtensionFunctionLookup(#[from] ExtensionFunctionLookupError),
}
