use super::{AttributeType, EntityTypeDescription, Schema, SchemaType, TypeMismatchError};
use crate::ast::{
    BorrowedRestrictedExpr, Entity, EntityType, EntityUID, ExprKind, Literal, Unknown,
};
use crate::extensions::{ExtensionFunctionLookupError, Extensions};
use smol_str::SmolStr;
use std::collections::HashMap;
use thiserror::Error;

/// Errors raised when entities do not conform to the schema
#[derive(Debug, Error)]
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
    #[error("entity `{uid}` has type `{}` which is not declared in the schema{}",
        &.uid.entity_type(),
        match .suggested_types.as_slice() {
            [] => String::new(),
            [ty] => format!(". Did you mean `{ty}`?"),
            tys => format!(". Did you mean one of {:?}?", tys.iter().map(ToString::to_string).collect::<Vec<String>>())
        }
    )]
    UnexpectedEntityType {
        /// Entity that had the unexpected type
        uid: EntityUID,
        /// Suggested similar entity types that actually are declared in the schema (if any)
        suggested_types: Vec<EntityType>,
    },
    /// Encountered an action which was not declared in the schema
    #[error("found action entity `{uid}`, but it was not declared as an action in the schema")]
    UndeclaredAction {
        /// Action which was not declared in the schema
        uid: EntityUID,
    },
    /// Encountered an action whose definition doesn't precisely match the
    /// schema's declaration of that action
    #[error("definition of action `{uid}` does not match its schema declaration")]
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
        err: ExtensionFunctionLookupError,
    },
}

/// Found a set whose elements don't all have the same type.  This doesn't match
/// any possible schema.
#[derive(Debug, Error)]
#[error("set elements have different types: {ty1} and {ty2}")]
pub struct HeterogeneousSetError {
    /// First element type which was found
    ty1: Box<SchemaType>,
    /// Second element type which was found
    ty2: Box<SchemaType>,
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
                .action(&uid)
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
                    EntityType::Concrete(name) => self
                        .schema
                        .entity_types_with_basename(name.basename())
                        .collect(),
                    EntityType::Unspecified => vec![],
                };
                EntitySchemaConformanceError::UnexpectedEntityType {
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
                        return Err(EntitySchemaConformanceError::UnexpectedEntityAttr {
                            uid: uid.clone(),
                            attr: attr.into(),
                        });
                    }
                    Some(expected_ty) => {
                        // typecheck: ensure that the entity attribute value matches
                        // the expected type
                        match type_of_restricted_expr(val.clone(), self.extensions) {
                            Ok(actual_ty) => {
                                if actual_ty.is_consistent_with(&expected_ty) {
                                    // typecheck passes
                                } else {
                                    return Err(EntitySchemaConformanceError::TypeMismatch {
                                        uid: uid.clone(),
                                        attr: attr.into(),
                                        err: TypeMismatchError {
                                            expected: Box::new(expected_ty),
                                            actual_ty: Some(Box::new(actual_ty)),
                                            actual_val: Box::new(val.to_owned()),
                                        },
                                    });
                                }
                            }
                            Err(TypeOfRestrictedExprError::UnknownInsufficientTypeInfo {
                                ..
                            }) => {
                                // in this case we just don't have the information to know whether
                                // the attribute value (an unknown) matches the expected type.
                                // For now we consider this as passing -- we can't really report a
                                // type error.
                            }
                            Err(TypeOfRestrictedExprError::HeterogeneousSet(err)) => {
                                return Err(EntitySchemaConformanceError::HeterogeneousSet {
                                    uid: uid.clone(),
                                    attr: attr.into(),
                                    err,
                                });
                            }
                            Err(TypeOfRestrictedExprError::ExtensionFunctionLookup(err)) => {
                                return Err(
                                    EntitySchemaConformanceError::ExtensionFunctionLookup {
                                        uid: uid.clone(),
                                        attr: attr.into(),
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

/// Errors thrown by [`type_of_restricted_expr()`]
#[derive(Debug, Error)]
pub enum TypeOfRestrictedExprError {
    /// Encountered a heterogeneous set. Heterogeneous sets do not have a valid
    /// `SchemaType`.
    #[error(transparent)]
    HeterogeneousSet(#[from] HeterogeneousSetError),
    /// Error looking up an extension function, which may be necessary for
    /// expressions that contain extension function calls -- not to actually
    /// call the extension function, but to get metadata about it
    #[error(transparent)]
    ExtensionFunctionLookup(#[from] ExtensionFunctionLookupError),
    /// Trying to compute the type of a restricted expression which contains
    /// an [`Unknown`] that has insufficient type information associated in
    /// order to compute the `SchemaType`
    #[error("cannot compute type because of insufficient type information for `{unknown}`")]
    UnknownInsufficientTypeInfo {
        /// `Unknown` which has insufficient type information
        unknown: Unknown,
    },
}

/// Get the [`SchemaType`] of a restricted expression.
///
/// This isn't possible for general `Expr`s (without a request, full schema,
/// etc), but is possible for restricted expressions, given the information in
/// `Extensions`.
///
/// For records, we can't know whether the attributes in the given record are
/// required or optional.
/// This function, when given a record that has keys A, B, and C, will return a
/// `SchemaType` where A, B, and C are all marked as optional attributes, but no
/// other attributes are possible.
/// That is, this assumes that all existing attributes are optional, but that no
/// other optional attributes are possible.
/// Compared to marking A, B, and C as required, this allows the returned
/// `SchemaType` to `is_consistent_with()` more types.
pub fn type_of_restricted_expr(
    rexpr: BorrowedRestrictedExpr<'_>,
    extensions: Extensions<'_>,
) -> Result<SchemaType, TypeOfRestrictedExprError> {
    match rexpr.expr_kind() {
        ExprKind::Lit(Literal::Bool(_)) => Ok(SchemaType::Bool),
        ExprKind::Lit(Literal::Long(_)) => Ok(SchemaType::Long),
        ExprKind::Lit(Literal::String(_)) => Ok(SchemaType::String),
        ExprKind::Lit(Literal::EntityUID(uid)) => Ok(SchemaType::Entity { ty: uid.entity_type().clone() }),
        ExprKind::Set(elements) => {
            let mut element_types = elements.iter().map(|el| {
                type_of_restricted_expr(BorrowedRestrictedExpr::new_unchecked(el), extensions) // assuming the invariant holds for the set as a whole, it will also hold for each element
            });
            match element_types.next() {
                None => Ok(SchemaType::EmptySet),
                Some(Err(e)) => Err(e),
                Some(Ok(element_ty)) => {
                    let matches_element_ty = |ty: &Result<SchemaType, TypeOfRestrictedExprError>| matches!(ty, Ok(ty) if ty.is_consistent_with(&element_ty));
                    let conflicting_ty = element_types.find(|ty| !matches_element_ty(ty));
                    match conflicting_ty {
                        None => Ok(SchemaType::Set { element_ty: Box::new(element_ty) }),
                        Some(Ok(conflicting_ty)) => Err(HeterogeneousSetError {
                                ty1: Box::new(element_ty),
                                ty2: Box::new(conflicting_ty),
                        }.into()),
                        Some(Err(e)) => Err(e),
                    }
                }
            }
        }
        ExprKind::Record(map) => {
            Ok(SchemaType::Record { attrs: {
                map.iter().map(|(k, v)| {
                    let attr_type = type_of_restricted_expr(
                        BorrowedRestrictedExpr::new_unchecked(v), // assuming the invariant holds for the record as a whole, it will also hold for each attribute value
                        extensions,
                    )?;
                    // we can't know if the attribute is required or optional,
                    // but marking it optional is more flexible -- allows the
                    // attribute type to `is_consistent_with()` more types
                    Ok((k.clone(), AttributeType::optional(attr_type)))
                }).collect::<Result<HashMap<_,_>, TypeOfRestrictedExprError>>()?
            }})
        }
        ExprKind::ExtensionFunctionApp { fn_name, .. } => {
            let efunc = extensions.func(fn_name)?;
            Ok(efunc.return_type().cloned().ok_or_else(|| ExtensionFunctionLookupError::HasNoType {
                name: efunc.name().clone()
            })?)
        }
        ExprKind::Unknown(u @ Unknown { type_annotation, .. }) => match type_annotation {
            None => Err(TypeOfRestrictedExprError::UnknownInsufficientTypeInfo { unknown: u.clone() }),
            Some(ty) => match SchemaType::from_ty(ty.clone()) {
                Some(ty) => Ok(ty),
                None => Err(TypeOfRestrictedExprError::UnknownInsufficientTypeInfo { unknown: u.clone() }),
            }
        }
        // PANIC SAFETY. Unreachable by invariant on restricted expressions
        #[allow(clippy::unreachable)]
        expr => unreachable!("internal invariant violation: BorrowedRestrictedExpr somehow contained this expr case: {expr:?}"),
    }
}
