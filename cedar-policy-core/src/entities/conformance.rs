use super::SchemaType;
use crate::ast::{EntityType, EntityUID};
use smol_str::SmolStr;
use thiserror::Error;

/// Errors raised when (non-action) entities do not conform to the schema.
#[derive(Debug, Error)]
pub enum EntitySchemaConformanceError {
    /// Encountered this attribute on this entity, but that attribute shouldn't
    /// exist on entities of this type
    #[error("attribute `{attr}` on `{uid}` should not exist according to the schema")]
    UnexpectedEntityAttr {
        /// Entity that had the unexpected attribute
        uid: EntityUID,
        /// Name of the attribute that was unexpected
        attr: SmolStr,
    },
    /// Didn't encounter this attribute of an entity, but that attribute should
    /// have existed
    #[error("expected entity `{uid}` to have an attribute `{attr}`, but it does not")]
    MissingRequiredEntityAttr {
        /// Entity that is missing a required attribute
        uid: EntityUID,
        /// Name of the attribute which was expected
        attr: SmolStr,
    },
    /// The given attribute on the given entity had a different type than the
    /// schema indicated to expect
    #[error("in attribute `{attr}` on `{uid}`, type mismatch: attribute was expected to have type {expected}, but actually has type {actual}")]
    TypeMismatch {
        /// Entity where the type mismatch occurred
        uid: EntityUID,
        /// Name of the attribute where the type mismatch occurred
        attr: SmolStr,
        /// Type which was expected
        expected: Box<SchemaType>,
        /// Type which was encountered instead
        actual: Box<SchemaType>,
    },
    /// During schema-based parsing, found a set whose elements don't all have the
    /// same type.  This doesn't match any possible schema.
    #[error(
        "in attribute `{attr}` on `{uid}`, set elements have different types: {ty1} and {ty2}"
    )]
    HeterogeneousSet {
        /// Entity where the error occurred
        uid: EntityUID,
        /// Name of the attribute where the error occurred
        attr: SmolStr,
        /// First element type which was found
        ty1: Box<SchemaType>,
        /// Second element type which was found
        ty2: Box<SchemaType>,
    },
    /// During schema-based parsing, found a parent of a type that's not allowed
    /// for that entity
    #[error(
        "`{uid}` is not allowed to have a parent of type `{parent_ty}` according to the schema"
    )]
    InvalidParentType {
        /// Entity that has an invalid parent type
        uid: EntityUID,
        /// Parent type which was invalid
        parent_ty: Box<EntityType>, // boxed to avoid this variant being very large (and thus all EntitySchemaConformanceErrors being large)
    },
}
