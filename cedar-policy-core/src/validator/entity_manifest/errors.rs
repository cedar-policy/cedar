use crate::ast::{BinaryOp, EntityUID, Expr, Value};
use crate::entities::err::EntitiesError;
use crate::validator::types::Type;
use crate::validator::{self, ValidationResult};
use miette::Diagnostic;
use thiserror::Error;

/// General entity manifest error
#[derive(Debug, Error)]
pub enum EntityManifestError {
    /// A validation error occurred during entity manifest processing
    #[error("a validation error occurred")]
    Validation(ValidationResult),
    /// An error occurred with entity operations
    #[error(transparent)]
    Entities(#[from] EntitiesError),
    /// A partial request was encountered when a concrete request was required
    #[error(transparent)]
    PartialRequest(#[from] PartialRequestError),
    /// A partial expression was encountered when a concrete expression was required
    #[error(transparent)]
    PartialExpression(#[from] PartialExpressionError),
    /// An error expression was encountered
    #[error(transparent)]
    ErrorExpression(#[from] ErrorExpressionError),
}

/// Error when converting between human-readable and DAG-based entity manifests
#[derive(Debug, Error)]
pub enum ConversionError {
    /// Error parsing a path expression
    #[error(transparent)]
    ParseError(#[from] PathExpressionParseError),
    /// Error serializing or deserializing JSON
    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),
    /// Error typechecking the resulting entity manifest
    #[error(transparent)]
    EntityManifestTypecheck(#[from] EntityManifestTypecheckError),
}

/// Error when entity manifest is mismatched
#[derive(Debug, Clone, Error, Eq, PartialEq)]
pub enum EntityManifestTypecheckError {
    /// An entity is missing from the schema that exists in the manifest
    #[error(transparent)]
    MismatchedMissingEntity(#[from] MismatchedMissingEntityError),
    /// The schema is not in strict mode, which is required for entity manifests
    #[error(transparent)]
    MismatchedNotStrictSchema(#[from] MismatchedNotStrictSchemaError),
    /// The schema does not agree with the entity manifest, expected an entity or record type
    #[error(transparent)]
    ExpectedEntityOrRecordType(#[from] ExpectedEntityOrRecordTypeError),
    /// An schema does not match the entity manifest, expected an entity type
    #[error(transparent)]
    ExpectedEntityType(#[from] ExpectedEntityTypeError),
}

/// Error when parsing entity manifest from JSON
#[derive(Debug, Error)]
pub enum EntityManifestFromJsonError {
    /// JSON parsing error occurred
    #[error(transparent)]
    SerdeJsonParse(#[from] serde_json::Error),
    /// Entity manifest doesn't match the expected schema
    #[error(transparent)]
    EntityManifestTypecheck(#[from] EntityManifestTypecheckError),
}

/// Errors for entity slicing operations
#[derive(Debug, Error)]
pub enum EntitySliceError {
    /// A partial request was encountered when a concrete request was required
    #[error(transparent)]
    PartialRequest(#[from] PartialRequestError),
    /// A partial context was encountered when a concrete context was required
    #[error(transparent)]
    PartialContext(#[from] PartialContextError),
    /// A partial entity was encountered when a concrete entity was required
    #[error(transparent)]
    PartialEntity(#[from] PartialEntityError),
    /// The entity manifest is incompatible with the expected format
    #[error(transparent)]
    ExpectedEntityOrRecord(#[from] ExpectedEntityOrRecordError),

    /// A required entity is missing from the entity store
    #[error(transparent)]
    EntityMissing(#[from] EntityMissingError),
    /// A required field is missing from an entity
    #[error(transparent)]
    EntityFieldMissing(#[from] EntityFieldMissingError),
    /// A required field is missing from a record
    #[error(transparent)]
    RecordFieldMissing(#[from] RecordFieldMissingError),
    /// A required tag is missing from an entity
    #[error(transparent)]
    EntityTagMissing(#[from] EntityTagMissingError),
    /// Expected an entity type but found a different value type during loading
    #[error(transparent)]
    ExpectedEntity(#[from] ExpectedEntityError),
    /// Expected a string type but found a different value type during loading
    #[error(transparent)]
    ExpectedString(#[from] ExpectedStringError),
    /// Expected an entity or entity set but found something else
    #[error(transparent)]
    ExpectedEntityOrEntitySet(#[from] ExpectedEntityOrEntitySetError),
    /// An error when we got conflicting data for the same entity
    #[error(transparent)]
    ConflictingEntityData(#[from] ConflictingEntityDataError),
    /// A residual value was encountered during entity slicing
    #[error(transparent)]
    ResidualEncountered(#[from] ResidualEncounteredError),

    /// An error occurred with entity operations
    #[error(transparent)]
    Entities(#[from] EntitiesError),
}

/// Error when entity slicing encounters a partial expression
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity slicing requires fully concrete policies. Got a policy with an unknown expression")]
pub struct PartialExpressionError {}

/// An error expression was encountered while performing manifest analysis
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("error expression encountered while computing entity manifest: {expr}. Error expressions are not supported by entity manifests")]
pub struct ErrorExpressionError {
    /// The error expression
    pub(crate) expr: Expr<Option<validator::types::Type>>,
}

/// Error when entity slicing encounters a partial request
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity slicing requires a fully concrete request. Got a partial request")]
pub struct PartialRequestError {}

/// Error when entity manifest doesn't match the schema
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity manifest doesn't match schema. Schema is missing entity {entity}. Either you wrote an entity manifest by hand (not recommended) or you are using an out-of-date entity manifest with respect to the schema")]
pub struct MismatchedMissingEntityError {
    /// The entity UID that is missing from the schema
    pub(crate) entity: EntityUID,
}

/// Error when schema is not strict
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity manifests are only compatible with schemas that validate in strict mode. Tried to use an invalid schema with an entity manifest")]
pub struct MismatchedNotStrictSchemaError {}

/// Error when the schema does not agree with the entity manifest
/// and we expected an entity or record type
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity manifest doesn't match schema. We expected an entity or record type, but found a different type: {found_type}")]
pub struct ExpectedEntityOrRecordTypeError {
    /// The type that was found instead of an entity or record type
    pub(crate) found_type: Type,
}

/// Error when the schema does not agree with the entity manifest
/// and we expected an entity type
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity manifest doesn't match schema. We expected an entity type, but found a different type: {found_type}")]
pub struct ExpectedEntityTypeError {
    /// The type that was found instead of an entity type
    pub(crate) found_type: Type,
}

/// Error when access term is not found in entity manifest
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("access term not found in entity manifest. This may indicate that you are using the wrong entity manifest with this term")]
pub struct AccessTermNotFoundError {
    /// The ID of the access term that was not found
    pub(crate) path_id: usize,
}

/// Error when entity slicing encounters a partial context
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity slicing requires a fully concrete context. Got a partial context")]
pub struct PartialContextError {}

/// Error when entity slicing encounters a partial entity
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity slicing requires a fully concrete entity. Got a partial entity")]
pub struct PartialEntityError {}

/// Error when entity slicing encounters a residual value
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity slicing encountered a residual value for entity {entity_id}")]
pub struct ResidualEncounteredError {
    /// The entity ID where the residual was encountered
    pub entity_id: EntityUID,
}

/// Error when entity manifest encounters incompatible values
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity slicing encountered a non-record or entity value where a record or entity was expected: {non_record_entity_value:?}")]
pub struct ExpectedEntityOrRecordError {
    /// The non-record entity value that was encountered
    pub non_record_entity_value: Value,
}

/// Error when an entity is missing from the store
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity {entity_id} was missing from the entity store")]
pub struct EntityMissingError {
    /// The entity UID that is missing from the store
    pub entity_id: EntityUID,
}

/// Error when an entity field is missing
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity {entity:?} was missing field {field}")]
pub struct EntityFieldMissingError {
    /// The entity that is missing a field
    pub entity: crate::ast::Entity,
    /// The name of the missing field
    pub field: smol_str::SmolStr,
}

/// Error when a record field is missing
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("record was missing field {field}")]
pub struct RecordFieldMissingError {
    /// The name of the missing field
    pub field: smol_str::SmolStr,
}

/// Error when an entity tag is missing
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity {entity:?} was missing tag {tag}")]
pub struct EntityTagMissingError {
    /// The entity that is missing a tag
    pub entity: crate::ast::Entity,
    /// The name of the missing tag
    pub tag: smol_str::SmolStr,
}

/// Error when expecting an entity type but got something else
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("expected entity type, found: {found_value:?}")]
pub struct ExpectedEntityError {
    /// The value that was found instead of an entity type
    pub found_value: crate::ast::Value,
}

/// Error when expecting a string type but got something else
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("expected string type, found: {found_value:?}")]
pub struct ExpectedStringError {
    /// The value that was found instead of a string type
    pub found_value: crate::ast::Value,
}

/// Error when a user gives an entity twice with conflicting data
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error(
    "conflicting data for entity {entity_id}: old value {old_value:?}, new value {new_value:?}"
)]
pub struct ConflictingEntityDataError {
    /// The entity UID that has conflicting data
    pub entity_id: EntityUID,
    /// The conflicting data that was provided for the entity
    pub old_value: crate::ast::Value,
    /// The new value that conflicts with the old value
    pub new_value: crate::ast::Value,
}

/// Error whene expecting an entity or entity set but got something else
/// This is a specialized version of `ExpectedEntityTypeError` for cases where
/// an entity or entity set is expected, but a different type is found.
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("expected entity or entity set, found: {found_value:?}")]
pub struct ExpectedEntityOrEntitySetError {
    /// The value that was found instead of an entity or entity set
    pub found_value: crate::ast::Value,
}

/// Error when parsing a term expression
#[derive(Debug, Clone, Error, Eq, PartialEq)]
pub enum PathExpressionParseError {
    /// Invalid root expression
    #[error("Invalid root expression: {0}")]
    InvalidRoot(String),
    /// Unsupported binary operator
    #[error("Unsupported binary operator: {operator:?}")]
    UnsupportedBinaryOperator {
        /// The unsupported binary operator that was encountered
        operator: BinaryOp,
    },
    /// Unsupported expression type
    #[error("Unsupported path expression: {expr}. See the HumanEntityManifest documentation for supported cedar expressions.")]
    UnsupportedExpression {
        /// The unsupported expression type that was encountered
        expr: Expr,
    },
}

impl Diagnostic for PathExpressionParseError {}
