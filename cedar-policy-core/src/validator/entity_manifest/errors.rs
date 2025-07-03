use crate::ast::EntityUID;
use crate::entities::err::EntitiesError;
use crate::validator::ValidationResult;
use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

/// Error when entity slicing encounters a partial expression
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity slicing requires fully concrete policies. Got a policy with an unknown expression")]
pub struct PartialExpressionError {}

/// Error when entity slicing encounters a partial request
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity slicing requires a fully concrete request. Got a partial request")]
pub struct PartialRequestError {}

/// Error when encountering an unsupported Cedar feature
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity manifest analysis currently doesn't support Cedar feature: {feature}")]
pub struct UnsupportedCedarFeatureError {
    /// The name of the unsupported Cedar feature
    pub(crate) feature: SmolStr,
}

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

/// Error when access path is not found in entity manifest
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("access path not found in entity manifest. This may indicate that you are using the wrong entity manifest with this path")]
pub struct AccessPathNotFoundError {
    /// The ID of the access path that was not found
    pub(crate) path_id: usize,
}

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
    /// An unsupported Cedar feature was encountered
    #[error(transparent)]
    UnsupportedCedarFeature(#[from] UnsupportedCedarFeatureError),
}

/// Error when entity manifest is mismatched
#[derive(Debug, Clone, Error, Eq, PartialEq)]
pub enum MismatchedEntityManifestError {
    /// An entity is missing from the schema that exists in the manifest
    #[error(transparent)]
    MismatchedMissingEntity(#[from] MismatchedMissingEntityError),
    /// The schema is not in strict mode, which is required for entity manifests
    #[error(transparent)]
    MismatchedNotStrictSchema(#[from] MismatchedNotStrictSchemaError),
    /// An access path was not found in the entity manifest
    #[error(transparent)]
    AccessPathNotFound(#[from] AccessPathNotFoundError),
}

/// Error when parsing entity manifest from JSON
#[derive(Debug, Error)]
pub enum EntityManifestFromJsonError {
    /// JSON parsing error occurred
    #[error(transparent)]
    SerdeJsonParseError(#[from] serde_json::Error),
    /// Entity manifest doesn't match the expected schema
    #[error(transparent)]
    MismatchedEntityManifest(#[from] MismatchedEntityManifestError),
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
    IncompatibleEntityManifest(#[from] IncompatibleEntityManifestError),
    /// A required entity is missing from the entity store
    #[error(transparent)]
    EntityMissing(#[from] EntityMissingError),
    /// A required field is missing from an entity
    #[error(transparent)]
    EntityFieldMissing(#[from] EntityFieldMissingError),
    /// A required field is missing from a record
    #[error(transparent)]
    RecordFieldMissing(#[from] RecordFieldMissingError),
    /// The number of entities provided doesn't match the expected count
    #[error(transparent)]
    WrongNumberOfEntities(#[from] WrongNumberOfEntitiesError),
    /// Expected an entity type but found a different value type
    #[error(transparent)]
    ExpectedEntityType(#[from] ExpectedEntityTypeError),
    /// An error occurred with entity operations
    #[error(transparent)]
    Entities(#[from] EntitiesError),
}

/// Error when entity slicing encounters a partial context
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity slicing requires a fully concrete context. Got a partial context")]
pub struct PartialContextError {}

/// Error when entity slicing encounters a partial entity
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity slicing requires a fully concrete entity. Got a partial entity")]
pub struct PartialEntityError {}

/// Error when entity manifest encounters incompatible values
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity slicing encountered a non-record value where a record was expected: {non_record_entity_value:?}")]
pub struct IncompatibleEntityManifestError {
    /// The non-record entity value that was encountered
    pub non_record_entity_value: crate::ast::Value,
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

/// Error when wrong number of entities are provided
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("expected {expected} entities, got {got}")]
pub struct WrongNumberOfEntitiesError {
    /// The expected number of entities
    pub expected: usize,
    /// The actual number of entities received
    pub got: usize,
}

/// Error when expecting an entity type but got something else
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("expected entity type, found: {found_value:?}")]
pub struct ExpectedEntityTypeError {
    /// The value that was found instead of an entity type
    pub found_value: crate::ast::Value,
}

/// Error when parsing a path expression
#[derive(Debug, Clone, Error, Eq, PartialEq)]
pub enum PathExpressionParseError {
    /// Invalid root expression
    #[error("Invalid root expression: {0}")]
    InvalidRoot(String),
    /// Unsupported binary operator
    #[error("Unsupported binary operator: {operator:?}")]
    UnsupportedBinaryOperator {
        /// The unsupported binary operator that was encountered
        operator: String,
    },
    /// Unsupported expression type
    #[error("Unsupported expression type: {expr_type}")]
    UnsupportedExpressionType {
        /// The unsupported expression type that was encountered
        expr_type: String,
    },
}

impl Diagnostic for PathExpressionParseError {}

/// Error when converting between human-readable and DAG-based entity manifests
#[derive(Debug, Error)]
pub enum ConversionError {
    /// Error parsing a path expression
    #[error(transparent)]
    ParseError(#[from] PathExpressionParseError),
    /// Error serializing or deserializing JSON
    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),
    /// A mismatched entity manifest error
    #[error(transparent)]
    MismatchedEntityManifest(#[from] MismatchedEntityManifestError),
}
