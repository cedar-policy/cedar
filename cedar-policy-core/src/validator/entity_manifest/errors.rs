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
    pub(crate) feature: SmolStr,
}

/// Error when entity manifest doesn't match the schema
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity manifest doesn't match schema. Schema is missing entity {entity}. Either you wrote an entity manifest by hand (not recommended) or you are using an out-of-date entity manifest with respect to the schema")]
pub struct MismatchedMissingEntityError {
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
    pub(crate) path_id: usize,
}

/// General entity manifest error
#[derive(Debug, Error)]
pub enum EntityManifestError {
    #[error("a validation error occurred")]
    Validation(ValidationResult),
    #[error(transparent)]
    Entities(#[from] EntitiesError),
    #[error(transparent)]
    PartialRequest(#[from] PartialRequestError),
    #[error(transparent)]
    PartialExpression(#[from] PartialExpressionError),
    #[error(transparent)]
    UnsupportedCedarFeature(#[from] UnsupportedCedarFeatureError),
}

/// Error when entity manifest is mismatched
#[derive(Debug, Clone, Error, Eq, PartialEq)]
pub enum MismatchedEntityManifestError {
    #[error(transparent)]
    MismatchedMissingEntity(#[from] MismatchedMissingEntityError),
    #[error(transparent)]
    MismatchedNotStrictSchema(#[from] MismatchedNotStrictSchemaError),
    #[error(transparent)]
    AccessPathNotFound(#[from] AccessPathNotFoundError),
}

/// Error when parsing entity manifest from JSON
#[derive(Debug, Error)]
pub enum EntityManifestFromJsonError {
    #[error(transparent)]
    SerdeJsonParseError(#[from] serde_json::Error),
    #[error(transparent)]
    MismatchedEntityManifest(#[from] MismatchedEntityManifestError),
}

/// Errors for entity slicing operations
#[derive(Debug, Error)]
pub enum EntitySliceError {
    #[error(transparent)]
    PartialRequest(#[from] PartialRequestError),
    #[error(transparent)]
    PartialContext(#[from] PartialContextError),
    #[error(transparent)]
    PartialEntity(#[from] PartialEntityError),
    #[error(transparent)]
    IncompatibleEntityManifest(#[from] IncompatibleEntityManifestError),
    #[error(transparent)]
    EntityMissing(#[from] EntityMissingError),
    #[error(transparent)]
    EntityFieldMissing(#[from] EntityFieldMissingError),
    #[error(transparent)]
    RecordFieldMissing(#[from] RecordFieldMissingError),
    #[error(transparent)]
    WrongNumberOfEntities(#[from] WrongNumberOfEntitiesError),
    #[error(transparent)]
    ExpectedEntityType(#[from] ExpectedEntityTypeError),
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
    pub non_record_entity_value: crate::ast::Value,
}

/// Error when an entity is missing from the store
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity {entity_id} was missing from the entity store")]
pub struct EntityMissingError {
    pub entity_id: EntityUID,
}

/// Error when an entity field is missing
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("entity {entity:?} was missing field {field}")]
pub struct EntityFieldMissingError {
    pub entity: crate::ast::Entity,
    pub field: smol_str::SmolStr,
}

/// Error when a record field is missing
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("record was missing field {field}")]
pub struct RecordFieldMissingError {
    pub field: smol_str::SmolStr,
}

/// Error when wrong number of entities are provided
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("expected {expected} entities, got {got}")]
pub struct WrongNumberOfEntitiesError {
    pub expected: usize,
    pub got: usize,
}

/// Error when expecting an entity type but got something else
#[derive(Debug, Clone, Error, Eq, PartialEq, Diagnostic)]
#[error("expected entity type, found: {found_value:?}")]
pub struct ExpectedEntityTypeError {
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
    UnsupportedBinaryOperator { operator: String },
    /// Unsupported expression type
    #[error("Unsupported expression type: {expr_type}")]
    UnsupportedExpressionType { expr_type: String },
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
