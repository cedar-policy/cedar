use crate::ast::EntityUID;
use crate::entities::err::EntitiesError;
use crate::validator::ValidationResult;
use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
#[error("entity slicing requires fully concrete policies. Got a policy with an unknown expression")]
pub struct PartialExpressionError {}

impl Diagnostic for PartialExpressionError {}

#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
#[error("entity slicing requires a fully concrete request. Got a partial request")]
pub struct PartialRequestError {}
impl Diagnostic for PartialRequestError {}

#[derive(Debug, Clone, Error, Diagnostic)]
#[error("entity manifest analysis currently doesn't support Cedar feature: {feature}")]
pub struct UnsupportedCedarFeatureError {
    pub(crate) feature: SmolStr,
}

#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
#[error("entity manifest doesn't match schema. Schema is missing entity {entity}. Either you wrote an entity manifest by hand (not recommended) or you are using an out-of-date entity manifest with respect to the schema")]
pub struct MismatchedMissingEntityError {
    pub(crate) entity: EntityUID,
}

#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
#[error("entity manifests are only compatible with schemas that validate in strict mode. Tried to use an invalid schema with an entity manifest")]
pub struct MismatchedNotStrictSchemaError {}

#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
#[error("access path not found in entity manifest. This may indicate that you are using the wrong entity manifest with this path")]
pub struct AccessPathNotFoundError {
    pub(crate) path_id: usize,
}

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

#[derive(Debug, Clone, Error, Hash, Eq, PartialEq)]
pub enum MismatchedEntityManifestError {
    #[error(transparent)]
    MismatchedMissingEntity(#[from] MismatchedMissingEntityError),
    #[error(transparent)]
    MismatchedNotStrictSchema(#[from] MismatchedNotStrictSchemaError),
    #[error(transparent)]
    AccessPathNotFoundError(#[from] AccessPathNotFoundError),
}

#[derive(Debug, Error)]
pub enum EntityManifestFromJsonError {
    #[error(transparent)]
    SerdeJsonParseError(#[from] serde_json::Error),
    #[error(transparent)]
    MismatchedEntityManifest(#[from] MismatchedEntityManifestError),
}

// Errors for entity slicing
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
}

#[derive(Debug, Error)]
#[error("entity slicing requires a fully concrete context. Got a partial context")]
pub struct PartialContextError {}

#[derive(Debug, Error)]
#[error("entity slicing requires a fully concrete entity. Got a partial entity")]
pub struct PartialEntityError {}

#[derive(Debug, Error)]
#[error("entity slicing encountered a non-record value where a record was expected: {non_record_entity_value:?}")]
pub struct IncompatibleEntityManifestError {
    pub non_record_entity_value: crate::ast::Value,
}

#[derive(Debug, Error)]
#[error("entity {entity_id} was missing from the entity store")]
pub struct EntityMissingError {
    pub entity_id: EntityUID,
}

#[derive(Debug, Error)]
#[error("entity {entity:?} was missing field {field}")]
pub struct EntityFieldMissingError {
    pub entity: crate::ast::Entity,
    pub field: smol_str::SmolStr,
}

#[derive(Debug, Error)]
#[error("record was missing field {field}")]
pub struct RecordFieldMissingError {
    pub field: smol_str::SmolStr,
}

#[derive(Debug, Error)]
#[error("expected {expected} entities, got {got}")]
pub struct WrongNumberOfEntitiesError {
    pub expected: usize,
    pub got: usize,
}
