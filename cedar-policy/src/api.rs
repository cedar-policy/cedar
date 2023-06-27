/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! This module contains the public library api
#![allow(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::similar_names
)]
pub use ast::Effect;
pub use authorizer::Decision;
use cedar_policy_core::ast;
use cedar_policy_core::authorizer;
use cedar_policy_core::entities;
use cedar_policy_core::entities::JsonDeserializationErrorContext;
use cedar_policy_core::entities::{ContextSchema, Dereference, JsonDeserializationError};
use cedar_policy_core::est;
use cedar_policy_core::evaluator::{Evaluator, RestrictedEvaluator};
pub use cedar_policy_core::extensions;
use cedar_policy_core::extensions::Extensions;
use cedar_policy_core::parser;
pub use cedar_policy_core::parser::err::ParseErrors;
use cedar_policy_core::parser::SourceInfo;
use cedar_policy_core::FromNormalizedStr;
pub use cedar_policy_validator::{TypeErrorKind, ValidationErrorKind, ValidationWarningKind};
use itertools::Itertools;
use ref_cast::RefCast;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;
use thiserror::Error;

/// Identifier for a Template slot
#[repr(transparent)]
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, RefCast)]
pub struct SlotId(ast::SlotId);

impl SlotId {
    /// Get the slot for `principal`
    pub fn principal() -> Self {
        Self(ast::SlotId::principal())
    }

    /// Get the slot for `resource`
    pub fn resource() -> Self {
        Self(ast::SlotId::resource())
    }
}

impl std::fmt::Display for SlotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<ast::SlotId> for SlotId {
    fn from(a: ast::SlotId) -> Self {
        Self(a)
    }
}

impl From<SlotId> for ast::SlotId {
    fn from(s: SlotId) -> Self {
        s.0
    }
}

/// Entity datatype
#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq, RefCast)]
pub struct Entity(ast::Entity);

impl Entity {
    /// Create a new `Entity` with this Uid, attributes, and parents.
    ///
    /// Attribute values are specified here as "restricted expressions".
    /// See docs on `RestrictedExpression`
    pub fn new(
        uid: EntityUid,
        attrs: HashMap<String, RestrictedExpression>,
        parents: HashSet<EntityUid>,
    ) -> Self {
        // note that we take a "parents" parameter here; we will compute TC when
        // the `Entities` object is created
        Self(ast::Entity::new(
            uid.0,
            attrs
                .into_iter()
                .map(|(k, v)| (SmolStr::from(k), v.0))
                .collect(),
            parents.into_iter().map(|uid| uid.0).collect(),
        ))
    }

    /// Create a new `Entity` with this Uid, no attributes, and no parents.
    pub fn with_uid(uid: EntityUid) -> Self {
        Self(ast::Entity::with_uid(uid.0))
    }

    /// Get the Uid of this entity
    pub fn uid(&self) -> EntityUid {
        EntityUid(self.0.uid())
    }

    /// Get the value for the given attribute, or `None` if not present.
    ///
    /// This can also return Some(Err) if the attribute had an illegal value.
    pub fn attr(&self, attr: &str) -> Option<Result<EvalResult, EvaluationError>> {
        let expr = self.0.get(attr)?;
        let all_ext = Extensions::all_available();
        let evaluator = RestrictedEvaluator::new(&all_ext);
        Some(
            evaluator
                .interpret(expr.as_borrowed())
                .map(EvalResult::from)
                .map_err(|e| EvaluationError::StringMessage(e.to_string())),
        )
    }
}

impl std::fmt::Display for Entity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents an entity hierarchy, and allows looking up `Entity` objects by
/// Uid.
#[repr(transparent)]
#[derive(Debug, Clone, Default, PartialEq, Eq, RefCast)]
pub struct Entities(pub(crate) entities::Entities);

pub use entities::EntitiesError;

impl Entities {
    /// Create a fresh `Entities` with no entities
    pub fn empty() -> Self {
        Self(entities::Entities::new())
    }

    /// Get the `Entity` with the given Uid, if any
    pub fn get(&self, uid: &EntityUid) -> Option<&Entity> {
        match self.0.entity(&uid.0) {
            Dereference::Residual(_) | Dereference::NoSuchEntity => None,
            Dereference::Data(e) => Some(Entity::ref_cast(e)),
        }
    }

    /// Transform the store into a partial store, where
    /// attempting to dereference a non-existent `EntityUID` results in
    /// a residual instead of an error.
    #[must_use]
    pub fn partial(self) -> Self {
        Self(self.0.partial())
    }

    /// Iterate over the `Entity`'s in the `Entities`
    pub fn iter(&self) -> impl Iterator<Item = &Entity> {
        self.0.iter().map(Entity::ref_cast)
    }

    /// Create an `Entities` object with the given entities
    /// It will error if the entities cannot be read or if the entities hierarchy is cyclic
    pub fn from_entities(
        entities: impl IntoIterator<Item = Entity>,
    ) -> Result<Self, entities::EntitiesError> {
        entities::Entities::from_entities(
            entities.into_iter().map(|e| e.0),
            entities::TCComputation::ComputeNow,
        )
        .map(Entities)
    }

    /// Parse an entities JSON file (in `&str` form) into an `Entities` object
    ///
    /// If a `schema` is provided, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit, and it will error
    /// if attributes have the wrong types (e.g., string instead of integer).
    pub fn from_json_str(
        json: &str,
        schema: Option<&Schema>,
    ) -> Result<Self, entities::EntitiesError> {
        let eparser = entities::EntityJsonParser::new(
            schema.map(|s| cedar_policy_validator::CoreSchema::new(&s.0)),
            Extensions::all_available(),
            entities::TCComputation::ComputeNow,
        );
        eparser.from_json_str(json).map(Entities)
    }

    /// Parse an entities JSON file (in `serde_json::Value` form) into an
    /// `Entities` object
    ///
    /// If a `schema` is provided, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit, and it will error
    /// if attributes have the wrong types (e.g., string instead of integer).
    pub fn from_json_value(
        json: serde_json::Value,
        schema: Option<&Schema>,
    ) -> Result<Self, entities::EntitiesError> {
        let eparser = entities::EntityJsonParser::new(
            schema.map(|s| cedar_policy_validator::CoreSchema::new(&s.0)),
            Extensions::all_available(),
            entities::TCComputation::ComputeNow,
        );
        eparser.from_json_value(json).map(Entities)
    }

    /// Parse an entities JSON file (in `std::io::Read` form) into an `Entities`
    /// object
    ///
    /// If a `schema` is provided, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit, and it will error
    /// if attributes have the wrong types (e.g., string instead of integer).
    pub fn from_json_file(
        json: impl std::io::Read,
        schema: Option<&Schema>,
    ) -> Result<Self, entities::EntitiesError> {
        let eparser = entities::EntityJsonParser::new(
            schema.map(|s| cedar_policy_validator::CoreSchema::new(&s.0)),
            Extensions::all_available(),
            entities::TCComputation::ComputeNow,
        );
        eparser.from_json_file(json).map(Entities)
    }

    /// Is entity `a` an ancestor of entity `b`?
    /// Same semantics as `b in a` in the Cedar language
    pub fn is_ancestor_of(&self, a: &EntityUid, b: &EntityUid) -> bool {
        match self.0.entity(&b.0) {
            Dereference::Data(b) => b.is_descendant_of(&a.0),
            _ => a == b, // if b doesn't exist, `b in a` is only true if `b == a`
        }
    }

    /// Get an iterator over the ancestors of the given Euid.
    /// Returns `None` if the given `Euid` does not exist.
    pub fn ancestors<'a>(
        &'a self,
        euid: &EntityUid,
    ) -> Option<impl Iterator<Item = &'a EntityUid>> {
        let entity = match self.0.entity(&euid.0) {
            Dereference::Residual(_) | Dereference::NoSuchEntity => None,
            Dereference::Data(e) => Some(e),
        }?;
        Some(entity.ancestors().map(EntityUid::ref_cast))
    }

    /// Dump an `Entities` object into an entities JSON file.
    ///
    /// The resulting JSON will be suitable for parsing in via
    /// `from_json_*`, and will be parse-able even with no `Schema`.
    ///
    /// To read an `Entities` object from an entities JSON file, use
    /// `from_json_file`.
    pub fn write_to_json(
        &self,
        f: impl std::io::Write,
    ) -> std::result::Result<(), entities::EntitiesError> {
        self.0.write_to_json(f)
    }
}

/// Authorizer object, which provides responses to authorization queries
#[repr(transparent)]
#[derive(Debug, RefCast)]
pub struct Authorizer(authorizer::Authorizer);

impl Default for Authorizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Authorizer {
    /// Create a new `Authorizer`
    pub fn new() -> Self {
        Self(authorizer::Authorizer::new())
    }

    /// Returns an authorization response for `r` with respect to the given
    /// `PolicySet` and `Entities`.
    ///
    /// The language spec and Dafny model give a precise definition of how this
    /// is computed.
    pub fn is_authorized(&self, r: &Request, p: &PolicySet, e: &Entities) -> Response {
        self.0.is_authorized(&r.0, &p.ast, &e.0).into()
    }

    /// A partially evaluated authorization request.
    /// The Authorizer will attempt to make as much progress as possible in the presence of unknowns.
    /// If the Authorizer can reach a response, it will return that response.
    /// Otherwise, it will return a list of residual policies that still need to be evaluated.
    pub fn is_authorized_partial(
        &self,
        query: &Request,
        policy_set: &PolicySet,
        entities: &Entities,
    ) -> PartialResponse {
        let response = self
            .0
            .is_authorized_core(&query.0, &policy_set.ast, &entities.0);
        match response {
            authorizer::ResponseKind::FullyEvaluated(a) => PartialResponse::Concrete(Response {
                decision: a.decision,
                diagnostics: Diagnostics {
                    reason: a.diagnostics.reason.into_iter().map(PolicyId).collect(),
                    errors: a.diagnostics.errors.into_iter().collect(),
                },
            }),
            authorizer::ResponseKind::Partial(p) => PartialResponse::Residual(ResidualResponse {
                residuals: PolicySet::from_ast(p.residuals),
                diagnostics: Diagnostics {
                    reason: p.diagnostics.reason.into_iter().map(PolicyId).collect(),
                    errors: p.diagnostics.errors.into_iter().collect(),
                },
            }),
        }
    }
}

/// Authorization response returned from the `Authorizer`
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Authorization decision
    decision: Decision,
    /// Diagnostics providing more information on how this decision was reached
    diagnostics: Diagnostics,
}

/// Authorization response returned from `is_authorized_partial`
/// It can either be a full concrete response, or a residual response.
#[derive(Debug, PartialEq, Clone)]
pub enum PartialResponse {
    /// A full, concrete response.
    Concrete(Response),
    /// A residual response. Determining the concrete response requires further processing.
    Residual(ResidualResponse),
}

/// A residual response obtained from `is_authorized_partial`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ResidualResponse {
    /// Residual policies
    residuals: PolicySet,
    /// Diagnostics
    diagnostics: Diagnostics,
}

/// Diagnostics providing more information on how a `Decision` was reached
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Diagnostics {
    /// `PolicyId`s of the policies that contributed to the decision.
    /// If no policies applied to the request, this set will be empty.
    reason: HashSet<PolicyId>,
    /// list of error messages which occurred
    errors: HashSet<String>,
}

impl Diagnostics {
    /// Get the policies that contributed to the decision
    pub fn reason(&self) -> impl Iterator<Item = &PolicyId> {
        self.reason.iter()
    }

    /// Get the error messages
    pub fn errors(&self) -> impl Iterator<Item = EvaluationError> + '_ {
        self.errors
            .iter()
            .cloned()
            .map(EvaluationError::StringMessage)
    }
}

impl Response {
    /// Create a new `Response`
    pub fn new(decision: Decision, reason: HashSet<PolicyId>, errors: HashSet<String>) -> Self {
        Self {
            decision,
            diagnostics: Diagnostics { reason, errors },
        }
    }

    /// Get the authorization decision
    pub fn decision(&self) -> Decision {
        self.decision
    }

    /// Get the authorization diagnostics
    pub fn diagnostics(&self) -> &Diagnostics {
        &self.diagnostics
    }
}

impl From<authorizer::Response> for Response {
    fn from(a: authorizer::Response) -> Self {
        Self {
            decision: a.decision,
            diagnostics: Diagnostics {
                reason: a.diagnostics.reason.into_iter().map(PolicyId).collect(),
                errors: a.diagnostics.errors.into_iter().collect(),
            },
        }
    }
}

impl ResidualResponse {
    /// Create a new `ResidualResponse`
    pub fn new(residuals: PolicySet, reason: HashSet<PolicyId>, errors: HashSet<String>) -> Self {
        Self {
            residuals,
            diagnostics: Diagnostics { reason, errors },
        }
    }

    /// Get the residual policies needed to reach an authorization decision.
    pub fn residuals(&self) -> &PolicySet {
        &self.residuals
    }

    /// Get the authorization diagnostics
    pub fn diagnostics(&self) -> &Diagnostics {
        &self.diagnostics
    }
}

/// Errors encountered while evaluating policies or expressions, or making
/// authorization decisions.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EvaluationError {
    /// Error message, as string.
    /// TODO in the future this can/should be the actual Core `EvaluationError`
    #[error("{0}")]
    StringMessage(String),
}

/// Used to select how a policy will be validated.
#[derive(Default, Eq, PartialEq, Copy, Clone, Debug)]
#[non_exhaustive]
pub enum ValidationMode {
    /// Validate that policies do not contain any type errors, and additionally
    /// have a restricted form which is amenable for analysis.
    #[default]
    Strict,
    /// Validate that policies do not contain any type errors.
    Permissive,
}

impl From<ValidationMode> for cedar_policy_validator::ValidationMode {
    fn from(mode: ValidationMode) -> Self {
        match mode {
            ValidationMode::Strict => Self::Strict,
            ValidationMode::Permissive => Self::Permissive,
        }
    }
}

/// Validator object, which provides policy validation and typechecking.
#[repr(transparent)]
#[derive(Debug, RefCast)]
pub struct Validator(cedar_policy_validator::Validator);

impl Validator {
    /// Construct a new `Validator` to validate policies using the given
    /// `Schema`.
    pub fn new(schema: Schema) -> Self {
        Self(cedar_policy_validator::Validator::new(schema.0))
    }

    /// Validate all policies in a policy set, collecting all validation errors
    /// found into the returned `ValidationResult`. Each error is returned together with the
    /// policy id of the policy where the error was found. If a policy id
    /// included in the input policy set does not appear in the output iterator, then
    /// that policy passed the validator. If the function `validation_passed`
    /// returns true, then there were no validation errors found, so all
    /// policies in the policy set have passed the validator.
    pub fn validate<'a>(
        &'a self,
        pset: &'a PolicySet,
        mode: ValidationMode,
    ) -> ValidationResult<'a> {
        ValidationResult::from(self.0.validate(&pset.ast, mode.into()))
    }
}

/// Contains all the type information used to construct a `Schema` that can be
/// used to validate a policy.
#[derive(Debug)]
pub struct SchemaFragment(cedar_policy_validator::ValidatorSchemaFragment);

impl SchemaFragment {
    /// Extract namespaces defined in this `SchemaFragment`. Each namespace
    /// entry defines the name of the namespace and the entity types and actions
    /// that exist in the namespace.
    pub fn namespaces(&self) -> impl Iterator<Item = Option<EntityNamespace>> + '_ {
        self.0
            .namespaces()
            .map(|ns| ns.as_ref().map(|ns| EntityNamespace(ns.clone())))
    }

    /// Create an `SchemaFragment` from a JSON value (which should be an
    /// object of the shape required for Cedar schemas).
    pub fn from_json_value(json: serde_json::Value) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_validator::SchemaFragment::from_json_value(json)?.try_into()?,
        ))
    }

    /// Create a `SchemaFragment` directly from a file.
    pub fn from_file(file: impl std::io::Read) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_validator::SchemaFragment::from_file(file)?.try_into()?,
        ))
    }
}

impl TryInto<Schema> for SchemaFragment {
    type Error = SchemaError;

    /// Convert `SchemaFragment` into a `Schema`. To build the `Schema` we
    /// need to have all entity types defined, so an error will be returned if
    /// any undeclared entity types are referenced in the schema fragment.
    fn try_into(self) -> Result<Schema, Self::Error> {
        Ok(Schema(
            cedar_policy_validator::ValidatorSchema::from_schema_fragments([self.0])?,
        ))
    }
}

impl FromStr for SchemaFragment {
    type Err = SchemaError;
    /// Construct `SchemaFragment` from a string containing a schema formatted
    /// in the cedar schema format. This can fail if the string is not valid
    /// JSON, or if the JSON structure does not form a valid schema. This
    /// function does not check for consistency in the schema (e.g., references
    /// to undefined entities) because this is not required until a `Schema` is
    /// constructed.
    fn from_str(src: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            serde_json::from_str::<cedar_policy_validator::SchemaFragment>(src)
                .map_err(cedar_policy_validator::SchemaError::from)?
                .try_into()?,
        ))
    }
}

/// Object containing schema information used by the validator.
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct Schema(pub(crate) cedar_policy_validator::ValidatorSchema);

impl FromStr for Schema {
    type Err = SchemaError;

    /// Construct a schema from a string containing a schema formatted in the
    /// Cedar schema format. This can fail if it is not possible to parse a
    /// schema from the strings, or if errors in values in the schema are
    /// uncovered after parsing. For instance, when an entity attribute name is
    /// found to not be a valid attribute name according to the Cedar
    /// grammar.
    fn from_str(schema_src: &str) -> Result<Self, Self::Err> {
        Ok(Self(schema_src.parse()?))
    }
}

impl Schema {
    /// Create a `Schema` from multiple `SchemaFragment`. The individual
    /// fragments may references entity types that are not declared in that
    /// fragment, but all referenced entity types must be declared in some
    /// fragment.
    pub fn from_schema_fragments(
        fragments: impl IntoIterator<Item = SchemaFragment>,
    ) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_validator::ValidatorSchema::from_schema_fragments(
                fragments.into_iter().map(|f| f.0),
            )?,
        ))
    }

    /// Create a `Schema` from a JSON value (which should be an object of the
    /// shape required for Cedar schemas).
    pub fn from_json_value(json: serde_json::Value) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_validator::ValidatorSchema::from_json_value(json)?,
        ))
    }

    /// Create a `Schema` directly from a file.
    pub fn from_file(file: impl std::io::Read) -> Result<Self, SchemaError> {
        Ok(Self(cedar_policy_validator::ValidatorSchema::from_file(
            file,
        )?))
    }

    /// Extract from the schema an `Entities` containing the action entities
    /// declared in the schema.
    pub fn action_entities(&self) -> Result<Entities, entities::EntitiesError> {
        Ok(Entities(self.0.action_entities()?))
    }
}

/// Errors encountered during construction of a Validation Schema
#[derive(Debug, Error)]
pub enum SchemaError {
    /// Errors loading and parsing schema files
    #[error("JSON Schema file could not be parsed: {0}")]
    ParseJson(serde_json::Error),
    /// Errors occurring while computing or enforcing transitive closure on
    /// action id hierarchy.
    #[error("Transitive closure error on action hierarchy: {0}")]
    ActionTransitiveClosureError(String),
    /// Errors occurring while computing or enforcing transitive closure on
    /// entity type hierarchy.
    #[error("Transitive closure error on entity hierarchy: {0}")]
    EntityTransitiveClosureError(String),
    /// Error generated when processing a schema file that uses features which
    /// are not yet supported by the implementation.
    #[error("Unsupported feature used in schema: {0}")]
    UnsupportedSchemaFeature(String),
    /// Undeclared entity type(s) used in an entity type's memberOf field or an
    /// action's appliesTo fields.
    #[error("Undeclared entity types: {0:?}")]
    UndeclaredEntityTypes(HashSet<String>),
    /// Undeclared action(s) used in an action's memberOf field.
    #[error("Undeclared actions: {0:?}")]
    UndeclaredActions(HashSet<String>),
    /// Undeclared type used in entity or context attributes.
    #[error("Undeclared common types: {0:?}")]
    UndeclaredCommonType(HashSet<String>),
    /// Duplicate specifications for an entity type. Argument is the name of
    /// the duplicate entity type.
    #[error("Duplicate entity type {0}")]
    DuplicateEntityType(String),
    /// Duplicate specifications for an action. Argument is the name of the
    /// duplicate action.
    #[error("Duplicate action {0}")]
    DuplicateAction(String),
    /// Duplicate specifications for a reusable common type. Argument is the
    /// name of the duplicate type.
    #[error("Duplicate common type {0}")]
    DuplicateCommonType(String),
    /// Cycle in the schema's action hierarchy.
    #[error("Cycle in action hierarchy")]
    CycleInActionHierarchy,
    /// Parse errors occurring while parsing an entity type.
    #[error("Parse error in entity type: {0}")]
    EntityTypeParse(ParseErrors),
    /// Parse errors occurring while parsing a namespace identifier.
    #[error("Parse error in namespace identifier: {0}")]
    NamespaceParse(ParseErrors),
    /// Parse errors occurring while parsing a common type identifier.
    #[error("Parse error in common type identifier: {0}")]
    CommonTypeParseError(ParseErrors),
    /// Parse errors occurring while parsing an extension type.
    #[error("Parse error in extension type: {0}")]
    ExtensionTypeParse(ParseErrors),
    /// The schema file included an entity type `Action` in the entity type
    /// list. The `Action` entity type is always implicitly declared, and it
    /// cannot currently have attributes or be in any groups, so there is no
    /// purposes in adding an explicit entry.
    #[error("Entity type `Action` declared in `entityTypes` list.")]
    ActionEntityTypeDeclared,
    /// One or more action entities are declared with `attributes` lists, but
    /// action entities cannot have attributes.
    #[error("Actions declared with `attributes`: [{}]", .0.iter().map(String::as_str).join(", "))]
    ActionEntityAttributes(Vec<String>),
    /// An action context or entity type shape was declared to have a type other
    /// than `Record`.
    #[error("{0} is not a record")]
    ContextOrShapeNotRecord(ContextOrShape),
    /// An Action Entity (transitively) has an attribute that is an empty set
    #[error("Action attribute is an empty set")]
    ActionEntityAttributeEmptySet,
    /// An Action Entity (transitively) has an attribute of unsupported type (ExprEscape, EntityEscape or ExtnEscape)
    #[error(
        "Action has an attribute of unsupported type (escaped expression, entity or extension)"
    )]
    ActionEntityAttributeUnsupportedType,
}

/// Describes in what action context or entity type shape a schema parsing error
/// occurred.
#[derive(Debug)]
pub enum ContextOrShape {
    /// An error occurred when parsing the context for the action with this
    /// `EntityUid`.
    ActionContext(EntityUid),
    /// An error occurred when parsing the shape for the entity type with this
    /// `EntityTypeName`.
    EntityTypeShape(EntityTypeName),
}

impl std::fmt::Display for ContextOrShape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActionContext(action) => write!(f, "Context for action {action}"),
            Self::EntityTypeShape(entity_type) => {
                write!(f, "Shape for entity type {entity_type}")
            }
        }
    }
}

impl From<cedar_policy_validator::ContextOrShape> for ContextOrShape {
    fn from(value: cedar_policy_validator::ContextOrShape) -> Self {
        match value {
            cedar_policy_validator::ContextOrShape::ActionContext(euid) => {
                Self::ActionContext(EntityUid(euid))
            }
            cedar_policy_validator::ContextOrShape::EntityTypeShape(name) => {
                Self::EntityTypeShape(EntityTypeName(name))
            }
        }
    }
}

#[doc(hidden)]
impl From<cedar_policy_validator::SchemaError> for SchemaError {
    fn from(value: cedar_policy_validator::SchemaError) -> Self {
        match value {
            cedar_policy_validator::SchemaError::ParseFileFormat(e) => Self::ParseJson(e),
            cedar_policy_validator::SchemaError::ActionTransitiveClosureError(e) => {
                Self::ActionTransitiveClosureError(e.to_string())
            }
            cedar_policy_validator::SchemaError::EntityTransitiveClosureError(e) => {
                Self::EntityTransitiveClosureError(e.to_string())
            }
            cedar_policy_validator::SchemaError::UnsupportedSchemaFeature(e) => {
                Self::UnsupportedSchemaFeature(e.to_string())
            }
            cedar_policy_validator::SchemaError::UndeclaredEntityTypes(e) => {
                Self::UndeclaredEntityTypes(e)
            }
            cedar_policy_validator::SchemaError::UndeclaredActions(e) => Self::UndeclaredActions(e),
            cedar_policy_validator::SchemaError::UndeclaredCommonType(c) => {
                Self::UndeclaredCommonType(c)
            }
            cedar_policy_validator::SchemaError::DuplicateEntityType(e) => {
                Self::DuplicateEntityType(e)
            }
            cedar_policy_validator::SchemaError::DuplicateAction(e) => Self::DuplicateAction(e),
            cedar_policy_validator::SchemaError::DuplicateCommonType(c) => {
                Self::DuplicateCommonType(c)
            }
            cedar_policy_validator::SchemaError::CycleInActionHierarchy => {
                Self::CycleInActionHierarchy
            }
            cedar_policy_validator::SchemaError::EntityTypeParseError(e) => {
                Self::EntityTypeParse(ParseErrors(e))
            }
            cedar_policy_validator::SchemaError::NamespaceParseError(e) => {
                Self::NamespaceParse(ParseErrors(e))
            }
            cedar_policy_validator::SchemaError::CommonTypeParseError(e) => {
                Self::CommonTypeParseError(ParseErrors(e))
            }
            cedar_policy_validator::SchemaError::ExtensionTypeParseError(e) => {
                Self::ExtensionTypeParse(ParseErrors(e))
            }
            cedar_policy_validator::SchemaError::ActionEntityTypeDeclared => {
                Self::ActionEntityTypeDeclared
            }
            cedar_policy_validator::SchemaError::ActionEntityAttributes(e) => {
                Self::ActionEntityAttributes(e)
            }
            cedar_policy_validator::SchemaError::ContextOrShapeNotRecord(context_or_shape) => {
                Self::ContextOrShapeNotRecord(context_or_shape.into())
            }
            cedar_policy_validator::SchemaError::ActionEntityAttributeEmptySet => {
                Self::ActionEntityAttributeEmptySet
            }
            cedar_policy_validator::SchemaError::ActionEntityAttributeUnsupportedType => {
                Self::ActionEntityAttributeUnsupportedType
            }
        }
    }
}

/// Contains the result of policy validation. The result includes the list of of
/// issues found by the validation and whether validation succeeds or fails.
/// Validation succeeds if there are no fatal errors.  There are currently no
/// non-fatal warnings, so any issues found will cause validation to fail.
#[derive(Debug)]
pub struct ValidationResult<'a> {
    validation_errors: Vec<ValidationError<'a>>,
}

impl<'a> ValidationResult<'a> {
    /// True when validation passes. There are no fatal errors.
    pub fn validation_passed(&self) -> bool {
        self.validation_errors.is_empty()
    }

    /// Get the list of errors found by the validator.
    pub fn validation_errors(&self) -> impl Iterator<Item = &ValidationError<'a>> {
        self.validation_errors.iter()
    }
}

impl<'a> From<cedar_policy_validator::ValidationResult<'a>> for ValidationResult<'a> {
    fn from(r: cedar_policy_validator::ValidationResult<'a>) -> Self {
        Self {
            validation_errors: r
                .into_validation_errors()
                .map(ValidationError::from)
                .collect(),
        }
    }
}

/// An error generated by the validator when it finds a potential problem in a
/// policy. The error contains a enumeration that specifies the kind of problem,
/// and provides details specific to that kind of problem. The error also records
/// where the problem was encountered.
#[derive(Debug, Error)]
pub struct ValidationError<'a> {
    location: SourceLocation<'a>,
    error_kind: ValidationErrorKind,
}

impl<'a> ValidationError<'a> {
    /// Extract details about the exact issue detected by the validator.
    pub fn error_kind(&self) -> &ValidationErrorKind {
        &self.error_kind
    }

    /// Extract the location where the validator found the issue.
    pub fn location(&self) -> &SourceLocation<'a> {
        &self.location
    }
}

impl<'a> From<cedar_policy_validator::ValidationError<'a>> for ValidationError<'a> {
    fn from(err: cedar_policy_validator::ValidationError<'a>) -> Self {
        let (location, error_kind) = err.into_location_and_error_kind();
        Self {
            location: SourceLocation::from(location),
            error_kind,
        }
    }
}

impl<'a> std::fmt::Display for ValidationError<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Validation error on policy {}", self.location.policy_id)?;
        if let (Some(range_start), Some(range_end)) =
            (self.location().range_start(), self.location().range_end())
        {
            write!(f, " at offset {range_start}-{range_end}")?;
        }
        write!(f, ": {}", self.error_kind())
    }
}

/// Represents a location in Cedar policy source.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SourceLocation<'a> {
    policy_id: &'a PolicyId,
    source_range: Option<SourceInfo>,
}

impl<'a> SourceLocation<'a> {
    /// Get the `PolicyId` for the policy at this source location.
    pub fn policy_id(&self) -> &'a PolicyId {
        self.policy_id
    }

    /// Get the start of the location. Returns `None` if this location does not
    /// have a range.
    pub fn range_start(&self) -> Option<usize> {
        self.source_range.as_ref().map(SourceInfo::range_start)
    }

    /// Get the end of the location. Returns `None` if this location does not
    /// have a range.
    pub fn range_end(&self) -> Option<usize> {
        self.source_range.as_ref().map(SourceInfo::range_end)
    }
}

impl<'a> From<cedar_policy_validator::SourceLocation<'a>> for SourceLocation<'a> {
    fn from(loc: cedar_policy_validator::SourceLocation<'a>) -> SourceLocation<'a> {
        let policy_id: &'a PolicyId = PolicyId::ref_cast(loc.policy_id());
        let source_range = loc.into_source_info();
        Self {
            policy_id,
            source_range,
        }
    }
}

/// Scan a set of policies for potentially confusing/obfuscating text.
pub fn confusable_string_checker<'a>(
    templates: impl Iterator<Item = &'a Template>,
) -> impl Iterator<Item = ValidationWarning<'a>> {
    cedar_policy_validator::confusable_string_checks(templates.map(|t| &t.ast))
        .map(std::convert::Into::into)
}

#[derive(Debug, Error)]
#[error("Warning on policy {}: {}", .location.policy_id, .kind)]
/// Warnings found in Cedar policies
pub struct ValidationWarning<'a> {
    location: SourceLocation<'a>,
    kind: ValidationWarningKind,
}

impl<'a> ValidationWarning<'a> {
    /// Extract details about the exact issue detected by the validator.
    pub fn warning_kind(&self) -> &ValidationWarningKind {
        &self.kind
    }

    /// Extract the location where the validator found the issue.
    pub fn location(&self) -> &SourceLocation<'a> {
        &self.location
    }
}

#[doc(hidden)]
impl<'a> From<cedar_policy_validator::ValidationWarning<'a>> for ValidationWarning<'a> {
    fn from(w: cedar_policy_validator::ValidationWarning<'a>) -> Self {
        let (loc, kind) = w.to_kind_and_location();
        ValidationWarning {
            location: SourceLocation {
                policy_id: PolicyId::ref_cast(loc),
                source_range: None,
            },
            kind,
        }
    }
}

/// unique identifier portion of the `EntityUid` type
#[repr(transparent)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, RefCast)]
pub struct EntityId(ast::Eid);

impl FromStr for EntityId {
    type Err = ParseErrors;
    fn from_str(eid_str: &str) -> Result<Self, Self::Err> {
        Ok(Self(ast::Eid::new(eid_str)))
    }
}

impl AsRef<str> for EntityId {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

// Note that this Display formatter will format the EntityId as it would be expected
// in the EntityUid string form. For instance, the `"alice"` in `User::"alice"`.
// This means it adds quotes and potentially performs some escaping.
impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents a concatenation of Namespaces and `TypeName`
#[repr(transparent)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, RefCast)]
pub struct EntityTypeName(ast::Name);

impl EntityTypeName {
    /// Get the basename of the `EntityTypeName` (ie, with namespaces stripped).
    pub fn basename(&self) -> &str {
        self.0.basename().as_ref()
    }

    /// Get the namespace of the `EntityTypeName`, as components
    pub fn namespace_components(&self) -> impl Iterator<Item = &str> {
        self.0.namespace_components().map(AsRef::as_ref)
    }

    /// Get the full namespace of the `EntityTypeName`, as a single string.
    ///
    /// Examples:
    /// - `foo::bar` --> the namespace is `"foo"`
    /// - `bar` --> the namespace is `""`
    /// - `foo::bar::baz` --> the namespace is `"foo::bar"`
    pub fn namespace(&self) -> String {
        self.0.namespace()
    }
}

// This FromStr implementation requires the _normalized_ representation of the
// type name. See https://github.com/cedar-policy/rfcs/pull/9/.
impl FromStr for EntityTypeName {
    type Err = ParseErrors;

    fn from_str(namespace_type_str: &str) -> Result<Self, Self::Err> {
        ast::Name::from_normalized_str(namespace_type_str)
            .map(EntityTypeName)
            .map_err(ParseErrors)
    }
}

impl std::fmt::Display for EntityTypeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents a namespace
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntityNamespace(ast::Name);

// This FromStr implementation requires the _normalized_ representation of the
// namespace. See https://github.com/cedar-policy/rfcs/pull/9/.
impl FromStr for EntityNamespace {
    type Err = ParseErrors;

    fn from_str(namespace_str: &str) -> Result<Self, Self::Err> {
        ast::Name::from_normalized_str(namespace_str)
            .map(EntityNamespace)
            .map_err(ParseErrors)
    }
}

impl std::fmt::Display for EntityNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique Id for an entity, such as `User::"alice"`
#[repr(transparent)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, RefCast)]
pub struct EntityUid(ast::EntityUID);

impl EntityUid {
    /// Returns the portion of the Euid that represents namespace and entity type
    pub fn type_name(&self) -> &EntityTypeName {
        match self.0.entity_type() {
            ast::EntityType::Unspecified => panic!("Impossible to have an unspecified entity"),
            ast::EntityType::Concrete(name) => EntityTypeName::ref_cast(name),
        }
    }

    /// Returns the id portion of the Euid
    pub fn id(&self) -> &EntityId {
        EntityId::ref_cast(self.0.eid())
    }

    /// Creates `EntityUid` from `EntityTypeName` and `EntityId`
    pub fn from_type_name_and_id(name: EntityTypeName, id: EntityId) -> Self {
        Self(ast::EntityUID::from_components(name.0, id.0))
    }

    /// Creates `EntityUid` from a JSON value, which should have
    /// either the implicit or explicit `__entity` form.
    ///
    /// Examples:
    /// * `{ "__entity": { "type": "User", "id": "123abc" } }`
    /// * `{ "type": "User", "id": "123abc" }`
    pub fn from_json(json: serde_json::Value) -> Result<Self, impl std::error::Error> {
        let parsed: entities::EntityUidJSON = serde_json::from_value(json)?;
        Ok::<Self, entities::JsonDeserializationError>(Self(
            parsed.into_euid(|| JsonDeserializationErrorContext::EntityUid)?,
        ))
    }

    /// Testing utility for creating `EntityUids` a bit easier
    #[cfg(test)]
    pub(crate) fn from_strs(typename: &str, id: &str) -> Self {
        Self::from_type_name_and_id(
            EntityTypeName::from_str(typename).unwrap(),
            EntityId::from_str(id).unwrap(),
        )
    }
}

// This FromStr implementation requires the _normalized_ representation of the
// UID. See https://github.com/cedar-policy/rfcs/pull/9/.
impl FromStr for EntityUid {
    type Err = ParseErrors;

    /// This is deprecated (starting with Cedar 1.2); use
    /// `EntityUid::from_type_name_and_id()` or `EntityUid::from_json()`
    /// instead.
    //
    // You can't actually `#[deprecated]` a trait implementation or trait
    // method.
    fn from_str(uid_str: &str) -> Result<Self, Self::Err> {
        ast::EntityUID::from_normalized_str(uid_str)
            .map(EntityUid)
            .map_err(ParseErrors)
    }
}

impl std::fmt::Display for EntityUid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Potential errors when adding to a `PolicySet`.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum PolicySetError {
    /// There was a `PolicyId` collision in either the set of templates or the set of policies.
    #[error("Collision in template or policy id")]
    AlreadyDefined,
    /// Error when instantiating a template.
    #[error("Unable to link template: {0}")]
    LinkingError(#[from] ast::LinkingError),
    /// Expected an static policy, but a template-linked policy was provided.
    #[error("Expected static policy, but a template-linked policy was provided")]
    ExpectedStatic,
}

impl From<ast::PolicySetError> for PolicySetError {
    fn from(e: ast::PolicySetError) -> Self {
        match e {
            ast::PolicySetError::Occupied => Self::AlreadyDefined,
        }
    }
}

impl From<ast::ContainsSlot> for PolicySetError {
    fn from(_: ast::ContainsSlot) -> Self {
        Self::ExpectedStatic
    }
}

/// Represents a set of `Policy`s
#[derive(Debug, Clone, Default)]
pub struct PolicySet {
    /// AST representation. Technically partially redundant with the other fields.
    /// Internally, we ensure that the duplicated information remains consistent.
    pub(crate) ast: ast::PolicySet,
    /// Policies in the set (this includes both static policies and template linked-policies)
    policies: HashMap<PolicyId, Policy>,
    /// Templates in the set
    templates: HashMap<PolicyId, Template>,
}

impl PartialEq for PolicySet {
    fn eq(&self, other: &Self) -> bool {
        // eq is based on just the `ast`
        self.ast.eq(&other.ast)
    }
}
impl Eq for PolicySet {}

impl FromStr for PolicySet {
    type Err = ParseErrors;

    /// Create a policy set from multiple statements.
    ///
    /// Policy ids will default to "policy*" with numbers from 0
    /// If you load more policies, do not use the default id, or there will be conflicts.
    ///
    /// See [`Policy`] for more.
    fn from_str(policies: &str) -> Result<Self, Self::Err> {
        let (texts, pset) = parser::parse_policyset_and_also_return_policy_text(policies)?;
        let policies = pset.policies().map(|p|
            (
                PolicyId(p.id().clone()),
                Policy { lossless: LosslessPolicy::policy_or_template_text(*texts.get(p.id()).expect("internal invariant violation: policy id exists in asts but not texts")), ast: p.clone() }
            )
        ).collect();
        let templates = pset.templates().map(|t|
            (
                PolicyId(t.id().clone()),
                Template { lossless: LosslessPolicy::policy_or_template_text(*texts.get(t.id()).expect("internal invariant violation: template id exists in asts but not ests")), ast: t.clone() }
            )
        ).collect();
        Ok(Self {
            ast: pset,
            policies,
            templates,
        })
    }
}

impl PolicySet {
    /// Create a fresh empty `PolicySet`
    pub fn new() -> Self {
        Self {
            ast: ast::PolicySet::new(),
            policies: HashMap::new(),
            templates: HashMap::new(),
        }
    }

    /// Create a `PolicySet` from the given policies
    pub fn from_policies(
        policies: impl IntoIterator<Item = Policy>,
    ) -> Result<Self, PolicySetError> {
        let mut set = Self::new();
        for policy in policies {
            set.add(policy)?;
        }
        Ok(set)
    }

    /// Add an static policy to the `PolicySet`. To add a template instance, use
    /// `link` instead. This function will return an error (and not modify
    /// the `PolicySet`) if a template-linked policy is passed in.
    pub fn add(&mut self, policy: Policy) -> Result<(), PolicySetError> {
        if policy.is_static() {
            let id = PolicyId(policy.ast.id().clone());
            self.ast.add(policy.ast.clone())?;
            self.policies.insert(id, policy);
            Ok(())
        } else {
            Err(PolicySetError::ExpectedStatic)
        }
    }

    /// Add a `Template` to the `PolicySet`
    pub fn add_template(&mut self, template: Template) -> Result<(), PolicySetError> {
        let id = PolicyId(template.ast.id().clone());
        self.ast.add_template(template.ast.clone())?;
        self.templates.insert(id, template);
        Ok(())
    }

    /// Iterate over all the `Policy`s in the `PolicySet`.
    ///
    /// This will include both static and template-linked policies.
    pub fn policies(&self) -> impl Iterator<Item = &Policy> {
        self.policies.values()
    }

    /// Iterate over the `Template`'s in the `PolicySet`.
    pub fn templates(&self) -> impl Iterator<Item = &Template> {
        self.templates.values()
    }

    /// Get a `Template` by its `PolicyId`
    pub fn template(&self, id: &PolicyId) -> Option<&Template> {
        self.templates.get(id)
    }

    /// Get a `Policy` by its `PolicyId`
    pub fn policy(&self, id: &PolicyId) -> Option<&Policy> {
        self.policies.get(id)
    }

    /// Extract annotation data from a `Policy` by its `PolicyId` and annotation key
    pub fn annotation<'a>(&'a self, id: &PolicyId, key: impl AsRef<str>) -> Option<&'a str> {
        self.ast
            .get(&id.0)?
            .annotation(&key.as_ref().parse().ok()?)
            .map(smol_str::SmolStr::as_str)
    }

    /// Extract annotation data from a `Template` by its `PolicyId` and annotation key.
    pub fn template_annotation(&self, id: &PolicyId, key: impl AsRef<str>) -> Option<String> {
        self.ast
            .get_template(&id.0)?
            .annotation(&key.as_ref().parse().ok()?)
            .map(smol_str::SmolStr::to_string)
    }

    /// Returns true iff the `PolicySet` is empty
    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(
            self.ast.is_empty(),
            self.policies.is_empty() && self.templates.is_empty()
        );
        self.ast.is_empty()
    }

    /// Attempt to link a template and add the new template-linked policy to the policy set.
    /// If link fails, the `PolicySet` is not modified.
    /// Failure can happen for two reasons
    ///   1) The map passed in `vals` may not match the slots in the template
    ///   2) The `new_id` may conflict w/ a policy that already exists in the set
    #[allow(clippy::needless_pass_by_value)]
    pub fn link(
        &mut self,
        template_id: PolicyId,
        new_id: PolicyId,
        vals: HashMap<SlotId, EntityUid>,
    ) -> Result<(), PolicySetError> {
        let unwrapped_vals: HashMap<ast::SlotId, ast::EntityUID> = vals
            .into_iter()
            .map(|(key, value)| (key.into(), value.0))
            .collect();
        self.ast
            .link(
                template_id.0.clone(),
                new_id.0.clone(),
                unwrapped_vals.clone(),
            )
            .map_err(PolicySetError::LinkingError)?;
        let linked_ast = self
            .ast
            .get(&new_id.0)
            .expect("ast.link() didn't fail above, so this shouldn't fail");
        let linked_lossless = self
            .templates
            .get(&template_id)
            .expect("ast.link() didn't fail above, so this shouldn't fail")
            .lossless
            .clone()
            .link(unwrapped_vals.iter().map(|(k, v)| (*k, v)))
            .expect("ast.link() didn't fail above, so this shouldn't fail");
        self.policies.insert(
            new_id,
            Policy {
                ast: linked_ast.clone(),
                lossless: linked_lossless,
            },
        );
        Ok(())
    }

    /// Create a `PolicySet` from its AST representation only. The EST will
    /// reflect the AST structure. When possible, don't use this method and
    /// create the ESTs from the policy text or CST instead, as the conversion
    /// to AST is lossy. ESTs generated by this method will reflect the AST and
    /// not the original policy syntax.
    fn from_ast(ast: ast::PolicySet) -> Self {
        let policies = ast
            .policies()
            .map(|p| (PolicyId(p.id().clone()), Policy::from_ast(p.clone())))
            .collect();
        let templates = ast
            .templates()
            .map(|t| (PolicyId(t.id().clone()), Template::from_ast(t.clone())))
            .collect();
        Self {
            ast,
            policies,
            templates,
        }
    }
}

impl std::fmt::Display for PolicySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ast)
    }
}

/// Policy template datatype
#[derive(Debug, Clone)]
pub struct Template {
    /// AST representation of the template, used for most operations.
    /// In particular, the `ast` contains the authoritative `PolicyId` for the template.
    ast: ast::Template,

    /// Some "lossless" representation of the template, whichever is most
    /// convenient to provide (and can be provided with the least overhead).
    /// This is used just for `to_json()`.
    /// We can't just derive this on-demand from `ast`, because the AST is lossy:
    /// we can't reconstruct an accurate CST/EST/policy-text from the AST, but
    /// we can from the EST (modulo whitespace and a few other things like the
    /// order of annotations).
    ///
    /// This is a `LosslessPolicy` (rather than something like `LosslessTemplate`)
    /// because the EST doesn't distinguish between static policies and templates.
    lossless: LosslessPolicy,
}

impl PartialEq for Template {
    fn eq(&self, other: &Self) -> bool {
        // eq is based on just the `ast`
        self.ast.eq(&other.ast)
    }
}
impl Eq for Template {}

impl Template {
    /// Attempt to parse a `Template` from source.
    /// If `id` is Some, then the resulting template will have that `id`.
    /// If the `id` is None, the parser will use the default "policy0".
    /// The behavior around None may change in the future.
    pub fn parse(id: Option<String>, src: impl AsRef<str>) -> Result<Self, ParseErrors> {
        let ast = parser::parse_policy_template(id, src.as_ref()).map_err(ParseErrors)?;
        Ok(Self {
            ast,
            lossless: LosslessPolicy::policy_or_template_text(src.as_ref()),
        })
    }

    /// Get the `PolicyId` of this `Template`
    pub fn id(&self) -> &PolicyId {
        PolicyId::ref_cast(self.ast.id())
    }

    /// Clone this `Template` with a new `PolicyId`
    #[must_use]
    pub fn new_id(&self, id: PolicyId) -> Self {
        Self {
            ast: self.ast.new_id(id.0),
            lossless: self.lossless.clone(), // Lossless representation doesn't include the `PolicyId`
        }
    }

    /// Get the `Effect` (`Forbid` or `Permit`) of this `Template`
    pub fn effect(&self) -> Effect {
        self.ast.effect()
    }

    /// Get an annotation value of this `Template`
    pub fn annotation(&self, key: impl AsRef<str>) -> Option<&str> {
        self.ast
            .annotation(&key.as_ref().parse().ok()?)
            .map(smol_str::SmolStr::as_str)
    }

    /// Iterate through annotation data of this `Template` as key-value pairs
    pub fn annotations(&self) -> impl Iterator<Item = (&str, &str)> {
        self.ast
            .annotations()
            .map(|(k, v)| (k.as_ref(), v.as_str()))
    }

    /// Iterate over the open slots in this `Template`
    pub fn slots(&self) -> impl Iterator<Item = &SlotId> {
        self.ast.slots().map(SlotId::ref_cast)
    }

    /// Get the head constraint on this policy's principal
    pub fn principal_constraint(&self) -> TemplatePrincipalConstraint {
        match self.ast.principal_constraint().as_inner() {
            ast::PrincipalOrResourceConstraint::Any => TemplatePrincipalConstraint::Any,
            ast::PrincipalOrResourceConstraint::In(eref) => {
                TemplatePrincipalConstraint::In(match eref {
                    ast::EntityReference::EUID(e) => Some(EntityUid(e.as_ref().clone())),
                    ast::EntityReference::Slot => None,
                })
            }
            ast::PrincipalOrResourceConstraint::Eq(eref) => {
                TemplatePrincipalConstraint::Eq(match eref {
                    ast::EntityReference::EUID(e) => Some(EntityUid(e.as_ref().clone())),
                    ast::EntityReference::Slot => None,
                })
            }
        }
    }

    /// Get the head constraint on this policy's action
    pub fn action_constraint(&self) -> ActionConstraint {
        // Clone the data from Core to be consistent with the other constraints
        match self.ast.action_constraint() {
            ast::ActionConstraint::Any => ActionConstraint::Any,
            ast::ActionConstraint::In(ids) => ActionConstraint::In(
                ids.iter()
                    .map(|id| EntityUid(id.as_ref().clone()))
                    .collect(),
            ),
            ast::ActionConstraint::Eq(id) => ActionConstraint::Eq(EntityUid(id.as_ref().clone())),
        }
    }

    /// Get the head constraint on this policy's resource
    pub fn resource_constraint(&self) -> TemplateResourceConstraint {
        match self.ast.resource_constraint().as_inner() {
            ast::PrincipalOrResourceConstraint::Any => TemplateResourceConstraint::Any,
            ast::PrincipalOrResourceConstraint::In(eref) => {
                TemplateResourceConstraint::In(match eref {
                    ast::EntityReference::EUID(e) => Some(EntityUid(e.as_ref().clone())),
                    ast::EntityReference::Slot => None,
                })
            }
            ast::PrincipalOrResourceConstraint::Eq(eref) => {
                TemplateResourceConstraint::Eq(match eref {
                    ast::EntityReference::EUID(e) => Some(EntityUid(e.as_ref().clone())),
                    ast::EntityReference::Slot => None,
                })
            }
        }
    }

    /// Create a `Template` from its JSON representation.
    /// If `id` is Some, the policy will be given that Policy Id.
    /// If `id` is None, then "JSON policy" will be used.
    /// The behavior around None may change in the future.
    #[allow(dead_code)] // planned to be a public method in the future
    fn from_json(
        id: Option<PolicyId>,
        json: serde_json::Value,
    ) -> Result<Self, cedar_policy_core::est::EstToAstError> {
        let est: est::Policy =
            serde_json::from_value(json).map_err(JsonDeserializationError::Serde)?;
        Ok(Self {
            ast: est.clone().try_into_ast_template(id.map(|id| id.0))?,
            lossless: LosslessPolicy::Est(est),
        })
    }

    /// Get the JSON representation of this `Template`.
    #[allow(dead_code)] // planned to be a public method in the future
    fn to_json(&self) -> Result<serde_json::Value, impl std::error::Error> {
        let est = self.lossless.est()?;
        let json = serde_json::to_value(est)?;
        Ok::<_, PolicyToJsonError>(json)
    }

    /// Create a `Template` from its AST representation only. The EST will
    /// reflect the AST structure. When possible, don't use this method and
    /// create the EST from the policy text or CST instead, as the conversion
    /// to AST is lossy. ESTs generated by this method will reflect the AST and
    /// not the original policy syntax.
    fn from_ast(ast: ast::Template) -> Self {
        let text = ast.to_string(); // assume that pretty-printing is faster than `est::Policy::from(ast.clone())`; is that true?
        Self {
            ast,
            lossless: LosslessPolicy::policy_or_template_text(text),
        }
    }
}

impl FromStr for Template {
    type Err = ParseErrors;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        Self::parse(None, src)
    }
}

/// Head constraint on policy principals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalConstraint {
    /// Un-constrained
    Any,
    /// Must be In the given EntityUid
    In(EntityUid),
    /// Must be equal to the given EntityUid
    Eq(EntityUid),
}

/// Head constraint on policy principals for templates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplatePrincipalConstraint {
    /// Un-constrained
    Any,
    /// Must be In the given EntityUid.
    /// If [`None`], then it is a template slot.
    In(Option<EntityUid>),
    /// Must be equal to the given EntityUid
    /// If [`None`], then it is a template slot.
    Eq(Option<EntityUid>),
}

impl TemplatePrincipalConstraint {
    /// Does this constraint contain a slot?
    pub fn has_slot(&self) -> bool {
        match self {
            Self::Any => false,
            Self::In(o) | Self::Eq(o) => o.is_none(),
        }
    }
}

/// Head constraint on policy actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionConstraint {
    /// Un-constrained
    Any,
    /// Must be In the given EntityUid
    In(Vec<EntityUid>),
    /// Must be equal to the given EntityUid
    Eq(EntityUid),
}

/// Head constraint on policy resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceConstraint {
    /// Un-constrained
    Any,
    /// Must be In the given EntityUid
    In(EntityUid),
    /// Must be equal to the given EntityUid
    Eq(EntityUid),
}

/// Head constraint on policy resources for templates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateResourceConstraint {
    /// Un-constrained
    Any,
    /// Must be In the given EntityUid.
    /// If [`None`], then it is a template slot.
    In(Option<EntityUid>),
    /// Must be equal to the given EntityUid
    /// If [`None`], then it is a template slot.
    Eq(Option<EntityUid>),
}

impl TemplateResourceConstraint {
    /// Does this constraint contain a slot?
    pub fn has_slot(&self) -> bool {
        match self {
            Self::Any => false,
            Self::In(o) | Self::Eq(o) => o.is_none(),
        }
    }
}

/// Unique Ids assigned to policies and templates
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize, RefCast)]
pub struct PolicyId(ast::PolicyID);

impl FromStr for PolicyId {
    type Err = ParseErrors;

    /// Create a `PolicyId` from a string. Currently always returns Ok().
    fn from_str(id: &str) -> Result<Self, Self::Err> {
        Ok(Self(ast::PolicyID::from_string(id)))
    }
}

impl std::fmt::Display for PolicyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Structure for a `Policy`. Includes both static policies and template-linked policies.
#[derive(Debug, Clone)]
pub struct Policy {
    /// AST representation of the policy, used for most operations.
    /// In particular, the `ast` contains the authoritative `PolicyId` for the policy.
    ast: ast::Policy,
    /// Some "lossless" representation of the policy, whichever is most
    /// convenient to provide (and can be provided with the least overhead).
    /// This is used just for `to_json()`.
    /// We can't just derive this on-demand from `ast`, because the AST is lossy:
    /// we can't reconstruct an accurate CST/EST/policy-text from the AST, but
    /// we can from the EST (modulo whitespace and a few other things like the
    /// order of annotations).
    lossless: LosslessPolicy,
}

impl PartialEq for Policy {
    fn eq(&self, other: &Self) -> bool {
        // eq is based on just the `ast`
        self.ast.eq(&other.ast)
    }
}
impl Eq for Policy {}

impl Policy {
    /// Get the `PolicyId` of the `Template` this is linked to.
    /// If this is a static policy, this will return `None`.
    pub fn template_id(&self) -> Option<&PolicyId> {
        if self.is_static() {
            None
        } else {
            Some(PolicyId::ref_cast(self.ast.template().id()))
        }
    }

    /// Get the `Effect` (`Permit` or `Forbid`) for this instance
    pub fn effect(&self) -> Effect {
        self.ast.effect()
    }

    /// Get an annotation value of this template-linked or static policy
    pub fn annotation(&self, key: impl AsRef<str>) -> Option<&str> {
        self.ast
            .annotation(&key.as_ref().parse().ok()?)
            .map(smol_str::SmolStr::as_str)
    }

    /// Iterate through annotation data of this template-linked or static policy
    pub fn annotations(&self) -> impl Iterator<Item = (&str, &str)> {
        self.ast
            .annotations()
            .map(|(k, v)| (k.as_ref(), v.as_str()))
    }

    /// Get the `PolicyId` for this template-linked or static policy
    pub fn id(&self) -> &PolicyId {
        PolicyId::ref_cast(self.ast.id())
    }

    /// Clone this `Policy` with a new `PolicyId`
    #[must_use]
    pub fn new_id(&self, id: PolicyId) -> Self {
        Self {
            ast: self.ast.new_id(id.0),
            lossless: self.lossless.clone(), // Lossless representation doesn't include the `PolicyId`
        }
    }

    /// Returns `true` if this is a static policy, `false` otherwise.
    pub fn is_static(&self) -> bool {
        self.ast.is_static()
    }

    /// Get the head constraint on this policy's principal
    pub fn principal_constraint(&self) -> PrincipalConstraint {
        let slot_id = ast::SlotId::principal();
        match self.ast.template().principal_constraint().as_inner() {
            ast::PrincipalOrResourceConstraint::Any => PrincipalConstraint::Any,
            ast::PrincipalOrResourceConstraint::In(eref) => {
                PrincipalConstraint::In(self.convert_entity_reference(eref, slot_id).clone())
            }
            ast::PrincipalOrResourceConstraint::Eq(eref) => {
                PrincipalConstraint::Eq(self.convert_entity_reference(eref, slot_id).clone())
            }
        }
    }

    /// Get the head constraint on this policy's action
    pub fn action_constraint(&self) -> ActionConstraint {
        // Clone the data from Core to be consistant with the other constraints
        match self.ast.template().action_constraint() {
            ast::ActionConstraint::Any => ActionConstraint::Any,
            ast::ActionConstraint::In(ids) => ActionConstraint::In(
                ids.iter()
                    .map(|euid| EntityUid::ref_cast(euid.as_ref()))
                    .cloned()
                    .collect(),
            ),
            ast::ActionConstraint::Eq(id) => ActionConstraint::Eq(EntityUid::ref_cast(id).clone()),
        }
    }

    /// Get the head constraint on this policy's resource
    pub fn resource_constraint(&self) -> ResourceConstraint {
        let slot_id = ast::SlotId::resource();
        match self.ast.template().resource_constraint().as_inner() {
            ast::PrincipalOrResourceConstraint::Any => ResourceConstraint::Any,
            ast::PrincipalOrResourceConstraint::In(eref) => {
                ResourceConstraint::In(self.convert_entity_reference(eref, slot_id).clone())
            }
            ast::PrincipalOrResourceConstraint::Eq(eref) => {
                ResourceConstraint::Eq(self.convert_entity_reference(eref, slot_id).clone())
            }
        }
    }

    fn convert_entity_reference<'a>(
        &'a self,
        r: &'a ast::EntityReference,
        slot: ast::SlotId,
    ) -> &'a EntityUid {
        match r {
            ast::EntityReference::EUID(euid) => EntityUid::ref_cast(euid),
            // This `unwrap` here is safe due the invariant (values total map) on policies.
            ast::EntityReference::Slot => EntityUid::ref_cast(self.ast.env().get(&slot).unwrap()),
        }
    }

    /// Parse a single policy.
    /// If `id` is Some, the policy will be given that Policy Id.
    /// If `id` is None, then "policy0" will be used.
    /// The behavior around None may change in the future.
    pub fn parse(id: Option<String>, policy_src: impl AsRef<str>) -> Result<Self, ParseErrors> {
        let inline_ast = parser::parse_policy(id, policy_src.as_ref()).map_err(ParseErrors)?;
        let (_, ast) = ast::Template::link_static_policy(inline_ast);
        Ok(Self {
            ast,
            lossless: LosslessPolicy::policy_or_template_text(policy_src.as_ref()),
        })
    }

    /// Create a `Policy` from its JSON representation.
    /// If `id` is Some, the policy will be given that Policy Id.
    /// If `id` is None, then "JSON policy" will be used.
    /// The behavior around None may change in the future.
    pub fn from_json(
        id: Option<PolicyId>,
        json: serde_json::Value,
    ) -> Result<Self, cedar_policy_core::est::EstToAstError> {
        let est: est::Policy =
            serde_json::from_value(json).map_err(JsonDeserializationError::Serde)?;
        Ok(Self {
            ast: est.clone().try_into_ast_policy(id.map(|id| id.0))?,
            lossless: LosslessPolicy::Est(est),
        })
    }

    /// Get the JSON representation of this `Policy`.
    pub fn to_json(&self) -> Result<serde_json::Value, impl std::error::Error> {
        let est = self.lossless.est()?;
        let json = serde_json::to_value(est)?;
        Ok::<_, PolicyToJsonError>(json)
    }

    /// Create a `Policy` from its AST representation only. The `LosslessPolicy`
    /// will reflect the AST structure. When possible, don't use this method and
    /// create the `Policy` from the policy text, CST, or EST instead, as the
    /// conversion to AST is lossy. ESTs for policies generated by this method
    /// will reflect the AST and not the original policy syntax.
    fn from_ast(ast: ast::Policy) -> Self {
        let text = ast.to_string(); // assume that pretty-printing is faster than `est::Policy::from(ast.clone())`; is that true?
        Self {
            ast,
            lossless: LosslessPolicy::policy_or_template_text(text),
        }
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.ast.fmt(f)
    }
}

impl FromStr for Policy {
    type Err = ParseErrors;
    /// Create a policy
    ///
    /// Important note: Policies have ids, but this interface does not
    /// allow them to be set. It will use the default "policy0", which
    /// may cause id conflicts if not handled. Use `Policy::parse` to set
    /// the id when parsing, or `Policy::new_id` to clone a policy with
    /// a new id.
    fn from_str(policy: &str) -> Result<Self, Self::Err> {
        Self::parse(None, policy)
    }
}

/// See comments on `Policy` and `Template`.
///
/// This structure can be used for static policies, linked policies, and templates.
#[derive(Debug, Clone)]
enum LosslessPolicy {
    /// EST representation
    Est(est::Policy),
    /// Text representation
    Text {
        /// actual policy text, of the policy or template
        text: String,
        /// For linked policies, map of slot to UID. Only linked policies have
        /// this; static policies and (unlinked) templates have an empty map
        /// here
        slots: HashMap<ast::SlotId, ast::EntityUID>,
    },
}

impl LosslessPolicy {
    /// Create a new `LosslessPolicy` from the text of a policy or template.
    fn policy_or_template_text(text: impl Into<String>) -> Self {
        Self::Text {
            text: text.into(),
            slots: HashMap::new(),
        }
    }

    /// Get the EST representation of this static policy, linked policy, or template
    fn est(&self) -> Result<est::Policy, PolicyToJsonError> {
        match self {
            Self::Est(est) => Ok(est.clone()),
            Self::Text { text, slots } => {
                let est = parser::parse_policy_or_template_to_est(text)?;
                if slots.is_empty() {
                    Ok(est)
                } else {
                    let unwrapped_vals = slots.iter().map(|(k, v)| (*k, v.into())).collect();
                    Ok(est.link(&unwrapped_vals)?)
                }
            }
        }
    }

    fn link<'a>(
        self,
        vals: impl IntoIterator<Item = (ast::SlotId, &'a ast::EntityUID)>,
    ) -> Result<Self, est::InstantiationError> {
        match self {
            Self::Est(est) => {
                let unwrapped_est_vals: HashMap<ast::SlotId, entities::EntityUidJSON> =
                    vals.into_iter().map(|(k, v)| (k, v.into())).collect();
                Ok(Self::Est(est.link(&unwrapped_est_vals)?))
            }
            Self::Text { text, slots } => {
                debug_assert!(
                    slots.is_empty(),
                    "shouldn't call link() on an already-linked policy"
                );
                let slots = vals.into_iter().map(|(k, v)| (k, v.clone())).collect();
                Ok(Self::Text { text, slots })
            }
        }
    }
}

/// Errors that can happen when getting the JSON representation of a policy
#[derive(Debug, Error)]
pub enum PolicyToJsonError {
    /// Parse error in the policy text
    #[error(transparent)]
    Parse(#[from] ParseErrors),
    /// For linked policies, error linking the JSON representation
    #[error(transparent)]
    Link(#[from] est::InstantiationError),
    /// Error in the JSON serialization
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}

/// Expressions to be evaluated
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct Expression(ast::Expr);

impl Expression {
    /// Create an expression representing a literal string.
    pub fn new_string(value: String) -> Self {
        Self(ast::Expr::val(value))
    }

    /// Create an expression representing a literal bool.
    pub fn new_bool(value: bool) -> Self {
        Self(ast::Expr::val(value))
    }

    /// Create an expression representing a literal long.
    pub fn new_long(value: i64) -> Self {
        Self(ast::Expr::val(value))
    }

    /// Create an expression representing a record.
    pub fn new_record(fields: impl IntoIterator<Item = (String, Self)>) -> Self {
        Self(ast::Expr::record(
            fields.into_iter().map(|(k, v)| (SmolStr::from(k), v.0)),
        ))
    }

    /// Create an expression representing a Set.
    pub fn new_set(values: impl IntoIterator<Item = Self>) -> Self {
        Self(ast::Expr::set(values.into_iter().map(|v| v.0)))
    }
}

impl FromStr for Expression {
    type Err = ParseErrors;

    /// create an Expression using Cedar syntax
    fn from_str(expression: &str) -> Result<Self, Self::Err> {
        ast::Expr::from_str(expression)
            .map_err(ParseErrors)
            .map(Expression)
    }
}

/// "Restricted" expressions are used for attribute values and `context`.
///
/// Restricted expressions can contain only the following:
///   - bool, int, and string literals
///   - literal `EntityUid`s such as `User::"alice"`
///   - extension function calls, where the arguments must be other things
///       on this list
///   - set and record literals, where the values must be other things on
///       this list
///
/// That means the following are not allowed in restricted expressions:
///   - `principal`, `action`, `resource`, `context`
///   - builtin operators and functions, including `.`, `in`, `has`, `like`,
///       `.contains()`
///   - if-then-else expressions
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct RestrictedExpression(ast::RestrictedExpr);

impl RestrictedExpression {
    /// Create an expression representing a literal string.
    pub fn new_string(value: String) -> Self {
        Self(ast::RestrictedExpr::val(value))
    }

    /// Create an expression representing a literal bool.
    pub fn new_bool(value: bool) -> Self {
        Self(ast::RestrictedExpr::val(value))
    }

    /// Create an expression representing a literal long.
    pub fn new_long(value: i64) -> Self {
        Self(ast::RestrictedExpr::val(value))
    }

    /// Create an expression representing a record.
    pub fn new_record(fields: impl IntoIterator<Item = (String, Self)>) -> Self {
        Self(ast::RestrictedExpr::record(
            fields.into_iter().map(|(k, v)| (SmolStr::from(k), v.0)),
        ))
    }

    /// Create an expression representing a Set.
    pub fn new_set(values: impl IntoIterator<Item = Self>) -> Self {
        Self(ast::RestrictedExpr::set(values.into_iter().map(|v| v.0)))
    }
}

impl FromStr for RestrictedExpression {
    type Err = ParseErrors;

    /// create a `RestrictedExpression` using Cedar syntax
    fn from_str(expression: &str) -> Result<Self, Self::Err> {
        ast::RestrictedExpr::from_str(expression)
            .map_err(ParseErrors)
            .map(RestrictedExpression)
    }
}

/// Represents the request tuple <P, A, R, C> (see the Cedar design doc).
#[repr(transparent)]
#[derive(Debug, RefCast)]
pub struct Request(pub(crate) ast::Request);

impl Request {
    /// Create a Request.
    ///
    /// Note that you can create the `EntityUid`s using `.parse()` on any
    /// string (via the `FromStr` implementation for `EntityUid`).
    /// The principal, action, and resource fields are optional to support
    /// the case where these fields do not contribute to authorization
    /// decisions (e.g., because they are not used in your policies).
    /// If any of the fields are `None`, we will automatically generate
    /// a unique entity UID that is not equal to any UID in the store.
    pub fn new(
        principal: Option<EntityUid>,
        action: Option<EntityUid>,
        resource: Option<EntityUid>,
        context: Context,
    ) -> Self {
        let p = match principal {
            Some(p) => p.0,
            None => ast::EntityUID::unspecified_from_eid(ast::Eid::new("principal")),
        };
        let a = match action {
            Some(a) => a.0,
            None => ast::EntityUID::unspecified_from_eid(ast::Eid::new("action")),
        };
        let r = match resource {
            Some(r) => r.0,
            None => ast::EntityUID::unspecified_from_eid(ast::Eid::new("resource")),
        };
        Self(ast::Request::new(p, a, r, context.0))
    }

    ///Get the principal component of the request
    pub fn principal(&self) -> Option<&EntityUid> {
        match self.0.principal() {
            ast::EntityUIDEntry::Concrete(euid) => Some(EntityUid::ref_cast(euid.as_ref())),
            ast::EntityUIDEntry::Unknown => None,
        }
    }

    ///Get the action component of the request
    pub fn action(&self) -> Option<&EntityUid> {
        match self.0.action() {
            ast::EntityUIDEntry::Concrete(euid) => Some(EntityUid::ref_cast(euid.as_ref())),
            ast::EntityUIDEntry::Unknown => None,
        }
    }

    ///Get the resource component of the request
    pub fn resource(&self) -> Option<&EntityUid> {
        match self.0.resource() {
            ast::EntityUIDEntry::Concrete(euid) => Some(EntityUid::ref_cast(euid.as_ref())),
            ast::EntityUIDEntry::Unknown => None,
        }
    }
}

/// the Context object for an authorization request
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct Context(ast::Context);

impl Context {
    /// Create an empty `Context`
    pub fn empty() -> Self {
        Self(ast::Context::empty())
    }

    /// Create a `Context` from a map of key to "restricted expression",
    /// or a Vec of `(key, restricted expression)` pairs, or any other iterator
    /// of `(key, restricted expression)` pairs.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, RestrictedExpression)>) -> Self {
        Self(ast::Context::from_pairs(
            pairs.into_iter().map(|(k, v)| (SmolStr::from(k), v.0)),
        ))
    }

    /// Create a `Context` from a string containing JSON (which must be a JSON
    /// object, not any other JSON type, or you will get an error here).
    /// JSON here must use the `__entity` and `__extn` escapes for entity
    /// references, extension values, etc.
    ///
    /// If a `schema` is provided, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit, and it will error
    /// if attributes have the wrong types (e.g., string instead of integer).
    /// Since different Actions have different schemas for `Context`, you also
    /// must specify the `Action` for schema-based parsing.
    pub fn from_json_str(
        json: &str,
        schema: Option<(&Schema, &EntityUid)>,
    ) -> Result<Self, ContextJsonError> {
        let schema = schema
            .map(|(s, uid)| Self::get_context_schema(s, uid))
            .transpose()?;
        let context =
            entities::ContextJsonParser::new(schema.as_ref(), Extensions::all_available())
                .from_json_str(json)?;
        Ok(Self(context))
    }

    /// Create a `Context` from a `serde_json::Value` (which must be a JSON object,
    /// not any other JSON type, or you will get an error here).
    /// JSON here must use the `__entity` and `__extn` escapes for entity
    /// references, extension values, etc.
    ///
    /// If a `schema` is provided, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit, and it will error
    /// if attributes have the wrong types (e.g., string instead of integer).
    /// Since different Actions have different schemas for `Context`, you also
    /// must specify the `Action` for schema-based parsing.
    pub fn from_json_value(
        json: serde_json::Value,
        schema: Option<(&Schema, &EntityUid)>,
    ) -> Result<Self, ContextJsonError> {
        let schema = schema
            .map(|(s, uid)| Self::get_context_schema(s, uid))
            .transpose()?;
        let context =
            entities::ContextJsonParser::new(schema.as_ref(), Extensions::all_available())
                .from_json_value(json)?;
        Ok(Self(context))
    }

    /// Create a `Context` from a JSON file.  The JSON file must contain a JSON
    /// object, not any other JSON type, or you will get an error here.
    /// JSON here must use the `__entity` and `__extn` escapes for entity
    /// references, extension values, etc.
    ///
    /// If a `schema` is provided, this will inform the parsing: for instance, it
    /// will allow `__entity` and `__extn` escapes to be implicit, and it will error
    /// if attributes have the wrong types (e.g., string instead of integer).
    /// Since different Actions have different schemas for `Context`, you also
    /// must specify the `Action` for schema-based parsing.
    pub fn from_json_file(
        json: impl std::io::Read,
        schema: Option<(&Schema, &EntityUid)>,
    ) -> Result<Self, ContextJsonError> {
        let schema = schema
            .map(|(s, uid)| Self::get_context_schema(s, uid))
            .transpose()?;
        let context =
            entities::ContextJsonParser::new(schema.as_ref(), Extensions::all_available())
                .from_json_file(json)?;
        Ok(Self(context))
    }

    /// Internal helper function to convert `(&Schema, &EntityUid)` to `impl ContextSchema`
    fn get_context_schema(
        schema: &Schema,
        action: &EntityUid,
    ) -> Result<impl ContextSchema, ContextJsonError> {
        schema
            .0
            .get_context_schema(&action.0)
            .ok_or_else(|| ContextJsonError::ActionDoesNotExist {
                action: action.clone(),
            })
    }
}

/// Error type for parsing `Context` from JSON
#[derive(Debug, Error)]
pub enum ContextJsonError {
    /// Error deserializing the JSON into a Context
    #[error(transparent)]
    JsonDeserializationError(#[from] JsonDeserializationError),
    /// The supplied action doesn't exist in the supplied schema
    #[error("Action {action} doesn't exist in the supplied schema")]
    ActionDoesNotExist {
        /// UID of the action which doesn't exist
        action: EntityUid,
    },
}

impl std::fmt::Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Result of Evaluation
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvalResult {
    /// Boolean value
    Bool(bool),
    /// Signed integer value
    Long(i64),
    /// String value
    String(String),
    /// Entity Uid
    EntityUid(EntityUid),
    /// A first-class set
    Set(Set),
    /// A first-class anonymous record
    Record(Record),
    /// An extension value, currently limited to String results
    ExtensionValue(String),
    // ExtensionValue(std::sync::Arc<dyn InternalExtensionValue>),
}

/// Sets of Cedar values
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Set(BTreeSet<EvalResult>);

impl Set {
    /// Iterate over the members of the set
    pub fn iter(&self) -> impl Iterator<Item = &EvalResult> {
        self.0.iter()
    }

    /// Is a given element in the set
    pub fn contains(&self, elem: &EvalResult) -> bool {
        self.0.contains(elem)
    }

    /// Get the number of members of the set
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Test if the set is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A record of Cedar values
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Record(BTreeMap<String, EvalResult>);

impl Record {
    /// Iterate over the attribute/value pairs in the record
    pub fn iter(&self) -> impl Iterator<Item = (&String, &EvalResult)> {
        self.0.iter()
    }

    /// Check if a given attribute is in the record
    pub fn contains_attribute(&self, key: impl AsRef<str>) -> bool {
        self.0.contains_key(key.as_ref())
    }

    /// Get a given attribute from the record
    pub fn get(&self, key: impl AsRef<str>) -> Option<&EvalResult> {
        self.0.get(key.as_ref())
    }

    /// Get the number of attributes in the record
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Test if the record is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[doc(hidden)]
impl From<ast::Value> for EvalResult {
    fn from(v: ast::Value) -> Self {
        match v {
            ast::Value::Lit(ast::Literal::Bool(b)) => Self::Bool(b),
            ast::Value::Lit(ast::Literal::Long(i)) => Self::Long(i),
            ast::Value::Lit(ast::Literal::String(s)) => Self::String(s.to_string()),
            ast::Value::Lit(ast::Literal::EntityUID(e)) => {
                Self::EntityUid(EntityUid(ast::EntityUID::clone(&e)))
            }
            ast::Value::Set(s) => Self::Set(Set(s
                .authoritative
                .iter()
                .map(|v| v.clone().into())
                .collect())),
            ast::Value::Record(r) => Self::Record(Record(
                r.iter()
                    .map(|(k, v)| (k.to_string(), v.clone().into()))
                    .collect(),
            )),
            ast::Value::ExtensionValue(v) => Self::ExtensionValue(v.to_string()),
        }
    }
}
impl std::fmt::Display for EvalResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool(b) => write!(f, "{b}"),
            Self::Long(l) => write!(f, "{l}"),
            Self::String(s) => write!(f, "\"{}\"", s.escape_debug()),
            Self::EntityUid(uid) => write!(f, "{uid}"),
            Self::Set(s) => {
                write!(f, "[")?;
                for (i, ev) in s.iter().enumerate() {
                    write!(f, "{ev}")?;
                    if (i + 1) < s.len() {
                        write!(f, ", ")?;
                    }
                }
                write!(f, "]")?;
                Ok(())
            }
            Self::Record(r) => {
                write!(f, "{{")?;
                for (i, (k, v)) in r.iter().enumerate() {
                    write!(f, "\"{}\": {v}", k.escape_debug())?;
                    if (i + 1) < r.len() {
                        write!(f, ", ")?;
                    }
                }
                write!(f, "}}")?;
                Ok(())
            }
            Self::ExtensionValue(s) => write!(f, "{s}"),
        }
    }
}

/// Evaluate
/// If evaluation results in an error (e.g., attempting to access a non-existent Entity or Record,
/// passing the wrong number of arguments to a function etc.), that error is returned as a String
pub fn eval_expression(
    request: &Request,
    entities: &Entities,
    expr: &Expression,
) -> Result<EvalResult, EvaluationError> {
    let all_ext = Extensions::all_available();
    let eval = Evaluator::new(&request.0, &entities.0, &all_ext)
        .map_err(|e| EvaluationError::StringMessage(e.to_string()))?;
    Ok(EvalResult::from(
        // Evaluate under the empty slot map, as an expression should not have slots
        eval.interpret(&expr.0, &ast::SlotEnv::new())
            .map_err(|e| EvaluationError::StringMessage(e.to_string()))?,
    ))
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use crate::{PolicyId, PolicySet, ResidualResponse};

    #[test]
    fn test_pe_response_constructor() {
        let p: PolicySet = "permit(principal, action, resource);".parse().unwrap();
        let reason: HashSet<PolicyId> = std::iter::once("id1".parse().unwrap()).collect();
        let errors: HashSet<String> = std::iter::once("error".to_string()).collect();
        let a = ResidualResponse::new(p.clone(), reason.clone(), errors.clone());
        assert_eq!(a.diagnostics().errors, errors);
        assert_eq!(a.diagnostics().reason, reason);
        assert_eq!(a.residuals(), &p);
    }
}

#[cfg(test)]
mod entity_uid_tests {
    use super::*;

    /// building an `EntityUid` from components
    #[test]
    fn entity_uid_from_parts() {
        let entity_id = EntityId::from_str("bobby").expect("failed at constructing EntityId");
        let entity_type_name = EntityTypeName::from_str("Chess::Master")
            .expect("failed at constructing EntityTypeName");
        let euid = EntityUid::from_type_name_and_id(entity_type_name, entity_id);
        assert_eq!(euid.id().as_ref(), "bobby");
        assert_eq!(euid.type_name().to_string(), "Chess::Master");
        assert_eq!(euid.type_name().basename(), "Master");
        assert_eq!(euid.type_name().namespace(), "Chess");
        assert_eq!(euid.type_name().namespace_components().count(), 1);
    }

    /// building an `EntityUid` from components, with no namespace
    #[test]
    fn entity_uid_no_namespace() {
        let entity_id = EntityId::from_str("bobby").expect("failed at constructing EntityId");
        let entity_type_name =
            EntityTypeName::from_str("User").expect("failed at constructing EntityTypeName");
        let euid = EntityUid::from_type_name_and_id(entity_type_name, entity_id);
        assert_eq!(euid.id().as_ref(), "bobby");
        assert_eq!(euid.type_name().to_string(), "User");
        assert_eq!(euid.type_name().basename(), "User");
        assert_eq!(euid.type_name().namespace(), String::new());
        assert_eq!(euid.type_name().namespace_components().count(), 0);
    }

    /// building an `EntityUid` from components, with many nested namespaces
    #[test]
    fn entity_uid_nested_namespaces() {
        let entity_id = EntityId::from_str("bobby").expect("failed at constructing EntityId");
        let entity_type_name = EntityTypeName::from_str("A::B::C::D::Z")
            .expect("failed at constructing EntityTypeName");
        let euid = EntityUid::from_type_name_and_id(entity_type_name, entity_id);
        assert_eq!(euid.id().as_ref(), "bobby");
        assert_eq!(euid.type_name().to_string(), "A::B::C::D::Z");
        assert_eq!(euid.type_name().basename(), "Z");
        assert_eq!(euid.type_name().namespace(), "A::B::C::D");
        assert_eq!(euid.type_name().namespace_components().count(), 4);
    }

    /// building an `EntityUid` from components, including escapes
    #[test]
    fn entity_uid_with_escape() {
        // EntityId contains some things that look like escapes
        let entity_id = EntityId::from_str(r#"bobby\'s sister:\nVeronica"#)
            .expect("failed at constructing EntityId");
        let entity_type_name = EntityTypeName::from_str("Hockey::Master")
            .expect("failed at constructing EntityTypeName");
        let euid = EntityUid::from_type_name_and_id(entity_type_name, entity_id);
        // these are passed through (no escape interpretation):
        //   the EntityId has the literal backslash characters in it
        assert_eq!(euid.id().as_ref(), r#"bobby\'s sister:\nVeronica"#);
        assert_eq!(euid.type_name().to_string(), "Hockey::Master");
        assert_eq!(euid.type_name().basename(), "Master");
        assert_eq!(euid.type_name().namespace(), "Hockey");
        assert_eq!(euid.type_name().namespace_components().count(), 1);
    }

    /// building an `EntityUid` from components, including backslashes
    #[test]
    fn entity_uid_with_backslashes() {
        // backslashes preceding a variety of characters
        let entity_id =
            EntityId::from_str(r#"\ \a \b \' \" \\"#).expect("failed at constructing EntityId");
        let entity_type_name =
            EntityTypeName::from_str("Test::User").expect("failed at constructing EntityTypeName");
        let euid = EntityUid::from_type_name_and_id(entity_type_name, entity_id);
        // the backslashes appear the same way in the EntityId
        assert_eq!(euid.id().as_ref(), r#"\ \a \b \' \" \\"#);
        assert_eq!(euid.type_name().to_string(), "Test::User");
    }

    /// building an `EntityUid` from components, including single and double quotes (and backslashes)
    #[test]
    fn entity_uid_with_quotes() {
        let euid: EntityUid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Test::User").unwrap(),
            EntityId::from_str(r#"b'ob"by\'s sis\"ter"#).unwrap(),
        );
        // EntityId is passed through (no escape interpretation):
        //   the EntityId has all the same literal characters in it
        assert_eq!(euid.id().as_ref(), r#"b'ob"by\'s sis\"ter"#);
        assert_eq!(euid.type_name().to_string(), r#"Test::User"#);
    }

    /// building an `EntityUid` from components, including whitespace in various places
    #[test]
    fn entity_uid_with_whitespace() {
        EntityTypeName::from_str("A ::   B::C").expect_err("should fail due to RFC 9");
        EntityTypeName::from_str(" A :: B\n::C \n  ::D\n").expect_err("should fail due to RFC 9");

        // but embedded whitespace should be OK when parsing an actual policy
        let policy = Policy::from_str(
            r#"permit(principal == A ::   B::C :: " hi there are spaces ", action, resource);"#,
        )
        .expect("should succeed, see RFC 9");
        let euid = match policy.principal_constraint() {
            PrincipalConstraint::Eq(euid) => euid,
            _ => panic!("expected Eq constraint"),
        };
        assert_eq!(euid.id().as_ref(), " hi there are spaces ");
        assert_eq!(euid.type_name().to_string(), "A::B::C"); // expect to have been normalized
        assert_eq!(euid.type_name().basename(), "C");
        assert_eq!(euid.type_name().namespace(), "A::B");
        assert_eq!(euid.type_name().namespace_components().count(), 2);

        let policy = Policy::from_str(
            r#"
permit(principal ==  A :: B
    ::C
    :: D
    ::  " hi there are
    spaces and
    newlines ", action, resource);"#,
        )
        .expect("should succeed, see RFC 9");
        let euid = match policy.principal_constraint() {
            PrincipalConstraint::Eq(euid) => euid,
            _ => panic!("expected Eq constraint"),
        };
        assert_eq!(
            euid.id().as_ref(),
            " hi there are\n    spaces and\n    newlines "
        );
        assert_eq!(euid.type_name().to_string(), "A::B::C::D"); // expect to have been normalized
        assert_eq!(euid.type_name().basename(), "D");
        assert_eq!(euid.type_name().namespace(), "A::B::C");
        assert_eq!(euid.type_name().namespace_components().count(), 3);
    }

    #[test]
    fn malformed_entity_type_name_should_fail() {
        let result = EntityTypeName::from_str("I'm an invalid name");

        assert!(matches!(result, Err(ParseErrors(_))));
        let error = result.err().unwrap();
        assert!(error.to_string().contains("invalid token"));
    }

    /// parsing an `EntityUid` from string
    #[test]
    fn parse_euid() {
        let parsed_eid: EntityUid = r#"Test::User::"bobby""#.parse().expect("Failed to parse");
        assert_eq!(parsed_eid.id().as_ref(), r#"bobby"#);
        assert_eq!(parsed_eid.type_name().to_string(), r#"Test::User"#);
    }

    /// parsing an `EntityUid` from string, including escapes
    #[test]
    fn parse_euid_with_escape() {
        // the EntityUid string has an escaped single-quote and escaped double-quote
        let parsed_eid: EntityUid = r#"Test::User::"b\'ob\"by""#.parse().expect("Failed to parse");
        // the escapes were interpreted:
        //   the EntityId has single-quote and double-quote characters (but no backslash characters)
        assert_eq!(parsed_eid.id().as_ref(), r#"b'ob"by"#);
        assert_eq!(parsed_eid.type_name().to_string(), r#"Test::User"#);
    }

    /// parsing an `EntityUid` from string, including both escaped and unescaped single-quotes
    #[test]
    fn parse_euid_single_quotes() {
        // the EntityUid string has an unescaped and escaped single-quote
        let euid_str = r#"Test::User::"b'obby\'s sister""#;
        EntityUid::from_str(euid_str).expect_err("Should fail, not normalized -- see RFC 9");
        // but this should be accepted in an actual policy
        let policy_str = "permit(principal == ".to_string() + euid_str + ", action, resource);";
        let policy = Policy::from_str(&policy_str).expect("Should parse; see RFC 9");
        let parsed_euid = match policy.principal_constraint() {
            PrincipalConstraint::Eq(euid) => euid,
            _ => panic!("Expected an Eq constraint"),
        };
        // the escape was interpreted:
        //   the EntityId has both single-quote characters (but no backslash characters)
        assert_eq!(parsed_euid.id().as_ref(), r#"b'obby's sister"#);
        assert_eq!(parsed_euid.type_name().to_string(), r#"Test::User"#);
    }

    /// parsing an `EntityUid` from string, including whitespace
    #[test]
    fn parse_euid_whitespace() {
        let euid_str = " A ::B :: C:: D \n :: \n E\n :: \"hi\"";
        EntityUid::from_str(euid_str).expect_err("Should fail, not normalized -- see RFC 9");
        // but this should be accepted in an actual policy
        let policy_str = "permit(principal == ".to_string() + euid_str + ", action, resource);";
        let policy = Policy::from_str(&policy_str).expect("Should parse; see RFC 9");
        let parsed_euid = match policy.principal_constraint() {
            PrincipalConstraint::Eq(euid) => euid,
            _ => panic!("Expected an Eq constraint"),
        };
        assert_eq!(parsed_euid.id().as_ref(), "hi");
        assert_eq!(parsed_euid.type_name().to_string(), "A::B::C::D::E"); // expect to have been normalized
        assert_eq!(parsed_euid.type_name().basename(), "E");
        assert_eq!(parsed_euid.type_name().namespace(), "A::B::C::D");
        assert_eq!(parsed_euid.type_name().namespace_components().count(), 4);
    }

    /// test that we can parse the `Display` output of `EntityUid`
    #[test]
    fn euid_roundtrip() {
        let parsed_euid: EntityUid = r#"Test::User::"b\'ob""#.parse().expect("Failed to parse");
        assert_eq!(parsed_euid.id().as_ref(), r#"b'ob"#);
        let reparsed: EntityUid = format!("{parsed_euid}")
            .parse()
            .expect("failed to roundtrip");
        assert_eq!(reparsed.id().as_ref(), r#"b'ob"#);
    }
}

#[cfg(test)]
mod head_constraints_tests {
    use super::*;

    #[test]
    fn principal_constraint_inline() {
        let p = Policy::from_str("permit(principal,action,resource);").unwrap();
        assert_eq!(p.principal_constraint(), PrincipalConstraint::Any);
        let euid = EntityUid::from_strs("T", "a");
        assert_eq!(euid.id().as_ref(), "a");
        assert_eq!(
            euid.type_name(),
            &EntityTypeName::from_str("T").expect("Failed to parse EntityTypeName")
        );
        let p =
            Policy::from_str("permit(principal == T::\"a\",action,resource == T::\"b\");").unwrap();
        assert_eq!(
            p.principal_constraint(),
            PrincipalConstraint::Eq(euid.clone())
        );
        let p = Policy::from_str("permit(principal in T::\"a\",action,resource);").unwrap();
        assert_eq!(p.principal_constraint(), PrincipalConstraint::In(euid));
    }

    #[test]
    fn action_constraint_inline() {
        let p = Policy::from_str("permit(principal,action,resource);").unwrap();
        assert_eq!(p.action_constraint(), ActionConstraint::Any);
        let euid = EntityUid::from_strs("NN::N::Action", "a");
        assert_eq!(
            euid.type_name(),
            &EntityTypeName::from_str("NN::N::Action").expect("Failed to parse EntityTypeName")
        );
        let p = Policy::from_str(
            "permit(principal == T::\"b\",action == NN::N::Action::\"a\",resource == T::\"c\");",
        )
        .unwrap();
        assert_eq!(p.action_constraint(), ActionConstraint::Eq(euid.clone()));
        let p = Policy::from_str("permit(principal,action in [NN::N::Action::\"a\"],resource);")
            .unwrap();
        assert_eq!(p.action_constraint(), ActionConstraint::In(vec![euid]));
    }

    #[test]
    fn resource_constraint_inline() {
        let p = Policy::from_str("permit(principal,action,resource);").unwrap();
        assert_eq!(p.resource_constraint(), ResourceConstraint::Any);
        let euid = EntityUid::from_strs("NN::N::T", "a");
        assert_eq!(
            euid.type_name(),
            &EntityTypeName::from_str("NN::N::T").expect("Failed to parse EntityTypeName")
        );
        let p =
            Policy::from_str("permit(principal == T::\"b\",action,resource == NN::N::T::\"a\");")
                .unwrap();
        assert_eq!(
            p.resource_constraint(),
            ResourceConstraint::Eq(euid.clone())
        );
        let p = Policy::from_str("permit(principal,action,resource in NN::N::T::\"a\");").unwrap();
        assert_eq!(p.resource_constraint(), ResourceConstraint::In(euid));
    }

    #[test]
    fn principal_constraint_link() {
        let p = link("permit(principal,action,resource);", HashMap::new());
        assert_eq!(p.principal_constraint(), PrincipalConstraint::Any);
        let euid = EntityUid::from_strs("T", "a");
        let p = link(
            "permit(principal == T::\"a\",action,resource);",
            HashMap::new(),
        );
        assert_eq!(
            p.principal_constraint(),
            PrincipalConstraint::Eq(euid.clone())
        );
        let p = link(
            "permit(principal in T::\"a\",action,resource);",
            HashMap::new(),
        );
        assert_eq!(
            p.principal_constraint(),
            PrincipalConstraint::In(euid.clone())
        );
        let map: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), euid.clone())).collect();
        let p = link(
            "permit(principal in ?principal,action,resource);",
            map.clone(),
        );
        assert_eq!(
            p.principal_constraint(),
            PrincipalConstraint::In(euid.clone())
        );
        let p = link("permit(principal == ?principal,action,resource);", map);
        assert_eq!(p.principal_constraint(), PrincipalConstraint::Eq(euid));
    }

    #[test]
    fn action_constraint_link() {
        let p = link("permit(principal,action,resource);", HashMap::new());
        assert_eq!(p.action_constraint(), ActionConstraint::Any);
        let euid = EntityUid::from_strs("Action", "a");
        let p = link(
            "permit(principal,action == Action::\"a\",resource);",
            HashMap::new(),
        );
        assert_eq!(p.action_constraint(), ActionConstraint::Eq(euid.clone()));
        let p = link(
            "permit(principal,action in [Action::\"a\",Action::\"b\"],resource);",
            HashMap::new(),
        );
        assert_eq!(
            p.action_constraint(),
            ActionConstraint::In(vec![euid, EntityUid::from_strs("Action", "b"),])
        );
    }

    #[test]
    fn resource_constraint_link() {
        let p = link("permit(principal,action,resource);", HashMap::new());
        assert_eq!(p.resource_constraint(), ResourceConstraint::Any);
        let euid = EntityUid::from_strs("T", "a");
        let p = link(
            "permit(principal,action,resource == T::\"a\");",
            HashMap::new(),
        );
        assert_eq!(
            p.resource_constraint(),
            ResourceConstraint::Eq(euid.clone())
        );
        let p = link(
            "permit(principal,action,resource in T::\"a\");",
            HashMap::new(),
        );
        assert_eq!(
            p.resource_constraint(),
            ResourceConstraint::In(euid.clone())
        );
        let map: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::resource(), euid.clone())).collect();
        let p = link(
            "permit(principal,action,resource in ?resource);",
            map.clone(),
        );
        assert_eq!(
            p.resource_constraint(),
            ResourceConstraint::In(euid.clone())
        );
        let p = link("permit(principal,action,resource == ?resource);", map);
        assert_eq!(p.resource_constraint(), ResourceConstraint::Eq(euid));
    }

    fn link(src: &str, values: HashMap<SlotId, EntityUid>) -> Policy {
        let mut pset = PolicySet::new();
        let template = Template::parse(Some("Id".to_string()), src).unwrap();

        pset.add_template(template).unwrap();

        let link_id = PolicyId::from_str("link").unwrap();
        pset.link(PolicyId::from_str("Id").unwrap(), link_id.clone(), values)
            .unwrap();
        pset.policy(&link_id).unwrap().clone()
    }
}

/// Tests in this module are adapted from Core's `policy_set.rs` tests
#[cfg(test)]
mod policy_set_tests {
    use super::*;
    use ast::LinkingError;

    #[test]
    fn link_conflicts() {
        let mut pset = PolicySet::new();
        let p1 = Policy::parse(Some("id".into()), "permit(principal,action,resource);")
            .expect("Failed to parse");
        pset.add(p1).expect("Failed to add");
        let template = Template::parse(
            Some("t".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Failed to parse");
        pset.add_template(template).expect("Add failed");

        let env: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect();

        let r = pset.link(
            PolicyId::from_str("t").unwrap(),
            PolicyId::from_str("id").unwrap(),
            env,
        );

        match r {
            Ok(_) => panic!("Should have failed due to conflict"),
            Err(PolicySetError::LinkingError(LinkingError::PolicyIdConflict)) => (),
            Err(e) => panic!("Incorrect error: {e}"),
        };
    }

    #[test]
    fn policyset_add() {
        let mut pset = PolicySet::new();
        let static_policy = Policy::parse(Some("id".into()), "permit(principal,action,resource);")
            .expect("Failed to parse");
        pset.add(static_policy).expect("Failed to add");

        let template = Template::parse(
            Some("t".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Failed to parse");
        pset.add_template(template).expect("Failed to add");

        let env1: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test1"))).collect();
        pset.link(
            PolicyId::from_str("t").unwrap(),
            PolicyId::from_str("link").unwrap(),
            env1,
        )
        .expect("Failed to link");

        let env2: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test2"))).collect();

        let err = pset
            .link(
                PolicyId::from_str("t").unwrap(),
                PolicyId::from_str("link").unwrap(),
                env2.clone(),
            )
            .expect_err("Should have failed due to conflict with existing link id");
        match err {
            PolicySetError::LinkingError(_) => (),
            e => panic!("Wrong error: {e}"),
        }

        pset.link(
            PolicyId::from_str("t").unwrap(),
            PolicyId::from_str("link2").unwrap(),
            env2,
        )
        .expect("Failed to link");

        let template2 = Template::parse(
            Some("t".into()),
            "forbid(principal, action, resource == ?resource);",
        )
        .expect("Failed to parse");
        pset.add_template(template2)
            .expect_err("should have failed due to conflict on template id");
        let template2 = Template::parse(
            Some("t2".into()),
            "forbid(principal, action, resource == ?resource);",
        )
        .expect("Failed to parse");
        pset.add_template(template2)
            .expect("Failed to add template");
        let env3: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::resource(), EntityUid::from_strs("Test", "test3"))).collect();

        pset.link(
            PolicyId::from_str("t").unwrap(),
            PolicyId::from_str("unique3").unwrap(),
            env3.clone(),
        )
        .expect_err("should have failed due to conflict on template id");

        pset.link(
            PolicyId::from_str("t2").unwrap(),
            PolicyId::from_str("unique3").unwrap(),
            env3,
        )
        .expect("should succeed with unique ids");
    }

    #[test]
    fn pset_requests() {
        let template = Template::parse(
            Some("template".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        let static_policy = Policy::parse(
            Some("static".into()),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        let mut pset = PolicySet::new();
        pset.add_template(template).unwrap();
        pset.add(static_policy).unwrap();
        pset.link(
            PolicyId::from_str("template").unwrap(),
            PolicyId::from_str("linked").unwrap(),
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect(),
        )
        .expect("Link failure");

        assert_eq!(pset.templates().count(), 1);
        assert_eq!(pset.policies().count(), 2);
        assert_eq!(pset.policies().filter(|p| p.is_static()).count(), 1);

        assert_eq!(
            pset.template(&"template".parse().unwrap())
                .expect("lookup failed")
                .id(),
            &"template".parse().unwrap()
        );
        assert_eq!(
            pset.policy(&"static".parse().unwrap())
                .expect("lookup failed")
                .id(),
            &"static".parse().unwrap()
        );
        assert_eq!(
            pset.policy(&"linked".parse().unwrap())
                .expect("lookup failed")
                .id(),
            &"linked".parse().unwrap()
        );
    }
}

#[cfg(test)]
mod schema_tests {
    use super::*;
    use cool_asserts::assert_matches;
    use serde_json::json;

    /// A minimal test that a valid Schema parses
    #[test]
    fn valid_schema() {
        Schema::from_json_value(json!(
        { "": {
            "entityTypes": {
                "Photo": {
                    "memberOfTypes": [ "Album" ],
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "foo": {
                                "type": "Boolean",
                                "required": false
                            }
                        }
                    }
                },
                "Album": {
                    "memberOfTypes": [ ],
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "foo": {
                                "type": "Boolean",
                                "required": false
                            }
                        }
                    }
                }
            },
            "actions": {
                "view": {
                    "appliesTo": {
                        "principalTypes": ["Photo", "Album"],
                        "resourceTypes": ["Photo"]
                    }
                }
            }
        }}))
        .expect("schema should be valid");
    }

    /// Test that an invalid schema returns the appropriate error
    #[test]
    fn invalid_schema() {
        assert_matches!(
            Schema::from_json_value(json!(
                // Written as a string because duplicate entity types are detected
                // by the serde-json string parser.
                r#""{"": {
                "entityTypes": {
                    "Photo": {
                        "memberOfTypes": [ "Album" ],
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "foo": {
                                    "type": "Boolean",
                                    "required": false
                                }
                            }
                        }
                    },
                    "Album": {
                        "memberOfTypes": [ ],
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "foo": {
                                    "type": "Boolean",
                                    "required": false
                                }
                            }
                        }
                    },
                    "Photo": {
                        "memberOfTypes": [ "Album" ],
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "foo": {
                                    "type": "Boolean",
                                    "required": false
                                }
                            }
                        }
                    }
                },
                "actions": {
                    "view": {
                        "appliesTo": {
                            "principalTypes": ["Photo", "Album"],
                            "resourceTypes": ["Photo"]
                        }
                    }
                }
            }}"#
            )),
            Err(SchemaError::ParseJson(_))
        );
    }
}

#[cfg(test)]
mod ancestors_tests {
    use super::*;

    #[test]
    fn test_ancestors() {
        let a_euid: EntityUid = EntityUid::from_strs("test", "A");
        let b_euid: EntityUid = EntityUid::from_strs("test", "b");
        let c_euid: EntityUid = EntityUid::from_strs("test", "C");
        let a = Entity::new(a_euid.clone(), HashMap::new(), HashSet::new());
        let b = Entity::new(
            b_euid.clone(),
            HashMap::new(),
            std::iter::once(a_euid.clone()).collect(),
        );
        let c = Entity::new(
            c_euid.clone(),
            HashMap::new(),
            std::iter::once(b_euid.clone()).collect(),
        );
        let es = Entities::from_entities([a, b, c]).unwrap();
        let ans = es.ancestors(&c_euid).unwrap().collect::<HashSet<_>>();
        assert_eq!(ans.len(), 2);
        assert!(ans.contains(&b_euid));
        assert!(ans.contains(&a_euid));
    }
}

/// The main unit tests for schema-based parsing live here, as they require both
/// the Validator and Core packages working together.
///
/// (Core has similar tests, but using a stubbed implementation of Schema.)
#[cfg(test)]
mod schema_based_parsing_tests {
    use std::assert_eq;

    use super::*;
    use cool_asserts::assert_matches;
    use serde_json::json;

    /// Simple test that exercises a variety of attribute types.
    #[test]
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::cognitive_complexity)]
    fn attr_types() {
        let schema = Schema::from_json_value(json!(
        {"": {
            "entityTypes": {
                "Employee": {
                    "memberOfTypes": [],
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "isFullTime": { "type": "Boolean" },
                            "numDirectReports": { "type": "Long" },
                            "department": { "type": "String" },
                            "manager": { "type": "Entity", "name": "Employee" },
                            "hr_contacts": { "type": "Set", "element": {
                                "type": "Entity", "name": "HR" } },
                            "json_blob": { "type": "Record", "attributes": {
                                "inner1": { "type": "Boolean" },
                                "inner2": { "type": "String" },
                                "inner3": { "type": "Record", "attributes": {
                                    "innerinner": { "type": "Entity", "name": "Employee" }
                                }}
                            }},
                            "home_ip": { "type": "Extension", "name": "ipaddr" },
                            "work_ip": { "type": "Extension", "name": "ipaddr" },
                            "trust_score": { "type": "Extension", "name": "decimal" },
                            "tricky": { "type": "Record", "attributes": {
                                "type": { "type": "String" },
                                "id": { "type": "String" }
                            }}
                        }
                    }
                },
                "HR": {
                    "memberOfTypes": []
                }
            },
            "actions": {
                "view": { }
            }
        }}
        ))
        .expect("should be a valid schema");

        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        // without schema-based parsing, `home_ip` and `trust_score` are
        // strings, `manager` and `work_ip` are Records, `hr_contacts` contains
        // Records, and `json_blob.inner3.innerinner` is a Record
        let parsed = Entities::from_json_value(entitiesjson.clone(), None)
            .expect("Should parse without error");
        assert_eq!(parsed.iter().count(), 1);
        let parsed = parsed
            .get(&EntityUid::from_strs("Employee", "12UA45"))
            .expect("that should be the employee id");
        assert_eq!(
            parsed.attr("home_ip"),
            Some(Ok(EvalResult::String("222.222.222.101".into())))
        );
        assert_eq!(
            parsed.attr("trust_score"),
            Some(Ok(EvalResult::String("5.7".into())))
        );
        assert!(matches!(
            parsed.attr("manager"),
            Some(Ok(EvalResult::Record(_)))
        ));
        assert!(matches!(
            parsed.attr("work_ip"),
            Some(Ok(EvalResult::Record(_)))
        ));
        {
            let Some(Ok(EvalResult::Set(set))) = parsed.attr("hr_contacts") else { panic!("expected hr_contacts attr to exist and be a Set") };
            let contact = set.iter().next().expect("should be at least one contact");
            assert!(matches!(contact, EvalResult::Record(_)));
        };
        {
            let Some(Ok(EvalResult::Record(rec))) = parsed.attr("json_blob") else { panic!("expected json_blob attr to exist and be a Record") };
            let inner3 = rec.get("inner3").expect("expected inner3 attr to exist");
            let EvalResult::Record(rec) = inner3 else { panic!("expected inner3 to be a Record") };
            let innerinner = rec
                .get("innerinner")
                .expect("expected innerinner attr to exist");
            assert!(matches!(innerinner, EvalResult::Record(_)));
        };
        // but with schema-based parsing, we get these other types
        let parsed = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect("Should parse without error");
        assert_eq!(parsed.iter().count(), 1);
        let parsed = parsed
            .get(&EntityUid::from_strs("Employee", "12UA45"))
            .expect("that should be the employee id");
        assert_eq!(parsed.attr("isFullTime"), Some(Ok(EvalResult::Bool(true))));
        assert_eq!(
            parsed.attr("numDirectReports"),
            Some(Ok(EvalResult::Long(3)))
        );
        assert_eq!(
            parsed.attr("department"),
            Some(Ok(EvalResult::String("Sales".into())))
        );
        assert_eq!(
            parsed.attr("manager"),
            Some(Ok(EvalResult::EntityUid(EntityUid::from_strs(
                "Employee", "34FB87"
            ))))
        );
        {
            let Some(Ok(EvalResult::Set(set))) = parsed.attr("hr_contacts") else { panic!("expected hr_contacts attr to exist and be a Set") };
            let contact = set.iter().next().expect("should be at least one contact");
            assert!(matches!(contact, EvalResult::EntityUid(_)));
        };
        {
            let Some(Ok(EvalResult::Record(rec))) = parsed.attr("json_blob") else { panic!("expected json_blob attr to exist and be a Record") };
            let inner3 = rec.get("inner3").expect("expected inner3 attr to exist");
            let EvalResult::Record(rec) = inner3 else { panic!("expected inner3 to be a Record") };
            let innerinner = rec
                .get("innerinner")
                .expect("expected innerinner attr to exist");
            assert!(matches!(innerinner, EvalResult::EntityUid(_)));
        };
        assert_eq!(
            parsed.attr("home_ip"),
            Some(Ok(EvalResult::ExtensionValue("222.222.222.101/32".into())))
        );
        assert_eq!(
            parsed.attr("work_ip"),
            Some(Ok(EvalResult::ExtensionValue("2.2.2.0/24".into())))
        );
        assert_eq!(
            parsed.attr("trust_score"),
            Some(Ok(EvalResult::ExtensionValue("5.7000".into())))
        );

        // simple type mismatch with expected type
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": "3",
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let err = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect_err("should fail due to type mismatch on numDirectReports");
        assert!(
            err.to_string().contains(r#"In attribute "numDirectReports" on Employee::"12UA45", type mismatch: attribute was expected to have type long, but actually has type string"#),
            "actual error message was {err}"
        );

        // another simple type mismatch with expected type
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": "34FB87",
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let err = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect_err("should fail due to type mismatch on manager");
        assert!(
            err.to_string()
                .contains(r#"In attribute "manager" on Employee::"12UA45", expected a literal entity reference, but got "34FB87""#),
            "actual error message was {err}"
        );

        // type mismatch where we expect a set and get just a single element
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": { "type": "HR", "id": "aaaaa" },
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let err = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect_err("should fail due to type mismatch on hr_contacts");
        assert!(
            err.to_string().contains(r#"In attribute "hr_contacts" on Employee::"12UA45", type mismatch: attribute was expected to have type (set of (entity of type HR)), but actually has type record with attributes: ("#),
            "actual error message was {err}"
        );

        // type mismatch where we just get the wrong entity type
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "HR", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let err = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect_err("should fail due to type mismatch on manager");
        assert!(
            err.to_string().contains(r#"In attribute "manager" on Employee::"12UA45", type mismatch: attribute was expected to have type (entity of type Employee), but actually has type (entity of type HR)"#),
            "actual error message was {err}"
        );

        // type mismatch where we're expecting an extension type and get a
        // different extension type
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": { "fn": "decimal", "arg": "3.33" },
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let err = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect_err("should fail due to type mismatch on home_ip");
        assert!(
            err.to_string().contains(r#"In attribute "home_ip" on Employee::"12UA45", type mismatch: attribute was expected to have type ipaddr, but actually has type decimal"#),
            "actual error message was {err}"
        );

        // missing a record attribute entirely
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let err = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect_err("should fail due to missing attribute \"inner2\"");
        assert!(
            err.to_string().contains(r#"In attribute "json_blob" on Employee::"12UA45", expected the record to have an attribute "inner2", but it didn't"#),
            "actual error message was {err}"
        );

        // record attribute has the wrong type
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": 33,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let err = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect_err("should fail due to type mismatch on attribute \"inner1\"");
        assert!(
            err.to_string().contains(r#"In attribute "json_blob" on Employee::"12UA45", type mismatch: attribute was expected to have type record with attributes: "#),
            "actual error message was {err}"
        );

        let entitiesjson = json!(
            [
                {
                    "uid": { "__entity": { "type": "Employee", "id": "12UA45" } },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "__entity": { "type": "Employee", "id": "34FB87" } },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": { "__extn": { "fn": "ip", "arg": "222.222.222.101" } },
                        "work_ip": { "__extn": { "fn": "ip", "arg": "2.2.2.0/24" } },
                        "trust_score": { "__extn": { "fn": "decimal", "arg": "5.7" } },
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );

        Entities::from_json_value(entitiesjson, Some(&schema))
            .expect("this version with explicit __entity and __extn escapes should also pass");
    }

    /// Test that involves namespaced entity types
    #[test]
    fn namespaces() {
        let schema = Schema::from_str(
            r#"
        {"XYZCorp": {
            "entityTypes": {
                "Employee": {
                    "memberOfTypes": [],
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "isFullTime": { "type": "Boolean" },
                            "department": { "type": "String" },
                            "manager": {
                                "type": "Entity",
                                "name": "XYZCorp::Employee"
                            }
                        }
                    }
                }
            },
            "actions": {
                "view": {}
            }
        }}
        "#,
        )
        .expect("should be a valid schema");

        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "XYZCorp::Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "department": "Sales",
                        "manager": { "type": "XYZCorp::Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let parsed = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect("Should parse without error");
        assert_eq!(parsed.iter().count(), 1);
        let parsed = parsed
            .get(&EntityUid::from_strs("XYZCorp::Employee", "12UA45"))
            .expect("that should be the employee type and id");
        assert_eq!(parsed.attr("isFullTime"), Some(Ok(EvalResult::Bool(true))));
        assert_eq!(
            parsed.attr("department"),
            Some(Ok(EvalResult::String("Sales".into())))
        );
        assert_eq!(
            parsed.attr("manager"),
            Some(Ok(EvalResult::EntityUid(EntityUid::from_strs(
                "XYZCorp::Employee",
                "34FB87"
            ))))
        );

        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "XYZCorp::Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let err = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect_err("should fail due to manager being wrong entity type (missing namespace)");
        assert!(
            err.to_string().contains(r#"In attribute "manager" on XYZCorp::Employee::"12UA45", type mismatch: attribute was expected to have type (entity of type XYZCorp::Employee), but actually has type (entity of type Employee)"#),
            "actual error message was {err}"
        );
    }

    /// Test that involves optional attributes
    #[test]
    fn optional_attrs() {
        let schema = Schema::from_str(
            r#"
        {"": {
            "entityTypes": {
                "Employee": {
                    "memberOfTypes": [],
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "isFullTime": { "type": "Boolean" },
                            "department": { "type": "String", "required": false },
                            "manager": { "type": "Entity", "name": "Employee" }
                        }
                    }
                }
            },
            "actions": {
                "view": {}
            }
        }}
        "#,
        )
        .expect("should be a valid schema");

        // all good here
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let parsed = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect("Should parse without error");
        assert_eq!(parsed.iter().count(), 1);

        // "department" shouldn't be required
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "manager": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let parsed = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect("Should parse without error");
        assert_eq!(parsed.iter().count(), 1);
    }

    /// Test that involves open entities
    #[test]
    #[should_panic(
        expected = "UnsupportedSchemaFeature(\"Records and entities with additional attributes are not yet implemented.\")"
    )]
    fn open_entities() {
        let schema = Schema::from_str(
            r#"
        {"": {
            "entityTypes": {
                "Employee": {
                    "memberOfTypes": [],
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "isFullTime": { "type": "Boolean" },
                            "department": { "type": "String", "required": false },
                            "manager": { "type": "Entity", "name": "Employee" }
                        },
                        "additionalAttributes": true
                    }
                }
            },
            "actions": {
                "view": {}
            }
        }}
        "#,
        )
        .expect("should be a valid schema");

        // all good here
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let parsed = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect("Should parse without error");
        assert_eq!(parsed.iter().count(), 1);

        // providing another attribute "foobar" should be OK
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "foobar": 234,
                        "manager": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let parsed = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect("Should parse without error");
        assert_eq!(parsed.iter().count(), 1);
    }

    #[test]
    fn schema_sanity_check() {
        let src = "{ , .. }";
        assert_matches!(Schema::from_str(src), Err(super::SchemaError::ParseJson(_)));
    }

    #[test]
    fn template_constraint_sanity_checks() {
        assert!(!TemplatePrincipalConstraint::Any.has_slot());
        assert!(!TemplatePrincipalConstraint::In(Some(EntityUid::from_strs("a", "a"))).has_slot());
        assert!(!TemplatePrincipalConstraint::Eq(Some(EntityUid::from_strs("a", "a"))).has_slot());
        assert!(TemplatePrincipalConstraint::In(None).has_slot());
        assert!(TemplatePrincipalConstraint::Eq(None).has_slot());
        assert!(!TemplateResourceConstraint::Any.has_slot());
        assert!(!TemplateResourceConstraint::In(Some(EntityUid::from_strs("a", "a"))).has_slot());
        assert!(!TemplateResourceConstraint::Eq(Some(EntityUid::from_strs("a", "a"))).has_slot());
        assert!(TemplateResourceConstraint::In(None).has_slot());
        assert!(TemplateResourceConstraint::Eq(None).has_slot());
    }

    #[test]
    fn template_principal_constraints() {
        let src = r#"
            permit(principal, action, resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(t.principal_constraint(), TemplatePrincipalConstraint::Any);

        let src = r#"
            permit(principal == ?principal, action, resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.principal_constraint(),
            TemplatePrincipalConstraint::Eq(None)
        );

        let src = r#"
            permit(principal == A::"a", action, resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.principal_constraint(),
            TemplatePrincipalConstraint::Eq(Some(EntityUid::from_strs("A", "a")))
        );

        let src = r#"
            permit(principal in ?principal, action, resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.principal_constraint(),
            TemplatePrincipalConstraint::In(None)
        );

        let src = r#"
            permit(principal in A::"a", action, resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.principal_constraint(),
            TemplatePrincipalConstraint::In(Some(EntityUid::from_strs("A", "a")))
        );
    }

    #[test]
    fn template_action_constraints() {
        let src = r#"
            permit(principal, action, resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(t.action_constraint(), ActionConstraint::Any);

        let src = r#"
            permit(principal, action == Action::"A", resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.action_constraint(),
            ActionConstraint::Eq(EntityUid::from_strs("Action", "A"))
        );

        let src = r#"
            permit(principal, action in [Action::"A", Action::"B"], resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.action_constraint(),
            ActionConstraint::In(vec![
                EntityUid::from_strs("Action", "A"),
                EntityUid::from_strs("Action", "B")
            ])
        );
    }

    #[test]
    fn template_resource_constraints() {
        let src = r#"
            permit(principal, action, resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(t.resource_constraint(), TemplateResourceConstraint::Any);

        let src = r#"
            permit(principal, action, resource == ?resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.resource_constraint(),
            TemplateResourceConstraint::Eq(None)
        );

        let src = r#"
            permit(principal, action, resource == A::"a");
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.resource_constraint(),
            TemplateResourceConstraint::Eq(Some(EntityUid::from_strs("A", "a")))
        );

        let src = r#"
            permit(principal, action, resource in ?resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.resource_constraint(),
            TemplateResourceConstraint::In(None)
        );

        let src = r#"
            permit(principal, action, resource in A::"a");
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.resource_constraint(),
            TemplateResourceConstraint::In(Some(EntityUid::from_strs("A", "a")))
        );
    }

    #[test]
    fn schema_namespace() {
        let fragment: SchemaFragment = r#"
        {
            "Foo::Bar": {
                "entityTypes": {},
                "actions": {}
            }
        }
        "#
        .parse()
        .unwrap();
        let namespaces = fragment.namespaces().next().unwrap();
        assert_eq!(
            namespaces.map(|ns| ns.to_string()),
            Some("Foo::Bar".to_string())
        );
        let _schema: Schema = fragment.try_into().expect("Should convert to schema");

        let fragment: SchemaFragment = r#"
        {
            "": {
                "entityTypes": {},
                "actions": {}
            }
        }
        "#
        .parse()
        .unwrap();
        let namespaces = fragment.namespaces().next().unwrap();
        assert_eq!(namespaces, None);
        let _schema: Schema = fragment.try_into().expect("Should convert to schema");
    }

    #[test]
    fn load_multiple_namespaces() {
        let fragment = SchemaFragment::from_json_value(json!({
            "Foo::Bar": {
                "entityTypes": {
                    "Baz": {
                        "memberOfTypes": ["Bar::Foo::Baz"]
                    }
                },
                "actions": {}
            },
            "Bar::Foo": {
                "entityTypes": {
                    "Baz": {
                        "memberOfTypes": ["Foo::Bar::Baz"]
                    }
                },
                "actions": {}
            }
        }))
        .unwrap();

        let schema = Schema::from_schema_fragments([fragment]).unwrap();

        assert!(schema
            .0
            .get_entity_type(&"Foo::Bar::Baz".parse().unwrap())
            .is_some());
        assert!(schema
            .0
            .get_entity_type(&"Bar::Foo::Baz".parse().unwrap())
            .is_some());
    }

    #[test]
    fn get_attributes_from_schema() {
        let fragment: SchemaFragment = SchemaFragment::from_json_value(json!({
        "": {
            "entityTypes": {},
            "actions": {
                "A": {},
                "B": {
                    "memberOf": [{"id": "A"}]
                },
                "C": {
                    "memberOf": [{"id": "A"}]
                },
                "D": {
                    "memberOf": [{"id": "B"}, {"id": "C"}]
                },
                "E": {
                    "memberOf": [{"id": "D"}]
                }
            }
        }}))
        .unwrap();

        let schema = Schema::from_schema_fragments([fragment]).unwrap();
        let action_entities = schema.action_entities().unwrap();

        let a_euid = EntityUid::from_strs("Action", "A");
        let b_euid = EntityUid::from_strs("Action", "B");
        let c_euid = EntityUid::from_strs("Action", "C");
        let d_euid = EntityUid::from_strs("Action", "D");
        let e_euid = EntityUid::from_strs("Action", "E");

        assert_eq!(
            action_entities,
            Entities::from_entities([
                Entity::new(a_euid.clone(), HashMap::new(), HashSet::new()),
                Entity::new(
                    b_euid.clone(),
                    HashMap::new(),
                    HashSet::from([a_euid.clone()])
                ),
                Entity::new(
                    c_euid.clone(),
                    HashMap::new(),
                    HashSet::from([a_euid.clone()])
                ),
                Entity::new(
                    d_euid.clone(),
                    HashMap::new(),
                    HashSet::from([a_euid.clone(), b_euid.clone(), c_euid.clone()])
                ),
                Entity::new(
                    e_euid,
                    HashMap::new(),
                    HashSet::from([a_euid, b_euid, c_euid, d_euid])
                ),
            ])
            .unwrap()
        );
    }
}
