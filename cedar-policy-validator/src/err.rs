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

use std::collections::HashSet;

use cedar_policy_core::{
    ast::{EntityUID, Name},
    parser::err::{ParseError, ParseErrors},
    transitive_closure,
};
use itertools::Itertools;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SchemaError {
    /// Errors loading and parsing schema files
    #[error("JSON Schema file could not be parsed: {0}")]
    ParseFileFormat(serde_json::Error),
    /// Errors occurring while computing or enforcing transitive closure on
    /// action id hierarchy.
    #[error("Transitive closure error on action hierarchy: {0}")]
    ActionTransitiveClosureError(Box<transitive_closure::TcError<EntityUID>>),
    /// Errors occurring while computing or enforcing transitive closure on
    /// entity type hierarchy.
    #[error("Transitive closure error on entity hierarchy: {0}")]
    EntityTransitiveClosureError(transitive_closure::TcError<Name>),
    /// Error generated when processing a schema file that uses features which
    /// are not yet supported by the implementation.
    #[error("Unsupported feature used in schema: {0}")]
    UnsupportedSchemaFeature(UnsupportedFeature),
    /// Undeclared entity type(s) used in an entity type's memberOf field, an
    /// action's appliesTo fields, or an attribute type in a context or entity
    /// attributes record. Entity types are reported fully qualified, including
    /// any implicit or explicit namespaces.
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
    /// Duplicate specification for a reusable type declaration.
    #[error("Duplicate common type {0}")]
    DuplicateCommonType(String),
    /// Cycle in the schema's action hierarchy.
    #[error("Cycle in action hierarchy")]
    CycleInActionHierarchy,
    /// Parse errors occurring while parsing an entity type.
    #[error("Parse error in entity type: {}", Self::format_parse_errs(.0))]
    EntityTypeParseError(ParseErrors),
    /// Parse errors occurring while parsing a namespace identifier.
    #[error("Parse error in namespace identifier: {}", Self::format_parse_errs(.0))]
    NamespaceParseError(ParseErrors),
    /// Parse errors occurring while parsing an extension type.
    #[error("Parse error in extension type: {}", Self::format_parse_errs(.0))]
    ExtensionTypeParseError(ParseErrors),
    /// Parse errors occurring while parsing the name of one of reusable
    /// declared types.
    #[error("Parse error in common type identifier: {}", Self::format_parse_errs(.0))]
    CommonTypeParseError(ParseErrors),
    /// The schema file included an entity type `Action` in the entity type
    /// list. The `Action` entity type is always implicitly declared, and it
    /// cannot currently have attributes or be in any groups, so there is no
    /// purposes in adding an explicit entry.
    #[error("Entity type `Action` declared in `entityTypes` list")]
    ActionEntityTypeDeclared,
    /// One or more action entities are declared with `attributes`, but this is
    /// not currently supported.
    #[error("Actions declared with `attributes`: [{}]", .0.iter().join(", "))]
    ActionEntityAttributes(Vec<String>),
    #[error("{0} is declared with a type other than `Record`")]
    ContextOrShapeNotRecord(ContextOrShape),
    /// An Action Entity (transitively) has an attribute that is an empty set
    #[error("An action entity has an attribute that is an empty set")]
    ActionEntityAttributeEmptySet,
    /// An Action Entity (transitively) has an attribute of unsupported type (ExprEscape, EntityEscape or ExtnEscape)
    #[error("An action entity has attribute with unsupported type: (escaped expression, entity or extension)")]
    ActionEntityAttributeUnsupportedType,
}

impl From<transitive_closure::TcError<EntityUID>> for SchemaError {
    fn from(e: transitive_closure::TcError<EntityUID>) -> Self {
        // we use code in transitive_closure to check for cycles in the action
        // hierarchy, but in case of an error we want to report the more descriptive
        // CycleInActionHierarchy instead of ActionTransitiveClosureError
        match e {
            transitive_closure::TcError::MissingTcEdge { .. } => {
                SchemaError::ActionTransitiveClosureError(Box::new(e))
            }
            transitive_closure::TcError::HasCycle { .. } => SchemaError::CycleInActionHierarchy,
        }
    }
}

impl From<serde_json::Error> for SchemaError {
    fn from(e: serde_json::Error) -> Self {
        SchemaError::ParseFileFormat(e)
    }
}

impl From<transitive_closure::TcError<Name>> for SchemaError {
    fn from(e: transitive_closure::TcError<Name>) -> Self {
        SchemaError::EntityTransitiveClosureError(e)
    }
}

pub type Result<T> = std::result::Result<T, SchemaError>;

impl SchemaError {
    fn format_parse_errs(errs: &[ParseError]) -> String {
        errs.iter().map(|e| e.to_string()).join(", ")
    }
}

#[derive(Debug)]
pub enum ContextOrShape {
    ActionContext(EntityUID),
    EntityTypeShape(Name),
}

impl std::fmt::Display for ContextOrShape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContextOrShape::ActionContext(action) => write!(f, "Context for action {}", action),
            ContextOrShape::EntityTypeShape(entity_type) => {
                write!(f, "Shape for entity type {}", entity_type)
            }
        }
    }
}

#[derive(Debug)]
pub enum UnsupportedFeature {
    OpenRecordsAndEntities,
}

impl std::fmt::Display for UnsupportedFeature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnsupportedFeature::OpenRecordsAndEntities => write!(
                f,
                "Records and entities with additional attributes are not yet implemented."
            ),
        }
    }
}
