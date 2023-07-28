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
    /// Error thrown by the `serde_json` crate during deserialization
    #[error("failed to parse schema: {0}")]
    Serde(#[from] serde_json::Error),
    /// Errors occurring while computing or enforcing transitive closure on
    /// action hierarchy.
    #[error("transitive closure computation/enforcement error on action hierarchy: {0}")]
    ActionTransitiveClosure(Box<transitive_closure::TcError<EntityUID>>),
    /// Errors occurring while computing or enforcing transitive closure on
    /// entity type hierarchy.
    #[error("transitive closure computation/enforcement error on entity type hierarchy: {0}")]
    EntityTypeTransitiveClosure(#[from] transitive_closure::TcError<Name>),
    /// Error generated when processing a schema file that uses unsupported features
    #[error("unsupported feature used in schema: {0}")]
    UnsupportedFeature(UnsupportedFeature),
    /// Undeclared entity type(s) used in the `memberOf` field of an entity
    /// type, the `appliesTo` fields of an action, or an attribute type in a
    /// context or entity attribute record. Entity types in the error message
    /// are fully qualified, including any implicit or explicit namespaces.
    #[error("undeclared entity type(s): {0:?}")]
    UndeclaredEntityTypes(HashSet<String>),
    /// Undeclared action(s) used in the `memberOf` field of an action.
    #[error("undeclared action(s): {0:?}")]
    UndeclaredActions(HashSet<String>),
    /// Undeclared common type(s) used in entity or context attributes.
    #[error("undeclared common type(s): {0:?}")]
    UndeclaredCommonTypes(HashSet<String>),
    /// Duplicate specifications for an entity type. Argument is the name of
    /// the duplicate entity type.
    #[error("duplicate entity type: {0}")]
    DuplicateEntityType(String),
    /// Duplicate specifications for an action. Argument is the name of the
    /// duplicate action.
    #[error("duplicate action: {0}")]
    DuplicateAction(String),
    /// Duplicate specification for a reusable type declaration.
    #[error("duplicate common type: {0}")]
    DuplicateCommonType(String),
    /// Cycle in the schema's action hierarchy.
    #[error("cycle in action hierarchy")]
    CycleInActionHierarchy,
    /// Parse errors occurring while parsing an entity type.
    #[error("parse error in entity type: {}", Self::format_parse_errs(.0))]
    ParseEntityType(ParseErrors),
    /// Parse errors occurring while parsing a namespace identifier.
    #[error("parse error in namespace identifier: {}", Self::format_parse_errs(.0))]
    ParseNamespace(ParseErrors),
    /// Parse errors occurring while parsing an extension type.
    #[error("parse error in extension type: {}", Self::format_parse_errs(.0))]
    ParseExtensionType(ParseErrors),
    /// Parse errors occurring while parsing the name of one of reusable
    /// declared types.
    #[error("parse error in common type identifier: {}", Self::format_parse_errs(.0))]
    ParseCommonType(ParseErrors),
    /// The schema file included an entity type `Action` in the entity type
    /// list. The `Action` entity type is always implicitly declared, and it
    /// cannot currently have attributes or be in any groups, so there is no
    /// purposes in adding an explicit entry.
    #[error("entity type `Action` declared in `entityTypes` list")]
    ActionEntityTypeDeclared,
    /// `context` or `shape` fields are not records
    #[error("{0} is declared with a type other than `Record`")]
    ContextOrShapeNotRecord(ContextOrShape),
    /// An action entity (transitively) has an attribute that is an empty set.
    /// The validator cannot assign a type to an empty set.
    /// This error variant should only be used when `PermitAttributes` is enabled.
    #[error("action `{0}` has an attribute that is an empty set")]
    ActionAttributesContainEmptySet(EntityUID),
    /// An action entity (transitively) has an attribute of unsupported type (`ExprEscape`, `EntityEscape` or `ExtnEscape`).
    /// This error variant should only be used when `PermitAttributes` is enabled.
    #[error("action `{0}` has an attribute with unsupported JSON representation: {1}")]
    UnsupportedActionAttribute(EntityUID, String),
}

impl From<transitive_closure::TcError<EntityUID>> for SchemaError {
    fn from(e: transitive_closure::TcError<EntityUID>) -> Self {
        // we use code in transitive_closure to check for cycles in the action
        // hierarchy, but in case of an error we want to report the more descriptive
        // CycleInActionHierarchy instead of ActionTransitiveClosureError
        match e {
            transitive_closure::TcError::MissingTcEdge { .. } => {
                SchemaError::ActionTransitiveClosure(Box::new(e))
            }
            transitive_closure::TcError::HasCycle { .. } => SchemaError::CycleInActionHierarchy,
        }
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
    // Action attributes are allowed if `ActionBehavior` is `PermitAttributes`
    ActionAttributes(Vec<String>),
}

impl std::fmt::Display for UnsupportedFeature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenRecordsAndEntities => write!(
                f,
                "records and entities with additional attributes are not yet implemented"
            ),
            Self::ActionAttributes(attrs) => write!(
                f,
                "action declared with attributes: [{}]",
                attrs.iter().join(", ")
            ),
        }
    }
}
