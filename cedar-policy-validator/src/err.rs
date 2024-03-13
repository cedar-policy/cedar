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
    ast::{EntityAttrEvaluationError, EntityUID, Name},
    parser::err::{ParseError, ParseErrors},
    transitive_closure,
};
use itertools::Itertools;
use miette::Diagnostic;
use thiserror::Error;

use crate::human_schema::parser::HumanSyntaxParseErrors;

#[derive(Debug, Error, Diagnostic)]
pub enum HumanSchemaError {
    #[error("{0}")]
    #[diagnostic(transparent)]
    Core(#[from] SchemaError),
    #[error("{0}")]
    IO(#[from] std::io::Error),
    #[error("{0}")]
    #[diagnostic(transparent)]
    Parsing(#[from] HumanSyntaxParseErrors),
}

#[derive(Debug, Diagnostic, Error)]
pub enum SchemaError {
    /// Error thrown by the `serde_json` crate during deserialization
    #[error("failed to parse schema: {0}")]
    Serde(#[from] serde_json::Error),
    /// Errors occurring while computing or enforcing transitive closure on
    /// action hierarchy.
    #[error("transitive closure computation/enforcement error on action hierarchy: {0}")]
    #[diagnostic(transparent)]
    ActionTransitiveClosure(Box<transitive_closure::TcError<EntityUID>>),
    /// Errors occurring while computing or enforcing transitive closure on
    /// entity type hierarchy.
    #[error("transitive closure computation/enforcement error on entity type hierarchy: {0}")]
    #[diagnostic(transparent)]
    EntityTypeTransitiveClosure(#[from] transitive_closure::TcError<Name>),
    /// Error generated when processing a schema file that uses unsupported features
    #[error("unsupported feature used in schema: {0}")]
    #[diagnostic(transparent)]
    UnsupportedFeature(UnsupportedFeature),
    /// Undeclared entity type(s) used in the `memberOf` field of an entity
    /// type, the `appliesTo` fields of an action, or an attribute type in a
    /// context or entity attribute record. Entity types in the error message
    /// are fully qualified, including any implicit or explicit namespaces.
    #[error("undeclared entity type(s): {0:?}")]
    #[diagnostic(help(
        "any entity types appearing anywhere in a schema need to be declared in `entityTypes`"
    ))]
    UndeclaredEntityTypes(HashSet<String>),
    /// Undeclared action(s) used in the `memberOf` field of an action.
    #[error("undeclared action(s): {0:?}")]
    #[diagnostic(help("any actions appearing in `memberOf` need to be declared in `actions`"))]
    UndeclaredActions(HashSet<String>),
    /// This error occurs in either of the following cases (see discussion on #477):
    ///     - undeclared common type(s) appearing in entity or context attributes
    ///     - common type(s) (declared or not) appearing in declarations of other common types
    #[error("undeclared common type(s), or common type(s) used in the declaration of another common type: {0:?}")]
    #[diagnostic(help("any common types used in entity or context attributes need to be declared in `commonTypes`, and currently, common types may not reference other common types"))]
    UndeclaredCommonTypes(HashSet<String>),
    /// Duplicate specifications for an entity type. Argument is the name of
    /// the duplicate entity type.
    #[error("duplicate entity type `{0}`")]
    DuplicateEntityType(String),
    /// Duplicate specifications for an action. Argument is the name of the
    /// duplicate action.
    #[error("duplicate action `{0}`")]
    DuplicateAction(String),
    /// Duplicate specification for a reusable type declaration.
    #[error("duplicate common type `{0}`")]
    DuplicateCommonType(String),
    /// Cycle in the schema's action hierarchy.
    #[error("cycle in action hierarchy containing `{0}`")]
    CycleInActionHierarchy(EntityUID),
    /// Parse errors occurring while parsing an entity type.
    #[error("parse error in entity type: {}", Self::format_parse_errs(.0))]
    #[diagnostic(transparent)]
    ParseEntityType(ParseErrors),
    /// Parse errors occurring while parsing a namespace identifier.
    #[error("parse error in namespace identifier: {}", Self::format_parse_errs(.0))]
    #[diagnostic(transparent)]
    ParseNamespace(ParseErrors),
    /// Parse errors occurring while parsing an extension type.
    #[error("parse error in extension type: {}", Self::format_parse_errs(.0))]
    #[diagnostic(transparent)]
    ParseExtensionType(ParseErrors),
    /// Parse errors occurring while parsing the name of one of reusable
    /// declared types.
    #[error("parse error in common type identifier: {}", Self::format_parse_errs(.0))]
    #[diagnostic(transparent)]
    ParseCommonType(ParseErrors),
    /// The schema file included an entity type `Action` in the entity type
    /// list. The `Action` entity type is always implicitly declared, and it
    /// cannot currently have attributes or be in any groups, so there is no
    /// purposes in adding an explicit entry.
    #[error("entity type `Action` declared in `entityTypes` list")]
    ActionEntityTypeDeclared,
    /// `context` or `shape` fields are not records
    #[error("{0} is declared with a type other than `Record`")]
    #[diagnostic(help("{}", match .0 {
        ContextOrShape::ActionContext(_) => "action contexts must have type `Record`",
        ContextOrShape::EntityTypeShape(_) => "entity type shapes must have type `Record`",
    }))]
    ContextOrShapeNotRecord(ContextOrShape),
    /// An action entity (transitively) has an attribute that is an empty set.
    /// The validator cannot assign a type to an empty set.
    /// This error variant should only be used when `PermitAttributes` is enabled.
    #[error("action `{0}` has an attribute that is an empty set")]
    #[diagnostic(help(
        "actions are not currently allowed to have attributes whose value is an empty set"
    ))]
    ActionAttributesContainEmptySet(EntityUID),
    /// An action entity (transitively) has an attribute of unsupported type (`ExprEscape`, `EntityEscape` or `ExtnEscape`).
    /// This error variant should only be used when `PermitAttributes` is enabled.
    #[error("action `{0}` has an attribute with unsupported JSON representation: {1}")]
    UnsupportedActionAttribute(EntityUID, String),
    /// Error when evaluating an action attribute
    #[error(transparent)]
    #[diagnostic(transparent)]
    ActionAttrEval(EntityAttrEvaluationError),
    /// Error thrown when the schema contains the `__expr` escape.
    /// Support for this escape form has been dropped.
    #[error("the `__expr` escape is no longer supported")]
    #[diagnostic(help("to create an entity reference, use `__entity`; to create an extension value, use `__extn`; and for all other values, use JSON directly"))]
    ExprEscapeUsed,
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
            transitive_closure::TcError::HasCycle { vertex_with_loop } => {
                SchemaError::CycleInActionHierarchy(vertex_with_loop)
            }
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

#[derive(Debug, Diagnostic, Error)]
pub enum UnsupportedFeature {
    #[error("records and entities with `additionalAttributes` are experimental, but the experimental `partial-validate` feature is not enabled")]
    OpenRecordsAndEntities,
    // Action attributes are allowed if `ActionBehavior` is `PermitAttributes`
    #[error("action declared with attributes: [{}]", .0.iter().join(", "))]
    ActionAttributes(Vec<String>),
}
