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
    parser::err::ParseError,
    transitive_closure,
};
use itertools::Itertools;

#[derive(Debug)]
pub enum SchemaError {
    /// Errors loading and parsing schema files
    ParseFileFormat(serde_json::Error),
    /// Errors occurring while computing or enforcing transitive closure on
    /// action id hierarchy.
    ActionTransitiveClosureError(Box<transitive_closure::Err<EntityUID>>),
    /// Errors occurring while computing or enforcing transitive closure on
    /// entity type hierarchy.
    EntityTransitiveClosureError(transitive_closure::Err<Name>),
    /// Error generated when processing a schema file that uses features which
    /// are not yet supported by the implementation.
    UnsupportedSchemaFeature(UnsupportedFeature),
    /// Undeclared entity type(s) used in an entity type's memberOf field, an
    /// action's appliesTo fields, or an attribute type in a context or entity
    /// attributes record. Entity types are reported fully qualified, including
    /// any implicit or explicit namespaces.
    UndeclaredEntityTypes(HashSet<String>),
    /// Undeclared action(s) used in an action's memberOf field.
    UndeclaredActions(HashSet<String>),
    /// Undeclared type used in entity or context attributes.
    UndeclaredCommonType(HashSet<String>),
    /// Duplicate specifications for an entity type. Argument is the name of
    /// the duplicate entity type.
    DuplicateEntityType(String),
    /// Duplicate specifications for an action. Argument is the name of the
    /// duplicate action.
    DuplicateAction(String),
    /// Duplicate specification for a reusable type declaration.
    DuplicateCommonType(String),
    /// Cycle in the schema's action hierarchy.
    CycleInActionHierarchy,
    /// Parse errors occurring while parsing an entity type.
    EntityTypeParseError(Vec<ParseError>),
    /// Parse errors occurring while parsing a namespace identifier.
    NamespaceParseError(Vec<ParseError>),
    /// Parse errors occurring while parsing an extension type.
    ExtensionTypeParseError(Vec<ParseError>),
    /// Parse errors occurring while parsing the name of one of reusable
    /// declared types.
    CommonTypeParseError(Vec<ParseError>),
    /// The schema file included an entity type `Action` in the entity type
    /// list. The `Action` entity type is always implicitly declared, and it
    /// cannot currently have attributes or be in any groups, so there is no
    /// purposes in adding an explicit entry.
    ActionEntityTypeDeclared,
    /// One or more action entities are declared with `attributes`, but this is
    /// not currently supported.
    ActionEntityAttributes(Vec<String>),
    ContextOrShapeNotRecord,
    /// An Action Entity (transitively) has an attribute that is an empty set
    ActionEntityAttributeEmptySet,
    /// An Action Entity (transitively) has an attribute of unsupported type (ExprEscape, EntityEscape or ExtnEscape)
    ActionEntityAttributeUnsupportedType,
    /// Malformed bounds information on a declaration of type `Long`.
    MalformedLongBounds,
}

impl std::error::Error for SchemaError {}

impl From<transitive_closure::Err<EntityUID>> for SchemaError {
    fn from(e: transitive_closure::Err<EntityUID>) -> Self {
        // we use code in transitive_closure to check for cycles in the action
        // hierarchy, but in case of an error we want to report the more descriptive
        // CycleInActionHierarchy instead of ActionTransitiveClosureError
        match e {
            transitive_closure::Err::TCEnforcementError { .. } => {
                SchemaError::ActionTransitiveClosureError(Box::new(e))
            }
            transitive_closure::Err::HasCycle { .. } => SchemaError::CycleInActionHierarchy,
        }
    }
}

impl From<serde_json::Error> for SchemaError {
    fn from(e: serde_json::Error) -> Self {
        SchemaError::ParseFileFormat(e)
    }
}

impl From<transitive_closure::Err<Name>> for SchemaError {
    fn from(e: transitive_closure::Err<Name>) -> Self {
        SchemaError::EntityTransitiveClosureError(e)
    }
}

pub type Result<T> = std::result::Result<T, SchemaError>;

impl SchemaError {
    fn format_parse_errs(errs: &[ParseError]) -> String {
        errs.iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaError::ParseFileFormat(e) => {
                write!(f, "JSON Schema file could not be parsed: {e}")
            }
            SchemaError::ActionTransitiveClosureError(e) => {
                write!(f, "Transitive closure error on action hierarchy: {}", e)
            }
            SchemaError::EntityTransitiveClosureError(e) => {
                write!(f, "Transitive closure error on entity hierarchy: {}", e)
            }
            SchemaError::UnsupportedSchemaFeature(feat) => {
                write!(f, "Unsupported feature used in schema: {feat}")
            }
            SchemaError::UndeclaredEntityTypes(e) => {
                write!(f, "Undeclared entity types: {:?}", e)
            }
            SchemaError::UndeclaredActions(a) => {
                write!(f, "Undeclared actions {:?}", a)
            }
            SchemaError::UndeclaredCommonType(t) => {
                write!(f, "Undeclared common types {:?}", t)
            }
            SchemaError::DuplicateEntityType(e) => {
                write!(f, "Duplicate entity type {e}")
            }
            SchemaError::DuplicateAction(a) => {
                write!(f, "Duplicate action {}", a)
            }
            SchemaError::DuplicateCommonType(t) => {
                write!(f, "Duplicate common type {t}")
            }
            SchemaError::CycleInActionHierarchy => {
                write!(f, "Cycle in action hierarchy")
            }
            SchemaError::EntityTypeParseError(parse_errs) => {
                write!(
                    f,
                    "Parse error in entity type: {}",
                    Self::format_parse_errs(parse_errs),
                )
            }
            SchemaError::NamespaceParseError(parse_errs) => {
                write!(
                    f,
                    "Parse error in namespace identifier: {}",
                    Self::format_parse_errs(parse_errs),
                )
            }
            SchemaError::CommonTypeParseError(parse_errs) => {
                write!(
                    f,
                    "Parse error in common type identifier: {}",
                    Self::format_parse_errs(parse_errs),
                )
            }
            SchemaError::ExtensionTypeParseError(parse_errs) => {
                write!(
                    f,
                    "Parse error in extension type: {}",
                    Self::format_parse_errs(parse_errs),
                )
            }
            SchemaError::ActionEntityTypeDeclared => {
                write!(f, "Entity type `Action` declared in `entityTypes` list.")
            }
            SchemaError::ActionEntityAttributes(actions) => {
                write!(
                    f,
                    "Actions declared with `attributes`: [{}]",
                    actions.iter().join(", ")
                )
            }
            SchemaError::ContextOrShapeNotRecord => {
                write!(
                    f,
                    "An entity shape or action context is declared with a type other than `Record`"
                )
            }
            SchemaError::ActionEntityAttributeEmptySet => {
                write!(f, "An action entity has an attribute that is an empty set")
            }
            SchemaError::ActionEntityAttributeUnsupportedType => {
                write!(
                    f,
                    "An action entity has attribute with unsupported type: (escaped expression, entity or extension)"
                )
            }
            SchemaError::MalformedLongBounds => {
                write!(
                    f,
                    "Malformed bounds information on a declaration of type `Long`."
                )
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
