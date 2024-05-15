/*
 * Copyright Cedar Contributors
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
    transitive_closure,
};
use itertools::Itertools;
use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

use crate::human_schema;

#[derive(Debug, Error, Diagnostic)]
pub enum HumanSchemaError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    Core(#[from] SchemaError),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    #[diagnostic(transparent)]
    Parsing(#[from] HumanSyntaxParseError),
}

/// Error parsing a human-syntax schema
#[derive(Debug, Error)]
#[error("error parsing schema: {errs}")]
pub struct HumanSyntaxParseError {
    /// Underlying parse error(s)
    errs: human_schema::parser::HumanSyntaxParseErrors,
    /// Did the schema look like it was intended to be JSON format instead of
    /// human?
    suspect_json_format: bool,
}

impl Diagnostic for HumanSyntaxParseError {
    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        let suspect_json_help = if self.suspect_json_format {
            Some(Box::new("this API was expecting a schema in the Cedar schema format; did you mean to use a different function, which expects a JSON-format Cedar schema"))
        } else {
            None
        };
        match (suspect_json_help, self.errs.help()) {
            (Some(json), Some(inner)) => Some(Box::new(format!("{inner}\n{json}"))),
            (Some(h), None) => Some(h),
            (None, Some(h)) => Some(h),
            (None, None) => None,
        }
    }

    // Everything else is forwarded to `errs`

    fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.errs.code()
    }
    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        self.errs.labels()
    }
    fn severity(&self) -> Option<miette::Severity> {
        self.errs.severity()
    }
    fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.errs.url()
    }
    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        self.errs.source_code()
    }
    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.errs.diagnostic_source()
    }
    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        self.errs.related()
    }
}

impl HumanSyntaxParseError {
    /// `errs`: the `human_schema::parser::HumanSyntaxParseErrors` that were thrown
    ///
    /// `src`: the human-syntax text that we were trying to parse
    pub(crate) fn new(errs: human_schema::parser::HumanSyntaxParseErrors, src: &str) -> Self {
        // let's see what the first non-whitespace character is
        let suspect_json_format = match src.trim_start().chars().next() {
            None => false, // schema is empty or only whitespace; the problem is unlikely to be JSON vs human format
            Some('{') => true, // yes, this looks like it was intended to be a JSON schema
            Some(_) => false, // any character other than '{', not likely it was intended to be a JSON schema
        };
        Self {
            errs,
            suspect_json_format,
        }
    }

    #[cfg(test)]
    pub(crate) fn inner(&self) -> &human_schema::parser::HumanSyntaxParseErrors {
        &self.errs
    }
}

#[derive(Debug, Diagnostic, Error)]
pub enum SchemaError {
    /// This error is thrown when `serde_json` fails to deserialize the JSON
    #[error(transparent)]
    #[diagnostic(transparent)]
    JsonDeserialization(#[from] JsonDeserializationError),
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
    UndeclaredEntityTypes(HashSet<Name>),
    /// Undeclared action(s) used in the `memberOf` field of an action.
    #[error("undeclared action(s): {0:?}")]
    #[diagnostic(help("any actions appearing in `memberOf` need to be declared in `actions`"))]
    UndeclaredActions(HashSet<SmolStr>),
    /// This error occurs in either of the following cases (see discussion on #477):
    ///     - undeclared common type(s) appearing in entity or context attributes
    ///     - common type(s) (declared or not) appearing in declarations of other common types
    #[error("undeclared common type(s), or common type(s) used in the declaration of another common type: {0:?}")]
    #[diagnostic(help("any common types used in entity or context attributes need to be declared in `commonTypes`, and currently, common types may not reference other common types"))]
    UndeclaredCommonTypes(HashSet<Name>),
    /// Duplicate specifications for an entity type. Argument is the name of
    /// the duplicate entity type.
    #[error("duplicate entity type `{0}`")]
    DuplicateEntityType(Name),
    /// Duplicate specifications for an action. Argument is the name of the
    /// duplicate action.
    #[error("duplicate action `{0}`")]
    DuplicateAction(SmolStr),
    /// Duplicate specification for a reusable type declaration.
    #[error("duplicate common type `{0}`")]
    DuplicateCommonType(Name),
    /// Cycle in the schema's action hierarchy.
    #[error("cycle in action hierarchy containing `{0}`")]
    CycleInActionHierarchy(EntityUID),
    /// Cycle in the schema's common type declarations.
    #[error("cycle in common type references containing `{0}`")]
    CycleInCommonTypeReferences(Name),
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
    UnsupportedActionAttribute(EntityUID, SmolStr),
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
            transitive_closure::TcError::HasCycle(err) => {
                SchemaError::CycleInActionHierarchy(err.vertex_with_loop().clone())
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, SchemaError>;

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

/// This error is thrown when `serde_json` fails to deserialize the JSON
#[derive(Debug, Error)]
#[error("failed to parse schema in JSON format: {err}")]
pub struct JsonDeserializationError {
    /// Error thrown by the `serde_json` crate
    err: serde_json::Error,
    /// Did the schema look like it was intended to be human format instead of
    /// JSON?
    suspect_human_format: bool,
}

impl Diagnostic for JsonDeserializationError {
    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        if self.suspect_human_format {
            Some(Box::new("this API was expecting a schema in the JSON format; did you mean to use a different function, which expects the Cedar schema format?"))
        } else {
            None
        }
    }
}

impl JsonDeserializationError {
    /// `err`: the `serde_json::Error` that was thrown
    ///
    /// `src`: the JSON that we were trying to deserialize (if available in string form)
    pub(crate) fn new(err: serde_json::Error, src: Option<&str>) -> Self {
        match src {
            None => Self {
                err,
                suspect_human_format: false,
            },
            Some(src) => {
                // let's see what the first non-whitespace character is
                let suspect_human_format = match src.trim_start().chars().next() {
                    None => false, // schema is empty or only whitespace; the problem is unlikely to be JSON vs human format
                    Some('{') => false, // yes, this looks like it was intended to be a JSON schema
                    Some(_) => true, // any character other than '{', we suspect it might be a human-format schema
                };
                Self {
                    err,
                    suspect_human_format,
                }
            }
        }
    }
}
