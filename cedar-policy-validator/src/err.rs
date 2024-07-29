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

use cedar_policy_core::{
    ast::{EntityUID, ReservedNameError},
    transitive_closure,
};
use miette::Diagnostic;
use thiserror::Error;

use crate::human_schema;

/// Error creating a schema from human syntax
#[derive(Debug, Error, Diagnostic)]
pub enum HumanSchemaError {
    /// Errors with the schema content
    #[error(transparent)]
    #[diagnostic(transparent)]
    Schema(#[from] SchemaError),
    /// IO error
    #[error(transparent)]
    IO(#[from] std::io::Error),
    /// Parse error
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

/// Error when constructing a schema
//
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Diagnostic, Error)]
pub enum SchemaError {
    /// Error thrown by the `serde_json` crate during serialization
    #[error(transparent)]
    #[diagnostic(transparent)]
    JsonSerialization(#[from] schema_errors::JsonSerializationError),
    /// This error is thrown when `serde_json` fails to deserialize the JSON
    #[error(transparent)]
    #[diagnostic(transparent)]
    JsonDeserialization(#[from] schema_errors::JsonDeserializationError),
    /// Errors occurring while computing or enforcing transitive closure on
    /// action hierarchy.
    #[error(transparent)]
    #[diagnostic(transparent)]
    ActionTransitiveClosure(#[from] schema_errors::ActionTransitiveClosureError),
    /// Errors occurring while computing or enforcing transitive closure on
    /// entity type hierarchy.
    #[error(transparent)]
    #[diagnostic(transparent)]
    EntityTypeTransitiveClosure(#[from] schema_errors::EntityTypeTransitiveClosureError),
    /// Error generated when processing a schema file that uses unsupported features
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnsupportedFeature(#[from] schema_errors::UnsupportedFeatureError),
    /// Undeclared entity type(s) used in the `memberOf` field of an entity
    /// type, the `appliesTo` fields of an action, or an attribute type in a
    /// context or entity attribute record. Entity types in the error message
    /// are fully qualified, including any implicit or explicit namespaces.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UndeclaredEntityTypes(#[from] schema_errors::UndeclaredEntityTypesError),
    /// Undeclared action(s) used in the `memberOf` field of an action.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UndeclaredActions(#[from] schema_errors::UndeclaredActionsError),
    /// This error occurs when an undeclared common type appears in entity or context
    /// attributes.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UndeclaredCommonTypes(#[from] schema_errors::UndeclaredCommonTypesError),
    /// Duplicate specifications for an entity type. Argument is the name of
    /// the duplicate entity type.
    #[error(transparent)]
    #[diagnostic(transparent)]
    DuplicateEntityType(#[from] schema_errors::DuplicateEntityTypeError),
    /// Duplicate specifications for an action. Argument is the name of the
    /// duplicate action.
    #[error(transparent)]
    #[diagnostic(transparent)]
    DuplicateAction(#[from] schema_errors::DuplicateActionError),
    /// Duplicate specification for a reusable type declaration.
    #[error(transparent)]
    #[diagnostic(transparent)]
    DuplicateCommonType(#[from] schema_errors::DuplicateCommonTypeError),
    /// Cycle in the schema's action hierarchy.
    #[error(transparent)]
    #[diagnostic(transparent)]
    CycleInActionHierarchy(#[from] schema_errors::CycleInActionHierarchyError),
    /// Cycle in the schema's common type declarations.
    #[error(transparent)]
    #[diagnostic(transparent)]
    CycleInCommonTypeReferences(#[from] schema_errors::CycleInCommonTypeReferencesError),
    /// The schema file included an entity type `Action` in the entity type
    /// list. The `Action` entity type is always implicitly declared, and it
    /// cannot currently have attributes or be in any groups, so there is no
    /// purposes in adding an explicit entry.
    #[error(transparent)]
    #[diagnostic(transparent)]
    ActionEntityTypeDeclared(#[from] schema_errors::ActionEntityTypeDeclaredError),
    /// `context` or `shape` fields are not records
    #[error(transparent)]
    #[diagnostic(transparent)]
    ContextOrShapeNotRecord(#[from] schema_errors::ContextOrShapeNotRecordError),
    /// An action entity (transitively) has an attribute that is an empty set.
    /// The validator cannot assign a type to an empty set.
    /// This error variant should only be used when `PermitAttributes` is enabled.
    #[error(transparent)]
    #[diagnostic(transparent)]
    ActionAttributesContainEmptySet(#[from] schema_errors::ActionAttributesContainEmptySetError),
    /// An action entity (transitively) has an attribute of unsupported type (`ExprEscape`, `EntityEscape` or `ExtnEscape`).
    /// This error variant should only be used when `PermitAttributes` is enabled.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnsupportedActionAttribute(#[from] schema_errors::UnsupportedActionAttributeError),
    /// Error when evaluating an action attribute
    #[error(transparent)]
    #[diagnostic(transparent)]
    ActionAttrEval(#[from] schema_errors::ActionAttrEvalError),
    /// Error thrown when the schema contains the `__expr` escape.
    /// Support for this escape form has been dropped.
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExprEscapeUsed(#[from] schema_errors::ExprEscapeUsedError),
    /// The schema used an extension type that the validator doesn't know about.
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnknownExtensionType(schema_errors::UnknownExtensionTypeError),
    /// The schema used a reserved namespace or typename (as of this writing, just `__cedar`).
    #[error(transparent)]
    #[diagnostic(transparent)]
    ReservedName(#[from] ReservedNameError),
    /// Common type names conflict with primitive types.
    #[error(transparent)]
    #[diagnostic(transparent)]
    CommonTypeNameConflict(#[from] schema_errors::CommonTypeNameConflictError),
}

impl From<transitive_closure::TcError<EntityUID>> for SchemaError {
    fn from(e: transitive_closure::TcError<EntityUID>) -> Self {
        // we use code in transitive_closure to check for cycles in the action
        // hierarchy, but in case of an error we want to report the more descriptive
        // CycleInActionHierarchy instead of ActionTransitiveClosureError
        match e {
            transitive_closure::TcError::MissingTcEdge { .. } => {
                SchemaError::ActionTransitiveClosure(Box::new(e).into())
            }
            transitive_closure::TcError::HasCycle(err) => {
                schema_errors::CycleInActionHierarchyError(err.vertex_with_loop().clone()).into()
            }
        }
    }
}

/// Convenience alias
pub type Result<T> = std::result::Result<T, SchemaError>;

/// Error subtypes for [`SchemaError`]
pub mod schema_errors {
    use std::{collections::BTreeSet, fmt::Display};

    use cedar_policy_core::{
        ast::{
            EntityAttrEvaluationError, EntityType, EntityUID, Name, UncheckedName, UnreservedId,
        },
        parser::join_with_conjunction,
        transitive_closure,
    };
    use itertools::Itertools;
    use miette::Diagnostic;
    use smol_str::SmolStr;
    use thiserror::Error;

    /// JSON deserialization error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[error(transparent)]
    pub struct JsonSerializationError(#[from] pub(crate) serde_json::Error);

    /// Transitive closure of action hierarchy computation or enforcement error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[error("transitive closure computation/enforcement error on action hierarchy")]
    #[diagnostic(transparent)]
    pub struct ActionTransitiveClosureError(
        #[from] pub(crate) Box<transitive_closure::TcError<EntityUID>>,
    );

    /// Transitive closure of entity type hierarchy computation or enforcement error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[error("transitive closure computation/enforcement error on entity type hierarchy")]
    #[diagnostic(transparent)]
    pub struct EntityTypeTransitiveClosureError(
        #[from] pub(crate) Box<transitive_closure::TcError<EntityType>>,
    );

    /// Undeclared entity types error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[diagnostic(help(
        "any entity types appearing anywhere in a schema need to be declared in `entityTypes`"
    ))]
    pub struct UndeclaredEntityTypesError(pub(crate) BTreeSet<EntityType>);

    impl Display for UndeclaredEntityTypesError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            if self.0.len() == 1 {
                write!(f, "undeclared entity type: ")?;
            } else {
                write!(f, "undeclared entity types: ")?;
            }
            join_with_conjunction(f, "and", self.0.iter(), |f, s| s.fmt(f))
        }
    }

    /// Undeclared actions error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[diagnostic(help("any actions appearing in `memberOf` need to be declared in `actions`"))]
    pub struct UndeclaredActionsError(pub(crate) BTreeSet<SmolStr>);

    impl Display for UndeclaredActionsError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            if self.0.len() == 1 {
                write!(f, "undeclared action: ")?;
            } else {
                write!(f, "undeclared actions: ")?;
            }
            join_with_conjunction(f, "and", self.0.iter(), |f, s| s.fmt(f))
        }
    }

    /// Undeclared common types error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[error("undeclared common type: {0}")]
    #[diagnostic(help("any common types used in entity or context attributes need to be declared in `commonTypes`"))]
    pub struct UndeclaredCommonTypesError(pub(crate) Name);

    /// Duplicate entity type error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[error("duplicate entity type `{0}`")]
    pub struct DuplicateEntityTypeError(pub(crate) EntityType);

    /// Duplicate action error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[error("duplicate action `{0}`")]
    pub struct DuplicateActionError(pub(crate) SmolStr);

    /// Duplicate common type error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[error("duplicate common type type `{0}`")]
    pub struct DuplicateCommonTypeError(pub(crate) UncheckedName);

    /// Cycle in action hierarchy error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[error("cycle in action hierarchy containing `{0}`")]
    pub struct CycleInActionHierarchyError(pub(crate) EntityUID);

    /// Cycle in common type hierarchy error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[error("cycle in common type references containing `{0}`")]
    pub struct CycleInCommonTypeReferencesError(pub(crate) Name);

    /// Action declared in `entityType` list error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Clone, Diagnostic, Error)]
    #[error("entity type `Action` declared in `entityTypes` list")]
    pub struct ActionEntityTypeDeclaredError {}

    /// Context or entity type shape not declared as record error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[error("{0} is declared with a type other than `Record`")]
    #[diagnostic(help("{}", match .0 {
    ContextOrShape::ActionContext(_) => "action contexts must have type `Record`",
    ContextOrShape::EntityTypeShape(_) => "entity type shapes must have type `Record`",
}))]
    pub struct ContextOrShapeNotRecordError(pub(crate) ContextOrShape);

    /// Action attributes contain empty set error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[error("action `{0}` has an attribute that is an empty set")]
    #[diagnostic(help(
        "actions are not currently allowed to have attributes whose value is an empty set"
    ))]
    pub struct ActionAttributesContainEmptySetError(pub(crate) EntityUID);

    /// Unsupported action attribute error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[error("action `{0}` has an attribute with unsupported JSON representation: {1}")]
    pub struct UnsupportedActionAttributeError(pub(crate) EntityUID, pub(crate) SmolStr);

    /// Unsupported `__expr` escape error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Clone, Diagnostic, Error)]
    #[error("the `__expr` escape is no longer supported")]
    #[diagnostic(help("to create an entity reference, use `__entity`; to create an extension value, use `__extn`; and for all other values, use JSON directly"))]
    pub struct ExprEscapeUsedError {}

    /// Action attribute evaluation error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[error(transparent)]
    #[diagnostic(transparent)]
    pub struct ActionAttrEvalError(#[from] pub(crate) EntityAttrEvaluationError);

    /// Unsupported feature error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[error("unsupported feature used in schema")]
    #[diagnostic(transparent)]
    pub struct UnsupportedFeatureError(#[from] pub(crate) UnsupportedFeature);

    #[derive(Debug)]
    pub(crate) enum ContextOrShape {
        ActionContext(EntityUID),
        EntityTypeShape(EntityType),
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
    pub(crate) enum UnsupportedFeature {
        #[error("records and entities with `additionalAttributes` are experimental, but the experimental `partial-validate` feature is not enabled")]
        OpenRecordsAndEntities,
        // Action attributes are allowed if `ActionBehavior` is `PermitAttributes`
        #[error("action declared with attributes: [{}]", .0.iter().join(", "))]
        ActionAttributes(Vec<String>),
    }

    /// This error is thrown when `serde_json` fails to deserialize the JSON
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Error)]
    #[error("{err}")]
    pub struct JsonDeserializationError {
        /// Error thrown by the `serde_json` crate
        err: serde_json::Error,
        /// Possible fix for the error
        advice: Option<JsonDeserializationAdvice>,
    }

    impl Diagnostic for JsonDeserializationError {
        fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            self.advice
                .as_ref()
                .map(|h| Box::new(h) as Box<dyn Display>)
        }
    }

    #[derive(Debug, Error)]
    enum JsonDeserializationAdvice {
        #[error("this API was expecting a schema in the JSON format; did you mean to use a different function, which expects the Cedar schema format?")]
        HumanFormat,
        #[error("JSON formatted schema must specify a namespace. If you want to use the empty namespace, explicitly specify it with `{{ \"\": {{..}} }}`")]
        MissingNamespace,
    }

    impl JsonDeserializationError {
        /// `err`: the `serde_json::Error` that was thrown
        ///
        /// `src`: the JSON that we were trying to deserialize (if available in string form)
        pub(crate) fn new(err: serde_json::Error, src: Option<&str>) -> Self {
            match src {
                None => Self { err, advice: None },
                Some(src) => {
                    // let's see what the first non-whitespace character is
                    let advice = match src.trim_start().chars().next() {
                        None => None, // schema is empty or only whitespace; the problem is unlikely to be JSON vs human format
                        Some('{') => {
                            // This looks like it was intended to be a JSON schema. Check fields of top level JSON object to see
                            // if it looks like it's missing a namespace.
                            if let Ok(serde_json::Value::Object(obj)) =
                                serde_json::from_str::<serde_json::Value>(src)
                            {
                                if obj.contains_key("entityTypes")
                                    || obj.contains_key("actions")
                                    || obj.contains_key("commonTypes")
                                {
                                    // These keys are expected inside a namespace, so it's likely the user forgot to specify a
                                    // namespace if they're at the top level of the schema json object.
                                    Some(JsonDeserializationAdvice::MissingNamespace)
                                } else {
                                    // Probably something wrong inside a namespace definition.
                                    None
                                }
                            } else {
                                // Invalid JSON
                                None
                            }
                        }
                        Some(_) => Some(JsonDeserializationAdvice::HumanFormat), // any character other than '{', we suspect it might be a human-format schema
                    };
                    Self { err, advice }
                }
            }
        }
    }

    /// Unknown extension type error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Error, Debug)]
    #[error("unknown extension type `{actual}`")]
    pub struct UnknownExtensionTypeError {
        pub(crate) actual: Name,
        pub(crate) suggested_replacement: Option<String>,
    }

    impl Diagnostic for UnknownExtensionTypeError {
        fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            self.suggested_replacement.as_ref().map(|suggestion| {
                Box::new(format!("did you mean `{suggestion}`?")) as Box<dyn Display>
            })
        }
    }

    /// This error is thrown when a common type name conflicts with a primitive
    /// type
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Error, Debug, Diagnostic)]
    #[error("Common type name `{0}` conflicts with primitive type")]
    pub struct CommonTypeNameConflictError(pub(crate) UnreservedId);
}
