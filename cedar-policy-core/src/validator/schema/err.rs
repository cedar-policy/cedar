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

use crate::{
    ast::{EntityUID, ReservedNameError},
    transitive_closure,
};
use itertools::{Either, Itertools};
use miette::Diagnostic;
use nonempty::NonEmpty;
use thiserror::Error;

use crate::validator::cedar_schema;

/// Error creating a schema from the Cedar syntax
#[derive(Debug, Error, Diagnostic)]
pub enum CedarSchemaError {
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
    Parsing(#[from] CedarSchemaParseError),
}

/// Error parsing a Cedar-syntax schema
// WARNING: this type is publicly exported from `cedar-policy`
#[derive(Debug, Error)]
#[error("error parsing schema: {errs}")]
pub struct CedarSchemaParseError {
    /// Underlying parse error(s)
    errs: cedar_schema::parser::CedarSchemaParseErrors,
    /// Did the schema look like it was intended to be JSON format instead of
    /// Cedar?
    suspect_json_format: bool,
}

impl Diagnostic for CedarSchemaParseError {
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

impl CedarSchemaParseError {
    /// `errs`: the `cedar_schema::parser::CedarSyntaxParseErrors` that were thrown
    ///
    /// `src`: the Cedar-syntax text that we were trying to parse
    pub(crate) fn new(errs: cedar_schema::parser::CedarSchemaParseErrors, src: &str) -> Self {
        // let's see what the first non-whitespace character is
        let suspect_json_format = match src.trim_start().chars().next() {
            None => false, // schema is empty or only whitespace; the problem is unlikely to be JSON vs Cedar format
            Some('{') => true, // yes, this looks like it was intended to be a JSON schema
            Some(_) => false, // any character other than '{', not likely it was intended to be a JSON schema
        };
        Self {
            errs,
            suspect_json_format,
        }
    }

    /// Did the schema look like it was JSON data?
    /// If so, it was probably intended to be parsed as the JSON schema format.
    /// In that case, the reported errors are probably not super helpful.
    /// (This check is provided on a best-effort basis)
    pub fn suspect_json_format(&self) -> bool {
        self.suspect_json_format
    }

    /// Get the errors that were encountered while parsing
    pub fn errors(&self) -> &cedar_schema::parser::CedarSchemaParseErrors {
        &self.errs
    }
}

/// Error when constructing a schema
//
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Diagnostic, Error)]
#[non_exhaustive]
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
    /// This error occurs when we cannot resolve a typename (because it refers
    /// to an entity type or common type that was not defined).
    #[error(transparent)]
    #[diagnostic(transparent)]
    TypeNotDefined(#[from] schema_errors::TypeNotDefinedError),
    /// This error occurs when we cannot resolve an action name used in the
    /// `memberOf` field of an action (because it refers to an action that was
    /// not defined).
    #[error(transparent)]
    #[diagnostic(transparent)]
    ActionNotDefined(#[from] schema_errors::ActionNotDefinedError),
    /// Entity/common type shadowing error. Some shadowing relationships are not
    /// allowed for clarity reasons; see
    /// [RFC 70](https://github.com/cedar-policy/rfcs/blob/main/text/0070-disallow-empty-namespace-shadowing.md).
    #[error(transparent)]
    #[diagnostic(transparent)]
    TypeShadowing(#[from] schema_errors::TypeShadowingError),
    /// Action shadowing error. Some shadowing relationships are not
    /// allowed for clarity reasons; see
    /// [RFC 70](https://github.com/cedar-policy/rfcs/blob/main/text/0070-disallow-empty-namespace-shadowing.md).
    #[error(transparent)]
    #[diagnostic(transparent)]
    ActionShadowing(#[from] schema_errors::ActionShadowingError),
    /// Duplicate specifications for an entity type
    #[error(transparent)]
    #[diagnostic(transparent)]
    DuplicateEntityType(#[from] schema_errors::DuplicateEntityTypeError),
    /// Duplicate specifications for an action
    #[error(transparent)]
    #[diagnostic(transparent)]
    DuplicateAction(#[from] schema_errors::DuplicateActionError),
    /// Duplicate specification for a common type declaration
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
    /// Could not find a definition for a common type, at a point in the code
    /// where internal invariants should guarantee that we would find one.
    #[error(transparent)]
    #[diagnostic(transparent)]
    CommonTypeInvariantViolation(#[from] schema_errors::CommonTypeInvariantViolationError),
    /// Could not find a definition for an action, at a point in the code where
    /// internal invariants should guarantee that we would find one.
    #[error(transparent)]
    #[diagnostic(transparent)]
    ActionInvariantViolation(#[from] schema_errors::ActionInvariantViolationError),
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
                schema_errors::CycleInActionHierarchyError {
                    uid: err.vertex_with_loop().clone(),
                }
                .into()
            }
        }
    }
}

impl SchemaError {
    /// Given one or more `SchemaError`, collect them into a single `SchemaError`.
    /// Due to current structures, some errors may have to be dropped in some cases.
    pub fn join_nonempty(errs: NonEmpty<SchemaError>) -> SchemaError {
        // if we have any `TypeNotDefinedError`s, we can report all of those at once (but have to drop the others).
        // Same for `ActionNotDefinedError`s.
        // Any other error, we can just report the first one and have to drop the others.
        let (type_ndef_errors, non_type_ndef_errors): (Vec<_>, Vec<_>) =
            errs.into_iter().partition_map(|e| match e {
                SchemaError::TypeNotDefined(e) => Either::Left(e),
                _ => Either::Right(e),
            });
        if let Some(errs) = NonEmpty::from_vec(type_ndef_errors) {
            schema_errors::TypeNotDefinedError::join_nonempty(errs).into()
        } else {
            let (action_ndef_errors, other_errors): (Vec<_>, Vec<_>) =
                non_type_ndef_errors.into_iter().partition_map(|e| match e {
                    SchemaError::ActionNotDefined(e) => Either::Left(e),
                    _ => Either::Right(e),
                });
            if let Some(errs) = NonEmpty::from_vec(action_ndef_errors) {
                schema_errors::ActionNotDefinedError::join_nonempty(errs).into()
            } else {
                // We partitioned a `NonEmpty` (`errs`) into what we now know is an empty vector
                // (`type_ndef_errors`) and `non_type_ndef_errors`, so `non_type_ndef_errors` cannot
                // be empty. Then we partitioned `non_type_ndef_errors` into what we now know is an
                // empty vector (`action_ndef_errors`) and `other_errors`, so `other_errors` cannot
                // be empty.
                // PANIC SAFETY: see comments immediately above
                #[allow(clippy::expect_used)]
                other_errors.into_iter().next().expect("cannot be empty")
            }
        }
    }
}

impl From<NonEmpty<SchemaError>> for SchemaError {
    fn from(errs: NonEmpty<SchemaError>) -> Self {
        Self::join_nonempty(errs)
    }
}

impl From<NonEmpty<schema_errors::ActionNotDefinedError>> for SchemaError {
    fn from(errs: NonEmpty<schema_errors::ActionNotDefinedError>) -> Self {
        Self::ActionNotDefined(schema_errors::ActionNotDefinedError::join_nonempty(errs))
    }
}

impl From<NonEmpty<schema_errors::TypeNotDefinedError>> for SchemaError {
    fn from(errs: NonEmpty<schema_errors::TypeNotDefinedError>) -> Self {
        Self::TypeNotDefined(schema_errors::TypeNotDefinedError::join_nonempty(errs))
    }
}

/// Convenience alias
pub type Result<T> = std::result::Result<T, SchemaError>;

/// Error subtypes for [`SchemaError`]
pub mod schema_errors {
    use std::fmt::Display;

    use crate::ast::{EntityAttrEvaluationError, EntityType, EntityUID, InternalName, Name};
    use crate::parser::{join_with_conjunction, Loc};
    use crate::{
        impl_diagnostic_from_method_on_field, impl_diagnostic_from_method_on_nonempty_field,
        transitive_closure,
    };
    use itertools::Itertools;
    use miette::Diagnostic;
    use nonempty::NonEmpty;
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
    #[derive(Debug, Error)]
    pub struct UndeclaredEntityTypesError {
        /// Entity type(s) which were not declared
        pub(crate) types: NonEmpty<EntityType>,
    }

    impl Display for UndeclaredEntityTypesError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            if self.types.len() == 1 {
                write!(f, "undeclared entity type: ")?;
            } else {
                write!(f, "undeclared entity types: ")?;
            }
            join_with_conjunction(f, "and", self.types.iter().sorted_unstable(), |f, s| {
                s.fmt(f)
            })
        }
    }

    impl Diagnostic for UndeclaredEntityTypesError {
        fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
            Some(Box::new("any entity types appearing anywhere in a schema need to be declared in `entityTypes`"))
        }

        impl_diagnostic_from_method_on_nonempty_field!(types, loc);
    }

    /// Type resolution error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Error)]
    #[error("failed to resolve type{}: {}", if .undefined_types.len() > 1 { "s" } else { "" }, .undefined_types.iter().map(crate::validator::ConditionalName::raw).join(", "))]
    pub struct TypeNotDefinedError {
        /// Names of type(s) which were not defined
        pub(crate) undefined_types: NonEmpty<crate::validator::ConditionalName>,
    }

    impl Diagnostic for TypeNotDefinedError {
        fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
            // we choose to give only the help for the first failed-to-resolve name, because otherwise the help message would be too cluttered and complicated
            Some(Box::new(
                self.undefined_types.first().resolution_failure_help(),
            ))
        }

        impl_diagnostic_from_method_on_nonempty_field!(undefined_types, loc);
    }

    impl TypeNotDefinedError {
        /// Combine all the errors into a single [`TypeNotDefinedError`].
        ///
        /// This cannot fail, because `NonEmpty` guarantees there is at least
        /// one error to join.
        pub(crate) fn join_nonempty(errs: NonEmpty<TypeNotDefinedError>) -> Self {
            Self {
                undefined_types: errs.flat_map(|err| err.undefined_types),
            }
        }
    }

    impl From<NonEmpty<TypeNotDefinedError>> for TypeNotDefinedError {
        fn from(value: NonEmpty<TypeNotDefinedError>) -> Self {
            Self::join_nonempty(value)
        }
    }

    /// Action resolution error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Diagnostic, Error)]
    #[diagnostic(help("any actions appearing as parents need to be declared as actions"))]
    pub struct ActionNotDefinedError(
        pub(crate)  NonEmpty<
            crate::validator::json_schema::ActionEntityUID<crate::validator::ConditionalName>,
        >,
    );

    impl ActionNotDefinedError {
        /// Combine all the errors into a single [`ActionNotDefinedError`].
        ///
        /// This cannot fail, because `NonEmpty` guarantees there is at least
        /// one error to join.
        pub(crate) fn join_nonempty(errs: NonEmpty<ActionNotDefinedError>) -> Self {
            Self(errs.flat_map(|err| err.0))
        }
    }

    impl From<NonEmpty<ActionNotDefinedError>> for ActionNotDefinedError {
        fn from(value: NonEmpty<ActionNotDefinedError>) -> Self {
            Self::join_nonempty(value)
        }
    }

    impl Display for ActionNotDefinedError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            if self.0.len() == 1 {
                write!(f, "undeclared action: ")?;
            } else {
                write!(f, "undeclared actions: ")?;
            }
            join_with_conjunction(
                f,
                "and",
                self.0.iter().map(|aeuid| aeuid.as_raw()),
                |f, s| s.fmt(f),
            )
        }
    }

    /// Entity/common type shadowing error. Some shadowing relationships are not
    /// allowed for clarity reasons; see
    /// [RFC 70](https://github.com/cedar-policy/rfcs/blob/main/text/0070-disallow-empty-namespace-shadowing.md).
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Error)]
    #[error(
        "definition of `{shadowing_def}` illegally shadows the existing definition of `{shadowed_def}`"
    )]
    pub struct TypeShadowingError {
        /// Definition that is being shadowed illegally
        pub(crate) shadowed_def: InternalName,
        /// Definition that is responsible for shadowing it illegally
        pub(crate) shadowing_def: InternalName,
    }

    impl Diagnostic for TypeShadowingError {
        fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
            Some(Box::new(format!(
                "try renaming one of the definitions, or moving `{}` to a different namespace",
                self.shadowed_def
            )))
        }

        // we use the location of the `shadowing_def` as the location of the error
        // possible future improvement: provide two underlines
        impl_diagnostic_from_method_on_field!(shadowing_def, loc);
    }

    /// Action shadowing error. Some shadowing relationships are not allowed for
    /// clarity reasons; see
    /// [RFC 70](https://github.com/cedar-policy/rfcs/blob/main/text/0070-disallow-empty-namespace-shadowing.md).
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Error)]
    #[error(
        "definition of `{shadowing_def}` illegally shadows the existing definition of `{shadowed_def}`"
    )]
    pub struct ActionShadowingError {
        /// Definition that is being shadowed illegally
        pub(crate) shadowed_def: EntityUID,
        /// Definition that is responsible for shadowing it illegally
        pub(crate) shadowing_def: EntityUID,
    }

    impl Diagnostic for ActionShadowingError {
        fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
            Some(Box::new(format!(
                "try renaming one of the actions, or moving `{}` to a different namespace",
                self.shadowed_def
            )))
        }

        // we use the location of the `shadowing_def` as the location of the error
        // possible future improvement: provide two underlines
        impl_diagnostic_from_method_on_field!(shadowing_def, loc);
    }

    /// Duplicate entity type error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Error)]
    #[error("duplicate entity type `{ty}`")]
    pub struct DuplicateEntityTypeError {
        pub(crate) ty: EntityType,
    }

    impl Diagnostic for DuplicateEntityTypeError {
        impl_diagnostic_from_method_on_field!(ty, loc);
    }

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
    #[derive(Debug, Error)]
    #[error("duplicate common type `{ty}`")]
    pub struct DuplicateCommonTypeError {
        pub(crate) ty: InternalName,
    }

    impl Diagnostic for DuplicateCommonTypeError {
        impl_diagnostic_from_method_on_field!(ty, loc);
    }

    /// Cycle in action hierarchy error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Error)]
    #[error("cycle in action hierarchy containing `{uid}`")]
    pub struct CycleInActionHierarchyError {
        pub(crate) uid: EntityUID,
    }

    impl Diagnostic for CycleInActionHierarchyError {
        impl_diagnostic_from_method_on_field!(uid, loc);
    }

    /// Cycle in common type hierarchy error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Error)]
    #[error("cycle in common type references containing `{ty}`")]
    pub struct CycleInCommonTypeReferencesError {
        pub(crate) ty: InternalName,
    }

    impl Diagnostic for CycleInCommonTypeReferencesError {
        impl_diagnostic_from_method_on_field!(ty, loc);
    }

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
    #[derive(Debug, Error)]
    #[error("{ctx_or_shape} is declared with a type other than `Record`")]
    pub struct ContextOrShapeNotRecordError {
        pub(crate) ctx_or_shape: ContextOrShape,
    }

    impl Diagnostic for ContextOrShapeNotRecordError {
        fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
            match &self.ctx_or_shape {
                ContextOrShape::ActionContext(_) => {
                    Some(Box::new("action contexts must have type `Record`"))
                }
                ContextOrShape::EntityTypeShape(_) => {
                    Some(Box::new("entity type shapes must have type `Record`"))
                }
            }
        }

        impl_diagnostic_from_method_on_field!(ctx_or_shape, loc);
    }

    /// Action attributes contain empty set error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Error)]
    #[error("action `{uid}` has an attribute that is an empty set")]
    pub struct ActionAttributesContainEmptySetError {
        pub(crate) uid: EntityUID,
    }

    impl Diagnostic for ActionAttributesContainEmptySetError {
        fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
            Some(Box::new(
                "actions are not currently allowed to have attributes whose value is an empty set",
            ))
        }

        impl_diagnostic_from_method_on_field!(uid, loc);
    }

    /// Unsupported action attribute error
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Error)]
    #[error("action `{uid}` has an attribute with unsupported JSON representation: {attr}")]
    pub struct UnsupportedActionAttributeError {
        pub(crate) uid: EntityUID,
        pub(crate) attr: SmolStr,
    }

    impl Diagnostic for UnsupportedActionAttributeError {
        impl_diagnostic_from_method_on_field!(uid, loc);
    }

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

    impl ContextOrShape {
        pub fn loc(&self) -> Option<&Loc> {
            match self {
                ContextOrShape::ActionContext(uid) => uid.loc(),
                ContextOrShape::EntityTypeShape(ty) => ty.loc(),
            }
        }
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
        CedarFormat,
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
                        None => None, // schema is empty or only whitespace; the problem is unlikely to be JSON vs Cedar format
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
                        Some(_) => Some(JsonDeserializationAdvice::CedarFormat), // any character other than '{', we suspect it might be a Cedar-format schema
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

        impl_diagnostic_from_method_on_field!(actual, loc);
    }

    /// Could not find a definition for a common type, at a point in the code
    /// where internal invariants should guarantee that we would find one.
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Error, Debug)]
    #[error("internal invariant violated: failed to find a common-type definition for {name}")]
    pub struct CommonTypeInvariantViolationError {
        /// Fully-qualified [`InternalName`] of the common type we failed to find a definition for
        pub(crate) name: InternalName,
    }

    impl Diagnostic for CommonTypeInvariantViolationError {
        fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
            Some(Box::new("please file an issue at <https://github.com/cedar-policy/cedar/issues> including the schema that caused this error"))
        }

        impl_diagnostic_from_method_on_field!(name, loc);
    }

    /// Could not find a definition for an action, at a point in the code where
    /// internal invariants should guarantee that we would find one.
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Error, Debug)]
    #[error("internal invariant violated: failed to find {} for {}", if .euids.len() > 1 { "action definitions" } else { "an action definition" }, .euids.iter().join(", "))]
    pub struct ActionInvariantViolationError {
        /// Fully-qualified [`EntityUID`]s of the action(s) we failed to find a definition for
        pub(crate) euids: NonEmpty<EntityUID>,
    }

    impl Diagnostic for ActionInvariantViolationError {
        fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
            Some(Box::new("please file an issue at <https://github.com/cedar-policy/cedar/issues> including the schema that caused this error"))
        }

        impl_diagnostic_from_method_on_nonempty_field!(euids, loc);
    }
}
