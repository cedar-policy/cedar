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

use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    iter::{once, Chain, Once},
    vec,
};

use cedar_policy_core::parser::{
    err::{expected_to_string, ExpectedTokenConfig},
    unescape::UnescapeError,
    Loc, Node,
};
use lalrpop_util as lalr;
use lazy_static::lazy_static;
use miette::{Diagnostic, LabeledSpan, SourceSpan};
use nonempty::NonEmpty;
use smol_str::{SmolStr, ToSmolStr};
use thiserror::Error;

use super::ast::PR;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UserError {
    #[error("An empty list was passed")]
    EmptyList,
    #[error("Invalid escape codes")]
    StringEscape(NonEmpty<UnescapeError>),
    #[error("`{0}` is a reserved identifier")]
    ReservedIdentifierUsed(SmolStr),
}

pub(crate) type RawLocation = usize;
pub(crate) type RawToken<'a> = lalr::lexer::Token<'a>;
pub(crate) type RawUserError = Node<UserError>;

pub(crate) type RawParseError<'a> = lalr::ParseError<RawLocation, RawToken<'a>, RawUserError>;
pub(crate) type RawErrorRecovery<'a> = lalr::ErrorRecovery<RawLocation, RawToken<'a>, RawUserError>;

type OwnedRawParseError = lalr::ParseError<RawLocation, String, RawUserError>;

lazy_static! {
    static ref SCHEMA_TOKEN_CONFIG: ExpectedTokenConfig = ExpectedTokenConfig {
        friendly_token_names: HashMap::from([
            ("IN", "`in`"),
            ("PRINCIPAL", "`principal`"),
            ("ACTION", "`action`"),
            ("RESOURCE", "`resource`"),
            ("CONTEXT", "`context`"),
            ("STRINGLIT", "string literal"),
            ("ENTITY", "`entity`"),
            ("NAMESPACE", "`namespace`"),
            ("TYPE", "`type`"),
            ("SET", "`Set`"),
            ("IDENTIFIER", "identifier"),
        ]),
        impossible_tokens: HashSet::new(),
        special_identifier_tokens: HashSet::from([
            "NAMESPACE",
            "ENTITY",
            "IN",
            "TYPE",
            "APPLIESTO",
            "PRINCIPAL",
            "ACTION",
            "RESOURCE",
            "CONTEXT",
            "ATTRIBUTES",
            "LONG",
            "STRING",
            "BOOL",
        ]),
        identifier_sentinel: "IDENTIFIER",
        first_set_identifier_tokens: HashSet::from(["SET"]),
        first_set_sentinel: "\"{\"",
    };
}

/// For errors during parsing
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// Error generated by lalrpop
    err: OwnedRawParseError,
}

impl From<RawParseError<'_>> for ParseError {
    fn from(err: RawParseError<'_>) -> Self {
        Self {
            err: err.map_token(|token| token.to_string()),
        }
    }
}

impl From<RawErrorRecovery<'_>> for ParseError {
    fn from(recovery: RawErrorRecovery<'_>) -> Self {
        recovery.error.into()
    }
}

impl ParseError {
    /// Extract a primary source span locating the error.
    pub fn primary_source_span(&self) -> SourceSpan {
        let Self { err } = self;
        match err {
            OwnedRawParseError::InvalidToken { location } => SourceSpan::from(*location),
            OwnedRawParseError::UnrecognizedEof { location, .. } => SourceSpan::from(*location),
            OwnedRawParseError::UnrecognizedToken {
                token: (token_start, _, token_end),
                ..
            } => SourceSpan::from(*token_start..*token_end),
            OwnedRawParseError::ExtraToken {
                token: (token_start, _, token_end),
            } => SourceSpan::from(*token_start..*token_end),
            OwnedRawParseError::User { error } => error.loc.span,
        }
    }
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { err } = self;
        match err {
            OwnedRawParseError::InvalidToken { .. } => write!(f, "invalid token"),
            OwnedRawParseError::UnrecognizedEof { .. } => write!(f, "unexpected end of input"),
            OwnedRawParseError::UnrecognizedToken {
                token: (_, token, _),
                ..
            } => write!(f, "unexpected token `{token}`"),
            OwnedRawParseError::ExtraToken {
                token: (_, token, _),
                ..
            } => write!(f, "extra token `{token}`"),
            OwnedRawParseError::User {
                error: Node { node, .. },
            } => write!(f, "{node}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl Diagnostic for ParseError {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        let primary_source_span = self.primary_source_span();
        let Self { err } = self;
        let labeled_span = match err {
            OwnedRawParseError::InvalidToken { .. } => LabeledSpan::underline(primary_source_span),
            OwnedRawParseError::UnrecognizedEof { expected, .. } => LabeledSpan::new_with_span(
                expected_to_string(expected, &SCHEMA_TOKEN_CONFIG),
                primary_source_span,
            ),
            OwnedRawParseError::UnrecognizedToken { expected, .. } => LabeledSpan::new_with_span(
                expected_to_string(expected, &SCHEMA_TOKEN_CONFIG),
                primary_source_span,
            ),
            OwnedRawParseError::ExtraToken { .. } => LabeledSpan::underline(primary_source_span),
            OwnedRawParseError::User { .. } => LabeledSpan::underline(primary_source_span),
        };
        Some(Box::new(std::iter::once(labeled_span)))
    }
}

/// Multiple parse errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseErrors(Box<NonEmpty<ParseError>>);

impl ParseErrors {
    pub fn new(first: ParseError, tail: impl IntoIterator<Item = ParseError>) -> Self {
        Self(Box::new(NonEmpty {
            head: first,
            tail: tail.into_iter().collect(),
        }))
    }

    pub fn from_iter(i: impl IntoIterator<Item = ParseError>) -> Option<Self> {
        let v = i.into_iter().collect::<Vec<_>>();
        Some(Self(Box::new(NonEmpty::from_vec(v)?)))
    }

    // Borrowed Iterator over reported errors
    pub fn iter(&self) -> impl Iterator<Item = &ParseError> {
        self.0.iter()
    }
}

impl Display for ParseErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.first())
    }
}

impl IntoIterator for ParseErrors {
    type Item = ParseError;
    type IntoIter = Chain<Once<ParseError>, vec::IntoIter<ParseError>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl std::error::Error for ParseErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(self.0.first())
    }
}

// Except for `.related()`, everything else is forwarded to the first error, if it is present.
// This ensures that users who only use `Display`, `.code()`, `.labels()` etc, still get rich
// information for the first error, even if they don't realize there are multiple errors here.
// See cedar-policy/cedar#326.
impl Diagnostic for ParseErrors {
    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        // the .related() on the first error, and then the 2nd through Nth errors (but not their own .related())
        let mut errs = self.iter().map(|err| err as &dyn Diagnostic);
        errs.next().map(move |first_err| match first_err.related() {
            Some(first_err_related) => Box::new(first_err_related.chain(errs)),
            None => Box::new(errs) as Box<dyn Iterator<Item = _>>,
        })
    }

    fn code<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Diagnostic::code(self.0.first())
    }

    fn severity(&self) -> Option<miette::Severity> {
        Diagnostic::severity(self.0.first())
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Diagnostic::help(self.0.first())
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Diagnostic::url(self.0.first())
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Diagnostic::source_code(self.0.first())
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        Diagnostic::labels(self.0.first())
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        Diagnostic::diagnostic_source(self.0.first())
    }
}

/// Collection of [`ToJsonSchemaError`]
/// This collection is guaranteed (by construction) to have at least one error.
// WARNING: This type is publicly exported from [`cedar-core`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToJsonSchemaErrors(NonEmpty<ToJsonSchemaError>);

impl ToJsonSchemaErrors {
    /// Constructor. Guaranteed to have at least one error by construction.
    pub fn new(errs: NonEmpty<ToJsonSchemaError>) -> Self {
        Self(errs)
    }

    /// (Borrowed) iterator
    pub fn iter(&self) -> impl Iterator<Item = &ToJsonSchemaError> {
        self.0.iter()
    }
}

impl IntoIterator for ToJsonSchemaErrors {
    type Item = ToJsonSchemaError;
    type IntoIter = <NonEmpty<ToJsonSchemaError> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl From<ToJsonSchemaError> for ToJsonSchemaErrors {
    fn from(value: ToJsonSchemaError) -> Self {
        Self(NonEmpty::singleton(value))
    }
}

impl Display for ToJsonSchemaErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.first()) // intentionally showing only the first error; see #326 for discussion on a similar error type
    }
}

impl std::error::Error for ToJsonSchemaErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.first().source()
    }

    #[allow(deprecated)]
    fn description(&self) -> &str {
        self.0.first().description()
    }

    #[allow(deprecated)]
    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.0.first().cause()
    }
}

// Except for `.related()`, everything else is forwarded to the first error, if it is present.
// This ensures that users who only use `Display`, `.code()`, `.labels()` etc, still get rich
// information for the first error, even if they don't realize there are multiple errors here.
// See #326 for discussion on a similar error type.
impl Diagnostic for ToJsonSchemaErrors {
    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        // the .related() on the first error, and then the 2nd through Nth errors (but not their own .related())
        let mut errs = self.iter().map(|err| err as &dyn Diagnostic);
        errs.next().map(move |first_err| match first_err.related() {
            Some(first_err_related) => Box::new(first_err_related.chain(errs)),
            None => Box::new(errs) as Box<dyn Iterator<Item = _>>,
        })
    }

    fn code<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.0.first().code()
    }

    fn severity(&self) -> Option<miette::Severity> {
        self.0.first().severity()
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.0.first().help()
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.0.first().url()
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        self.0.first().source_code()
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        self.0.first().labels()
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.0.first().diagnostic_source()
    }
}

// WARNING: This error type is publicly exported in `cedar-policy`, so it is part of the public interface
/// For errors during schema format conversion
#[derive(Clone, Debug, Error, PartialEq, Eq, Diagnostic)]
pub enum ToJsonSchemaError {
    /// Error raised when there are duplicate keys
    #[error(transparent)]
    #[diagnostic(transparent)]
    DuplicateKeys(DuplicateKeys),
    /// Error raised when there are duplicate declarations
    #[error(transparent)]
    #[diagnostic(transparent)]
    DuplicateDeclarations(DuplicateDeclarations),
    /// Error raised when an action has multiple context declarations
    #[error(transparent)]
    #[diagnostic(transparent)]
    DuplicateContext(DuplicateContext),
    /// Error raised when a `principal` or `resource` is declared twice
    #[error(transparent)]
    #[diagnostic(transparent)]
    DuplicatePrincipalOrResource(DuplicatePrincipalOrResource),
    /// Error raised when an action does not define either `principal` or `resource`
    #[error(transparent)]
    #[diagnostic(transparent)]
    NoPrincipalOrResource(NoPrincipalOrResource),
    /// Error raised when there are duplicate namespace IDs
    #[error(transparent)]
    #[diagnostic(transparent)]
    DuplicateNameSpaces(DuplicateNameSpace),
    /// Error raised when a type name is unknown
    #[error(transparent)]
    #[diagnostic(transparent)]
    UnknownTypeName(UnknownTypeName),
    /// Invalid type name
    #[error(transparent)]
    #[diagnostic(transparent)]
    ReservedName(ReservedName),
    /// Use reserved schema keywords
    #[error(transparent)]
    #[diagnostic(transparent)]
    ReservedSchemaKeyword(SchemaKeyword),
}

impl ToJsonSchemaError {
    pub(crate) fn duplicate_keys(key: impl ToSmolStr, loc1: Loc, loc2: Loc) -> Self {
        Self::DuplicateKeys(DuplicateKeys {
            key: key.to_smolstr(),
            loc1,
            loc2,
        })
    }

    pub(crate) fn duplicate_context(name: impl ToSmolStr, loc1: Loc, loc2: Loc) -> Self {
        Self::DuplicateContext(DuplicateContext {
            name: name.to_smolstr(),
            loc1,
            loc2,
        })
    }

    pub(crate) fn duplicate_decls(decl: impl ToSmolStr, loc1: Loc, loc2: Loc) -> Self {
        Self::DuplicateDeclarations(DuplicateDeclarations {
            decl: decl.to_smolstr(),
            loc1,
            loc2,
        })
    }

    pub(crate) fn duplicate_namespace(
        namespace_id: impl ToSmolStr,
        loc1: Option<Loc>,
        loc2: Option<Loc>,
    ) -> Self {
        Self::DuplicateNameSpaces(DuplicateNameSpace {
            namespace_id: namespace_id.to_smolstr(),
            loc1,
            loc2,
        })
    }

    pub(crate) fn duplicate_principal(name: impl ToSmolStr, loc1: Loc, loc2: Loc) -> Self {
        Self::DuplicatePrincipalOrResource(DuplicatePrincipalOrResource {
            name: name.to_smolstr(),
            kind: PR::Principal,
            loc1,
            loc2,
        })
    }

    pub(crate) fn duplicate_resource(name: impl ToSmolStr, loc1: Loc, loc2: Loc) -> Self {
        Self::DuplicatePrincipalOrResource(DuplicatePrincipalOrResource {
            name: name.to_smolstr(),
            kind: PR::Resource,
            loc1,
            loc2,
        })
    }

    pub(crate) fn no_principal(name: impl ToSmolStr, loc: Loc) -> Self {
        Self::NoPrincipalOrResource(NoPrincipalOrResource {
            kind: PR::Principal,
            name: name.to_smolstr(),
            loc,
        })
    }

    pub(crate) fn no_resource(name: impl ToSmolStr, loc: Loc) -> Self {
        Self::NoPrincipalOrResource(NoPrincipalOrResource {
            kind: PR::Resource,
            name: name.to_smolstr(),
            loc,
        })
    }

    pub(crate) fn reserved_name(name: impl ToSmolStr, loc: Loc) -> Self {
        Self::ReservedName(ReservedName {
            name: name.to_smolstr(),
            loc,
        })
    }

    pub(crate) fn reserved_keyword(keyword: impl ToSmolStr, loc: Loc) -> Self {
        Self::ReservedSchemaKeyword(SchemaKeyword {
            keyword: keyword.to_smolstr(),
            loc,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("this uses a reserved schema keyword: `{keyword}`")]
pub struct SchemaKeyword {
    keyword: SmolStr,
    loc: Loc,
}

impl Diagnostic for SchemaKeyword {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        underline_spans(once(self.loc.span))
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.loc.src as &dyn miette::SourceCode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("use of the reserved `__cedar` namespace")]
pub struct ReservedName {
    name: SmolStr,
    loc: Loc,
}

impl Diagnostic for ReservedName {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        underline_spans(once(self.loc.span))
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.loc.src as &dyn miette::SourceCode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unknown type name: `{name}`")]
pub struct UnknownTypeName {
    name: SmolStr,
    loc: Loc,
}

impl Diagnostic for UnknownTypeName {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        underline_spans(once(self.loc.span))
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.loc.src as &dyn miette::SourceCode)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        let msg = format!(
            "Did you mean to define `{}` as an entity type or common type?",
            self.name
        );
        Some(Box::new(msg))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("duplicate `{kind}` declaration in action `{name}`. Action may have at most one {kind} declaration")]
pub struct DuplicatePrincipalOrResource {
    name: SmolStr,
    kind: PR,
    loc1: Loc,
    loc2: Loc,
}

impl DuplicatePrincipalOrResource {
    #[cfg(test)]
    pub(crate) fn kind(&self) -> PR {
        self.kind
    }
}

impl Diagnostic for DuplicatePrincipalOrResource {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        underline_spans([self.loc1.span, self.loc2.span])
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.loc1.src as &dyn miette::SourceCode)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        let msg = format!("Actions may only have a single {} declaration. If you need it to apply to multiple types, try creating a parent type and using the `in` keyword", self.kind);
        Some(Box::new(msg))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("duplicate context declaration in action `{name}`. Action may have at most one context declaration")]
pub struct DuplicateContext {
    name: SmolStr,
    loc1: Loc,
    loc2: Loc,
}

impl Diagnostic for DuplicateContext {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        underline_spans([self.loc1.span, self.loc2.span])
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.loc1.src as &dyn miette::SourceCode)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new(
            "Try either deleting one of the declarations, or merging into a single declaration",
        ))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("`{decl}` is declared twice")]
pub struct DuplicateDeclarations {
    decl: SmolStr,
    loc1: Loc,
    loc2: Loc,
}

impl Diagnostic for DuplicateDeclarations {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        underline_spans([self.loc1.span, self.loc2.span])
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.loc1.src as &dyn miette::SourceCode)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Error)]
#[error("`{key}` declared twice")]
pub struct DuplicateKeys {
    key: SmolStr,
    loc1: Loc,
    loc2: Loc,
}

impl Diagnostic for DuplicateKeys {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        underline_spans([self.loc1.span, self.loc2.span])
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.loc1.src as &dyn miette::SourceCode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("missing `{kind}` declaration for `{name}`")]
pub struct NoPrincipalOrResource {
    kind: PR,
    name: SmolStr,
    loc: Loc,
}

pub const NO_PR_HELP_MSG: &str =
    "Every action must define both `principal` and `resource` targets.";

impl Diagnostic for NoPrincipalOrResource {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        Some(Box::new(once(LabeledSpan::underline(self.loc.span))))
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.loc.src as &dyn miette::SourceCode)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new(NO_PR_HELP_MSG))
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("duplicate namespace id: `{namespace_id}`")]
pub struct DuplicateNameSpace {
    namespace_id: SmolStr,
    // `Loc`s are optional here as the implicit empty namespace has no location
    loc1: Option<Loc>,
    loc2: Option<Loc>,
}

impl Diagnostic for DuplicateNameSpace {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        underline_spans([self.loc1.as_ref()?.span, self.loc2.as_ref()?.span])
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.loc1.as_ref()?.src as &dyn miette::SourceCode)
    }
}

/// Generate an underlined span for each source location in the input iterator
fn underline_spans<'a, I>(i: I) -> Option<Box<dyn Iterator<Item = LabeledSpan> + 'a>>
where
    I: IntoIterator<Item = SourceSpan> + 'a,
{
    Some(Box::new(
        i.into_iter().map(|span| LabeledSpan::underline(span)),
    ))
}

/// Error subtypes for [`SchemaWarning`]
pub mod schema_warnings {
    use cedar_policy_core::{impl_diagnostic_from_source_loc_field, parser::Loc};
    use miette::Diagnostic;
    use smol_str::SmolStr;
    use thiserror::Error;

    /// Warning when a builtin Cedar name is shadowed
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Clone, Error)]
    #[error("The name `{name}` shadows a builtin Cedar name. You'll have to refer to the builtin as `__cedar::{name}`.")]
    pub struct ShadowsBuiltinWarning {
        pub(crate) name: SmolStr,
        pub(crate) loc: Loc,
    }

    impl Diagnostic for ShadowsBuiltinWarning {
        impl_diagnostic_from_source_loc_field!(loc);

        fn severity(&self) -> Option<miette::Severity> {
            Some(miette::Severity::Warning)
        }
    }

    /// Warning when an entity name is shadowed by a common type name
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, Clone, Error)]
    #[error("The common type name {name} shadows an entity name")]
    pub struct ShadowsEntityWarning {
        pub(crate) name: SmolStr,
        pub(crate) entity_loc: Loc,
        pub(crate) common_loc: Loc,
    }

    impl Diagnostic for ShadowsEntityWarning {
        fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
            Some(Box::new(
                std::iter::once(&self.entity_loc)
                    .chain(std::iter::once(&self.common_loc))
                    .map(miette::LabeledSpan::underline),
            ))
        }

        fn source_code(&self) -> Option<&dyn miette::SourceCode> {
            // just have to pick one; we assume `entity_loc` and `common_loc`
            // have the same source code.
            // if that isn't true we'll have a confusing underline.
            Some(&self.entity_loc.src as _)
        }

        fn severity(&self) -> Option<miette::Severity> {
            Some(miette::Severity::Warning)
        }
    }
}

/// Warning when constructing a schema
//
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Diagnostic)]
pub enum SchemaWarning {
    /// Warning when a declaration shadows a builtin type
    #[error(transparent)]
    #[diagnostic(transparent)]
    ShadowsBuiltin(#[from] schema_warnings::ShadowsBuiltinWarning),
    /// Warning when a declaration shadows an entity type
    #[error(transparent)]
    #[diagnostic(transparent)]
    ShadowsEntity(#[from] schema_warnings::ShadowsEntityWarning),
}
