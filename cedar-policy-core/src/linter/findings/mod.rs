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

//! The finding types the linter and schema linter produce, and the [`Finding`] /
//! [`SchemaFinding`] enums that aggregate them.
//!
//! The individual finding structs live in submodules by the kind of lint that
//! produces them — [`policy`], [`schema`], [`schema_informed`], and (under the
//! `tpe` feature) [`tpe`] — and are re-exported here so the enums and the rest of
//! the crate can name them unqualified.

use miette::Diagnostic;
use thiserror::Error;

use crate::{ast::PolicyID, linter::Lint, parser::Loc};

mod policy;
pub use policy::*;

/// A single problem the linter found.
///
/// Each variant corresponds to one kind of finding; see [`Lint`](super::Lint)
/// for the analyses that produce them. Use [`Finding::is_warning`] to tell
/// advisory findings from ones that are essentially always bugs.
///
/// PUBLIC API: re-exported unchanged from `cedar-policy`, so a breaking change to
/// a variant here breaks that crate's API too. `#[non_exhaustive]`, so adding a
/// variant is not breaking.
#[derive(Diagnostic, Error, Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Finding {
    /// An expression that will error when evaluated.
    #[diagnostic(transparent)]
    #[error(transparent)]
    TypeError(#[from] TypeError),

    /// An operation relating two unrelated types.
    #[diagnostic(transparent)]
    #[error(transparent)]
    TypeMismatch(#[from] TypeMismatch),

    /// A `getTag` not guarded by a corresponding `hasTag`.
    #[diagnostic(transparent)]
    #[error(transparent)]
    TagError(#[from] TagError),

    /// An empty set literal.
    #[diagnostic(transparent)]
    #[error(transparent)]
    EmptySet(#[from] EmptySet),

    /// An extension constructor called with a non-literal argument.
    #[diagnostic(transparent)]
    #[error(transparent)]
    NonLitExtConstructor(#[from] NonLitExtConstructor),

    /// An extension constructor called with a literal that fails to parse.
    #[diagnostic(transparent)]
    #[error(transparent)]
    ExtConstructorError(#[from] ExtConstructorError),

    /// An attribute or tag access on an action, which no schema can declare.
    #[diagnostic(transparent)]
    #[error(transparent)]
    ActionMemberAccess(#[from] ActionMemberAccess),

    /// An `is` that no entity can satisfy, because the operand's action-ness
    /// disagrees with the type named.
    #[diagnostic(transparent)]
    #[error(transparent)]
    ImpossibleIsCheck(#[from] ImpossibleIsCheck),
}
impl Finding {
    /// The lint that produced this finding.
    pub fn lint(&self) -> Lint {
        match self {
            Finding::TypeError(_) | Finding::TypeMismatch(_) => Lint::Types,
            Finding::TagError(_) => Lint::Tags,
            Finding::EmptySet(_) => Lint::EmptySet,
            Finding::NonLitExtConstructor(_) | Finding::ExtConstructorError(_) => {
                Lint::ExtConstructors
            }
            Finding::ImpossibleIsCheck(_) => Lint::Types,
            Finding::ActionMemberAccess(_) => Lint::ActionAttrs,
        }
    }

    /// The source location this finding refers to, if the expression it was
    /// found in carried one.
    pub fn source_loc(&self) -> Option<&Loc> {
        match self {
            Finding::TypeError(f) => f.loc.as_ref(),
            Finding::TypeMismatch(f) => f.loc.as_ref(),
            Finding::TagError(f) => f.loc.as_ref(),
            Finding::EmptySet(f) => f.loc.as_ref(),
            Finding::NonLitExtConstructor(f) => f.loc.as_ref(),
            Finding::ExtConstructorError(f) => f.loc.as_ref(),
            Finding::ActionMemberAccess(f) => f.loc.as_ref(),
            Finding::ImpossibleIsCheck(f) => f.loc.as_ref(),
        }
    }

    /// Is this finding a warning rather than an error?
    ///
    /// Warnings flag constructs that are legal and may well be intentional,
    /// most often because they will be rejected by strict validation or cannot
    /// be analyzed. Errors flag code that is essentially always a bug.
    pub fn is_warning(&self) -> bool {
        Diagnostic::severity(self) == Some(miette::Severity::Warning)
    }
}
/// A [`Finding`], usually together with the ID of the policy it was found in.
///
/// Most findings are about a single policy and carry its ID. Some — the
/// decision-level TPE findings, which are scoped to a request environment and may
/// blame zero or several policies — carry none; their `policy_id` is `None`.
///
/// PUBLIC API: re-exported unchanged from `cedar-policy`; a breaking change to
/// this type or its methods breaks that crate's API too.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LintFinding {
    finding: Finding,
    policy_id: Option<PolicyID>,
}

impl std::fmt::Display for LintFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A policy-scoped finding names its policy; a decision-scoped one (no ID)
        // just renders its finding, which describes the environment itself.
        match &self.policy_id {
            Some(id) => write!(f, "for policy `{id}`, {}", self.finding),
            None => write!(f, "{}", self.finding),
        }
    }
}

impl std::error::Error for LintFinding {}

// Forwards to the inner finding rather than deriving, so that the source span,
// severity, and help survive; only the message gains the policy ID.
impl Diagnostic for LintFinding {
    fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.finding.code()
    }

    fn severity(&self) -> Option<miette::Severity> {
        self.finding.severity()
    }

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.finding.help()
    }

    fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.finding.url()
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        self.finding.source_code()
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        self.finding.labels()
    }

    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        self.finding.related()
    }
}

impl LintFinding {
    /// Tag each of `findings` with `policy_id`.
    pub(crate) fn tag_all(
        findings: impl IntoIterator<Item = Finding>,
        policy_id: &PolicyID,
    ) -> Vec<Self> {
        findings
            .into_iter()
            .map(|finding| Self {
                finding,
                policy_id: Some(policy_id.clone()),
            })
            .collect()
    }

    /// A finding not scoped to any single policy — a decision-level finding that
    /// describes a request environment rather than one policy.
    pub(crate) fn untagged(finding: Finding) -> Self {
        Self {
            finding,
            policy_id: None,
        }
    }

    /// The underlying finding.
    pub fn finding(&self) -> &Finding {
        &self.finding
    }

    /// The ID of the policy this finding was found in, if it is scoped to one. A
    /// decision-level finding (e.g. [`Lint::TrivialDecision`]) is scoped to a
    /// request environment, not a policy, and returns `None`.
    pub fn policy_id(&self) -> Option<&PolicyID> {
        self.policy_id.as_ref()
    }

    /// The lint that produced this finding.
    pub fn lint(&self) -> Lint {
        self.finding.lint()
    }

    /// Consume this, returning the underlying finding.
    pub fn into_finding(self) -> Finding {
        self.finding
    }

    /// Is this finding a warning rather than an error? See
    /// [`Finding::is_warning`].
    pub fn is_warning(&self) -> bool {
        self.finding.is_warning()
    }
}

