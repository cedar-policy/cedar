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
mod schema;
pub use schema::*;
mod schema_informed;
pub use schema_informed::*;
#[cfg(feature = "tpe")]
mod tpe;
#[cfg(feature = "tpe")]
pub use tpe::*;

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

    /// A multiplication where neither operand is constant.
    #[diagnostic(transparent)]
    #[error(transparent)]
    NonLinearArithmetic(#[from] NonLinearArithmetic),

    /// Arithmetic in a `forbid` policy, which may cause it to be skipped.
    #[diagnostic(transparent)]
    #[error(transparent)]
    ArithmeticInForbid(#[from] ArithmeticInForbid),

    /// Arithmetic in a `permit` policy, which may cause it to be skipped.
    #[diagnostic(transparent)]
    #[error(transparent)]
    ArithmeticInPermit(#[from] ArithmeticInPermit),

    /// A `like` pattern containing no wildcard.
    #[diagnostic(transparent)]
    #[error(transparent)]
    LikeWithoutWildcard(#[from] LikeWithoutWildcard),

    /// A `like` pattern consisting only of wildcards.
    #[diagnostic(transparent)]
    #[error(transparent)]
    LikeWithOnlyWildcards(#[from] LikeWithOnlyWildcards),

    /// A `like` pattern with two or more consecutive wildcards.
    #[diagnostic(transparent)]
    #[error(transparent)]
    LikeWithConsecutiveWildcards(#[from] LikeWithConsecutiveWildcards),

    /// A prefix and a suffix `like` pattern on the same operand that combine.
    #[diagnostic(transparent)]
    #[error(transparent)]
    CombinableLikePatterns(#[from] CombinableLikePatterns),

    /// A universal `permit` that makes other `permit`s redundant.
    #[diagnostic(transparent)]
    #[error(transparent)]
    PermitAllSubsumesPermits(#[from] PermitAllSubsumesPermits),

    /// A universal `permit` in a policy set with no `forbid`.
    #[diagnostic(transparent)]
    #[error(transparent)]
    PermitAllWithoutForbid(#[from] PermitAllWithoutForbid),

    /// A universal `forbid` that makes every other policy dead.
    #[diagnostic(transparent)]
    #[error(transparent)]
    ForbidAllSubsumesPolicies(#[from] ForbidAllSubsumesPolicies),

    /// A `forbid` in a policy set containing no `permit`.
    #[diagnostic(transparent)]
    #[error(transparent)]
    ForbidWithoutPermit(#[from] ForbidWithoutPermit),

    /// An attribute access in a `forbid` policy with no `has` guard.
    #[diagnostic(transparent)]
    #[error(transparent)]
    UnguardedAttrInForbid(#[from] UnguardedAttrInForbid),

    /// An attribute access in a `permit` policy with no `has` guard.
    #[diagnostic(transparent)]
    #[error(transparent)]
    UnguardedAttrInPermit(#[from] UnguardedAttrInPermit),

    /// A scope-expressible comparison written in a condition instead.
    #[diagnostic(transparent)]
    #[error(transparent)]
    ScopeConstraintInCondition(#[from] ScopeConstraintInCondition),

    /// A comparison against a boolean literal, or an `if` returning booleans.
    #[diagnostic(transparent)]
    #[error(transparent)]
    RedundantBoolean(#[from] RedundantBoolean),

    /// An expression spelled out by hand that Cedar has syntax for.
    #[diagnostic(transparent)]
    #[error(transparent)]
    PreferSugar(#[from] PreferSugar),

    /// An `expr["key"]` access where `expr.key` would do.
    #[diagnostic(transparent)]
    #[error(transparent)]
    IndexWithLiteralKey(#[from] IndexWithLiteralKey),

    /// A doubled pair of parentheses.
    #[diagnostic(transparent)]
    #[error(transparent)]
    RedundantParens(#[from] RedundantParens),

    /// An `unless` clause whose body is a negation.
    #[diagnostic(transparent)]
    #[error(transparent)]
    UnlessWithNegation(#[from] UnlessWithNegation),

    /// A separate `is` and `in` that the `is .. in ..` form would combine.
    #[diagnostic(transparent)]
    #[error(transparent)]
    SeparateIsAndIn(#[from] SeparateIsAndIn),

    /// An attribute or tag access on an action, which no schema can declare.
    #[diagnostic(transparent)]
    #[error(transparent)]
    ActionMemberAccess(#[from] ActionMemberAccess),

    /// An `is` that no entity can satisfy, because the operand's action-ness
    /// disagrees with the type named.
    #[diagnostic(transparent)]
    #[error(transparent)]
    ImpossibleIsCheck(#[from] ImpossibleIsCheck),

    /// A comparison whose two operands are identical.
    #[diagnostic(transparent)]
    #[error(transparent)]
    SelfComparison(#[from] SelfComparison),

    /// A constant expression used as a condition.
    #[diagnostic(transparent)]
    #[error(transparent)]
    ConstantCondition(#[from] ConstantCondition),

    /// An `&&`/`||` whose two operands are identical.
    #[diagnostic(transparent)]
    #[error(transparent)]
    RepeatedLogicalOperand(#[from] RepeatedLogicalOperand),

    /// An `if` whose branches are identical.
    #[diagnostic(transparent)]
    #[error(transparent)]
    IdenticalIfBranches(#[from] IdenticalIfBranches),

    /// A set literal with a duplicated element.
    #[diagnostic(transparent)]
    #[error(transparent)]
    DuplicateSetElement(#[from] DuplicateSetElement),

    /// A policy that duplicates an earlier one in the set.
    #[diagnostic(transparent)]
    #[error(transparent)]
    DuplicatePolicy(#[from] DuplicatePolicy),

    /// A literal on the left of `==`.
    #[diagnostic(transparent)]
    #[error(transparent)]
    YodaCondition(#[from] YodaCondition),

    /// A sub-expression that is a constant boolean in every request env.
    #[diagnostic(transparent)]
    #[error(transparent)]
    TypedConstantCondition(#[from] TypedConstantCondition),

    /// A `has` on a capability an earlier `has` already established.
    #[diagnostic(transparent)]
    #[error(transparent)]
    RedundantHas(#[from] RedundantHas),

    /// A `has` on an attribute the schema declares required.
    #[diagnostic(transparent)]
    #[error(transparent)]
    HasOnRequiredAttr(#[from] HasOnRequiredAttr),

    /// Arithmetic negation applied twice.
    #[diagnostic(transparent)]
    #[error(transparent)]
    DoubleNegation(#[from] DoubleNegation),

    /// An `in` against a one-element set literal.
    #[diagnostic(transparent)]
    #[error(transparent)]
    SingletonSetIn(#[from] SingletonSetIn),

    /// An addition of a negative literal, i.e. `a + -1`.
    #[diagnostic(transparent)]
    #[error(transparent)]
    PlusNegativeLiteral(#[from] PlusNegativeLiteral),

    /// A request environment whose authorization decision is fixed (TPE).
    #[cfg(feature = "tpe")]
    #[diagnostic(transparent)]
    #[error(transparent)]
    TrivialDecision(#[from] TrivialDecision),

    /// A policy that always errors in some environment, so it is skipped (TPE).
    #[cfg(feature = "tpe")]
    #[diagnostic(transparent)]
    #[error(transparent)]
    AlwaysErrors(#[from] AlwaysErrors),

    /// A policy whose condition folds to a constant in every environment (TPE).
    #[cfg(feature = "tpe")]
    #[diagnostic(transparent)]
    #[error(transparent)]
    VacuousPolicy(#[from] VacuousPolicy),

    /// A sub-expression that TPE folds to a constant boolean in every environment
    /// its policy applies to (TPE).
    #[cfg(feature = "tpe")]
    #[diagnostic(transparent)]
    #[error(transparent)]
    FoldedConstantCondition(#[from] FoldedConstantCondition),
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
            Finding::NonLinearArithmetic(_) => Lint::NonLinearArithmetic,
            Finding::ArithmeticInForbid(_) | Finding::ArithmeticInPermit(_) => {
                Lint::ErroringArithmetic
            }
            Finding::LikeWithoutWildcard(_)
            | Finding::LikeWithOnlyWildcards(_)
            | Finding::LikeWithConsecutiveWildcards(_)
            | Finding::CombinableLikePatterns(_) => Lint::LikePatterns,
            Finding::PermitAllSubsumesPermits(_)
            | Finding::PermitAllWithoutForbid(_)
            | Finding::ForbidAllSubsumesPolicies(_) => Lint::UniversalPolicy,
            Finding::ForbidWithoutPermit(_) => Lint::ForbidWithoutPermit,
            Finding::UnguardedAttrInForbid(_) => Lint::ForbidAttrGuards,
            Finding::UnguardedAttrInPermit(_) => Lint::PermitAttrGuards,
            Finding::ScopeConstraintInCondition(_) => Lint::ScopeConstraints,
            Finding::RedundantBoolean(_) => Lint::RedundantBoolean,
            Finding::PreferSugar(_) => Lint::PreferSugar,
            Finding::IndexWithLiteralKey(_)
            | Finding::RedundantParens(_)
            | Finding::UnlessWithNegation(_)
            | Finding::SeparateIsAndIn(_) => Lint::SyntaxStyle,
            Finding::SingletonSetIn(_) | Finding::PlusNegativeLiteral(_) => Lint::ExprStyle,
            Finding::DoubleNegation(_) => Lint::DoubleNegation,
            Finding::ImpossibleIsCheck(_) => Lint::Types,
            Finding::SelfComparison(_) => Lint::SelfComparison,
            Finding::ConstantCondition(_) => Lint::ConstantCondition,
            Finding::RepeatedLogicalOperand(_)
            | Finding::IdenticalIfBranches(_)
            | Finding::DuplicateSetElement(_) => Lint::RedundantExpr,
            Finding::DuplicatePolicy(_) => Lint::DuplicatePolicy,
            Finding::YodaCondition(_) => Lint::YodaCondition,
            Finding::TypedConstantCondition(_) => Lint::TypedConstantCondition,
            Finding::RedundantHas(_) => Lint::RedundantHas,
            Finding::HasOnRequiredAttr(_) => Lint::HasOnRequiredAttr,
            Finding::ActionMemberAccess(_) => Lint::ActionAttrs,
            #[cfg(feature = "tpe")]
            Finding::TrivialDecision(_) => Lint::TrivialDecision,
            #[cfg(feature = "tpe")]
            Finding::AlwaysErrors(_) => Lint::PolicyAlwaysErrors,
            #[cfg(feature = "tpe")]
            Finding::VacuousPolicy(_) => Lint::VacuousPolicy,
            #[cfg(feature = "tpe")]
            Finding::FoldedConstantCondition(_) => Lint::FoldedConstantCondition,
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
            Finding::NonLinearArithmetic(f) => f.loc.as_ref(),
            Finding::ArithmeticInForbid(f) => f.loc.as_ref(),
            Finding::ArithmeticInPermit(f) => f.loc.as_ref(),
            Finding::LikeWithoutWildcard(f) => f.loc.as_ref(),
            Finding::LikeWithOnlyWildcards(f) => f.loc.as_ref(),
            Finding::LikeWithConsecutiveWildcards(f) => f.loc.as_ref(),
            Finding::CombinableLikePatterns(f) => f.loc.as_ref(),
            Finding::PermitAllSubsumesPermits(f) => f.loc.as_ref(),
            Finding::PermitAllWithoutForbid(f) => f.loc.as_ref(),
            Finding::ForbidAllSubsumesPolicies(f) => f.loc.as_ref(),
            Finding::ForbidWithoutPermit(f) => f.loc.as_ref(),
            Finding::UnguardedAttrInForbid(f) => f.loc.as_ref(),
            Finding::UnguardedAttrInPermit(f) => f.loc.as_ref(),
            Finding::ScopeConstraintInCondition(f) => f.loc.as_ref(),
            Finding::RedundantBoolean(f) => f.loc.as_ref(),
            Finding::PreferSugar(f) => f.loc.as_ref(),
            Finding::IndexWithLiteralKey(f) => f.loc.as_ref(),
            Finding::RedundantParens(f) => f.loc.as_ref(),
            Finding::UnlessWithNegation(f) => f.loc.as_ref(),
            Finding::SeparateIsAndIn(f) => f.loc.as_ref(),
            Finding::ActionMemberAccess(f) => f.loc.as_ref(),
            Finding::ImpossibleIsCheck(f) => f.loc.as_ref(),
            Finding::SelfComparison(f) => f.loc.as_ref(),
            Finding::ConstantCondition(f) => f.loc.as_ref(),
            Finding::RepeatedLogicalOperand(f) => f.loc.as_ref(),
            Finding::IdenticalIfBranches(f) => f.loc.as_ref(),
            Finding::DuplicateSetElement(f) => f.loc.as_ref(),
            Finding::DuplicatePolicy(f) => f.loc.as_ref(),
            Finding::YodaCondition(f) => f.loc.as_ref(),
            Finding::TypedConstantCondition(f) => f.loc.as_ref(),
            Finding::RedundantHas(f) => f.loc.as_ref(),
            Finding::HasOnRequiredAttr(f) => f.loc.as_ref(),
            Finding::DoubleNegation(f) => f.loc.as_ref(),
            Finding::SingletonSetIn(f) => f.loc.as_ref(),
            Finding::PlusNegativeLiteral(f) => f.loc.as_ref(),
            #[cfg(feature = "tpe")]
            Finding::TrivialDecision(f) => f.loc.as_ref(),
            #[cfg(feature = "tpe")]
            Finding::AlwaysErrors(_) => None,
            #[cfg(feature = "tpe")]
            Finding::VacuousPolicy(f) => f.loc.as_ref(),
            #[cfg(feature = "tpe")]
            Finding::FoldedConstantCondition(f) => f.loc.as_ref(),
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

/// A single problem the schema linter found.
///
/// Schema findings are separate from policy [`Finding`]s: they arise from a
/// schema rather than a policy, and are located by the entity type, attribute, or
/// namespace they concern rather than by a policy ID.
///
/// PUBLIC API: re-exported unchanged from `cedar-policy`, so a breaking change to
/// a variant here breaks that crate's API too. `#[non_exhaustive]`, so adding a
/// variant is not breaking.
#[derive(Diagnostic, Error, Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum SchemaFinding {
    /// An attribute typed like the pre-`tags` tag-emulation idiom.
    #[diagnostic(transparent)]
    #[error(transparent)]
    AttributeShouldBeTags(#[from] AttributeShouldBeTags),

    /// Many entity types sharing a name prefix, which a namespace would express.
    #[diagnostic(transparent)]
    #[error(transparent)]
    SharedPrefixNamespace(#[from] SharedPrefixNamespace),

    /// A declared entity type nothing references.
    #[diagnostic(transparent)]
    #[error(transparent)]
    UnusedEntityType(#[from] UnusedEntityType),

    /// A declared common type nothing references.
    #[diagnostic(transparent)]
    #[error(transparent)]
    UnusedCommonType(#[from] UnusedCommonType),

    /// An action no other action lists as a parent.
    #[diagnostic(transparent)]
    #[error(transparent)]
    UnusedAction(#[from] UnusedAction),

    /// A `memberOf`/`in` list with a repeated entry.
    #[diagnostic(transparent)]
    #[error(transparent)]
    DuplicateMemberOf(#[from] DuplicateMemberOf),

    /// An enumerated entity type with a repeated choice.
    #[diagnostic(transparent)]
    #[error(transparent)]
    DuplicateEnumChoice(#[from] DuplicateEnumChoice),

    /// Several entity types sharing many attributes, suggesting a common type.
    #[diagnostic(transparent)]
    #[error(transparent)]
    SharedAttributes(#[from] SharedAttributes),

    /// Two entity types applicable in the same position for one action declare an
    /// attribute of the same name with incompatible types.
    #[diagnostic(transparent)]
    #[error(transparent)]
    ConflictingAppliesToAttr(#[from] ConflictingAppliesToAttr),

    /// Two actions declare a `context` attribute of the same name with
    /// incompatible types.
    #[diagnostic(transparent)]
    #[error(transparent)]
    ConflictingContextAttr(#[from] ConflictingContextAttr),

    /// Two entity types applicable in the same position for one action carry tags
    /// of incompatible types.
    #[diagnostic(transparent)]
    #[error(transparent)]
    ConflictingTagType(#[from] ConflictingTagType),
}

impl SchemaFinding {
    /// The lint that produced this finding.
    pub fn lint(&self) -> Lint {
        match self {
            SchemaFinding::AttributeShouldBeTags(_) => Lint::AttributeShouldBeTags,
            SchemaFinding::SharedPrefixNamespace(_) => Lint::SharedPrefixNamespace,
            SchemaFinding::UnusedEntityType(_) => Lint::UnusedEntityType,
            SchemaFinding::UnusedCommonType(_) => Lint::UnusedCommonType,
            SchemaFinding::UnusedAction(_) => Lint::UnusedAction,
            SchemaFinding::DuplicateMemberOf(_) => Lint::DuplicateMemberOf,
            SchemaFinding::DuplicateEnumChoice(_) => Lint::DuplicateEnumChoice,
            SchemaFinding::SharedAttributes(_) => Lint::SharedAttributes,
            SchemaFinding::ConflictingAppliesToAttr(_) => Lint::ConflictingAppliesToAttr,
            SchemaFinding::ConflictingContextAttr(_) => Lint::ConflictingContextAttr,
            SchemaFinding::ConflictingTagType(_) => Lint::ConflictingTagType,
        }
    }

    /// Is this finding a warning rather than an error? Every schema finding is
    /// advisory, so this is always true; provided for parity with [`Finding`].
    pub fn is_warning(&self) -> bool {
        Diagnostic::severity(self) == Some(miette::Severity::Warning)
    }
}
