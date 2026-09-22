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

//! A schema-free linter for Cedar policies.
//!
//! Unlike the validator, the linter needs no schema and makes no soundness
//! claim: it reports what it can determine from a policy's syntax alone. That
//! makes it useful before a schema exists, and as a way to find issues the
//! validator's schema-driven checks aren't looking for.
//!
//! # Usage
//!
//! [`Linter::lint`] takes a whole [`PolicySet`] and returns a [`LintResult`]:
//!
//! ```
//! # use cedar_policy_core::linter::Linter;
//! # use cedar_policy_core::parser::parse_policyset;
//! let policies = parse_policyset(r#"
//!     forbid(principal, action, resource) when { context.count + 1 > 10 };
//! "#).unwrap();
//! let result = Linter::default_lints().lint(&policies);
//! if !result.passed() {
//!     for finding in result.errors() {
//!         println!("{:?}: {}", finding.policy_id(), finding.finding());
//!     }
//! }
//! for finding in result.warnings() {
//!     println!("{:?} [{}]: {}", finding.policy_id(), finding.lint(), finding.finding());
//! }
//! ```
//!
//! Choose which lints to run, by name, by group, or individually:
//!
//! ```
//! # use cedar_policy_core::linter::{Lint, LintGroup, Linter};
//! # use cedar_policy_core::parser::parse_policyset;
//! # use std::str::FromStr;
//! # let policies = parse_policyset(
//! #     r#"permit(principal, action, resource) when { [] == [] };"#).unwrap();
//! // Only the lints you ask for.
//! Linter::new([Lint::EmptySet]).lint(&policies);
//!
//! // Everything except some.
//! Linter::default_lints().without(Lint::Types).lint(&policies);
//!
//! // A whole group.
//! Linter::new(LintGroup::StrictMigration.lints()).lint(&policies);
//!
//! // Every lint, including those off by default.
//! Linter::all_lints().lint(&policies);
//!
//! // Selected by name, e.g. from a CLI flag.
//! Linter::new([Lint::from_str("empty-set").unwrap()]).lint(&policies);
//! ```
//!
//! # Groups
//!
//! A lint's [`LintGroup`] says what a finding *means*, which is what decides how
//! to act on one:
//!
//! | Group | A finding says | Example |
//! | --- | --- | --- |
//! | [`Correctness`] | the policy is probably wrong | `Group::"admins".contains(principal)` always errors |
//! | [`Style`] | it is right, but oddly written | a `like` pattern with no wildcard is just `==` |
//! | [`StrictMigration`] | strict validation will reject it | an empty set literal has no element type |
//! | [`Analyzability`] | reasoning tools can't analyze it | non-linear arithmetic is undecidable for SMT |
//! | [`Restriction`] | it uses something you may have chosen to give up | arithmetic in a condition can overflow and skip the policy |
//!
//! `Restriction` lints are the ones to reach for deliberately: they flag policies
//! that are neither wrong nor badly written, and ask you to give up a construct
//! the language allows in exchange for a safety property. That is a real limit on
//! what you can express, so they are off by default.
//!
//! [`Correctness`]: LintGroup::Correctness
//! [`Style`]: LintGroup::Style
//! [`StrictMigration`]: LintGroup::StrictMigration
//! [`Analyzability`]: LintGroup::Analyzability
//! [`Restriction`]: LintGroup::Restriction

// Lint modules, grouped by analysis layer. Each of these directories holds one
// submodule per lint; the shared infrastructure (findings, util, types,
// cst_visitor) stays at this top level since every group draws on it.
mod findings;
mod util;
// Schema-free policy lints, one submodule each.
mod policy;
// Schema lints (the `SchemaLinter`).
mod schema;
// Schema-informed policy lints (typechecker as a service).
// TPE-based lints (feature-gated).

// Shared infrastructure used across the lint groups.
mod capability;
mod cst_visitor;
mod types;

// The policy lint modules are reached through `policy::`, but the driver names
// them unqualified for brevity; bring them into scope here.
use policy::*;
// The TPE lints live in `tpe`; the driver refers to it by its old name.

/// Test-only helpers shared by the per-lint test modules.
#[cfg(test)]
mod test_util {
    use miette::{Diagnostic, GraphicalReportHandler, GraphicalTheme};

    /// Render `findings` as the pretty miette output the per-lint snapshots use:
    /// each finding rendered with the no-color graphical handler, joined by blank
    /// lines. Every lint's test module renders the same way; this is that shared
    /// boilerplate.
    pub(crate) fn render<D: Diagnostic>(findings: &[D]) -> String {
        let handler = GraphicalReportHandler::new_themed(GraphicalTheme::unicode_nocolor());
        findings
            .iter()
            .map(|f| {
                let mut buf = String::new();
                handler
                    .render_report(&mut buf, f as &dyn Diagnostic)
                    .expect("failed to render report");
                buf
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

use std::collections::BTreeSet;

use crate::{
    ast::{Effect, Expr, PolicySet, Template},
    fuzzy_match::fuzzy_search,
};

pub use findings::{Finding, LintFinding, SchemaFinding};
pub use schema::SchemaLinter;

/// Run each enabled lint over `$input`, collecting its findings into `$findings`.
/// Collapses the otherwise-identical per-lint dispatch blocks in
/// [`Linter::lint_expr`] and [`Linter::lint_template`]. Two forms of lint:
///
/// * `Lint => fn path` — a free function `fn(&Input) -> Vec<Finding>`;
/// * `Lint => type Type` — a `Default` linter with `lint(&Input)` +
///   `into_findings()` (the older stateful shape).
macro_rules! run_lints {
    ($self:ident, $findings:ident, $input:expr, { $($lint:expr => $kind:tt $body:path),+ $(,)? }) => {
        $( run_lints!(@one $self, $findings, $input, $lint => $kind $body); )+
    };
    (@one $self:ident, $findings:ident, $input:expr, $lint:expr => fn $f:path) => {
        if $self.runs($lint) {
            $findings.extend($f($input));
        }
    };
    (@one $self:ident, $findings:ident, $input:expr, $lint:expr => type $linter:path) => {
        if $self.runs($lint) {
            let mut linter = <$linter>::default();
            linter.lint($input);
            $findings.extend(linter.into_findings());
        }
    };
}

/// Declares the [`Lint`] enum along with each variant's name, group, and
/// default-on status, so that the three stay in sync and `Lint::all` cannot
/// silently omit a variant.
macro_rules! declare_lints {
    ($( $(#[$attr:meta])* $variant:ident => $name:literal, $group:ident, $default:literal; )+) => {
        /// The lints the linter can run.
        ///
        /// Each variant corresponds to one analysis. Use [`Linter`] to select
        /// which of them to run.
        ///
        /// PUBLIC API: re-exported from the `cedar-policy` crate as-is, so any
        /// breaking change here (renaming or removing a variant, changing a
        /// name string) is a breaking change to that crate's public API. It is
        /// `#[non_exhaustive]`, so *adding* a variant is not breaking.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[non_exhaustive]
        pub enum Lint {
            $( $(#[$attr])* $variant, )+
        }

        impl Lint {
            /// Every lint, including those that are off by default.
            pub fn all() -> impl Iterator<Item = Lint> {
                [ $( Lint::$variant, )+ ].into_iter()
            }

            /// A stable, machine-readable name for this lint, suitable for use
            /// in a CLI flag or a config file.
            pub fn name(self) -> &'static str {
                match self {
                    $( Lint::$variant => $name, )+
                }
            }

            /// The group this lint belongs to. Every lint is in exactly one
            /// group.
            pub fn group(self) -> LintGroup {
                match self {
                    $( Lint::$variant => LintGroup::$group, )+
                }
            }

            /// Is this lint on by default, i.e. included by
            /// [`Linter::default_lints`]?
            ///
            /// Lints that are off by default flag things that are often
            /// deliberate, so they would be noisy in a default run.
            pub fn is_default(self) -> bool {
                match self {
                    $( Lint::$variant => $default, )+
                }
            }
        }
    };
}

declare_lints! {
    /// Expressions that will definitely error when evaluated, e.g.
    /// `Group::"admins".contains(principal)`, and comparisons between unrelated
    /// types, e.g. `principal.name == 1`.
    ///
    /// Includes comparisons that action-ness rules out — `action == User::"a"`,
    /// `principal in Action::"a"`, `action is User` — which are always `false`
    /// whatever the schema. Attribute and tag accesses on an action are legal
    /// without a schema, so they are [`Lint::ActionAttrs`] instead.
    Types => "types", Correctness, true;

    /// Arithmetic negation applied twice, as in `- -x`, which computes the operand
    /// back again while adding an overflow failure mode. Almost always a mistake:
    /// a missing left operand of a subtraction, or a logical `!` meant instead.
    DoubleNegation => "double-negation", Correctness, true;

    /// A comparison whose two operands are syntactically identical, e.g.
    /// `principal == principal`. Almost always a mistake.
    SelfComparison => "self-comparison", Correctness, true;

    /// A constant expression used where a condition is expected, e.g.
    /// `when { false }`, which makes the policy dead code.
    ConstantCondition => "constant-condition", Correctness, true;

    /// Expressions with a redundant part: `a && a`, `if c then X else X`, and a
    /// duplicated set element.
    RedundantExpr => "redundant-expr", Correctness, true;

    /// `getTag` calls not guarded by a corresponding `hasTag`, which error if
    /// the tag is absent.
    Tags => "tags", Correctness, true;

    /// Attribute and tag accesses on an action. These evaluate fine without a
    /// schema, but no schema can declare attributes or tags on an action, so
    /// strict validation rejects them.
    ActionAttrs => "action-attrs", StrictMigration, true;

    /// Extension constructor calls: a string literal that fails to parse, and
    /// non-literal arguments, which strict validation rejects.
    ExtConstructors => "ext-constructors", StrictMigration, true;

    /// Empty set literals, which strict validation rejects.
    EmptySet => "empty-set", StrictMigration, true;

    /// Multiplication where neither operand is a constant, which automated
    /// reasoning tools cannot analyze.
    NonLinearArithmetic => "non-linear-arithmetic", Analyzability, false;

    /// Policies that apply to every request — unconstrained scope, no
    /// conditions — and so make other policies in the set redundant or
    /// unreachable. A policy set consisting of one such policy is not reported:
    /// that is a deliberately open, or closed, policy set.
    ///
    /// Off by default: a policy set may legitimately contain a blanket policy.
    UniversalPolicy => "universal-policy", Correctness, false;

    /// Policies that duplicate an earlier one in the set — same effect and
    /// condition. A duplicate has no additional effect.
    ///
    /// Off by default: a policy set is often linted in fragments, so an apparent
    /// duplicate may be intentional across files, and exact duplicates are rare
    /// enough that the check is opt-in.
    DuplicatePolicy => "duplicate-policy", Correctness, false;

    /// `forbid` policies in a policy set that contains no `permit`, so nothing
    /// is ever allowed regardless of the `forbid`s.
    ///
    /// Off by default: a policy set is often linted in fragments, so a missing
    /// `permit` may simply live elsewhere.
    ForbidWithoutPermit => "forbid-without-permit", Correctness, false;

    /// `like` patterns that are almost certainly not what was meant: one with
    /// no wildcard, or one that is only wildcards.
    LikePatterns => "like-patterns", Style, true;

    /// Boolean-valued expressions written the long way round: `a == true`,
    /// `a == false`, and `if c then true else false`. Pure rewrites, all
    /// expressible on the AST since the parser leaves them intact.
    RedundantBoolean => "redundant-boolean", Style, true;

    /// Negated comparisons and repeated `!` written out by hand, where Cedar has
    /// syntax that says the same thing: `!(a == b)` for `a != b`, `!!a` for `a`.
    ///
    /// Reads the CST rather than the AST, since the parser desugars `a != b` into
    /// `!(a == b)` and the two are indistinguishable afterwards.
    PreferSugar => "prefer-sugar", Style, true;

    /// Expressions with a shorter equivalent form that the AST records directly:
    /// `x in [E]` for `x in E`, and `a + -1` for `a - 1`.
    ExprStyle => "expr-style", Style, true;

    /// Roundabout syntax that the CST records but the AST does not:
    /// `principal["foo"]` for `principal.foo`, doubled parentheses, and an
    /// `unless` clause whose body is negated.
    SyntaxStyle => "syntax-style", Style, true;

    /// `==` and `in` comparisons between a scope variable and an entity literal
    /// that are written in a condition, where the policy scope could express
    /// them directly. Equivalent either way, but only a scope constraint lets a
    /// policy store slice on it.
    ScopeConstraints => "scope-constraints", Style, true;

    /// A literal on the left of `==`, e.g. `5 == context.n`, which reads more
    /// naturally with the literal on the right.
    YodaCondition => "yoda-condition", Style, true;

    /// Arithmetic in a policy condition, which can overflow and cause the
    /// policy to be skipped. Most dangerous in a `forbid`.
    ///
    /// Off by default: it rules out arithmetic in conditions altogether, which
    /// is a real restriction on what you can express.
    ErroringArithmetic => "erroring-arithmetic", Restriction, false;

    /// Attribute accesses in a `forbid` policy that no corresponding `has` check
    /// guards. If the attribute is missing the condition errors, which skips the
    /// `forbid` and may allow the request.
    ///
    /// Worth enabling even alongside strict validation: a guard also covers an
    /// entity that is absent from the store entirely, which no schema can rule
    /// out.
    ///
    /// Off by default: it asks for a guard on every access, which is a real
    /// restriction on how conditions can be written.
    ForbidAttrGuards => "forbid-attr-guards", Restriction, false;

    /// Attribute accesses in a `permit` policy that no corresponding `has` check
    /// guards. Same mechanism as [`Lint::ForbidAttrGuards`], but skipping a
    /// `permit` denies the request rather than allowing it, so this is about a
    /// `permit` silently not working rather than about security.
    ///
    /// Configured separately from the `forbid` case, since the `forbid` case is
    /// the one with a security consequence and is worth adopting on its own.
    PermitAttrGuards => "permit-attr-guards", Restriction, false;

    /// (Schema) An attribute typed `Set<{key: String, value: T}>`, the idiom for
    /// emulating tags before Cedar had a native `tags` construct.
    AttributeShouldBeTags => "attribute-should-be-tags", Schema, true;

    /// (Schema) Several entity types sharing a name prefix, which a namespace
    /// would express more cleanly.
    SharedPrefixNamespace => "shared-prefix-namespace", Schema, true;

    /// (Schema) An entity type no action applies to and nothing else references,
    /// so no request can involve it.
    UnusedEntityType => "unused-entity-type", Schema, true;

    /// (Schema) A common type nothing references.
    UnusedCommonType => "unused-common-type", Schema, true;

    /// (Schema) An action that groups no other action and applies to no request.
    UnusedAction => "unused-action", Schema, true;

    /// (Schema) A `memberOf`/`in` list that names the same parent twice.
    DuplicateMemberOf => "duplicate-member-of", Schema, true;

    /// (Schema) An enumerated entity type repeating a choice, e.g.
    /// `enum ["red", "red"]`.
    DuplicateEnumChoice => "duplicate-enum-choice", Schema, true;

    /// (Schema) Several entity types sharing many attributes (fully or partly),
    /// which a common type could factor out.
    SharedAttributes => "shared-attributes", Schema, true;
}

impl std::fmt::Display for Lint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for Lint {
    type Err = UnknownLintName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Lint::all().find(|l| l.name() == s).ok_or_else(|| {
            let names = Lint::all().map(|l| l.name()).collect::<Vec<_>>();
            UnknownLintName {
                name: s.to_string(),
                suggestion: fuzzy_search(s, &names),
            }
        })
    }
}

/// Error parsing a [`Lint`] from its name.
///
/// PUBLIC API: re-exported unchanged from `cedar-policy`; a breaking change here
/// breaks that crate's API too.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{name}` is not a known lint")]
pub struct UnknownLintName {
    name: String,
    suggestion: Option<String>,
}

impl miette::Diagnostic for UnknownLintName {
    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(match &self.suggestion {
            Some(s) => format!("did you mean `{s}`?"),
            None => format!(
                "valid lint names are: {}",
                Lint::all().map(|l| l.name()).collect::<Vec<_>>().join(", ")
            ),
        }))
    }
}

/// A coarse grouping of [`Lint`]s, for selecting several at once.
///
/// The groups differ in what a finding *means*, which is what determines how to
/// act on one: a `Correctness` finding says the policy is probably wrong, a
/// `Style` finding says it is right but oddly written, and a `Restriction`
/// finding says it is right and well written but uses something you may have
/// chosen to do without.
///
/// PUBLIC API: re-exported unchanged from `cedar-policy`; a breaking change here
/// (renaming or removing a variant, changing a name string) breaks that crate's
/// API too. `#[non_exhaustive]`, so adding a variant is not breaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum LintGroup {
    /// Lints for policies that are likely to be simply wrong, whether on their
    /// own or in how they combine with the rest of the policy set.
    Correctness,
    /// Lints for policies that do what they say, but say it in a way that is
    /// probably not what was meant. The fix is to write the same thing
    /// differently, not to change the policy's behavior.
    Style,
    /// Lints for constructs that strict validation rejects, useful when
    /// migrating to it.
    StrictMigration,
    /// Lints for constructs that automated reasoning tools cannot analyze.
    Analyzability,
    /// Lints that rule out a Cedar construct entirely, in exchange for a safety
    /// property.
    ///
    /// These flag policies that are neither wrong nor badly written — they use
    /// something the language allows and this group asks you to give up. That is
    /// a real limit on what you can express, so these lints are off by default;
    /// enable them when the property is worth the constraint.
    Restriction,
    /// Lints for Cedar *schemas* rather than policies, run by
    /// [`SchemaLinter`](crate::linter::SchemaLinter). Suspect but legal schema
    /// constructs — emulated tags, unused declarations, a prefix that wants a
    /// namespace.
    Schema,
}

impl LintGroup {
    /// Every group.
    pub fn all() -> impl Iterator<Item = LintGroup> {
        [
            LintGroup::Correctness,
            LintGroup::Style,
            LintGroup::StrictMigration,
            LintGroup::Analyzability,
            LintGroup::Restriction,
            LintGroup::Schema,
        ]
        .into_iter()
    }

    /// The lints in this group.
    pub fn lints(self) -> impl Iterator<Item = Lint> {
        Lint::all().filter(move |l| l.group() == self)
    }

    /// A stable, machine-readable name for this group.
    pub fn name(self) -> &'static str {
        match self {
            LintGroup::Correctness => "correctness",
            LintGroup::Style => "style",
            LintGroup::StrictMigration => "strict-migration",
            LintGroup::Analyzability => "analyzability",
            LintGroup::Restriction => "restriction",
            LintGroup::Schema => "schema",
        }
    }
}

impl std::fmt::Display for LintGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for LintGroup {
    type Err = UnknownLintGroupName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        LintGroup::all()
            .find(|g| g.name() == s)
            .ok_or_else(|| UnknownLintGroupName(s.to_string()))
    }
}

/// Error parsing a [`LintGroup`] from its name.
///
/// PUBLIC API: re-exported unchanged from `cedar-policy`; a breaking change here
/// breaks that crate's API too.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{0}` is not a known lint group")]
pub struct UnknownLintGroupName(String);

impl miette::Diagnostic for UnknownLintGroupName {
    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "valid lint group names are: {}",
            LintGroup::all()
                .map(|g| g.name())
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }
}

/// The findings from a linter run.
///
/// Findings are split by severity: an *error* is something essentially always
/// wrong, a *warning* is advisory. [`LintResult::passed`] reports whether there
/// were any errors.
///
/// PUBLIC API: re-exported unchanged from `cedar-policy`; a breaking change to
/// this type or its methods breaks that crate's API too.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LintResult {
    findings: Vec<LintFinding>,
}

impl LintResult {
    /// Build a result from `findings`.
    pub fn new(findings: impl IntoIterator<Item = LintFinding>) -> Self {
        Self {
            findings: findings.into_iter().collect(),
        }
    }

    /// True when no findings were errors. There may still be warnings.
    pub fn passed(&self) -> bool {
        !self.findings.iter().any(|f| !f.is_warning())
    }

    /// True when there were no findings at all.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// How many findings there were, of any severity.
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Every finding, of any severity.
    pub fn findings(&self) -> impl Iterator<Item = &LintFinding> {
        self.findings.iter()
    }

    /// Only the findings that are errors.
    pub fn errors(&self) -> impl Iterator<Item = &LintFinding> {
        self.findings.iter().filter(|f| !f.is_warning())
    }

    /// Only the findings that are warnings.
    pub fn warnings(&self) -> impl Iterator<Item = &LintFinding> {
        self.findings.iter().filter(|f| f.is_warning())
    }

    /// Only the findings produced by `lint`.
    pub fn from_lint(&self, lint: Lint) -> impl Iterator<Item = &LintFinding> {
        self.findings.iter().filter(move |f| f.lint() == lint)
    }

    /// Consume this result, returning every finding.
    pub fn into_findings(self) -> Vec<LintFinding> {
        self.findings
    }
}

impl IntoIterator for LintResult {
    type Item = LintFinding;
    type IntoIter = std::vec::IntoIter<LintFinding>;

    fn into_iter(self) -> Self::IntoIter {
        self.findings.into_iter()
    }
}

/// Runs a selected set of [`Lint`]s over policies.
///
/// See the [module docs](self) for examples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Linter {
    lints: BTreeSet<Lint>,
}

/// The default bound for [`Lint::BoundedAttributeDepth`]. Chains up to this depth
/// are allowed; deeper ones are reported.
pub const DEFAULT_ATTRIBUTE_DEPTH_BOUND: usize = 3;

impl Linter {
    /// A linter that runs exactly `lints`.
    pub fn new(lints: impl IntoIterator<Item = Lint>) -> Self {
        Self {
            lints: lints.into_iter().collect(),
        }
    }

    /// A linter that runs the lints that are on by default, i.e. those for which
    /// [`Lint::is_default`] holds. This is the recommended starting point.
    pub fn default_lints() -> Self {
        Self::new(Lint::all().filter(|l| l.is_default()))
    }

    /// A linter that runs every lint, including those off by default.
    pub fn all_lints() -> Self {
        Self::new(Lint::all())
    }

    /// Add `lint` to the set this linter runs.
    pub fn with(mut self, lint: Lint) -> Self {
        self.lints.insert(lint);
        self
    }

    /// Add every lint in `group` to the set this linter runs.
    pub fn with_group(mut self, group: LintGroup) -> Self {
        self.lints.extend(group.lints());
        self
    }

    /// Remove `lint` from the set this linter runs.
    pub fn without(mut self, lint: Lint) -> Self {
        self.lints.remove(&lint);
        self
    }

    /// Remove every lint in `group` from the set this linter runs.
    pub fn without_group(mut self, group: LintGroup) -> Self {
        for lint in group.lints() {
            self.lints.remove(&lint);
        }
        self
    }

    /// Will this linter run `lint`?
    pub fn runs(&self, lint: Lint) -> bool {
        self.lints.contains(&lint)
    }

    /// The lints this linter runs.
    pub fn lints(&self) -> impl Iterator<Item = Lint> + '_ {
        self.lints.iter().copied()
    }

    /// Run the selected lints over every policy and template in `policy_set`.
    ///
    /// Findings are tagged with the ID of the policy they were found in. Each
    /// policy is linted once: static policies are linted via the template they
    /// were linked from.
    pub fn lint(&self, policy_set: &PolicySet) -> LintResult {
        let mut findings: Vec<LintFinding> = policy_set
            .all_templates()
            .flat_map(|t| self.lint_template(t))
            .collect();

        // Lints that need to see the whole policy set.
        if self.runs(Lint::UniversalPolicy) {
            findings.extend(universal_policy::lint(policy_set));
        }
        if self.runs(Lint::ForbidWithoutPermit) {
            findings.extend(forbid_without_permit::lint(policy_set));
        }
        if self.runs(Lint::DuplicatePolicy) {
            findings.extend(duplicate_policy::lint_duplicate_policy(policy_set));
        }

        LintResult::new(findings)
    }

    /// Lint policies from their source text, which additionally runs the lints
    /// that need the concrete syntax tree.
    ///
    /// [`Linter::lint`] cannot run those: the parser desugars `a != b` into
    /// `!(a == b)` and drops parentheses and the `unless` keyword, so a
    /// [`PolicySet`] no longer records how the author wrote things.
    /// [`Lint::PreferSugar`] and [`Lint::SyntaxStyle`] need this; every other lint
    /// gives the same result either way.
    ///
    /// Returns a parse error if `src` does not parse, since there is nothing to
    /// lint in that case.
    pub fn lint_str(&self, src: &str) -> Result<LintResult, crate::parser::err::ParseErrors> {
        let cst = crate::parser::text_to_cst::parse_policies(src)?;
        let policy_set = cst.to_policyset()?;
        let mut result = self.lint(&policy_set).into_findings();
        if self.runs(Lint::PreferSugar) {
            result.extend(sugar::SugarLinter::lint_policies(&cst));
        }
        if self.runs(Lint::SyntaxStyle) {
            result.extend(syntax_style::SyntaxStyleLinter::lint_policies(&cst));
        }
        Ok(LintResult::new(result))
    }

    /// Lint a single template or static policy.
    fn lint_template(&self, template: &Template) -> Vec<LintFinding> {
        let mut findings = self.lint_expr(&template.condition());

        // Linters that consume the whole `template` (they inspect the scope, or the
        // effect, or both).
        run_lints!(self, findings, template, {
            Lint::ErroringArithmetic => type erroring_forbid::ErroringForbidLinter,
            Lint::ScopeConstraints => type scope_constraints::ScopeConstraintLinter,
        });

        // Linters that consume just the `when`/`unless` clauses, skipped when the
        // policy has none.
        if let Some(conditions) = template.non_scope_constraints() {
            run_lints!(self, findings, conditions, {
                Lint::DoubleNegation => type double_negation::DoubleNegationLinter,
                Lint::ExprStyle => type expr_style::ExprStyleLinter,
                Lint::RedundantBoolean => type redundant_boolean::RedundantBooleanLinter,
                Lint::ConstantCondition => type constant_condition::ConstantConditionLinter,
            });
        }

        // Free-function lints over the whole template.

        // Lints with a non-`Default` constructor.
        for (lint, effect) in [
            (Lint::ForbidAttrGuards, Effect::Forbid),
            (Lint::PermitAttrGuards, Effect::Permit),
        ] {
            if self.runs(lint) {
                let mut linter = attr_guards::AttrGuardLinter::new(effect);
                linter.lint(template);
                findings.extend(linter.into_findings());
            }
        }

        LintFinding::tag_all(findings, template.id())
    }

    /// The expression-level lints, untagged.
    fn lint_expr(&self, expr: &Expr) -> Vec<Finding> {
        let mut findings = Vec::new();

        // One pass serves two lints: the type checks and the action attribute/tag
        // checks share its type inference, but the latter is a migration concern
        // rather than a correctness one, so each can be enabled alone.
        if self.runs(Lint::Types) || self.runs(Lint::ActionAttrs) {
            let mut linter =
                types::TypeLinter::default().with_action_attrs(self.runs(Lint::ActionAttrs));
            linter.lint(expr);
            let type_findings = linter.into_findings();
            // When only `ActionAttrs` is on, drop the findings belonging to
            // `Types`, and vice versa.
            findings.extend(type_findings.into_iter().filter(|f| self.runs(f.lint())));
        }

        // The rest scan the whole condition expression and yield findings; the
        // `fn` ones use the `scan` combinator, the `type` ones still carry state.
        run_lints!(self, findings, expr, {
            Lint::Tags => type tags::TagLinter,
            Lint::EmptySet => fn empty_set::lint,
            Lint::ExtConstructors => fn ext_constructors::lint,
            Lint::NonLinearArithmetic => fn nonlinear::lint,
            Lint::LikePatterns => fn like_patterns::lint,
            Lint::SelfComparison => fn self_comparison::lint,
            Lint::YodaCondition => fn yoda_condition::lint,
            Lint::RedundantExpr => fn redundant_expr::lint,
        });

        findings
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ast::PolicyID;
    use crate::parser::parse_policyset;
    use std::str::FromStr;

    /// Wrap `condition` in a `permit` and lint the resulting policy set.
    #[track_caller]
    fn lint_condition(linter: &Linter, condition: &str) -> LintResult {
        let src = format!("permit(principal, action, resource) when {{ {condition} }};");
        let policies = parse_policyset(&src).expect("failed to parse");
        linter.lint(&policies)
    }

    #[test]
    fn all_lints_runs_everything() {
        let linter = Linter::all_lints();
        for lint in Lint::all() {
            assert!(linter.runs(lint), "{lint} should be enabled");
        }
    }

    /// The default set is a strict subset of every lint: some lints are off by
    /// default, and no lint is on by default without also being in `all`.
    #[test]
    fn default_lints_is_a_strict_subset() {
        let default = Linter::default_lints();
        let mut off_by_default = 0;
        for lint in Lint::all() {
            assert_eq!(default.runs(lint), lint.is_default(), "{lint}");
            if !lint.is_default() {
                off_by_default += 1;
            }
        }
        assert!(
            off_by_default > 0,
            "if every lint is on by default, `default_lints` is pointless"
        );
    }

    #[test]
    fn selecting_one_lint_excludes_others() {
        // This condition trips both the empty-set and the type lints.
        assert!(!lint_condition(&Linter::all_lints(), "[] == 1").is_empty());

        let only_empty_set = lint_condition(&Linter::new([Lint::EmptySet]), "[] == 1");
        assert_eq!(only_empty_set.len(), 1);
        assert_eq!(
            only_empty_set.findings().next().unwrap().lint(),
            Lint::EmptySet
        );

        let only_types = lint_condition(&Linter::new([Lint::Types]), "[] == 1");
        assert_eq!(only_types.len(), 1);
        assert_eq!(only_types.findings().next().unwrap().lint(), Lint::Types);
    }

    #[test]
    fn with_and_without() {
        let linter = Linter::new([Lint::Types]).with(Lint::Tags);
        assert!(linter.runs(Lint::Types));
        assert!(linter.runs(Lint::Tags));

        let linter = linter.without(Lint::Types);
        assert!(!linter.runs(Lint::Types));
        assert!(linter.runs(Lint::Tags));
    }

    #[test]
    fn with_and_without_group() {
        let linter = Linter::new([]).with_group(LintGroup::StrictMigration);
        for lint in LintGroup::StrictMigration.lints() {
            assert!(linter.runs(lint), "{lint}");
        }
        assert!(!linter.runs(Lint::Types));

        let linter = Linter::all_lints().without_group(LintGroup::StrictMigration);
        for lint in LintGroup::StrictMigration.lints() {
            assert!(!linter.runs(lint), "{lint}");
        }
        assert!(linter.runs(Lint::Types));
    }

    /// Errors and warnings are separated, and `passed` tracks only errors.
    #[test]
    fn result_splits_by_severity() {
        // A bad `ip` literal is an error; an empty set is a warning.
        let linter = Linter::new([Lint::ExtConstructors, Lint::EmptySet]);
        let result = lint_condition(&linter, r#"ip("bad") == ip("1.2.3.4") && [] == []"#);

        assert!(!result.passed(), "a bad ip literal is an error");
        assert_eq!(result.errors().count(), 1);
        assert_eq!(result.warnings().count(), 2);
        assert_eq!(result.len(), 3);
        assert_eq!(result.findings().count(), 3);
    }

    /// A run with only warnings still passes.
    #[test]
    fn warnings_alone_pass() {
        let result = lint_condition(&Linter::new([Lint::EmptySet]), "[] == []");
        assert!(!result.is_empty());
        assert!(result.passed());
        assert_eq!(result.errors().count(), 0);
    }

    #[test]
    fn empty_result_passes() {
        // A policy that trips no lint: a scope anchor (so `no-unconstrained-scope`
        // stays quiet) with a type constraint rather than an entity literal (so
        // `no-scope-entity-literals` stays quiet), and a guarded attribute access
        // with distinct operands and no constants in the condition.
        // (`principal == principal` used to serve here, but the self-comparison
        // lint now flags it; a fully-open scope now trips a restriction lint.)
        let policies = parse_policyset(
            r#"permit(principal is User, action, resource) when { principal has name && principal.name == "alice" };"#,
        )
        .expect("failed to parse");
        let result = Linter::all_lints().lint(&policies);
        assert!(result.is_empty());
        assert!(result.passed());
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn from_lint_filters() {
        let linter = Linter::new([Lint::EmptySet, Lint::Types]);
        let result = lint_condition(&linter, "[] == 1");
        assert_eq!(result.from_lint(Lint::EmptySet).count(), 1);
        assert_eq!(result.from_lint(Lint::Types).count(), 1);
        assert_eq!(result.from_lint(Lint::Tags).count(), 0);
    }

    #[test]
    fn result_into_iter() {
        let result = lint_condition(&Linter::new([Lint::EmptySet]), "[] == []");
        let n = result.len();
        assert_eq!(result.into_iter().count(), n);
    }

    /// `ErroringArithmetic` distinguishes `forbid` from `permit`, which requires
    /// the policy's effect rather than just its condition.
    #[test]
    fn policy_level_lint_sees_the_effect() {
        let linter = Linter::new([Lint::ErroringArithmetic]);

        let forbid =
            parse_policyset(r#"forbid(principal, action, resource) when { context.a + 1 > 0 };"#)
                .unwrap();
        let findings = linter.lint(&forbid).into_findings();
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].finding(),
            Finding::ArithmeticInForbid(_)
        ));

        let result = lint_condition(&linter, "context.a + 1 > 0");
        let findings = result.into_findings();
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].finding(),
            Finding::ArithmeticInPermit(_)
        ));
    }

    /// The two attribute-guard lints are selected independently, and each only
    /// reports policies of its own effect.
    #[test]
    fn attr_guard_lints_are_independent() {
        let policies = parse_policyset(
            r#"
            forbid(principal, action, resource) when { principal.a };
            permit(principal, action, resource) when { principal.a };
        "#,
        )
        .unwrap();

        let only_forbid = Linter::new([Lint::ForbidAttrGuards]).lint(&policies);
        assert_eq!(only_forbid.len(), 1);
        assert!(matches!(
            only_forbid.findings().next().unwrap().finding(),
            Finding::UnguardedAttrInForbid(_)
        ));

        let only_permit = Linter::new([Lint::PermitAttrGuards]).lint(&policies);
        assert_eq!(only_permit.len(), 1);
        assert!(matches!(
            only_permit.findings().next().unwrap().finding(),
            Finding::UnguardedAttrInPermit(_)
        ));

        // Both together report both, and neither is on by default.
        assert_eq!(
            Linter::new([Lint::ForbidAttrGuards, Lint::PermitAttrGuards])
                .lint(&policies)
                .len(),
            2
        );
        assert!(Linter::default_lints().lint(&policies).is_empty());
    }

    #[test]
    fn findings_are_tagged_with_policy_id() {
        let policies = parse_policyset(
            r#"
            forbid(principal, action, resource) when { context.a + 1 > 0 };
            permit(principal, action, resource) when { [] == 1 };
        "#,
        )
        .unwrap();
        let result = Linter::all_lints().lint(&policies);
        let ids: Vec<&PolicyID> = result.findings().filter_map(|f| f.policy_id()).collect();
        assert!(ids.contains(&&PolicyID::from_string("policy0")));
        assert!(ids.contains(&&PolicyID::from_string("policy1")));
    }

    /// Every policy in the set is linted, and each is linted only once.
    #[test]
    fn lints_all_policies_once() {
        let policies = parse_policyset(
            r#"
            permit(principal, action, resource) when { [] == 1 };
            permit(principal, action, resource) when { [] == 1 };
        "#,
        )
        .unwrap();
        assert_eq!(Linter::new([Lint::EmptySet]).lint(&policies).len(), 2);
    }

    /// Templates are linted alongside static policies.
    #[test]
    fn lints_templates() {
        let policies = parse_policyset(
            r#"permit(principal == ?principal, action, resource) when { [] == 1 };"#,
        )
        .unwrap();
        assert_eq!(Linter::new([Lint::EmptySet]).lint(&policies).len(), 1);
    }

    #[test]
    fn empty_policy_set_has_no_findings() {
        let policies = parse_policyset("").unwrap();
        assert!(Linter::all_lints().lint(&policies).is_empty());
    }

    #[test]
    fn lint_names_round_trip() {
        for lint in Lint::all() {
            assert_eq!(Lint::from_str(lint.name()), Ok(lint));
        }
        assert!(Lint::from_str("no-such-lint").is_err());
    }

    #[test]
    fn lint_group_names_round_trip() {
        for group in LintGroup::all() {
            assert_eq!(LintGroup::from_str(group.name()), Ok(group));
        }
        assert!(LintGroup::from_str("no-such-group").is_err());
    }

    /// A near-miss name suggests the intended lint.
    #[test]
    fn unknown_lint_name_suggests() {
        let err = Lint::from_str("empty_set").unwrap_err();
        let help = miette::Diagnostic::help(&err).unwrap().to_string();
        assert!(help.contains("empty-set"), "unexpected help: {help}");
    }

    /// Every lint is in exactly one group, and the groups partition `all`.
    #[test]
    fn groups_partition_all_lints() {
        let all: BTreeSet<Lint> = Lint::all().collect();
        let mut grouped: Vec<Lint> = LintGroup::all().flat_map(|g| g.lints()).collect();
        let n = grouped.len();
        grouped.sort();
        grouped.dedup();
        assert_eq!(grouped.len(), n, "a lint appears in more than one group");
        assert_eq!(grouped.into_iter().collect::<BTreeSet<_>>(), all);
    }

    /// `Lint::all` is generated by a macro, so it cannot drift from the enum.
    /// This pins the count so that adding a lint is a deliberate change.
    #[test]
    fn lint_count() {
        assert_eq!(Lint::all().count(), 31);
        assert_eq!(LintGroup::all().count(), 6);
    }

    /// Every finding type maps back to a lint that actually produces it.
    #[test]
    fn findings_map_to_their_lint() {
        let policies = parse_policyset(
            r#"
            permit(principal, action, resource) when {
                [] == 1 && principal.a like "x" && ip("bad") == ip("1.2.3.4")
                && context.n * context.m > 0 && principal.getTag("t") == ""
            };
        "#,
        )
        .unwrap();
        let result = Linter::all_lints().lint(&policies);
        assert!(!result.is_empty());
        for finding in result.findings() {
            // The reported lint must be one the linter was actually running.
            assert!(
                Linter::all_lints().runs(finding.lint()),
                "{} is not a known lint",
                finding.lint()
            );
        }
    }
}
