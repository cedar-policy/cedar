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

//! Finding types produced by the schema-free policy lints. Aggregated into
//! [`Finding`](super::Finding).

use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

use crate::{
    ast::{Name, Var},
    linter::types::Type,
    parser::Loc,
};

// Shorthand macro for setting the diagnostic severity to Warning. Used for
// lints that flag constructs which are legal today but rejected by strict
// validation, so they only advise about a future migration.
macro_rules! impl_diagnostic_warning {
    () => {
        fn severity(&self) -> Option<miette::Severity> {
            Some(miette::Severity::Warning)
        }
    };
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("expected {expected} but got {actual}")]
pub struct TypeError {
    pub(crate) loc: Option<Loc>,
    pub(crate) expected: Type,
    pub(crate) actual: Type,
}

impl Diagnostic for TypeError {
    impl_diagnostic_from_source_loc_opt_field!(loc);
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("expression relates two different types {ty1} and {ty2}")]
pub struct TypeMismatch {
    pub(crate) loc: Option<Loc>,
    pub(crate) ty1: Type,
    pub(crate) ty2: Type,
}

impl Diagnostic for TypeMismatch {
    impl_diagnostic_from_source_loc_opt_field!(loc);
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`getTag` is not preceded by corresponding `hasTag")]
pub struct TagError {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for TagError {
    impl_diagnostic_from_source_loc_opt_field!(loc);
}

/// An empty set literal. Legal today, but rejected by strict validation, which
/// cannot assign the empty set an element type. Warned about to ease migration.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("empty set literal")]
pub struct EmptySet {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for EmptySet {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "strict validation forbids empty set literals because it cannot infer their element type",
        ))
    }
}

/// An extension constructor called with a non-literal argument. Legal today,
/// but rejected by strict validation, which can only check constructor
/// arguments it can evaluate statically. Warned about to ease migration.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("extension constructor `{fn_name}` called with a non-literal argument")]
pub struct NonLitExtConstructor {
    pub(crate) loc: Option<Loc>,
    pub(crate) fn_name: Name,
}

impl Diagnostic for NonLitExtConstructor {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "consider applying extension constructors inside attribute values when constructing entity or context data",
        ))
    }
}

/// An extension constructor called with a literal argument that fails to parse.
/// Unlike the two warnings above, this is always a bug: the call is guaranteed
/// to error at evaluation time.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`{fn_name}` cannot be constructed from `{arg}`: {err}")]
pub struct ExtConstructorError {
    pub(crate) loc: Option<Loc>,
    pub(crate) fn_name: Name,
    pub(crate) arg: String,
    pub(crate) err: String,
    pub(crate) err_help: Option<String>,
}

impl Diagnostic for ExtConstructorError {
    impl_diagnostic_from_source_loc_opt_field!(loc);

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.err_help
            .as_ref()
            .map(|h| Box::new(h) as Box<dyn std::fmt::Display + 'a>)
    }
}

/// A multiplication where neither operand is a constant. Legal and cheap to
/// evaluate, but hard to *analyze*: symbolic analysis compiles `Long` to a
/// fixed-width bitvector, and a variable-by-variable multiply bit-blasts to a
/// multiplier circuit that SAT/SMT solvers reason through slowly. Multiplying by
/// a constant lowers to shifts and adds and stays cheap.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("multiplication of two non-constant expressions")]
pub struct NonLinearArithmetic {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for NonLinearArithmetic {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "multiplying two variables bit-blasts to a multiplier circuit that automated reasoning tools solve slowly; multiplying by a constant avoids it",
        ))
    }
}

/// Arithmetic in a `forbid` policy. Arithmetic errors on overflow, and a policy
/// whose condition errors is skipped, so an overflow here silently drops the
/// `forbid` and may allow a request that should have been denied.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("arithmetic in a `forbid` policy may cause the policy to be skipped")]
pub struct ArithmeticInForbid {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for ArithmeticInForbid {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "arithmetic errors on overflow, and a policy whose condition errors is skipped, so this `forbid` may fail to deny a request; consider bounding the operands or moving the arithmetic into the data",
        ))
    }
}

/// Arithmetic in a `permit` policy. Same mechanism as [`ArithmeticInForbid`],
/// but skipping a `permit` fails closed, so this is only a warning.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("arithmetic in a `permit` policy may cause the policy to be skipped")]
pub struct ArithmeticInPermit {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for ArithmeticInPermit {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "arithmetic errors on overflow, and a policy whose condition errors is skipped, so this `permit` may fail to allow a request",
        ))
    }
}
/// A `like` pattern with no wildcard, which is just a string equality.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`like` pattern `\"{pattern}\"` contains no wildcard")]
pub struct LikeWithoutWildcard {
    pub(crate) loc: Option<Loc>,
    pub(crate) pattern: String,
}

impl Diagnostic for LikeWithoutWildcard {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "this matches only the one exact string; use `==` to compare strings, or add a `*` wildcard",
        ))
    }
}

/// A `like` pattern of only wildcards, which matches every string.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`like` pattern `\"{pattern}\"` matches every string")]
pub struct LikeWithOnlyWildcards {
    pub(crate) loc: Option<Loc>,
    pub(crate) pattern: String,
}

impl Diagnostic for LikeWithOnlyWildcards {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "this comparison is always true for a string operand, so it has no effect",
        ))
    }
}

/// A `like` pattern with two or more consecutive wildcards, e.g. `"a**b"`. A run of
/// `*`s matches exactly what a single `*` matches, so the extra ones are redundant.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`like` pattern `\"{pattern}\"` has consecutive wildcards")]
pub struct LikeWithConsecutiveWildcards {
    pub(crate) loc: Option<Loc>,
    pub(crate) pattern: String,
}

impl Diagnostic for LikeWithConsecutiveWildcards {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "a run of `*`s matches the same as a single `*`; collapse each run to one wildcard",
        ))
    }
}

/// Two `like` patterns on the same operand — a prefix constraint (`"cs*"`) and a
/// suffix constraint (`"*p"`) — that combine into one equivalent pattern
/// (`"cs*p"`). Only reported when the prefix and suffix literals cannot overlap, so
/// the merge is exactly equivalent (see the lint docs).
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`like` patterns `\"{prefix}\"` and `\"{suffix}\"` on the same operand combine into one")]
pub struct CombinableLikePatterns {
    /// Anchored at the first of the two patterns in source order.
    pub(crate) loc: Option<Loc>,
    /// The prefix-constraint pattern (`"cs*"`), as written.
    pub(crate) prefix: String,
    /// The suffix-constraint pattern (`"*p"`), as written.
    pub(crate) suffix: String,
    /// The single equivalent pattern (`"cs*p"`).
    pub(crate) merged: String,
}

impl Diagnostic for CombinableLikePatterns {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "the prefix and suffix cannot overlap, so together they are exactly `like \"{}\"`; use that single pattern",
            self.merged,
        )))
    }
}

/// A universal `permit` in a policy set that contains other `permit`s, which it
/// makes redundant.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("this `permit` applies to every request, making the other `permit` policies redundant")]
pub struct PermitAllSubsumesPermits {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for PermitAllSubsumesPermits {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "it allows everything the other, constrained `permit` policies were written to allow selectively",
        ))
    }
}

/// A universal `permit` in a policy set with no `forbid`, so nothing can deny a
/// request.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("this `permit` applies to every request, and no `forbid` policy can deny one")]
pub struct PermitAllWithoutForbid {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for PermitAllWithoutForbid {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "every request is allowed; add a `forbid` policy or constrain this one",
        ))
    }
}

/// A universal `forbid`, which denies every request and so makes every other
/// policy in the set unreachable.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("this `forbid` applies to every request, making every other policy unreachable")]
pub struct ForbidAllSubsumesPolicies {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for ForbidAllSubsumesPolicies {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "`forbid` overrides every `permit`, so this denies all requests and the rest of the policy set has no effect",
        ))
    }
}

/// A `forbid` in a policy set containing no `permit`, so nothing is ever allowed
/// regardless.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("this `forbid` is in a policy set with no `permit` policy")]
pub struct ForbidWithoutPermit {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for ForbidWithoutPermit {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "Cedar denies by default, so every request is already denied and this `forbid` changes nothing; the policy set may be missing a `permit`",
        ))
    }
}

/// An attribute access in a `forbid` policy that no `has` check guards. If the
/// attribute is absent the access errors, the `forbid` is skipped, and the
/// request may be allowed by some `permit`.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("attribute `{attr}` is accessed in a `forbid` policy without a `has` guard")]
pub struct UnguardedAttrInForbid {
    pub(crate) loc: Option<Loc>,
    pub(crate) attr: SmolStr,
    /// How the target reads in source, for the suggested guard, e.g. `principal`
    /// for `principal.admin`.
    pub(crate) target: String,
}

impl Diagnostic for UnguardedAttrInForbid {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "if `{attr}` is absent the condition errors and the `forbid` is skipped, so the request may be allowed; guard the access with `{target} has {attr} &&`",
            attr = self.attr,
            target = self.target,
        )))
    }
}

/// An attribute access in a `permit` policy that no `has` check guards. Same
/// mechanism as [`UnguardedAttrInForbid`], but skipping a `permit` fails closed:
/// the request is denied rather than allowed. Still worth flagging, since the
/// `permit` silently stops working.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("attribute `{attr}` is accessed in a `permit` policy without a `has` guard")]
pub struct UnguardedAttrInPermit {
    pub(crate) loc: Option<Loc>,
    pub(crate) attr: SmolStr,
    /// How the target reads in source, for the suggested guard, e.g. `principal`
    /// for `principal.admin`.
    pub(crate) target: String,
}

impl Diagnostic for UnguardedAttrInPermit {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "if `{attr}` is absent the condition errors and the `permit` is skipped, so the request may be denied; guard the access with `{target} has {attr} &&`",
            attr = self.attr,
            target = self.target,
        )))
    }
}

/// A comparison between a scope variable and an entity literal, written in a
/// condition where the policy scope could express it directly.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`{var} {op} ..` belongs in the policy scope, not in a condition")]
pub struct ScopeConstraintInCondition {
    pub(crate) loc: Option<Loc>,
    pub(crate) var: Var,
    /// The operator as it reads in source, `==` or `in`.
    pub(crate) op: &'static str,
}

impl Diagnostic for ScopeConstraintInCondition {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "write it as `{var} {op} ..` in the scope instead; the scope is what lets a policy store slice on this constraint, and what a reader sees first",
            var = self.var,
            op = self.op,
        )))
    }
}

/// An expression written the long way round, where Cedar has syntax that says the
/// same thing. A pure rewrite: both forms evaluate identically.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("{wrote} can be written more directly")]
pub struct PreferSugar {
    pub(crate) loc: Option<Loc>,
    /// What was written, as it reads in source.
    pub(crate) wrote: String,
    /// What to write instead.
    pub(crate) prefer: String,
}

impl Diagnostic for PreferSugar {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "prefer {}; the two are equivalent for every input",
            self.prefer
        )))
    }
}

/// A boolean-valued expression written the long way round: compared against a
/// boolean literal, or produced by an `if` whose branches are `true`/`false`.
/// A pure rewrite; both forms evaluate identically.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("{wrote} is redundant")]
pub struct RedundantBoolean {
    pub(crate) loc: Option<Loc>,
    /// What was written, as it reads in source.
    pub(crate) wrote: String,
    /// What to write instead.
    pub(crate) prefer: String,
}

impl Diagnostic for RedundantBoolean {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "write {} instead; the two are equivalent for every input",
            self.prefer
        )))
    }
}

/// An `expr["key"]` access whose key is a legal identifier, so `expr.key` says the
/// same thing more directly.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`[\"{key}\"]` can be written as `.{key}`")]
pub struct IndexWithLiteralKey {
    pub(crate) loc: Option<Loc>,
    pub(crate) key: String,
}

impl Diagnostic for IndexWithLiteralKey {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "`.{key}` is the idiomatic form; the index form is needed only when the key is not a legal identifier",
            key = self.key,
        )))
    }
}

/// A pair of parentheses immediately inside another pair, which cannot affect
/// precedence.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("redundant parentheses")]
pub struct RedundantParens {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for RedundantParens {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "this pair is already inside another, so it cannot change how the expression parses",
        ))
    }
}

/// An `unless` clause whose body is negated, which is a double negative since the
/// clause itself negates.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`unless` with a negated body is a double negative")]
pub struct UnlessWithNegation {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for UnlessWithNegation {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "`unless` already negates, so drop the `!` and use `when` instead",
        ))
    }
}

/// An `in` whose right operand is a one-element set literal. `x in [E]` and
/// `x in E` are evaluated identically, so the set adds nothing.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`in` against a one-element set")]
pub struct SingletonSetIn {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for SingletonSetIn {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "`in` accepts a single entity directly, so the surrounding `[..]` can be dropped",
        ))
    }
}

/// An addition of a negative literal, i.e. `a + -1`, which reads as a subtraction.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("adding a negative literal")]
pub struct PlusNegativeLiteral {
    pub(crate) loc: Option<Loc>,
    /// The literal's magnitude, for the suggested rewrite.
    pub(crate) magnitude: String,
}

impl Diagnostic for PlusNegativeLiteral {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "write `- {mag}` instead; both compute the same value and overflow in the same cases",
            mag = self.magnitude,
        )))
    }
}

/// A policy whose scope constrains none of `principal`, `action`, or `resource`
/// — the bare `permit(principal, action, resource)` form. The `no-unconstrained-
/// scope` restriction asks every policy to anchor somewhere in the request space
/// so its reach is visible from the scope alone.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("this {effect} constrains nothing in its scope")]
pub struct UnconstrainedScope {
    pub(crate) loc: Option<Loc>,
    pub(crate) effect: &'static str,
}

impl Diagnostic for UnconstrainedScope {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "constrain at least one of `principal`, `action`, or `resource` in the scope (with `==`, `in`, or `is`), so the policy's reach is visible without reading the condition and a policy store can slice on it; a deliberately global policy can suppress this",
        ))
    }
}

/// One entity literal pinned in a scope position, with the exact slot rewrite
/// that preserves its constraint operator.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ScopeLiteral {
    /// The scope variable — `principal` or `resource`.
    pub(crate) var: Var,
    /// The entity named, e.g. ``User::"alice"``.
    pub(crate) entity: String,
    /// The scope form with the literal replaced by a slot, preserving the
    /// operator: ``principal == ?principal``, ``resource in ?resource``, or
    /// ``principal is User in ?principal``.
    pub(crate) slot_form: String,
}

/// Entity literals in the `principal` and/or `resource` scope of one policy, e.g.
/// `permit(principal == User::"alice", ...)`. The identities are data baked into
/// policy text; a linked template keeps them in template-linking data instead. One
/// finding per policy covers both positions when both are literals.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("{}", scope_literal_headline(&self.literals))]
pub struct ScopeEntityLiteral {
    pub(crate) loc: Option<Loc>,
    /// The scope positions that name a literal, in scope order (principal before
    /// resource). Never empty.
    pub(crate) literals: Vec<ScopeLiteral>,
}

/// The headline naming the position(s) and entity(ies) a scope pins by literal.
fn scope_literal_headline(literals: &[ScopeLiteral]) -> String {
    let parts: Vec<String> = literals
        .iter()
        .map(|l| format!("`{}` names `{}`", l.var, l.entity))
        .collect();
    format!("scope pins an entity literal: {}", parts.join(", and "))
}

impl Diagnostic for ScopeEntityLiteral {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        // Suggest the operator-preserving slot rewrite for every pinned position.
        let slots: Vec<String> = self
            .literals
            .iter()
            .map(|l| format!("`{}`", l.slot_form))
            .collect();
        let links: Vec<String> = self
            .literals
            .iter()
            .map(|l| format!("`{}`", l.entity))
            .collect();
        Some(Box::new(format!(
            "replace the literal(s) with slot(s) ({slots}) and supply {links} as template links; the identities then live in linking data that can be listed and reviewed, not in the policy text",
            slots = slots.join(", "),
            links = links.join(", "),
        )))
    }
}

/// An attribute or tag access chain, rooted at a request variable, deeper than
/// the configured bound. Each step is a store lookup and a hop the analyzer must
/// follow; the bound caps both.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("access chain is {depth} levels deep, over the bound of {bound}")]
pub struct AttributeTooDeep {
    pub(crate) loc: Option<Loc>,
    pub(crate) depth: usize,
    pub(crate) bound: usize,
}

impl Diagnostic for AttributeTooDeep {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "each attribute or tag access on an entity is a store lookup at evaluation time and a dereference the analyzer must follow; a shallower chain (e.g. denormalizing the value onto a nearer entity) keeps evaluation and analysis within a fixed bound. This counts syntactic access depth, so it is an upper bound on the RFC 76 entity-dereference level",
        ))
    }
}

/// A `forbid` whose condition, with attribute `attr` absent, evaluates to `false`
/// — the `forbid` does not fire and fails open. The `has` guard that was meant to
/// protect the access is what turns the missing attribute into `false` instead of
/// an error; the fail-closed rewrite makes the missing attribute *fire* the forbid.
///
/// This is a semantic property, not a fixed syntactic shape: it holds for
/// `e has a && e.a`, `if e has a then e.a else false`, `e has a && e.a == true`,
/// and any other condition that folds to `false` when `a` is absent.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`forbid` fails open when `{attr}` is absent")]
pub struct ForbidGuardFailsOpen {
    pub(crate) loc: Option<Loc>,
    pub(crate) attr: SmolStr,
}

impl Diagnostic for ForbidGuardFailsOpen {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        let attr = &self.attr;
        Some(Box::new(format!(
            "when `{attr}` is absent this condition is `false`, so the `forbid` does not fire and a missing attribute fails open; restructure so a missing `{attr}` makes the condition true (e.g. `!(e has {attr}) || <uses {attr}>`, or `if e has {attr} then <uses {attr}> else true`) to fire the `forbid` instead. Note this denies every entity lacking `{attr}`, which may be more restrictive than intended",
        )))
    }
}

/// An `x is T && x in E` that the combined `x is T in E` form expresses directly.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`is` and `in` on the same operand can be combined")]
pub struct SeparateIsAndIn {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for SeparateIsAndIn {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "Cedar has an `is .. in ..` form that states both constraints at once",
        ))
    }
}

/// Arithmetic negation applied twice, as in `- -x`. Computes the operand back
/// again, so it says nothing `x` alone does not — while adding an overflow failure
/// mode, since negating `i64::MIN` errors. Almost certainly not what was intended.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("negation applied twice")]
pub struct DoubleNegation {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for DoubleNegation {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "negating twice computes the operand back again, and errors on `i64::MIN` where the operand alone would not; did you mean a subtraction, or the logical `!`?",
        ))
    }
}

/// Which kind of member was accessed on an action.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ActionMember {
    /// An attribute, as in `action.foo` or `action has foo`.
    Attribute,
    /// A tag, as in `action.getTag("t")` or `action.hasTag("t")`.
    Tag,
}

impl std::fmt::Display for ActionMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionMember::Attribute => write!(f, "attribute"),
            ActionMember::Tag => write!(f, "tag"),
        }
    }
}

/// An attribute or tag access on an action.
///
/// Legal today: an action entity in the store may carry attributes and tags, and
/// Cedar evaluates the access normally. But a schema cannot declare either on an
/// action, so strict validation rejects the policy. Warned about to ease migration.
///
/// Attributes and tags are one finding because the cause, the consequence, and the
/// fix are the same; the `member` field says which was written.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("{member} accessed on an action{}", match &self.name {
    Some(n) => format!(" (`{n}`)"),
    None => String::new(),
})]
pub struct ActionMemberAccess {
    pub(crate) loc: Option<Loc>,
    pub(crate) member: ActionMember,
    /// The attribute name, where it is statically known. A tag name is an
    /// arbitrary expression, so it is often absent.
    pub(crate) name: Option<String>,
}

impl Diagnostic for ActionMemberAccess {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "a schema cannot declare {member}s on an action, so strict validation will reject this; consider moving the value into the context",
            member = self.member,
        )))
    }
}

/// An `is` test that no entity can satisfy, because the operand is known to be an
/// action and the type named is not, or vice versa.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("{target} is never of type `{entity_type}`")]
pub struct ImpossibleIsCheck {
    pub(crate) loc: Option<Loc>,
    pub(crate) entity_type: String,
    pub(crate) target: &'static str,
}

impl Diagnostic for ImpossibleIsCheck {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "`action` is always an action type and `principal`/`resource` never are, so this test is always `false`",
        ))
    }
}

/// A comparison whose two operands are syntactically identical, e.g.
/// `principal == principal`. Almost always a mistake — one operand was likely
/// meant to be something else. What it does at runtime varies (always true,
/// always an error, or a type error), so the finding reports the shape.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("both operands of this comparison are the same expression")]
pub struct SelfComparison {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for SelfComparison {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "comparing a value to itself is redundant; did you mean to compare it to something else?",
        ))
    }
}

/// A constant expression standing where a condition is expected, e.g.
/// `when { false }`. It has the same value for every request, so it is dead code
/// or a placeholder rather than a real condition.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("this condition is constant")]
pub struct ConstantCondition {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for ConstantCondition {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "it does not depend on the request, so it is the same for every one; remove it, or replace it with the intended condition",
        ))
    }
}

/// An `&&` or `||` whose two operands are syntactically identical, e.g.
/// `a && a`, which is just `a`.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("both operands of `{op}` are the same expression")]
pub struct RepeatedLogicalOperand {
    pub(crate) loc: Option<Loc>,
    pub(crate) op: &'static str,
}

impl Diagnostic for RepeatedLogicalOperand {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "this is equivalent to the operand on its own; did you mean a different operand on one side?",
        ))
    }
}

/// An `if` whose `then` and `else` branches are syntactically identical, so the
/// condition makes no difference.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("both branches of this `if` are the same expression")]
pub struct IdenticalIfBranches {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for IdenticalIfBranches {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "the condition has no effect since both branches are identical; use the branch expression directly",
        ))
    }
}

/// A set literal containing an element equal to an earlier one, e.g. `[1, 2, 1]`.
/// The duplicate does not change the set's value.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("this set element is a duplicate")]
pub struct DuplicateSetElement {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for DuplicateSetElement {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "it already appears earlier in the set, so it has no effect; remove it",
        ))
    }
}

/// A policy syntactically identical to an earlier one in the same set — same
/// effect, same condition. The duplicate authorizes nothing the original does
/// not, so it is dead weight, usually a copy-paste or merge artifact.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("this policy is a duplicate of `{original}`")]
pub struct DuplicatePolicy {
    pub(crate) loc: Option<Loc>,
    /// The ID of the first policy with this effect and condition.
    pub(crate) original: String,
}

impl Diagnostic for DuplicatePolicy {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "it has the same effect and condition as `{original}`, so it has no additional effect; remove one of them",
            original = self.original,
        )))
    }
}

/// A comparison with a literal on the left of `==`, e.g. `5 == context.n`, which
/// reads more naturally with the literal on the right. Purely a readability
/// finding: the two forms are identical.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("literal on the left of `==`")]
pub struct YodaCondition {
    pub(crate) loc: Option<Loc>,
}

impl Diagnostic for YodaCondition {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "put the variable first and the literal second, as in `x == 5`; the two are equivalent",
        ))
    }
}
