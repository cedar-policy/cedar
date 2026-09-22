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

//! Flags an entity *literal* in the `principal` or `resource` scope.
//!
//! ```cedar
//! permit(principal == User::"alice", action, resource in Album::"vacation");
//! ```
//!
//! A principal or resource pinned by literal is a piece of the authorization
//! *data* baked into policy text. It rots silently — the entity may be renamed or
//! deleted with no signal here — and it escapes review of the entity store and of
//! template links. The intended form is a **linked template**:
//!
//! ```cedar
//! permit(principal == ?principal, action, resource in ?resource);
//! ```
//!
//! with `User::"alice"` / `Album::"vacation"` supplied as a link, so the identity
//! lives in linking data that can be listed, diffed, and access-reviewed.
//!
//! # What is reported
//!
//! Only `principal` and `resource`, and only when the constraint names a concrete
//! entity (`==`, `in`, or `is .. in ..` with an `EUID`). The `action` scope is
//! *exempt*: `action == Action::"view"` is the normal, encouraged way to scope an
//! action, and actions are part of the schema, not runtime data. Slots
//! (`?principal`) and pure type constraints (`principal is User`) name no literal
//! and are not reported.
//!
//! This is a `Restriction`, off by default: a genuine singleton system principal
//! or a well-known root resource is sometimes a legitimate policy-level constant.

use crate::{
    ast::{EntityReference, PrincipalOrResourceConstraint as PrcConstraint, Template, Var},
    linter::findings::{Finding, ScopeEntityLiteral, ScopeLiteral},
};

/// The literal a principal/resource constraint names and the operator-preserving
/// slot rewrite for it, if the constraint pins a concrete entity.
///
/// The rewrite keeps the constraint's operator so the suggestion is a drop-in:
/// `==` → `var == ?var`, `in` → `var in ?var`, `is T in` → `var is T in ?var`.
/// A bare `is T`, a slot, or `Any` name no literal.
fn constraint_literal(var: Var, c: &PrcConstraint) -> Option<ScopeLiteral> {
    let (euid, slot_form) = match c {
        PrcConstraint::Eq(EntityReference::EUID(euid)) => (euid, format!("{var} == ?{var}")),
        PrcConstraint::In(EntityReference::EUID(euid)) => (euid, format!("{var} in ?{var}")),
        PrcConstraint::IsIn(ty, EntityReference::EUID(euid)) => {
            (euid, format!("{var} is {ty} in ?{var}"))
        }
        PrcConstraint::Eq(EntityReference::Slot(_))
        | PrcConstraint::In(EntityReference::Slot(_))
        | PrcConstraint::IsIn(_, EntityReference::Slot(_))
        | PrcConstraint::Is(_)
        | PrcConstraint::Any => return None,
    };
    Some(ScopeLiteral {
        var,
        entity: euid.to_string(),
        slot_form,
    })
}

/// Lint `template`'s principal and resource scope for entity literals.
///
/// Both positions of one policy fold into a *single* finding: the fix — move the
/// pinned entities into template slots — is one edit to one policy, so one finding
/// listing every pinned position reads better than one per position.
pub(crate) fn lint(template: &Template) -> Vec<Finding> {
    let literals: Vec<ScopeLiteral> = [
        (Var::Principal, template.principal_constraint().as_inner()),
        (Var::Resource, template.resource_constraint().as_inner()),
    ]
    .into_iter()
    .filter_map(|(var, constraint)| constraint_literal(var, constraint))
    .collect();

    if literals.is_empty() {
        return Vec::new();
    }
    vec![ScopeEntityLiteral {
        loc: template.loc().cloned(),
        literals,
    }
    .into()]
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::test_util::render;
    use crate::parser::parse_policy_or_template;

    #[track_caller]
    fn lint_report(src: &str) -> String {
        let template = parse_policy_or_template(None, src).expect("failed to parse");
        render(&lint(&template))
    }

    #[test]
    fn principal_equality_literal() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal == User::"alice", action, resource);"#), @r#"
         ⚠ scope pins an entity literal: `principal` names `User::"alice"`
          ╭────
        1 │ permit(principal == User::"alice", action, resource);
          · ─────────────────────────────────────────────────────
          ╰────
         help: replace the literal(s) with slot(s) (`principal == ?principal`) and supply `User::"alice"` as template links; the identities then live in linking data that can be listed and reviewed, not in
               the policy text
        "#);
    }

    #[test]
    fn resource_in_literal() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource in Album::"vacation");"#), @r#"
         ⚠ scope pins an entity literal: `resource` names `Album::"vacation"`
          ╭────
        1 │ permit(principal, action, resource in Album::"vacation");
          · ─────────────────────────────────────────────────────────
          ╰────
         help: replace the literal(s) with slot(s) (`resource in ?resource`) and supply `Album::"vacation"` as template links; the identities then live in linking data that can be listed and reviewed, not
               in the policy text
        "#);
    }

    /// `is .. in ..` with a literal names the literal too.
    #[test]
    fn is_in_literal() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal is User in Group::"admins", action, resource);"#), @r#"
         ⚠ scope pins an entity literal: `principal` names `Group::"admins"`
          ╭────
        1 │ permit(principal is User in Group::"admins", action, resource);
          · ───────────────────────────────────────────────────────────────
          ╰────
         help: replace the literal(s) with slot(s) (`principal is User in ?principal`) and supply `Group::"admins"` as template links; the identities then live in linking data that can be listed and
               reviewed, not in the policy text
        "#);
    }

    /// The action scope is exempt: scoping an action by literal is encouraged.
    #[test]
    fn action_literal_is_exempt() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action == Action::"view", resource);"#), @"");
    }

    /// A slot names no literal.
    #[test]
    fn slot_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal == ?principal, action, resource in ?resource);"#), @"");
    }

    /// A bare type constraint names no literal.
    #[test]
    fn type_constraint_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal is User, action, resource is Photo);"#), @"");
    }

    /// Both principal and resource literals fold into one finding, each with its
    /// own operator-preserving slot suggestion.
    #[test]
    fn both_positions() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal == User::"alice", action, resource == Photo::"p");"#), @r#"
         ⚠ scope pins an entity literal: `principal` names `User::"alice"`, and `resource` names `Photo::"p"`
          ╭────
        1 │ permit(principal == User::"alice", action, resource == Photo::"p");
          · ───────────────────────────────────────────────────────────────────
          ╰────
         help: replace the literal(s) with slot(s) (`principal == ?principal`, `resource == ?resource`) and supply `User::"alice"`, `Photo::"p"` as template links; the identities then live in linking data
               that can be listed and reviewed, not in the policy text
        "#);
    }

    /// An unconstrained scope names nothing.
    #[test]
    fn unconstrained_is_not_reported() {
        insta::assert_snapshot!(lint_report(
            r#"permit(principal, action, resource);"#), @"");
    }
}
