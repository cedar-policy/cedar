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

//! Implements a simple, schema-less, type system for Cedar policies. It doesn't aim to be either
//! sound or complete. The goal is to report some simple mistakes a policy author might make without
//! requiring that they first write a schema.
//!
//! ## Findings
//!
//! * Type errors. These are expressions that will definitely hit an evaluation error (if they are
//!   evaluated). E.g., `Group::"admins".contains(principal)` always errors because `contains`
//!   expects a set operand, but we've given it an entity. These almost always correspond to an
//!   incorrect policy.
//! * Type mismatches. These are suspicious operations combining unrelated types. E.g.,
//!   `(principal.name + principal.uid) == "jane123"` is a almost certainly a mistake because a
//!   comparison between a long and a string is never true. These aren't immediate evaluation
//!   errors, so they can be treated as less severe than type errors, but they still almost always
//!   correspond to and incorrect policy.
//!
//! ## Limitations
//!
//! This a linter, and does not aim to be a sound typechecker. Specifically, it does not know the
//! type of any entity or context attributes and assumes that they are used correctly. E.g.,
//! `resource.is_admin > 2` is assumed to be correct. We do know the type of `is_admin`, so we
//! assume that it is a long.

use std::sync::Arc;

use crate::{
    ast::{BinaryOp, EntityType, Expr, ExprKind, Literal, Name, UnaryOp, Var},
    linter::findings::{
        ActionMember, ActionMemberAccess, Finding, ImpossibleIsCheck, TypeError, TypeMismatch,
    },
};

/// Which side of the action/non-action divide an entity is on.
///
/// Cedar keeps actions distinct from the entities they act on, whatever the
/// schema, so this much of an entity's type is knowable without one — and it is
/// enough to settle several comparisons that would otherwise need a schema.
///
/// An entity type is an action type when its base name is exactly `Action`,
/// namespaced or not ([`EntityType::is_action`]). `MyAction` is not one.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum EntityKind {
    /// The `action` variable, or a literal of an action type.
    Action,
    /// `principal` or `resource`, or a literal of a non-action type.
    ///
    /// A schema could in principle declare an action type as a principal, but the
    /// `appliesTo` machinery is built around actions being distinct from what they
    /// act on, so this pass assumes they are.
    NotAction,
    /// An entity whose action-ness is unknown, e.g. one from an attribute access.
    Unknown,
}

impl EntityKind {
    /// Do these two definitely disagree? Only when both are known and differ.
    fn disjoint(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::Action, Self::NotAction) | (Self::NotAction, Self::Action)
        )
    }

    /// The least upper bound: what is still known when either could hold.
    fn least_upper_bound(self, other: Self) -> Self {
        if self == other {
            self
        } else {
            Self::Unknown
        }
    }

    /// How this reads in a message.
    fn describe(self) -> &'static str {
        match self {
            Self::Action => "an action",
            Self::NotAction => "a non-action",
            Self::Unknown => "an entity of unknown type",
        }
    }

    fn of_entity_type(ty: &EntityType) -> Self {
        if ty.is_action() {
            Self::Action
        } else {
            Self::NotAction
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum Type {
    /// Type of boolean values
    Bool,
    /// Type of integer values
    Long,
    /// Type of string values
    String,
    /// Type of entities, refined by whether the entity is an action.
    ///
    /// The refinement is what lets this pass reject `action == User::"a"` without a
    /// schema: the two are disjoint types rather than both being "entity".
    Entity(EntityKind),
    /// Type of set values.
    Set(Arc<Type>),
    /// Type of a record value. We could track attributes and their types, but
    /// without a schema this would only enable better linting on record
    /// literals, so there's not much reason to support it.
    Record,
    /// Type of an extension value
    Extension(Name),
    /// Type used when the linter doesn't have enough information to assign a
    /// type. Most commonly this is the type of any attributes access. In the
    /// type lattice, this is the top type, but in this linter we effectively
    /// treat it as if it were bottom since we're not trying to be sound.
    Unknown,
    /// Type used for a polymorphic type that can be instantiated as any type.
    /// Used for the type of elements of empty sets and the expected type of set
    /// elements in set operations.
    Any,
}

impl std::fmt::Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Type::Bool => {
                write!(f, "boolean")
            }
            Type::Long => {
                write!(f, "long")
            }
            Type::String => {
                write!(f, "string")
            }
            // Both known kinds are named, so that a mismatch between them reads
            // as a real disagreement rather than "entity and entity". An unknown
            // kind is just an entity: saying more would be noise in the many
            // messages where action-ness is beside the point.
            Type::Entity(EntityKind::Action) => {
                write!(f, "action entity")
            }
            Type::Entity(EntityKind::NotAction) => {
                write!(f, "non-action entity")
            }
            Type::Entity(EntityKind::Unknown) => {
                write!(f, "entity")
            }
            Type::Set(ty) => {
                write!(f, "set of {ty}")
            }
            Type::Record => {
                write!(f, "record")
            }
            Type::Extension(name) => {
                write!(f, "{name}")
            }
            Type::Unknown => {
                write!(f, "unknown type")
            }
            Type::Any => {
                write!(f, "any type")
            }
        }
    }
}

impl Type {
    pub fn least_upper_bound(&self, other: &Type) -> Type {
        match (self, other) {
            _ if self == other => self.clone(),
            (Type::Set(t1), Type::Set(t2)) => Type::Set(Arc::new(t1.least_upper_bound(t2))),
            (Type::Any, ty) | (ty, Type::Any) => ty.clone(),
            // Two entities are still an entity, just without a known kind.
            (Type::Entity(k1), Type::Entity(k2)) => Type::Entity(k1.least_upper_bound(*k2)),
            _ => Type::Unknown,
        }
    }

    pub fn disjoint(&self, other: &Type) -> bool {
        match (self, other) {
            _ if self == other => false,
            (Type::Unknown | Type::Any, _) | (_, Type::Unknown | Type::Any) => false,
            // An action and a non-action can never be equal, so a comparison
            // between them is a mismatch even though both are entities.
            (Type::Entity(k1), Type::Entity(k2)) => k1.disjoint(*k2),
            (Type::Set(elem1), Type::Set(elem2)) => {
                // Not strictly true since both sets could be empty, but this
                // feels more useful for error reporting. An equality between
                // set-of-string and set-of-long should be a findings even
                // though it is true when both sets are empty.
                elem1.disjoint(elem2)
            }
            _ => true,
        }
    }

    pub fn maybe_bool(&self) -> bool {
        matches!(self, Type::Bool | Type::Unknown | Type::Any)
    }

    pub fn maybe_long(&self) -> bool {
        matches!(self, Type::Long | Type::Unknown | Type::Any)
    }

    pub fn maybe_string(&self) -> bool {
        matches!(self, Type::String | Type::Unknown | Type::Any)
    }

    pub fn maybe_entity(&self) -> bool {
        matches!(self, Type::Entity(_) | Type::Unknown | Type::Any)
    }

    /// Is this definitely an action entity?
    pub fn is_action(&self) -> bool {
        matches!(self, Type::Entity(EntityKind::Action))
    }

    /// The action-ness of this type, if it is an entity at all.
    fn entity_kind(&self) -> EntityKind {
        match self {
            Type::Entity(k) => *k,
            _ => EntityKind::Unknown,
        }
    }

    pub fn maybe_set(&self) -> bool {
        matches!(self, Type::Set(_) | Type::Unknown | Type::Any)
    }

    pub fn maybe_set_of_entity(&self) -> bool {
        matches!(self, Type::Set(elem) if elem.maybe_entity())
            || matches!(self, Type::Unknown | Type::Any)
    }

    pub fn maybe_record(&self) -> bool {
        matches!(self, Type::Record | Type::Unknown)
    }

    pub fn maybe_extension(&self, ext: &Name) -> bool {
        matches!(self, Type::Extension(e) if e == ext) || matches!(self, Type::Unknown | Type::Any)
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct TypeLinter {
    errors: Vec<Finding>,
    /// Whether to report attribute and tag accesses on an action.
    ///
    /// These share this pass's type inference but belong to a different lint:
    /// they are legal without a schema and only rejected by strict validation,
    /// so a user can want the type checks without them. See
    /// [`Lint::ActionAttrs`](crate::linter::Lint::ActionAttrs).
    report_action_attrs: bool,
}

impl TypeLinter {
    /// A linter that also reports attribute and tag accesses on an action.
    pub(crate) fn with_action_attrs(mut self, report: bool) -> Self {
        self.report_action_attrs = report;
        self
    }
}

impl TypeLinter {
    /// Consume this linter, returning the findings it accumulated.
    pub(crate) fn into_findings(self) -> Vec<Finding> {
        self.errors
    }
    /// Record a type error saying that `expr` was expected to have type
    /// `expected`, but actually has type `actual`.
    fn type_error(&mut self, expr: &Expr, expected: Type, actual: Type) {
        self.errors.push(
            TypeError {
                loc: expr.source_loc().cloned(),
                expected,
                actual,
            }
            .into(),
        );
    }

    fn type_mismatch(&mut self, expr: &Expr, ty1: Type, ty2: Type) {
        self.errors.push(
            TypeMismatch {
                loc: expr.source_loc().cloned(),
                ty1,
                ty2,
            }
            .into(),
        );
    }

    pub(crate) fn lint(&mut self, expr: &Expr) -> Type {
        match expr.expr_kind() {
            ExprKind::Lit(Literal::Bool(_)) => Type::Bool,
            ExprKind::Lit(Literal::Long(_)) => Type::Long,
            ExprKind::Lit(Literal::String(_)) => Type::String,
            ExprKind::Lit(Literal::EntityUID(uid)) => {
                Type::Entity(EntityKind::of_entity_type(uid.entity_type()))
            }
            // `action` is always an action: the action scope only accepts action
            // literals. `principal` and `resource` are assumed not to be.
            ExprKind::Var(Var::Action) => Type::Entity(EntityKind::Action),
            ExprKind::Var(Var::Principal | Var::Resource) => Type::Entity(EntityKind::NotAction),
            ExprKind::Var(Var::Context) => Type::Record,
            // A slot is filled on link, so its action-ness is unknown here.
            ExprKind::Slot(_) => Type::Entity(EntityKind::Unknown),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                let ty1 = self.lint(test_expr);
                if !ty1.maybe_bool() {
                    self.type_error(test_expr, Type::Bool, ty1);
                }
                let ty2 = self.lint(then_expr);
                let ty3 = self.lint(else_expr);
                ty2.least_upper_bound(&ty3)
            }
            ExprKind::And { left, right } | ExprKind::Or { left, right } => {
                let ty1 = self.lint(left);
                if !ty1.maybe_bool() {
                    self.type_error(left, Type::Bool, ty1);
                }
                let ty2 = self.lint(right);
                if !ty2.maybe_bool() {
                    self.type_error(right, Type::Bool, ty2);
                }
                Type::Bool
            }
            ExprKind::UnaryApp { op, arg } => {
                let ty = self.lint(arg);
                match op {
                    UnaryOp::Not => {
                        if !ty.maybe_bool() {
                            self.type_error(arg, Type::Bool, ty);
                        }
                        Type::Bool
                    }
                    UnaryOp::Neg => {
                        if !ty.maybe_long() {
                            self.type_error(arg, Type::Long, ty);
                        }
                        Type::Long
                    }
                    UnaryOp::IsEmpty => {
                        if !ty.maybe_set() {
                            self.type_error(arg, Type::Set(Arc::new(Type::Any)), ty);
                        }
                        Type::Bool
                    }
                }
            }
            ExprKind::BinaryApp { op, arg1, arg2 } => {
                let ty1 = self.lint(arg1);
                let ty2 = self.lint(arg2);
                match op {
                    BinaryOp::Eq => {
                        if ty1.disjoint(&ty2) {
                            self.type_mismatch(expr, ty1, ty2);
                        }
                        Type::Bool
                    }
                    BinaryOp::Less | BinaryOp::LessEq => {
                        if !ty1.maybe_long() {
                            self.type_error(arg1, Type::Long, ty1);
                        }
                        if !ty2.maybe_long() {
                            self.type_error(arg2, Type::Long, ty2);
                        }
                        Type::Bool
                    }
                    BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul => {
                        if !ty1.maybe_long() {
                            self.type_error(arg1, Type::Long, ty1);
                        }
                        if !ty2.maybe_long() {
                            self.type_error(arg2, Type::Long, ty2);
                        }
                        Type::Long
                    }
                    BinaryOp::In => {
                        if !ty1.maybe_entity() {
                            self.type_error(arg1, Type::Entity(EntityKind::Unknown), ty1.clone());
                        }
                        if !ty2.maybe_entity() && !ty2.maybe_set_of_entity() {
                            // FIXME: error message should also include set option
                            self.type_error(arg2, Type::Entity(EntityKind::Unknown), ty2.clone());
                        }
                        // An action is only ever a member of an action group, and a
                        // non-action is never a member of an action, so a mismatch
                        // here makes the `in` always `false`. For a set operand the
                        // element type is the least upper bound of the elements, so
                        // a mixed set is `Unknown` and correctly not reported: one
                        // matching element is enough to satisfy the `in`.
                        let rhs = match &ty2 {
                            Type::Set(elem) => (**elem).clone(),
                            other => other.clone(),
                        };
                        if ty1.disjoint(&rhs) {
                            self.type_mismatch(expr, ty1, rhs);
                        }
                        Type::Bool
                    }
                    BinaryOp::Contains => {
                        if !ty1.maybe_set() {
                            self.type_error(arg1, Type::Set(Arc::new(Type::Any)), ty1);
                        }
                        Type::Bool
                    }
                    BinaryOp::ContainsAll | BinaryOp::ContainsAny => {
                        if !ty1.maybe_set() {
                            self.type_error(arg1, Type::Set(Arc::new(Type::Any)), ty1);
                        }
                        if !ty2.maybe_set() {
                            self.type_error(arg2, Type::Set(Arc::new(Type::Any)), ty2);
                        }
                        Type::Bool
                    }
                    BinaryOp::GetTag | BinaryOp::HasTag => {
                        if !ty1.maybe_entity() {
                            self.type_error(arg1, Type::Entity(EntityKind::Unknown), ty1.clone());
                        }
                        // A schema cannot declare tags on an action, so this is
                        // rejected by strict validation (though it evaluates fine).
                        if ty1.is_action() && self.report_action_attrs {
                            self.errors.push(
                                ActionMemberAccess {
                                    loc: expr.source_loc().cloned(),
                                    member: ActionMember::Tag,
                                    // A tag name is an arbitrary expression, so
                                    // there is no name to report unless it is a
                                    // string literal.
                                    name: match arg2.expr_kind() {
                                        ExprKind::Lit(Literal::String(s)) => Some(s.to_string()),
                                        _ => None,
                                    },
                                }
                                .into(),
                            );
                        }
                        if !ty2.maybe_string() {
                            self.type_error(arg2, Type::String, ty2);
                        }
                        match op {
                            BinaryOp::HasTag => Type::Bool,
                            _ => Type::Unknown,
                        }
                    }
                }
            }
            ExprKind::ExtensionFunctionApp { args, .. } => {
                for a in args.iter() {
                    self.lint(a);
                }
                Type::Unknown
            }
            ExprKind::GetAttr {
                expr: target, attr, ..
            } => {
                let ty = self.lint(target);
                if !ty.maybe_entity() && !ty.maybe_record() {
                    self.type_error(target, Type::Record, ty.clone());
                }
                // A schema cannot declare attributes on an action, so this is
                // rejected by strict validation (though it evaluates fine).
                if ty.is_action() && self.report_action_attrs {
                    self.errors.push(
                        ActionMemberAccess {
                            loc: expr.source_loc().cloned(),
                            member: ActionMember::Attribute,
                            name: Some(attr.to_string()),
                        }
                        .into(),
                    );
                }
                Type::Unknown
            }
            ExprKind::HasAttr {
                expr: target, attr, ..
            } => {
                let ty = self.lint(target);
                if !ty.maybe_entity() && !ty.maybe_record() {
                    self.type_error(target, Type::Record, ty.clone());
                }
                if ty.is_action() && self.report_action_attrs {
                    self.errors.push(
                        ActionMemberAccess {
                            loc: expr.source_loc().cloned(),
                            member: ActionMember::Attribute,
                            name: Some(attr.to_string()),
                        }
                        .into(),
                    );
                }
                Type::Bool
            }
            ExprKind::Like { expr, .. } => {
                let ty = self.lint(expr);
                if !ty.maybe_string() {
                    self.type_error(expr, Type::String, ty);
                }
                Type::Bool
            }
            ExprKind::Is {
                expr: target,
                entity_type,
            } => {
                let ty = self.lint(target);
                if !ty.maybe_entity() {
                    self.type_error(target, Type::Entity(EntityKind::Unknown), ty.clone());
                }
                // `action is User` and `principal is Action` can never hold.
                let target_kind = ty.entity_kind();
                if target_kind.disjoint(EntityKind::of_entity_type(entity_type)) {
                    self.errors.push(
                        ImpossibleIsCheck {
                            loc: expr.source_loc().cloned(),
                            entity_type: entity_type.to_string(),
                            target: target_kind.describe(),
                        }
                        .into(),
                    );
                }
                Type::Bool
            }
            ExprKind::Set(exprs) => {
                let elem_ty = exprs
                    .iter()
                    .map(|e| self.lint(e))
                    .fold(Type::Any, |ty1, ty2| Type::least_upper_bound(&ty1, &ty2));
                Type::Set(Arc::new(elem_ty))
            }
            ExprKind::Record(attrs) => {
                for v in attrs.values() {
                    self.lint(v);
                }
                Type::Record
            }
            _ => Type::Unknown,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::test_util::render;
    use crate::parser::parse_expr;

    /// Lint `src` and return the pretty miette rendering of all findings,
    /// concatenated. Rendered without color so the snapshots stay readable.
    #[track_caller]
    fn lint_report(src: &str) -> String {
        // Action attribute/tag reporting is on here so that both lints this pass
        // serves are covered; `action_attrs_are_separately_gated` checks that they
        // can be turned off independently.
        let expr = parse_expr(src).expect("failed to parse");
        let mut linter = TypeLinter::default().with_action_attrs(true);
        linter.lint(&expr);
        render(&linter.errors)
    }

    #[test]
    fn if_test_not_bool() {
        insta::assert_snapshot!(lint_report(r#"if "str" then 1 else 2"#), @r#"
         × expected boolean but got string
          ╭────
        1 │ if "str" then 1 else 2
          ·    ─────
          ╰────
        "#);
    }

    #[test]
    fn and_operands_not_bool() {
        insta::assert_snapshot!(lint_report(r#"1 && "two""#), @r#"
         × expected boolean but got long
          ╭────
        1 │ 1 && "two"
          · ─
          ╰────

         × expected boolean but got string
          ╭────
        1 │ 1 && "two"
          ·      ─────
          ╰────
        "#);
    }

    #[test]
    fn get_attr_on_non_record() {
        insta::assert_snapshot!(lint_report(r#""str".foo"#), @r#"
         × expected record but got string
          ╭────
        1 │ "str".foo
          · ─────
          ╰────
        "#);
    }

    #[test]
    fn like_on_non_string() {
        insta::assert_snapshot!(lint_report(r#"principal like "User::\"*/admin/*\"""#), @r#"
         × expected string but got non-action entity
          ╭────
        1 │ principal like "User::\"*/admin/*\""
          · ─────────
          ╰────
        "#);
    }

    #[test]
    fn is_on_non_entity() {
        insta::assert_snapshot!(lint_report(r#"context is User"#), @"
         × expected entity but got record
          ╭────
        1 │ context is User
          · ───────
          ╰────
        ");
    }

    /// Arithmetic has `Long` type, so it can't be used as a boolean.
    #[test]
    fn arith_result_is_long() {
        insta::assert_snapshot!(lint_report(r#"(1 + 1) && true"#), @"
         × expected boolean but got long
          ╭────
        1 │ (1 + 1) && true
          ·  ─────
          ╰────
        ");
    }

    /// Comparison has `Bool` type, so it can't be used as a record.
    #[test]
    fn comparison_result_is_bool() {
        insta::assert_snapshot!(lint_report(r#"(1 < 2).foo"#), @"
         × expected record but got boolean
          ╭────
        1 │ (1 < 2).foo
          ·  ─────
          ╰────
        ");
    }

    #[test]
    fn unary_operand_types() {
        insta::assert_snapshot!(lint_report(r#"!1"#), @"
         × expected boolean but got long
          ╭────
        1 │ !1
          ·  ─
          ╰────
        ");
        insta::assert_snapshot!(lint_report(r#"-true"#), @"
         × expected long but got boolean
          ╭────
        1 │ -true
          ·  ────
          ╰────
        ");
        insta::assert_snapshot!(lint_report(r#""s".isEmpty()"#), @r#"
         × expected set of any type but got string
          ╭────
        1 │ "s".isEmpty()
          · ───
          ╰────
        "#);
        insta::assert_snapshot!(lint_report(r#"context.isEmpty()"#), @"
         × expected set of any type but got record
          ╭────
        1 │ context.isEmpty()
          · ───────
          ╰────
        ");
    }

    #[test]
    fn arith_operand_types() {
        insta::assert_snapshot!(lint_report(r#"principal.name + "b""#), @r#"
         × expected long but got string
          ╭────
        1 │ principal.name + "b"
          ·                  ───
          ╰────
        "#);
    }

    #[test]
    fn comparison_operand_types() {
        insta::assert_snapshot!(lint_report(r#""a" < "b""#), @r#"
         × expected long but got string
          ╭────
        1 │ "a" < "b"
          · ───
          ╰────

         × expected long but got string
          ╭────
        1 │ "a" < "b"
          ·       ───
          ╰────
        "#);
    }

    #[test]
    fn in_operand_types() {
        insta::assert_snapshot!(lint_report(r#"principal.age in [30, 40]"#), @"
         × expected entity but got set of long
          ╭────
        1 │ principal.age in [30, 40]
          ·                  ────────
          ╰────
        ");
        insta::assert_snapshot!(lint_report(r#""this" in principal.those"#), @r#"
         × expected entity but got string
          ╭────
        1 │ "this" in principal.those
          · ──────
          ╰────
        "#);
    }

    #[test]
    fn contains_operand_types() {
        insta::assert_snapshot!(lint_report(r#""foobar".contains(principal.letter)"#), @r#"
         × expected set of any type but got string
          ╭────
        1 │ "foobar".contains(principal.letter)
          · ────────
          ╰────
        "#);
        insta::assert_snapshot!(lint_report(r#"Group::"admins".contains(principal)"#), @r#"
         × expected set of any type but got non-action entity
          ╭────
        1 │ Group::"admins".contains(principal)
          · ───────────────
          ╰────
        "#);
    }

    #[test]
    fn tag_operand_types() {
        insta::assert_snapshot!(lint_report(r#"principal.getTag(1)"#), @"
         × expected string but got long
          ╭────
        1 │ principal.getTag(1)
          ·                  ─
          ╰────
        ");
        insta::assert_snapshot!(lint_report(r#"context.hasTag("t")"#), @r#"
         × expected entity but got record
          ╭────
        1 │ context.hasTag("t")
          · ───────
          ╰────
        "#);
    }

    #[test]
    fn bogus_eq() {
        insta::assert_snapshot!(lint_report(r#"principal == "alice""#), @r#"
         × expression relates two different types non-action entity and string
          ╭────
        1 │ principal == "alice"
          · ────────────────────
          ╰────
        "#);
        insta::assert_snapshot!(lint_report(r#"context == []"#), @"
         × expression relates two different types record and set of any type
          ╭────
        1 │ context == []
          · ─────────────
          ╰────
        ");
        insta::assert_snapshot!(lint_report(r#"(principal.name + principal.uid) == "jane123""#), @r#"
         × expression relates two different types long and string
          ╭────
        1 │ (principal.name + principal.uid) == "jane123"
          · ─────────────────────────────────────────────
          ╰────
        "#);
        insta::assert_snapshot!(lint_report(r#"[1, 2] == ["a", "b"]"#), @r#"
         × expression relates two different types set of long and set of string
          ╭────
        1 │ [1, 2] == ["a", "b"]
          · ────────────────────
          ╰────
        "#);
    }
    // --- `action`-related findings ---
    //
    // These follow from action-ness being part of an entity's type: `action` is
    // always an action and `principal`/`resource` never are. Two different lints
    // come out of that:
    //
    // * The comparisons (`==`, `in`, `is`) are always `false` whatever the schema,
    //   so they are correctness findings.
    // * Attribute and tag accesses evaluate fine without a schema — an action
    //   entity in the store may carry them — but no schema can declare them, so
    //   they are strict-migration findings under a separate lint.

    #[test]
    fn action_attribute_access_is_a_migration_warning() {
        insta::assert_snapshot!(lint_report(r#"action.foo"#), @"
         ⚠ attribute accessed on an action (`foo`)
          ╭────
        1 │ action.foo
          · ──────────
          ╰────
         help: a schema cannot declare attributes on an action, so strict validation will reject this; consider moving the value into the context
        ");
    }

    #[test]
    fn action_has_attribute() {
        insta::assert_snapshot!(lint_report(r#"action has foo"#), @"
         ⚠ attribute accessed on an action (`foo`)
          ╭────
        1 │ action has foo
          · ──────────────
          ╰────
         help: a schema cannot declare attributes on an action, so strict validation will reject this; consider moving the value into the context
        ");
    }

    /// An action literal is an action wherever it appears.
    #[test]
    fn action_literal_attribute_access() {
        insta::assert_snapshot!(lint_report(r#"Action::"view".foo"#), @r#"
         ⚠ attribute accessed on an action (`foo`)
          ╭────
        1 │ Action::"view".foo
          · ──────────────────
          ╰────
         help: a schema cannot declare attributes on an action, so strict validation will reject this; consider moving the value into the context
        "#);
        insta::assert_snapshot!(lint_report(r#"PhotoApp::Action::"view".foo"#), @r#"
         ⚠ attribute accessed on an action (`foo`)
          ╭────
        1 │ PhotoApp::Action::"view".foo
          · ────────────────────────────
          ╰────
         help: a schema cannot declare attributes on an action, so strict validation will reject this; consider moving the value into the context
        "#);
    }

    #[test]
    fn action_tag_access_is_a_migration_warning() {
        insta::assert_snapshot!(lint_report(r#"action.hasTag("t")"#), @r#"
         ⚠ tag accessed on an action (`t`)
          ╭────
        1 │ action.hasTag("t")
          · ──────────────────
          ╰────
         help: a schema cannot declare tags on an action, so strict validation will reject this; consider moving the value into the context
        "#);
        insta::assert_snapshot!(lint_report(r#"action.getTag("t") == """#), @r#"
         ⚠ tag accessed on an action (`t`)
          ╭────
        1 │ action.getTag("t") == ""
          · ──────────────────
          ╰────
         help: a schema cannot declare tags on an action, so strict validation will reject this; consider moving the value into the context
        "#);
    }

    /// The other variables may have attributes and tags.
    #[test]
    fn non_action_attributes_and_tags_are_fine() {
        insta::assert_snapshot!(lint_report(r#"principal.foo"#), @"");
        insta::assert_snapshot!(lint_report(r#"resource has bar"#), @"");
        insta::assert_snapshot!(lint_report(r#"principal.hasTag("t")"#), @"");
    }

    #[test]
    fn action_equals_non_action() {
        insta::assert_snapshot!(lint_report(r#"action == User::"alice""#), @r#"
         × expression relates two different types action entity and non-action entity
          ╭────
        1 │ action == User::"alice"
          · ───────────────────────
          ╰────
        "#);
        insta::assert_snapshot!(lint_report(r#"principal == Action::"view""#), @r#"
         × expression relates two different types non-action entity and action entity
          ╭────
        1 │ principal == Action::"view"
          · ───────────────────────────
          ╰────
        "#);
    }

    /// Comparing like with like is the point of the operator.
    #[test]
    fn matching_kinds_are_fine() {
        insta::assert_snapshot!(lint_report(r#"action == Action::"view""#), @"");
        insta::assert_snapshot!(lint_report(r#"action == PhotoApp::Action::"view""#), @"");
        insta::assert_snapshot!(lint_report(r#"principal == User::"alice""#), @"");
        insta::assert_snapshot!(lint_report(r#"principal == resource"#), @"");
    }

    #[test]
    fn action_in_non_action() {
        insta::assert_snapshot!(lint_report(r#"action in User::"alice""#), @r#"
         × expression relates two different types action entity and non-action entity
          ╭────
        1 │ action in User::"alice"
          · ───────────────────────
          ╰────
        "#);
        insta::assert_snapshot!(lint_report(r#"principal in Action::"view""#), @r#"
         × expression relates two different types non-action entity and action entity
          ╭────
        1 │ principal in Action::"view"
          · ───────────────────────────
          ╰────
        "#);
    }

    #[test]
    fn action_in_action_is_fine() {
        insta::assert_snapshot!(lint_report(r#"action in Action::"readOnly""#), @"");
        insta::assert_snapshot!(lint_report(r#"action in [Action::"a", Action::"b"]"#), @"");
    }

    /// A set of only non-actions cannot contain the action.
    #[test]
    fn action_in_all_non_action_set() {
        insta::assert_snapshot!(lint_report(r#"action in [User::"a", Group::"b"]"#), @r#"
         × expression relates two different types action entity and non-action entity
          ╭────
        1 │ action in [User::"a", Group::"b"]
          · ─────────────────────────────────
          ╰────
        "#);
    }

    /// A mixed set is satisfiable via its action element, so it is not reported.
    /// The element type is the least upper bound of the elements, which is an
    /// entity of unknown action-ness.
    #[test]
    fn mixed_set_in_is_not_reported() {
        insta::assert_snapshot!(lint_report(r#"action in [Action::"a", User::"b"]"#), @"");
        insta::assert_snapshot!(lint_report(r#"principal in [Action::"a", User::"b"]"#), @"");
    }

    #[test]
    fn impossible_is_check() {
        insta::assert_snapshot!(lint_report(r#"action is User"#), @"
         ⚠ an action is never of type `User`
          ╭────
        1 │ action is User
          · ──────────────
          ╰────
         help: `action` is always an action type and `principal`/`resource` never are, so this test is always `false`
        ");
        insta::assert_snapshot!(lint_report(r#"principal is Action"#), @"
         ⚠ a non-action is never of type `Action`
          ╭────
        1 │ principal is Action
          · ───────────────────
          ╰────
         help: `action` is always an action type and `principal`/`resource` never are, so this test is always `false`
        ");
        insta::assert_snapshot!(lint_report(r#"resource is PhotoApp::Action"#), @"
         ⚠ a non-action is never of type `PhotoApp::Action`
          ╭────
        1 │ resource is PhotoApp::Action
          · ────────────────────────────
          ╰────
         help: `action` is always an action type and `principal`/`resource` never are, so this test is always `false`
        ");
    }

    /// `action is Action` is trivially true rather than impossible, and a
    /// non-action `is` a non-action type needs a schema to check.
    #[test]
    fn possible_is_checks_are_fine() {
        insta::assert_snapshot!(lint_report(r#"action is Action"#), @"");
        insta::assert_snapshot!(lint_report(r#"action is PhotoApp::Action"#), @"");
        insta::assert_snapshot!(lint_report(r#"principal is User"#), @"");
    }

    /// Only a base name of exactly `Action` is an action type.
    #[test]
    fn action_lookalike_types() {
        insta::assert_snapshot!(lint_report(r#"principal is MyAction"#), @"");
        insta::assert_snapshot!(lint_report(r#"principal is ActionGroup"#), @"");
        // ... so `action` is disjoint from them.
        insta::assert_snapshot!(lint_report(r#"action is MyAction"#), @"
         ⚠ an action is never of type `MyAction`
          ╭────
        1 │ action is MyAction
          · ──────────────────
          ╰────
         help: `action` is always an action type and `principal`/`resource` never are, so this test is always `false`
        ");
    }

    /// An operand whose action-ness is unknown is left alone: it may hold an action.
    #[test]
    fn unknown_kinds_are_not_reported() {
        insta::assert_snapshot!(lint_report(r#"context.who == Action::"a""#), @"");
        insta::assert_snapshot!(lint_report(r#"context.who in Action::"a""#), @"");
        insta::assert_snapshot!(lint_report(r#"context.who is Action"#), @"");
        insta::assert_snapshot!(lint_report(r#"principal.role == action"#), @"");
    }

    /// An `if` yielding entities of differing action-ness is an entity of unknown
    /// action-ness, not a mismatch.
    #[test]
    fn least_upper_bound_of_kinds() {
        insta::assert_snapshot!(
            lint_report(r#"(if principal.b then action else principal) == User::"a""#), @"");
    }
    /// The action attribute/tag checks belong to a different lint than the type
    /// checks, so they can be disabled while the type checks stay on.
    #[test]
    fn action_attrs_are_separately_gated() {
        let expr = parse_expr(r#"action.foo == 1"#).expect("failed to parse");

        let mut with = TypeLinter::default().with_action_attrs(true);
        with.lint(&expr);
        assert_eq!(with.errors.len(), 1, "the action attribute access");

        let mut without = TypeLinter::default().with_action_attrs(false);
        without.lint(&expr);
        assert!(
            without.errors.is_empty(),
            "nothing to report: the comparison itself is well typed"
        );

        // The type checks are unaffected either way.
        let expr = parse_expr(r#"principal == "alice""#).expect("failed to parse");
        let mut off = TypeLinter::default().with_action_attrs(false);
        off.lint(&expr);
        assert_eq!(off.errors.len(), 1, "the type mismatch is still reported");
    }
}
