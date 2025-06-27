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

//! Implementation of level validation (RFC 76)

use super::*;
use crate::ast::{BinaryOp, Expr, ExprKind, Literal, PolicyID};
use crate::validator::types::{EntityRecordKind, RequestEnv, Type};
use smol_str::SmolStr;
use thiserror::Error;
use typecheck::PolicyCheck;

/// Represents how many entity dereferences can be applied to a node.
#[derive(Default, Debug, Clone, Hash, Eq, PartialEq, Error, Copy, Ord, PartialOrd)]
pub struct EntityDerefLevel {
    level: u32,
}

impl std::fmt::Display for EntityDerefLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}", self.level)
    }
}

impl<I: Into<u32>> From<I> for EntityDerefLevel {
    fn from(value: I) -> Self {
        EntityDerefLevel {
            level: value.into(),
        }
    }
}

impl EntityDerefLevel {
    fn increment(self) -> Self {
        (self.level + 1).into()
    }

    fn zero() -> Self {
        EntityDerefLevel { level: 0 }
    }
}

impl Validator {
    /// Run `validate_policy` against a single static policy or template (note
    /// that Core `Template` includes static policies as well), gathering all
    /// validation errors and warnings in the returned iterators.
    /// If validation passes, we will also perform level validation (see RFC 76).
    pub(crate) fn validate_policy_with_level<'a>(
        &'a self,
        p: &'a Template,
        mode: ValidationMode,
        max_deref_level: u32,
    ) -> (
        impl Iterator<Item = ValidationError> + 'a,
        impl Iterator<Item = ValidationWarning> + 'a,
    ) {
        let (errors, warnings) = self.validate_policy(p, mode);

        let mut peekable_errors = errors.peekable();

        // Only perform level validation if validation passed.
        if peekable_errors.peek().is_none() {
            let typechecker = Typechecker::new(&self.schema, mode);
            let type_annotated_asts = typechecker.typecheck_by_request_env(p);
            let mut level_checker = LevelChecker {
                policy_id: p.id(),
                max_level: max_deref_level.into(),
                level_checking_errors: HashSet::new(),
            };
            for (req_env, policy_check) in type_annotated_asts {
                match policy_check {
                    PolicyCheck::Success(e) | PolicyCheck::Irrelevant(_, e) => {
                        level_checker.check_expr_level(&e, &req_env);
                    }
                    // PANIC SAFETY: We only validate the level after validation passed
                    #[allow(clippy::unreachable)]
                    PolicyCheck::Fail(_) => unreachable!(),
                }
            }
            (
                peekable_errors.chain(level_checker.level_checking_errors),
                warnings,
            )
        } else {
            (peekable_errors.chain(HashSet::new()), warnings)
        }
    }
}

#[derive(Debug)]
struct LevelChecker<'a> {
    /// ID of the policy we're typechecking; used for associating any validation
    /// errors with the correct policy ID
    policy_id: &'a PolicyID,
    max_level: EntityDerefLevel,
    level_checking_errors: HashSet<ValidationError>,
}

impl LevelChecker<'_> {
    /// Check the level of the target of an entity dereference.
    ///
    /// We assume the expression has passed the typechecker, so the target of an
    /// entity deference will be an entity type expression. If this function is
    /// initially called on a non-entity-type expression it will return in an
    /// `InternalInvariantViolation`.
    ///
    /// In order to handle attributes access on records containing entities
    /// (e.g., `{foo: principal}.foo.bar`), this function track an `access_path`
    /// of record attributes accessed by the expression. This generalizes the
    /// precondition on `e` so that this function can be called if `e` is a
    /// record literal with a attribute `a` such that `access_path.pop() == some(a)`
    /// and the expression for `a` recursively satisfies the precondition.
    /// For `{foo: principal}.foo.bar` the recursive call on `{foo: principal}`
    /// is made with access path `[foo]`.
    fn check_entity_deref_target_level(
        &mut self,
        e: &Expr<Option<Type>>,
        mut access_path: Vec<SmolStr>,
        env: &RequestEnv<'_>,
    ) -> EntityDerefLevel {
        match e.expr_kind() {
            ExprKind::Var(_) => EntityDerefLevel::zero(),
            // A slot cannot currently appear in an entity dereference position,
            // but, if it could, we would handle it as an entity literal.
            ExprKind::Slot(_) => {
                self.level_checking_errors
                    .insert(ValidationError::literal_dereference_target(
                        e.source_loc().cloned(),
                        self.policy_id.clone(),
                    ));
                EntityDerefLevel::zero()
            }
            ExprKind::Lit(Literal::EntityUID(euid)) => {
                // Allow a literal if it's the current request env's action entity. This is mainly
                // an artifact of what is convenient in the Lean implementation.
                if Some(euid.as_ref()) != env.action_entity_uid() {
                    self.level_checking_errors
                        .insert(ValidationError::literal_dereference_target(
                            e.source_loc().cloned(),
                            self.policy_id.clone(),
                        ));
                }
                EntityDerefLevel::zero()
            }
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                self.check_expr_level(test_expr, env);
                let then_lvl =
                    self.check_entity_deref_target_level(then_expr, access_path.clone(), env);
                let else_lvl = self.check_entity_deref_target_level(else_expr, access_path, env);
                then_lvl.max(else_lvl)
            }
            // We don't need to handle `HasAttr` here because it has type Boolean.
            ExprKind::GetAttr { expr, attr } => match expr.data() {
                Some(Type::EntityOrRecord(EntityRecordKind::Entity { .. })) => self
                    .check_entity_deref_target_level(expr, access_path, env)
                    .increment(),
                Some(Type::EntityOrRecord(EntityRecordKind::Record { .. })) => {
                    // We push `attr` onto the access path so that, if the
                    // target of the `getAttr` is a literal, we can avoid
                    // reporting false positives for the unaccessed branches.
                    access_path.push(attr.clone());
                    self.check_entity_deref_target_level(expr, access_path, env)
                }
                // The typechecker ensures `GetAttr` only applies to entities and records. This also
                // captures `AnyEntity` and `ActionEntity` because these types will never have any attributes.
                _ => {
                    self.level_checking_errors.insert(
                        ValidationError::internal_invariant_violation(
                            e.source_loc().cloned(),
                            self.policy_id.clone(),
                        ),
                    );
                    EntityDerefLevel::zero()
                }
            },
            ExprKind::BinaryApp {
                // We don't need to handle `HasTag` or `In` here because they have type Boolean.
                op: BinaryOp::GetTag,
                arg1,
                arg2,
            } => {
                let deref_target_level =
                    self.check_entity_deref_target_level(arg1, access_path, env);
                self.check_expr_level(arg2, env);
                deref_target_level.increment()
            }
            ExprKind::Record(attrs) => {
                match access_path
                    .pop()
                    .and_then(|a| attrs.get_key_value(a.as_str()))
                {
                    Some((attr, accessed_e)) => {
                        for (_, e) in attrs.iter().filter(|(a, _)| *a != attr) {
                            self.check_expr_level(e, env);
                        }
                        self.check_entity_deref_target_level(accessed_e, access_path, env)
                    }
                    // From the `access_path` precondition, for a record
                    // literal, the access path be non-empty and start with an
                    // attribtue in the record literal.
                    None => {
                        self.level_checking_errors.insert(
                            ValidationError::internal_invariant_violation(
                                e.source_loc().cloned(),
                                self.policy_id.clone(),
                            ),
                        );
                        EntityDerefLevel::zero()
                    }
                }
            }

            // We only ever call this function on the target of entity
            // derferencing expressions, so a non-entity-type expressions
            // shouldn't be possible.
            _ => {
                self.level_checking_errors
                    .insert(ValidationError::internal_invariant_violation(
                        e.source_loc().cloned(),
                        self.policy_id.clone(),
                    ));
                EntityDerefLevel::zero()
            }
        }
    }

    fn check_expr_level(
        &mut self,
        e: &Expr<Option<crate::validator::types::Type>>,
        env: &RequestEnv<'_>,
    ) {
        match e.expr_kind() {
            ExprKind::Lit(_) | ExprKind::Var(_) | ExprKind::Slot(_) | ExprKind::Unknown(_) => (),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                self.check_expr_level(test_expr, env);
                self.check_expr_level(then_expr, env);
                self.check_expr_level(else_expr, env);
            }
            ExprKind::Or { left, right } | ExprKind::And { left, right } => {
                self.check_expr_level(left, env);
                self.check_expr_level(right, env);
            }
            ExprKind::UnaryApp { arg, .. } => {
                self.check_expr_level(arg, env);
            }
            ExprKind::BinaryApp {
                op: BinaryOp::HasTag | BinaryOp::GetTag | BinaryOp::In,
                arg1,
                arg2,
            } => {
                let deref_target_lvl = self.check_entity_deref_target_level(arg1, Vec::new(), env);
                if deref_target_lvl >= self.max_level {
                    self.level_checking_errors
                        .insert(ValidationError::maximum_level_exceeded(
                            e.source_loc().cloned(),
                            self.policy_id.clone(),
                            self.max_level,
                            deref_target_lvl.increment(),
                        ));
                }
                self.check_expr_level(arg2, env);
            }
            ExprKind::BinaryApp { arg1, arg2, .. } => {
                self.check_expr_level(arg1, env);
                self.check_expr_level(arg2, env);
            }
            ExprKind::ExtensionFunctionApp { args, .. } => {
                for arg in args.iter() {
                    self.check_expr_level(arg, env);
                }
            }
            ExprKind::HasAttr { expr, .. } | ExprKind::GetAttr { expr, .. } => match expr.data() {
                Some(Type::EntityOrRecord(EntityRecordKind::Entity { .. })) => {
                    let deref_target_lvl =
                        self.check_entity_deref_target_level(expr, Vec::new(), env);
                    if deref_target_lvl >= self.max_level {
                        self.level_checking_errors
                            .insert(ValidationError::maximum_level_exceeded(
                                e.source_loc().cloned(),
                                self.policy_id.clone(),
                                self.max_level,
                                deref_target_lvl.increment(),
                            ));
                    }
                }
                Some(Type::EntityOrRecord(EntityRecordKind::Record { .. })) => {
                    self.check_expr_level(expr, env);
                }
                // The typechecker ensures `GetAttr` only applies to entities and records. This also
                // captures `AnyEntity` and `ActionEntity` because these types will never have any attributes.
                _ => {
                    self.level_checking_errors.insert(
                        ValidationError::internal_invariant_violation(
                            e.source_loc().cloned(),
                            self.policy_id.clone(),
                        ),
                    );
                }
            },
            ExprKind::Like { expr, .. } => {
                self.check_expr_level(expr, env);
            }
            ExprKind::Is { expr, .. } => {
                self.check_expr_level(expr, env);
            }
            ExprKind::Set(exprs) => {
                for e in exprs.iter() {
                    self.check_expr_level(e, env);
                }
            }
            ExprKind::Record(attrs) => {
                for (_, e) in attrs.iter() {
                    self.check_expr_level(e, env);
                }
            }
            #[cfg(feature = "tolerant-ast")]
            ExprKind::Error { .. } => {
                self.level_checking_errors
                    .insert(ValidationError::internal_invariant_violation(
                        e.source_loc().cloned(),
                        self.policy_id.clone(),
                    ));
            }
        }
    }
}

#[cfg(test)]
mod levels_validation_tests {
    use super::*;
    use crate::parser;
    use crate::test_utils::{expect_err, ExpectedErrorMessageBuilder};

    fn get_schema() -> ValidatorSchema {
        json_schema::Fragment::from_json_value(serde_json::json!(
            {
                "": {
                    "entityTypes": {
                        "User": {
                            "memberOfTypes": ["User"],
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "user": {
                                        "type": "Entity",
                                        "name": "User"
                                    },
                                    "bool": {
                                        "type": "Boolean"
                                    },
                                    "other": {
                                        "type": "String"
                                    },
                                    "ip": {
                                        "type": "Extension",
                                        "name": "ipaddr",
                                    },
                                    "nested": {
                                        "type": "Record",
                                        "attributes" :{
                                            "user": {
                                                "type": "Entity",
                                                "name": "User",
                                            }
                                        }
                                    }
                                }
                            },
                            "tags": {
                                "type": "Entity",
                                "name": "User"
                            }
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "user": {
                                        "type": "Entity",
                                        "name": "User",
                                    }
                                }
                            }
                        }
                    },
                    "actions": {
                        "view": {
                            "appliesTo": {
                                "resourceTypes": [ "Photo" ],
                                "principalTypes": [ "User" ],
                                "context": {
                                  "type": "Record",
                                  "attributes": {
                                      "user": {
                                          "type": "Entity",
                                          "name": "User",
                                      },
                                      "nested": {
                                          "type": "Record",
                                          "attributes" :{
                                              "user": {
                                                  "type": "Entity",
                                                  "name": "User",
                                              }
                                          }
                                      }
                                  }
                                }
                            }
                        }
                    }
                }
            }
        ))
        .expect("Schema parse error.")
        .try_into()
        .expect("Expected valid schema.")
    }

    #[track_caller]
    fn assert_fails_at_level<'a>(
        src: &'a str,
        underlines: impl IntoIterator<Item = &'a str>,
        level: u32,
        actual_level: u32,
    ) {
        let schema = get_schema();
        let validator = Validator::new(schema);
        let p = parser::parse_policy_or_template(None, src).unwrap();
        let underlines = underlines.into_iter().collect::<Vec<_>>();
        let mut errs = validator
            .validate_policy_with_level(&p, ValidationMode::Strict, level)
            .0
            .collect::<Vec<_>>();
        if errs.len() != underlines.len() {
            let l = errs.len();
            for e in errs {
                println!("{:?}", miette::Report::new(e));
            }
            panic!(
                "Did not see expected number of errors: {} != {}",
                l,
                underlines.len()
            );
        }

        let msg = format!(
             "for policy `{}`, this policy requires level {}, which exceeds the maximum allowed level ({})",
            p.id(),
            actual_level,
            level,
        );

        if underlines.len() == 1 {
            let expected = ExpectedErrorMessageBuilder::error(&msg)
                .exactly_one_underline(underlines[0])
                .build();
            expect_err(src, &miette::Report::new(errs.remove(0)), &expected);
        } else {
            for ul in underlines {
                let expected = ExpectedErrorMessageBuilder::error(&msg)
                    .exactly_one_underline(ul)
                    .build();
                if !errs.iter().any(|e| expected.matches(e)) {
                    for e in errs {
                        println!("{:?}", miette::Report::new(e));
                    }
                    panic!("Failed to find any error message with underlined text: {ul}");
                }
            }
        }
    }

    #[track_caller]
    fn assert_requires_level<'a>(
        src: &'a str,
        underlines: impl IntoIterator<Item = &'a str>,
        level: u32,
    ) {
        let schema = get_schema();
        let validator = Validator::new(schema);
        let p = parser::parse_policy_or_template(None, src).unwrap();

        // We should validate at `level`
        let errs = validator
            .validate_policy_with_level(&p, ValidationMode::Strict, level)
            .0
            .collect::<Vec<_>>();
        if !errs.is_empty() {
            for e in errs {
                println!("{:?}", miette::Report::new(e));
            }
            panic!("Did not expect errors at level {level}");
        }

        // But not at `level - 1`
        if level > 0 {
            assert_fails_at_level(src, underlines, level - 1, level);
        }
    }

    #[test]
    fn valid_at_level_zero() {
        assert_requires_level(r#"permit(principal, action, resource);"#, [], 0);
        assert_requires_level(
            r#"permit(principal == User::"alice", action, resource);"#,
            [],
            0,
        );
        assert_requires_level(
            r#"permit(principal, action == Action::"view", resource);"#,
            [],
            0,
        );
        assert_requires_level(r#"permit(principal is User, action, resource);"#, [], 0);
        assert_requires_level(
            r#"permit(principal, action, resource) when {1 > 0};"#,
            [],
            0,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { User::"alice" is User };"#,
            [],
            0,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { context has user };"#,
            [],
            0,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { context.user is User };"#,
            [],
            0,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { context.nested.user is User };"#,
            [],
            0,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { {foo: principal} has foo };"#,
            [],
            0,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { {foo: principal}.foo is User };"#,
            [],
            0,
        );
    }

    #[test]
    fn require_level_one() {
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal.bool };"#,
            [r#"principal.bool"#],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal.nested.user is User };"#,
            [r#"principal.nested.user"#],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal has user};"#,
            [r#"principal has user"#],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal.hasTag("tag") && principal.getTag("tag") is User };"#,
            [r#"principal.hasTag("tag")"#, r#"principal.getTag("tag")"#],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal in User::"other" };"#,
            [r#"principal in User::"other""#],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal in [User::"other"] };"#,
            [r#"principal in [User::"other"]"#],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { action in Action::"view" };"#,
            [r#"action in Action::"view""#],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { context.user.bool };"#,
            [r#"context.user.bool"#],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { context.nested.user.bool };"#,
            [r#"context.nested.user.bool"#],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { Action::"view" in action };"#,
            [r#"Action::"view" in action"#],
            1,
        );
    }

    #[test]
    fn require_level_two() {
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal.user.bool };"#,
            [r#"principal.user.bool"#],
            2,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal.nested.user.bool };"#,
            [r#"principal.nested.user.bool"#],
            2,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal.hasTag("tag") && principal.getTag("tag").bool };"#,
            [r#"principal.getTag("tag").bool"#],
            2,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal.user.hasTag("tag") && principal.user.getTag("tag") is User};"#,
            [
                r#"principal.user.hasTag("tag")"#,
                r#"principal.user.getTag("tag")"#,
            ],
            2,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { context.user.user.bool };"#,
            [r#"context.user.user.bool"#],
            2,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { context.nested.user.nested.user.bool };"#,
            [r#"context.nested.user.nested.user.bool"#],
            2,
        );
    }

    #[test]
    fn require_level_three() {
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal.user.hasTag("t") && principal.user.getTag("t") in resource.user};"#,
            [r#"principal.user.getTag("t") in resource.user"#],
            3,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal.nested.user.nested.user.bool };"#,
            ["principal.nested.user.nested.user.bool"],
            3,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal has user.user.bool && principal.user.user.bool };"#,
            ["principal has user.user.bool", "principal.user.user.bool"],
            3,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal.hasTag("foo") && principal.getTag("foo").hasTag("bar") && principal.getTag("foo").getTag("bar").bool };"#,
            [r#"principal.getTag("foo").getTag("bar").bool"#],
            3,
        );
    }

    #[test]
    fn get_has_tag_arg_is_checked() {
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal.hasTag(principal.user.other) && principal.getTag(principal["user"]["other"]) is User};"#,
            [r#"principal.user.other"#, r#"principal["user"]["other"]"#],
            2,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal.hasTag(principal.user.user.other) && principal.getTag(principal.user["user"]["other"]).bool};"#,
            [
                r#"principal.user.user.other"#,
                r#"principal.user["user"]["other"]"#,
            ],
            3,
        );
    }

    #[test]
    fn in_arg_is_checked() {
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal in principal.user.user };"#,
            [r#"principal.user.user"#],
            2,
        );
    }

    #[test]
    fn top_level_if_is_checked() {
        assert_requires_level(
            r#"permit(principal, action, resource) when { if principal.user.user.bool then principal.bool else resource.user.bool };"#,
            [r#"principal.user.user.bool"#],
            3,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { if principal.bool then principal.bool else resource.user.user.bool };"#,
            [r#"resource.user.user.bool"#],
            3,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { if principal.bool then principal.user.user.bool else resource.user.bool };"#,
            [r#"principal.user.user.bool"#],
            3,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { if context.user.user.user.bool then resource.user.user.bool else principal.user.user.bool };"#,
            [
                "context.user.user.user.bool",
                "principal.user.user.bool",
                "principal.user.user.bool",
            ],
            3,
        );
    }

    #[test]
    fn if_checked_as_deref_target() {
        assert_requires_level(
            r#"permit(principal, action, resource) when { (if principal.bool then principal.user else resource.user).bool };"#,
            [r#"(if principal.bool then principal.user else resource.user).bool"#],
            2,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { (if principal.bool then principal.user else resource.user.user).bool };"#,
            [r#"(if principal.bool then principal.user else resource.user.user).bool"#],
            3,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { (if principal.bool then principal.user.user else resource.user).bool };"#,
            [r#"(if principal.bool then principal.user.user else resource.user).bool"#],
            3,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { (if principal.user.bool then principal.user.user else resource.user.user).bool };"#,
            [r#"(if principal.user.bool then principal.user.user else resource.user.user).bool"#],
            3,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { (if principal.user.user.bool then principal.user.user else resource.user.user).bool };"#,
            ["(if principal.user.user.bool then principal.user.user else resource.user.user).bool", "principal.user.user.bool"],
            3,
        );
    }

    #[test]
    fn unaccessed_record_attr_is_checked() {
        assert_requires_level(
            r#"permit(principal, action, resource) when { {foo: principal, bar: principal.user.user.user.user}.foo.bool };"#,
            [r#"principal.user.user.user.user"#],
            4,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { {foo: principal, bar: principal.user.user, baz: resource.user.user}.foo.bool };"#,
            ["principal.user.user", "resource.user.user"],
            2,
        );
    }

    #[test]
    fn unaccessed_record_is_checked() {
        assert_requires_level(
            r#"permit(principal, action, resource) when { {foo: principal.user, bar: principal.bool} == {foo: principal.nested.user, bar: false} };"#,
            ["principal.user", "principal.bool", "principal.nested.user"],
            1,
        );
    }

    #[test]
    fn record_attrs_as_deref_target() {
        assert_requires_level(
            r#"permit(principal, action, resource) when { {foo: {bar: principal}}.foo.bar is User };"#,
            [],
            0,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { {foo: {bar: principal}}.foo.bar.bool};"#,
            ["{foo: {bar: principal}}.foo.bar.bool"],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { {foo: principal.user}.foo.bool };"#,
            [r#"{foo: principal.user}.foo.bool"#],
            2,
        );
        assert_fails_at_level(
            r#"permit(principal, action, resource) when { {foo: principal.user}.foo.bool };"#,
            ["{foo: principal.user}.foo.bool"],
            0,
            2,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { {biz: {foo: {bar: principal.user}}.foo}.biz.bar.bool};"#,
            ["{biz: {foo: {bar: principal.user}}.foo}.biz.bar.bool"],
            2,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { {biz: {foo: {bar: principal}.bar.user}.foo}.biz.bool};"#,
            ["{biz: {foo: {bar: principal}.bar.user}.foo}.biz.bool"],
            2,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { {biz: {baz: {bar: {foo: principal.nested.user}.foo.nested.user}}.baz}.biz.bar.nested.user.bool };"#,
            [
                r#"{biz: {baz: {bar: {foo: principal.nested.user}.foo.nested.user}}.baz}.biz.bar.nested.user.bool"#,
            ],
            4,
        );
    }

    #[track_caller]
    fn assert_derefs_entity_lit<'a>(
        src: &'a str,
        underlines: impl IntoIterator<Item = &'a str>,
        level: u32,
    ) {
        let schema = get_schema();
        let validator = Validator::new(schema);
        let p = parser::parse_policy_or_template(None, src).unwrap();
        let underlines = underlines.into_iter().collect::<Vec<_>>();
        let mut errs = validator
            .validate_policy_with_level(&p, ValidationMode::Strict, level)
            .0
            .collect::<Vec<_>>();
        if errs.len() != underlines.len() {
            let l = errs.len();
            for e in errs {
                println!("{:?}", miette::Report::new(e));
            }
            panic!(
                "Did not see expected number of errors: {} != {}",
                l,
                underlines.len()
            );
        }

        let msg = format!(
            "for policy `{}`, entity literals cannot be dereferenced at any level",
            p.id()
        );

        if underlines.len() == 1 {
            let expected = ExpectedErrorMessageBuilder::error(&msg)
                .exactly_one_underline(underlines[0])
                .build();
            expect_err(src, &miette::Report::new(errs.remove(0)), &expected);
        } else {
            for ul in underlines {
                let expected = ExpectedErrorMessageBuilder::error(&msg)
                    .exactly_one_underline(ul)
                    .build();
                if !errs.iter().any(|e| expected.matches(e)) {
                    for e in errs {
                        println!("{:?}", miette::Report::new(e));
                    }
                    panic!("Failed to find any error message with underlined text: {ul}");
                }
            }
        }
    }

    #[test]
    fn entity_lit_deref_forbidden() {
        assert_derefs_entity_lit(
            r#"permit(principal, action, resource) when { User::"alice".bool }; "#,
            [r#"User::"alice""#],
            1,
        );
        assert_derefs_entity_lit(
            r#"permit(principal, action, resource) when { User::"alice" has user }; "#,
            [r#"User::"alice""#],
            1,
        );
        assert_derefs_entity_lit(
            r#"permit(principal, action, resource) when { User::"alice" has user.user }; "#,
            [r#"User::"alice""#],
            2,
        );
        assert_derefs_entity_lit(
            r#"permit(principal, action, resource) when { User::"alice".hasTag("foo") }; "#,
            [r#"User::"alice""#],
            1,
        );
        assert_derefs_entity_lit(
            r#"permit(principal, action, resource) when { User::"alice" in User::"bob"}; "#,
            [r#"User::"alice""#],
            1,
        );
        assert_derefs_entity_lit(
            r#"permit(principal, action, resource) when { (if principal.bool then User::"alice" else principal).bool}; "#,
            [r#"User::"alice""#],
            1,
        );
        assert_derefs_entity_lit(
            r#"permit(principal, action, resource) when { (if principal.bool then User::"alice" else User::"bob").bool}; "#,
            [r#"User::"alice""#, r#"User::"bob""#],
            1,
        );
        assert_derefs_entity_lit(
            r#"permit(principal, action, resource) when { {foo: User::"alice", bar: User::"bob"}.foo.bool }; "#,
            [r#"User::"alice""#],
            1,
        );
    }

    #[test]
    fn nested_level_errors() {
        assert_requires_level(
            r#"permit(principal, action, resource) when { [principal.bool].contains(true) };"#,
            [r#"principal.bool"#],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { [context.user.user, principal.user].containsAny([resource.user]) };"#,
            ["context.user.user", "principal.user", "resource.user"],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal.ip.isInRange(ip("192.168.0.0/12"))};"#,
            [r#"principal.ip.isInRange(ip("192.168.0.0/12"))"#],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { ip("192.168.0.0").isInRange(principal.ip) };"#,
            [r#"principal.ip"#],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { principal.other like "*"};"#,
            ["principal.other"],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { ! ( principal.bool )};"#,
            ["principal.bool"],
            1,
        );
    }

    #[test]
    fn fails_at_much_lower_level() {
        assert_fails_at_level(
            r#"permit(principal, action, resource) when { principal.user.user.user.user.user.bool };"#,
            ["principal.user.user.user.user.user.bool"],
            0,
            6,
        );
        assert_fails_at_level(
            r#"permit(principal, action, resource) when { principal.user.user.user.user.user.bool };"#,
            ["principal.user.user.user.user.user.bool"],
            2,
            6,
        );
    }

    #[test]
    fn short_circuiting_checks_evaluated_expr() {
        assert_requires_level(
            r#"permit(principal, action, resource) when { (principal.bool || true) || true};"#,
            ["principal.bool"],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { (principal.bool && false) && false};"#,
            ["principal.bool"],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { if (principal.bool && false) then true else false };"#,
            ["principal.bool"],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { if (principal.bool && false) then true else false };"#,
            ["principal.bool"],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { if true then principal.bool else false };"#,
            ["principal.bool"],
            1,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { if false then true else principal.bool };"#,
            ["principal.bool"],
            1,
        );
    }

    #[test]
    fn short_circuiting_skips_unevaluated_expr() {
        assert_requires_level(
            r#"permit(principal, action, resource) when { true || principal.bool};"#,
            [],
            0,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { false && principal.bool};"#,
            [],
            0,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { if false then principal.bool else false };"#,
            [],
            0,
        );
        assert_requires_level(
            r#"permit(principal, action, resource) when { if true then true else principal.bool };"#,
            [],
            0,
        );
    }
}
