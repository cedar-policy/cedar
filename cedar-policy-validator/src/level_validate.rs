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

use crate::validation_errors::InternalInvariantViolation;

use super::*;
use cedar_policy_core::ast::{BinaryOp, PolicyID};
use typecheck::PolicyCheck;
use validation_errors::{EntityDerefLevel, EntityDerefLevelViolation};

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
            let levels_errors =
                self.check_entity_deref_level(p, mode, &EntityDerefLevel::from(max_deref_level));
            (peekable_errors.chain(levels_errors), warnings)
        } else {
            (peekable_errors.chain(vec![]), warnings)
        }
    }

    /// Check that `t` respects `max_allowed_level`
    /// This assumes that (strict) typechecking has passed
    fn check_entity_deref_level<'a>(
        &'a self,
        t: &'a Template,
        mode: ValidationMode,
        max_allowed_level: &EntityDerefLevel,
    ) -> Vec<ValidationError> {
        let typechecker = Typechecker::new(&self.schema, mode);
        let type_annotated_asts = typechecker.typecheck_by_request_env(t);
        let mut errs = vec![];
        for (_, policy_check) in type_annotated_asts {
            match policy_check {
                PolicyCheck::Success(e) | PolicyCheck::Irrelevant(_, e) => {
                    let res = Self::check_entity_deref_level_helper(&e, max_allowed_level, t.id());
                    if let Some(e) = res.1 {
                        errs.push(e)
                    }
                }
                // PANIC SAFETY: We only validate the level after validation passed
                #[allow(clippy::unreachable)]
                PolicyCheck::Fail(_) => unreachable!(),
            }
        }
        errs
    }

    fn min(
        v: impl IntoIterator<Item = (EntityDerefLevel, Option<ValidationError>)>,
    ) -> (EntityDerefLevel, Option<ValidationError>) {
        let p = v.into_iter().min_by(|(l1, _), (l2, _)| l1.cmp(l2));
        match p {
            Some(p) => p,
            None => (EntityDerefLevel { level: 0 }, None),
        }
    }

    /// Walk the type-annotated AST and compute the used level and possible violation
    /// Returns a tuple of `(actual level used, optional violation information)`
    fn check_entity_deref_level_helper(
        e: &cedar_policy_core::ast::Expr<Option<crate::types::Type>>,
        max_allowed_level: &EntityDerefLevel,
        policy_id: &PolicyID,
    ) -> (EntityDerefLevel, Option<ValidationError>) {
        use crate::types::{EntityRecordKind, Type};
        use cedar_policy_core::ast::ExprKind;
        match e.expr_kind() {
            ExprKind::Lit(_) => (
                EntityDerefLevel { level: 0 }, //Literals can't be dereferenced
                None,
            ),
            ExprKind::Var(_) => (*max_allowed_level, None), //Roots start at `max_allowed_level`
            ExprKind::Slot(_) => (EntityDerefLevel { level: 0 }, None), //Slot will be replaced by Entity literal so treat the same
            ExprKind::Unknown(_) => (
                EntityDerefLevel { level: 0 }, //Can't dereference an unknown
                None,
            ),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                let es = [test_expr, then_expr, else_expr];
                let v: Vec<(EntityDerefLevel, Option<_>)> = es
                    .iter()
                    .map(|l| Self::check_entity_deref_level_helper(l, max_allowed_level, policy_id))
                    .collect();
                Self::min(v)
            }
            ExprKind::And { left, right } | ExprKind::Or { left, right } => {
                let es = [left, right];
                let v: Vec<(EntityDerefLevel, Option<_>)> = es
                    .iter()
                    .map(|l| Self::check_entity_deref_level_helper(l, max_allowed_level, policy_id))
                    .collect();
                Self::min(v)
            }
            ExprKind::UnaryApp { arg, .. } => {
                Self::check_entity_deref_level_helper(arg, max_allowed_level, policy_id)
            }
            // `In` operator decrements the LHS only
            ExprKind::BinaryApp { op, arg1, arg2 } if op == &BinaryOp::In => {
                let lhs = Self::check_entity_deref_level_helper(arg1, max_allowed_level, policy_id);
                let rhs = Self::check_entity_deref_level_helper(arg2, max_allowed_level, policy_id);
                let lhs = (lhs.0.decrement(), lhs.1);
                let new_level = Self::min(vec![lhs, rhs]).0;
                if new_level.level < 0 {
                    (
                        new_level,
                        Some(
                            EntityDerefLevelViolation {
                                source_loc: e.source_loc().cloned(),
                                policy_id: policy_id.clone(),
                                actual_level: new_level,
                                allowed_level: *max_allowed_level,
                            }
                            .into(),
                        ),
                    )
                } else {
                    (new_level, None)
                }
            }
            ExprKind::BinaryApp { arg1, arg2, .. } => {
                let es = [arg1, arg2];
                let v: Vec<(EntityDerefLevel, Option<_>)> = es
                    .iter()
                    .map(|l| Self::check_entity_deref_level_helper(l, max_allowed_level, policy_id))
                    .collect();
                Self::min(v)
            }
            ExprKind::ExtensionFunctionApp { args, .. } => {
                let v: Vec<(EntityDerefLevel, Option<_>)> = args
                    .iter()
                    .map(|l| Self::check_entity_deref_level_helper(l, max_allowed_level, policy_id))
                    .collect();
                Self::min(v)
            }
            ExprKind::GetAttr { expr, attr }
                if matches!(expr.expr_kind(), ExprKind::Record(..)) =>
            {
                match expr.expr_kind() {
                    ExprKind::Record(m) => {
                        // PANIC SAFETY: Validation checked that this access is safe
                        #[allow(clippy::unwrap_used)]
                        Self::check_entity_deref_level_helper(
                            m.get(attr).unwrap(),
                            max_allowed_level,
                            policy_id,
                        )
                    }
                    // PANIC SAFETY: We just checked that this node is a Record
                    #[allow(clippy::unreachable)]
                    _ => unreachable!(),
                }
            }
            ExprKind::GetAttr { expr, .. } | ExprKind::HasAttr { expr, .. } => match expr
                .as_ref()
                .data()
            {
                Some(ty) => {
                    let child_level_info =
                        Self::check_entity_deref_level_helper(expr, max_allowed_level, policy_id);
                    match ty {
                        Type::EntityOrRecord(EntityRecordKind::Entity { .. })
                        | Type::EntityOrRecord(EntityRecordKind::ActionEntity { .. }) => {
                            let child_level = child_level_info.0;
                            let new_level = child_level.decrement();
                            if new_level.level < 0 {
                                (
                                    new_level,
                                    Some(
                                        EntityDerefLevelViolation {
                                            source_loc: e.source_loc().cloned(),
                                            policy_id: policy_id.clone(),
                                            actual_level: new_level,
                                            allowed_level: *max_allowed_level,
                                        }
                                        .into(),
                                    ),
                                )
                            } else {
                                (new_level, None)
                            }
                        }
                        Type::EntityOrRecord(EntityRecordKind::AnyEntity) => {
                            // AnyEntity cannot be dereferenced
                            (EntityDerefLevel { level: 0 }, None)
                        }
                        _ => child_level_info,
                    }
                }
                // PANIC SAFETY: Validation passed, so annotating the AST will succeed
                #[allow(clippy::unreachable)]
                None => unreachable!("Expected type-annotated AST"),
            },
            ExprKind::Like { expr, .. } | ExprKind::Is { expr, .. } => {
                Self::check_entity_deref_level_helper(expr, max_allowed_level, policy_id)
            }
            ExprKind::Set(elems) => {
                let v: Vec<(EntityDerefLevel, Option<_>)> = elems
                    .iter()
                    .map(|l| Self::check_entity_deref_level_helper(l, max_allowed_level, policy_id))
                    .collect();
                Self::min(v)
            }
            ExprKind::Record(fields) => {
                let v: Vec<(EntityDerefLevel, Option<_>)> = fields
                    .iter()
                    .map(|(_, l)| {
                        Self::check_entity_deref_level_helper(l, max_allowed_level, policy_id)
                    })
                    .collect();
                Self::min(v)
            }
            #[cfg(feature = "tolerant-ast")]
            ExprKind::Error { .. } => (
                EntityDerefLevel { level: 0 },
                Some(ValidationError::InternalInvariantViolation(
                    InternalInvariantViolation {
                        source_loc: None,
                        policy_id: policy_id.clone(),
                    },
                )),
            ),
        }
    }
}

#[cfg(test)]
mod levels_validation_tests {
    use super::*;
    use cedar_policy_core::parser;

    fn get_schema() -> ValidatorSchema {
        json_schema::Fragment::from_json_str(
            r#"
            {
                "": {
                    "entityTypes": {
                        "User": {
                            "memberOfTypes": ["User"]
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "foo": {
                                        "type": "Entity",
                                        "name": "User",
                                        "required": true
                                    }
                                }
                            }
                        }
                    },
                    "actions": {
                        "view": {
                            "appliesTo": {
                                "resourceTypes": [ "Photo" ],
                                "principalTypes": [ "User" ]
                            }
                        }
                    }
                }
            }
        "#,
        )
        .expect("Schema parse error.")
        .try_into()
        .expect("Expected valid schema.")
    }

    #[test]
    fn test_levels_validation_passes() {
        let schema = get_schema();
        let validator = Validator::new(schema);

        let mut set = PolicySet::new();
        let src = r#"permit(principal == User::"һenry", action, resource) when {1 > 0};"#;
        let p = parser::parse_policy(None, src).unwrap();
        set.add_static(p).unwrap();

        let result = validator.check_entity_deref_level(
            set.get_template(&PolicyID::from_string("policy0")).unwrap(),
            ValidationMode::default(),
            &EntityDerefLevel { level: 0 },
        );
        assert!(result.is_empty());
    }

    #[test]
    fn test_levels_validation_fails() {
        let schema = get_schema();
        let validator = Validator::new(schema);

        let mut set = PolicySet::new();
        let src = r#"permit(principal == User::"һenry", action, resource) when {principal in resource.foo};"#;
        let p = parser::parse_policy(None, src).unwrap();
        set.add_static(p).unwrap();

        let result = validator.check_entity_deref_level(
            set.get_template(&PolicyID::from_string("policy0")).unwrap(),
            ValidationMode::default(),
            &EntityDerefLevel { level: 0 },
        );
        assert!(result.len() == 1);
    }
}
