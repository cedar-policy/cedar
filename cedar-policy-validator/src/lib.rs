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

//! Validator for Cedar policies
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]
#![deny(
    missing_docs,
    missing_debug_implementations,
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_html_tags,
    rustdoc::invalid_rust_codeblocks,
    rustdoc::bare_urls,
    clippy::doc_markdown
)]
#![allow(clippy::result_large_err, clippy::large_enum_variant)] // see #878
#![cfg_attr(feature = "wasm", allow(non_snake_case))]

#[cfg(feature = "level-validate")]
use cedar_policy_core::ast::{BinaryOp, PolicyID};
use cedar_policy_core::ast::{Policy, PolicySet, Template};
use serde::Serialize;
use std::collections::HashSet;
#[cfg(feature = "level-validate")]
use validation_errors::{EntityDerefLevel, EntityDerefLevelViolation};

#[cfg(feature = "entity-manifest")]
pub mod entity_manifest;
mod err;
pub use err::*;
mod coreschema;
pub use coreschema::*;
mod diagnostics;
pub use diagnostics::*;
mod expr_iterator;
mod extension_schema;
mod extensions;
mod fuzzy_match;
mod rbac;
mod schema;
pub use schema::*;
pub mod json_schema;
mod str_checks;
pub use str_checks::confusable_string_checks;
pub mod cedar_schema;
pub mod typecheck;
#[cfg(feature = "level-validate")]
use typecheck::PolicyCheck;
use typecheck::Typechecker;

pub mod types;

/// Used to select how a policy will be validated.
#[derive(Default, Eq, PartialEq, Copy, Clone, Debug, Serialize)]
pub enum ValidationMode {
    /// Strict mode
    #[default]
    Strict,
    /// Permissive mode
    Permissive,
    /// Partial validation, allowing you to use an incomplete schema, but
    /// providing no formal guarantees
    #[cfg(feature = "partial-validate")]
    Partial,
}

impl ValidationMode {
    /// Does this mode use partial validation. We could conceivably have a
    /// strict/partial validation mode.
    fn is_partial(self) -> bool {
        match self {
            ValidationMode::Strict | ValidationMode::Permissive => false,
            #[cfg(feature = "partial-validate")]
            ValidationMode::Partial => true,
        }
    }

    /// Does this mode apply strict validation rules.
    fn is_strict(self) -> bool {
        match self {
            ValidationMode::Strict => true,
            ValidationMode::Permissive => false,
            #[cfg(feature = "partial-validate")]
            ValidationMode::Partial => false,
        }
    }
}

/// Structure containing the context needed for policy validation. This is
/// currently only the `EntityType`s and `ActionType`s from a single schema.
#[derive(Debug)]
pub struct Validator {
    schema: ValidatorSchema,
}

impl Validator {
    /// Construct a new Validator from a schema file.
    pub fn new(schema: ValidatorSchema) -> Validator {
        Self { schema }
    }

    /// Validate all templates, links, and static policies in a policy set.
    /// Return a `ValidationResult`.
    pub fn validate(&self, policies: &PolicySet, mode: ValidationMode) -> ValidationResult {
        let validate_policy_results: (Vec<_>, Vec<_>) = policies
            .all_templates()
            .map(|p| self.validate_policy(p, mode))
            .unzip();
        let template_and_static_policy_errs = validate_policy_results.0.into_iter().flatten();
        let template_and_static_policy_warnings = validate_policy_results.1.into_iter().flatten();
        let link_errs = policies
            .policies()
            .filter_map(|p| self.validate_slots(p, mode))
            .flatten();
        ValidationResult::new(
            template_and_static_policy_errs.chain(link_errs),
            template_and_static_policy_warnings
                .chain(confusable_string_checks(policies.all_templates())),
        )
    }

    #[cfg(feature = "level-validate")]
    /// Strictly validate all templates, links, and static policies in a policy set.
    /// If strict validation passes, also run level validation with `max_deref_level`
    /// (see RFC 76).
    /// Return a `ValidationResult`.
    pub fn strict_validate_with_level(
        &self,
        policies: &PolicySet,
        max_deref_level: u32,
    ) -> ValidationResult {
        let validate_policy_results: (Vec<_>, Vec<_>) = policies
            .all_templates()
            .map(|p| self.strict_validate_policy_with_level(p, max_deref_level))
            .unzip();
        let template_and_static_policy_errs = validate_policy_results.0.into_iter().flatten();
        let template_and_static_policy_warnings = validate_policy_results.1.into_iter().flatten();
        let link_errs = policies
            .policies()
            .filter_map(|p| self.validate_slots(p, ValidationMode::Strict))
            .flatten();
        ValidationResult::new(
            template_and_static_policy_errs.chain(link_errs),
            template_and_static_policy_warnings
                .chain(confusable_string_checks(policies.all_templates())),
        )
    }

    /// Run all validations against a single static policy or template (note
    /// that Core `Template` includes static policies as well), gathering all
    /// validation errors and warnings in the returned iterators.
    fn validate_policy<'a>(
        &'a self,
        p: &'a Template,
        mode: ValidationMode,
    ) -> (
        impl Iterator<Item = ValidationError> + 'a,
        impl Iterator<Item = ValidationWarning> + 'a,
    ) {
        let validation_errors = if mode.is_partial() {
            // We skip `validate_entity_types`, `validate_action_ids`, and
            // `validate_action_application` passes for partial schema
            // validation because there may be arbitrary extra entity types and
            // actions, so we can never claim that one doesn't exist.
            None
        } else {
            Some(
                self.validate_entity_types(p)
                    .chain(self.validate_action_ids(p))
                    // We could usefully update this pass to apply to partial
                    // schema if it only failed when there is a known action
                    // applied to known principal/resource entity types that are
                    // not in its `appliesTo`.
                    .chain(self.validate_template_action_application(p)),
            )
        }
        .into_iter()
        .flatten();
        let (errors, warnings) = self.typecheck_policy(p, mode);
        (validation_errors.chain(errors), warnings)
    }

    #[cfg(feature = "level-validate")]
    /// Run `validate_policy` in strict mode against a single static policy or template (note
    /// that Core `Template` includes static policies as well), gathering all
    /// validation errors and warnings in the returned iterators.
    /// If strict validation passes, we will also perform level validation (see RFC 76).
    fn strict_validate_policy_with_level<'a>(
        &'a self,
        p: &'a Template,
        max_deref_level: u32,
    ) -> (
        impl Iterator<Item = ValidationError> + 'a,
        impl Iterator<Item = ValidationWarning> + 'a,
    ) {
        let (errors, warnings) = self.validate_policy(p, ValidationMode::Strict);

        let mut peekable_errors = errors.peekable();

        // Only perform level validation if strict validation passed.
        if peekable_errors.peek().is_none() {
            let levels_errors =
                self.check_entity_deref_level(p, &EntityDerefLevel::from(max_deref_level), p.id());
            (peekable_errors.chain(levels_errors), warnings)
        } else {
            (peekable_errors.into_iter().chain(vec![]), warnings)
        }
    }

    /// Run relevant validations against a single template-linked policy,
    /// gathering all validation errors together in the returned iterator.
    fn validate_slots<'a>(
        &'a self,
        p: &'a Policy,
        mode: ValidationMode,
    ) -> Option<impl Iterator<Item = ValidationError> + 'a> {
        // Ignore static policies since they are already handled by `validate_policy`
        if p.is_static() {
            return None;
        }
        // In partial validation, there may be arbitrary extra entity types and
        // actions, so we can never claim that one doesn't exist or that the
        // action application is invalid.
        if mode.is_partial() {
            return None;
        }
        // For template-linked policies `Policy::principal_constraint()` and
        // `Policy::resource_constraint()` return a copy of the constraint with
        // the slot filled by the appropriate value.
        Some(
            self.validate_entity_types_in_slots(p.id(), p.env())
                .chain(self.validate_linked_action_application(p)),
        )
    }

    /// Construct a Typechecker instance and use it to detect any type errors in
    /// the argument static policy or template (note that Core `Template`
    /// includes static policies as well) in the context of the schema for this
    /// validator. Any detected type errors are wrapped and returned as
    /// `ValidationErrorKind`s.
    fn typecheck_policy<'a>(
        &'a self,
        t: &'a Template,
        mode: ValidationMode,
    ) -> (
        impl Iterator<Item = ValidationError> + 'a,
        impl Iterator<Item = ValidationWarning> + 'a,
    ) {
        let typecheck = Typechecker::new(&self.schema, mode, t.id().clone());
        let mut errors = HashSet::new();
        let mut warnings = HashSet::new();
        typecheck.typecheck_policy(t, &mut errors, &mut warnings);
        (errors.into_iter(), warnings.into_iter())
    }

    #[cfg(feature = "level-validate")]
    /// Check that `t` respects `max_allowed_level`
    /// This assumes that (strict) typechecking has passed
    fn check_entity_deref_level<'a>(
        &'a self,
        t: &'a Template,
        max_allowed_level: &EntityDerefLevel,
        policy_id: &PolicyID,
    ) -> Vec<ValidationError> {
        let typechecker = Typechecker::new(&self.schema, ValidationMode::Strict, t.id().clone());
        let type_annotated_asts = typechecker.typecheck_by_request_env(t);
        let mut errs = vec![];
        for (_, policy_check) in type_annotated_asts {
            match policy_check {
                PolicyCheck::Success(e) | PolicyCheck::Irrelevant(_, e) => {
                    let res =
                        self.check_entity_deref_level_helper(&e, max_allowed_level, policy_id);
                    match res.1 {
                        Some(e) => errs.push(ValidationError::EntityDerefLevelViolation(e)),
                        None => (),
                    }
                }
                // PANIC SAFETY: We only validate the level after strict validation passed
                #[allow(clippy::unreachable)]
                PolicyCheck::Fail(_) => unreachable!(),
            }
        }
        errs
    }

    #[cfg(feature = "level-validate")]
    fn min(
        v: impl IntoIterator<Item = (EntityDerefLevel, Option<EntityDerefLevelViolation>)>,
    ) -> (EntityDerefLevel, Option<EntityDerefLevelViolation>) {
        let p = v.into_iter().min_by(|(l1, _), (l2, _)| l1.cmp(l2));
        match p {
            Some(p) => p.clone(),
            None => (EntityDerefLevel { level: 0 }, None),
        }
    }

    #[cfg(feature = "level-validate")]
    /// Walk the type-annotated AST and compute the used level and possible violation
    /// Returns a tuple of `(actual level used, optional violation information)`
    fn check_entity_deref_level_helper<'a>(
        &'a self,
        e: &cedar_policy_core::ast::Expr<Option<crate::types::Type>>,
        max_allowed_level: &EntityDerefLevel,
        policy_id: &PolicyID,
    ) -> (EntityDerefLevel, Option<EntityDerefLevelViolation>) {
        use crate::types::{EntityRecordKind, Type};
        use cedar_policy_core::ast::ExprKind;
        match e.expr_kind() {
            ExprKind::Lit(_) => (
                EntityDerefLevel { level: 0 }, //Literals can't be dereferenced
                None,
            ),
            ExprKind::Var(_) => (max_allowed_level.clone(), None), //Roots start at `max_allowed_level`
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
                    .map(|l| self.check_entity_deref_level_helper(l, max_allowed_level, policy_id))
                    .collect();
                Self::min(v)
            }
            ExprKind::And { left, right } | ExprKind::Or { left, right } => {
                let es = [left, right];
                let v: Vec<(EntityDerefLevel, Option<_>)> = es
                    .iter()
                    .map(|l| self.check_entity_deref_level_helper(l, max_allowed_level, policy_id))
                    .collect();
                Self::min(v)
            }
            ExprKind::UnaryApp { arg, .. } => {
                self.check_entity_deref_level_helper(arg, max_allowed_level, policy_id)
            }
            // `In` operator decrements the LHS only
            ExprKind::BinaryApp { op, arg1, arg2 } if op == &BinaryOp::In => {
                let mut lhs =
                    self.check_entity_deref_level_helper(arg1, max_allowed_level, policy_id);
                let rhs = self.check_entity_deref_level_helper(arg2, max_allowed_level, policy_id);
                lhs = (lhs.0.decrement(), lhs.1);
                let new_level = Self::min(vec![lhs, rhs]).0;
                if new_level.level < 0 {
                    (
                        new_level,
                        Some(EntityDerefLevelViolation {
                            source_loc: e.source_loc().cloned(),
                            policy_id: policy_id.clone(),
                            actual_level: new_level,
                            allowed_level: max_allowed_level.clone(),
                        }),
                    )
                } else {
                    (new_level, None)
                }
            }
            ExprKind::BinaryApp { arg1, arg2, .. } => {
                let es = [arg1, arg2];
                let v: Vec<(EntityDerefLevel, Option<_>)> = es
                    .iter()
                    .map(|l| self.check_entity_deref_level_helper(l, max_allowed_level, policy_id))
                    .collect();
                Self::min(v)
            }
            ExprKind::ExtensionFunctionApp { args, .. } => {
                let v: Vec<(EntityDerefLevel, Option<_>)> = args
                    .iter()
                    .map(|l| self.check_entity_deref_level_helper(l, max_allowed_level, policy_id))
                    .collect();
                Self::min(v)
            }
            ExprKind::GetAttr { expr, attr }
                if matches!(expr.expr_kind(), ExprKind::Record(..)) =>
            {
                match expr.expr_kind() {
                    ExprKind::Record(m) => {
                        // PANIC SAFETY: Strict validation checked that this access is safe
                        #[allow(clippy::unwrap_used)]
                        self.check_entity_deref_level_helper(
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
                        self.check_entity_deref_level_helper(expr, max_allowed_level, policy_id);
                    match ty {
                        Type::EntityOrRecord(EntityRecordKind::Entity { .. })
                        | Type::EntityOrRecord(EntityRecordKind::ActionEntity { .. }) => {
                            let child_level = child_level_info.0;
                            let new_level = child_level.decrement();
                            if new_level.level < 0 {
                                (
                                    new_level,
                                    Some(EntityDerefLevelViolation {
                                        source_loc: e.source_loc().cloned(),
                                        policy_id: policy_id.clone(),
                                        actual_level: new_level,
                                        allowed_level: max_allowed_level.clone(),
                                    }),
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
                // PANIC SAFETY: Strict validation passed, so annotating the AST will succeed
                #[allow(clippy::unreachable)]
                None => unreachable!("Expected type-annotated AST"),
            },
            ExprKind::Like { expr, .. } | ExprKind::Is { expr, .. } => {
                self.check_entity_deref_level_helper(expr, max_allowed_level, policy_id)
            }
            ExprKind::Set(elems) => {
                let v: Vec<(EntityDerefLevel, Option<_>)> = elems
                    .iter()
                    .map(|l| self.check_entity_deref_level_helper(l, max_allowed_level, policy_id))
                    .collect();
                Self::min(v)
            }
            ExprKind::Record(fields) => {
                let v: Vec<(EntityDerefLevel, Option<_>)> = fields
                    .iter()
                    .map(|(_, l)| {
                        self.check_entity_deref_level_helper(l, max_allowed_level, policy_id)
                    })
                    .collect();
                Self::min(v)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use itertools::Itertools;
    use std::{collections::HashMap, sync::Arc};

    use crate::types::Type;
    use crate::Result;

    use super::*;
    use cedar_policy_core::{
        ast::{self, PolicyID},
        parser::{self, Loc},
    };

    #[test]
    fn top_level_validate() -> Result<()> {
        let mut set = PolicySet::new();
        let foo_type = "foo_type";
        let bar_type = "bar_type";
        let action_name = "action";
        let schema_file = json_schema::NamespaceDefinition::new(
            [
                (
                    foo_type.parse().unwrap(),
                    json_schema::EntityType {
                        member_of_types: vec![],
                        shape: json_schema::AttributesOrContext::default(),
                        tags: None,
                    },
                ),
                (
                    bar_type.parse().unwrap(),
                    json_schema::EntityType {
                        member_of_types: vec![],
                        shape: json_schema::AttributesOrContext::default(),
                        tags: None,
                    },
                ),
            ],
            [(
                action_name.into(),
                json_schema::ActionType {
                    applies_to: Some(json_schema::ApplySpec {
                        principal_types: vec!["foo_type".parse().unwrap()],
                        resource_types: vec!["bar_type".parse().unwrap()],
                        context: json_schema::AttributesOrContext::default(),
                    }),
                    member_of: None,
                    attributes: None,
                },
            )],
        );
        let schema = schema_file.try_into().unwrap();
        let validator = Validator::new(schema);

        let policy_a_src = r#"permit(principal in foo_type::"a", action == Action::"actin", resource == bar_type::"b");"#;
        let policy_a = parser::parse_policy(Some(PolicyID::from_string("pola")), policy_a_src)
            .expect("Test Policy Should Parse");
        set.add_static(policy_a.clone())
            .expect("Policy already present in PolicySet");

        let policy_b_src = r#"permit(principal in foo_tye::"a", action == Action::"action", resource == br_type::"b");"#;
        let policy_b = parser::parse_policy(Some(PolicyID::from_string("polb")), policy_b_src)
            .expect("Test Policy Should Parse");
        set.add_static(policy_b.clone())
            .expect("Policy already present in PolicySet");

        let result = validator.validate(&set, ValidationMode::default());
        let principal_err = ValidationError::unrecognized_entity_type(
            Some(Loc::new(20..27, Arc::from(policy_b_src))),
            PolicyID::from_string("polb"),
            "foo_tye".to_string(),
            Some("foo_type".to_string()),
        );
        let resource_err = ValidationError::unrecognized_entity_type(
            Some(Loc::new(74..81, Arc::from(policy_b_src))),
            PolicyID::from_string("polb"),
            "br_type".to_string(),
            Some("bar_type".to_string()),
        );
        let action_err = ValidationError::unrecognized_action_id(
            Some(Loc::new(45..60, Arc::from(policy_a_src))),
            PolicyID::from_string("pola"),
            "Action::\"actin\"".to_string(),
            Some("Action::\"action\"".to_string()),
        );

        assert!(!result.validation_passed());
        assert!(
            result.validation_errors().contains(&principal_err),
            "{result:?}"
        );
        assert!(
            result.validation_errors().contains(&resource_err),
            "{result:?}"
        );
        assert!(
            result.validation_errors().contains(&action_err),
            "{result:?}"
        );
        Ok(())
    }

    #[test]
    fn top_level_validate_with_links() -> Result<()> {
        let mut set = PolicySet::new();
        let schema: ValidatorSchema = json_schema::Fragment::from_json_str(
            r#"
            {
                "some_namespace": {
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "department": {
                                        "type": "String"
                                    },
                                    "jobLevel": {
                                        "type": "Long"
                                    }
                                }
                            },
                            "memberOfTypes": [
                                "UserGroup"
                            ]
                        },
                        "UserGroup": {},
                        "Photo" : {}
                    },
                    "actions": {
                        "view": {
                            "appliesTo": {
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "principalTypes": [
                                    "User"
                                ]
                            }
                        }
                    }
                }
            }
        "#,
        )
        .expect("Schema parse error.")
        .try_into()
        .expect("Expected valid schema.");
        let validator = Validator::new(schema);

        let t = parser::parse_policy_or_template(
            Some(PolicyID::from_string("template")),
            r#"permit(principal == some_namespace::User::"Alice", action, resource in ?resource);"#,
        )
        .expect("Parse Error");
        let loc = t.loc().cloned();
        set.add_template(t)
            .expect("Template already present in PolicySet");

        // the template is valid by itself
        let result = validator.validate(&set, ValidationMode::default());
        assert_eq!(
            result.validation_errors().collect::<Vec<_>>(),
            Vec::<&ValidationError>::new()
        );

        // a valid link is valid
        let mut values = HashMap::new();
        values.insert(
            ast::SlotId::resource(),
            ast::EntityUID::from_components(
                "some_namespace::Photo".parse().unwrap(),
                ast::Eid::new("foo"),
                None,
            ),
        );
        set.link(
            ast::PolicyID::from_string("template"),
            ast::PolicyID::from_string("link1"),
            values,
        )
        .expect("Linking failed!");
        let result = validator.validate(&set, ValidationMode::default());
        assert!(result.validation_passed());

        // an invalid link results in an error
        let mut values = HashMap::new();
        values.insert(
            ast::SlotId::resource(),
            ast::EntityUID::from_components(
                "some_namespace::Undefined".parse().unwrap(),
                ast::Eid::new("foo"),
                None,
            ),
        );
        set.link(
            ast::PolicyID::from_string("template"),
            ast::PolicyID::from_string("link2"),
            values,
        )
        .expect("Linking failed!");
        let result = validator.validate(&set, ValidationMode::default());
        assert!(!result.validation_passed());
        assert_eq!(result.validation_errors().count(), 2);
        let undefined_err = ValidationError::unrecognized_entity_type(
            None,
            PolicyID::from_string("link2"),
            "some_namespace::Undefined".to_string(),
            Some("some_namespace::User".to_string()),
        );
        let invalid_action_err = ValidationError::invalid_action_application(
            loc.clone(),
            PolicyID::from_string("link2"),
            false,
            false,
        );
        assert!(result.validation_errors().any(|x| x == &undefined_err));
        assert!(result.validation_errors().any(|x| x == &invalid_action_err));

        // this is also an invalid link (not a valid resource type for any action in the schema)
        let mut values = HashMap::new();
        values.insert(
            ast::SlotId::resource(),
            ast::EntityUID::from_components(
                "some_namespace::User".parse().unwrap(),
                ast::Eid::new("foo"),
                None,
            ),
        );
        set.link(
            ast::PolicyID::from_string("template"),
            ast::PolicyID::from_string("link3"),
            values,
        )
        .expect("Linking failed!");
        let result = validator.validate(&set, ValidationMode::default());
        assert!(!result.validation_passed());
        // `result` contains the two prior error messages plus one new one
        assert_eq!(result.validation_errors().count(), 3);
        let invalid_action_err = ValidationError::invalid_action_application(
            loc.clone(),
            PolicyID::from_string("link3"),
            false,
            false,
        );
        assert!(result.validation_errors().contains(&invalid_action_err));

        Ok(())
    }

    #[test]
    fn validate_finds_warning_and_error() {
        let schema: ValidatorSchema = json_schema::Fragment::from_json_str(
            r#"
            {
                "": {
                    "entityTypes": {
                        "User": { }
                    },
                    "actions": {
                        "view": {
                            "appliesTo": {
                                "resourceTypes": [ "User" ],
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
        .expect("Expected valid schema.");
        let validator = Validator::new(schema);

        let mut set = PolicySet::new();
        let src = r#"permit(principal == User::"һenry", action, resource) when {1 > true};"#;
        let p = parser::parse_policy(None, src).unwrap();
        set.add_static(p).unwrap();

        let result = validator.validate(&set, ValidationMode::default());
        assert_eq!(
            result.validation_errors().collect::<Vec<_>>(),
            vec![&ValidationError::expected_type(
                typecheck::test::test_utils::get_loc(src, "true"),
                PolicyID::from_string("policy0"),
                Type::primitive_long(),
                Type::singleton_boolean(true),
                None,
            )]
        );
        assert_eq!(
            result.validation_warnings().collect::<Vec<_>>(),
            vec![&ValidationWarning::mixed_script_identifier(
                None,
                PolicyID::from_string("policy0"),
                "һenry"
            )]
        );
    }
}

#[cfg(feature = "level-validate")]
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

        let template_name = PolicyID::from_string("policy0");
        let result = validator.check_entity_deref_level(
            set.get_template(&template_name).unwrap(),
            &EntityDerefLevel { level: 0 },
            &template_name,
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

        let template_name = PolicyID::from_string("policy0");
        let result = validator.check_entity_deref_level(
            set.get_template(&template_name).unwrap(),
            &EntityDerefLevel { level: 0 },
            &template_name,
        );
        assert!(result.len() == 1);
    }
}
