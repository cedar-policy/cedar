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

use cedar_policy_core::ast::{Policy, PolicySet, Template};
use serde::Serialize;
use std::collections::HashSet;

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
mod schema_file_format;
pub use schema_file_format::*;
mod str_checks;
pub use str_checks::confusable_string_checks;
pub mod human_schema;
pub mod typecheck;
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
        let (type_errors, warnings) = self.typecheck_policy(p, mode);
        (validation_errors.chain(type_errors), warnings)
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
        let mut type_errors = HashSet::new();
        let mut warnings = HashSet::new();
        typecheck.typecheck_policy(t, &mut type_errors, &mut warnings);
        (type_errors.into_iter(), warnings.into_iter())
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
        ast::{self, Expr, PolicyID},
        parser::{self, Loc},
    };

    #[test]
    fn top_level_validate() -> Result<()> {
        let mut set = PolicySet::new();
        let foo_type = "foo_type";
        let bar_type = "bar_type";
        let action_name = "action";
        let schema_file = NamespaceDefinition::new(
            [
                (
                    foo_type.parse().unwrap(),
                    EntityType {
                        member_of_types: vec![],
                        shape: AttributesOrContext::default(),
                    },
                ),
                (
                    bar_type.parse().unwrap(),
                    EntityType {
                        member_of_types: vec![],
                        shape: AttributesOrContext::default(),
                    },
                ),
            ],
            [(
                action_name.into(),
                ActionType {
                    applies_to: Some(ApplySpec {
                        principal_types: vec!["foo_type".parse().unwrap()],
                        resource_types: vec!["bar_type".parse().unwrap()],
                        context: AttributesOrContext::default(),
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
        let schema: ValidatorSchema = serde_json::from_str::<SchemaFragment<RawName>>(
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

        let t = parser::parse_policy_template(
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
        let schema: ValidatorSchema = serde_json::from_str::<SchemaFragment<RawName>>(
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
                Expr::val(true),
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
