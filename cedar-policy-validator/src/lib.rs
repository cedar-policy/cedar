/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

use std::collections::HashSet;

use cedar_policy_core::ast::{PolicySet, Template};

mod err;
mod str_checks;
pub use err::*;
mod expr_iterator;
mod extension_schema;
mod extensions;
mod fuzzy_match;
mod validation_result;
use serde::Serialize;
pub use validation_result::*;
mod rbac;
mod schema;
pub use schema::*;
mod schema_file_format;
pub use schema_file_format::*;
mod type_error;
pub use type_error::*;
pub mod typecheck;
pub mod types;

pub use str_checks::{confusable_string_checks, ValidationWarning, ValidationWarningKind};

use self::typecheck::Typechecker;

/// Used to select how a policy will be validated.
#[derive(Default, Eq, PartialEq, Copy, Clone, Debug, Serialize)]
pub enum ValidationMode {
    #[default]
    Strict,
    Permissive,
}

impl ValidationMode {
    /// Does this mode apply strict validation rules.
    fn is_strict(self) -> bool {
        match self {
            ValidationMode::Strict => true,
            ValidationMode::Permissive => false,
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

    /// Validate all templates in a policy set (which includes static policies) and
    /// return an iterator of policy notes associated with each policy id.
    pub fn validate<'a>(
        &'a self,
        policies: &'a PolicySet,
        mode: ValidationMode,
    ) -> ValidationResult<'a> {
        let template_errs = policies
            .all_templates()
            .flat_map(|p| self.validate_policy(p, mode));
        let instantiation_errs = policies.policies().flat_map(|p| {
            self.validate_slots(p.env())
                .map(move |note| ValidationError::with_policy_id(p.id(), None, note))
        });
        ValidationResult::new(template_errs.chain(instantiation_errs))
    }

    /// Run all validations against a single policy, gathering all validation
    /// notes from together in the returned iterator.
    fn validate_policy<'a>(
        &'a self,
        p: &'a Template,
        mode: ValidationMode,
    ) -> impl Iterator<Item = ValidationError> + 'a {
        self.validate_entity_types(p)
            .chain(self.validate_action_ids(p))
            .chain(self.validate_action_application(p))
            .map(move |note| ValidationError::with_policy_id(p.id(), None, note))
            .chain(self.typecheck_policy(p, mode))
    }

    /// Construct a Typechecker instance and use it to detect any type errors in
    /// the argument policy in the context of the schema for this validator. Any
    /// detected type errors are wrapped and returned as `ValidationErrorKind`s.
    fn typecheck_policy<'a>(
        &'a self,
        t: &'a Template,
        mode: ValidationMode,
    ) -> impl Iterator<Item = ValidationError> + 'a {
        let typecheck = Typechecker::new(&self.schema, mode);
        let mut type_errors = HashSet::new();
        typecheck.typecheck_policy(t, &mut type_errors);
        type_errors.into_iter().map(|type_error| {
            let (kind, location) = type_error.kind_and_location();
            ValidationError::with_policy_id(t.id(), location, ValidationErrorKind::type_error(kind))
        })
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use super::*;
    use cedar_policy_core::{ast, parser};

    #[test]
    fn top_level_validate() -> Result<()> {
        let mut set = PolicySet::new();
        let foo_type = "foo_type";
        let bar_type = "bar_type";
        let action_name = "action";
        let schema_file = NamespaceDefinition::new(
            [
                (
                    foo_type.into(),
                    EntityType {
                        member_of_types: vec![],
                        shape: AttributesOrContext::default(),
                    },
                ),
                (
                    bar_type.into(),
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
                        resource_types: None,
                        principal_types: None,
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
        let policy_a = parser::parse_policy(Some("pola".to_string()), policy_a_src)
            .expect("Test Policy Should Parse");
        set.add_static(policy_a.clone())
            .expect("Policy already present in PolicySet");

        let policy_b_src = r#"permit(principal in foo_tye::"a", action == Action::"action", resource == br_type::"b");"#;
        let policy_b = parser::parse_policy(Some("polb".to_string()), policy_b_src)
            .expect("Test Policy Should Parse");
        set.add_static(policy_b.clone())
            .expect("Policy already present in PolicySet");

        let result = validator.validate(&set, ValidationMode::default());
        let principal_err = ValidationError::with_policy_id(
            policy_b.id(),
            None,
            ValidationErrorKind::unrecognized_entity_type(
                "foo_tye".to_string(),
                Some("foo_type".to_string()),
            ),
        );
        let resource_err = ValidationError::with_policy_id(
            policy_b.id(),
            None,
            ValidationErrorKind::unrecognized_entity_type(
                "br_type".to_string(),
                Some("bar_type".to_string()),
            ),
        );
        let action_err = ValidationError::with_policy_id(
            policy_a.id(),
            None,
            ValidationErrorKind::unrecognized_action_id(
                "Action::\"actin\"".to_string(),
                Some("Action::\"action\"".to_string()),
            ),
        );
        assert!(!result.validation_passed());
        assert!(result.validation_errors().any(|x| x == &principal_err));
        assert!(result.validation_errors().any(|x| x == &resource_err));
        assert!(result.validation_errors().any(|x| x == &action_err));

        Ok(())
    }

    #[test]
    fn top_level_validate_with_instantiations() -> Result<()> {
        let mut set = PolicySet::new();
        let schema: ValidatorSchema = serde_json::from_str::<SchemaFragment>(
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
            Some("template".to_string()),
            r#"permit(principal == some_namespace::User::"Alice", action, resource in ?resource);"#,
        )
        .expect("Parse Error");
        set.add_template(t)
            .expect("Template already present in PolicySet");

        // the template is valid by itself
        let result = validator.validate(&set, ValidationMode::default());
        assert_eq!(
            result.into_validation_errors().collect::<Vec<_>>(),
            Vec::new()
        );

        // a valid instantiation is valid
        let mut values = HashMap::new();
        values.insert(
            ast::SlotId::resource(),
            ast::EntityUID::from_components(
                "some_namespace::Photo".parse().unwrap(),
                ast::Eid::new("foo"),
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

        // an invalid instantiation results in an error
        let mut values = HashMap::new();
        values.insert(
            ast::SlotId::resource(),
            ast::EntityUID::from_components(
                "some_namespace::Undefined".parse().unwrap(),
                ast::Eid::new("foo"),
            ),
        );
        set.link(
            ast::PolicyID::from_string("template"),
            ast::PolicyID::from_string("link2"),
            values,
        )
        .expect("Linking failed!");
        let result = validator.validate(&set, ValidationMode::default());

        let pid = ast::PolicyID::from_string("link2");
        let resource_err = ValidationError::with_policy_id(
            &pid,
            None,
            ValidationErrorKind::unrecognized_entity_type(
                "some_namespace::Undefined".to_string(),
                Some("some_namespace::User".to_string()),
            ),
        );
        assert!(!result.validation_passed());
        println!("{:?}", result.validation_errors().collect::<Vec<_>>());
        assert!(result.validation_errors().any(|x| x == &resource_err));

        Ok(())
    }
}
