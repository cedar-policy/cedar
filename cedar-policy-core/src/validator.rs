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
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_html_tags,
    rustdoc::invalid_rust_codeblocks,
    rustdoc::bare_urls,
    clippy::doc_markdown
)]
#![cfg_attr(feature = "wasm", allow(non_snake_case))]

use crate::ast::{Policy, PolicySet, Template};
use serde::Serialize;
use std::collections::HashSet;
mod level_validate;

mod coreschema;
#[cfg(feature = "entity-manifest")]
pub mod entity_manifest;
pub use coreschema::*;
mod diagnostics;
pub use diagnostics::*;
mod expr_iterator;
mod extension_schema;
mod extensions;
mod rbac;
mod schema;
pub use schema::err::*;
pub use schema::*;
mod deprecated_schema_compat;
pub mod json_schema;
mod str_checks;
pub use str_checks::confusable_string_checks;
pub mod cedar_schema;
pub mod typecheck;
use typecheck::Typechecker;
mod partition_nonempty;
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
#[derive(Debug, Clone)]
pub struct Validator {
    schema: ValidatorSchema,
}

impl Validator {
    /// Construct a new Validator from a schema file.
    pub fn new(schema: ValidatorSchema) -> Validator {
        Self { schema }
    }

    /// Get the `ValidatorSchema` this `Validator` is using.
    pub fn schema(&self) -> &ValidatorSchema {
        &self.schema
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

    /// Validate all templates, links, and static policies in a policy set.
    /// If validation passes, also run level validation with `max_deref_level`
    /// (see RFC 76).
    /// Return a `ValidationResult`.
    pub fn validate_with_level(
        &self,
        policies: &PolicySet,
        mode: ValidationMode,
        max_deref_level: u32,
    ) -> ValidationResult {
        let validate_policy_results: (Vec<_>, Vec<_>) = policies
            .all_templates()
            .map(|p| self.validate_policy_with_level(p, mode, max_deref_level))
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
                    .chain(self.validate_enum_entity(p))
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
        let typecheck = Typechecker::new(&self.schema, mode);
        let mut errors = HashSet::new();
        let mut warnings = HashSet::new();
        typecheck.typecheck_policy(t, &mut errors, &mut warnings);
        (errors.into_iter(), warnings.into_iter())
    }
}

#[cfg(test)]
mod test {
    use itertools::Itertools;
    use std::{collections::HashMap, sync::Arc};

    use crate::validator::types::Type;
    use crate::validator::validation_errors::UnrecognizedActionIdHelp;
    use crate::validator::Result;

    use super::*;
    use crate::{
        ast::{self, PolicyID},
        est::Annotations,
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
                    json_schema::StandardEntityType {
                        member_of_types: vec![],
                        shape: json_schema::AttributesOrContext::default(),
                        tags: None,
                    }
                    .into(),
                ),
                (
                    bar_type.parse().unwrap(),
                    json_schema::StandardEntityType {
                        member_of_types: vec![],
                        shape: json_schema::AttributesOrContext::default(),
                        tags: None,
                    }
                    .into(),
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
                    annotations: Annotations::new(),
                    loc: None,
                    #[cfg(feature = "extended-schema")]
                    defn_loc: None,
                },
            )],
        );
        let schema = schema_file.try_into().unwrap();
        let validator = Validator::new(schema);

        let policy_a_src = r#"permit(principal in foo_type::"a", action == Action::"actin", resource == bar_type::"b");"#;
        let policy_a = parser::parse_policy(Some(PolicyID::from_string("pola")), policy_a_src)
            .expect("Test Policy Should Parse");
        set.add_static(policy_a)
            .expect("Policy already present in PolicySet");

        let policy_b_src = r#"permit(principal in foo_tye::"a", action == Action::"action", resource == br_type::"b");"#;
        let policy_b = parser::parse_policy(Some(PolicyID::from_string("polb")), policy_b_src)
            .expect("Test Policy Should Parse");
        set.add_static(policy_b)
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
            Some(UnrecognizedActionIdHelp::SuggestAlternative(
                "Action::\"action\"".to_string(),
            )),
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
            loc,
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

#[cfg(test)]
mod enumerated_entity_types {
    use crate::{
        ast::{Eid, EntityUID, ExprBuilder, PolicyID},
        expr_builder::ExprBuilder as _,
        extensions::Extensions,
        parser::parse_policy_or_template,
    };
    use cool_asserts::assert_matches;
    use itertools::Itertools;

    use crate::validator::{
        typecheck::test::test_utils::get_loc,
        types::{EntityLUB, Type},
        validation_errors::AttributeAccess,
        ValidationError, ValidationWarning, Validator, ValidatorSchema,
    };

    #[track_caller]
    fn schema() -> ValidatorSchema {
        ValidatorSchema::from_json_value(
            serde_json::json!(
                {
                    "":  {  "entityTypes": {
                             "Foo": {
                                "enum": [ "foo" ],
                            },
                            "Bar": {
                                "memberOfTypes": ["Foo"],
                            }
                        },
                        "actions": {
                            "a": {
                                "appliesTo": {
                                    "principalTypes": ["Foo"],
                                    "resourceTypes": ["Bar"],
                                }
                            }
                        }
                }
            }
            ),
            Extensions::none(),
        )
        .unwrap()
    }

    #[test]
    fn basic() {
        let schema = schema();
        let template = parse_policy_or_template(None, r#"permit(principal, action == Action::"a", resource) when { principal == Foo::"foo" };"#).unwrap();
        let validator = Validator::new(schema);
        let (errors, warnings) =
            validator.validate_policy(&template, crate::validator::ValidationMode::Strict);
        assert!(warnings.collect_vec().is_empty());
        assert!(errors.collect_vec().is_empty());
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn basic_invalid() {
        let schema = schema();
        let template = parse_policy_or_template(None, r#"permit(principal, action == Action::"a", resource) when { principal == Foo::"fo" };"#).unwrap();
        let validator = Validator::new(schema.clone());
        let (errors, warnings) =
            validator.validate_policy(&template, crate::validator::ValidationMode::Strict);
        assert!(warnings.collect_vec().is_empty());
        assert_matches!(&errors.collect_vec(), [ValidationError::InvalidEnumEntity(err)] => {
            assert_eq!(err.err.choices, vec![Eid::new("foo")]);
            assert_eq!(err.err.uid, EntityUID::with_eid_and_type("Foo", "fo").unwrap());
        });

        let template = parse_policy_or_template(
            None,
            r#"permit(principal == Foo::"🏈", action == Action::"a", resource);"#,
        )
        .unwrap();
        let validator = Validator::new(schema.clone());
        let (errors, warnings) =
            validator.validate_policy(&template, crate::validator::ValidationMode::Strict);
        assert!(warnings.collect_vec().is_empty());
        assert_matches!(&errors.collect_vec(), [ValidationError::InvalidEnumEntity(err)] => {
            assert_eq!(err.err.choices, vec![Eid::new("foo")]);
            assert_eq!(err.err.uid, EntityUID::with_eid_and_type("Foo", "🏈").unwrap());
        });

        let template = parse_policy_or_template(
            None,
            r#"permit(principal in Foo::"🏈", action == Action::"a", resource);"#,
        )
        .unwrap();
        let validator = Validator::new(schema.clone());
        let (errors, warnings) =
            validator.validate_policy(&template, crate::validator::ValidationMode::Strict);
        assert!(warnings.collect_vec().is_empty());
        assert_matches!(&errors.collect_vec(), [ValidationError::InvalidEnumEntity(err)] => {
            assert_eq!(err.err.choices, vec![Eid::new("foo")]);
            assert_eq!(err.err.uid, EntityUID::with_eid_and_type("Foo", "🏈").unwrap());
        });

        let template = parse_policy_or_template(
            None,
            r#"permit(principal, action == Action::"a", resource)
            when { {"🏈": Foo::"🏈"} has "🏈" };
        "#,
        )
        .unwrap();
        let validator = Validator::new(schema.clone());
        let (errors, warnings) =
            validator.validate_policy(&template, crate::validator::ValidationMode::Strict);
        assert!(warnings.collect_vec().is_empty());
        assert_matches!(&errors.collect_vec(), [ValidationError::InvalidEnumEntity(err)] => {
            assert_eq!(err.err.choices, vec![Eid::new("foo")]);
            assert_eq!(err.err.uid, EntityUID::with_eid_and_type("Foo", "🏈").unwrap());
        });

        let template = parse_policy_or_template(
            None,
            r#"permit(principal, action == Action::"a", resource)
            when { [Foo::"🏈"].isEmpty() };
        "#,
        )
        .unwrap();
        let validator = Validator::new(schema.clone());
        let (errors, warnings) =
            validator.validate_policy(&template, crate::validator::ValidationMode::Strict);
        assert!(warnings.collect_vec().is_empty());
        assert_matches!(&errors.collect_vec(), [ValidationError::InvalidEnumEntity(err)] => {
            assert_eq!(err.err.choices, vec![Eid::new("foo")]);
            assert_eq!(err.err.uid, EntityUID::with_eid_and_type("Foo", "🏈").unwrap());
        });

        let template = parse_policy_or_template(
            None,
            r#"permit(principal, action == Action::"a", resource)
            when { [{"🏈": Foo::"🏈"}].isEmpty() };
        "#,
        )
        .unwrap();
        let validator = Validator::new(schema);
        let (errors, warnings) =
            validator.validate_policy(&template, crate::validator::ValidationMode::Strict);
        assert!(warnings.collect_vec().is_empty());
        assert_matches!(&errors.collect_vec(), [ValidationError::InvalidEnumEntity(err)] => {
            assert_eq!(err.err.choices, vec![Eid::new("foo")]);
            assert_eq!(err.err.uid, EntityUID::with_eid_and_type("Foo", "🏈").unwrap());
        });
    }

    #[test]
    fn no_attrs_allowed() {
        let schema = schema();
        let src = r#"permit(principal, action == Action::"a", resource) when { principal.foo == "foo" };"#;
        let template = parse_policy_or_template(None, src).unwrap();
        let validator = Validator::new(schema);
        let (errors, warnings) =
            validator.validate_policy(&template, crate::validator::ValidationMode::Strict);
        assert!(warnings.collect_vec().is_empty());
        assert_eq!(
            errors.collect_vec(),
            [ValidationError::unsafe_attribute_access(
                get_loc(src, "principal.foo"),
                PolicyID::from_string("policy0"),
                AttributeAccess::EntityLUB(
                    EntityLUB::single_entity("Foo".parse().unwrap()),
                    vec!["foo".into()],
                ),
                None,
                false,
            )]
        );
    }

    #[test]
    fn no_ancestors() {
        let schema = schema();
        let src = r#"permit(principal, action == Action::"a", resource) when { principal in Bar::"bar" };"#;
        let template = parse_policy_or_template(None, src).unwrap();
        let validator = Validator::new(schema);
        let (errors, warnings) =
            validator.validate_policy(&template, crate::validator::ValidationMode::Strict);
        assert_eq!(
            warnings.collect_vec(),
            [ValidationWarning::impossible_policy(
                get_loc(src, src),
                PolicyID::from_string("policy0")
            )]
        );
        assert!(errors.collect_vec().is_empty());
    }

    #[test]
    fn no_tags_allowed() {
        let schema = schema();
        let src = r#"permit(principal, action == Action::"a", resource) when { principal.getTag("foo") == "foo" };"#;
        let template = parse_policy_or_template(None, src).unwrap();
        let validator = Validator::new(schema);
        let (errors, warnings) =
            validator.validate_policy(&template, crate::validator::ValidationMode::Strict);
        assert!(warnings.collect_vec().is_empty());
        assert_eq!(
            errors.collect_vec(),
            [ValidationError::unsafe_tag_access(
                get_loc(src, r#"principal.getTag("foo")"#),
                PolicyID::from_string("policy0"),
                Some(EntityLUB::single_entity("Foo".parse().unwrap()),),
                {
                    let builder = ExprBuilder::new();
                    let mut expr = builder.val("foo");
                    expr.set_data(Some(Type::primitive_string()));
                    expr
                },
            )]
        );
    }
}
