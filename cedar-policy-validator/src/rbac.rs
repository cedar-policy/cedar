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

//! Contains the validation logic specific to RBAC policy validation.

use cedar_policy_core::ast::{
    self, ActionConstraint, EntityReference, EntityUID, Name, PrincipalConstraint,
    PrincipalOrResourceConstraint, ResourceConstraint, SlotEnv, Template,
};

use std::{collections::HashSet, sync::Arc};

use crate::expr_iterator::{policy_entity_type_names, policy_entity_uids};

use super::{
    fuzzy_match::fuzzy_search, schema::*, validation_result::ValidationErrorKind, Validator,
};

impl Validator {
    /// Generate UnrecognizedEntityType notes for every entity type in the
    /// expression that could not also be found in the schema.
    pub(crate) fn validate_entity_types<'a>(
        &'a self,
        template: &'a Template,
    ) -> impl Iterator<Item = ValidationErrorKind> + 'a {
        // All valid entity types in the schema. These will be used to generate
        // suggestion when an entity type is not found.
        let known_entity_types = self
            .schema
            .known_entity_types()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        policy_entity_type_names(template)
            .filter_map(move |name| {
                let is_action_entity_type = is_action_entity_type(name);
                let is_known_entity_type = self.schema.is_known_entity_type(name);

                if !is_action_entity_type && !is_known_entity_type {
                    let actual_entity_type = name.to_string();
                    let suggested_entity_type =
                        fuzzy_search(&actual_entity_type, known_entity_types.as_slice());
                    Some(ValidationErrorKind::unrecognized_entity_type(
                        actual_entity_type,
                        suggested_entity_type,
                    ))
                } else {
                    None
                }
            })
            .chain(policy_entity_uids(template).filter_map(move |euid| {
                let entity_type = euid.entity_type();
                match entity_type {
                    cedar_policy_core::ast::EntityType::Unspecified => Some(
                        ValidationErrorKind::unspecified_entity(euid.eid().to_string()),
                    ),
                    cedar_policy_core::ast::EntityType::Specified(_) => None,
                }
            }))
    }

    /// Generate UnrecognizedActionId notes for every entity id with an action
    /// entity type where the id could not be found in the actions list from the
    /// schema.
    pub(crate) fn validate_action_ids<'a>(
        &'a self,
        template: &'a Template,
    ) -> impl Iterator<Item = ValidationErrorKind> + 'a {
        // Valid action id names that will be used to generate suggestions if an
        // action id is not found
        let known_action_ids = self
            .schema
            .known_action_ids()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        policy_entity_uids(template).filter_map(move |euid| {
            let entity_type = euid.entity_type();
            match entity_type {
                ast::EntityType::Unspecified => Some(ValidationErrorKind::unspecified_entity(
                    euid.eid().to_string(),
                )),
                ast::EntityType::Specified(name) => {
                    let is_known_action_entity_id = self.schema.is_known_action_id(euid);
                    let is_action_entity_type = is_action_entity_type(name);

                    if is_action_entity_type && !is_known_action_entity_id {
                        Some(ValidationErrorKind::unrecognized_action_id(
                            euid.to_string(),
                            fuzzy_search(euid.eid().as_ref(), known_action_ids.as_slice()),
                        ))
                    } else {
                        None
                    }
                }
            }
        })
    }

    /// Generate UnrecognizedEntityType or UnspecifiedEntityError notes for every
    /// entity type in the slot environment that is either not in the schema,
    /// or unspecified.
    pub(crate) fn validate_entity_types_in_slots<'a>(
        &'a self,
        slots: &'a SlotEnv,
    ) -> impl Iterator<Item = ValidationErrorKind> + 'a {
        // All valid entity types in the schema. These will be used to generate
        // suggestion when an entity type is not found.
        let known_entity_types = self
            .schema
            .known_entity_types()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        slots.values().filter_map(move |euid| {
            let entity_type = euid.entity_type();
            match entity_type {
                cedar_policy_core::ast::EntityType::Unspecified => Some(
                    ValidationErrorKind::unspecified_entity(euid.eid().to_string()),
                ),
                cedar_policy_core::ast::EntityType::Specified(name) => {
                    if !self.schema.is_known_entity_type(name) {
                        let actual_entity_type = entity_type.to_string();
                        let suggested_entity_type =
                            fuzzy_search(&actual_entity_type, known_entity_types.as_slice());
                        Some(ValidationErrorKind::unrecognized_entity_type(
                            actual_entity_type,
                            suggested_entity_type,
                        ))
                    } else {
                        None
                    }
                }
            }
        })
    }

    fn check_if_in_fixes_principal(
        &self,
        principal_constraint: &PrincipalConstraint,
        action_constraint: &ActionConstraint,
    ) -> bool {
        self.check_if_in_fixes(
            principal_constraint.as_inner(),
            &self
                .get_apply_specs_for_action(action_constraint)
                .collect::<Vec<_>>(),
            &|spec| Box::new(spec.applicable_principal_types()),
        )
    }

    fn check_if_in_fixes_resource(
        &self,
        resource_constraint: &ResourceConstraint,
        action_constraint: &ActionConstraint,
    ) -> bool {
        self.check_if_in_fixes(
            resource_constraint.as_inner(),
            &self
                .get_apply_specs_for_action(action_constraint)
                .collect::<Vec<_>>(),
            &|spec| Box::new(spec.applicable_resource_types()),
        )
    }

    fn check_if_in_fixes<'a>(
        &'a self,
        scope_constraint: &PrincipalOrResourceConstraint,
        apply_specs: &[&'a ValidatorApplySpec],
        select_apply_spec: &impl Fn(
            &'a ValidatorApplySpec,
        ) -> Box<dyn Iterator<Item = &'a ast::EntityType> + 'a>,
    ) -> bool {
        let entity_type = Validator::get_eq_comparison(scope_constraint);

        // Now we check the following property
        // not exists spec in apply_specs such that lit in spec.principals
        // AND
        // exists spec in apply_specs such that there exists principal in spec.principals such that lit `memberOf` principal
        // (as well as for resource)
        self.check_if_none_equal(apply_specs, entity_type, &select_apply_spec)
            && self.check_if_any_contain(apply_specs, entity_type, &select_apply_spec)
    }

    // This checks the first property:
    // not exists spec in apply_specs such that lit in spec.principals
    fn check_if_none_equal<'a>(
        &'a self,
        specs: &[&'a ValidatorApplySpec],
        lit_opt: Option<&Name>,
        select_apply_spec: &impl Fn(
            &'a ValidatorApplySpec,
        ) -> Box<dyn Iterator<Item = &'a ast::EntityType> + 'a>,
    ) -> bool {
        if let Some(lit) = lit_opt {
            !specs.iter().any(|spec| {
                select_apply_spec(spec).any(|e| match e {
                    ast::EntityType::Specified(e) => e == lit,
                    ast::EntityType::Unspecified => false,
                })
            })
        } else {
            false
        }
    }

    // This checks the second property
    // exists spec in apply_specs such that there exists principal in spec.principals such that lit `memberOf` principal
    fn check_if_any_contain<'a>(
        &'a self,
        specs: &[&'a ValidatorApplySpec],
        lit_opt: Option<&Name>,
        select_apply_spec: &impl Fn(
            &'a ValidatorApplySpec,
        ) -> Box<dyn Iterator<Item = &'a ast::EntityType> + 'a>,
    ) -> bool {
        if let Some(etype) = lit_opt.and_then(|typename| self.schema.get_entity_type(typename)) {
            specs.iter().any(|spec| {
                select_apply_spec(spec).any(|p| match p {
                    ast::EntityType::Specified(p) => etype.descendants.contains(p),
                    ast::EntityType::Unspecified => false,
                })
            })
        } else {
            false
        }
    }

    /// Check if an expression is an equality comparison between a literal EUID
    /// and a scope variable.  If it is, return the type of the literal EUID.
    fn get_eq_comparison(scope_constraint: &PrincipalOrResourceConstraint) -> Option<&Name> {
        match scope_constraint {
            PrincipalOrResourceConstraint::Eq(EntityReference::EUID(euid)) => {
                match euid.entity_type() {
                    ast::EntityType::Specified(name) => Some(name),
                    ast::EntityType::Unspecified => None,
                }
            }
            _ => None,
        }
    }

    // Check that there exists a (action id, principal type, resource type)
    // entity type pair where the action can be applied to both the principal
    // and resource. This function takes the three scope constraints as input
    // (rather than a template) to facilitate code reuse.
    pub(crate) fn validate_action_application(
        &self,
        principal_constraint: &PrincipalConstraint,
        action_constraint: &ActionConstraint,
        resource_constraint: &ResourceConstraint,
    ) -> impl Iterator<Item = ValidationErrorKind> {
        let mut apply_specs = self.get_apply_specs_for_action(action_constraint);
        let resources_for_scope: HashSet<&Name> = self
            .get_resources_satisfying_constraint(resource_constraint)
            .collect();
        let principals_for_scope: HashSet<&Name> = self
            .get_principals_satisfying_constraint(principal_constraint)
            .collect();

        let would_in_fix_principal =
            self.check_if_in_fixes_principal(principal_constraint, action_constraint);
        let would_in_fix_resource =
            self.check_if_in_fixes_resource(resource_constraint, action_constraint);

        Some(ValidationErrorKind::invalid_action_application(
            would_in_fix_principal,
            would_in_fix_resource,
        ))
        .filter(|_| {
            !apply_specs.any(|spec| {
                let action_principals = spec
                    .applicable_principal_types()
                    .filter_map(|ty| match ty {
                        ast::EntityType::Specified(name) => Some(name),
                        ast::EntityType::Unspecified => None,
                    })
                    .collect::<HashSet<_>>();
                let applicable_principal_unspecified = spec
                    .applicable_principal_types()
                    .any(|ty| matches!(ty, ast::EntityType::Unspecified));
                let action_resources = spec
                    .applicable_resource_types()
                    .filter_map(|ty| match ty {
                        ast::EntityType::Specified(name) => Some(name),
                        ast::EntityType::Unspecified => None,
                    })
                    .collect::<HashSet<_>>();
                let applicable_resource_unspecified = spec
                    .applicable_resource_types()
                    .any(|ty| matches!(ty, ast::EntityType::Unspecified));

                let matching_principal = applicable_principal_unspecified
                    || !principals_for_scope.is_disjoint(&action_principals);
                let matching_resource = applicable_resource_unspecified
                    || !resources_for_scope.is_disjoint(&action_resources);
                matching_principal && matching_resource
            })
        })
        .into_iter()
    }

    /// Gather all ApplySpec objects for all actions in the schema. The `applies_to`
    /// field is optional in the schema. In the case that it was not supplied, the
    /// `applies_to` field will contain `UnspecifiedEntity`.
    pub(crate) fn get_apply_specs_for_action<'a>(
        &'a self,
        action_constraint: &'a ActionConstraint,
    ) -> impl Iterator<Item = &ValidatorApplySpec> + 'a {
        self.get_actions_satisfying_constraint(action_constraint)
            // Get the action type if the id string exists, and then the
            // applies_to list.
            .filter_map(|action_id| self.schema.get_action_id(action_id))
            .map(|action| &action.applies_to)
    }

    /// Get the set of actions (action entity id strings) that satisfy the
    /// action scope constraint of the policy.
    fn get_actions_satisfying_constraint<'a>(
        &'a self,
        action_constraint: &'a ActionConstraint,
    ) -> Box<dyn Iterator<Item = &'a EntityUID> + 'a> {
        match action_constraint {
            // <var>
            ActionConstraint::Any => Box::new(self.schema.known_action_ids()),
            // <var> == <literal euid>
            ActionConstraint::Eq(euid) => Box::new(std::iter::once(euid.as_ref())),
            // <var> in [<literal euid>...]
            ActionConstraint::In(euids) => Box::new(
                self.schema
                    .get_actions_in_set(euids.iter().map(Arc::as_ref))
                    .unwrap_or_default()
                    .into_iter(),
            ),
        }
    }

    /// Get the set of principals (entity type strings) that satisfy the principal
    /// scope constraint of the policy.
    pub(crate) fn get_principals_satisfying_constraint<'a>(
        &'a self,
        principal_constraint: &'a PrincipalConstraint,
    ) -> impl Iterator<Item = &'a Name> + 'a {
        self.get_entity_types_satisfying_constraint(principal_constraint.as_inner())
    }

    /// Get the set of resources (entity type strings) that satisfy the resource
    /// scope constraint of the policy.
    pub(crate) fn get_resources_satisfying_constraint<'a>(
        &'a self,
        resource_constraint: &'a ResourceConstraint,
    ) -> impl Iterator<Item = &'a Name> + 'a {
        self.get_entity_types_satisfying_constraint(resource_constraint.as_inner())
    }

    // Get the set of entity types satisfying the condition for the principal
    // or resource variable in the policy scope.
    fn get_entity_types_satisfying_constraint<'a>(
        &'a self,
        scope_constraint: &'a PrincipalOrResourceConstraint,
    ) -> Box<dyn Iterator<Item = &'a Name> + 'a> {
        match scope_constraint {
            // <var>
            PrincipalOrResourceConstraint::Any => Box::new(self.schema.known_entity_types()),
            // <var> == <literal euid>
            PrincipalOrResourceConstraint::Eq(EntityReference::EUID(euid)) => Box::new(
                match euid.entity_type() {
                    ast::EntityType::Specified(name) => Some(name),
                    ast::EntityType::Unspecified => None,
                }
                .into_iter(),
            ),
            // <var> in <literal euid>
            PrincipalOrResourceConstraint::In(EntityReference::EUID(euid)) => {
                Box::new(self.schema.get_entity_types_in(euid.as_ref()).into_iter())
            }
            PrincipalOrResourceConstraint::Eq(EntityReference::Slot)
            | PrincipalOrResourceConstraint::In(EntityReference::Slot) => {
                Box::new(self.schema.known_entity_types())
            }
            PrincipalOrResourceConstraint::Is(entity_type)
            | PrincipalOrResourceConstraint::IsIn(entity_type, EntityReference::Slot) => Box::new(
                if self.schema.is_known_entity_type(entity_type) {
                    Some(entity_type)
                } else {
                    None
                }
                .into_iter(),
            ),
            PrincipalOrResourceConstraint::IsIn(entity_type, EntityReference::EUID(in_entity)) => {
                Box::new(
                    self.schema
                        .get_entity_types_in(in_entity.as_ref())
                        .into_iter()
                        .filter(move |k| &entity_type == k),
                )
            }
        }
    }
}

// PANIC SAFETY unit tests
#[allow(clippy::panic)]
// PANIC SAFETY unit tests
#[allow(clippy::indexing_slicing)]
#[cfg(test)]
mod test {
    use std::collections::{HashMap, HashSet};

    use cedar_policy_core::{
        ast::{
            Annotations, Effect, Eid, EntityUID, Expr, PolicyID, PrincipalConstraint,
            ResourceConstraint,
        },
        parser::{parse_policy, parse_policy_template},
    };

    use super::*;
    use crate::{
        err::*, schema_file_format::NamespaceDefinition, schema_file_format::*, TypeErrorKind,
        UnrecognizedActionId, UnrecognizedEntityType, UnspecifiedEntityError, ValidationError,
        ValidationMode, Validator,
    };

    use cool_asserts::assert_matches;

    #[test]
    fn validate_entity_type_empty_schema() -> Result<()> {
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::any(),
            ResourceConstraint::is_eq(
                EntityUID::with_eid_and_type("foo_type", "foo_name").expect("should be valid"),
            ),
            Expr::val(true),
        );

        let validate = Validator::new(ValidatorSchema::empty());
        let notes: Vec<ValidationErrorKind> = validate.validate_entity_types(&policy).collect();

        assert_eq!(1, notes.len());
        match notes.first() {
            Some(ValidationErrorKind::UnrecognizedEntityType(UnrecognizedEntityType {
                actual_entity_type,
                suggested_entity_type,
            })) => {
                assert_eq!("foo_type", actual_entity_type);
                assert!(
                    suggested_entity_type.is_none(),
                    "Did not expect suggested entity type."
                );
            }
            _ => panic!("Unexpected variant of ValidationErrorKind."),
        };

        Ok(())
    }

    #[test]
    fn validate_equals_instead_of_in() -> Result<()> {
        let user_type = "user";
        let group_type = "admins";
        let widget_type = "widget";
        let bin_type = "bin";
        let action_name = "act";
        let schema_file = NamespaceDefinition::new(
            [
                (
                    user_type.into(),
                    EntityType {
                        member_of_types: vec![group_type.into()],
                        shape: AttributesOrContext::default(),
                    },
                ),
                (
                    group_type.into(),
                    EntityType {
                        member_of_types: vec![],
                        shape: AttributesOrContext::default(),
                    },
                ),
                (
                    widget_type.into(),
                    EntityType {
                        member_of_types: vec![bin_type.into()],
                        shape: AttributesOrContext::default(),
                    },
                ),
                (
                    bin_type.into(),
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
                        resource_types: Some(vec![widget_type.into()]),
                        principal_types: Some(vec![user_type.into()]),
                        context: AttributesOrContext::default(),
                    }),
                    member_of: None,
                    attributes: None,
                },
            )],
        );
        let schema = schema_file.try_into().unwrap();

        let group_eid = EntityUID::with_eid_and_type(group_type, "admin1").expect("");

        let action_eid = EntityUID::with_eid_and_type("Action", action_name).expect("");

        let bin_eid = EntityUID::with_eid_and_type(bin_type, "bin").expect("");

        let principal_constraint = PrincipalConstraint::is_eq(group_eid);
        let action_constraint = ActionConstraint::is_eq(action_eid);
        let resource_constraint = ResourceConstraint::is_eq(bin_eid);

        let v = Validator::new(schema);

        let notes = v
            .validate_action_application(
                &principal_constraint,
                &action_constraint,
                &resource_constraint,
            )
            .collect::<Vec<_>>();

        assert_eq!(
            vec![ValidationErrorKind::invalid_action_application(true, true)],
            notes,
            "Validation result did not contain InvalidActionApplication with both suggested fixes."
        );
        Ok(())
    }

    #[test]
    fn validate_entity_type_in_singleton_schema() -> Result<()> {
        let foo_type = "foo_type";
        let schema_file = NamespaceDefinition::new(
            [(
                foo_type.into(),
                EntityType {
                    member_of_types: vec![],
                    shape: AttributesOrContext::default(),
                },
            )],
            [],
        );
        let singleton_schema = schema_file.try_into().unwrap();
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::any(),
            ResourceConstraint::is_eq(
                EntityUID::with_eid_and_type(foo_type, "foo_name")
                    .expect("should be a valid identifier"),
            ),
            Expr::val(true),
        );

        let validate = Validator::new(singleton_schema);
        assert!(
            validate.validate_entity_types(&policy).next().is_none(),
            "Did not expect any validation notes."
        );

        Ok(())
    }

    #[test]
    fn validate_entity_type_not_in_singleton_schema() -> Result<()> {
        let schema_file = NamespaceDefinition::new(
            [(
                "foo_type".into(),
                EntityType {
                    member_of_types: vec![],
                    shape: AttributesOrContext::default(),
                },
            )],
            [],
        );
        let singleton_schema = schema_file.try_into().unwrap();
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::is_eq(
                EntityUID::with_eid_and_type("bar_type", "bar_name")
                    .expect("should be a valid identifier"),
            ),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let validate = Validator::new(singleton_schema);
        let notes: Vec<ValidationErrorKind> = validate.validate_entity_types(&policy).collect();

        assert_eq!(1, notes.len());
        match notes.first() {
            Some(ValidationErrorKind::UnrecognizedEntityType(UnrecognizedEntityType {
                actual_entity_type,
                suggested_entity_type,
            })) => {
                assert_eq!("bar_type", actual_entity_type);
                assert_eq!(
                    "foo_type",
                    suggested_entity_type
                        .as_ref()
                        .expect("Expected a suggested entity type")
                );
            }
            _ => panic!("Unexpected variant of ValidationErrorKind."),
        };

        Ok(())
    }

    #[test]
    fn validate_action_id_empty_schema() -> Result<()> {
        let entity = EntityUID::with_eid_and_type("Action", "foo_name")
            .expect("should be a valid identifier");
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::is_eq(entity),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let validate = Validator::new(ValidatorSchema::empty());
        let notes: Vec<ValidationErrorKind> = validate.validate_action_ids(&policy).collect();

        assert_eq!(1, notes.len());
        match notes.first() {
            Some(ValidationErrorKind::UnrecognizedActionId(UnrecognizedActionId {
                actual_action_id,
                suggested_action_id,
            })) => {
                assert_eq!("Action::\"foo_name\"", actual_action_id);
                assert!(
                    suggested_action_id.is_none(),
                    "Did not expect suggested action id."
                );
            }
            _ => panic!("Unexpected variant of ValidationErrorKind."),
        };

        Ok(())
    }

    #[test]
    fn validate_action_id_in_singleton_schema() -> Result<()> {
        let foo_name = "foo_name";
        let schema_file = NamespaceDefinition::new(
            [],
            [(
                foo_name.into(),
                ActionType {
                    applies_to: None,
                    member_of: None,
                    attributes: None,
                },
            )],
        );
        let singleton_schema = schema_file.try_into().unwrap();
        let entity =
            EntityUID::with_eid_and_type("Action", foo_name).expect("should be a valid identifier");
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::is_eq(entity),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let validate = Validator::new(singleton_schema);
        assert!(
            validate.validate_action_ids(&policy).next().is_none(),
            "Did not expect any validation notes."
        );

        Ok(())
    }

    #[test]
    fn validate_principal_slot_in_singleton_schema() {
        let p_name = "User";
        let schema_file = NamespaceDefinition::new(
            [(
                p_name.into(),
                EntityType {
                    member_of_types: vec![],
                    shape: AttributesOrContext::default(),
                },
            )],
            [],
        );
        let schema = schema_file.try_into().unwrap();
        let principal_constraint = PrincipalConstraint::is_eq_slot();
        let validator = Validator::new(schema);
        let entities = validator
            .get_principals_satisfying_constraint(&principal_constraint)
            .collect::<Vec<_>>();
        assert_eq!(entities.len(), 1);
        let name = entities[0];
        assert_eq!(name, &p_name.parse().expect("Expected valid entity type."));
    }

    #[test]
    fn validate_resource_slot_in_singleton_schema() {
        let p_name = "Package";
        let schema_file = NamespaceDefinition::new(
            [(
                p_name.into(),
                EntityType {
                    member_of_types: vec![],
                    shape: AttributesOrContext::default(),
                },
            )],
            [],
        );
        let schema = schema_file.try_into().unwrap();
        let principal_constraint = PrincipalConstraint::any();
        let validator = Validator::new(schema);
        let entities = validator
            .get_principals_satisfying_constraint(&principal_constraint)
            .collect::<Vec<_>>();
        assert_eq!(entities.len(), 1);
        let name = entities[0];
        assert_eq!(name, &p_name.parse().expect("Expected valid entity type."));
    }

    #[test]
    fn undefined_entity_type_in_principal_slot() -> Result<()> {
        let p_name = "User";
        let schema_file = NamespaceDefinition::new(
            [(
                p_name.into(),
                EntityType {
                    member_of_types: vec![],
                    shape: AttributesOrContext::default(),
                },
            )],
            [],
        );
        let schema = schema_file.try_into().expect("Invalid schema");

        let undefined_euid: EntityUID = "Undefined::\"foo\""
            .parse()
            .expect("Expected entity UID to parse.");
        let env = HashMap::from([(ast::SlotId::principal(), undefined_euid)]);

        let validator = Validator::new(schema);
        let notes: Vec<ValidationErrorKind> =
            validator.validate_entity_types_in_slots(&env).collect();

        assert_eq!(1, notes.len());
        match notes.first() {
            Some(ValidationErrorKind::UnrecognizedEntityType(UnrecognizedEntityType {
                actual_entity_type,
                suggested_entity_type,
            })) => {
                assert_eq!("Undefined", actual_entity_type);
                assert_eq!(
                    "User",
                    suggested_entity_type
                        .as_ref()
                        .expect("Expected a suggested entity type")
                );
            }
            _ => panic!("Unexpected variant of ValidationErrorKind."),
        };

        Ok(())
    }

    #[test]
    fn validate_action_id_not_in_singleton_schema() -> Result<()> {
        let schema_file = NamespaceDefinition::new(
            [],
            [(
                "foo_name".into(),
                ActionType {
                    applies_to: None,
                    member_of: None,
                    attributes: None,
                },
            )],
        );
        let singleton_schema = schema_file.try_into().unwrap();
        let entity = EntityUID::with_eid_and_type("Action", "bar_name")
            .expect("Should be a valid identifier");
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::is_eq(entity),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let validate = Validator::new(singleton_schema);
        let notes: Vec<ValidationErrorKind> = validate.validate_action_ids(&policy).collect();

        assert_eq!(1, notes.len());
        match notes.first() {
            Some(ValidationErrorKind::UnrecognizedActionId(UnrecognizedActionId {
                actual_action_id,
                suggested_action_id,
            })) => {
                assert_eq!("Action::\"bar_name\"", actual_action_id);
                assert_eq!(
                    "Action::\"foo_name\"",
                    suggested_action_id
                        .as_ref()
                        .expect("Expected suggested action id.")
                )
            }
            _ => panic!("Unexpected variant of ValidationErrorKind."),
        };

        Ok(())
    }

    #[test]
    fn validate_namespaced_action_id_in_schema() -> Result<()> {
        let descriptors: SchemaFragment = serde_json::from_str(
            r#"
                {
                    "NS": {
                        "entityTypes": {},
                        "actions": { "foo_name": {} }
                    }
                }"#,
        )
        .expect("Expected schema parse.");
        let schema = descriptors.try_into().unwrap();
        let entity: EntityUID = "NS::Action::\"foo_name\""
            .parse()
            .expect("Expected entity parse.");
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::is_eq(entity),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let validate = Validator::new(schema);
        let notes: Vec<ValidationErrorKind> = validate.validate_action_ids(&policy).collect();
        assert_eq!(notes, vec![], "Did not expect any invalid action.");
        Ok(())
    }

    #[test]
    fn validate_namespaced_invalid_action() -> Result<()> {
        let descriptors: SchemaFragment = serde_json::from_str(
            r#"
                {
                    "NS": {
                        "entityTypes": {},
                        "actions": { "foo_name": {} }
                    }
                }"#,
        )
        .expect("Expected schema parse.");
        let schema = descriptors.try_into().unwrap();
        let entity: EntityUID = "Bogus::Action::\"foo_name\""
            .parse()
            .expect("Expected entity parse.");
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::is_eq(entity),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let validate = Validator::new(schema);
        let notes: Vec<ValidationErrorKind> = validate.validate_action_ids(&policy).collect();
        assert_eq!(
            notes,
            vec![ValidationErrorKind::unrecognized_action_id(
                "Bogus::Action::\"foo_name\"".into(),
                Some("NS::Action::\"foo_name\"".into()),
            )]
        );
        Ok(())
    }

    #[test]
    fn validate_namespaced_entity_type_in_schema() -> Result<()> {
        let descriptors: SchemaFragment = serde_json::from_str(
            r#"
                {
                    "NS": {
                        "entityTypes": {"Foo": {} },
                        "actions": {}
                    }
                }"#,
        )
        .expect("Expected schema parse.");
        let schema = descriptors.try_into().unwrap();
        let entity_type: Name = "NS::Foo".parse().expect("Expected entity type parse.");
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::is_eq(EntityUID::from_components(entity_type, Eid::new("bar"))),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let validate = Validator::new(schema);
        let notes: Vec<ValidationErrorKind> = validate.validate_entity_types(&policy).collect();
        assert_eq!(notes, vec![], "Did not expect any invalid action.");
        Ok(())
    }

    #[test]
    fn validate_namespaced_invalid_entity_type() -> Result<()> {
        let descriptors: SchemaFragment = serde_json::from_str(
            r#"
                {
                    "NS": {
                        "entityTypes": {"Foo": {} },
                        "actions": {}
                    }
                }"#,
        )
        .expect("Expected schema parse.");
        let schema = descriptors.try_into().unwrap();
        let entity_type: Name = "Bogus::Foo".parse().expect("Expected entity type parse.");
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::is_eq(EntityUID::from_components(entity_type, Eid::new("bar"))),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let validate = Validator::new(schema);
        let notes: Vec<ValidationErrorKind> = validate.validate_entity_types(&policy).collect();
        assert_eq!(
            notes,
            vec![ValidationErrorKind::unrecognized_entity_type(
                "Bogus::Foo".into(),
                Some("NS::Foo".into())
            )]
        );
        Ok(())
    }

    #[test]
    fn get_possible_actions_eq() -> Result<()> {
        let foo_name = "foo_name";
        let euid_foo =
            EntityUID::with_eid_and_type("Action", foo_name).expect("should be a valid identifier");
        let action_constraint = ActionConstraint::is_eq(euid_foo.clone());

        let schema_file = NamespaceDefinition::new(
            [],
            [(
                foo_name.into(),
                ActionType {
                    applies_to: None,
                    member_of: None,
                    attributes: None,
                },
            )],
        );
        let singleton_schema = schema_file.try_into().unwrap();

        let validate = Validator::new(singleton_schema);
        let actions = validate
            .get_actions_satisfying_constraint(&action_constraint)
            .collect();
        assert_eq!(HashSet::from([&euid_foo]), actions);

        Ok(())
    }

    #[test]
    fn get_possible_actions_in_no_parents() -> Result<()> {
        let foo_name = "foo_name";
        let euid_foo =
            EntityUID::with_eid_and_type("Action", foo_name).expect("should be a valid identifier");
        let action_constraint = ActionConstraint::is_in(vec![euid_foo.clone()]);

        let schema_file = NamespaceDefinition::new(
            [],
            [(
                foo_name.into(),
                ActionType {
                    applies_to: None,
                    member_of: None,
                    attributes: None,
                },
            )],
        );
        let singleton_schema = schema_file.try_into().unwrap();

        let validate = Validator::new(singleton_schema);
        let actions = validate
            .get_actions_satisfying_constraint(&action_constraint)
            .collect();
        assert_eq!(HashSet::from([&euid_foo]), actions);

        Ok(())
    }

    #[test]
    fn get_possible_actions_in_set_no_parents() -> Result<()> {
        let foo_name = "foo_name";
        let euid_foo =
            EntityUID::with_eid_and_type("Action", foo_name).expect("should be a valid identifier");
        let action_constraint = ActionConstraint::is_in(vec![euid_foo.clone()]);

        let schema_file = NamespaceDefinition::new(
            [],
            [(
                foo_name.into(),
                ActionType {
                    applies_to: None,
                    member_of: None,
                    attributes: None,
                },
            )],
        );
        let singleton_schema = schema_file.try_into().unwrap();

        let validate = Validator::new(singleton_schema);
        let actions = validate
            .get_actions_satisfying_constraint(&action_constraint)
            .collect();
        assert_eq!(HashSet::from([&euid_foo]), actions);

        Ok(())
    }

    #[test]
    fn get_possible_principals_eq() -> Result<()> {
        let foo_type = "foo_type";
        let euid_foo = EntityUID::with_eid_and_type(foo_type, "foo_name")
            .expect("should be a valid identifier");
        let principal_constraint = PrincipalConstraint::is_eq(euid_foo.clone());

        let schema_file = NamespaceDefinition::new(
            [(
                foo_type.into(),
                EntityType {
                    member_of_types: vec![],
                    shape: AttributesOrContext::default(),
                },
            )],
            [],
        );
        let singleton_schema = schema_file.try_into().unwrap();

        let validate = Validator::new(singleton_schema);
        let principals = validate
            .get_principals_satisfying_constraint(&principal_constraint)
            .cloned()
            .map(cedar_policy_core::ast::EntityType::Specified)
            .collect::<HashSet<_>>();
        assert_eq!(HashSet::from([euid_foo.components().0]), principals);

        Ok(())
    }

    fn schema_with_single_principal_action_resource(
    ) -> (EntityUID, EntityUID, EntityUID, ValidatorSchema) {
        let action_name = "foo";
        let action_euid = EntityUID::with_eid_and_type("Action", action_name)
            .expect("should be a valid identifier");
        let principal_type = "bar";
        let principal_euid = EntityUID::with_eid_and_type(principal_type, "principal")
            .expect("should be a valid identifier");
        let resource_type = "baz";
        let resource_euid = EntityUID::with_eid_and_type(resource_type, "resource")
            .expect("should be a valid identifier");

        let schema = NamespaceDefinition::new(
            [
                (
                    principal_type.into(),
                    EntityType {
                        member_of_types: vec![],
                        shape: AttributesOrContext::default(),
                    },
                ),
                (
                    resource_type.into(),
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
                        resource_types: Some(vec![resource_type.into()]),
                        principal_types: Some(vec![principal_type.into()]),
                        context: AttributesOrContext::default(),
                    }),
                    member_of: Some(vec![]),
                    attributes: None,
                },
            )],
        )
        .try_into()
        .expect("Expected valid schema file.");
        (principal_euid, action_euid, resource_euid, schema)
    }

    #[test]
    fn validate_action_apply_correct() -> Result<()> {
        let (principal, action, resource, schema) = schema_with_single_principal_action_resource();

        let policy = Template::new(
            PolicyID::from_string("policy0"),
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::is_eq(principal),
            ActionConstraint::is_eq(action),
            ResourceConstraint::is_eq(resource),
            Expr::val(true),
        );

        let validate = Validator::new(schema);
        assert!(
            validate
                .validate_policy(&policy, ValidationMode::default())
                .next()
                .is_none(),
            "Did not expect any validation notes."
        );

        Ok(())
    }

    #[test]
    fn validate_action_apply_incorrect_principal() -> Result<()> {
        let (_, action, resource, schema) = schema_with_single_principal_action_resource();

        let principal_constraint = PrincipalConstraint::is_eq(resource.clone());
        let action_constraint = ActionConstraint::is_eq(action);
        let resource_constraint = ResourceConstraint::is_eq(resource);

        let validate = Validator::new(schema);
        let notes: Vec<ValidationErrorKind> = validate
            .validate_action_application(
                &principal_constraint,
                &action_constraint,
                &resource_constraint,
            )
            .collect();
        assert_eq!(1, notes.len());
        match notes.first() {
            Some(ValidationErrorKind::InvalidActionApplication(_)) => (),
            _ => panic!("Unexpected variant of ValidationErrorKind."),
        }

        Ok(())
    }

    #[test]
    fn validate_action_apply_incorrect_resource() -> Result<()> {
        let (principal, action, _, schema) = schema_with_single_principal_action_resource();

        let principal_constraint = PrincipalConstraint::is_eq(principal.clone());
        let action_constraint = ActionConstraint::is_eq(action);
        let resource_constraint = ResourceConstraint::is_eq(principal);

        let validate = Validator::new(schema);
        let notes: Vec<ValidationErrorKind> = validate
            .validate_action_application(
                &principal_constraint,
                &action_constraint,
                &resource_constraint,
            )
            .collect();
        assert_eq!(1, notes.len());
        match notes.first() {
            Some(ValidationErrorKind::InvalidActionApplication(_)) => (),
            _ => panic!("Unexpected variant of ValidationErrorKind."),
        }

        Ok(())
    }

    #[test]
    fn validate_action_apply_incorrect_principal_and_resource() -> Result<()> {
        let (principal, action, resource, schema) = schema_with_single_principal_action_resource();

        let principal_constraint = PrincipalConstraint::is_eq(resource);
        let action_constraint = ActionConstraint::is_eq(action);
        let resource_constraint = ResourceConstraint::is_eq(principal);

        let validate = Validator::new(schema);
        let notes: Vec<ValidationErrorKind> = validate
            .validate_action_application(
                &principal_constraint,
                &action_constraint,
                &resource_constraint,
            )
            .collect();
        assert_eq!(1, notes.len());
        match notes.first() {
            Some(ValidationErrorKind::InvalidActionApplication(_)) => (),
            _ => panic!("Unexpected variant of ValidationErrorKind."),
        }

        Ok(())
    }

    #[test]
    fn validate_used_as_correct() -> Result<()> {
        let (principal, action, resource, schema) = schema_with_single_principal_action_resource();
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::is_eq(principal),
            ActionConstraint::is_eq(action),
            ResourceConstraint::is_eq(resource),
            Expr::val(true),
        );

        let validate = Validator::new(schema);
        assert!(
            validate
                .validate_policy(&policy, ValidationMode::default())
                .next()
                .is_none(),
            "Did not expect any validation notes."
        );

        Ok(())
    }

    #[test]
    fn validate_used_as_incorrect() -> Result<()> {
        let (principal, _, resource, schema) = schema_with_single_principal_action_resource();

        let principal_constraint = PrincipalConstraint::is_eq(resource);
        let action_constraint = ActionConstraint::any();
        let resource_constraint = ResourceConstraint::is_eq(principal);

        let validate = Validator::new(schema);
        let notes: Vec<_> = validate
            .validate_action_application(
                &principal_constraint,
                &action_constraint,
                &resource_constraint,
            )
            .collect();
        assert_eq!(
            notes,
            vec![ValidationErrorKind::invalid_action_application(
                false, false
            )],
        );

        Ok(())
    }

    #[test]
    fn validate_principal_is() {
        let (_, _, _, schema) = schema_with_single_principal_action_resource();

        let policy =
            parse_policy_template(None, "permit(principal is bar, action, resource);").unwrap();

        let validate = Validator::new(schema.clone());
        assert!(
            validate
                .validate_policy(&policy, ValidationMode::default())
                .next()
                .is_none(),
            "Did not expect any validation notes."
        );

        let policy = parse_policy_template(
            None,
            r#"permit(principal is bar in bar::"baz", action, resource);"#,
        )
        .unwrap();

        let validate = Validator::new(schema);
        assert!(
            validate
                .validate_policy(&policy, ValidationMode::default())
                .next()
                .is_none(),
            "Did not expect any validation notes."
        );
    }

    #[test]
    fn validate_principal_is_err() {
        let (_, _, _, schema) = schema_with_single_principal_action_resource();

        let policy =
            parse_policy_template(None, "permit(principal is baz, action, resource);").unwrap();

        let validate = Validator::new(schema.clone());
        assert_eq!(
            validate
                .validate_policy(&policy, ValidationMode::default())
                .map(|e| { e.into_location_and_error_kind().1 })
                .collect::<Vec<ValidationErrorKind>>(),
            vec![
                ValidationErrorKind::invalid_action_application(false, false),
                ValidationErrorKind::TypeError(TypeErrorKind::ImpossiblePolicy)
            ],
        );

        let policy = parse_policy_template(
            None,
            r#"permit(principal is biz in faz::"a", action, resource);"#,
        )
        .unwrap();

        let validate = Validator::new(schema.clone());
        assert_eq!(
            validate
                .validate_policy(&policy, ValidationMode::default())
                .map(|e| { e.into_location_and_error_kind().1 })
                .collect::<Vec<ValidationErrorKind>>(),
            vec![
                ValidationErrorKind::unrecognized_entity_type("faz".into(), Some("baz".into())),
                ValidationErrorKind::unrecognized_entity_type("biz".into(), Some("baz".into())),
                ValidationErrorKind::invalid_action_application(false, false),
                ValidationErrorKind::TypeError(TypeErrorKind::ImpossiblePolicy)
            ],
        );

        let policy = parse_policy_template(
            None,
            r#"permit(principal is bar in baz::"buz", action, resource);"#,
        )
        .unwrap();

        let validate = Validator::new(schema.clone());
        assert_eq!(
            validate
                .validate_policy(&policy, ValidationMode::default())
                .map(|e| { e.into_location_and_error_kind().1 })
                .collect::<Vec<ValidationErrorKind>>(),
            vec![
                ValidationErrorKind::invalid_action_application(false, false),
                ValidationErrorKind::TypeError(TypeErrorKind::ImpossiblePolicy)
            ],
        );
    }

    #[test]
    fn validate_resource_is() {
        let (_, _, _, schema) = schema_with_single_principal_action_resource();

        let policy =
            parse_policy_template(None, "permit(principal, action, resource is baz);").unwrap();

        let validate = Validator::new(schema.clone());
        assert!(
            validate
                .validate_policy(&policy, ValidationMode::default())
                .next()
                .is_none(),
            "Did not expect any validation notes."
        );

        let policy = parse_policy_template(
            None,
            r#"permit(principal, action, resource is baz in baz::"bar");"#,
        )
        .unwrap();

        let validate = Validator::new(schema);
        assert!(
            validate
                .validate_policy(&policy, ValidationMode::default())
                .next()
                .is_none(),
            "Did not expect any validation notes."
        );
    }

    #[test]
    fn validate_resource_is_err() {
        let (_, _, _, schema) = schema_with_single_principal_action_resource();

        let policy =
            parse_policy_template(None, "permit(principal, action, resource is bar);").unwrap();

        let validate = Validator::new(schema.clone());
        assert_eq!(
            validate
                .validate_policy(&policy, ValidationMode::default())
                .map(|e| { e.into_location_and_error_kind().1 })
                .collect::<Vec<ValidationErrorKind>>(),
            vec![
                ValidationErrorKind::invalid_action_application(false, false),
                ValidationErrorKind::TypeError(TypeErrorKind::ImpossiblePolicy)
            ],
        );

        let policy = parse_policy_template(
            None,
            r#"permit(principal, action, resource is baz in bar::"buz");"#,
        )
        .unwrap();

        let validate = Validator::new(schema.clone());
        assert_eq!(
            validate
                .validate_policy(&policy, ValidationMode::default())
                .map(|e| { e.into_location_and_error_kind().1 })
                .collect::<Vec<ValidationErrorKind>>(),
            vec![
                ValidationErrorKind::invalid_action_application(false, false),
                ValidationErrorKind::TypeError(TypeErrorKind::ImpossiblePolicy)
            ],
        );

        let policy = parse_policy_template(
            None,
            r#"permit(principal, action, resource is biz in faz::"a");"#,
        )
        .unwrap();

        let validate = Validator::new(schema.clone());
        assert_eq!(
            validate
                .validate_policy(&policy, ValidationMode::default())
                .map(|e| { e.into_location_and_error_kind().1 })
                .collect::<Vec<ValidationErrorKind>>(),
            vec![
                ValidationErrorKind::unrecognized_entity_type("faz".into(), Some("baz".into())),
                ValidationErrorKind::unrecognized_entity_type("biz".into(), Some("baz".into())),
                ValidationErrorKind::invalid_action_application(false, false),
                ValidationErrorKind::TypeError(TypeErrorKind::ImpossiblePolicy)
            ],
        );
    }

    #[test]
    fn is_unknown_entity_condition() {
        let (_, _, _, schema) = schema_with_single_principal_action_resource();
        let policy = parse_policy_template(
            None,
            r#"permit(principal, action, resource) when { resource is biz };"#,
        )
        .unwrap();

        let validate = Validator::new(schema.clone());
        assert_eq!(
            validate
                .validate_policy(&policy, ValidationMode::default())
                .map(|e| { e.into_location_and_error_kind().1 })
                .collect::<Vec<ValidationErrorKind>>(),
            vec![
                ValidationErrorKind::unrecognized_entity_type("biz".into(), Some("baz".into())),
                ValidationErrorKind::TypeError(TypeErrorKind::ImpossiblePolicy)
            ],
        );
    }

    #[test]
    fn test_with_tc_computation() -> Result<()> {
        let action_name = "foo";
        let action_parent_name = "foo_parent";
        let action_grandparent_name = "foo_grandparent";
        let action_grandparent_euid =
            EntityUID::with_eid_and_type("Action", action_grandparent_name)
                .expect("should be a valid identifier");

        let principal_type = "bar";

        let resource_type = "baz";
        let resource_parent_type = "baz_parent";
        let resource_grandparent_type = "baz_grandparent";
        let resource_grandparent_euid =
            EntityUID::with_eid_and_type(resource_parent_type, "resource")
                .expect("should be a valid identifier");

        let schema_file = NamespaceDefinition::new(
            [
                (
                    principal_type.into(),
                    EntityType {
                        member_of_types: vec![],
                        shape: AttributesOrContext::default(),
                    },
                ),
                (
                    resource_type.into(),
                    EntityType {
                        member_of_types: vec![resource_parent_type.into()],
                        shape: AttributesOrContext::default(),
                    },
                ),
                (
                    resource_parent_type.into(),
                    EntityType {
                        member_of_types: vec![resource_grandparent_type.into()],
                        shape: AttributesOrContext::default(),
                    },
                ),
                (
                    resource_grandparent_type.into(),
                    EntityType {
                        member_of_types: vec![],
                        shape: AttributesOrContext::default(),
                    },
                ),
            ],
            [
                (
                    action_name.into(),
                    ActionType {
                        applies_to: Some(ApplySpec {
                            resource_types: Some(vec![resource_type.into()]),
                            principal_types: Some(vec![principal_type.into()]),
                            context: AttributesOrContext::default(),
                        }),
                        member_of: Some(vec![ActionEntityUID {
                            ty: None,
                            id: action_parent_name.into(),
                        }]),
                        attributes: None,
                    },
                ),
                (
                    action_parent_name.into(),
                    ActionType {
                        applies_to: None,
                        member_of: Some(vec![ActionEntityUID {
                            ty: None,
                            id: action_grandparent_name.into(),
                        }]),
                        attributes: None,
                    },
                ),
                (
                    action_grandparent_name.into(),
                    ActionType {
                        applies_to: None,
                        member_of: Some(vec![]),
                        attributes: None,
                    },
                ),
            ],
        );
        let schema = schema_file.try_into().unwrap();

        let policy = Template::new(
            PolicyID::from_string("policy0"),
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::is_in([action_grandparent_euid]),
            ResourceConstraint::is_in(resource_grandparent_euid),
            Expr::val(true),
        );

        let validate = Validator::new(schema);

        let notes: Vec<ValidationError> = validate
            .validate_policy(&policy, ValidationMode::default())
            .collect();
        assert!(
            notes.is_empty(),
            "Expected empty validation notes, saw {:?}",
            notes
        );

        Ok(())
    }

    #[test]
    fn unspecified_entity_in_scope() -> Result<()> {
        // Note: it's not possible to create an unspecified entity through the parser,
        // so we have to test using manually-constructed policies.
        let validate = Validator::new(ValidatorSchema::empty());

        // resource == Unspecified::"foo"
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::any(),
            ResourceConstraint::is_eq(EntityUID::unspecified_from_eid(Eid::new("foo"))),
            Expr::val(true),
        );
        let notes: Vec<ValidationErrorKind> = validate.validate_entity_types(&policy).collect();
        assert_eq!(1, notes.len());
        assert_matches!(notes.first(),
            Some(ValidationErrorKind::UnspecifiedEntity(UnspecifiedEntityError { entity_id })) => {
                assert_eq!("foo", entity_id);
            }
        );

        // principal in Unspecified::"foo"
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::is_in(EntityUID::unspecified_from_eid(Eid::new("foo"))),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            Expr::val(true),
        );
        let notes: Vec<ValidationErrorKind> = validate.validate_entity_types(&policy).collect();
        assert_eq!(1, notes.len());
        assert_matches!(notes.first(),
            Some(ValidationErrorKind::UnspecifiedEntity(UnspecifiedEntityError { entity_id })) => {
                assert_eq!("foo", entity_id);
            }
        );

        Ok(())
    }

    #[test]
    fn unspecified_entity_in_additional_constraints() -> Result<()> {
        let validate = Validator::new(ValidatorSchema::empty());

        // resource == Unspecified::"foo"
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            Expr::is_eq(
                Expr::var(cedar_policy_core::ast::Var::Resource),
                Expr::val(EntityUID::unspecified_from_eid(Eid::new("foo"))),
            ),
        );
        let notes: Vec<ValidationErrorKind> = validate.validate_entity_types(&policy).collect();
        println!("{:?}", notes);
        assert_eq!(1, notes.len());
        assert_matches!(notes.first(),
            Some(ValidationErrorKind::UnspecifiedEntity(UnspecifiedEntityError { entity_id })) => {
                assert_eq!("foo", entity_id);
            }
        );

        Ok(())
    }

    #[test]
    fn action_with_unspecified_resource_applies() {
        let schema = serde_json::from_str::<NamespaceDefinition>(
            r#"
        {
            "entityTypes": {"a": {}},
            "actions": {
                "": {
                    "appliesTo": {
                        "principalTypes": ["a"],
                        "resourceTypes": null
                    }
                }
            }
        }
        "#,
        )
        .unwrap()
        .try_into()
        .unwrap();
        let policy = parse_policy(
            Some("0".to_string()),
            r#"permit(principal == a::"", action == Action::"", resource);"#,
        )
        .unwrap();

        let validate = Validator::new(schema);
        let (template, _) = Template::link_static_policy(policy);
        let mut errs = validate.validate_policy(&template, ValidationMode::default());
        assert!(
            errs.next().is_none(),
            "Did not expect any validation errors."
        );
    }

    #[test]
    fn action_with_unspecified_principal_applies() {
        let schema = serde_json::from_str::<NamespaceDefinition>(
            r#"
        {
            "entityTypes": {"a": {}},
            "actions": {
                "": {
                    "appliesTo": {
                        "principalTypes": null,
                        "resourceTypes": ["a"]
                    }
                }
            }
        }
        "#,
        )
        .unwrap()
        .try_into()
        .unwrap();
        let policy = parse_policy(
            Some("0".to_string()),
            r#"permit(principal, action == Action::"", resource == a::"");"#,
        )
        .unwrap();

        let validate = Validator::new(schema);
        let (template, _) = Template::link_static_policy(policy);
        let mut errs = validate.validate_policy(&template, ValidationMode::default());
        assert!(
            errs.next().is_none(),
            "Did not expect any validation errors."
        );
    }

    #[test]
    fn unspecified_principal_resource_with_scope_conditions() {
        let schema = serde_json::from_str::<NamespaceDefinition>(
            r#"
        {
            "entityTypes": {"a": {}},
            "actions": {
                "": { }
            }
        }
        "#,
        )
        .unwrap()
        .try_into()
        .unwrap();
        let policy = parse_policy(
            Some("0".to_string()),
            r#"permit(principal == a::"p", action, resource == a::"r");"#,
        )
        .unwrap();

        let validate = Validator::new(schema);
        let (template, _) = Template::link_static_policy(policy);
        let errs = validate.validate_policy(&template, ValidationMode::default());
        assert_eq!(
            errs.map(|e| e.into_location_and_error_kind().1)
                .collect::<Vec<_>>(),
            vec![ValidationErrorKind::type_error(
                TypeErrorKind::ImpossiblePolicy
            )]
        );
    }
}

#[cfg(test)]
#[cfg(feature = "partial-validate")]
mod partial_schema {
    use cedar_policy_core::{
        ast::{StaticPolicy, Template},
        parser::parse_policy,
    };

    use crate::{NamespaceDefinition, Validator};

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_validates_with_empty_schema(policy: StaticPolicy) {
        let schema = serde_json::from_str::<NamespaceDefinition>(
            r#"
        {
            "entityTypes": { },
            "actions": {}
        }
        "#,
        )
        .unwrap()
        .try_into()
        .unwrap();

        let (template, _) = Template::link_static_policy(policy);
        let validate = Validator::new(schema);
        let errs = validate
            .validate_policy(&template, crate::ValidationMode::Partial)
            .collect::<Vec<_>>();
        assert_eq!(errs, vec![], "Did not expect any validation errors.");
    }

    #[test]
    fn undeclared_entity_type_partial_schema() {
        let policy = parse_policy(
            Some("0".to_string()),
            r#"permit(principal == User::"alice", action, resource);"#,
        )
        .unwrap();
        assert_validates_with_empty_schema(policy);

        let policy = parse_policy(
            Some("0".to_string()),
            r#"permit(principal, action == Action::"view", resource);"#,
        )
        .unwrap();
        assert_validates_with_empty_schema(policy);

        let policy = parse_policy(
            Some("0".to_string()),
            r#"permit(principal, action, resource == Photo::"party.jpg");"#,
        )
        .unwrap();
        assert_validates_with_empty_schema(policy);
    }
}
