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
    self, ActionConstraint, EntityReference, EntityUID, Name, PrincipalOrResourceConstraint,
    SlotEnv, Template,
};

use std::{collections::HashSet, sync::Arc};

/// Enum for representing a reference to any variation of a HeadConstraint
#[derive(Debug, Clone)]
pub enum HeadConstraint<'a> {
    /// Represents constraints on the principal or resource
    PrincipalOrResource(&'a PrincipalOrResourceConstraint),
    /// Represents action constraints
    Action(&'a ActionConstraint),
}

impl<'a> From<&'a ActionConstraint> for HeadConstraint<'a> {
    fn from(a: &'a ActionConstraint) -> Self {
        HeadConstraint::Action(a)
    }
}

impl<'a> From<&'a PrincipalOrResourceConstraint> for HeadConstraint<'a> {
    fn from(por: &'a PrincipalOrResourceConstraint) -> Self {
        HeadConstraint::PrincipalOrResource(por)
    }
}

use crate::expr_iterator::policy_entity_uids;

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

        policy_entity_uids(template).filter_map(move |euid| {
            let entity_type = euid.entity_type();
            match entity_type {
                cedar_policy_core::ast::EntityType::Unspecified => Some(
                    ValidationErrorKind::unspecified_entity(euid.eid().to_string()),
                ),
                cedar_policy_core::ast::EntityType::Concrete(name) => {
                    let is_action_entity_type = is_action_entity_type(name);
                    let is_known_entity_type = self.schema.is_known_entity_type(name);

                    if !is_action_entity_type && !is_known_entity_type {
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
                ast::EntityType::Concrete(name) => {
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

    /// Generate UnrecognizedEntityType or UnspecifiedEntity notes for every
    /// entity type in the slot environment that is either not in the schema,
    /// or unspecified.
    pub(crate) fn validate_slots<'a>(
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
                cedar_policy_core::ast::EntityType::Concrete(name) => {
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

    fn check_if_in_fixes_principal(&self, template: &Template) -> bool {
        self.check_if_in_fixes(
            template.principal_constraint().as_inner(),
            &self
                .get_apply_specs_for_action(template)
                .collect::<Vec<_>>(),
            &|spec| Box::new(spec.applicable_principal_types()),
        )
    }

    fn check_if_in_fixes_resource(&self, template: &Template) -> bool {
        self.check_if_in_fixes(
            template.resource_constraint().as_inner(),
            &self
                .get_apply_specs_for_action(template)
                .collect::<Vec<_>>(),
            &|spec| Box::new(spec.applicable_resource_types()),
        )
    }

    fn check_if_in_fixes<'a>(
        &'a self,
        head_var_condition: &PrincipalOrResourceConstraint,
        apply_specs: &[&'a ValidatorApplySpec],
        select_apply_spec: &impl Fn(
            &'a ValidatorApplySpec,
        ) -> Box<dyn Iterator<Item = &'a ast::EntityType> + 'a>,
    ) -> bool {
        let euid = Validator::get_eq_comparison(
            head_var_condition,
            PrincipalOrResourceHeadVar::PrincipalOrResource,
        );

        // Now we check the following property
        // not exists spec in apply_specs such that lit in spec.principals
        // AND
        // exists spec in apply_specs such that there exists principal in spec.principals such that lit `memberOf` principal
        // (as well as for resource)
        self.check_if_none_equal(apply_specs, euid.as_ref(), &select_apply_spec)
            && self.check_if_any_contain(apply_specs, euid.as_ref(), &select_apply_spec)
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
                    ast::EntityType::Concrete(e) => e == lit,
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
                    ast::EntityType::Concrete(p) => etype.descendants.contains(p),
                    ast::EntityType::Unspecified => false,
                })
            })
        } else {
            false
        }
    }

    /// Check if an expression is an equality comparison between a literal EUID and a head variable.
    /// If it is, return the EUID.
    fn get_eq_comparison<K>(
        head_var_condition: &PrincipalOrResourceConstraint,
        var: impl HeadVar<K>,
    ) -> Option<K> {
        match head_var_condition {
            PrincipalOrResourceConstraint::Eq(EntityReference::EUID(euid)) => {
                var.get_euid_component(euid.as_ref().clone())
            }
            _ => None,
        }
    }

    // Check that there exists a (action id, principal type, resource type)
    // entity type pair where the action can be applied to both the principal
    // and resource.
    pub(crate) fn validate_action_application(
        &self,
        template: &Template,
    ) -> impl Iterator<Item = ValidationErrorKind> {
        let mut apply_specs = self.get_apply_specs_for_action(template);
        let resources_for_head: HashSet<Name> =
            self.get_resources_satisfying_constraint(template).collect();
        let principals_for_head: HashSet<Name> = self
            .get_principals_satisfying_constraint(template)
            .collect();

        let would_in_fix_principal = self.check_if_in_fixes_principal(template);
        let would_in_fix_resource = self.check_if_in_fixes_resource(template);

        Some(ValidationErrorKind::invalid_action_application(
            would_in_fix_principal,
            would_in_fix_resource,
        ))
        .filter(|_| {
            !apply_specs.any(|spec| {
                let action_principals = spec
                    .applicable_principal_types()
                    .filter_map(|ty| match ty {
                        ast::EntityType::Concrete(name) => Some(name.clone()),
                        ast::EntityType::Unspecified => None,
                    })
                    .collect::<HashSet<_>>();
                let applicable_principal_unspecified = spec
                    .applicable_principal_types()
                    .any(|ty| matches!(ty, ast::EntityType::Unspecified));
                let action_resources = spec
                    .applicable_resource_types()
                    .filter_map(|ty| match ty {
                        ast::EntityType::Concrete(name) => Some(name.clone()),
                        ast::EntityType::Unspecified => None,
                    })
                    .collect::<HashSet<_>>();
                let applicable_resource_unspecified = spec
                    .applicable_resource_types()
                    .any(|ty| matches!(ty, ast::EntityType::Unspecified));

                let matching_principal = applicable_principal_unspecified
                    || !principals_for_head.is_disjoint(&action_principals);
                let matching_resource = applicable_resource_unspecified
                    || !resources_for_head.is_disjoint(&action_resources);
                matching_principal && matching_resource
            })
        })
        .into_iter()
    }

    /// Gather all ApplySpec objects for all actions in the schema. The `applies_to`
    /// field is optional, so any actions lacking this field are omitted from the
    /// result.
    pub(crate) fn get_apply_specs_for_action<'a>(
        &'a self,
        template: &'a Template,
    ) -> impl Iterator<Item = &ValidatorApplySpec> + 'a {
        self.get_actions_satisfying_constraint(template)
            // Get the action type if the id string exists, and then the
            // applies_to list for the action type, if that exists.
            .filter_map(|action_id| self.schema.get_action_id(&action_id))
            .map(|action| &action.applies_to)
    }

    /// Get the set of principals (entity type strings) that satisfy the principal
    /// head constraint of the policy.
    pub(crate) fn get_principals_satisfying_constraint<'a>(
        &'a self,
        template: &'a Template,
    ) -> impl Iterator<Item = Name> + 'a {
        self.get_entities_satisfying_constraint(
            HeadConstraint::from(template.principal_constraint().as_inner()),
            PrincipalOrResourceHeadVar::PrincipalOrResource,
        )
    }

    /// Get the set of actions (action entity id strings) that satisfy the
    /// action head constraint of the policy.
    pub(crate) fn get_actions_satisfying_constraint<'a>(
        &'a self,
        template: &'a Template,
    ) -> impl Iterator<Item = EntityUID> + 'a {
        self.get_entities_satisfying_constraint(
            HeadConstraint::from(template.action_constraint()),
            ActionHeadVar::Action,
        )
    }

    /// Get the set of resources (entity type strings) that satisfy the resource
    /// head constraint of the policy.
    pub(crate) fn get_resources_satisfying_constraint<'a>(
        &'a self,
        template: &'a Template,
    ) -> impl Iterator<Item = Name> + 'a {
        self.get_entities_satisfying_constraint(
            HeadConstraint::from(template.resource_constraint().as_inner()),
            PrincipalOrResourceHeadVar::PrincipalOrResource,
        )
    }

    // Get the set of entities satisfying the condition for a particular
    // variable in the head of the policy. Note: The strings returned by this
    // function will be entity types in the case that `var` is principal or
    // resource but will be action ids in the case that it is action.
    fn get_entities_satisfying_constraint<'a, H, K>(
        &'a self,
        head_var_condition: HeadConstraint<'a>,
        var: H,
    ) -> Box<dyn Iterator<Item = K> + 'a>
    where
        H: 'a + HeadVar<K>,
        K: 'a + Clone,
    {
        match head_var_condition {
            HeadConstraint::Action(ActionConstraint::Any)
            | HeadConstraint::PrincipalOrResource(PrincipalOrResourceConstraint::Any) => {
                // <var>
                Box::new(var.get_known_vars(&self.schema).map(Clone::clone))
            }
            HeadConstraint::Action(ActionConstraint::Eq(euid))
            | HeadConstraint::PrincipalOrResource(PrincipalOrResourceConstraint::Eq(
                EntityReference::EUID(euid),
            )) => {
                // <var> == <literal euid>
                match self.schema.get_entity_eq(var, euid.as_ref().clone()) {
                    Some(entity) => Box::new([entity].into_iter()),
                    None => Box::new(std::iter::empty()),
                }
            }
            HeadConstraint::PrincipalOrResource(PrincipalOrResourceConstraint::In(
                EntityReference::EUID(euid),
            )) => {
                // <var> in <literal euid>
                Box::new(
                    self.schema
                        .get_entities_in(var, euid.as_ref().clone())
                        .unwrap_or_default()
                        .into_iter(),
                )
            }
            HeadConstraint::PrincipalOrResource(PrincipalOrResourceConstraint::Eq(
                EntityReference::Slot,
            )) => Box::new(var.get_known_vars(&self.schema).map(Clone::clone)),
            HeadConstraint::PrincipalOrResource(PrincipalOrResourceConstraint::In(
                EntityReference::Slot,
            )) => Box::new(var.get_known_vars(&self.schema).map(Clone::clone)),
            HeadConstraint::Action(ActionConstraint::In(euids)) => {
                // <var> in [<literal euid>...]
                Box::new(
                    self.schema
                        .get_entities_in_set(var, euids.iter().map(Arc::as_ref).cloned())
                        .unwrap_or_default()
                        .into_iter(),
                )
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::{BTreeMap, HashMap, HashSet};

    use cedar_policy_core::{
        ast::{Effect, Eid, EntityUID, Expr, PolicyID, PrincipalConstraint, ResourceConstraint},
        parser::parse_policy,
    };

    use super::*;
    use crate::{
        err::*, schema_file_format::NamespaceDefinition, schema_file_format::*, TypeErrorKind,
        UnrecognizedActionId, UnrecognizedEntityType, UnspecifiedEntity, ValidationError,
        ValidationMode, Validator,
    };

    #[test]
    fn validate_entity_type_empty_schema() -> Result<()> {
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
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
        match notes.get(0) {
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
                        member_of_types_incomplete: false,
                        shape: AttributesOrContext::default(),
                    },
                ),
                (
                    group_type.into(),
                    EntityType {
                        member_of_types: vec![],
                        member_of_types_incomplete: false,
                        shape: AttributesOrContext::default(),
                    },
                ),
                (
                    widget_type.into(),
                    EntityType {
                        member_of_types: vec![bin_type.into()],
                        member_of_types_incomplete: false,
                        shape: AttributesOrContext::default(),
                    },
                ),
                (
                    bin_type.into(),
                    EntityType {
                        member_of_types: vec![],
                        member_of_types_incomplete: false,
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
                    member_of_incomplete: false,
                    attributes: None,
                },
            )],
        );
        let schema = schema_file.try_into().unwrap();

        let group_eid = EntityUID::with_eid_and_type(group_type, "admin1").expect("");

        let action_eid = EntityUID::with_eid_and_type("Action", action_name).expect("");

        let bin_eid = EntityUID::with_eid_and_type(bin_type, "bin").expect("");

        let id = "id";
        let p = Template::new(
            PolicyID::from_string(id),
            BTreeMap::new(),
            Effect::Permit,
            PrincipalConstraint::is_eq(group_eid),
            ActionConstraint::is_eq(action_eid),
            ResourceConstraint::is_eq(bin_eid),
            Expr::val(true),
        );

        let v = Validator::new(schema);

        let notes = v.validate_action_application(&p).collect::<Vec<_>>();

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
                    member_of_types_incomplete: false,
                    shape: AttributesOrContext::default(),
                },
            )],
            [],
        );
        let singleton_schema = schema_file.try_into().unwrap();
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
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
                    member_of_types_incomplete: false,
                    shape: AttributesOrContext::default(),
                },
            )],
            [],
        );
        let singleton_schema = schema_file.try_into().unwrap();
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
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
        match notes.get(0) {
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
            BTreeMap::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::is_eq(entity),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let validate = Validator::new(ValidatorSchema::empty());
        let notes: Vec<ValidationErrorKind> = validate.validate_action_ids(&policy).collect();

        assert_eq!(1, notes.len());
        match notes.get(0) {
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
                    member_of_incomplete: false,
                    attributes: None,
                },
            )],
        );
        let singleton_schema = schema_file.try_into().unwrap();
        let entity =
            EntityUID::with_eid_and_type("Action", foo_name).expect("should be a valid identifier");
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
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
                    member_of_types_incomplete: false,
                    shape: AttributesOrContext::default(),
                },
            )],
            [],
        );
        let schema = schema_file.try_into().unwrap();
        let template = Template::new(
            PolicyID::from_string("id"),
            BTreeMap::new(),
            Effect::Forbid,
            PrincipalConstraint::is_eq_slot(),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            Expr::val(true),
        );
        let validator = Validator::new(schema);
        let entities = validator
            .get_principals_satisfying_constraint(&template)
            .collect::<Vec<_>>();
        assert_eq!(entities.len(), 1);
        let name = &entities[0];
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
                    member_of_types_incomplete: false,
                    shape: AttributesOrContext::default(),
                },
            )],
            [],
        );
        let schema = schema_file.try_into().unwrap();
        let template = Template::new(
            PolicyID::from_string("id"),
            BTreeMap::new(),
            Effect::Forbid,
            PrincipalConstraint::any(),
            ActionConstraint::any(),
            ResourceConstraint::is_in_slot(),
            Expr::val(true),
        );
        let validator = Validator::new(schema);
        let entities = validator
            .get_principals_satisfying_constraint(&template)
            .collect::<Vec<_>>();
        assert_eq!(entities.len(), 1);
        let name = &entities[0];
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
                    member_of_types_incomplete: false,
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
        let notes: Vec<ValidationErrorKind> = validator.validate_slots(&env).collect();

        assert_eq!(1, notes.len());
        match notes.get(0) {
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
                    member_of_incomplete: false,
                    attributes: None,
                },
            )],
        );
        let singleton_schema = schema_file.try_into().unwrap();
        let entity = EntityUID::with_eid_and_type("Action", "bar_name")
            .expect("Should be a valid identifier");
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::is_eq(entity),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let validate = Validator::new(singleton_schema);
        let notes: Vec<ValidationErrorKind> = validate.validate_action_ids(&policy).collect();

        assert_eq!(1, notes.len());
        match notes.get(0) {
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
            BTreeMap::new(),
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
            BTreeMap::new(),
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
            BTreeMap::new(),
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
            BTreeMap::new(),
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
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::is_eq(euid_foo.clone()),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let schema_file = NamespaceDefinition::new(
            [],
            [(
                foo_name.into(),
                ActionType {
                    applies_to: None,
                    member_of: None,
                    member_of_incomplete: false,
                    attributes: None,
                },
            )],
        );
        let singleton_schema = schema_file.try_into().unwrap();

        let validate = Validator::new(singleton_schema);
        let actions = validate
            .get_actions_satisfying_constraint(&policy)
            .collect();
        assert_eq!(HashSet::from([euid_foo]), actions);

        Ok(())
    }

    #[test]
    fn get_possible_actions_in_no_parents() -> Result<()> {
        let foo_name = "foo_name";
        let euid_foo =
            EntityUID::with_eid_and_type("Action", foo_name).expect("should be a valid identifier");
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::is_in(vec![euid_foo.clone()]),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let schema_file = NamespaceDefinition::new(
            [],
            [(
                foo_name.into(),
                ActionType {
                    applies_to: None,
                    member_of: None,
                    member_of_incomplete: false,
                    attributes: None,
                },
            )],
        );
        let singleton_schema = schema_file.try_into().unwrap();

        let validate = Validator::new(singleton_schema);
        let actions = validate
            .get_actions_satisfying_constraint(&policy)
            .collect();
        assert_eq!(HashSet::from([euid_foo]), actions);

        Ok(())
    }

    #[test]
    fn get_possible_actions_in_set_no_parents() -> Result<()> {
        let foo_name = "foo_name";
        let euid_foo =
            EntityUID::with_eid_and_type("Action", foo_name).expect("should be a valid identifier");
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::is_in(vec![euid_foo.clone()]),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let schema_file = NamespaceDefinition::new(
            [],
            [(
                foo_name.into(),
                ActionType {
                    applies_to: None,
                    member_of: None,
                    member_of_incomplete: false,
                    attributes: None,
                },
            )],
        );
        let singleton_schema = schema_file.try_into().unwrap();

        let validate = Validator::new(singleton_schema);
        let actions = validate
            .get_actions_satisfying_constraint(&policy)
            .collect();
        assert_eq!(HashSet::from([euid_foo]), actions);

        Ok(())
    }

    #[test]
    fn get_possible_principals_eq() -> Result<()> {
        let foo_type = "foo_type";
        let euid_foo = EntityUID::with_eid_and_type(foo_type, "foo_name")
            .expect("should be a valid identifier");
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
            Effect::Permit,
            PrincipalConstraint::is_eq(euid_foo.clone()),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let schema_file = NamespaceDefinition::new(
            [(
                foo_type.into(),
                EntityType {
                    member_of_types: vec![],
                    member_of_types_incomplete: false,
                    shape: AttributesOrContext::default(),
                },
            )],
            [],
        );
        let singleton_schema = schema_file.try_into().unwrap();

        let validate = Validator::new(singleton_schema);
        let principals = validate
            .get_principals_satisfying_constraint(&policy)
            .map(cedar_policy_core::ast::EntityType::Concrete)
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
                        member_of_types_incomplete: false,
                        shape: AttributesOrContext::default(),
                    },
                ),
                (
                    resource_type.into(),
                    EntityType {
                        member_of_types: vec![],
                        member_of_types_incomplete: false,
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
                    member_of_incomplete: false,
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
            BTreeMap::new(),
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

        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
            Effect::Permit,
            PrincipalConstraint::is_eq(resource.clone()),
            ActionConstraint::is_eq(action),
            ResourceConstraint::is_eq(resource),
            Expr::val(true),
        );

        let validate = Validator::new(schema);
        let notes: Vec<ValidationErrorKind> =
            validate.validate_action_application(&policy).collect();
        assert_eq!(1, notes.len());
        match notes.get(0) {
            Some(ValidationErrorKind::InvalidActionApplication(_)) => (),
            _ => panic!("Unexpected variant of ValidationErrorKind."),
        }

        Ok(())
    }

    #[test]
    fn validate_action_apply_incorrect_resource() -> Result<()> {
        let (principal, action, _, schema) = schema_with_single_principal_action_resource();

        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
            Effect::Permit,
            PrincipalConstraint::is_eq(principal.clone()),
            ActionConstraint::is_eq(action),
            ResourceConstraint::is_eq(principal),
            Expr::val(true),
        );

        let validate = Validator::new(schema);
        let notes: Vec<ValidationErrorKind> =
            validate.validate_action_application(&policy).collect();
        assert_eq!(1, notes.len());
        match notes.get(0) {
            Some(ValidationErrorKind::InvalidActionApplication(_)) => (),
            _ => panic!("Unexpected variant of ValidationErrorKind."),
        }

        Ok(())
    }

    #[test]
    fn validate_action_apply_incorrect_principal_and_resource() -> Result<()> {
        let (principal, action, resource, schema) = schema_with_single_principal_action_resource();

        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
            Effect::Permit,
            PrincipalConstraint::is_eq(resource),
            ActionConstraint::is_eq(action),
            ResourceConstraint::is_eq(principal),
            Expr::val(true),
        );

        let validate = Validator::new(schema);
        let notes: Vec<ValidationErrorKind> =
            validate.validate_action_application(&policy).collect();
        assert_eq!(1, notes.len());
        match notes.get(0) {
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
            BTreeMap::new(),
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

        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
            Effect::Permit,
            PrincipalConstraint::is_eq(resource),
            ActionConstraint::any(),
            ResourceConstraint::is_eq(principal),
            Expr::val(true),
        );

        let validate = Validator::new(schema);
        let notes: Vec<_> = validate.validate_action_application(&policy).collect();
        assert_eq!(
            notes,
            vec![ValidationErrorKind::invalid_action_application(
                false, false
            )],
        );

        Ok(())
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
                        member_of_types_incomplete: false,
                        shape: AttributesOrContext::default(),
                    },
                ),
                (
                    resource_type.into(),
                    EntityType {
                        member_of_types: vec![resource_parent_type.into()],
                        member_of_types_incomplete: false,
                        shape: AttributesOrContext::default(),
                    },
                ),
                (
                    resource_parent_type.into(),
                    EntityType {
                        member_of_types: vec![resource_grandparent_type.into()],
                        member_of_types_incomplete: false,
                        shape: AttributesOrContext::default(),
                    },
                ),
                (
                    resource_grandparent_type.into(),
                    EntityType {
                        member_of_types: vec![],
                        member_of_types_incomplete: false,
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
                        member_of_incomplete: false,
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
                        member_of_incomplete: false,
                        attributes: None,
                    },
                ),
                (
                    action_grandparent_name.into(),
                    ActionType {
                        applies_to: None,
                        member_of: Some(vec![]),
                        member_of_incomplete: false,
                        attributes: None,
                    },
                ),
            ],
        );
        let schema = schema_file.try_into().unwrap();

        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
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
    fn unspecified_entity_in_head() -> Result<()> {
        // Note: it's not possible to create an unspecified entity through the parser,
        // so we have to test using manually-constructed policies.
        let validate = Validator::new(ValidatorSchema::empty());

        // resource == Unspecified::"foo"
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::any(),
            ResourceConstraint::is_eq(EntityUID::unspecified_from_eid(Eid::new("foo"))),
            Expr::val(true),
        );
        let notes: Vec<ValidationErrorKind> = validate.validate_entity_types(&policy).collect();
        assert_eq!(1, notes.len());
        match notes.get(0) {
            Some(ValidationErrorKind::UnspecifiedEntity(UnspecifiedEntity { entity_id })) => {
                assert_eq!("foo", entity_id);
            }
            _ => panic!("Unexpected variant of ValidationErrorKind."),
        };

        // principal in Unspecified::"foo"
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
            Effect::Permit,
            PrincipalConstraint::is_in(EntityUID::unspecified_from_eid(Eid::new("foo"))),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            Expr::val(true),
        );
        let notes: Vec<ValidationErrorKind> = validate.validate_entity_types(&policy).collect();
        assert_eq!(1, notes.len());
        match notes.get(0) {
            Some(ValidationErrorKind::UnspecifiedEntity(UnspecifiedEntity { entity_id })) => {
                assert_eq!("foo", entity_id);
            }
            _ => panic!("Unexpected variant of ValidationErrorKind."),
        };

        Ok(())
    }

    #[test]
    fn unspecified_entity_in_additional_constraints() -> Result<()> {
        let validate = Validator::new(ValidatorSchema::empty());

        // resource == Unspecified::"foo"
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            BTreeMap::new(),
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
        match notes.get(0) {
            Some(ValidationErrorKind::UnspecifiedEntity(UnspecifiedEntity { entity_id })) => {
                assert_eq!("foo", entity_id);
            }
            _ => panic!("Unexpected variant of ValidationErrorKind."),
        };

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
    fn unspecified_principal_resource_with_head_conditions() {
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
#[cfg(feature = "partial_schema")]
mod partial_schema {
    use cedar_policy_core::{
        ast::{StaticPolicy, Template},
        parser::parse_policy,
    };

    use crate::{NamespaceDefinition, Validator};

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
