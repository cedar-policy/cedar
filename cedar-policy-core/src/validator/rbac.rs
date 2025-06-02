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

//! Contains the validation logic specific to RBAC policy validation.

use crate::{
    ast::{
        self, ActionConstraint, Eid, EntityReference, EntityUID, Policy, PolicyID,
        PrincipalConstraint, PrincipalOrResourceConstraint, ResourceConstraint, SlotEnv, Template,
    },
    entities::conformance::is_valid_enumerated_entity,
    fuzzy_match::fuzzy_search,
    parser::Loc,
};

use std::{collections::HashSet, sync::Arc};

use crate::validator::{
    expr_iterator::{policy_entity_type_names, policy_entity_uids},
    validation_errors::unrecognized_action_id_help,
    ValidationError,
};

use super::{schema::*, Validator};

impl Validator {
    /// Validate if a [`Template`] contains entities of enumerated entity types
    /// but with invalid UIDs
    pub(crate) fn validate_enum_entity<'a>(
        &'a self,
        template: &'a Template,
    ) -> impl Iterator<Item = ValidationError> + 'a {
        policy_entity_uids(template)
            .filter(|e| !e.is_action())
            .filter_map(|e: &EntityUID| {
                if let Some(ValidatorEntityType {
                    kind: ValidatorEntityTypeKind::Enum(choices),
                    ..
                }) = self.schema.get_entity_type(e.entity_type())
                {
                    match is_valid_enumerated_entity(&Vec::from(choices.clone().map(Eid::new)), e) {
                        Ok(_) => {}
                        Err(err) => {
                            return Some(ValidationError::invalid_enum_entity(
                                e.loc().cloned(),
                                template.id().clone(),
                                err,
                            ));
                        }
                    };
                }
                None
            })
    }
    /// Generate `UnrecognizedEntityType` error for every entity type in the
    /// expression that could not also be found in the schema.
    pub(crate) fn validate_entity_types<'a>(
        &'a self,
        template: &'a Template,
    ) -> impl Iterator<Item = ValidationError> + 'a {
        // All valid entity types in the schema. These will be used to generate
        // suggestion when an entity type is not found.
        let known_entity_types = self
            .schema
            .entity_type_names()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        policy_entity_type_names(template).filter_map(move |name| {
            let is_known_entity_type = self.schema.is_known_entity_type(name);

            if !name.is_action() && !is_known_entity_type {
                let actual_entity_type = name.to_string();
                let suggested_entity_type =
                    fuzzy_search(&actual_entity_type, known_entity_types.as_slice());
                Some(ValidationError::unrecognized_entity_type(
                    name.loc().cloned(),
                    template.id().clone(),
                    actual_entity_type,
                    suggested_entity_type,
                ))
            } else {
                None
            }
        })
    }

    /// Generate `UnrecognizedActionId` error for every entity id with an action
    /// entity type where the id could not be found in the actions list from the
    /// schema.
    pub(crate) fn validate_action_ids<'a>(
        &'a self,
        template: &'a Template,
    ) -> impl Iterator<Item = ValidationError> + 'a {
        // Valid action id names that will be used to generate suggestions if an
        // action id is not found
        policy_entity_uids(template).filter_map(move |euid| {
            let entity_type = euid.entity_type();
            if entity_type.is_action() && !self.schema.is_known_action_id(euid) {
                Some(ValidationError::unrecognized_action_id(
                    euid.loc().cloned(),
                    template.id().clone(),
                    euid.to_string(),
                    unrecognized_action_id_help(euid, &self.schema),
                ))
            } else {
                None
            }
        })
    }

    /// Generate `UnrecognizedEntityType` error for
    /// every entity type in the slot environment that is not in the schema
    pub(crate) fn validate_entity_types_in_slots<'a>(
        &'a self,
        policy_id: &'a PolicyID,
        slots: &'a SlotEnv,
    ) -> impl Iterator<Item = ValidationError> + 'a {
        // All valid entity types in the schema. These will be used to generate
        // suggestion when an entity type is not found.
        let known_entity_types = self
            .schema
            .entity_type_names()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        slots.values().filter_map(move |euid| {
            let entity_type = euid.entity_type();
            if !self.schema.is_known_entity_type(entity_type) {
                let actual_entity_type = entity_type.to_string();
                let suggested_entity_type =
                    fuzzy_search(&actual_entity_type, known_entity_types.as_slice());
                Some(ValidationError::unrecognized_entity_type(
                    None,
                    policy_id.clone(),
                    actual_entity_type,
                    suggested_entity_type,
                ))
            } else {
                None
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
        apply_specs: &[&'a ValidatorApplySpec<ast::EntityType>],
        select_apply_spec: &impl Fn(
            &'a ValidatorApplySpec<ast::EntityType>,
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
        specs: &[&'a ValidatorApplySpec<ast::EntityType>],
        lit_opt: Option<&ast::EntityType>,
        select_apply_spec: &impl Fn(
            &'a ValidatorApplySpec<ast::EntityType>,
        ) -> Box<dyn Iterator<Item = &'a ast::EntityType> + 'a>,
    ) -> bool {
        if let Some(lit) = lit_opt {
            !specs
                .iter()
                .any(|spec| select_apply_spec(spec).any(|e| e == lit))
        } else {
            false
        }
    }

    // This checks the second property
    // exists spec in apply_specs such that there exists principal in spec.principals such that lit `memberOf` principal
    fn check_if_any_contain<'a>(
        &'a self,
        specs: &[&'a ValidatorApplySpec<ast::EntityType>],
        lit_opt: Option<&ast::EntityType>,
        select_apply_spec: &impl Fn(
            &'a ValidatorApplySpec<ast::EntityType>,
        ) -> Box<dyn Iterator<Item = &'a ast::EntityType> + 'a>,
    ) -> bool {
        if let Some(etype) = lit_opt.and_then(|typename| self.schema.get_entity_type(typename)) {
            specs
                .iter()
                .any(|spec| select_apply_spec(spec).any(|p| etype.descendants.contains(p)))
        } else {
            false
        }
    }

    /// Check if an expression is an equality comparison between a literal EUID
    /// and a scope variable.  If it is, return the type of the literal EUID.
    fn get_eq_comparison(
        scope_constraint: &PrincipalOrResourceConstraint,
    ) -> Option<&ast::EntityType> {
        match scope_constraint {
            PrincipalOrResourceConstraint::Eq(EntityReference::EUID(euid)) => {
                Some(euid.entity_type())
            }
            _ => None,
        }
    }

    pub(crate) fn validate_linked_action_application<'a>(
        &self,
        p: &'a Policy,
    ) -> impl Iterator<Item = ValidationError> + 'a {
        self.validate_action_application(
            p.loc(),
            p.id(),
            &p.principal_constraint(),
            p.action_constraint(),
            &p.resource_constraint(),
        )
    }

    pub(crate) fn validate_template_action_application<'a>(
        &self,
        t: &'a Template,
    ) -> impl Iterator<Item = ValidationError> + 'a {
        self.validate_action_application(
            t.loc(),
            t.id(),
            t.principal_constraint(),
            t.action_constraint(),
            t.resource_constraint(),
        )
    }

    // Check that there exists a (action id, principal type, resource type)
    // entity type pair where the action can be applied to both the principal
    // and resource. This function takes the three scope constraints as input
    // (rather than a template) to facilitate code reuse.
    fn validate_action_application(
        &self,
        source_loc: Option<&Loc>,
        policy_id: &PolicyID,
        principal_constraint: &PrincipalConstraint,
        action_constraint: &ActionConstraint,
        resource_constraint: &ResourceConstraint,
    ) -> impl Iterator<Item = ValidationError> {
        let mut apply_specs = self.get_apply_specs_for_action(action_constraint);
        let resources_for_scope: HashSet<&ast::EntityType> = self
            .get_resources_satisfying_constraint(resource_constraint)
            .collect();
        let principals_for_scope: HashSet<&ast::EntityType> = self
            .get_principals_satisfying_constraint(principal_constraint)
            .collect();

        let would_in_fix_principal =
            self.check_if_in_fixes_principal(principal_constraint, action_constraint);
        let would_in_fix_resource =
            self.check_if_in_fixes_resource(resource_constraint, action_constraint);

        Some(ValidationError::invalid_action_application(
            source_loc.cloned(),
            policy_id.clone(),
            would_in_fix_principal,
            would_in_fix_resource,
        ))
        .filter(|_| {
            !apply_specs.any(|spec| {
                let action_principals = spec.applicable_principal_types().collect::<HashSet<_>>();
                let action_resources = spec.applicable_resource_types().collect::<HashSet<_>>();
                let matching_principal = !principals_for_scope.is_disjoint(&action_principals);
                let matching_resource = !resources_for_scope.is_disjoint(&action_resources);
                matching_principal && matching_resource
            })
        })
        .into_iter()
    }

    /// Gather all `ApplySpec` objects for all actions in the schema.
    pub(crate) fn get_apply_specs_for_action<'a>(
        &'a self,
        action_constraint: &'a ActionConstraint,
    ) -> impl Iterator<Item = &'a ValidatorApplySpec<ast::EntityType>> + 'a {
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
            ActionConstraint::Any => {
                Box::new(self.schema.action_ids().map(ValidatorActionId::name))
            }
            // <var> == <literal euid>
            ActionConstraint::Eq(euid) => Box::new(std::iter::once(euid.as_ref())),
            // <var> in [<literal euid>...]
            ActionConstraint::In(euids) => Box::new(
                self.schema
                    .get_actions_in_set(euids.iter().map(Arc::as_ref))
                    .unwrap_or_default()
                    .into_iter(),
            ),
            #[cfg(feature = "tolerant-ast")]
            ActionConstraint::ErrorConstraint => {
                let v = vec![].into_iter();
                Box::new(v)
            }
        }
    }

    /// Get the set of principals (entity type strings) that satisfy the principal
    /// scope constraint of the policy.
    pub(crate) fn get_principals_satisfying_constraint<'a>(
        &'a self,
        principal_constraint: &'a PrincipalConstraint,
    ) -> impl Iterator<Item = &'a ast::EntityType> + 'a {
        self.get_entity_types_satisfying_constraint(principal_constraint.as_inner())
    }

    /// Get the set of resources (entity type strings) that satisfy the resource
    /// scope constraint of the policy.
    pub(crate) fn get_resources_satisfying_constraint<'a>(
        &'a self,
        resource_constraint: &'a ResourceConstraint,
    ) -> impl Iterator<Item = &'a ast::EntityType> + 'a {
        self.get_entity_types_satisfying_constraint(resource_constraint.as_inner())
    }

    // Get the set of entity types satisfying the condition for the principal
    // or resource variable in the policy scope.
    fn get_entity_types_satisfying_constraint<'a>(
        &'a self,
        scope_constraint: &'a PrincipalOrResourceConstraint,
    ) -> Box<dyn Iterator<Item = &'a ast::EntityType> + 'a> {
        match scope_constraint {
            // <var>
            PrincipalOrResourceConstraint::Any => Box::new(self.schema.entity_type_names()),
            // <var> == <literal euid>
            PrincipalOrResourceConstraint::Eq(EntityReference::EUID(euid)) => {
                Box::new(std::iter::once(euid.entity_type()))
            }
            // <var> in <literal euid>
            PrincipalOrResourceConstraint::In(EntityReference::EUID(euid)) => {
                Box::new(self.schema.get_entity_types_in(euid.as_ref()).into_iter())
            }
            PrincipalOrResourceConstraint::Eq(EntityReference::Slot(_))
            | PrincipalOrResourceConstraint::In(EntityReference::Slot(_)) => {
                Box::new(self.schema.entity_type_names())
            }
            PrincipalOrResourceConstraint::Is(entity_type)
            | PrincipalOrResourceConstraint::IsIn(entity_type, EntityReference::Slot(_)) => {
                Box::new(
                    if self.schema.is_known_entity_type(entity_type) {
                        Some(entity_type.as_ref())
                    } else {
                        None
                    }
                    .into_iter(),
                )
            }
            PrincipalOrResourceConstraint::IsIn(entity_type, EntityReference::EUID(in_entity)) => {
                Box::new(
                    self.schema
                        .get_entity_types_in(in_entity.as_ref())
                        .into_iter()
                        .filter(move |k| &entity_type.as_ref() == k),
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

    use crate::{
        ast::{Effect, Eid, EntityUID, Expr, PolicyID, PrincipalConstraint, ResourceConstraint},
        est::Annotations,
        parser::{parse_policy, parse_policy_or_template},
        test_utils::{expect_err, ExpectedErrorMessageBuilder},
    };
    use miette::Report;

    use super::*;
    use crate::validator::{
        json_schema, validation_errors::UnrecognizedEntityType, RawName, ValidationMode,
        ValidationWarning, Validator,
    };

    #[test]
    fn validate_entity_type_empty_schema() {
        let src = r#"permit(principal, action, resource == foo_type::"foo_name");"#;
        let policy = parse_policy_or_template(None, src).unwrap();
        let validate = Validator::new(ValidatorSchema::empty());
        let notes: Vec<ValidationError> = validate.validate_entity_types(&policy).collect();
        expect_err(
            src,
            &Report::new(notes.first().unwrap().clone()),
            &ExpectedErrorMessageBuilder::error(
                "for policy `policy0`, unrecognized entity type `foo_type`",
            )
            .exactly_one_underline("foo_type")
            .build(),
        );
        assert_eq!(notes.len(), 1, "{:?}", notes);
    }

    #[test]
    fn validate_equals_instead_of_in() {
        let schema_file: json_schema::NamespaceDefinition<RawName> =
            serde_json::from_value(serde_json::json!(
                {
                    "entityTypes": {
                        "user": {
                            "memberOfTypes": ["admins"]
                        },
                        "admins": {},
                        "widget": {
                            "memberOfTypes": ["bin"]
                        },
                        "bin": {}
                    },
                    "actions": {
                        "act": {
                            "appliesTo": {
                                "principalTypes": ["user"],
                                "resourceTypes": ["widget"]
                            }
                        }
                    }
                }
            ))
            .unwrap();
        let schema = schema_file.try_into().unwrap();

        let src = r#"permit(principal == admins::"admin1", action == Action::"act", resource == bin::"bin");"#;
        let p = parse_policy_or_template(None, src).unwrap();

        let validate = Validator::new(schema);
        let notes: Vec<ValidationError> =
            validate.validate_template_action_application(&p).collect();

        expect_err(
            src,
            &Report::new(notes.first().unwrap().clone()),
            &ExpectedErrorMessageBuilder::error(
                r#"for policy `policy0`, unable to find an applicable action given the policy scope constraints"#,
            )
            .help("try replacing `==` with `in` in the principal clause and the resource clause")
            .exactly_one_underline(src)
            .build(),
        );
        assert_eq!(notes.len(), 1, "{:?}", notes);
    }

    #[test]
    fn validate_entity_type_in_singleton_schema() {
        let foo_type = "foo_type";
        let schema_file = json_schema::NamespaceDefinition::new(
            [(
                foo_type.parse().unwrap(),
                json_schema::StandardEntityType {
                    member_of_types: vec![],
                    shape: json_schema::AttributesOrContext::default(),
                    tags: None,
                }
                .into(),
            )],
            [],
        );
        let singleton_schema = schema_file.try_into().unwrap();
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            None,
            ast::Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::any(),
            ResourceConstraint::is_eq(Arc::new(
                EntityUID::with_eid_and_type(foo_type, "foo_name")
                    .expect("should be a valid identifier"),
            )),
            Expr::val(true),
        );

        let validate = Validator::new(singleton_schema);
        assert!(
            validate.validate_entity_types(&policy).next().is_none(),
            "Did not expect any validation errors."
        );
    }

    #[test]
    fn validate_entity_type_not_in_singleton_schema() {
        let schema_file = json_schema::NamespaceDefinition::new(
            [(
                "foo_type".parse().unwrap(),
                json_schema::StandardEntityType {
                    member_of_types: vec![],
                    shape: json_schema::AttributesOrContext::default(),
                    tags: None,
                }
                .into(),
            )],
            [],
        );
        let singleton_schema = schema_file.try_into().unwrap();

        let src = r#"permit(principal, action, resource == bar_type::"bar_name");"#;
        let policy = parse_policy_or_template(None, src).unwrap();
        let validate = Validator::new(singleton_schema);
        let notes: Vec<ValidationError> = validate.validate_entity_types(&policy).collect();
        expect_err(
            src,
            &Report::new(notes.first().unwrap().clone()),
            &ExpectedErrorMessageBuilder::error(
                "for policy `policy0`, unrecognized entity type `bar_type`",
            )
            .exactly_one_underline("bar_type")
            .help("did you mean `foo_type`?")
            .build(),
        );
        assert_eq!(notes.len(), 1, "{:?}", notes);
    }

    #[test]
    fn validate_action_id_empty_schema() {
        let src = r#"permit(principal, action == Action::"foo_name", resource);"#;
        let policy = parse_policy_or_template(None, src).unwrap();
        let validate = Validator::new(ValidatorSchema::empty());
        let notes: Vec<ValidationError> = validate.validate_action_ids(&policy).collect();
        expect_err(
            src,
            &Report::new(notes.first().unwrap().clone()),
            &ExpectedErrorMessageBuilder::error(
                r#"for policy `policy0`, unrecognized action `Action::"foo_name"`"#,
            )
            .exactly_one_underline(r#"Action::"foo_name""#)
            .build(),
        );
        assert_eq!(notes.len(), 1, "{:?}", notes);
    }

    #[test]
    fn validate_action_id_in_singleton_schema() {
        let foo_name = "foo_name";
        let schema_file = json_schema::NamespaceDefinition::new(
            [],
            [(
                foo_name.into(),
                json_schema::ActionType {
                    applies_to: None,
                    member_of: None,
                    attributes: None,
                    annotations: Annotations::new(),
                    loc: None,
                    #[cfg(feature = "extended-schema")]
                    defn_loc: None,
                },
            )],
        );
        let singleton_schema = schema_file.try_into().unwrap();
        let entity =
            EntityUID::with_eid_and_type("Action", foo_name).expect("should be a valid identifier");
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            None,
            ast::Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::is_eq(entity),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let validate = Validator::new(singleton_schema);
        assert!(
            validate.validate_action_ids(&policy).next().is_none(),
            "Did not expect any validation errors."
        );
    }

    #[test]
    fn validate_principal_slot_in_singleton_schema() {
        let p_name = "User";
        let schema_file = json_schema::NamespaceDefinition::new(
            [(
                p_name.parse().unwrap(),
                json_schema::StandardEntityType {
                    member_of_types: vec![],
                    shape: json_schema::AttributesOrContext::default(),
                    tags: None,
                }
                .into(),
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
        let schema_file = json_schema::NamespaceDefinition::new(
            [(
                p_name.parse().unwrap(),
                json_schema::StandardEntityType {
                    member_of_types: vec![],
                    shape: json_schema::AttributesOrContext::default(),
                    tags: None,
                }
                .into(),
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
    fn undefined_entity_type_in_principal_slot() {
        let p_name = "User";
        let schema_file = json_schema::NamespaceDefinition::new(
            [(
                p_name.parse().unwrap(),
                json_schema::StandardEntityType {
                    member_of_types: vec![],
                    shape: json_schema::AttributesOrContext::default(),
                    tags: None,
                }
                .into(),
            )],
            [],
        );
        let schema = schema_file.try_into().expect("Invalid schema");

        let undefined_euid: EntityUID = "Undefined::\"foo\""
            .parse()
            .expect("Expected entity UID to parse.");
        let env = HashMap::from([(ast::SlotId::principal(), undefined_euid)]);

        let validator = Validator::new(schema);
        let notes: Vec<ValidationError> = validator
            .validate_entity_types_in_slots(&PolicyID::from_string("0"), &env)
            .collect();

        assert_eq!(1, notes.len());
        match notes.first() {
            Some(ValidationError::UnrecognizedEntityType(UnrecognizedEntityType {
                actual_entity_type,
                suggested_entity_type,
                ..
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
    }

    #[test]
    fn validate_action_id_not_in_singleton_schema() {
        let schema_file = json_schema::NamespaceDefinition::new(
            [],
            [(
                "foo_name".into(),
                json_schema::ActionType {
                    applies_to: None,
                    member_of: None,
                    attributes: None,
                    annotations: Annotations::new(),
                    loc: None,
                    #[cfg(feature = "extended-schema")]
                    defn_loc: None,
                },
            )],
        );
        let singleton_schema = schema_file.try_into().unwrap();

        let src = r#"permit(principal, action == Action::"bar_name", resource);"#;
        let policy = parse_policy_or_template(None, src).unwrap();
        let validate = Validator::new(singleton_schema);
        let notes: Vec<ValidationError> = validate.validate_action_ids(&policy).collect();
        expect_err(
            src,
            &Report::new(notes.first().unwrap().clone()),
            &ExpectedErrorMessageBuilder::error(
                r#"for policy `policy0`, unrecognized action `Action::"bar_name"`"#,
            )
            .exactly_one_underline(r#"Action::"bar_name""#)
            .help(r#"did you mean `Action::"foo_name"`?"#)
            .build(),
        );
        assert_eq!(notes.len(), 1, "{:?}", notes);
    }

    #[test]
    fn validate_action_id_with_action_type() {
        let schema_file = json_schema::NamespaceDefinition::new(
            [],
            [(
                "Action::view".into(),
                json_schema::ActionType {
                    applies_to: None,
                    member_of: None,
                    attributes: None,
                    annotations: Annotations::new(),
                    loc: None,
                    #[cfg(feature = "extended-schema")]
                    defn_loc: None,
                },
            )],
        );
        let singleton_schema = schema_file.try_into().unwrap();

        let src = r#"permit(principal, action == Action::"view", resource);"#;
        let policy = parse_policy_or_template(None, src).unwrap();
        let validate = Validator::new(singleton_schema);
        let notes: Vec<ValidationError> = validate.validate_action_ids(&policy).collect();
        expect_err(
            src,
            &Report::new(notes.first().unwrap().clone()),
            &ExpectedErrorMessageBuilder::error(
                r#"for policy `policy0`, unrecognized action `Action::"view"`"#,
            )
            .exactly_one_underline(r#"Action::"view""#)
            .help(r#"did you intend to include the type in action `Action::"Action::view"`?"#)
            .build(),
        );
        assert_eq!(notes.len(), 1, "{:?}", notes);
    }

    #[test]
    fn validate_action_id_with_action_type_namespace() {
        let schema_src = r#"
        {
            "foo::foo::bar::baz": {
                "entityTypes": {},
                "actions": {
                    "Action::view": {}
                }
            }
        }"#;

        let schema_fragment: json_schema::Fragment<RawName> =
            serde_json::from_str(schema_src).expect("Parse Error");
        let schema = schema_fragment.try_into().unwrap();

        let src = r#"permit(principal, action == Action::"view", resource);"#;
        let policy = parse_policy_or_template(None, src).unwrap();
        let validate = Validator::new(schema);
        let notes: Vec<ValidationError> = validate.validate_action_ids(&policy).collect();
        expect_err(
            src,
            &Report::new(notes.first().unwrap().clone()),
            &ExpectedErrorMessageBuilder::error(
                r#"for policy `policy0`, unrecognized action `Action::"view"`"#,
            )
            .exactly_one_underline(r#"Action::"view""#)
            .help(r#"did you intend to include the type in action `foo::foo::bar::baz::Action::"Action::view"`?"#)
            .build(),
        );
        assert_eq!(notes.len(), 1, "{:?}", notes);
    }

    #[test]
    fn validate_namespaced_action_id_in_schema() {
        let descriptors = json_schema::Fragment::from_json_str(
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
            None,
            ast::Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::is_eq(entity),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let validate = Validator::new(schema);
        let notes: Vec<ValidationError> = validate.validate_action_ids(&policy).collect();
        assert_eq!(notes, vec![], "Did not expect any invalid action.");
    }

    #[test]
    fn validate_namespaced_invalid_action() {
        let descriptors = json_schema::Fragment::from_json_str(
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

        let src = r#"permit(principal, action == Bogus::Action::"foo_name", resource);"#;
        let policy = parse_policy_or_template(None, src).unwrap();
        let validate = Validator::new(schema);
        let notes: Vec<ValidationError> = validate.validate_action_ids(&policy).collect();
        expect_err(
            src,
            &Report::new(notes.first().unwrap().clone()),
            &ExpectedErrorMessageBuilder::error(
                r#"for policy `policy0`, unrecognized action `Bogus::Action::"foo_name"`"#,
            )
            .exactly_one_underline(r#"Bogus::Action::"foo_name""#)
            .help(r#"did you mean `NS::Action::"foo_name"`?"#)
            .build(),
        );
        assert_eq!(notes.len(), 1, "{:?}", notes);
    }

    #[test]
    fn validate_namespaced_entity_type_in_schema() {
        let descriptors = json_schema::Fragment::from_json_str(
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
        let entity_type: ast::EntityType = "NS::Foo".parse().expect("Expected entity type parse.");
        let policy = Template::new(
            PolicyID::from_string("policy0"),
            None,
            ast::Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::is_eq(Arc::new(EntityUID::from_components(
                entity_type,
                Eid::new("bar"),
                None,
            ))),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            Expr::val(true),
        );

        let validate = Validator::new(schema);
        let notes: Vec<ValidationError> = validate.validate_entity_types(&policy).collect();

        assert_eq!(notes, vec![], "Did not expect any invalid action.");
    }

    #[test]
    fn validate_namespaced_invalid_entity_type() {
        let descriptors = json_schema::Fragment::from_json_str(
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

        let src = r#"permit(principal == Bogus::Foo::"bar", action, resource);"#;
        let policy = parse_policy_or_template(None, src).unwrap();
        let validate = Validator::new(schema);
        let notes: Vec<ValidationError> = validate.validate_entity_types(&policy).collect();
        expect_err(
            src,
            &Report::new(notes.first().unwrap().clone()),
            &ExpectedErrorMessageBuilder::error(
                "for policy `policy0`, unrecognized entity type `Bogus::Foo`",
            )
            .exactly_one_underline("Bogus::Foo")
            .help("did you mean `NS::Foo`?")
            .build(),
        );
        assert_eq!(notes.len(), 1, "{:?}", notes);
    }

    #[test]
    fn get_possible_actions_eq() {
        let foo_name = "foo_name";
        let euid_foo =
            EntityUID::with_eid_and_type("Action", foo_name).expect("should be a valid identifier");
        let action_constraint = ActionConstraint::is_eq(euid_foo.clone());

        let schema_file = json_schema::NamespaceDefinition::new(
            [],
            [(
                foo_name.into(),
                json_schema::ActionType {
                    applies_to: None,
                    member_of: None,
                    attributes: None,
                    annotations: Annotations::new(),
                    loc: None,
                    #[cfg(feature = "extended-schema")]
                    defn_loc: None,
                },
            )],
        );
        let singleton_schema = schema_file.try_into().unwrap();

        let validate = Validator::new(singleton_schema);
        let actions = validate
            .get_actions_satisfying_constraint(&action_constraint)
            .collect();
        assert_eq!(HashSet::from([&euid_foo]), actions);
    }

    #[test]
    fn get_possible_actions_in_no_parents() {
        let foo_name = "foo_name";
        let euid_foo =
            EntityUID::with_eid_and_type("Action", foo_name).expect("should be a valid identifier");
        let action_constraint = ActionConstraint::is_in(vec![euid_foo.clone()]);

        let schema_file = json_schema::NamespaceDefinition::new(
            [],
            [(
                foo_name.into(),
                json_schema::ActionType {
                    applies_to: None,
                    member_of: None,
                    attributes: None,
                    annotations: Annotations::new(),
                    loc: None,
                    #[cfg(feature = "extended-schema")]
                    defn_loc: None,
                },
            )],
        );
        let singleton_schema = schema_file.try_into().unwrap();

        let validate = Validator::new(singleton_schema);
        let actions = validate
            .get_actions_satisfying_constraint(&action_constraint)
            .collect();
        assert_eq!(HashSet::from([&euid_foo]), actions);
    }

    #[test]
    fn get_possible_actions_in_set_no_parents() {
        let foo_name = "foo_name";
        let euid_foo =
            EntityUID::with_eid_and_type("Action", foo_name).expect("should be a valid identifier");
        let action_constraint = ActionConstraint::is_in(vec![euid_foo.clone()]);

        let schema_file = json_schema::NamespaceDefinition::new(
            [],
            [(
                foo_name.into(),
                json_schema::ActionType {
                    applies_to: None,
                    member_of: None,
                    attributes: None,
                    annotations: Annotations::new(),
                    loc: None,
                    #[cfg(feature = "extended-schema")]
                    defn_loc: None,
                },
            )],
        );
        let singleton_schema = schema_file.try_into().unwrap();

        let validate = Validator::new(singleton_schema);
        let actions = validate
            .get_actions_satisfying_constraint(&action_constraint)
            .collect();
        assert_eq!(HashSet::from([&euid_foo]), actions);
    }

    #[test]
    fn get_possible_principals_eq() {
        let foo_type = "foo_type";
        let euid_foo = EntityUID::with_eid_and_type(foo_type, "foo_name")
            .expect("should be a valid identifier");
        let principal_constraint = PrincipalConstraint::is_eq(Arc::new(euid_foo.clone()));

        let schema_file = json_schema::NamespaceDefinition::new(
            [(
                foo_type.parse().unwrap(),
                json_schema::StandardEntityType {
                    member_of_types: vec![],
                    shape: json_schema::AttributesOrContext::default(),
                    tags: None,
                }
                .into(),
            )],
            [],
        );
        let singleton_schema = schema_file.try_into().unwrap();

        let validate = Validator::new(singleton_schema);
        let principals = validate
            .get_principals_satisfying_constraint(&principal_constraint)
            .cloned()
            .collect::<HashSet<_>>();
        assert_eq!(HashSet::from([euid_foo.components().0]), principals);
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

        let schema = json_schema::NamespaceDefinition::new(
            [
                (
                    principal_type.parse().unwrap(),
                    json_schema::StandardEntityType {
                        member_of_types: vec![],
                        shape: json_schema::AttributesOrContext::default(),
                        tags: None,
                    }
                    .into(),
                ),
                (
                    resource_type.parse().unwrap(),
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
                        resource_types: vec![resource_type.parse().unwrap()],
                        principal_types: vec![principal_type.parse().unwrap()],
                        context: json_schema::AttributesOrContext::default(),
                    }),
                    member_of: Some(vec![]),
                    attributes: None,
                    annotations: Annotations::new(),
                    loc: None,
                    #[cfg(feature = "extended-schema")]
                    defn_loc: None,
                },
            )],
        )
        .try_into()
        .expect("Expected valid schema file.");
        (principal_euid, action_euid, resource_euid, schema)
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_validate_policy_succeeds(validator: &Validator, policy: &Template) {
        assert!(
            validator
                .validate_policy(policy, ValidationMode::default())
                .0
                .next()
                .is_none(),
            "Did not expect any validation errors."
        );
        assert!(
            validator
                .validate_policy(policy, ValidationMode::default())
                .1
                .next()
                .is_none(),
            "Did not expect any validation warnings."
        );
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_validate_policy_fails(
        validator: &Validator,
        policy: &Template,
        expected: &[ValidationError],
    ) {
        assert_eq!(
            validator
                .validate_policy(policy, ValidationMode::default())
                .0
                .collect::<Vec<ValidationError>>(),
            expected,
            "Unexpected validation errors."
        );
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_validate_policy_flags_impossible_policy(validator: &Validator, policy: &Template) {
        assert_eq!(
            validator
                .validate_policy(policy, ValidationMode::default())
                .1
                .collect::<Vec<ValidationWarning>>(),
            vec![ValidationWarning::impossible_policy(
                policy.loc().cloned(),
                policy.id().clone()
            )],
            "Unexpected validation warnings."
        );
    }

    #[test]
    fn validate_action_apply_correct() {
        let (principal, action, resource, schema) = schema_with_single_principal_action_resource();

        let policy = Template::new(
            PolicyID::from_string("policy0"),
            None,
            ast::Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::is_eq(Arc::new(principal)),
            ActionConstraint::is_eq(action),
            ResourceConstraint::is_eq(Arc::new(resource)),
            Expr::val(true),
        );

        let validator = Validator::new(schema);
        assert_validate_policy_succeeds(&validator, &policy);
    }

    #[test]
    fn validate_action_apply_incorrect_principal() {
        let (_, _, _, schema) = schema_with_single_principal_action_resource();

        let src =
            r#"permit(principal == baz::"p", action == Action::"foo", resource == baz::"r");"#;
        let p = parse_policy_or_template(None, src).unwrap();

        let validate = Validator::new(schema);
        let notes: Vec<ValidationError> =
            validate.validate_template_action_application(&p).collect();

        expect_err(
            src,
            &Report::new(notes.first().unwrap().clone()),
            &ExpectedErrorMessageBuilder::error(
                r#"for policy `policy0`, unable to find an applicable action given the policy scope constraints"#,
            )
            .exactly_one_underline(src)
            .build(),
        );
        assert_eq!(notes.len(), 1, "{:?}", notes);
    }

    #[test]
    fn validate_action_apply_incorrect_resource() {
        let (_, _, _, schema) = schema_with_single_principal_action_resource();

        let src =
            r#"permit(principal == bar::"p", action == Action::"foo", resource == bar::"r");"#;
        let p = parse_policy_or_template(None, src).unwrap();

        let validate = Validator::new(schema);
        let notes: Vec<ValidationError> =
            validate.validate_template_action_application(&p).collect();

        expect_err(
            src,
            &Report::new(notes.first().unwrap().clone()),
            &ExpectedErrorMessageBuilder::error(
                r#"for policy `policy0`, unable to find an applicable action given the policy scope constraints"#,
            )
            .exactly_one_underline(src)
            .build(),
        );
        assert_eq!(notes.len(), 1, "{:?}", notes);
    }

    #[test]
    fn validate_action_apply_incorrect_principal_and_resource() {
        let (_, _, _, schema) = schema_with_single_principal_action_resource();

        let src =
            r#"permit(principal == baz::"p", action == Action::"foo", resource == bar::"r");"#;
        let p = parse_policy_or_template(None, src).unwrap();

        let validate = Validator::new(schema);
        let notes: Vec<ValidationError> =
            validate.validate_template_action_application(&p).collect();

        expect_err(
            src,
            &Report::new(notes.first().unwrap().clone()),
            &ExpectedErrorMessageBuilder::error(
                r#"for policy `policy0`, unable to find an applicable action given the policy scope constraints"#,
            )
            .exactly_one_underline(src)
            .build(),
        );
        assert_eq!(notes.len(), 1, "{:?}", notes);
    }

    #[test]
    fn validate_principal_is() {
        let (_, _, _, schema) = schema_with_single_principal_action_resource();

        let policy =
            parse_policy_or_template(None, "permit(principal is bar, action, resource);").unwrap();

        let validator = Validator::new(schema);
        assert_validate_policy_succeeds(&validator, &policy);

        let policy = parse_policy_or_template(
            None,
            r#"permit(principal is bar in bar::"baz", action, resource);"#,
        )
        .unwrap();

        assert_validate_policy_succeeds(&validator, &policy);
    }

    #[test]
    fn validate_principal_is_err() {
        let (_, _, _, schema) = schema_with_single_principal_action_resource();

        let src = "permit(principal is baz, action, resource);";
        let policy = parse_policy_or_template(None, src).unwrap();

        let validator = Validator::new(schema);
        assert_validate_policy_fails(
            &validator,
            &policy,
            &[ValidationError::invalid_action_application(
                Some(Loc::new(0..43, Arc::from(src))),
                PolicyID::from_string("policy0"),
                false,
                false,
            )],
        );
        assert_validate_policy_flags_impossible_policy(&validator, &policy);

        let src = r#"permit(principal is biz in faz::"a", action, resource);"#;
        let policy = parse_policy_or_template(None, src).unwrap();

        assert_validate_policy_fails(
            &validator,
            &policy,
            &[
                ValidationError::unrecognized_entity_type(
                    Some(Loc::new(27..30, Arc::from(src))),
                    PolicyID::from_string("policy0"),
                    "faz".into(),
                    Some("baz".into()),
                ),
                ValidationError::unrecognized_entity_type(
                    Some(Loc::new(20..23, Arc::from(src))),
                    PolicyID::from_string("policy0"),
                    "biz".into(),
                    Some("baz".into()),
                ),
                ValidationError::invalid_action_application(
                    Some(Loc::new(0..55, Arc::from(src))),
                    PolicyID::from_string("policy0"),
                    false,
                    false,
                ),
            ],
        );
        assert_validate_policy_flags_impossible_policy(&validator, &policy);

        let src = r#"permit(principal is bar in baz::"buz", action, resource);"#;
        let policy = parse_policy_or_template(None, src).unwrap();

        assert_validate_policy_fails(
            &validator,
            &policy,
            &[ValidationError::invalid_action_application(
                Some(Loc::new(0..57, Arc::from(src))),
                PolicyID::from_string("policy0"),
                false,
                false,
            )],
        );
        assert_validate_policy_flags_impossible_policy(&validator, &policy);
    }

    #[test]
    fn validate_resource_is() {
        let (_, _, _, schema) = schema_with_single_principal_action_resource();

        let policy =
            parse_policy_or_template(None, "permit(principal, action, resource is baz);").unwrap();

        let validator = Validator::new(schema);
        assert_validate_policy_succeeds(&validator, &policy);

        let policy = parse_policy_or_template(
            None,
            r#"permit(principal, action, resource is baz in baz::"bar");"#,
        )
        .unwrap();

        assert_validate_policy_succeeds(&validator, &policy);
    }

    #[test]
    fn validate_resource_is_err() {
        let (_, _, _, schema) = schema_with_single_principal_action_resource();

        let src = "permit(principal, action, resource is bar);";
        let policy = parse_policy_or_template(None, src).unwrap();

        let validator = Validator::new(schema);
        assert_validate_policy_fails(
            &validator,
            &policy,
            &[ValidationError::invalid_action_application(
                Some(Loc::new(0..43, Arc::from(src))),
                PolicyID::from_string("policy0"),
                false,
                false,
            )],
        );
        assert_validate_policy_flags_impossible_policy(&validator, &policy);

        let src = r#"permit(principal, action, resource is baz in bar::"buz");"#;
        let policy = parse_policy_or_template(None, src).unwrap();

        assert_validate_policy_fails(
            &validator,
            &policy,
            &[ValidationError::invalid_action_application(
                Some(Loc::new(0..57, Arc::from(src))),
                PolicyID::from_string("policy0"),
                false,
                false,
            )],
        );
        assert_validate_policy_flags_impossible_policy(&validator, &policy);

        let src = r#"permit(principal, action, resource is biz in faz::"a");"#;
        let policy = parse_policy_or_template(None, src).unwrap();

        assert_validate_policy_fails(
            &validator,
            &policy,
            &[
                ValidationError::unrecognized_entity_type(
                    Some(Loc::new(45..48, Arc::from(src))),
                    PolicyID::from_string("policy0"),
                    "faz".into(),
                    Some("baz".into()),
                ),
                ValidationError::unrecognized_entity_type(
                    Some(Loc::new(38..41, Arc::from(src))),
                    PolicyID::from_string("policy0"),
                    "biz".into(),
                    Some("baz".into()),
                ),
                ValidationError::invalid_action_application(
                    Some(Loc::new(0..55, Arc::from(src))),
                    PolicyID::from_string("policy0"),
                    false,
                    false,
                ),
            ],
        );
        assert_validate_policy_flags_impossible_policy(&validator, &policy);
    }

    #[test]
    fn is_unknown_entity_condition() {
        let (_, _, _, schema) = schema_with_single_principal_action_resource();
        let src = r#"permit(principal, action, resource) when { resource is biz };"#;
        let policy = parse_policy_or_template(None, src).unwrap();

        let validator = Validator::new(schema);
        let err = validator
            .validate_policy(&policy, ValidationMode::default())
            .0
            .next()
            .unwrap();
        expect_err(
            src,
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error(
                "for policy `policy0`, unrecognized entity type `biz`",
            )
            .exactly_one_underline("biz")
            .help("did you mean `baz`?")
            .build(),
        );

        assert_validate_policy_flags_impossible_policy(&validator, &policy);
    }

    #[test]
    fn test_with_tc_computation() {
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

        let schema_file = json_schema::NamespaceDefinition::new(
            [
                (
                    principal_type.parse().unwrap(),
                    json_schema::StandardEntityType {
                        member_of_types: vec![],
                        shape: json_schema::AttributesOrContext::default(),
                        tags: None,
                    }
                    .into(),
                ),
                (
                    resource_type.parse().unwrap(),
                    json_schema::StandardEntityType {
                        member_of_types: vec![resource_parent_type.parse().unwrap()],
                        shape: json_schema::AttributesOrContext::default(),
                        tags: None,
                    }
                    .into(),
                ),
                (
                    resource_parent_type.parse().unwrap(),
                    json_schema::StandardEntityType {
                        member_of_types: vec![resource_grandparent_type.parse().unwrap()],
                        shape: json_schema::AttributesOrContext::default(),
                        tags: None,
                    }
                    .into(),
                ),
                (
                    resource_grandparent_type.parse().unwrap(),
                    json_schema::StandardEntityType {
                        member_of_types: vec![],
                        shape: json_schema::AttributesOrContext::default(),
                        tags: None,
                    }
                    .into(),
                ),
            ],
            [
                (
                    action_name.into(),
                    json_schema::ActionType {
                        applies_to: Some(json_schema::ApplySpec {
                            resource_types: vec![resource_type.parse().unwrap()],
                            principal_types: vec![principal_type.parse().unwrap()],
                            context: json_schema::AttributesOrContext::default(),
                        }),
                        member_of: Some(vec![json_schema::ActionEntityUID::new(
                            None,
                            action_parent_name.into(),
                        )]),
                        attributes: None,
                        annotations: Annotations::new(),
                        loc: None,
                        #[cfg(feature = "extended-schema")]
                        defn_loc: None,
                    },
                ),
                (
                    action_parent_name.into(),
                    json_schema::ActionType {
                        applies_to: None,
                        member_of: Some(vec![json_schema::ActionEntityUID::new(
                            None,
                            action_grandparent_name.into(),
                        )]),
                        attributes: None,
                        annotations: Annotations::new(),
                        loc: None,
                        #[cfg(feature = "extended-schema")]
                        defn_loc: None,
                    },
                ),
                (
                    action_grandparent_name.into(),
                    json_schema::ActionType {
                        applies_to: None,
                        member_of: Some(vec![]),
                        attributes: None,
                        annotations: Annotations::new(),
                        loc: None,
                        #[cfg(feature = "extended-schema")]
                        defn_loc: None,
                    },
                ),
            ],
        );
        let schema = schema_file.try_into().unwrap();

        let policy = Template::new(
            PolicyID::from_string("policy0"),
            None,
            ast::Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::any(),
            ActionConstraint::is_in([action_grandparent_euid]),
            ResourceConstraint::is_in(Arc::new(resource_grandparent_euid)),
            Expr::val(true),
        );

        let validator = Validator::new(schema);
        assert_validate_policy_succeeds(&validator, &policy);
    }

    #[test]
    fn unspecified_principal_resource_with_scope_conditions() {
        let schema = serde_json::from_str::<json_schema::NamespaceDefinition<RawName>>(
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
            Some(PolicyID::from_string("0")),
            r#"permit(principal == a::"p", action, resource == a::"r");"#,
        )
        .unwrap();

        let validator = Validator::new(schema);
        let (template, _) = Template::link_static_policy(policy);
        assert_validate_policy_flags_impossible_policy(&validator, &template);
    }
}

#[cfg(test)]
#[cfg(feature = "partial-validate")]
mod partial_schema {
    use crate::{
        ast::{PolicyID, StaticPolicy, Template},
        parser::parse_policy,
    };

    use crate::validator::{json_schema, RawName, Validator};

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_validates_with_empty_schema(policy: StaticPolicy) {
        let schema: json_schema::NamespaceDefinition<RawName> = serde_json::from_str(
            r#"
        {
            "entityTypes": { },
            "actions": {}
        }
        "#,
        )
        .unwrap();
        let schema = schema.try_into().unwrap();

        let (template, _) = Template::link_static_policy(policy);
        let validate = Validator::new(schema);
        let errs = validate
            .validate_policy(&template, crate::validator::ValidationMode::Partial)
            .0
            .collect::<Vec<_>>();
        assert_eq!(errs, vec![], "Did not expect any validation errors.");
    }

    #[test]
    fn undeclared_entity_type_partial_schema() {
        let policy = parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal == User::"alice", action, resource);"#,
        )
        .unwrap();
        assert_validates_with_empty_schema(policy);

        let policy = parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action == Action::"view", resource);"#,
        )
        .unwrap();
        assert_validates_with_empty_schema(policy);

        let policy = parse_policy(
            Some(PolicyID::from_string("0")),
            r#"permit(principal, action, resource == Photo::"party.jpg");"#,
        )
        .unwrap();
        assert_validates_with_empty_schema(policy);
    }
}
