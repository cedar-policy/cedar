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

use crate::{ValidatorEntityType, ValidatorSchema};
use cedar_policy_core::entities::json::GetSchemaTypeError;
use cedar_policy_core::extensions::Extensions;
use cedar_policy_core::{ast, entities};
use miette::Diagnostic;
use smol_str::SmolStr;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;

/// Struct which carries enough information that it can (efficiently) impl Core's `Schema`
#[derive(Debug)]
pub struct CoreSchema<'a> {
    /// Contains all the information
    schema: &'a ValidatorSchema,
    /// For easy lookup, this is a map from action name to `Entity` object
    /// for each action in the schema. This information is contained in the
    /// `ValidatorSchema`, but not efficient to extract -- getting the `Entity`
    /// from the `ValidatorSchema` is O(N) as of this writing, but with this
    /// cache it's O(1).
    actions: HashMap<ast::EntityUID, Arc<ast::Entity>>,
}

impl<'a> CoreSchema<'a> {
    /// Create a new `CoreSchema` for the given `ValidatorSchema`
    pub fn new(schema: &'a ValidatorSchema) -> Self {
        Self {
            actions: schema
                .action_entities_iter()
                .map(|e| (e.uid().clone(), Arc::new(e)))
                .collect(),
            schema,
        }
    }
}

impl<'a> entities::Schema for CoreSchema<'a> {
    type EntityTypeDescription = EntityTypeDescription;
    type ActionEntityIterator = Vec<Arc<ast::Entity>>;

    fn entity_type(&self, entity_type: &ast::EntityType) -> Option<EntityTypeDescription> {
        EntityTypeDescription::new(self.schema, entity_type)
    }

    fn action(&self, action: &ast::EntityUID) -> Option<Arc<ast::Entity>> {
        self.actions.get(action).cloned()
    }

    fn entity_types_with_basename<'b>(
        &'b self,
        basename: &'b ast::Id,
    ) -> Box<dyn Iterator<Item = ast::EntityType> + 'b> {
        Box::new(
            self.schema
                .entity_types()
                .filter_map(move |(entity_type, _)| {
                    if entity_type.name().basename() == basename {
                        Some(entity_type.clone())
                    } else {
                        None
                    }
                }),
        )
    }

    fn action_entities(&self) -> Self::ActionEntityIterator {
        self.actions.values().map(Arc::clone).collect()
    }
}

/// Struct which carries enough information that it can impl Core's `EntityTypeDescription`
#[derive(Debug)]
pub struct EntityTypeDescription {
    /// Core `EntityType` this is describing
    core_type: ast::EntityType,
    /// Contains most of the schema information for this entity type
    validator_type: ValidatorEntityType,
    /// Allowed parent types for this entity type. (As of this writing, this
    /// information is not contained in the `validator_type` by itself.)
    allowed_parent_types: Arc<HashSet<ast::EntityType>>,
}

impl EntityTypeDescription {
    /// Create a description of the given type in the given schema.
    /// Returns `None` if the given type is not in the given schema.
    pub fn new(schema: &ValidatorSchema, type_name: &ast::EntityType) -> Option<Self> {
        Some(Self {
            core_type: type_name.clone(),
            validator_type: schema.get_entity_type(type_name).cloned()?,
            allowed_parent_types: {
                let mut set = HashSet::new();
                for (possible_parent_typename, possible_parent_et) in schema.entity_types() {
                    if possible_parent_et.descendants.contains(type_name) {
                        set.insert(possible_parent_typename.clone());
                    }
                }
                Arc::new(set)
            },
        })
    }
}

impl entities::EntityTypeDescription for EntityTypeDescription {
    fn entity_type(&self) -> ast::EntityType {
        self.core_type.clone()
    }

    fn attr_type(&self, attr: &str) -> Option<entities::SchemaType> {
        let attr_type: &crate::types::Type = &self.validator_type.attr(attr)?.attr_type;
        // This converts a type from a schema into the representation of schema
        // types used by core. `attr_type` is taken from a `ValidatorEntityType`
        // which was constructed from a schema.
        // PANIC SAFETY: see above
        #[allow(clippy::expect_used)]
        let core_schema_type: entities::SchemaType = attr_type
            .clone()
            .try_into()
            .expect("failed to convert validator type into Core SchemaType");
        debug_assert!(attr_type.is_consistent_with(&core_schema_type));
        Some(core_schema_type)
    }

    fn required_attrs<'s>(&'s self) -> Box<dyn Iterator<Item = SmolStr> + 's> {
        Box::new(
            self.validator_type
                .attributes
                .iter()
                .filter(|(_, ty)| ty.is_required)
                .map(|(attr, _)| attr.clone()),
        )
    }

    fn allowed_parent_types(&self) -> Arc<HashSet<ast::EntityType>> {
        Arc::clone(&self.allowed_parent_types)
    }

    fn open_attributes(&self) -> bool {
        self.validator_type.open_attributes.is_open()
    }
}

impl ast::RequestSchema for ValidatorSchema {
    type Error = RequestValidationError;
    fn validate_request(
        &self,
        request: &ast::Request,
        extensions: Extensions<'_>,
    ) -> std::result::Result<(), Self::Error> {
        use ast::EntityUIDEntry;
        // first check that principal and resource are of types that exist in
        // the schema, we can do this check even if action is unknown.
        if let EntityUIDEntry::Known {
            euid: principal, ..
        } = request.principal()
        {
            if self.get_entity_type(principal.entity_type()).is_none() {
                return Err(request_validation_errors::UndeclaredPrincipalTypeError {
                    principal_ty: principal.entity_type().clone(),
                }
                .into());
            }
        }
        if let EntityUIDEntry::Known { euid: resource, .. } = request.resource() {
            if self.get_entity_type(resource.entity_type()).is_none() {
                return Err(request_validation_errors::UndeclaredResourceTypeError {
                    resource_ty: resource.entity_type().clone(),
                }
                .into());
            }
        }

        // the remaining checks require knowing about the action.
        match request.action() {
            EntityUIDEntry::Known { euid: action, .. } => {
                let validator_action_id = self.get_action_id(action).ok_or_else(|| {
                    request_validation_errors::UndeclaredActionError {
                        action: Arc::clone(action),
                    }
                })?;
                if let EntityUIDEntry::Known {
                    euid: principal, ..
                } = request.principal()
                {
                    if !validator_action_id
                        .applies_to
                        .is_applicable_principal_type(principal.entity_type())
                    {
                        return Err(request_validation_errors::InvalidPrincipalTypeError {
                            principal_ty: principal.entity_type().clone(),
                            action: Arc::clone(action),
                        }
                        .into());
                    }
                }
                if let EntityUIDEntry::Known { euid: resource, .. } = request.resource() {
                    if !validator_action_id
                        .applies_to
                        .is_applicable_resource_type(resource.entity_type())
                    {
                        return Err(request_validation_errors::InvalidResourceTypeError {
                            resource_ty: resource.entity_type().clone(),
                            action: Arc::clone(action),
                        }
                        .into());
                    }
                }
                if let Some(context) = request.context() {
                    let expected_context_ty = validator_action_id.context_type();
                    if !expected_context_ty
                        .typecheck_partial_value(&context.clone().into(), extensions)
                        .map_err(RequestValidationError::TypeOfContext)?
                    {
                        return Err(request_validation_errors::InvalidContextError {
                            context: context.clone(),
                            action: Arc::clone(action),
                        }
                        .into());
                    }
                }
            }
            EntityUIDEntry::Unknown { .. } => {
                // We could hypothetically ensure that the concrete parts of the
                // request are valid for _some_ action, but this is probably more
                // expensive than we want for this validation step.
                // Instead, we just let the above checks (that principal and
                // resource are of types that at least _exist_ in the schema)
                // suffice.
            }
        }
        Ok(())
    }
}

impl<'a> ast::RequestSchema for CoreSchema<'a> {
    type Error = RequestValidationError;
    fn validate_request(
        &self,
        request: &ast::Request,
        extensions: Extensions<'_>,
    ) -> Result<(), Self::Error> {
        self.schema.validate_request(request, extensions)
    }
}

/// Error when the request does not conform to the schema.
#[derive(Debug, Diagnostic, Error)]
pub enum RequestValidationError {
    /// Request action is not declared in the schema
    #[error(transparent)]
    #[diagnostic(transparent)]
    UndeclaredAction(#[from] request_validation_errors::UndeclaredActionError),
    /// Request principal is of a type not declared in the schema
    #[error(transparent)]
    #[diagnostic(transparent)]
    UndeclaredPrincipalType(#[from] request_validation_errors::UndeclaredPrincipalTypeError),
    /// Request resource is of a type not declared in the schema
    #[error(transparent)]
    #[diagnostic(transparent)]
    UndeclaredResourceType(#[from] request_validation_errors::UndeclaredResourceTypeError),
    /// Request principal is of a type that is declared in the schema, but is
    /// not valid for the request action
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidPrincipalType(#[from] request_validation_errors::InvalidPrincipalTypeError),
    /// Request resource is of a type that is declared in the schema, but is
    /// not valid for the request action
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidResourceType(#[from] request_validation_errors::InvalidResourceTypeError),
    /// Context does not comply with the shape specified for the request action
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidContext(#[from] request_validation_errors::InvalidContextError),
    /// Error computing the type of the `Context`; see the contained error type
    /// for details about the kinds of errors that can occur
    #[error("context is not valid: {0}")]
    #[diagnostic(transparent)]
    TypeOfContext(GetSchemaTypeError),
}

/// Errors related to validation
pub mod request_validation_errors {
    use cedar_policy_core::ast;
    use miette::Diagnostic;
    use std::sync::Arc;
    use thiserror::Error;

    /// Request action is not declared in the schema
    #[derive(Debug, Error, Diagnostic)]
    #[error("request's action `{action}` is not declared in the schema")]
    pub struct UndeclaredActionError {
        /// Action which was not declared in the schema
        pub(super) action: Arc<ast::EntityUID>,
    }

    impl UndeclaredActionError {
        /// The action which was not declared in the schema
        pub fn action(&self) -> &ast::EntityUID {
            &self.action
        }
    }

    /// Request principal is of a type not declared in the schema
    #[derive(Debug, Error, Diagnostic)]
    #[error("principal type `{principal_ty}` is not declared in the schema")]
    pub struct UndeclaredPrincipalTypeError {
        /// Principal type which was not declared in the schema
        pub(super) principal_ty: ast::EntityType,
    }

    impl UndeclaredPrincipalTypeError {
        /// The principal type which was not declared in the schema
        pub fn principal_ty(&self) -> &ast::EntityType {
            &self.principal_ty
        }
    }

    /// Request resource is of a type not declared in the schema
    #[derive(Debug, Error, Diagnostic)]
    #[error("resource type `{resource_ty}` is not declared in the schema")]
    pub struct UndeclaredResourceTypeError {
        /// Resource type which was not declared in the schema
        pub(super) resource_ty: ast::EntityType,
    }

    impl UndeclaredResourceTypeError {
        /// The resource type which was not declared in the schema
        pub fn resource_ty(&self) -> &ast::EntityType {
            &self.resource_ty
        }
    }

    /// Request principal is of a type that is declared in the schema, but is
    /// not valid for the request action
    #[derive(Debug, Error, Diagnostic)]
    #[error("principal type `{principal_ty}` is not valid for `{action}`")]
    pub struct InvalidPrincipalTypeError {
        /// Principal type which is not valid
        pub(super) principal_ty: ast::EntityType,
        /// Action which it is not valid for
        pub(super) action: Arc<ast::EntityUID>,
    }

    impl InvalidPrincipalTypeError {
        /// The principal type which is not valid
        pub fn principal_ty(&self) -> &ast::EntityType {
            &self.principal_ty
        }

        /// The action which it is not valid for
        pub fn action(&self) -> &ast::EntityUID {
            &self.action
        }
    }

    /// Request resource is of a type that is declared in the schema, but is
    /// not valid for the request action
    #[derive(Debug, Error, Diagnostic)]
    #[error("resource type `{resource_ty}` is not valid for `{action}`")]
    pub struct InvalidResourceTypeError {
        /// Resource type which is not valid
        pub(super) resource_ty: ast::EntityType,
        /// Action which it is not valid for
        pub(super) action: Arc<ast::EntityUID>,
    }

    impl InvalidResourceTypeError {
        /// The resource type which is not valid
        pub fn resource_ty(&self) -> &ast::EntityType {
            &self.resource_ty
        }

        /// The action which it is not valid for
        pub fn action(&self) -> &ast::EntityUID {
            &self.action
        }
    }

    /// Context does not comply with the shape specified for the request action
    #[derive(Debug, Error, Diagnostic)]
    #[error("context `{context}` is not valid for `{action}`")]
    pub struct InvalidContextError {
        /// Context which is not valid
        pub(super) context: ast::Context,
        /// Action which it is not valid for
        pub(super) action: Arc<ast::EntityUID>,
    }

    impl InvalidContextError {
        /// The context which is not valid
        pub fn context(&self) -> &ast::Context {
            &self.context
        }

        /// The action which it is not valid for
        pub fn action(&self) -> &ast::EntityUID {
            &self.action
        }
    }
}

/// Struct which carries enough information that it can impl Core's
/// `ContextSchema`.
#[derive(Debug, Clone, PartialEq)]
pub struct ContextSchema(
    // INVARIANT: The `Type` stored in this struct must be representable as a
    // `SchemaType` to avoid panicking in `context_type`.
    crate::types::Type,
);

/// A `Type` contains all the information we need for a Core `ContextSchema`.
impl entities::ContextSchema for ContextSchema {
    fn context_type(&self) -> entities::SchemaType {
        // PANIC SAFETY: By `ContextSchema` invariant, `self.0` is representable as a schema type.
        #[allow(clippy::expect_used)]
        self.0
            .clone()
            .try_into()
            .expect("failed to convert validator type into Core SchemaType")
    }
}

/// Since different Actions have different schemas for `Context`, you must
/// specify the `Action` in order to get a `ContextSchema`.
///
/// Returns `None` if the action is not in the schema.
pub fn context_schema_for_action(
    schema: &ValidatorSchema,
    action: &ast::EntityUID,
) -> Option<ContextSchema> {
    // The invariant on `ContextSchema` requires that the inner type is
    // representable as a schema type. `ValidatorSchema::context_type`
    // always returns a closed record type, which are representable as long
    // as their values are representable. The values are representable
    // because they are taken from the context of a `ValidatorActionId`
    // which was constructed directly from a schema.
    schema.context_type(action).cloned().map(ContextSchema)
}

#[cfg(test)]
mod test {
    use super::*;
    use cedar_policy_core::test_utils::{expect_err, ExpectedErrorMessageBuilder};
    use cool_asserts::assert_matches;
    use serde_json::json;

    fn schema() -> ValidatorSchema {
        let src = json!(
        { "": {
            "entityTypes": {
                "User": {
                    "memberOfTypes": [ "Group" ]
                },
                "Group": {
                    "memberOfTypes": []
                },
                "Photo": {
                    "memberOfTypes": [ "Album" ]
                },
                "Album": {
                    "memberOfTypes": []
                }
            },
            "actions": {
                "view_photo": {
                    "appliesTo": {
                        "principalTypes": ["User", "Group"],
                        "resourceTypes": ["Photo"]
                    }
                },
                "edit_photo": {
                    "appliesTo": {
                        "principalTypes": ["User", "Group"],
                        "resourceTypes": ["Photo"],
                        "context": {
                            "type": "Record",
                            "attributes": {
                                "admin_approval": {
                                    "type": "Boolean",
                                    "required": true,
                                }
                            }
                        }
                    }
                }
            }
        }});
        ValidatorSchema::from_json_value(src, Extensions::all_available())
            .expect("failed to create ValidatorSchema")
    }

    /// basic success with concrete request and no context
    #[test]
    fn success_concrete_request_no_context() {
        assert_matches!(
            ast::Request::new(
                (
                    ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(),
                    None
                ),
                (
                    ast::EntityUID::with_eid_and_type("Action", "view_photo").unwrap(),
                    None
                ),
                (
                    ast::EntityUID::with_eid_and_type("Photo", "vacationphoto94.jpg").unwrap(),
                    None
                ),
                ast::Context::empty(),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Ok(_)
        );
    }

    /// basic success with concrete request and a context
    #[test]
    fn success_concrete_request_with_context() {
        assert_matches!(
            ast::Request::new(
                (
                    ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(),
                    None
                ),
                (
                    ast::EntityUID::with_eid_and_type("Action", "edit_photo").unwrap(),
                    None
                ),
                (
                    ast::EntityUID::with_eid_and_type("Photo", "vacationphoto94.jpg").unwrap(),
                    None
                ),
                ast::Context::from_pairs(
                    [("admin_approval".into(), ast::RestrictedExpr::val(true))],
                    Extensions::all_available()
                )
                .unwrap(),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Ok(_)
        );
    }

    /// success leaving principal unknown
    #[test]
    fn success_principal_unknown() {
        assert_matches!(
            ast::Request::new_with_unknowns(
                ast::EntityUIDEntry::Unknown { loc: None },
                ast::EntityUIDEntry::known(
                    ast::EntityUID::with_eid_and_type("Action", "view_photo").unwrap(),
                    None,
                ),
                ast::EntityUIDEntry::known(
                    ast::EntityUID::with_eid_and_type("Photo", "vacationphoto94.jpg").unwrap(),
                    None,
                ),
                Some(ast::Context::empty()),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Ok(_)
        );
    }

    /// success leaving action unknown
    #[test]
    fn success_action_unknown() {
        assert_matches!(
            ast::Request::new_with_unknowns(
                ast::EntityUIDEntry::known(
                    ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(),
                    None,
                ),
                ast::EntityUIDEntry::Unknown { loc: None },
                ast::EntityUIDEntry::known(
                    ast::EntityUID::with_eid_and_type("Photo", "vacationphoto94.jpg").unwrap(),
                    None,
                ),
                Some(ast::Context::empty()),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Ok(_)
        );
    }

    /// success leaving resource unknown
    #[test]
    fn success_resource_unknown() {
        assert_matches!(
            ast::Request::new_with_unknowns(
                ast::EntityUIDEntry::known(
                    ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(),
                    None,
                ),
                ast::EntityUIDEntry::known(
                    ast::EntityUID::with_eid_and_type("Action", "view_photo").unwrap(),
                    None,
                ),
                ast::EntityUIDEntry::Unknown { loc: None },
                Some(ast::Context::empty()),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Ok(_)
        );
    }

    /// success leaving context unknown
    #[test]
    fn success_context_unknown() {
        assert_matches!(
            ast::Request::new_with_unknowns(
                ast::EntityUIDEntry::known(
                    ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(),
                    None,
                ),
                ast::EntityUIDEntry::known(
                    ast::EntityUID::with_eid_and_type("Action", "view_photo").unwrap(),
                    None,
                ),
                ast::EntityUIDEntry::known(
                    ast::EntityUID::with_eid_and_type("Photo", "vacationphoto94.jpg").unwrap(),
                    None,
                ),
                None,
                Some(&schema()),
                Extensions::all_available(),
            ),
            Ok(_)
        )
    }

    /// success leaving everything unknown
    #[test]
    fn success_everything_unspecified() {
        assert_matches!(
            ast::Request::new_with_unknowns(
                ast::EntityUIDEntry::Unknown { loc: None },
                ast::EntityUIDEntry::Unknown { loc: None },
                ast::EntityUIDEntry::Unknown { loc: None },
                None,
                Some(&schema()),
                Extensions::all_available(),
            ),
            Ok(_)
        );
    }

    /// this succeeds for now: unknown action, concrete principal and
    /// resource of valid types, but none of the schema's actions would work
    /// with this principal and resource type
    #[test]
    fn success_unknown_action_but_invalid_types() {
        assert_matches!(
            ast::Request::new_with_unknowns(
                ast::EntityUIDEntry::known(
                    ast::EntityUID::with_eid_and_type("Album", "abc123").unwrap(),
                    None,
                ),
                ast::EntityUIDEntry::Unknown { loc: None },
                ast::EntityUIDEntry::known(
                    ast::EntityUID::with_eid_and_type("User", "alice").unwrap(),
                    None,
                ),
                None,
                Some(&schema()),
                Extensions::all_available(),
            ),
            Ok(_)
        );
    }

    /// request action not declared in the schema
    #[test]
    fn action_not_declared() {
        assert_matches!(
            ast::Request::new(
                (ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Action", "destroy").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Photo", "vacationphoto94.jpg").unwrap(), None),
                ast::Context::empty(),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Err(e) => {
                expect_err("", &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(r#"request's action `Action::"destroy"` is not declared in the schema"#).build());
            }
        );
    }

    /// request principal type not declared in the schema (action concrete)
    #[test]
    fn principal_type_not_declared() {
        assert_matches!(
            ast::Request::new(
                (ast::EntityUID::with_eid_and_type("Foo", "abc123").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Action", "view_photo").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Photo", "vacationphoto94.jpg").unwrap(), None),
                ast::Context::empty(),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Err(e) => {
                expect_err("", &miette::Report::new(e), &ExpectedErrorMessageBuilder::error("principal type `Foo` is not declared in the schema").build());
            }
        );
    }

    /// request resource type not declared in the schema (action concrete)
    #[test]
    fn resource_type_not_declared() {
        assert_matches!(
            ast::Request::new(
                (ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Action", "view_photo").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Foo", "vacationphoto94.jpg").unwrap(), None),
                ast::Context::empty(),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Err(e) => {
                expect_err("", &miette::Report::new(e), &ExpectedErrorMessageBuilder::error("resource type `Foo` is not declared in the schema").build());
            }
        );
    }

    /// request principal type declared, but invalid for request's action
    #[test]
    fn principal_type_invalid() {
        assert_matches!(
            ast::Request::new(
                (ast::EntityUID::with_eid_and_type("Album", "abc123").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Action", "view_photo").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Photo", "vacationphoto94.jpg").unwrap(), None),
                ast::Context::empty(),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Err(e) => {
                expect_err("", &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(r#"principal type `Album` is not valid for `Action::"view_photo"`"#).build());
            }
        );
    }

    /// request resource type declared, but invalid for request's action
    #[test]
    fn resource_type_invalid() {
        assert_matches!(
            ast::Request::new(
                (ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Action", "view_photo").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Group", "coders").unwrap(), None),
                ast::Context::empty(),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Err(e) => {
                expect_err("", &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(r#"resource type `Group` is not valid for `Action::"view_photo"`"#).build());
            }
        );
    }

    /// request context does not comply with specification: missing attribute
    #[test]
    fn context_missing_attribute() {
        assert_matches!(
            ast::Request::new(
                (ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Action", "edit_photo").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Photo", "vacationphoto94.jpg").unwrap(), None),
                ast::Context::empty(),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Err(e) => {
                expect_err("", &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(r#"context `<first-class record with 0 fields>` is not valid for `Action::"edit_photo"`"#).build());
            }
        );
    }

    /// request context does not comply with specification: extra attribute
    #[test]
    fn context_extra_attribute() {
        let context_with_extra_attr = ast::Context::from_pairs(
            [
                ("admin_approval".into(), ast::RestrictedExpr::val(true)),
                ("extra".into(), ast::RestrictedExpr::val(42)),
            ],
            Extensions::all_available(),
        )
        .unwrap();
        assert_matches!(
            ast::Request::new(
                (ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Action", "edit_photo").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Photo", "vacationphoto94.jpg").unwrap(), None),
                context_with_extra_attr.clone(),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Err(e) => {
                expect_err("", &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(r#"context `<first-class record with 2 fields>` is not valid for `Action::"edit_photo"`"#).build());
            }
        );
    }

    /// request context does not comply with specification: attribute is wrong type
    #[test]
    fn context_attribute_wrong_type() {
        let context_with_wrong_type_attr = ast::Context::from_pairs(
            [(
                "admin_approval".into(),
                ast::RestrictedExpr::set([ast::RestrictedExpr::val(true)]),
            )],
            Extensions::all_available(),
        )
        .unwrap();
        assert_matches!(
            ast::Request::new(
                (ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Action", "edit_photo").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Photo", "vacationphoto94.jpg").unwrap(), None),
                context_with_wrong_type_attr.clone(),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Err(e) => {
                expect_err("", &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(r#"context `<first-class record with 1 fields>` is not valid for `Action::"edit_photo"`"#).build());
            }
        );
    }

    /// request context contains heterogeneous set
    #[test]
    fn context_attribute_heterogeneous_set() {
        let context_with_heterogeneous_set = ast::Context::from_pairs(
            [(
                "admin_approval".into(),
                ast::RestrictedExpr::set([
                    ast::RestrictedExpr::val(true),
                    ast::RestrictedExpr::val(-1001),
                ]),
            )],
            Extensions::all_available(),
        )
        .unwrap();
        assert_matches!(
            ast::Request::new(
                (ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Action", "edit_photo").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Photo", "vacationphoto94.jpg").unwrap(), None),
                context_with_heterogeneous_set.clone(),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Err(e) => {
                expect_err("", &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(r#"context `<first-class record with 1 fields>` is not valid for `Action::"edit_photo"`"#).build());
            }
        );
    }
}
