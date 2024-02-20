use crate::{ValidatorEntityType, ValidatorSchema};
use cedar_policy_core::entities::GetSchemaTypeError;
use cedar_policy_core::extensions::Extensions;
use cedar_policy_core::{ast, entities};
use miette::Diagnostic;
use smol_str::SmolStr;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;

/// Struct which carries enough information that it can (efficiently) impl Core's `Schema`
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
        match entity_type {
            ast::EntityType::Unspecified => None, // Unspecified entities cannot be declared in the schema and should not appear in JSON data
            ast::EntityType::Specified(name) => EntityTypeDescription::new(self.schema, name),
        }
    }

    fn action(&self, action: &ast::EntityUID) -> Option<Arc<ast::Entity>> {
        self.actions.get(action).map(Arc::clone)
    }

    fn entity_types_with_basename<'b>(
        &'b self,
        basename: &'b ast::Id,
    ) -> Box<dyn Iterator<Item = ast::EntityType> + 'b> {
        Box::new(self.schema.entity_types().filter_map(move |(name, _)| {
            if name.basename() == basename {
                Some(ast::EntityType::Specified(name.clone()))
            } else {
                None
            }
        }))
    }

    fn action_entities(&self) -> Self::ActionEntityIterator {
        self.actions.values().map(Arc::clone).collect()
    }
}

/// Struct which carries enough information that it can impl Core's `EntityTypeDescription`
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
    pub fn new(schema: &ValidatorSchema, type_name: &ast::Name) -> Option<Self> {
        Some(Self {
            core_type: ast::EntityType::Specified(type_name.clone()),
            validator_type: schema.get_entity_type(type_name).cloned()?,
            allowed_parent_types: {
                let mut set = HashSet::new();
                for (possible_parent_typename, possible_parent_et) in schema.entity_types() {
                    if possible_parent_et.descendants.contains(type_name) {
                        set.insert(ast::EntityType::Specified(possible_parent_typename.clone()));
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
        // the schema, or unspecified.
        // we can do this check even if action is unknown.
        if let EntityUIDEntry::Known {
            euid: principal, ..
        } = request.principal()
        {
            match principal.entity_type() {
                ast::EntityType::Specified(name) => {
                    if self.get_entity_type(name).is_none() {
                        return Err(RequestValidationError::UndeclaredPrincipalType {
                            principal_ty: principal.entity_type().clone(),
                        });
                    }
                }
                ast::EntityType::Unspecified => {} // unspecified principal is allowed, unless we find it is not allowed for this action, which we will check below
            }
        }
        if let EntityUIDEntry::Known { euid: resource, .. } = request.resource() {
            match resource.entity_type() {
                ast::EntityType::Specified(name) => {
                    if self.get_entity_type(name).is_none() {
                        return Err(RequestValidationError::UndeclaredResourceType {
                            resource_ty: resource.entity_type().clone(),
                        });
                    }
                }
                ast::EntityType::Unspecified => {} // unspecified resource is allowed, unless we find it is not allowed for this action, which we will check below
            }
        }

        // the remaining checks require knowing about the action.
        match request.action() {
            EntityUIDEntry::Known { euid: action, .. } => {
                let validator_action_id = self.get_action_id(action).ok_or_else(|| {
                    RequestValidationError::UndeclaredAction {
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
                        return Err(RequestValidationError::InvalidPrincipalType {
                            principal_ty: principal.entity_type().clone(),
                            action: Arc::clone(action),
                        });
                    }
                }
                if let EntityUIDEntry::Known { euid: resource, .. } = request.resource() {
                    if !validator_action_id
                        .applies_to
                        .is_applicable_resource_type(resource.entity_type())
                    {
                        return Err(RequestValidationError::InvalidResourceType {
                            resource_ty: resource.entity_type().clone(),
                            action: Arc::clone(action),
                        });
                    }
                }
                if let Some(context) = request.context() {
                    let expected_context_ty = validator_action_id.context_type();
                    if !expected_context_ty
                        .typecheck_partial_value(context.as_ref(), extensions)
                        .map_err(RequestValidationError::TypeOfContext)?
                    {
                        return Err(RequestValidationError::InvalidContext {
                            context: context.clone(),
                            action: Arc::clone(action),
                        });
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

#[derive(Debug, Diagnostic, Error)]
pub enum RequestValidationError {
    /// Request action is not declared in the schema
    #[error("request's action `{action}` is not declared in the schema")]
    UndeclaredAction {
        /// Action which was not declared in the schema
        action: Arc<ast::EntityUID>,
    },
    /// Request principal is of a type not declared in the schema
    #[error("principal type `{principal_ty}` is not declared in the schema")]
    UndeclaredPrincipalType {
        /// Principal type which was not declared in the schema
        principal_ty: ast::EntityType,
    },
    /// Request resource is of a type not declared in the schema
    #[error("resource type `{resource_ty}` is not declared in the schema")]
    UndeclaredResourceType {
        /// Resource type which was not declared in the schema
        resource_ty: ast::EntityType,
    },
    /// Request principal is of a type that is declared in the schema, but is
    /// not valid for the request action
    #[error("principal type `{principal_ty}` is not valid for `{action}`")]
    InvalidPrincipalType {
        /// Principal type which is not valid
        principal_ty: ast::EntityType,
        /// Action which it is not valid for
        action: Arc<ast::EntityUID>,
    },
    /// Request resource is of a type that is declared in the schema, but is
    /// not valid for the request action
    #[error("resource type `{resource_ty}` is not valid for `{action}`")]
    InvalidResourceType {
        /// Resource type which is not valid
        resource_ty: ast::EntityType,
        /// Action which it is not valid for
        action: Arc<ast::EntityUID>,
    },
    /// Context does not comply with the shape specified for the request action
    #[error("context `{context}` is not valid for `{action}`")]
    InvalidContext {
        /// Context which is not valid
        context: ast::Context,
        /// Action which it is not valid for
        action: Arc<ast::EntityUID>,
    },
    /// Error computing the type of the `Context`; see the contained error type
    /// for details about the kinds of errors that can occur
    #[error("context is not valid: {0}")]
    #[diagnostic(transparent)]
    TypeOfContext(GetSchemaTypeError),
}

/// Struct which carries enough information that it can impl Core's
/// `ContextSchema`.
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
    schema.context_type(action).map(ContextSchema)
}

#[cfg(test)]
mod test {
    use super::*;
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
                ast::EntityUIDEntry::concrete(
                    ast::EntityUID::with_eid_and_type("Action", "view_photo").unwrap(),
                    None,
                ),
                ast::EntityUIDEntry::concrete(
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
                ast::EntityUIDEntry::concrete(
                    ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(),
                    None,
                ),
                ast::EntityUIDEntry::Unknown { loc: None },
                ast::EntityUIDEntry::concrete(
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
                ast::EntityUIDEntry::concrete(
                    ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(),
                    None,
                ),
                ast::EntityUIDEntry::concrete(
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
                ast::EntityUIDEntry::concrete(
                    ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(),
                    None,
                ),
                ast::EntityUIDEntry::concrete(
                    ast::EntityUID::with_eid_and_type("Action", "view_photo").unwrap(),
                    None,
                ),
                ast::EntityUIDEntry::concrete(
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
                ast::EntityUIDEntry::concrete(
                    ast::EntityUID::with_eid_and_type("Album", "abc123").unwrap(),
                    None,
                ),
                ast::EntityUIDEntry::Unknown { loc: None },
                ast::EntityUIDEntry::concrete(
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
            Err(RequestValidationError::UndeclaredAction { action }) => {
                assert_eq!(&*action, &ast::EntityUID::with_eid_and_type("Action", "destroy").unwrap());
            }
        );
    }

    /// request action unspecified (and not declared in the schema)
    #[test]
    fn action_unspecified() {
        assert_matches!(
            ast::Request::new(
                (ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(), None),
                (ast::EntityUID::unspecified_from_eid(ast::Eid::new("blahblah")), None),
                (ast::EntityUID::with_eid_and_type("Photo", "vacationphoto94.jpg").unwrap(), None),
                ast::Context::empty(),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Err(RequestValidationError::UndeclaredAction { action }) => {
                assert_eq!(&*action, &ast::EntityUID::unspecified_from_eid(ast::Eid::new("blahblah")));
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
            Err(RequestValidationError::UndeclaredPrincipalType { principal_ty }) => {
                assert_eq!(principal_ty, ast::EntityType::Specified(ast::Name::parse_unqualified_name("Foo").unwrap()));
            }
        );
    }

    /// request principal type not declared in the schema (action unspecified)
    #[test]
    fn principal_type_not_declared_action_unspecified() {
        assert_matches!(
            ast::Request::new(
                (ast::EntityUID::with_eid_and_type("Foo", "abc123").unwrap(), None),
                (ast::EntityUID::unspecified_from_eid(ast::Eid::new("blahblah")), None),
                (ast::EntityUID::with_eid_and_type("Photo", "vacationphoto94.jpg").unwrap(), None),
                ast::Context::empty(),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Err(RequestValidationError::UndeclaredPrincipalType { principal_ty }) => {
                assert_eq!(principal_ty, ast::EntityType::Specified(ast::Name::parse_unqualified_name("Foo").unwrap()));
            }
        );
    }

    /// request principal type unspecified (and not declared in the schema)
    #[test]
    fn principal_unspecified() {
        assert_matches!(
            ast::Request::new(
                (ast::EntityUID::unspecified_from_eid(ast::Eid::new("principal")), None),
                (ast::EntityUID::with_eid_and_type("Action", "view_photo").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Photo", "vacationphoto94.jpg").unwrap(), None),
                ast::Context::empty(),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Err(RequestValidationError::InvalidPrincipalType { principal_ty, .. }) => {
                assert_eq!(principal_ty, ast::EntityType::Unspecified);
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
            Err(RequestValidationError::UndeclaredResourceType { resource_ty }) => {
                assert_eq!(resource_ty, ast::EntityType::Specified(ast::Name::parse_unqualified_name("Foo").unwrap()));
            }
        );
    }

    /// request resource type not declared in the schema (action unspecified)
    #[test]
    fn resource_type_not_declared_action_unspecified() {
        assert_matches!(
            ast::Request::new(
                (ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(), None),
                (ast::EntityUID::unspecified_from_eid(ast::Eid::new("blahblah")), None),
                (ast::EntityUID::with_eid_and_type("Foo", "vacationphoto94.jpg").unwrap(), None),
                ast::Context::empty(),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Err(RequestValidationError::UndeclaredResourceType { resource_ty }) => {
                assert_eq!(resource_ty, ast::EntityType::Specified(ast::Name::parse_unqualified_name("Foo").unwrap()));
            }
        );
    }

    /// request resource type unspecified (and not declared in the schema)
    #[test]
    fn resource_unspecified() {
        assert_matches!(
            ast::Request::new(
                (ast::EntityUID::with_eid_and_type("User", "abc123").unwrap(), None),
                (ast::EntityUID::with_eid_and_type("Action", "view_photo").unwrap(), None),
                (ast::EntityUID::unspecified_from_eid(ast::Eid::new("resource")), None),
                ast::Context::empty(),
                Some(&schema()),
                Extensions::all_available(),
            ),
            Err(RequestValidationError::InvalidResourceType { resource_ty, .. }) => {
                assert_eq!(resource_ty, ast::EntityType::Unspecified);
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
            Err(RequestValidationError::InvalidPrincipalType { principal_ty, action }) => {
                assert_eq!(principal_ty, ast::EntityType::Specified(ast::Name::parse_unqualified_name("Album").unwrap()));
                assert_eq!(&*action, &ast::EntityUID::with_eid_and_type("Action", "view_photo").unwrap());
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
            Err(RequestValidationError::InvalidResourceType { resource_ty, action }) => {
                assert_eq!(resource_ty, ast::EntityType::Specified(ast::Name::parse_unqualified_name("Group").unwrap()));
                assert_eq!(&*action, &ast::EntityUID::with_eid_and_type("Action", "view_photo").unwrap());
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
            Err(RequestValidationError::InvalidContext { context, action }) => {
                assert_eq!(context, ast::Context::empty());
                assert_eq!(&*action, &ast::EntityUID::with_eid_and_type("Action", "edit_photo").unwrap());
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
            Err(RequestValidationError::InvalidContext { context, action }) => {
                assert_eq!(context, context_with_extra_attr);
                assert_eq!(&*action, &ast::EntityUID::with_eid_and_type("Action", "edit_photo").unwrap());
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
            Err(RequestValidationError::InvalidContext { context, action }) => {
                assert_eq!(context, context_with_wrong_type_attr);
                assert_eq!(&*action, &ast::EntityUID::with_eid_and_type("Action", "edit_photo").unwrap());
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
            Err(RequestValidationError::InvalidContext { context, action }) => {
                assert_eq!(context, context_with_heterogeneous_set);
                assert_eq!(&*action, &ast::EntityUID::with_eid_and_type("Action", "edit_photo").unwrap());
            }
        );
    }
}
