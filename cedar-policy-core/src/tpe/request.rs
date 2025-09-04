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

//! This module contains the partial request.

use std::{collections::BTreeMap, sync::Arc};

use crate::ast::{EntityUIDEntry, RequestSchema};
use crate::tpe::err::{
    ExistingPrincipalError, ExistingResourceError, InconsistentActionError,
    InconsistentPrincipalEidError, InconsistentPrincipalTypeError, InconsistentResourceEidError,
    InconsistentResourceTypeError, IncorrectPrincipalEntityTypeError,
    IncorrectResourceEntityTypeError, NoMatchingReqEnvError, RequestBuilderError,
    RequestConsistencyError,
};
use crate::validator::request_validation_errors::{
    UndeclaredActionError, UndeclaredPrincipalTypeError, UndeclaredResourceTypeError,
};
use crate::validator::{
    types::RequestEnv, RequestValidationError, ValidationMode, ValidatorEntityType,
    ValidatorEntityTypeKind, ValidatorSchema,
};
use crate::{
    ast::{Context, Eid, EntityType, EntityUID, Request, Value},
    entities::conformance::is_valid_enumerated_entity,
    extensions::Extensions,
};
use smol_str::SmolStr;

/// Partial EntityUID
#[derive(Debug, Clone)]
pub struct PartialEntityUID {
    /// Typename of the entity
    pub ty: EntityType,
    /// Optional EID of the entity
    pub eid: Option<Eid>,
}

impl TryFrom<PartialEntityUID> for EntityUID {
    type Error = ();
    fn try_from(value: PartialEntityUID) -> std::result::Result<EntityUID, ()> {
        if let Some(eid) = value.eid {
            std::result::Result::Ok(EntityUID::from_components(value.ty, eid, None))
        } else {
            Err(())
        }
    }
}

impl From<EntityUID> for PartialEntityUID {
    fn from(value: EntityUID) -> Self {
        Self {
            ty: value.entity_type().clone(),
            eid: Some(value.eid().clone()),
        }
    }
}

/// Represents the request tuple <P, A, R, C> (see the Cedar design doc).
#[derive(Debug, Clone)]
pub struct PartialRequest {
    /// Principal associated with the request
    pub(crate) principal: PartialEntityUID,

    /// Action associated with the request
    pub(crate) action: EntityUID,

    /// Resource associated with the request
    pub(crate) resource: PartialEntityUID,

    /// Context associated with the request.
    /// `None` means that variable will result in a residual for partial evaluation.
    pub(crate) context: Option<Arc<BTreeMap<SmolStr, Value>>>,
}

impl PartialRequest {
    /// Create a well-formed `PartialRequest` (i.e., it conforms to the schema)
    pub fn new(
        principal: PartialEntityUID,
        action: EntityUID,
        resource: PartialEntityUID,

        context: Option<Arc<BTreeMap<SmolStr, Value>>>,
        schema: &ValidatorSchema,
    ) -> std::result::Result<Self, RequestValidationError> {
        let req = Self {
            principal,
            action,
            resource,
            context,
        };
        req.validate(schema)?;
        Ok(req)
    }

    /// Like `new` but do not perform any validation
    pub fn new_unchecked(
        principal: PartialEntityUID,
        resource: PartialEntityUID,
        action: EntityUID,
        context: Option<Arc<BTreeMap<SmolStr, Value>>>,
    ) -> Self {
        Self {
            principal,
            action,
            resource,
            context,
        }
    }

    // Find the matching `RequestEnv`
    pub(crate) fn find_request_env<'s>(
        &self,
        schema: &'s ValidatorSchema,
    ) -> std::result::Result<RequestEnv<'s>, NoMatchingReqEnvError> {
        // PANIC SAFETY: strict validation should produce concrete action entity uid
        #[allow(clippy::unwrap_used)]
        schema
            .unlinked_request_envs(ValidationMode::Strict)
            .find(|env| {
                env.action_entity_uid().unwrap() == &self.action
                    && env.principal_entity_type() == Some(&self.principal.ty)
                    && env.resource_entity_type() == Some(&self.resource.ty)
            })
            .ok_or(NoMatchingReqEnvError)
    }

    // Validate `self` with `schema`
    pub(crate) fn validate(
        &self,
        schema: &ValidatorSchema,
    ) -> std::result::Result<(), RequestValidationError> {
        if let Some(action_id) = schema.get_action_id(&self.action) {
            action_id.check_principal_type(&self.principal.ty, &self.action.clone().into())?;
            action_id.check_resource_type(&self.resource.ty, &self.action.clone().into())?;
            if let Some(principal_ty) = schema.get_entity_type(&self.principal.ty) {
                if let std::result::Result::Ok(uid) = self.principal.clone().try_into() {
                    if let ValidatorEntityType {
                        kind: ValidatorEntityTypeKind::Enum(choices),
                        ..
                    } = principal_ty
                    {
                        is_valid_enumerated_entity(
                            &Vec::from(choices.clone().map(Eid::new)),
                            &uid,
                        )?;
                    }
                }
            } else {
                return Err(UndeclaredPrincipalTypeError {
                    principal_ty: self.principal.ty.clone(),
                }
                .into());
            }
            if let Some(resource_ty) = schema.get_entity_type(&self.resource.ty) {
                if let std::result::Result::Ok(uid) = self.resource.clone().try_into() {
                    if let ValidatorEntityType {
                        kind: ValidatorEntityTypeKind::Enum(choices),
                        ..
                    } = resource_ty
                    {
                        is_valid_enumerated_entity(
                            &Vec::from(choices.clone().map(Eid::new)),
                            &uid,
                        )?;
                    }
                }
            } else {
                return Err(UndeclaredResourceTypeError {
                    resource_ty: self.resource.ty.clone(),
                }
                .into());
            }
            if let Some(m) = &self.context {
                schema.validate_context(
                    &Context::Value(m.clone()),
                    &self.action,
                    Extensions::all_available(),
                )?;
            }
            Ok(())
        } else {
            Err(UndeclaredActionError {
                action: self.action.clone().into(),
            }
            .into())
        }
    }

    /// Check consistency between a [`PartialRequest`] and a [`Request`]
    pub fn check_consistency(
        &self,
        request: &Request,
    ) -> std::result::Result<(), RequestConsistencyError> {
        match &request.principal {
            EntityUIDEntry::Unknown { .. } => {
                return Err(RequestConsistencyError::UnknownPrincipal);
            }
            EntityUIDEntry::Known { euid, .. } => {
                if euid.entity_type() != &self.principal.ty {
                    return Err(InconsistentPrincipalTypeError {
                        partial: self.principal.ty.clone(),
                        concrete: euid.entity_type().clone(),
                    }
                    .into());
                }
                if let Some(eid) = &self.principal.eid {
                    if eid != euid.eid() {
                        return Err(InconsistentPrincipalEidError {
                            partial: eid.clone(),
                            concrete: euid.eid().clone(),
                        }
                        .into());
                    }
                }
            }
        }

        match &request.resource {
            EntityUIDEntry::Unknown { .. } => {
                return Err(RequestConsistencyError::UnknownResource);
            }
            EntityUIDEntry::Known { euid, .. } => {
                if euid.entity_type() != &self.resource.ty {
                    return Err(InconsistentResourceTypeError {
                        partial: self.resource.ty.clone(),
                        concrete: euid.entity_type().clone(),
                    }
                    .into());
                }
                if let Some(eid) = &self.resource.eid {
                    if eid != euid.eid() {
                        return Err(InconsistentResourceEidError {
                            partial: eid.clone(),
                            concrete: euid.eid().clone(),
                        }
                        .into());
                    }
                }
            }
        }

        match &request.action {
            EntityUIDEntry::Unknown { .. } => {
                return Err(RequestConsistencyError::UnknownAction);
            }
            EntityUIDEntry::Known { euid, .. } => {
                if euid.as_ref() != &self.action {
                    return Err(InconsistentActionError {
                        partial: self.action.clone(),
                        concrete: euid.as_ref().clone(),
                    }
                    .into());
                }
            }
        }

        match &request.context {
            Some(Context::Value(c)) => {
                if let Some(m) = &self.context {
                    if c != m {
                        return Err(RequestConsistencyError::InconsistentContext);
                    }
                }
            }
            Some(Context::RestrictedResidual { .. }) => {
                return Err(RequestConsistencyError::ConcreteContextContainsUnknowns);
            }
            None => {
                return Err(RequestConsistencyError::UnknownContext);
            }
        }
        Ok(())
    }

    /// Get the [`EntityType`] of `principal`
    pub fn get_principal_type(&self) -> EntityType {
        self.principal.ty.clone()
    }

    /// Get the [`EntityType`] of `resource`
    pub fn get_resource_type(&self) -> EntityType {
        self.resource.ty.clone()
    }

    /// Get the `principal`
    pub fn get_principal(&self) -> PartialEntityUID {
        self.principal.clone()
    }

    /// Get the `resource`
    pub fn get_resource(&self) -> PartialEntityUID {
        self.resource.clone()
    }

    /// Get the `action`
    pub fn get_action(&self) -> EntityUID {
        self.action.clone()
    }

    /// Get the `context` attributes
    pub fn get_context_attrs(&self) -> Option<&BTreeMap<SmolStr, Value>> {
        self.context.as_ref().map(|attrs| attrs.as_ref())
    }
}

/// A request builder based on a [`PartialRequest`]
/// Users should use it to iteratively construct a [`Request`] using methods
/// `add_*`
#[derive(Debug, Clone)]
pub struct RequestBuilder<'s> {
    /// The `PartialRequest`
    partial_request: PartialRequest,
    /// Env used for validation
    schema: &'s ValidatorSchema,
}

impl<'s> RequestBuilder<'s> {
    /// Attempt to construct a [`RequestBuilder`] from a [`PartialRequest`] and
    /// a [`ValidatorSchema`]
    pub fn new(
        partial_request: PartialRequest,
        schema: &'s ValidatorSchema,
    ) -> std::result::Result<Self, RequestBuilderError> {
        partial_request.validate(schema)?;
        Ok(Self {
            partial_request,
            schema,
        })
    }

    /// Attempt to get a concrete [`Request`]
    /// Return `None` if there are still missing components
    pub fn get_request(&self) -> Option<Request> {
        let PartialRequest {
            principal,
            action,
            resource,
            context,
        } = &self.partial_request;
        match (
            EntityUID::try_from(principal.clone()),
            EntityUID::try_from(resource.clone()),
            context,
        ) {
            (
                std::result::Result::Ok(principal),
                std::result::Result::Ok(resource),
                Some(context),
            ) => Some(Request::new_unchecked(
                principal.into(),
                action.clone().into(),
                resource.into(),
                Some(Context::Value(context.clone())),
            )),
            _ => None,
        }
    }

    /// Attempt to add `principal`
    pub fn add_principal(
        &mut self,
        candidate: &EntityUID,
    ) -> std::result::Result<(), RequestBuilderError> {
        if let PartialEntityUID { eid: Some(eid), .. } = &self.partial_request.principal {
            Err(ExistingPrincipalError {
                principal: EntityUID::from_components(
                    self.partial_request.principal.ty.clone(),
                    eid.clone(),
                    None,
                ),
            }
            .into())
        } else {
            // PANIC SAFETY: partial_request is validated and hence the entity type must exist in the schema
            #[allow(clippy::unwrap_used)]
            if candidate.entity_type() != &self.partial_request.principal.ty {
                Err(IncorrectPrincipalEntityTypeError {
                    ty: candidate.entity_type().clone(),
                    expected: self.partial_request.principal.ty.clone(),
                }
                .into())
            } else {
                let principal_ty = self
                    .schema
                    .get_entity_type(&self.partial_request.principal.ty)
                    .unwrap();
                if let ValidatorEntityType {
                    kind: ValidatorEntityTypeKind::Enum(choices),
                    ..
                } = principal_ty
                {
                    is_valid_enumerated_entity(
                        &Vec::from(choices.clone().map(Eid::new)),
                        candidate,
                    )
                    .map_err(RequestBuilderError::InvalidPrincipalCandidate)?;
                }
                self.partial_request.principal = PartialEntityUID {
                    ty: candidate.entity_type().clone(),
                    eid: Some(candidate.eid().clone()),
                };
                Ok(())
            }
        }
    }

    /// Attempt to add `resource`
    pub fn add_resource(
        &mut self,
        candidate: &EntityUID,
    ) -> std::result::Result<(), RequestBuilderError> {
        if let PartialEntityUID { eid: Some(eid), .. } = &self.partial_request.resource {
            Err(ExistingResourceError {
                resource: EntityUID::from_components(
                    self.partial_request.resource.ty.clone(),
                    eid.clone(),
                    None,
                ),
            }
            .into())
        } else {
            // PANIC SAFETY: partial_request is validated and hence the entity type must exist in the schema
            #[allow(clippy::unwrap_used)]
            if candidate.entity_type() != &self.partial_request.resource.ty {
                Err(IncorrectResourceEntityTypeError {
                    ty: candidate.entity_type().clone(),
                    expected: self.partial_request.resource.ty.clone(),
                }
                .into())
            } else {
                let resource_ty = self
                    .schema
                    .get_entity_type(&self.partial_request.resource.ty)
                    .unwrap();
                if let ValidatorEntityType {
                    kind: ValidatorEntityTypeKind::Enum(choices),
                    ..
                } = resource_ty
                {
                    is_valid_enumerated_entity(
                        &Vec::from(choices.clone().map(Eid::new)),
                        candidate,
                    )
                    .map_err(RequestBuilderError::InvalidResourceCandidate)?;
                }
                self.partial_request.resource = PartialEntityUID {
                    ty: candidate.entity_type().clone(),
                    eid: Some(candidate.eid().clone()),
                };
                Ok(())
            }
        }
    }

    /// Attempt to add `context`
    pub fn add_context(
        &mut self,
        candidate: &Context,
    ) -> std::result::Result<(), RequestBuilderError> {
        if let Context::Value(v) = candidate {
            if self.partial_request.context.is_some() {
                Err(RequestBuilderError::ExistingContext)
            } else {
                self.schema
                    .validate_context(
                        candidate,
                        &self.partial_request.action,
                        Extensions::all_available(),
                    )
                    .map_err(RequestBuilderError::IllTypedContextCandidate)?;
                self.partial_request.context = Some(v.clone());
                Ok(())
            }
        } else {
            Err(RequestBuilderError::UnknownContextCandidate)
        }
    }
}

#[cfg(test)]
mod request_builder_tests {
    use std::{collections::BTreeMap, sync::Arc};

    use cool_asserts::assert_matches;
    use std::str::FromStr;

    use crate::{
        ast::{Context, EntityUID},
        extensions::Extensions,
        tpe::{
            err::RequestBuilderError,
            request::{PartialEntityUID, PartialRequest, RequestBuilder},
        },
        validator::ValidatorSchema,
    };

    #[track_caller]
    fn schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            r#"
        entity A enum ["foo"];
        entity B;
        action a appliesTo {
          principal: A,
          resource: B,
          context: {
            "" : A,
          }
        };
        "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    #[track_caller]
    fn request() -> PartialRequest {
        PartialRequest::new(
            PartialEntityUID {
                ty: "A".parse().unwrap(),
                eid: None,
            },
            r#"Action::"a""#.parse().unwrap(),
            PartialEntityUID {
                ty: "B".parse().unwrap(),
                eid: None,
            },
            None,
            &schema(),
        )
        .unwrap()
    }

    #[test]
    fn build() {
        let schema = schema();
        let request = request();
        let mut builder = RequestBuilder::new(request, &schema).expect("should succeed");

        // add principal of incorrect type
        assert_matches!(
            builder.add_principal(&r#"B::"""#.parse().unwrap()),
            Err(RequestBuilderError::IncorrectPrincipalEntityType(_))
        );
        // add invalid principal
        assert_matches!(
            builder.add_principal(&r#"A::"""#.parse().unwrap()),
            Err(RequestBuilderError::InvalidPrincipalCandidate(_))
        );
        // add a principal
        assert_matches!(
            builder.add_principal(&r#"A::"foo""#.parse().unwrap()),
            Ok(_)
        );
        // then we can't add it again
        assert_matches!(
            builder.add_principal(&r#"A::"foo""#.parse().unwrap()),
            Err(RequestBuilderError::ExistingPrincipal(_))
        );
        // and we're not done
        assert_matches!(builder.get_request(), None);
        // add resource
        assert_matches!(builder.add_resource(&r#"B::"foo""#.parse().unwrap()), Ok(_));
        // so we can't do it again
        assert_matches!(
            builder.add_resource(&r#"B::"foo""#.parse().unwrap()),
            Err(RequestBuilderError::ExistingResource(_))
        );
        // add a context of incorrect type
        assert_matches!(
            builder.add_context(&Context::Value(Arc::new(BTreeMap::from_iter([(
                "".into(),
                1.into()
            )])))),
            Err(RequestBuilderError::IllTypedContextCandidate(_))
        );
        // add a context
        assert_matches!(
            builder.add_context(&Context::Value(Arc::new(BTreeMap::from_iter([(
                "".into(),
                EntityUID::from_str(r#"A::"foo""#).unwrap().into(),
            )])))),
            Ok(_)
        );
        // can't do it again
        assert_matches!(
            builder.add_context(&Context::Value(Arc::new(BTreeMap::from_iter([(
                "".into(),
                EntityUID::from_str(r#"A::"foo""#).unwrap().into(),
            )])))),
            Err(RequestBuilderError::ExistingContext)
        );
        // and we're done
        assert_matches!(builder.get_request(), Some(_));
    }
}
