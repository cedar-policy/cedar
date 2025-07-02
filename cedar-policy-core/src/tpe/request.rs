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

use crate::ast::RequestSchema;
use crate::tpe::err::{
    ExistingPrincipalError, ExistingResourceError, IncorrectPrincipalEntityTypeError,
    IncorrectResourceEntityTypeError, NoMatchingReqEnvError, RequestBuilderError,
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
        resource: PartialEntityUID,
        action: EntityUID,
        context: Option<Arc<BTreeMap<SmolStr, Value>>>,
        schema: &ValidatorSchema,
    ) -> std::result::Result<Self, RequestValidationError> {
        let req = Self {
            principal,
            resource,
            action,
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
            resource,
            action,
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
            return Err(ExistingPrincipalError {
                principal: EntityUID::from_components(
                    self.partial_request.principal.ty.clone(),
                    eid.clone(),
                    None,
                ),
            }
            .into());
        } else {
            // PANIC SAFETY: partial_request is validated and hence the entity type must exist in the schema
            #[allow(clippy::unwrap_used)]
            if candidate.entity_type() != &self.partial_request.principal.ty {
                return Err(IncorrectPrincipalEntityTypeError {
                    ty: candidate.entity_type().clone(),
                    expected: self.partial_request.principal.ty.clone(),
                }
                .into());
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
            return Err(ExistingResourceError {
                resource: EntityUID::from_components(
                    self.partial_request.resource.ty.clone(),
                    eid.clone(),
                    None,
                ),
            }
            .into());
        } else {
            // PANIC SAFETY: partial_request is validated and hence the entity type must exist in the schema
            #[allow(clippy::unwrap_used)]
            if candidate.entity_type() != &self.partial_request.resource.ty {
                return Err(IncorrectResourceEntityTypeError {
                    ty: candidate.entity_type().clone(),
                    expected: self.partial_request.resource.ty.clone(),
                }
                .into());
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
            if let Some(_) = &self.partial_request.context {
                return Err(RequestBuilderError::ExistingContext);
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
            return Err(RequestBuilderError::UnknownContextCandidate);
        }
    }
}
