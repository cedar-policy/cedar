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
    ) -> anyhow::Result<Self> {
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
    ) -> Option<RequestEnv<'s>> {
        // PANIC SAFETY: strict validation should produce concrete action entity uid
        #[allow(clippy::unwrap_used)]
        schema
            .unlinked_request_envs(ValidationMode::Strict)
            .find(|env| {
                env.action_entity_uid().unwrap() == &self.action
                    && env.principal_entity_type() == Some(&self.principal.ty)
                    && env.resource_entity_type() == Some(&self.resource.ty)
            })
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

/// A request builder based on a `PartialRequest`
// TODO:
// 1. add validation
// 2. add a partial constructor that ensures `partial_request` is consistent with `env`
#[derive(Debug, Clone)]
pub struct RequestBuilder<'e> {
    /// The `PartialRequest`
    pub partial_request: PartialRequest,
    /// Env used for validation
    pub env: RequestEnv<'e>,
}

use anyhow::anyhow;
impl RequestBuilder<'_> {
    /// Try to get a concrete `Request`
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

    /// Try to add a principal
    pub fn add_principal(&mut self, candidate: &EntityUID) -> anyhow::Result<()> {
        if let PartialEntityUID { eid: Some(_), .. } = &self.partial_request.principal {
            return Err(anyhow!("principal exists"));
        } else {
            if candidate.entity_type() != &self.partial_request.principal.ty {
                return Err(anyhow!("mismatched principal entity type"));
            } else {
                self.partial_request.principal = PartialEntityUID {
                    ty: candidate.entity_type().clone(),
                    eid: Some(candidate.eid().clone()),
                };
                Ok(())
            }
        }
    }

    /// Try to add a resource
    pub fn add_resource(&mut self, candidate: &EntityUID) -> anyhow::Result<()> {
        if let PartialEntityUID { eid: Some(_), .. } = &self.partial_request.resource {
            return Err(anyhow!("resource exists"));
        } else {
            if candidate.entity_type() != &self.partial_request.resource.ty {
                return Err(anyhow!("mismatched resource entity type"));
            } else {
                self.partial_request.resource = PartialEntityUID {
                    ty: candidate.entity_type().clone(),
                    eid: Some(candidate.eid().clone()),
                };
                Ok(())
            }
        }
    }

    /// Try add `Context`
    pub fn add_context(&mut self, candidate: &Context) -> anyhow::Result<()> {
        if let Context::Value(v) = candidate {
            if let Some(_) = &self.partial_request.context {
                return Err(anyhow!("context already exists"));
            } else {
                self.partial_request.context = Some(v.clone());
                Ok(())
            }
        } else {
            return Err(anyhow!("invalid context"));
        }
    }
}
