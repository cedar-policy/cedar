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
use crate::entities::conformance::err::InvalidEnumEntityError;
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
    types::RequestEnv, RequestValidationError, ValidationMode, ValidatorEntityTypeKind,
    ValidatorSchema,
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

#[derive(Debug)]
enum PartialEUIDConsistencyError {
    Unknown,
    InconsistentType(EntityType, EntityType),
    InconsistentEid(Eid, Eid),
}

impl PartialEUIDConsistencyError {
    pub fn into_resource_error(self) -> RequestConsistencyError {
        match self {
            PartialEUIDConsistencyError::Unknown => RequestConsistencyError::UnknownResource,
            PartialEUIDConsistencyError::InconsistentType(partial, concrete) => {
                InconsistentResourceTypeError { partial, concrete }.into()
            }
            PartialEUIDConsistencyError::InconsistentEid(partial, concrete) => {
                InconsistentResourceEidError { partial, concrete }.into()
            }
        }
    }

    pub fn into_principal_error(self) -> RequestConsistencyError {
        match self {
            PartialEUIDConsistencyError::Unknown => RequestConsistencyError::UnknownPrincipal,
            PartialEUIDConsistencyError::InconsistentType(partial, concrete) => {
                InconsistentPrincipalTypeError { partial, concrete }.into()
            }
            PartialEUIDConsistencyError::InconsistentEid(partial, concrete) => {
                InconsistentPrincipalEidError { partial, concrete }.into()
            }
        }
    }
}

#[derive(Debug)]
enum PartialEUIDValidationError {
    UndeclaredType(EntityType),
    InvalidEnum(InvalidEnumEntityError),
}

impl PartialEUIDValidationError {
    pub fn into_resource_error(self) -> RequestValidationError {
        match self {
            PartialEUIDValidationError::UndeclaredType(resource_ty) => {
                UndeclaredResourceTypeError { resource_ty }.into()
            }
            PartialEUIDValidationError::InvalidEnum(enum_err) => enum_err.into(),
        }
    }

    pub fn into_principal_error(self) -> RequestValidationError {
        match self {
            PartialEUIDValidationError::UndeclaredType(principal_ty) => {
                UndeclaredPrincipalTypeError { principal_ty }.into()
            }
            PartialEUIDValidationError::InvalidEnum(enum_err) => enum_err.into(),
        }
    }
}

#[derive(Debug)]
enum PartialEUIDBuilderError {
    Existing(EntityUID),
    IncorrectType(EntityType, EntityType),
    Invalid(PartialEUIDValidationError),
}

impl PartialEUIDBuilderError {
    pub fn into_resource_error(self) -> RequestBuilderError {
        match self {
            PartialEUIDBuilderError::Existing(resource) => {
                ExistingResourceError { resource }.into()
            }
            PartialEUIDBuilderError::IncorrectType(ty, expected) => {
                IncorrectResourceEntityTypeError { ty, expected }.into()
            }
            PartialEUIDBuilderError::Invalid(e) => e.into_resource_error().into(),
        }
    }

    pub fn into_principal_error(self) -> RequestBuilderError {
        match self {
            PartialEUIDBuilderError::Existing(principal) => {
                ExistingPrincipalError { principal }.into()
            }
            PartialEUIDBuilderError::IncorrectType(ty, expected) => {
                IncorrectPrincipalEntityTypeError { ty, expected }.into()
            }
            PartialEUIDBuilderError::Invalid(e) => e.into_principal_error().into(),
        }
    }
}

impl PartialEntityUID {
    fn check_type(
        &self,
        schema: &ValidatorSchema,
        uid: Option<&EntityUID>,
    ) -> Result<(), PartialEUIDValidationError> {
        // Entity type must be declared
        let entity_ty = schema
            .get_entity_type(&self.ty)
            .ok_or_else(|| PartialEUIDValidationError::UndeclaredType(self.ty.clone()))?;
        // If we have a concrete uid and this is an enum entity, it must be one
        // of the choices
        if let (ValidatorEntityTypeKind::Enum(choices), Some(uid)) = (&entity_ty.kind, uid) {
            is_valid_enumerated_entity(choices, uid)
                .map_err(PartialEUIDValidationError::InvalidEnum)?;
        }
        Ok(())
    }

    fn validate(&self, schema: &ValidatorSchema) -> Result<(), PartialEUIDValidationError> {
        self.check_type(schema, EntityUID::try_from(self.clone()).ok().as_ref())
    }

    fn check_consistency(&self, entry: &EntityUIDEntry) -> Result<(), PartialEUIDConsistencyError> {
        let EntityUIDEntry::Known { euid, .. } = entry else {
            return Err(PartialEUIDConsistencyError::Unknown);
        };
        if euid.entity_type() != &self.ty {
            return Err(PartialEUIDConsistencyError::InconsistentType(
                self.ty.clone(),
                euid.entity_type().clone(),
            ));
        }
        if let Some(eid) = &self.eid {
            if eid != euid.eid() {
                return Err(PartialEUIDConsistencyError::InconsistentEid(
                    eid.clone(),
                    euid.eid().clone(),
                ));
            }
        }
        Ok(())
    }

    /// Attempt to fill an unknown euid in a request with a concrete candidate.
    ///
    /// Errors without changing `self` if the candidate is in incompatible
    fn set_candidate(
        &mut self,
        candidate: EntityUID,
        schema: &ValidatorSchema,
    ) -> Result<(), PartialEUIDBuilderError> {
        if let Some(eid) = &self.eid {
            return Err(PartialEUIDBuilderError::Existing(
                EntityUID::from_components(self.ty.clone(), eid.clone(), None),
            ));
        }
        if candidate.entity_type() != &self.ty {
            return Err(PartialEUIDBuilderError::IncorrectType(
                candidate.entity_type().clone(),
                self.ty.clone(),
            ));
        }
        self.check_type(schema, Some(&candidate))
            .map_err(PartialEUIDBuilderError::Invalid)?;
        *self = PartialEntityUID::from(candidate);
        Ok(())
    }
}

impl TryFrom<PartialEntityUID> for EntityUID {
    type Error = ();
    fn try_from(value: PartialEntityUID) -> Result<EntityUID, ()> {
        if let Some(eid) = value.eid {
            Ok(EntityUID::from_components(value.ty, eid, None))
        } else {
            Err(())
        }
    }
}

impl From<EntityUID> for PartialEntityUID {
    fn from(value: EntityUID) -> Self {
        let (ty, eid) = value.components();
        Self { ty, eid: Some(eid) }
    }
}

/// Represents the request tuple <P, A, R, C> (see the Cedar design doc).
#[derive(Debug, Clone)]
pub struct PartialRequest {
    /// Principal associated with the request
    principal: PartialEntityUID,

    /// Action associated with the request
    action: EntityUID,

    /// Resource associated with the request
    resource: PartialEntityUID,

    /// Context associated with the request.
    /// `None` means that variable will result in a residual for partial evaluation.
    context: Option<Arc<BTreeMap<SmolStr, Value>>>,
}

impl PartialRequest {
    /// Create a well-formed `PartialRequest` (i.e., it conforms to the schema)
    pub fn new(
        principal: PartialEntityUID,
        action: EntityUID,
        resource: PartialEntityUID,
        context: Option<Arc<BTreeMap<SmolStr, Value>>>,
        schema: &ValidatorSchema,
    ) -> Result<Self, RequestValidationError> {
        let req = Self {
            principal,
            action,
            resource,
            context,
        };
        req.validate(schema)?;
        Ok(req)
    }

    // Find the matching `RequestEnv`
    pub(crate) fn find_request_env<'s>(
        &self,
        schema: &'s ValidatorSchema,
    ) -> Result<RequestEnv<'s>, NoMatchingReqEnvError> {
        #[expect(
            clippy::unwrap_used,
            reason = "strict validation should produce concrete action entity uid"
        )]
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
    pub(crate) fn validate(&self, schema: &ValidatorSchema) -> Result<(), RequestValidationError> {
        if let Some(action_id) = schema.get_action_id(&self.action) {
            action_id.check_principal_type(&self.principal.ty, &self.action.clone().into())?;
            action_id.check_resource_type(&self.resource.ty, &self.action.clone().into())?;
            self.principal
                .validate(schema)
                .map_err(|e| e.into_principal_error())?;
            self.resource
                .validate(schema)
                .map_err(|e| e.into_resource_error())?;
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
    pub fn check_consistency(&self, request: &Request) -> Result<(), RequestConsistencyError> {
        self.principal
            .check_consistency(&request.principal)
            .map_err(|e| e.into_principal_error())?;
        self.resource
            .check_consistency(&request.resource)
            .map_err(|e| e.into_resource_error())?;

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
    pub fn get_principal_type(&self) -> &EntityType {
        &self.principal.ty
    }

    /// Get the [`EntityType`] of `resource`
    pub fn get_resource_type(&self) -> &EntityType {
        &self.resource.ty
    }

    /// Get the `principal`
    pub fn get_principal(&self) -> &PartialEntityUID {
        &self.principal
    }

    /// Get the `resource`
    pub fn get_resource(&self) -> &PartialEntityUID {
        &self.resource
    }

    /// Get the `action`
    pub fn get_action(&self) -> &EntityUID {
        &self.action
    }

    /// Get the `context` attributes
    pub fn get_context_attrs(&self) -> Option<&Arc<BTreeMap<SmolStr, Value>>> {
        self.context.as_ref()
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
    ) -> Result<Self, RequestBuilderError> {
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
            (Ok(principal), Ok(resource), Some(context)) => Some(Request::new_unchecked(
                principal.into(),
                action.clone().into(),
                resource.into(),
                Some(Context::Value(context.clone())),
            )),
            _ => None,
        }
    }

    /// Attempt to add `principal`
    pub fn add_principal(&mut self, candidate: EntityUID) -> Result<(), RequestBuilderError> {
        self.partial_request
            .principal
            .set_candidate(candidate, self.schema)
            .map_err(|e| e.into_principal_error())
    }

    /// Attempt to add `resource`
    pub fn add_resource(&mut self, candidate: EntityUID) -> Result<(), RequestBuilderError> {
        self.partial_request
            .resource
            .set_candidate(candidate, self.schema)
            .map_err(|e| e.into_resource_error())
    }

    /// Attempt to add `context`
    pub fn add_context(&mut self, candidate: &Context) -> Result<(), RequestBuilderError> {
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
                    .map_err(RequestBuilderError::Validation)?;
                self.partial_request.context = Some(v.clone());
                Ok(())
            }
        } else {
            Err(RequestBuilderError::UnknownContextCandidate)
        }
    }
}

#[cfg(test)]
mod invalid_requests {
    use std::{collections::BTreeMap, sync::Arc};

    use crate::{
        ast::Value,
        extensions::Extensions,
        test_utils::{expect_err, ExpectedErrorMessage, ExpectedErrorMessageBuilder},
        tpe::request::PartialRequest,
        tpe::test_utils::parse_partial_euid,
        validator::ValidatorSchema,
    };

    #[track_caller]
    fn schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            r#"
        entity A enum ["foo"];
        entity B;
        entity C;
        action a appliesTo {
          principal: A,
          resource: B,
          context: {
            "" : A,
          }
        };
        action b appliesTo {
          principal: B,
          resource: A,
        };
        "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    #[track_caller]
    fn expect_validation_err(
        principal: &str,
        action: &str,
        resource: &str,
        context: Option<Arc<BTreeMap<smol_str::SmolStr, Value>>>,
        msg: &ExpectedErrorMessage<'_>,
    ) {
        let err = PartialRequest::new(
            parse_partial_euid(principal),
            action.parse().unwrap(),
            parse_partial_euid(resource),
            context,
            &schema(),
        )
        .expect_err("should fail to validate");
        expect_err("", &miette::Report::new(err), msg);
    }

    #[test]
    fn unknown_action() {
        expect_validation_err(
            "A",
            r#"Action::"c""#,
            "B",
            None,
            &ExpectedErrorMessageBuilder::error(
                r#"request's action `Action::"c"` is not declared in the schema"#,
            )
            .exactly_one_underline(r#"Action::"c""#)
            .build(),
        );
    }

    #[test]
    fn unknown_principal() {
        expect_validation_err(
            "D",
            r#"Action::"a""#,
            "B",
            None,
            &ExpectedErrorMessageBuilder::error(
                r#"principal type `D` is not valid for `Action::"a"`"#,
            )
            .help(r#"valid principal types for `Action::"a"`: `A`"#)
            .exactly_one_underline("D")
            .build(),
        );
    }

    #[test]
    fn unknown_resource() {
        expect_validation_err(
            "A",
            r#"Action::"a""#,
            "D",
            None,
            &ExpectedErrorMessageBuilder::error(
                r#"resource type `D` is not valid for `Action::"a"`"#,
            )
            .help(r#"valid resource types for `Action::"a"`: `B`"#)
            .exactly_one_underline("D")
            .build(),
        );
    }

    #[test]
    fn invalid_principal_for_action() {
        expect_validation_err(
            "C",
            r#"Action::"a""#,
            "B",
            None,
            &ExpectedErrorMessageBuilder::error(
                r#"principal type `C` is not valid for `Action::"a"`"#,
            )
            .help(r#"valid principal types for `Action::"a"`: `A`"#)
            .exactly_one_underline("C")
            .build(),
        );
    }

    #[test]
    fn invalid_resource_for_action() {
        expect_validation_err(
            "A",
            r#"Action::"a""#,
            "C",
            None,
            &ExpectedErrorMessageBuilder::error(
                r#"resource type `C` is not valid for `Action::"a"`"#,
            )
            .help(r#"valid resource types for `Action::"a"`: `B`"#)
            .exactly_one_underline("C")
            .build(),
        );
    }

    #[test]
    fn invalid_principal_enum() {
        expect_validation_err(
            r#"A::"bar""#,
            r#"Action::"a""#,
            "B",
            None,
            &ExpectedErrorMessageBuilder::error(
                r#"entity `A::"bar"` is of an enumerated entity type, but `"bar"` is not declared as a valid eid"#,
            )
            .help(r#"valid entity eids: "foo""#)
            .build(),
        );
    }

    #[test]
    fn invalid_resource_enum() {
        expect_validation_err(
            "B",
            r#"Action::"b""#,
            r#"A::"bar""#,
            None,
            &ExpectedErrorMessageBuilder::error(
                r#"entity `A::"bar"` is of an enumerated entity type, but `"bar"` is not declared as a valid eid"#,
            )
            .help(r#"valid entity eids: "foo""#)
            .build(),
        );
    }

    #[test]
    fn invalid_context() {
        // action `a` requires a context attribute `""` of type `A`, but we
        // supply a `Long`
        expect_validation_err(
            "A",
            r#"Action::"a""#,
            "B",
            Some(Arc::new(BTreeMap::from_iter([("".into(), 1.into())]))),
            &ExpectedErrorMessageBuilder::error(
                r#"context `{"": 1}` is not valid for `Action::"a"`"#,
            )
            .build(),
        );
    }
}

#[cfg(test)]
mod inconsistent_requests {
    use std::{collections::BTreeMap, sync::Arc};

    use crate::{
        ast::{Context, EntityUIDEntry, Request, Value},
        extensions::Extensions,
        test_utils::{expect_err, ExpectedErrorMessageBuilder},
        tpe::{request::PartialRequest, test_utils::parse_partial_euid},
        validator::ValidatorSchema,
    };

    #[track_caller]
    fn schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            r#"
        entity A;
        entity B;
        action a appliesTo {
          principal: A,
          resource: B,
          context: {
            "foo" : Long,
          }
        };
        action b appliesTo {
          principal: A,
          resource: B,
        };
        "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    /// A `PartialRequest` with a concrete principal `A::"p"`, action `a`,
    /// concrete resource `B::"r"`, and context `{foo: 0}`.
    #[track_caller]
    fn request() -> PartialRequest {
        PartialRequest::new(
            parse_partial_euid(r#"A::"p""#),
            r#"Action::"a""#.parse().unwrap(),
            parse_partial_euid(r#"B::"r""#),
            Some(Arc::new(BTreeMap::from_iter([("foo".into(), 0.into())]))),
            &schema(),
        )
        .unwrap()
    }

    /// Build a concrete [`Request`] out of the given components.
    #[track_caller]
    fn concrete_request(
        principal: &str,
        action: &str,
        resource: &str,
        context: BTreeMap<smol_str::SmolStr, Value>,
    ) -> Request {
        Request::new_unchecked(
            EntityUIDEntry::known(principal.parse().unwrap(), None),
            EntityUIDEntry::known(action.parse().unwrap(), None),
            EntityUIDEntry::known(resource.parse().unwrap(), None),
            Some(Context::Value(Arc::new(context))),
        )
    }

    #[track_caller]
    fn ctx() -> BTreeMap<smol_str::SmolStr, Value> {
        BTreeMap::from_iter([("foo".into(), 0.into())])
    }

    /// Check that [`request()`] is inconsistent with `concrete`, expecting the
    /// given error message.
    #[track_caller]
    fn expect_inconsistency(concrete: &Request, error: &str) {
        let err = request()
            .check_consistency(concrete)
            .expect_err("should be inconsistent");
        expect_err(
            "",
            &miette::Report::new(err),
            &ExpectedErrorMessageBuilder::error(error).build(),
        );
    }

    #[test]
    fn unknown_principal() {
        let concrete = Request::new_unchecked(
            EntityUIDEntry::unknown(),
            EntityUIDEntry::known(r#"Action::"a""#.parse().unwrap(), None),
            EntityUIDEntry::known(r#"B::"r""#.parse().unwrap(), None),
            Some(Context::Value(Arc::new(ctx()))),
        );
        expect_inconsistency(&concrete, "the concrete request's principal is unknown");
    }

    #[test]
    fn unknown_resource() {
        let concrete = Request::new_unchecked(
            EntityUIDEntry::known(r#"A::"p""#.parse().unwrap(), None),
            EntityUIDEntry::known(r#"Action::"a""#.parse().unwrap(), None),
            EntityUIDEntry::unknown(),
            Some(Context::Value(Arc::new(ctx()))),
        );
        expect_inconsistency(&concrete, "the concrete request's resource is unknown");
    }

    #[test]
    fn unknown_action() {
        let concrete = Request::new_unchecked(
            EntityUIDEntry::known(r#"A::"p""#.parse().unwrap(), None),
            EntityUIDEntry::unknown(),
            EntityUIDEntry::known(r#"B::"r""#.parse().unwrap(), None),
            Some(Context::Value(Arc::new(ctx()))),
        );
        expect_inconsistency(&concrete, "the concrete request's action is unknown");
    }

    #[test]
    fn unknown_context() {
        let concrete = Request::new_unchecked(
            EntityUIDEntry::known(r#"A::"p""#.parse().unwrap(), None),
            EntityUIDEntry::known(r#"Action::"a""#.parse().unwrap(), None),
            EntityUIDEntry::known(r#"B::"r""#.parse().unwrap(), None),
            None,
        );
        expect_inconsistency(&concrete, "the concrete request's context is unknown");
    }

    #[test]
    fn principal_type() {
        let concrete = concrete_request(r#"B::"p""#, r#"Action::"a""#, r#"B::"r""#, ctx());
        expect_inconsistency(
            &concrete,
            "partial request principal type `A` does not match concrete request principal type `B`",
        );
    }

    #[test]
    fn principal_id() {
        let concrete = concrete_request(r#"A::"other""#, r#"Action::"a""#, r#"B::"r""#, ctx());
        expect_inconsistency(
            &concrete,
            "partial request principal id `p` does not match concrete request principal id `other`",
        );
    }

    #[test]
    fn action_type() {
        let concrete = concrete_request(r#"A::"p""#, r#"Foo::"a""#, r#"B::"r""#, ctx());
        expect_inconsistency(
            &concrete,
            r#"partial request action `Action::"a"` does not match concrete request action `Foo::"a"`"#,
        );
    }

    #[test]
    fn action_id() {
        let concrete = concrete_request(r#"A::"p""#, r#"Action::"b""#, r#"B::"r""#, ctx());
        expect_inconsistency(
            &concrete,
            r#"partial request action `Action::"a"` does not match concrete request action `Action::"b"`"#,
        );
    }

    #[test]
    fn resource_type() {
        let concrete = concrete_request(r#"A::"p""#, r#"Action::"a""#, r#"A::"r""#, ctx());
        expect_inconsistency(
            &concrete,
            "partial request resource type `B` does not match concrete request resource type `A`",
        );
    }

    #[test]
    fn resource_id() {
        let concrete = concrete_request(r#"A::"p""#, r#"Action::"a""#, r#"B::"other""#, ctx());
        expect_inconsistency(
            &concrete,
            "partial request resource id `r` does not match concrete request resource id `other`",
        );
    }

    #[test]
    fn context() {
        let concrete = concrete_request(
            r#"A::"p""#,
            r#"Action::"a""#,
            r#"B::"r""#,
            BTreeMap::from_iter([("foo".into(), 1.into())]),
        );
        expect_inconsistency(
            &concrete,
            "the partial and concrete request contexts do not match",
        );
    }

    #[test]
    fn concrete_context_contains_unknowns() {
        use crate::ast::{Expr, Unknown};
        let residual =
            BTreeMap::from_iter([("foo".into(), Expr::unknown(Unknown::new_untyped("foo")))]);
        let concrete = Request::new_unchecked(
            EntityUIDEntry::known(r#"A::"p""#.parse().unwrap(), None),
            EntityUIDEntry::known(r#"Action::"a""#.parse().unwrap(), None),
            EntityUIDEntry::known(r#"B::"r""#.parse().unwrap(), None),
            Some(Context::RestrictedResidual(Arc::new(residual))),
        );
        expect_inconsistency(
            &concrete,
            "the concrete request's context contains unknowns",
        );
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
            request::{PartialRequest, RequestBuilder},
            test_utils::parse_partial_euid,
        },
        validator::{RequestValidationError, ValidatorSchema},
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
            parse_partial_euid("A"),
            r#"Action::"a""#.parse().unwrap(),
            parse_partial_euid("B"),
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
            builder.add_principal(r#"B::"""#.parse().unwrap()),
            Err(RequestBuilderError::IncorrectPrincipalEntityType(_))
        );
        // add invalid principal
        assert_matches!(
            builder.add_principal(r#"A::"""#.parse().unwrap()),
            Err(RequestBuilderError::Validation(
                RequestValidationError::InvalidEnumEntity(_)
            )),
        );
        // add a principal
        assert_matches!(builder.add_principal(r#"A::"foo""#.parse().unwrap()), Ok(_));
        // then we can't add it again
        assert_matches!(
            builder.add_principal(r#"A::"foo""#.parse().unwrap()),
            Err(RequestBuilderError::ExistingPrincipal(_))
        );
        // and we're not done
        assert_matches!(builder.get_request(), None);
        // add resource
        assert_matches!(builder.add_resource(r#"B::"foo""#.parse().unwrap()), Ok(_));
        // so we can't do it again
        assert_matches!(
            builder.add_resource(r#"B::"foo""#.parse().unwrap()),
            Err(RequestBuilderError::ExistingResource(_))
        );
        // add a context of incorrect type
        assert_matches!(
            builder.add_context(&Context::Value(Arc::new(BTreeMap::from_iter([(
                "".into(),
                1.into()
            )])))),
            Err(RequestBuilderError::Validation(
                RequestValidationError::InvalidContext(_)
            ))
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
