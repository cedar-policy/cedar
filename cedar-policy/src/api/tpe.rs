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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use cedar_policy_core::ast::{self, Value};
use cedar_policy_core::authorizer::Decision;
use cedar_policy_core::batched_evaluator::is_authorized_batched;
use cedar_policy_core::batched_evaluator::{
    err::BatchedEvalError, EntityLoader as EntityLoaderInternal,
};
use cedar_policy_core::evaluator::{EvaluationError, RestrictedEvaluator};
use cedar_policy_core::extensions::Extensions;
use cedar_policy_core::tpe;
use itertools::Itertools;
use ref_cast::RefCast;
use smol_str::SmolStr;

use crate::{
    api, tpe_err, Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PartialEntityError, PartialRequestCreationError, PermissionQueryError, Policy, PolicySet,
    Request, RequestValidationError, RestrictedExpression, Schema, TpeReauthorizationError,
};

/// A partial [`EntityUid`].
/// That is, its [`EntityId`] could be unknown
#[doc = include_str!("../../experimental_warning.md")]
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct PartialEntityUid(pub(crate) tpe::request::PartialEntityUID);

#[doc(hidden)]
impl AsRef<tpe::request::PartialEntityUID> for PartialEntityUid {
    fn as_ref(&self) -> &tpe::request::PartialEntityUID {
        &self.0
    }
}

impl PartialEntityUid {
    /// Construct a [`PartialEntityUid`]
    pub fn new(ty: EntityTypeName, id: Option<EntityId>) -> Self {
        Self(tpe::request::PartialEntityUID {
            ty: ty.0,
            eid: id.map(|id| <EntityId as AsRef<ast::Eid>>::as_ref(&id).clone()),
        })
    }

    /// Construct a [`PartialEntityUid`] from a concrete [`EntityUid`].
    pub fn from_concrete(euid: EntityUid) -> Self {
        let (ty, eid) = euid.0.components();
        Self(tpe::request::PartialEntityUID { ty, eid: Some(eid) })
    }
}

/// A partial [`Request`]
/// Its principal/resource types and action must be known and its context
/// must either be fully known or unknown
#[doc = include_str!("../../experimental_warning.md")]
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct PartialRequest(pub(crate) tpe::request::PartialRequest);

#[doc(hidden)]
impl AsRef<tpe::request::PartialRequest> for PartialRequest {
    fn as_ref(&self) -> &tpe::request::PartialRequest {
        &self.0
    }
}

impl PartialRequest {
    /// Construct a valid [`PartialRequest`] according to a [`Schema`]
    pub fn new(
        principal: PartialEntityUid,
        action: EntityUid,
        resource: PartialEntityUid,
        context: Option<Context>,
        schema: &Schema,
    ) -> Result<Self, PartialRequestCreationError> {
        let context = context
            .map(|c| match c.0 {
                ast::Context::RestrictedResidual(_) => {
                    Err(PartialRequestCreationError::ContextContainsUnknowns)
                }
                ast::Context::Value(m) => Ok(m),
            })
            .transpose()?;
        tpe::request::PartialRequest::new(principal.0, action.0, resource.0, context, &schema.0)
            .map(Self)
            .map_err(|e| PartialRequestCreationError::Validation(e.into()))
    }
}

/// Like [`PartialRequest`] but only `resource` can be unknown
#[doc = include_str!("../../experimental_warning.md")]
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct ResourceQueryRequest(pub(crate) PartialRequest);

impl ResourceQueryRequest {
    /// Construct a valid [`ResourceQueryRequest`] according to a [`Schema`]
    pub fn new(
        principal: EntityUid,
        action: EntityUid,
        resource: EntityTypeName,
        context: Context,
        schema: &Schema,
    ) -> Result<Self, PartialRequestCreationError> {
        PartialRequest::new(
            PartialEntityUid(principal.0.into()),
            action,
            PartialEntityUid::new(resource, None),
            Some(context),
            schema,
        )
        .map(Self)
    }

    /// Convert [`ResourceQueryRequest`] to a [`Request`] by providing the resource [`EntityId`]
    pub fn to_request(
        &self,
        resource_id: EntityId,
        schema: Option<&Schema>,
    ) -> Result<Request, RequestValidationError> {
        #[expect(
            clippy::unwrap_used,
            reason = "various fields are validated through the constructor"
        )]
        Request::new(
            EntityUid(self.0 .0.get_principal().try_into().unwrap()),
            EntityUid(self.0 .0.get_action()),
            EntityUid::from_type_name_and_id(
                EntityTypeName(self.0 .0.get_resource_type()),
                resource_id,
            ),
            Context::from_pairs(
                self.0
                     .0
                    .get_context_attrs()
                    .unwrap()
                    .iter()
                    .map(|(a, v)| (a.to_string(), RestrictedExpression(v.clone().into()))),
            )
            .unwrap(),
            schema,
        )
    }
}

/// Like [`PartialRequest`] but only `principal` can be unknown
#[doc = include_str!("../../experimental_warning.md")]
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct PrincipalQueryRequest(pub(crate) PartialRequest);

impl PrincipalQueryRequest {
    /// Construct a valid [`PrincipalQueryRequest`] according to a [`Schema`]
    pub fn new(
        principal: EntityTypeName,
        action: EntityUid,
        resource: EntityUid,
        context: Context,
        schema: &Schema,
    ) -> Result<Self, PartialRequestCreationError> {
        PartialRequest::new(
            PartialEntityUid::new(principal, None),
            action,
            PartialEntityUid(resource.0.into()),
            Some(context),
            schema,
        )
        .map(Self)
    }

    /// Convert [`PrincipalQueryRequest`] to a [`Request`] by providing the principal [`EntityId`]
    pub fn to_request(
        &self,
        principal_id: EntityId,
        schema: Option<&Schema>,
    ) -> Result<Request, RequestValidationError> {
        #[expect(
            clippy::unwrap_used,
            reason = "various fields are validated through the constructor"
        )]
        Request::new(
            EntityUid::from_type_name_and_id(
                EntityTypeName(self.0 .0.get_principal_type()),
                principal_id,
            ),
            EntityUid(self.0 .0.get_action()),
            EntityUid(self.0 .0.get_resource().try_into().unwrap()),
            Context::from_pairs(
                self.0
                     .0
                    .get_context_attrs()
                    .unwrap()
                    .iter()
                    .map(|(a, v)| (a.to_string(), RestrictedExpression(v.clone().into()))),
            )
            .unwrap(),
            schema,
        )
    }
}

/// Defines a [`PartialRequest`] which additionally leaves the action
/// undefined, enabling queries listing what actions might be authorized.
///
/// See [`PolicySet::query_action`] for documentation and example usage.
#[doc = include_str!("../../experimental_warning.md")]
#[derive(Debug, Clone)]
pub struct ActionQueryRequest {
    principal: PartialEntityUid,
    resource: PartialEntityUid,
    context: Option<Arc<BTreeMap<SmolStr, Value>>>,
    schema: Schema,
}

impl ActionQueryRequest {
    /// Construct a valid [`ActionQueryRequest`] according to a [`Schema`]
    pub fn new(
        principal: PartialEntityUid,
        resource: PartialEntityUid,
        context: Option<Context>,
        schema: Schema,
    ) -> Result<Self, PartialRequestCreationError> {
        let context = context
            .map(|c| match c.0 {
                ast::Context::RestrictedResidual(_) => {
                    Err(PartialRequestCreationError::ContextContainsUnknowns)
                }
                ast::Context::Value(m) => Ok(m),
            })
            .transpose()?;
        Ok(Self {
            principal,
            resource,
            context,
            schema,
        })
    }

    fn partial_request(
        &self,
        action: EntityUid,
    ) -> Result<PartialRequest, cedar_policy_core::validator::RequestValidationError> {
        tpe::request::PartialRequest::new(
            self.principal.0.clone(),
            action.0,
            self.resource.0.clone(),
            self.context.clone(),
            &self.schema.0,
        )
        .map(PartialRequest)
    }
}

/// Partial [`Entity`]
#[doc = include_str!("../../experimental_warning.md")]
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct PartialEntity(pub(crate) tpe::entities::PartialEntity);

impl PartialEntity {
    /// Construct a [`PartialEntity`]
    pub fn new(
        uid: EntityUid,
        attrs: Option<BTreeMap<SmolStr, RestrictedExpression>>,
        ancestors: Option<HashSet<EntityUid>>,
        tags: Option<BTreeMap<SmolStr, RestrictedExpression>>,
        schema: &Schema,
    ) -> Result<Self, PartialEntityError> {
        Ok(Self(tpe::entities::PartialEntity::new(
            uid.0,
            attrs
                .map(|ps| {
                    ps.into_iter()
                        .map(|(k, v)| {
                            Ok((
                                k,
                                RestrictedEvaluator::new(Extensions::all_available())
                                    .interpret(v.0.as_borrowed())?,
                            ))
                        })
                        .collect::<Result<BTreeMap<_, _>, EvaluationError>>()
                })
                .transpose()?,
            ancestors.map(|s| s.into_iter().map(|e| e.0).collect()),
            tags.map(|ps| {
                ps.into_iter()
                    .map(|(k, v)| {
                        Ok((
                            k,
                            RestrictedEvaluator::new(Extensions::all_available())
                                .interpret(v.0.as_borrowed())?,
                        ))
                    })
                    .collect::<Result<BTreeMap<_, _>, EvaluationError>>()
            })
            .transpose()?,
            &schema.0,
        )?))
    }
}

/// Partial [`Entities`]
#[doc = include_str!("../../experimental_warning.md")]
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct PartialEntities(pub(crate) tpe::entities::PartialEntities);

#[doc(hidden)]
impl AsRef<tpe::entities::PartialEntities> for PartialEntities {
    fn as_ref(&self) -> &tpe::entities::PartialEntities {
        &self.0
    }
}

impl PartialEntities {
    /// Construct [`PartialEntities`] from a JSON value
    /// The `parent`, `attrs`, `tags` field must be either fully known or
    /// unknown. And parent entities cannot have unknown parents.
    pub fn from_json_value(
        value: serde_json::Value,
        schema: &Schema,
    ) -> Result<Self, tpe_err::EntitiesError> {
        tpe::entities::PartialEntities::from_json_value(value, &schema.0).map(Self)
    }

    /// Construct [`PartialEntities`] given a fully concrete [`Entities`]
    pub fn from_concrete(
        entities: Entities,
        schema: &Schema,
    ) -> Result<Self, tpe_err::EntitiesError> {
        tpe::entities::PartialEntities::from_concrete(entities.0, &schema.0).map(Self)
    }

    /// Create a `PartialEntities` with no entities
    pub fn empty() -> Self {
        Self(tpe::entities::PartialEntities::new())
    }

    /// Construct [`PartialEntities`] from an iterator of [`PartialEntity`]
    pub fn from_partial_entities(
        entities: impl IntoIterator<Item = PartialEntity>,
        schema: &Schema,
    ) -> Result<Self, tpe_err::EntitiesError> {
        Ok(Self(tpe::entities::PartialEntities::from_entities(
            entities.into_iter().map(|entity| entity.0),
            &schema.0,
        )?))
    }
}

/// A partial version of [`crate::Response`].
#[doc = include_str!("../../experimental_warning.md")]
#[repr(transparent)]
#[derive(Debug, Clone, RefCast)]
pub struct TpeResponse<'a>(pub(crate) tpe::response::Response<'a>);

#[doc(hidden)]
impl<'a> AsRef<tpe::response::Response<'a>> for TpeResponse<'a> {
    fn as_ref(&self) -> &tpe::response::Response<'a> {
        &self.0
    }
}

impl TpeResponse<'_> {
    /// Attempt to get the authorization decision
    pub fn decision(&self) -> Option<Decision> {
        self.0.decision()
    }

    /// Perform reauthorization
    pub fn reauthorize(
        &self,
        request: &Request,
        entities: &Entities,
    ) -> Result<api::Response, TpeReauthorizationError> {
        self.0
            .reauthorize(&request.0, &entities.0)
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Return residuals as [`Policy`]s.
    ///
    /// Each returned [`Policy`] inherits its [`PolicyId`](crate::PolicyId) and
    /// annotations from the corresponding input policy. Its scope is
    /// unconstrained and its condition is a single `when` clause containing
    /// the residual expression.
    ///
    /// Use [`TpeResponse::nontrivial_residual_policies`] to skip trivially
    /// `true` or `false` residuals.
    ///
    /// The returned policies can be converted to PST for structured
    /// inspection of the residual expression tree:
    ///
    /// ```text
    /// let response = policy_set.tpe(&request, &entities, &schema)?;
    /// for policy in response.residual_policies() {
    ///     let pst_policy = policy.to_pst()?;
    ///     for clause in pst_policy.body().clauses() {
    ///         // inspect the residual expression via pst::Clause / pst::Expr
    ///     }
    /// }
    /// ```
    pub fn residual_policies(&self) -> impl Iterator<Item = Policy> + '_ {
        self.0
            .residual_policies()
            .map(|p| Policy::from_ast(p.clone().into()))
    }

    /// Returns an iterator of non-trivial (meaning more than just `true`
    /// or `false`) residuals as [`Policy`]s.
    ///
    /// Each returned [`Policy`] inherits its [`PolicyId`](crate::PolicyId) and
    /// annotations from the corresponding input policy. Its scope is
    /// unconstrained and its condition is a single `when` clause containing
    /// the residual expression.
    ///
    /// Call [`Policy::to_pst()`] on each result to get a [`crate::pst::Policy`]
    /// for structured inspection. Residual expressions may contain
    /// [`crate::pst::Expr::ResidualError`] nodes indicating subexpressions that
    /// would error at runtime; use [`crate::pst::Expr::has_error()`] to check.
    pub fn nontrivial_residual_policies(&'_ self) -> impl Iterator<Item = Policy> + '_ {
        self.0
            .residual_permits()
            .chain(self.0.residual_forbids())
            .map(|p| Policy::from_ast(p.clone().into()))
    }
}

/// Entity loader trait for batched evaluation.
///
/// Loads entities on demand, returning `None` for missing entities.
/// The `load_entities` function must load all requested entities,
/// and must compute and include all ancestors of the requested entities.
/// Loading more entities than requested is allowed.
#[doc = include_str!("../../experimental_warning.md")]
pub trait EntityLoader {
    /// Load all entities for the given set of entity UIDs.
    /// Returns a map from [`EntityUid`] to [`Option<Entity>`], where `None` indicates
    /// the entity does not exist.
    fn load_entities(&mut self, uids: &HashSet<EntityUid>) -> HashMap<EntityUid, Option<Entity>>;
}

/// Wrapper struct used to convert an [`EntityLoader`] to an `EntityLoaderInternal`
struct EntityLoaderWrapper<'a>(&'a mut dyn EntityLoader);

impl EntityLoaderInternal for EntityLoaderWrapper<'_> {
    fn load_entities(
        &mut self,
        uids: &HashSet<ast::EntityUID>,
    ) -> HashMap<ast::EntityUID, Option<ast::Entity>> {
        let ids = uids
            .iter()
            .map(|id| EntityUid::ref_cast(id).clone())
            .collect();
        self.0
            .load_entities(&ids)
            .into_iter()
            .map(|(uid, entity)| (uid.0, entity.map(|e| e.0)))
            .collect()
    }
}

/// Simple entity loader implementation that loads from a pre-existing Entities store
#[doc = include_str!("../../experimental_warning.md")]
#[derive(Debug)]

pub struct TestEntityLoader<'a> {
    entities: &'a Entities,
}

impl<'a> TestEntityLoader<'a> {
    /// Create a new [`TestEntityLoader`] from an existing Entities store
    pub fn new(entities: &'a Entities) -> Self {
        Self { entities }
    }
}

impl EntityLoader for TestEntityLoader<'_> {
    fn load_entities(&mut self, uids: &HashSet<EntityUid>) -> HashMap<EntityUid, Option<Entity>> {
        uids.iter()
            .map(|uid| {
                let entity = self.entities.get(uid).cloned();
                (uid.clone(), entity)
            })
            .collect()
    }
}

impl PolicySet {
    /// Perform type-aware partial evaluation on this [`PolicySet`].
    ///
    /// If successful, the result is a [`TpeResponse`] containing residual
    /// policies ready for re-authorization. Use
    /// [`TpeResponse::residual_policies()`] or
    /// [`TpeResponse::nontrivial_residual_policies()`] to get the residuals
    /// as [`Policy`] objects, then call [`Policy::to_pst()`] to convert them
    /// to [`crate::pst::Policy`] for structured inspection of the residual
    /// expression tree.
    #[doc = include_str!("../../experimental_warning.md")]
    pub fn tpe<'a>(
        &self,
        request: &'a PartialRequest,
        entities: &'a PartialEntities,
        schema: &'a Schema,
    ) -> Result<TpeResponse<'a>, tpe_err::TpeError> {
        use cedar_policy_core::tpe::is_authorized;
        let ps = &self.ast;
        let res = is_authorized(ps, &request.0, &entities.0, &schema.0)?;
        Ok(TpeResponse(res))
    }

    /// Like [`Authorizer::is_authorized`] but uses an [`EntityLoader`] to load
    /// entities on demand.
    ///
    /// Calls `loader` at most `max_iters` times, returning
    /// early if an authorization result is reached.
    /// Otherwise, it iterates `max_iters` times and returns
    /// a partial result.
    ///
    #[doc = include_str!("../../experimental_warning.md")]
    pub fn is_authorized_batched(
        &self,
        query: &Request,
        schema: &Schema,
        loader: &mut dyn EntityLoader,
        max_iters: u32,
    ) -> Result<Decision, BatchedEvalError> {
        is_authorized_batched(
            &query.0,
            &self.ast,
            &schema.0,
            &mut EntityLoaderWrapper(loader),
            max_iters,
        )
    }

    /// Perform a permission query on the resource
    #[doc = include_str!("../../experimental_warning.md")]
    pub fn query_resource(
        &self,
        request: &ResourceQueryRequest,
        entities: &Entities,
        schema: &Schema,
    ) -> Result<impl Iterator<Item = EntityUid>, PermissionQueryError> {
        let partial_entities = PartialEntities::from_concrete(entities.clone(), schema)?;
        let residuals = self.tpe(&request.0, &partial_entities, schema)?;
        #[expect(
            clippy::unwrap_used,
            reason = "policy set construction should succeed because there shouldn't be any policy id conflicts"
        )]
        let policies = &Self::from_policies(
            residuals
                .0
                .residual_policies()
                .map(|p| Policy::from_ast(p.clone().into())),
        )
        .unwrap();
        #[expect(
            clippy::unwrap_used,
            reason = "request construction should succeed because each entity passes validation"
        )]
        match residuals.decision() {
            Some(Decision::Allow) => Ok(entities
                .iter()
                .filter(|entity| entity.0.uid().entity_type() == &request.0 .0.get_resource_type())
                .map(super::Entity::uid)
                .collect_vec()
                .into_iter()),
            Some(Decision::Deny) => Ok(vec![].into_iter()),
            None => Ok(entities
                .iter()
                .filter(|entity| entity.0.uid().entity_type() == &request.0 .0.get_resource_type())
                .filter(|entity| {
                    let authorizer = Authorizer::new();
                    authorizer
                        .is_authorized(
                            &request.to_request(entity.uid().id().clone(), None).unwrap(),
                            policies,
                            entities,
                        )
                        .decision
                        == Decision::Allow
                })
                .map(super::Entity::uid)
                .collect_vec()
                .into_iter()),
        }
    }

    /// Perform a permission query on the principal
    #[doc = include_str!("../../experimental_warning.md")]
    pub fn query_principal(
        &self,
        request: &PrincipalQueryRequest,
        entities: &Entities,
        schema: &Schema,
    ) -> Result<impl Iterator<Item = EntityUid>, PermissionQueryError> {
        let partial_entities = PartialEntities::from_concrete(entities.clone(), schema)?;
        let residuals = self.tpe(&request.0, &partial_entities, schema)?;
        #[expect(
            clippy::unwrap_used,
            reason = "policy set construction should succeed because there shouldn't be any policy id conflicts"
        )]
        let policies = &Self::from_policies(
            residuals
                .0
                .residual_policies()
                .map(|p| Policy::from_ast(p.clone().into())),
        )
        .unwrap();
        #[expect(
            clippy::unwrap_used,
            reason = "request construction should succeed because each entity passes validation"
        )]
        match residuals.decision() {
            Some(Decision::Allow) => Ok(entities
                .iter()
                .filter(|entity| entity.0.uid().entity_type() == &request.0 .0.get_principal_type())
                .map(super::Entity::uid)
                .collect_vec()
                .into_iter()),
            Some(Decision::Deny) => Ok(vec![].into_iter()),
            None => Ok(entities
                .iter()
                .filter(|entity| entity.0.uid().entity_type() == &request.0 .0.get_principal_type())
                .filter(|entity| {
                    let authorizer = Authorizer::new();
                    authorizer
                        .is_authorized(
                            &request.to_request(entity.uid().id().clone(), None).unwrap(),
                            policies,
                            entities,
                        )
                        .decision
                        == Decision::Allow
                })
                .map(super::Entity::uid)
                .collect_vec()
                .into_iter()),
        }
    }

    /// Given a [`ActionQueryRequest`] (a partial request without a concrete
    /// action) enumerate actions in the schema which might be authorized
    /// for that request.
    ///
    /// Each action is returned with a partial authorization decision.  If
    /// the action is definitely authorized, then it is `Some(Decision::Allow)`.
    /// If we did not reach a concrete authorization decision, then it is
    /// `None`. Actions which are definitely not authorized (i.e., the
    /// decision is `Some(Decision::Deny)`) are not returned by this
    /// function. It is also possible that some actions without a concrete
    /// authorization decision are never authorized if the residual
    /// expressions after partial evaluation are not satisfiable.
    ///
    /// If the partial request for a particular action is invalid (e.g., the
    /// action does not apply to the type of principal and resource), then
    /// that action is not included in the result regardless of whether a
    /// request with that action would be authorized.
    ///
    /// ```
    /// # use cedar_policy::{PolicySet, Schema, ActionQueryRequest, PartialEntities, PartialEntityUid, Decision, EntityUid, Entities};
    /// # use std::str::FromStr;
    /// # let policies = PolicySet::from_str(r#"
    /// #     permit(principal, action == Action::"edit", resource) when { context.should_allow };
    /// #     permit(principal, action == Action::"view", resource);
    /// # "#).unwrap();
    /// # let schema = Schema::from_str("
    /// #     entity User, Photo;
    /// #     action view, edit appliesTo {
    /// #       principal: User,
    /// #       resource: Photo,
    /// #       context: { should_allow: Bool, }
    /// #     };
    /// # ").unwrap();
    /// # let entities = PartialEntities::empty();
    ///
    /// // Construct a request for a concrete principal and resource, but leaving the context unknown so
    /// // that we can see all actions that might be authorized for some context.
    /// let request = ActionQueryRequest::new(
    ///     PartialEntityUid::from_concrete(r#"User::"alice""#.parse().unwrap()),
    ///     PartialEntityUid::from_concrete(r#"Photo::"vacation.jpg""#.parse().unwrap()),
    ///     None,
    ///     schema,
    /// ).unwrap();
    ///
    /// // All actions which might be allowed for this principal and resource.
    /// // The exact authorization result may depend on currently unknown
    /// // context and entity data.
    /// let possibly_allowed_actions: Vec<&EntityUid> =
    ///     policies.query_action(&request, &entities)
    ///             .unwrap()
    ///             .map(|(a, _)| a)
    ///             .collect();
    /// # let mut possibly_allowed_actions = possibly_allowed_actions;
    /// # possibly_allowed_actions.sort();
    /// # assert_eq!(&possibly_allowed_actions, &[&r#"Action::"edit""#.parse().unwrap(), &r#"Action::"view""#.parse().unwrap()]);
    ///
    /// // These actions are definitely allowed for this principal and resource.
    /// // These will be allowed for _any_ context.
    /// let allowed_actions: Vec<&EntityUid> =
    ///     policies.query_action(&request, &entities).unwrap()
    ///             .filter(|(_, resp)| resp == &Some(Decision::Allow))
    ///             .map(|(a, _)| a)
    ///             .collect();
    /// # assert_eq!(&allowed_actions, &[&r#"Action::"view""#.parse().unwrap()]);
    /// ```
    #[doc = include_str!("../../experimental_warning.md")]
    pub fn query_action<'a>(
        &self,
        request: &'a ActionQueryRequest,
        entities: &PartialEntities,
    ) -> Result<impl Iterator<Item = (&'a EntityUid, Option<Decision>)>, PermissionQueryError> {
        let mut authorized_actions = Vec::new();
        // We only consider actions that apply to the type of the requested
        // principal and resource. Any requests for different actions would
        // be invalid, so they should never be authorized. Not however that
        // an authorization request for _could_ return `Allow` if the caller
        // ignores the request validation error.
        for action in request
            .schema
            .0
            .actions_for_principal_and_resource(&request.principal.0.ty, &request.resource.0.ty)
        {
            // If we fail to construct a partial request, then the partial context is not valid for
            // the context type declared for this action. This action should never be authorized,
            // but with the same caveats about invalid requests.
            if let Ok(partial_request) = request.partial_request(action.clone().into()) {
                let decision = self
                    .tpe(&partial_request, entities, &request.schema)?
                    .decision();
                if decision != Some(Decision::Deny) {
                    authorized_actions.push((RefCast::ref_cast(action), decision));
                }
            }
        }
        Ok(authorized_actions.into_iter())
    }
}

#[cfg(test)]
mod tpe_test {
    mod test {
        use std::{
            collections::{BTreeMap, HashSet},
            str::FromStr,
        };

        use cedar_policy_core::tpe::err::EntitiesError;
        use cool_asserts::assert_matches;

        use crate::{PartialEntity, PartialEntityError, RestrictedExpression, Schema};

        #[test]
        fn entity_construction() {
            let schema = Schema::from_str(
                r"
            entity A in B tags Long;
            entity B;
        ",
            )
            .unwrap();
            PartialEntity::new(
                r#"A::"foo""#.parse().unwrap(),
                None,
                Some(HashSet::from_iter([r#"B::"b""#.parse().unwrap()])),
                Some(BTreeMap::from_iter([(
                    "".into(),
                    RestrictedExpression::new_long(1),
                )])),
                &schema,
            )
            .unwrap();
            assert_matches!(
                PartialEntity::new(
                    r#"A::"foo""#.parse().unwrap(),
                    None,
                    Some(HashSet::from_iter([r#"C::"c""#.parse().unwrap()])),
                    Some(BTreeMap::from_iter([(
                        "".into(),
                        RestrictedExpression::new_long(1)
                    )])),
                    &schema
                ),
                Err(PartialEntityError::Entities(EntitiesError::Validation(_)))
            );

            assert_matches!(
                PartialEntity::new(
                    r#"A::"foo""#.parse().unwrap(),
                    None,
                    Some(HashSet::from_iter([r#"B::"b""#.parse().unwrap()])),
                    Some(BTreeMap::from_iter([(
                        "".into(),
                        RestrictedExpression::new_bool(true)
                    )])),
                    &schema
                ),
                Err(PartialEntityError::Entities(EntitiesError::Validation(_)))
            );
        }
    }

    mod streaming_service {
        use std::{collections::BTreeMap, str::FromStr};

        use cedar_policy_core::{authorizer::Decision, tpe::err::EntitiesError};
        use cool_asserts::assert_matches;
        use itertools::Itertools;
        use similar_asserts::assert_eq;

        use crate::{
            ActionConstraint, ActionQueryRequest, Context, Entities, EntityId, EntityUid,
            PartialEntities, PartialEntity, PartialEntityError, PartialEntityUid, PartialRequest,
            PolicySet, PrincipalConstraint, PrincipalQueryRequest, Request, ResourceConstraint,
            ResourceQueryRequest, RestrictedExpression, Schema,
        };

        #[test]
        fn entities_construction() {
            let schema = schema();
            PartialEntity::new(
                r#"Movie::"foo""#.parse().unwrap(),
                None,
                None,
                None,
                &schema,
            )
            .unwrap();
            PartialEntity::new(
                r#"Show::"foo""#.parse().unwrap(),
                Some(BTreeMap::from_iter([
                    ("isFree".into(), RestrictedExpression::new_bool(true)),
                    (
                        "releaseDate".into(),
                        RestrictedExpression::new_datetime("2025-01-01"),
                    ),
                    (
                        "isEarlyAccess".into(),
                        RestrictedExpression::new_bool(false),
                    ),
                ])),
                None,
                None,
                &schema,
            )
            .unwrap();

            assert_matches!(
                PartialEntity::new(
                    r#"Show::"foo""#.parse().unwrap(),
                    Some(BTreeMap::from_iter([
                        ("isFree".into(), RestrictedExpression::new_bool(true)),
                        (
                            "isEarlyAccess".into(),
                            RestrictedExpression::new_bool(false)
                        ),
                    ])),
                    None,
                    None,
                    &schema
                ),
                Err(PartialEntityError::Entities(EntitiesError::Validation(_)))
            );

            let e1 = PartialEntity::new(
                r#"Show::"foo""#.parse().unwrap(),
                Some(BTreeMap::from_iter([
                    ("isFree".into(), RestrictedExpression::new_bool(true)),
                    (
                        "releaseDate".into(),
                        RestrictedExpression::new_datetime("2025-01-01"),
                    ),
                    (
                        "isEarlyAccess".into(),
                        RestrictedExpression::new_bool(false),
                    ),
                ])),
                None,
                None,
                &schema,
            )
            .unwrap();
            let e2 = PartialEntity::new(
                r#"Subscriber::"a""#.parse().unwrap(),
                None,
                None,
                None,
                &schema,
            )
            .unwrap();
            PartialEntities::from_partial_entities([e1.clone(), e2.clone()], &schema).unwrap();
            let e3 = PartialEntity::new(
                r#"Show::"foo""#.parse().unwrap(),
                Some(BTreeMap::from_iter([
                    ("isFree".into(), RestrictedExpression::new_bool(true)),
                    (
                        "releaseDate".into(),
                        RestrictedExpression::new_datetime("2025-01-01"),
                    ),
                    ("isEarlyAccess".into(), RestrictedExpression::new_bool(true)),
                ])),
                None,
                None,
                &schema,
            )
            .unwrap();
            assert_matches!(
                PartialEntities::from_partial_entities([e1, e2, e3], &schema),
                Err(EntitiesError::Duplicate(_)),
            );
        }

        #[track_caller]
        fn schema() -> Schema {
            Schema::from_cedarschema_str(
                r"
            type Subscription = { tier: String };
            type Profile = { isKid: Bool };

            entity FreeMember;
            entity Subscriber = { subscription: Subscription, profile: Profile };
            entity Movie = { isFree: Bool, needsRentOrBuy: Bool, isOscarNominated: Bool };
            entity Show = { isFree: Bool, releaseDate: datetime, isEarlyAccess: Bool };

            action watch appliesTo {
                principal: [FreeMember, Subscriber],
                resource: [Movie, Show],
                context: { now: { datetime: datetime, localTimeOffset: duration } }
            };
            action rent, buy appliesTo {
                principal: [FreeMember, Subscriber],
                resource: Movie,
                context: { now: { datetime: datetime } }
            };
            ",
            )
            .unwrap()
            .0
        }

        #[track_caller]
        fn policy_set() -> PolicySet {
            PolicySet::from_str(
            r#"
            @id("subscriber-content-access/show")
            permit(principal is Subscriber, action == Action::"watch", resource is Show)
            unless { resource.isEarlyAccess && context.now.datetime < resource.releaseDate };

            @id("subscriber-content-access/movie")
            permit(principal is Subscriber, action == Action::"watch", resource is Movie)
            unless { resource.needsRentOrBuy };

            @id("free-content-access")
            permit(principal is FreeMember, action == Action::"watch", resource)
            when { resource.isFree };

            @id("rent-buy-oscar-movie")
            permit(principal is Subscriber, action in [Action::"rent", Action::"buy"], resource is Movie)
            when {
                resource.isOscarNominated &&
                context.now.datetime >= datetime("2025-02-02T19:00:00-0500") &&
                context.now.datetime < datetime("2025-03-02T19:00:00-0500")
            };

            @id("early-access-show")
            permit(principal is Subscriber, action == Action::"watch", resource is Show)
            when {
                resource.isEarlyAccess &&
                principal.subscription.tier == "premium" &&
                context.now.datetime >= resource.releaseDate.offset(duration("-24h"))
            };

            @id("forbid-bedtime-watch-kid-profile")
            forbid(principal is Subscriber, action == Action::"watch", resource)
            when { principal.profile.isKid }
            unless {
                duration("6h") <= context.now.datetime.offset(context.now.localTimeOffset).toTime() &&
                context.now.datetime.offset(context.now.localTimeOffset).toTime() <= duration("21h")
            };
            "#,
        )
        .unwrap()
        }

        #[track_caller]
        fn entities() -> Entities {
            Entities::from_json_value(
            serde_json::json!([
                {
                    "uid": { "type": "Subscriber", "id": "Alice" },
                    "attrs": { "subscription": { "tier": "standard" }, "profile": { "isKid": false } },
                    "parents": []
                },
                {
                    "uid": { "type": "FreeMember", "id": "Bob" },
                    "attrs": {},
                    "parents": []
                },
                {
                    "uid": { "type": "Subscriber", "id": "Charlie" },
                    "attrs": { "subscription": { "tier": "premium" }, "profile": { "isKid": false } },
                    "parents": []
                },
                {
                    "uid": { "type": "Subscriber", "id": "Dave" },
                    "attrs": { "subscription": { "tier": "standard" }, "profile": { "isKid": true } },
                    "parents": []
                },
                {
                    "uid": { "type": "Movie", "id": "The Godparent" },
                    "attrs": { "isFree": true, "needsRentOrBuy": false, "isOscarNominated": true },
                    "parents": []
                },
                {
                    "uid": { "type": "Movie", "id": "The Gleaming" },
                    "attrs": { "isFree": false, "needsRentOrBuy": false, "isOscarNominated": false },
                    "parents": []
                },
                {
                    "uid": { "type": "Movie", "id": "Devilish" },
                    "attrs": { "isFree": false, "needsRentOrBuy": true, "isOscarNominated": true },
                    "parents": []
                },
                {
                    "uid": { "type": "Show", "id": "Buddies" },
                    "attrs": { "isFree": false, "releaseDate": "2024-10-10", "isEarlyAccess": false },
                    "parents": []
                },
                {
                    "uid": { "type": "Show", "id": "Breach" },
                    "attrs": { "isFree": false, "releaseDate": "2025-02-21", "isEarlyAccess": true },
                    "parents": []
                },
            ]),
            Some(&schema()),
        )
        .unwrap()
        }

        /// Build a watch context with datetime="2025-07-22" and localTimeOffset="0h"
        #[track_caller]
        fn watch_context() -> Context {
            Context::from_pairs([(
                "now".into(),
                RestrictedExpression::new_record([
                    (
                        "datetime".into(),
                        RestrictedExpression::from_str(r#"datetime("2025-07-22")"#).unwrap(),
                    ),
                    (
                        "localTimeOffset".into(),
                        RestrictedExpression::from_str(r#"duration("0h")"#).unwrap(),
                    ),
                ])
                .unwrap(),
            )])
            .unwrap()
        }

        #[test]
        fn run_tpe() {
            let schema = schema();
            let request = PartialRequest::new(
                PartialEntityUid::from_concrete(r#"Subscriber::"Alice""#.parse().unwrap()),
                r#"Action::"watch""#.parse().unwrap(),
                PartialEntityUid::new("Movie".parse().unwrap(), None),
                Some(watch_context()),
                &schema,
            )
            .unwrap();
            let policies = policy_set();
            let partial_entities = PartialEntities::from_concrete(entities(), &schema).unwrap();

            let response = policies
                .tpe(&request, &partial_entities, &schema)
                .expect("tpe should succeed");

            assert_eq!(
                response.residual_policies().count(),
                policies.num_of_policies()
            );
            for p in response.residual_policies() {
                assert_matches!(p.action_constraint(), ActionConstraint::Any);
                assert_matches!(p.principal_constraint(), PrincipalConstraint::Any);
                assert_matches!(p.resource_constraint(), ResourceConstraint::Any);
            }
            assert_eq!(
                response
                    .nontrivial_residual_policies()
                    .next()
                    .unwrap()
                    .annotation("id")
                    .unwrap(),
                "subscriber-content-access/movie"
            );
            assert_eq!(response.decision(), None);

            let request = Request::new(
                EntityUid::from_type_name_and_id(
                    "Subscriber".parse().unwrap(),
                    EntityId::new("Alice"),
                ),
                r#"Action::"watch""#.parse().unwrap(),
                EntityUid::from_type_name_and_id(
                    "Movie".parse().unwrap(),
                    EntityId::new("The Godparent"),
                ),
                watch_context(),
                Some(&schema),
            )
            .unwrap();
            assert_matches!(response.reauthorize(&request, &entities()), Ok(res) => {
                assert_eq!(res.decision(), Decision::Allow);
            });

            let request = Request::new(
                EntityUid::from_type_name_and_id(
                    "Subscriber".parse().unwrap(),
                    EntityId::new("Alice"),
                ),
                r#"Action::"watch""#.parse().unwrap(),
                EntityUid::from_type_name_and_id(
                    "Movie".parse().unwrap(),
                    EntityId::new("Devilish"),
                ),
                watch_context(),
                Some(&schema),
            )
            .unwrap();
            assert_matches!(response.reauthorize(&request, &entities()), Ok(res) => {
                assert_eq!(res.decision(), Decision::Deny);
            });
        }

        #[test]
        fn query_resource() {
            let schema = schema();
            let policies = policy_set();
            let request = ResourceQueryRequest::new(
                r#"Subscriber::"Alice""#.parse().unwrap(),
                r#"Action::"watch""#.parse().unwrap(),
                "Movie".parse().unwrap(),
                watch_context(),
                &schema,
            )
            .unwrap();

            // The two movies do not need rent or buy and hence satisfy the
            // residual policy
            let movies = policies
                .query_resource(&request, &entities(), &schema)
                .unwrap()
                .sorted()
                .collect_vec();
            assert_eq!(
                movies,
                &[
                    EntityUid::from_str(r#"Movie::"The Gleaming""#).unwrap(),
                    EntityUid::from_str(r#"Movie::"The Godparent""#).unwrap(),
                ]
            );
        }

        #[test]
        fn query_principal() {
            let schema = schema();
            let policies = policy_set();
            let request = PrincipalQueryRequest::new(
                "Subscriber".parse().unwrap(),
                r#"Action::"watch""#.parse().unwrap(),
                r#"Movie::"The Godparent""#.parse().unwrap(),
                watch_context(),
                &schema,
            )
            .unwrap();

            let subscribers = policies
                .query_principal(&request, &entities(), &schema)
                .unwrap()
                .sorted()
                .collect_vec();
            assert_eq!(
                subscribers,
                &[
                    EntityUid::from_str(r#"Subscriber::"Alice""#).unwrap(),
                    EntityUid::from_str(r#"Subscriber::"Charlie""#).unwrap(),
                ]
            );
        }

        #[test]
        fn query_action_alice() {
            let schema = schema();
            let request = ActionQueryRequest::new(
                PartialEntityUid::from_concrete(r#"Subscriber::"Alice""#.parse().unwrap()),
                PartialEntityUid::from_concrete(r#"Movie::"The Godparent""#.parse().unwrap()),
                None,
                schema.clone(),
            )
            .unwrap();

            let policies = policy_set();
            let mut actions: Vec<_> = policies
                .query_action(
                    &request,
                    &PartialEntities::from_concrete(entities(), &schema).unwrap(),
                )
                .unwrap()
                .collect();
            actions.sort_by_key(|(a, _)| *a);
            assert_eq!(
                actions,
                vec![
                    (&r#"Action::"buy""#.parse().unwrap(), None),
                    (&r#"Action::"rent""#.parse().unwrap(), None),
                    (
                        &r#"Action::"watch""#.parse().unwrap(),
                        Some(Decision::Allow)
                    ),
                ]
            );
        }

        #[test]
        fn query_action_bob_free() {
            let schema = schema();
            let request = ActionQueryRequest::new(
                PartialEntityUid::from_concrete(r#"FreeMember::"Bob""#.parse().unwrap()),
                PartialEntityUid::from_concrete(r#"Movie::"The Godparent""#.parse().unwrap()),
                None,
                schema.clone(),
            )
            .unwrap();

            let policies = policy_set();
            let actions: Vec<_> = policies
                .query_action(
                    &request,
                    &PartialEntities::from_concrete(entities(), &schema).unwrap(),
                )
                .unwrap()
                .collect();
            assert_eq!(
                actions,
                vec![(
                    &r#"Action::"watch""#.parse().unwrap(),
                    Some(Decision::Allow)
                ),]
            );
        }

        #[test]
        fn query_action_bob_not_free() {
            let schema = schema();
            let request = ActionQueryRequest::new(
                PartialEntityUid::from_concrete(r#"FreeMember::"Bob""#.parse().unwrap()),
                PartialEntityUid::from_concrete(r#"Movie::"The Gleaming""#.parse().unwrap()),
                None,
                schema.clone(),
            )
            .unwrap();

            let policies = policy_set();
            let actions: Vec<_> = policies
                .query_action(
                    &request,
                    &PartialEntities::from_concrete(entities(), &schema).unwrap(),
                )
                .unwrap()
                .collect();
            assert_eq!(actions, vec![]);
        }
    }

    mod github {
        use std::{
            collections::{HashMap, HashSet},
            str::FromStr,
        };

        use cedar_policy_core::tpe::err::TpeError;
        use cedar_policy_core::{authorizer::Decision, batched_evaluator::err::BatchedEvalError};
        use cool_asserts::assert_matches;
        use itertools::Itertools;
        use serde_json::{json, Value};
        use similar_asserts::assert_eq;

        use crate::{
            ActionQueryRequest, Context, Entities, EntityUid, PartialEntities, PartialEntityUid,
            PolicySet, PrincipalQueryRequest, Request, ResourceQueryRequest, RestrictedExpression,
            Schema, TestEntityLoader,
        };

        #[track_caller]
        fn schema() -> Schema {
            Schema::from_str(
            r#"
            entity Team, UserGroup in [UserGroup];
            entity Issue = { "repo": Repository, "reporter": User };
            entity Org = { "members": UserGroup, "owners": UserGroup };
            entity Repository = {
                "admins": UserGroup, "maintainers": UserGroup,
                "readers": UserGroup, "triagers": UserGroup, "writers": UserGroup,
            };
            entity User in [UserGroup, Team];

            action push, pull, fork appliesTo { principal: [User], resource: [Repository] };
            action assign_issue, delete_issue, edit_issue appliesTo { principal: [User], resource: [Issue] };
            action add_reader, add_writer, add_maintainer, add_admin, add_triager
                appliesTo { principal: [User], resource: [Repository] };
            "#,
        )
        .unwrap()
        }

        fn policy_set() -> PolicySet {
            PolicySet::from_str(
                r#"
            // Readers
            permit(principal, action == Action::"pull", resource)
            when { principal in resource.readers };
            permit(principal, action == Action::"fork", resource)
            when { principal in resource.readers };
            permit(principal, action == Action::"delete_issue", resource)
            when { principal in resource.repo.readers && principal == resource.reporter };
            permit(principal, action == Action::"edit_issue", resource)
            when { principal in resource.repo.readers && principal == resource.reporter };

            // Triagers
            permit(principal, action == Action::"assign_issue", resource)
            when { principal in resource.repo.triagers };

            // Writers
            permit(principal, action == Action::"push", resource)
            when { principal in resource.writers };
            permit(principal, action == Action::"edit_issue", resource)
            when { principal in resource.repo.writers };

            // Maintainers
            permit(principal, action == Action::"delete_issue", resource)
            when { principal in resource.repo.maintainers };

            // Admins
            permit(
                principal,
                action in [Action::"add_reader", Action::"add_triager", Action::"add_writer",
                           Action::"add_maintainer", Action::"add_admin"],
                resource
            )
            when { principal in resource.admins };
            "#,
            )
            .unwrap()
        }

        #[track_caller]
        fn entities() -> Entities {
            fn repo_with_groups(n: &str) -> Vec<Value> {
                let Value::Array(arr) = json!([
                    { "uid": { "__entity": { "type": "Repository", "id": n } },
                      "attrs": {
                          "readers": { "__entity": { "type": "UserGroup", "id": format!("{n}_readers") } },
                          "triagers": { "__entity": { "type": "UserGroup", "id": format!("{n}_triagers") } },
                          "writers": { "__entity": { "type": "UserGroup", "id": format!("{n}_writers") } },
                          "maintainers": { "__entity": { "type": "UserGroup", "id": format!("{n}_maintainers") } },
                          "admins": { "__entity": { "type": "UserGroup", "id": format!("{n}_admins") } }, },
                      "parents": []
                    },
                    { "uid": { "__entity": { "type": "UserGroup", "id": format!("{n}_readers") } },
                        "attrs": {}, "parents": [] },
                    { "uid": { "__entity": { "type": "UserGroup", "id": format!("{n}_triagers") } },
                        "attrs": {}, "parents": [{ "__entity": { "type": "UserGroup", "id": format!("{n}_readers") } }] },
                    { "uid": { "__entity": { "type": "UserGroup", "id": format!("{n}_writers") } },
                        "attrs": {}, "parents": [{ "__entity": { "type": "UserGroup", "id": format!("{n}_triagers") } }] },
                    { "uid": { "__entity": { "type": "UserGroup", "id": format!("{n}_maintainers") } },
                        "attrs": {}, "parents": [{ "__entity": { "type": "UserGroup", "id": format!("{n}_writers") } }] },
                    { "uid": { "__entity": { "type": "UserGroup", "id": format!("{n}_admins") } },
                        "attrs": {}, "parents": [{ "__entity": { "type": "UserGroup", "id": format!("{n}_maintainers") } }] },
                ]) else {
                    panic!();
                };
                arr
            }

            let Value::Array(mut entities) = json!([
                { "uid": { "__entity": { "type": "User", "id": "alice" } }, "attrs": {},
                  "parents": [
                    { "__entity": { "type": "UserGroup", "id": "common_knowledge_writers" } },
                    { "__entity": { "type": "UserGroup", "id": "uncommon_knowledge_writers" } },
                  ] },
                { "uid": { "__entity": { "type": "User", "id": "jane" } }, "attrs": {},
                  "parents": [
                    { "__entity": { "type": "UserGroup", "id": "common_knowledge_maintainers" } },
                    { "__entity": { "type": "Team", "id": "team_that_can_read_everything" } },
                  ] },
                { "uid": { "__entity": { "type": "User", "id": "bob" } },
                  "attrs": {}, "parents": [] },
                { "uid": { "__entity": { "type": "Team", "id": "team_that_can_read_everything" } },
                  "attrs": {}, "parents": [
                      { "__entity": { "type": "UserGroup", "id": "common_knowledge_readers" } },
                      { "__entity": { "type": "UserGroup", "id": "secret_readers" } },
                      { "__entity": { "type": "UserGroup", "id": "uncommon_knowledge_readers" } }]}
            ]) else {
                panic!();
            };
            entities.extend(repo_with_groups("common_knowledge"));
            entities.extend(repo_with_groups("secret"));
            entities.extend(repo_with_groups("uncommon_knowledge"));

            Entities::from_json_value(serde_json::Value::Array(entities), Some(&schema())).unwrap()
        }

        #[test]
        fn query_resource() {
            let schema = schema();
            let request = ResourceQueryRequest::new(
                r#"User::"jane""#.parse().unwrap(),
                r#"Action::"push""#.parse().unwrap(),
                "Repository".parse().unwrap(),
                Context::empty(),
                &schema,
            )
            .unwrap();
            let policies = policy_set();
            assert_matches!(&policies.query_resource(&request, &entities(), &schema).unwrap().collect_vec(), [uid] => {
                assert_eq!(uid, &r#"Repository::"common_knowledge""#.parse().unwrap());
            });
        }

        #[test]
        fn query_principal() {
            let schema = schema();
            let request = PrincipalQueryRequest::new(
                r"User".parse().unwrap(),
                r#"Action::"pull""#.parse().unwrap(),
                r#"Repository::"secret""#.parse().unwrap(),
                Context::empty(),
                &schema,
            )
            .unwrap();
            let policies = policy_set();
            assert_matches!(&policies.query_principal(&request, &entities(), &schema).unwrap().collect_vec(), [uid] => {
                assert_eq!(uid, &r#"User::"jane""#.parse().unwrap());
            });
        }

        #[test]
        fn query_action() {
            let schema = schema();
            let request = ActionQueryRequest::new(
                PartialEntityUid::from_concrete(r#"User::"jane""#.parse().unwrap()),
                PartialEntityUid::from_concrete(r#"Repository::"secret""#.parse().unwrap()),
                None,
                schema.clone(),
            )
            .unwrap();

            let policies = policy_set();
            let mut actions: Vec<_> = policies
                .query_action(
                    &request,
                    &PartialEntities::from_concrete(entities(), &schema).unwrap(),
                )
                .unwrap()
                .collect();
            actions.sort_by_key(|(a, _)| *a);
            assert_eq!(
                actions,
                vec![
                    (&r#"Action::"fork""#.parse().unwrap(), Some(Decision::Allow)),
                    (&r#"Action::"pull""#.parse().unwrap(), Some(Decision::Allow)),
                ]
            );
        }

        /// Build a Request with empty context and schema validation
        #[track_caller]
        fn request(principal: &str, action: &str, resource: &str, schema: &Schema) -> Request {
            Request::new(
                principal.parse().unwrap(),
                action.parse().unwrap(),
                resource.parse().unwrap(),
                Context::empty(),
                Some(schema),
            )
            .unwrap()
        }

        #[test]
        fn test_is_authorized_vs_is_authorized_batched() {
            use crate::Authorizer;

            let schema = schema();
            let policies = policy_set();
            let entities = entities();
            let authorizer = Authorizer::new();

            let test_requests = vec![
                request(
                    r#"User::"alice""#,
                    r#"Action::"push""#,
                    r#"Repository::"common_knowledge""#,
                    &schema,
                ),
                request(
                    r#"User::"jane""#,
                    r#"Action::"pull""#,
                    r#"Repository::"secret""#,
                    &schema,
                ),
                request(
                    r#"User::"bob""#,
                    r#"Action::"push""#,
                    r#"Repository::"common_knowledge""#,
                    &schema,
                ),
                request(
                    r#"User::"alice""#,
                    r#"Action::"fork""#,
                    r#"Repository::"common_knowledge""#,
                    &schema,
                ),
            ];

            // Test each request with both methods and compare results
            for (i, request) in test_requests.iter().enumerate() {
                // Get result from is_authorized
                let standard_response = authorizer.is_authorized(request, &policies, &entities);

                // Get result from is_authorized_batched (if TPE feature is enabled)
                let mut loader = TestEntityLoader::new(&entities);
                let batched_decision = policies
                    .is_authorized_batched(request, &schema, &mut loader, u32::MAX)
                    .unwrap();

                // Compare decisions - they should be the same
                let standard_decision = standard_response.decision();

                assert_eq!(
                standard_decision,
                batched_decision,
                "Request {}: is_authorized returned {:?} but is_authorized_batched returned {:?}",
                i + 1,
                standard_decision,
                batched_decision
            );
            }
        }

        #[test]
        fn test_batched_evaluation_error_validation() {
            let schema = schema();
            let policies = PolicySet::from_str(
            r#"permit(principal, action, resource) when { principal.nonexistent_attr == "value" };"#,
        )
        .unwrap();

            let req = request(
                r#"User::"alice""#,
                r#"Action::"push""#,
                r#"Repository::"repo""#,
                &schema,
            );

            let entities = entities();
            let mut loader = TestEntityLoader::new(&entities);
            let result = policies.is_authorized_batched(&req, &schema, &mut loader, 10);

            assert!(matches!(
                result,
                Err(BatchedEvalError::TPE(TpeError::Validation(_)))
            ));
        }

        #[test]
        #[cfg(feature = "partial-eval")]
        fn test_batched_evaluation_error_partial_request() {
            let context_with_unknown = Context::from_pairs([(
                "key".to_string(),
                RestrictedExpression::new_unknown("test_unknown"),
            )])
            .unwrap();

            let request = Request::new(
                EntityUid::from_str("User::\"alice\"").unwrap(),
                EntityUid::from_str("Action::\"view\"").unwrap(),
                EntityUid::from_str("Resource::\"doc\"").unwrap(),
                context_with_unknown,
                None,
            )
            .unwrap();
            let schema = schema();

            let pset = PolicySet::from_str("permit(principal, action, resource);").unwrap();
            let entities = Entities::empty();
            let mut loader = TestEntityLoader::new(&entities);
            let result = pset.is_authorized_batched(&request, &schema, &mut loader, 10);

            assert_matches!(result, Err(BatchedEvalError::PartialRequest(_)));
        }

        #[test]
        fn test_batched_evaluation_error_invalid_entity() {
            // Create an entity loader that returns an invalid entity (wrong attribute type)
            struct InvalidEntityLoader;
            impl crate::EntityLoader for InvalidEntityLoader {
                fn load_entities(
                    &mut self,
                    _uids: &HashSet<EntityUid>,
                ) -> HashMap<EntityUid, Option<crate::Entity>> {
                    let mut result = HashMap::new();
                    let uid = EntityUid::from_strs("Org", "myorg");
                    let entity = crate::Entity::new(
                        uid.clone(),
                        [
                            (
                                "members".to_string(),
                                RestrictedExpression::new_string("not_a_usergroup".to_string()),
                            ),
                            (
                                "owners".to_string(),
                                RestrictedExpression::new_entity_uid(EntityUid::from_strs(
                                    "UserGroup",
                                    "2",
                                )),
                            ),
                        ]
                        .into(),
                        HashSet::new(),
                    )
                    .unwrap();
                    result.insert(uid, Some(entity));
                    result
                }
            }

            let schema = schema();
            let pset = PolicySet::from_str(
                "permit(principal, action, resource) when { Org::\"myorg\".members == UserGroup::\"1\"};",
            )
            .unwrap();

            let req = request(
                r#"User::"alice""#,
                r#"Action::"push""#,
                r#"Repository::"common_knowledge""#,
                &schema,
            );

            let mut loader = InvalidEntityLoader;
            let result = pset.is_authorized_batched(&req, &schema, &mut loader, 10);

            assert_matches!(result, Err(BatchedEvalError::Entities(_)));
        }

        #[test]
        #[cfg(feature = "partial-eval")]
        fn test_batched_evaluation_error_partial_entity() {
            // Create an entity loader that returns a partial entity (contains unknowns)
            struct PartialEntityLoader;
            impl crate::EntityLoader for PartialEntityLoader {
                fn load_entities(
                    &mut self,
                    _uids: &HashSet<EntityUid>,
                ) -> HashMap<EntityUid, Option<crate::Entity>> {
                    let mut result = HashMap::new();
                    let uid = EntityUid::from_strs("Org", "myorg");
                    let entity = crate::Entity::new(
                        uid.clone(),
                        [
                            (
                                "members".to_string(),
                                RestrictedExpression::new_unknown("partial_members"),
                            ),
                            (
                                "owners".to_string(),
                                RestrictedExpression::new_entity_uid(EntityUid::from_strs(
                                    "UserGroup",
                                    "2",
                                )),
                            ),
                        ]
                        .into(),
                        HashSet::new(),
                    )
                    .unwrap();
                    result.insert(uid, Some(entity));
                    result
                }
            }

            let schema = schema();
            let pset = PolicySet::from_str(
                "permit(principal, action, resource) when { Org::\"myorg\".members == UserGroup::\"1\"};",
            )
            .unwrap();

            let req = request(
                r#"User::"alice""#,
                r#"Action::"push""#,
                r#"Repository::"common_knowledge""#,
                &schema,
            );

            let mut loader = PartialEntityLoader;
            let result = pset.is_authorized_batched(&req, &schema, &mut loader, 10);

            assert_matches!(result, Err(BatchedEvalError::PartialValueToValue(_)));
        }

        #[test]
        fn test_batched_evaluation_error_insufficient_iters() {
            let schema = schema();
            let policies = policy_set();
            let entities = entities();
            let req = request(
                r#"User::"alice""#,
                r#"Action::"push""#,
                r#"Repository::"common_knowledge""#,
                &schema,
            );

            let mut loader = TestEntityLoader::new(&entities);
            let result = policies.is_authorized_batched(&req, &schema, &mut loader, 0);

            assert_matches!(result, Err(BatchedEvalError::InsufficientIterations(_)));
        }
    }

    mod trivial {
        use cedar_policy_core::authorizer::Decision;
        use itertools::Itertools;

        use crate::{
            Context, Entities, PartialEntities, PartialEntityUid, PartialRequest, PolicySet,
            PrincipalQueryRequest, ResourceQueryRequest, Schema,
        };
        use std::{i64, str::FromStr};

        /// Run TPE, query_principal, and query_resource for a given policy string,
        /// asserting the expected decision and expected entity lists.
        #[track_caller]
        fn assert_tpe_and_queries(
            policy: &str,
            expected_decision: Decision,
            expected_principals: &[&str],
            expected_resources: &[&str],
        ) {
            let schema =
                Schema::from_str("entity P, R; action A appliesTo { principal: P, resource: R };")
                    .unwrap();
            let entities = Entities::from_json_value(
                serde_json::json!([
                    { "uid": { "__entity": { "type": "P", "id": ""} }, "attrs": {}, "parents": [] },
                    { "uid": { "__entity": { "type": "R", "id": ""} }, "attrs": {}, "parents": [] },
                ]),
                None,
            )
            .unwrap();
            let partial_entities =
                PartialEntities::from_concrete(entities.clone(), &schema).unwrap();
            let partial_req = PartialRequest::new(
                PartialEntityUid::new("P".parse().unwrap(), None),
                r#"Action::"A""#.parse().unwrap(),
                PartialEntityUid::new("R".parse().unwrap(), None),
                None,
                &schema,
            )
            .unwrap();

            let response = PolicySet::from_str(policy)
                .unwrap()
                .tpe(&partial_req, &partial_entities, &schema)
                .unwrap();
            assert_eq!(response.decision(), Some(expected_decision));

            let preq = PrincipalQueryRequest::new(
                "P".parse().unwrap(),
                r#"Action::"A""#.parse().unwrap(),
                r#"R::"""#.parse().unwrap(),
                Context::empty(),
                &schema,
            )
            .unwrap();
            let principals = PolicySet::from_str(policy)
                .unwrap()
                .query_principal(&preq, &entities, &schema)
                .unwrap()
                .collect_vec();
            let expected_p: Vec<crate::EntityUid> = expected_principals
                .iter()
                .map(|s| s.parse().unwrap())
                .collect();
            assert_eq!(&principals, &expected_p);

            let rreq = ResourceQueryRequest::new(
                r#"P::"""#.parse().unwrap(),
                r#"Action::"A""#.parse().unwrap(),
                "R".parse().unwrap(),
                Context::empty(),
                &schema,
            )
            .unwrap();
            let resources = PolicySet::from_str(policy)
                .unwrap()
                .query_resource(&rreq, &entities, &schema)
                .unwrap()
                .collect_vec();
            let expected_r: Vec<crate::EntityUid> = expected_resources
                .iter()
                .map(|s| s.parse().unwrap())
                .collect();
            assert_eq!(&resources, &expected_r);
        }

        #[test]
        fn trivial_permit() {
            assert_tpe_and_queries(
                r"permit(principal, action, resource);",
                Decision::Allow,
                &[r#"P::"""#],
                &[r#"R::"""#],
            );
        }

        #[test]
        fn trivial_forbid() {
            assert_tpe_and_queries(
                r"forbid(principal, action, resource);",
                Decision::Deny,
                &[],
                &[],
            );
        }

        #[test]
        fn error() {
            assert_tpe_and_queries(
                &format!(
                    r#"permit(principal, action, resource) when {{ ({} + 1) == 0 || true }};"#,
                    i64::MAX
                ),
                Decision::Deny,
                &[],
                &[],
            );
        }

        #[test]
        fn empty() {
            assert_tpe_and_queries("", Decision::Deny, &[], &[]);
        }
    }

    mod query_action {
        use cedar_policy_core::authorizer::Decision;

        use crate::{
            ActionQueryRequest, Context, PartialEntities, PartialEntityUid, PolicySet, Schema,
        };
        use similar_asserts::assert_eq;
        use std::str::FromStr;

        /// Standard schema for User/Photo action query tests
        fn photo_schema() -> Schema {
            Schema::from_str(
                "entity User, Photo; action view appliesTo { principal: User, resource: Photo};",
            )
            .unwrap()
        }

        /// Build an ActionQueryRequest for User::"alice" on Photo::"vacation.jpg"
        fn alice_photo_request(schema: Schema, context: Option<Context>) -> ActionQueryRequest {
            ActionQueryRequest::new(
                PartialEntityUid::from_concrete(r#"User::"alice""#.parse().unwrap()),
                PartialEntityUid::from_concrete(r#"Photo::"vacation.jpg""#.parse().unwrap()),
                context,
                schema,
            )
            .unwrap()
        }

        #[test]
        fn test() {
            let policies = PolicySet::from_str(
                r#"
            permit(principal, action == Action::"edit", resource)
            when { context.ip.isInRange(resource.allowed_edit_range) };

            permit(principal, action == Action::"view", resource)
            when { resource.public };

            forbid(principal, action == Action::"delete", resource);

            permit(principal, action == Action::"not_on_photo", resource);
            "#,
            )
            .unwrap();
            let schema = Schema::from_str(
                r#"
            entity User, Other;
            entity Photo { public: Bool, allowed_edit_range: ipaddr };
            action view, edit, delete appliesTo {
                principal: User, resource: Photo, context: { ip: ipaddr }
            };
            action not_on_photo appliesTo { principal: User, resource: Other };
            "#,
            )
            .unwrap();
            let entities = PartialEntities::from_json_value(
                serde_json::json!([{
                    "uid": { "__entity": { "type": "Photo", "id": "vacation.jpg" } },
                    "attrs": { "public": true, "allowed_edit_range": "192.0.2.0/24" },
                    "parents": []
                }]),
                &schema,
            )
            .unwrap();

            let request = ActionQueryRequest::new(
                PartialEntityUid::from_concrete(r#"User::"alice""#.parse().unwrap()),
                PartialEntityUid::from_concrete(r#"Photo::"vacation.jpg""#.parse().unwrap()),
                None,
                schema,
            )
            .unwrap();

            let mut actions: Vec<_> = policies
                .query_action(&request, &entities)
                .unwrap()
                .collect();
            actions.sort_by_key(|(a, _)| *a);
            assert_eq!(
                actions,
                vec![
                    (&r#"Action::"edit""#.parse().unwrap(), None),
                    (&r#"Action::"view""#.parse().unwrap(), Some(Decision::Allow)),
                ]
            )
        }

        #[test]
        fn permitted_action() {
            let policies = PolicySet::from_str("permit(principal, action, resource);").unwrap();
            let schema = photo_schema();
            let entities = PartialEntities::empty();
            let request = alice_photo_request(schema, None);

            let actions: Vec<_> = policies
                .query_action(&request, &entities)
                .unwrap()
                .collect();
            assert_eq!(
                actions,
                vec![(&r#"Action::"view""#.parse().unwrap(), Some(Decision::Allow))]
            );
        }

        #[test]
        fn maybe_permitted_action() {
            let policies = PolicySet::from_str(
                "permit(principal, action, resource) when { context.should_allow };",
            )
            .unwrap();
            let schema = Schema::from_str(
                "entity User, Photo; action view appliesTo { principal: User, resource: Photo, context: {should_allow: Bool}};",
            )
            .unwrap();
            let entities = PartialEntities::empty();
            let request = alice_photo_request(schema, None);

            let actions: Vec<_> = policies
                .query_action(&request, &entities)
                .unwrap()
                .collect();
            assert_eq!(actions, vec![(&r#"Action::"view""#.parse().unwrap(), None)]);
        }

        #[test]
        fn forbidden_action() {
            let policies = PolicySet::from_str("forbid(principal, action, resource);").unwrap();
            let schema = photo_schema();
            let entities = PartialEntities::empty();
            let request = alice_photo_request(schema, None);

            let actions: Vec<_> = policies
                .query_action(&request, &entities)
                .unwrap()
                .collect();
            assert_eq!(actions, Vec::new(),);
        }

        #[test]
        fn invalid_permitted_action() {
            let policies = PolicySet::from_str("permit(principal, action, resource);").unwrap();
            let schema = Schema::from_str(
            "entity User, Photo, Other; action view appliesTo { principal: User, resource: Other};",
        )
        .unwrap();
            let entities = PartialEntities::empty();
            let request = alice_photo_request(schema, None);

            let actions: Vec<_> = policies
                .query_action(&request, &entities)
                .unwrap()
                .collect();
            assert_eq!(actions, Vec::new());
        }

        #[test]
        fn invalid_context_permitted_action() {
            let policies = PolicySet::from_str("permit(principal, action, resource);").unwrap();
            let schema = Schema::from_str("entity User, Photo; action view appliesTo { principal: User, resource: Photo, context: {a: Long}};").unwrap();
            let entities = PartialEntities::empty();
            let request = alice_photo_request(schema, Some(Context::empty()));

            let actions: Vec<_> = policies
                .query_action(&request, &entities)
                .unwrap()
                .collect();
            assert_eq!(actions, Vec::new());
        }

        #[test]
        fn no_actions_in_schema() {
            let policies = PolicySet::from_str("permit(principal, action, resource);").unwrap();
            let schema = Schema::from_str("entity User, Photo;").unwrap();
            let entities = PartialEntities::empty();
            let request = alice_photo_request(schema, None);

            let actions: Vec<_> = policies
                .query_action(&request, &entities)
                .unwrap()
                .collect();
            assert_eq!(actions, Vec::new());
        }

        #[test]
        fn permitted_action_error_permit() {
            let policies = PolicySet::from_str(&format!("permit(principal, action, resource);permit(principal, action, resource) when {{ {} + 1 == 0 || true }};", i64::MAX)).unwrap();
            let schema = photo_schema();
            let entities = PartialEntities::empty();
            let request = alice_photo_request(schema, None);

            let actions: Vec<_> = policies
                .query_action(&request, &entities)
                .unwrap()
                .collect();
            assert_eq!(
                actions,
                vec![(&r#"Action::"view""#.parse().unwrap(), Some(Decision::Allow))]
            );
        }

        #[test]
        fn permitted_action_error_forbid() {
            let policies = PolicySet::from_str(&format!("permit(principal, action, resource);forbid(principal, action, resource) when {{ {} + 1 == 0 || true }};", i64::MAX)).unwrap();
            let schema = photo_schema();
            let entities = PartialEntities::empty();
            let request = alice_photo_request(schema, None);

            let actions: Vec<_> = policies
                .query_action(&request, &entities)
                .unwrap()
                .collect();
            assert_eq!(
                actions,
                vec![(&r#"Action::"view""#.parse().unwrap(), Some(Decision::Allow))]
            );
        }

        #[test]
        fn forbidden_action_error_permit() {
            let policies = PolicySet::from_str(&format!(
                "permit(principal, action, resource) when {{ {} + 1 == 0 || true }};",
                i64::MAX
            ))
            .unwrap();
            let schema = photo_schema();
            let entities = PartialEntities::empty();
            let request = alice_photo_request(schema, None);

            let actions: Vec<_> = policies
                .query_action(&request, &entities)
                .unwrap()
                .collect();
            assert_eq!(actions, Vec::new(),);
        }
    }

    /// TPE produces `Residual::Error` when a concrete entity lacks an accessed
    /// attribute. The residual policy should be convertible to PST via
    /// `Policy::to_pst()`, with the error node represented as
    /// `pst::Expr::ResidualError`.
    #[test]
    fn residual_error_to_pst() {
        use cedar_policy_core::pst;
        use std::str::FromStr;

        let (schema, _) = crate::Schema::from_cedarschema_str(
            r#"
            entity User = { name: String };
            entity Account = { name: String, assignedTo?: User };
            action RevealCredentials appliesTo {
                principal: [User], resource: [Account], context: { flag: Bool }
            };
            "#,
        )
        .unwrap();

        let policies = crate::PolicySet::from_str(
            r#"permit(principal is User, action == Action::"RevealCredentials", resource is Account)
           when { context.flag && resource has assignedTo && resource.assignedTo == principal };"#,
        )
        .unwrap();

        // Account without assignedTo — TPE will produce an error node for
        // `resource.assignedTo`
        let entities = crate::Entities::from_json_value(
        serde_json::json!([
            { "uid": { "type": "User", "id": "u1" }, "attrs": { "name": "alice" }, "parents": [] },
            { "uid": { "type": "Account", "id": "a1" }, "attrs": { "name": "shared" }, "parents": [] },
        ]),
        Some(&schema),
    )
    .unwrap();

        let partial_entities = crate::PartialEntities::from_concrete(entities, &schema).unwrap();

        // Context is unknown — forces a residual on `context has flag`
        let request = crate::PartialRequest::new(
            crate::PartialEntityUid::from_concrete(r#"User::"u1""#.parse().unwrap()),
            r#"Action::"RevealCredentials""#.parse().unwrap(),
            crate::PartialEntityUid::from_concrete(r#"Account::"a1""#.parse().unwrap()),
            None,
            &schema,
        )
        .unwrap();

        let response = policies
            .tpe(&request, &partial_entities, &schema)
            .expect("tpe should succeed");

        // There should be exactly one nontrivial residual
        let residual_policies: Vec<_> = response.nontrivial_residual_policies().collect();
        assert_eq!(
            residual_policies.len(),
            1,
            "decision={:?}, all residuals: {:?}",
            response.decision(),
            response
                .residual_policies()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
        );

        let policy = &residual_policies[0];

        // Convert to PST
        let pst_policy = policy.to_pst().expect("to_pst should succeed");
        let clauses = pst_policy.body().clauses();
        assert_eq!(clauses.len(), 1);

        let expr = match &clauses[0] {
            pst::Clause::When(e) => e,
            pst::Clause::Unless(_) => panic!("expected when clause"),
        };

        // The expression should contain a ResidualError node (from
        // `resource.assignedTo` on an entity without that attribute)
        assert!(
            expr.has_error(),
            "residual expression should contain an error node"
        );
    }

    mod template_links {
        use std::{collections::HashMap, str::FromStr};

        use crate::{
            pst, Decision, EntityUid, PartialEntities, PartialEntityUid, PartialRequest, Policy,
            PolicyId, PolicySet, Schema, SlotId, Template,
        };

        fn schema() -> Schema {
            Schema::from_str(
            "entity User { age: Long }; entity Photo; action view appliesTo { principal: User, resource: Photo};",
        )
        .unwrap()
        }

        fn template_policy_set() -> PolicySet {
            let mut policies = PolicySet::new();
            let template = Template::parse(
                Some(PolicyId::new("t0").clone()),
                "permit(principal == ?principal, action, resource);",
            )
            .unwrap();
            policies.add_template(template).unwrap();
            let template = Template::parse(
                Some(PolicyId::new("t1").clone()),
                "permit(principal, action, resource == ?resource);",
            )
            .unwrap();
            policies.add_template(template).unwrap();
            policies
        }

        fn partial_req() -> PartialRequest {
            PartialRequest::new(
                PartialEntityUid::from_concrete(r#"User::"alice""#.parse().unwrap()),
                r#"Action::"view""#.parse().unwrap(),
                PartialEntityUid::new("Photo".parse().unwrap(), None),
                None,
                &schema(),
            )
            .unwrap()
        }

        #[test]
        fn concrete_allow() {
            let schema = schema();
            let mut policies = template_policy_set();
            policies
                .link(
                    PolicyId::new("t0"),
                    PolicyId::new("l"),
                    HashMap::from([(
                        SlotId::principal(),
                        EntityUid::from_str(r#"User::"alice""#).unwrap(),
                    )]),
                )
                .unwrap();

            let request = partial_req();
            let es = PartialEntities::empty();
            let response = policies.tpe(&request, &es, &schema).unwrap();

            assert_eq!(response.decision(), Some(Decision::Allow));
        }

        #[test]
        fn templates_no_links_deny() {
            let schema = schema();
            let policies = template_policy_set();

            let request = partial_req();
            let es = PartialEntities::empty();
            let response = policies.tpe(&request, &es, &schema).unwrap();

            assert_eq!(response.decision(), Some(Decision::Deny));
        }

        #[test]
        fn concrete_deny() {
            let schema = schema();
            let mut policies = template_policy_set();
            policies
                .link(
                    PolicyId::new("t0"),
                    PolicyId::new("l"),
                    HashMap::from([(
                        SlotId::principal(),
                        EntityUid::from_str(r#"User::"bob""#).unwrap(),
                    )]),
                )
                .unwrap();

            let request = partial_req();
            let es = PartialEntities::empty();
            let response = policies.tpe(&request, &es, &schema).unwrap();

            assert_eq!(response.decision(), Some(Decision::Deny));
        }

        #[test]
        fn residual() {
            let schema = schema();
            let mut policies = template_policy_set();
            policies
                .link(
                    PolicyId::new("t1"),
                    PolicyId::new("l"),
                    HashMap::from([(
                        SlotId::resource(),
                        EntityUid::from_str(r#"Photo::"p""#).unwrap(),
                    )]),
                )
                .unwrap();

            let request = partial_req();
            let es = PartialEntities::empty();
            let response = policies.tpe(&request, &es, &schema).unwrap();

            let expected: pst::Policy = Policy::parse(
                Some(PolicyId::new("l")),
                r#"permit(principal, action, resource) when { resource == Photo::"p" };"#,
            )
            .unwrap()
            .to_pst()
            .unwrap();

            let residuals: Vec<_> = response.nontrivial_residual_policies().collect();
            assert_eq!(residuals[0].to_pst().unwrap().body(), expected.body());
            assert_eq!(response.decision(), None);
            assert_eq!(residuals.len(), 1);
        }
    }
}
