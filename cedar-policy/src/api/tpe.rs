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

use cedar_policy_core::ast;
use cedar_policy_core::authorizer::Decision;
use cedar_policy_core::batched_evaluator::is_authorized_batched;
use cedar_policy_core::batched_evaluator::{
    err::BatchedEvalError, EntityLoader as EntityLoaderInternal,
};
use cedar_policy_core::evaluator::{EvaluationError, RestrictedEvaluator};
use cedar_policy_core::extensions::Extensions;
use cedar_policy_core::tpe;
use cedar_policy_core::tpe::value::{PartialAttribute, PartialRecord, PartialValue};
use cedar_policy_core::validator::types::Type;
use itertools::Itertools;
use ref_cast::RefCast;
use smol_str::SmolStr;

use crate::{
    api, tpe_err, Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PartialEntityError, PartialRequestCreationError, PermissionQueryError, Policy, PolicyId,
    PolicySet, Request, RequestValidationError, RestrictedExpression, Schema,
    TpeReauthorizationError,
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
        let context = context.as_ref().and_then(|c| {
            let ast::Context::Value(concrete_context) = &c.0 else {
                panic!();
            };
            PartialRecord::concrete_context_for_action(
                concrete_context,
                action.as_ref(),
                schema.as_ref(),
            )
        });
        tpe::request::PartialRequest::new(principal.0, action.0, resource.0, context, &schema.0)
            .map(Self)
            .map_err(|e| PartialRequestCreationError::Validation(e.into()))
    }
}

/// Like [`PartialRequest`] but only `resource` can be unknown
///
/// Intended for use with [`PolicySet::query_resource`].
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

    fn principal(&self) -> EntityUid {
        #[expect(
            clippy::unwrap_used,
            reason = "constructor requires concrete principal"
        )]
        EntityUid(self.0 .0.get_principal().try_into().unwrap())
    }

    fn context(&self, schema: Option<&Schema>) -> Context {
        let validator_schema = schema.map(|s| &s.0);
        #[expect(
            clippy::unwrap_used,
            reason = "building context from BTreeMap iter, so no duplicates are possible"
        )]
        Context::from_pairs(
            self.0
                 .0
                .get_context_attrs(validator_schema)
                .unwrap()
                .iter()
                .map(|(a, v)| (a.to_string(), RestrictedExpression(v.clone().into()))),
        )
        .unwrap()
    }

    /// Convert this to a [`Request`] by providing the resource [`EntityId`]
    ///
    /// Even though the partial request was already validated in [`ResourceQueryRequest::new`],
    /// to ensure that the concrete request returned here is valid we still need to
    /// check the resource entity id. If the resource has an enum entity type,
    /// then its id must be one of the listed instances of that type.
    pub fn to_request(
        &self,
        resource_id: EntityId,
        schema: Option<&Schema>,
    ) -> Result<Request, RequestValidationError> {
        Request::new(
            self.principal(),
            EntityUid(self.0 .0.get_action()),
            EntityUid::from_type_name_and_id(
                EntityTypeName(self.0 .0.get_resource_type()),
                resource_id,
            ),
            self.context(schema),
            schema,
        )
    }
}

/// Like [`PartialRequest`] but only `principal` can be unknown
///
/// Intended for use with [`PolicySet::query_principal`].
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

    fn resource(&self) -> EntityUid {
        #[expect(clippy::unwrap_used, reason = "constructor requires concrete resource")]
        EntityUid(self.0 .0.get_resource().try_into().unwrap())
    }

    fn context(&self, schema: Option<&Schema>) -> Context {
        let validator_schema = schema.map(|s| &s.0);
        #[expect(
            clippy::unwrap_used,
            reason = "building context from BTreeMap iter, so no duplicates are possible"
        )]
        Context::from_pairs(
            self.0
                 .0
                .get_context_attrs(validator_schema)
                .unwrap()
                .iter()
                .map(|(a, v)| (a.to_string(), RestrictedExpression(v.clone().into()))),
        )
        .unwrap()
    }

    /// Convert this to a [`Request`] by providing the principal [`EntityId`]
    ///
    /// Even though the partial request was already validated in [`PrincipalQueryRequest::new`],
    /// to ensure that the concrete request returned here is valid we still need to
    /// check the principal entity id. If the principal has an enum entity type,
    /// then its id must be one of the listed instances of that type.
    pub fn to_request(
        &self,
        principal_id: EntityId,
        schema: Option<&Schema>,
    ) -> Result<Request, RequestValidationError> {
        Request::new(
            EntityUid::from_type_name_and_id(
                EntityTypeName(self.0 .0.get_principal_type()),
                principal_id,
            ),
            EntityUid(self.0 .0.get_action()),
            self.resource(),
            self.context(schema),
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
    context: Option<Context>,
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
        // If action is not in the schema, context becomes None and
        // PartialRequest::new below will produce the proper UndeclaredAction error.
        let context = self.context.as_ref().and_then(|c| {
            let ast::Context::Value(concrete_context) = &c.0 else {
                panic!();
            };
            PartialRecord::concrete_context_for_action(
                concrete_context,
                action.as_ref(),
                self.schema.as_ref(),
            )
        });
        tpe::request::PartialRequest::new(
            self.principal.0.clone(),
            action.0,
            self.resource.0.clone(),
            context,
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
        let (schema_attrs, tag_type) = match schema.0.get_entity_type(uid.0.entity_type()) {
            Some(entity_type) => (
                entity_type.attributes().clone(),
                entity_type.tag_type().cloned().unwrap_or(Type::Never),
            ),
            None => (Default::default(), Type::Never),
        };
        Ok(Self(tpe::entities::PartialEntity::new(
            uid.0,
            attrs
                .map(|ps| {
                    eval_to_partial_record(ps, |k| {
                        schema_attrs
                            .get_attr(k)
                            .map(|a| a.attr_type.as_ref().clone())
                            .unwrap_or(Type::Never)
                    })
                })
                .transpose()?,
            ancestors.map(|s| s.into_iter().map(|e| e.0).collect()),
            tags.map(|ps| eval_to_partial_record(ps, |_| tag_type.clone()))
                .transpose()?,
            &schema.0,
        )?))
    }
}

/// Evaluate restricted expressions and wrap each as [`PartialAttribute::Present`],
/// using `type_for_key` to look up the type for each field.
fn eval_to_partial_record(
    attrs: BTreeMap<SmolStr, RestrictedExpression>,
    type_for_key: impl Fn(&SmolStr) -> Type,
) -> Result<PartialRecord, EvaluationError> {
    let eval = RestrictedEvaluator::new(Extensions::all_available());
    let attrs = attrs
        .into_iter()
        .map(|(k, v)| {
            let ty = type_for_key(&k);
            Ok((
                k,
                PartialAttribute::Present(PartialValue::from_value(
                    eval.interpret(v.0.as_borrowed())?,
                    &ty,
                )),
            ))
        })
        .collect::<Result<Vec<_>, EvaluationError>>()?;
    Ok(PartialRecord::from_attrs(attrs))
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

/// A response to a partial authorization request.
///
/// Most callers will want to first check if a concrete authorization decision was reached using
/// [`TpeResponse::decision`] before inspecting the unevaluated policies with
/// [`TpeResponse::residual_policies`] or resuming evaluation after providing
/// the missing parts of the request with [`TpeResponse::reauthorize`].
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
    /// Get the authorization decision, if TPE reached a concrete decision.
    ///
    /// This function can return three possible values:
    /// * `Some(Decision::Allow)`, when there was enough information in the
    ///    partial request to concretely decide that the request should be allowed.
    /// * `Some(Decision::Deny)`, when there was enough information to decide
    ///    that the request should be denied.
    /// * `None`, when the partial request did _not_ provide enough information to reach an
    ///    authorization decision. In this case you can use [`TpeResponse::reauthorize`] to provide
    ///    the missing parts of the request and reach a concrete decision.
    pub fn decision(&self) -> Option<Decision> {
        self.0.decision()
    }

    /// Get the determining policies for the partial authorization decision.
    /// These are a subset of the determining policies in the response returned
    /// after calling [`TpeResponse::reauthorize`] with a concrete request and entities.
    ///
    /// When [`TpeResponse::decision`] returns a concrete allow or deny, the
    /// determining policies returned by this function are exactly the policies from
    /// [`TpeResponse::true_permits`] or [`TpeResponse::true_forbids`] respectively.
    ///
    /// If partial authorization does not reach a decision, then this function
    /// returns `None`. It's reasonable to treat this response as "no known
    /// determining policies", in which case you can call this function as
    /// `response.reason().into_iter().flatten()`.
    pub fn reason(&self) -> Option<impl Iterator<Item = &PolicyId>> {
        Some(self.0.reason()?.map(PolicyId::ref_cast))
    }

    /// Get the permit policies that did not reach a concrete value or error for the partial request.
    ///
    /// This function only returns the `PolicyId`s for residual policies.
    /// To access the residual policy conditions, use [`TpeResponse::residual_policies`].
    ///
    /// These policies could be determining policies _if_ the eventual
    /// concrete authorization decision is `Allow` _and_ they are satisfied by
    /// the concrete request. If the [`TpeResponse::decision`] is `Deny`, then
    /// they cannot be determining.
    pub fn residual_permits(&self) -> impl Iterator<Item = &PolicyId> {
        self.0
            .residual_permits()
            .map(|rp| PolicyId::ref_cast(rp.get_policy_id()))
    }

    /// Get the permit policies that are concretely satisfied by the partial request.
    ///
    /// To properly interpret the ids returned from this function you need to
    /// consider them in the context of [`TpeResponse::decision`]:
    /// * For a concrete `Allow` decision, these are a subset of the concrete
    ///   determining policies and are exactly the policies returned by
    ///   [`TpeResponse::reason`].
    /// * For a concrete `Deny` decision, these are not determining policies. The
    ///   iterator may be empty if no permits were satisfied, or it may contain
    ///   satisfied permits which have been overridden by at least one satisfied
    ///   forbid policy.
    /// * For an unknown decision, these will be a subset of the determining
    ///   policies _if_ the eventual concrete authorization decision is `Allow`,
    ///   but they may still be overridden by any non-trivial residual forbid
    ///   policy.
    pub fn true_permits(&self) -> impl Iterator<Item = &PolicyId> {
        self.0
            .true_permits()
            .map(|rp| PolicyId::ref_cast(rp.get_policy_id()))
    }

    /// Get the permit policies that are concretely not satisfied by the partial request.
    ///
    /// These policies evaluate to `false`, so they have no impact on the
    /// partial authorization decision or on any subsequent concrete decision
    /// after reauthorization.
    pub fn false_permits(&self) -> impl Iterator<Item = &PolicyId> {
        self.0
            .false_permits()
            .map(|rp| PolicyId::ref_cast(rp.get_policy_id()))
    }

    /// Get the permit policies that encountered concrete errors for the partial request.
    ///
    /// These policies errored, so they have no impact on the partial
    /// authorization decision. Erroring policies are not generally expected
    /// since partial evaluation works only on _validated_ policies, but it is still
    /// possible to encounter errors, e.g., on integer overflow.
    pub fn error_permits(&self) -> impl Iterator<Item = &PolicyId> {
        self.0
            .error_permits()
            .map(|rp| PolicyId::ref_cast(rp.get_policy_id()))
    }

    /// Get the forbid policies that did not reach a concrete value or error for the partial request.
    ///
    /// This function only returns the `PolicyId`s for residual policies.
    /// To access the residual policy conditions, use [`TpeResponse::residual_policies`].
    ///
    /// The presence of any residual forbids means that [`TpeResponse::decision`] _cannot_ return
    /// a concrete `Allow` decision. We do not have enough information to say that these forbid
    /// policies do not apply, so they might still override any satisfied permit policies.
    pub fn residual_forbids(&self) -> impl Iterator<Item = &PolicyId> {
        self.0
            .residual_forbids()
            .map(|rp| PolicyId::ref_cast(rp.get_policy_id()))
    }

    /// Get the forbid policies that are concretely satisfied by the partial request.
    ///
    /// Presence of any satisfied forbids guarantees that they are exactly the
    /// policies returned by [`TpeResponse::reason`] and that [`TpeResponse::decision`]
    /// must return a concrete `Deny`.
    pub fn true_forbids(&self) -> impl Iterator<Item = &PolicyId> {
        self.0
            .true_forbids()
            .map(|rp| PolicyId::ref_cast(rp.get_policy_id()))
    }

    /// Get the forbid policies that are concretely not satisfied by the partial request.
    ///
    /// These policies evaluate to `false`, so they have no impact on the
    /// partial authorization decision or on any subsequent concrete decision
    /// after reauthorization.
    pub fn false_forbids(&self) -> impl Iterator<Item = &PolicyId> {
        self.0
            .false_forbids()
            .map(|rp| PolicyId::ref_cast(rp.get_policy_id()))
    }

    /// Get the forbid policies that encountered concrete errors for the partial request.
    ///
    /// These policies errored, so they have no impact on the partial
    /// authorization decision. Erroring policies are not generally expected
    /// since partial evaluation works only on _validated_ policies, but it is still
    /// possible to encounter errors, e.g., on integer overflow.
    pub fn error_forbids(&self) -> impl Iterator<Item = &PolicyId> {
        self.0
            .error_forbids()
            .map(|rp| PolicyId::ref_cast(rp.get_policy_id()))
    }

    /// Perform reauthorization, taking the residual policies and further
    /// evaluating them with a concrete request and entities.
    ///
    /// If [`TpeResponse::decision`] returns a decision, then reauthorization
    /// will always reach the same decision. If it does not, then this function
    /// allows you to provide any data omitted from the partial request in order
    /// to reach a concrete decision.
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

    /// Returns an iterator of non-trivial (meaning more than just `true`
    /// or `false`, or an error) residuals as [`Policy`]s.
    ///
    /// To find policies that reached a concrete value, use, e.g., [`TpeResponse::true_permits`].
    ///
    /// Each returned [`Policy`] inherits its [`PolicyId`] and
    /// annotations from the corresponding input policy. Its scope is
    /// unconstrained and its condition is a single `when` clause containing
    /// the residual expression.
    ///
    /// Call [`Policy::to_pst()`] on each result to get a [`pst::Policy`](crate::pst::Policy)
    /// for structured inspection.
    ///
    /// ```no_run
    /// # use cedar_policy::{PolicySet, PartialRequest, PartialEntities, Schema};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let (policy_set, request, entities, schema) : (&PolicySet, &PartialRequest, &PartialEntities, &Schema) = panic!();
    /// let response = policy_set.tpe(&request, &entities, &schema)?;
    /// for policy in response.residual_policies() {
    ///     let pst_policy = policy.to_pst()?;
    ///     for clause in pst_policy.body().clauses() {
    ///         // inspect the residual expression via pst::Clause / pst::Expr
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// When inspecting these policies, be aware that they may contain
    /// [`pst::Expr::ResidualError`](crate::pst::Expr::ResidualError) nodes
    /// which do not normally exist in Cedar expressions. These represent
    /// subexpressions which are statically known to error; however, the whole
    /// residual policy might or might not error, regardless of whether it
    /// contains these nodes.
    pub fn residual_policies(&self) -> impl Iterator<Item = Policy> + '_ {
        self.0
            .residual_permits()
            .chain(self.0.residual_forbids())
            .map(|p| Policy::from_ast(p.clone().into()))
    }

    /// Return all residuals as [`Policy`]s, including concretely `true`, `false`, and error residuals.
    ///
    /// Each returned [`Policy`] inherits its [`PolicyId`](crate::PolicyId) and
    /// annotations from the corresponding input policy. Its scope is
    /// unconstrained and its condition is a single `when` clause containing
    /// the residual expression.
    ///
    /// Use [`TpeResponse::residual_policies`] to skip `true`, `false`, and error residuals.
    ///
    /// See [`TpeResponse::residual_policies`] for documentation on how to inspect policies using the PST.
    pub fn policies(&self) -> impl Iterator<Item = Policy> + '_ {
        self.0
            .policies()
            .map(|p| Policy::from_ast(p.clone().into()))
    }

    /// Return all residuals as a [`PolicySet`], including concretely `true`, `false`, and error residuals.
    ///
    /// This returns exactly the same policies as [`TpeResponse::policies`], but collected into a policy set.
    pub fn policy_set(&self) -> PolicySet {
        PolicySet::from_ast(self.0.policy_set())
    }

    /// Deprecated alias for [`TpeResponse::residual_policies`]
    #[deprecated(
        since = "4.12.0",
        note = "TpeResponse::residual_policies now returns only non-trivial residual policies"
    )]
    pub fn nontrivial_residual_policies(&'_ self) -> impl Iterator<Item = Policy> + '_ {
        self.residual_policies()
    }

    /// Get the residual policy for a specific [`PolicyId`], if it exists.
    ///
    /// See [`TpeResponse::residual_policies`] for documentation on how to inspect policies using the PST.
    pub fn get_policy(&self, id: &PolicyId) -> Option<Policy> {
        self.0
            .get_residual_policy(id.as_ref())
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
    /// If successful, the result is a [`TpeResponse`] containing the authorization decision, if
    /// one was reached, and residual policies ready for re-authorization. Use [`TpeResponse::decision`]
    /// to check the decision and [`TpeResponse::residual_policies`] to get the residuals as
    /// [`Policy`] objects. You can then call [`Policy::to_pst`] to convert them to [`pst::Policy`](crate::pst::Policy)
    /// for structured inspection of the residual expression tree.
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
        let tpe_response = self.tpe(&request.0, &partial_entities, schema)?;
        let policies = tpe_response.policy_set();
        match tpe_response.decision() {
            Some(Decision::Allow) => Ok(entities
                .iter()
                .filter(|entity| entity.0.uid().entity_type() == &request.0 .0.get_resource_type())
                .map(Entity::uid)
                .collect_vec()
                .into_iter()),
            Some(Decision::Deny) => Ok(vec![].into_iter()),
            None => Ok(entities
                .iter()
                .filter(|entity| entity.0.uid().entity_type() == &request.0 .0.get_resource_type())
                .filter(|entity| {
                    #[expect(
                        clippy::unwrap_used, reason = "`to_request` cannot panic because we do not pass a schema. However, the correctness of the authorization
                        decision depends on having valid a request and entities, but we do not do any validation here. Entities were already validated by
                        `PartialEntities::from_concrete`. The request was _mostly_ validated by its constructor, but the concrete request could still be invalid
                        if the resource entity is an enum entity and the id is not an instance of that enum. This cannot happen here because we draw candidate
                        resources from the entities, which we know are valid."
                    )]
                    let req = request.to_request(entity.uid().id().clone(), None).unwrap();
                    let authorizer = Authorizer::new();
                    let auth_response = authorizer
                        .is_authorized(
                            &req,
                            &policies,
                            entities,
                        );
                    auth_response.decision() == Decision::Allow
                })
                .map(Entity::uid)
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
        let tpe_response = self.tpe(&request.0, &partial_entities, schema)?;
        let policies = tpe_response.policy_set();
        match tpe_response.decision() {
            Some(Decision::Allow) => Ok(entities
                .iter()
                .filter(|entity| entity.0.uid().entity_type() == &request.0.0.get_principal_type())
                .map(Entity::uid)
                .collect_vec()
                .into_iter()),
            Some(Decision::Deny) => Ok(vec![].into_iter()),
            None => Ok(entities
                .iter()
                .filter(|entity| entity.0.uid().entity_type() == &request.0.0.get_principal_type())
                .filter(|entity| {
                    #[expect(
                        clippy::unwrap_used, reason = "`to_request` cannot panic because we do not pass a schema. However, the correctness of the authorization
                        decision depends on having valid a request and entities, but we do not do any validation here. Entities were already validated by
                        `PartialEntities::from_concrete`. The request was _mostly_ validated by its constructor, but the concrete request could still be invalid
                        if the principal entity is an enum entity and the id is not an instance of that enum. This cannot happen here because we draw candidate
                        principals from the entities, which we know are valid."
                    )]
                    let req = request.to_request(entity.uid().id().clone(), None).unwrap();
                    let authorizer = Authorizer::new();
                    let auth_response = authorizer
                        .is_authorized(
                            &req,
                            &policies,
                            entities,
                        );
                    auth_response.decision() == Decision::Allow
                })
                .map(Entity::uid)
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
mod tpe_tests {
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

            // Partial attrs (missing required `releaseDate`) is valid — not-in-map = unknown
            // TODO: Once the public API supports explicit `Absent` attributes,
            // add a test that marking a required field as Absent produces a
            // validation error (EntitySchemaConformanceError::MissingRequiredEntityAttr).
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
                Ok(_)
            );

            // Wrong type for an attr is still a validation error
            assert_matches!(
                PartialEntity::new(
                    r#"Show::"foo""#.parse().unwrap(),
                    Some(BTreeMap::from_iter([(
                        "isFree".into(),
                        RestrictedExpression::new_string("not a bool".into())
                    ),])),
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
            // Types
type Subscription = {
  tier: String
};
type Profile = {
  isKid: Bool
};

// Entities
entity FreeMember;
entity Subscriber = {
  subscription: Subscription,
  profile: Profile
};
entity Movie = {
  isFree: Bool,
  needsRentOrBuy: Bool,
  isOscarNominated: Bool
};
entity Show = {
  isFree: Bool,
  releaseDate: datetime,
  isEarlyAccess: Bool
};

// Actions for content in general
action watch
  appliesTo {
    principal: [FreeMember, Subscriber],
    resource: [Movie, Show],
    context: {
      now: {
        datetime: datetime,
        localTimeOffset: duration
      }
    }
  };

// Actions for movies only
action rent, buy
  appliesTo {
    principal: [FreeMember, Subscriber],
    resource: Movie,
    context: {
      now: {
        datetime: datetime
      }
    }
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
            // Subscriber Content Access (Shows)
@id("subscriber-content-access/show")
permit (
  principal is Subscriber,
  action == Action::"watch",
  resource is Show
)
unless
{ resource.isEarlyAccess && context.now.datetime < resource.releaseDate };

// Subscriber Content Access (Movies)
@id("subscriber-content-access/movie")
permit (
  principal is Subscriber,
  action == Action::"watch",
  resource is Movie
)
unless { resource.needsRentOrBuy };

// Free Content Access
@id("free-content-access")
permit (
  principal is FreeMember,
  action == Action::"watch",
  resource
)
when { resource.isFree };

// Promo: Rent/Buy Oscar-Nominated Movies Until the Oscars
@id("rent-buy-oscar-movie")
permit (
  principal is Subscriber,
  action in [Action::"rent", Action::"buy"],
  resource is Movie
)
when
{
  resource.isOscarNominated &&
  context.now.datetime >= datetime("2025-02-02T19:00:00-0500") &&
  context.now.datetime < datetime(
      "2025-03-02T19:00:00-0500"
    ) // Oscars Night
};

// Early Access (24h) to Shows for Premium Subscribers
@id("early-access-show")
permit (
  principal is Subscriber,
  action == Action::"watch",
  resource is Show
)
when
{
  resource.isEarlyAccess &&
  principal.subscription.tier == "premium" &&
  context.now.datetime >= resource.releaseDate.offset(duration("-24h"))
};

// Forbid Bedtime Access to Kid Profile
@id("forbid-bedtime-watch-kid-profile")
forbid (
  principal is Subscriber,
  action == Action::"watch",
  resource
)
when { principal.profile.isKid }
unless
{
  // `toTime()` returns the duration modulo one day (i.e., it ignores the "date"
  // component). Here, we use it to calculate the subscriber's local time and
  // compare the result against durations that represent 6:00AM and 9:00PM.
  duration("6h") <= context.now
    .datetime
    .offset
    (
      context.now.localTimeOffset
    )
    .toTime
    (
    ) &&
  context.now.datetime.offset(context.now.localTimeOffset).toTime() <= duration(
      "21h"
    )
};
            "#,
            )
            .unwrap()
        }

        #[track_caller]
        fn entities() -> Entities {
            Entities::from_json_value(
                serde_json::json!(
                                [
                    {
                        "uid": {
                            "type": "Subscriber",
                            "id": "Alice"
                        },
                        "attrs": {
                            "subscription" : {
                                "tier": "standard"
                            },
                            "profile" : {
                                "isKid": false
                            }
                        },
                        "parents": []
                    },
                    {
                        "uid": {
                            "type": "FreeMember",
                            "id": "Bob"
                        },
                        "attrs": {},
                        "parents": []
                    },
                    {
                        "uid": {
                            "type": "Subscriber",
                            "id": "Charlie"
                        },
                        "attrs": {
                            "subscription" : {
                                "tier": "premium"
                            },
                            "profile" : {
                                "isKid": false
                            }
                        },
                        "parents": []
                    },
                    {
                        "uid": {
                            "type": "Subscriber",
                            "id": "Dave"
                        },
                        "attrs": {
                            "subscription" : {
                                "tier": "standard"
                            },
                            "profile" : {
                                "isKid": true
                            }
                        },
                        "parents": []
                    },
                    {
                        "uid": {
                            "type": "Movie",
                            "id": "The Godparent"
                        },
                        "attrs": {
                            "isFree" : true,
                            "needsRentOrBuy" : false,
                            "isOscarNominated": true
                        },
                        "parents": []
                    },
                    {
                        "uid": {
                            "type": "Movie",
                            "id": "The Gleaming"
                        },
                        "attrs": {
                            "isFree" : false,
                            "needsRentOrBuy" : false,
                            "isOscarNominated": false
                        },
                        "parents": []
                    },
                    {
                        "uid": {
                            "type": "Movie",
                            "id": "Devilish"
                        },
                        "attrs": {
                            "isFree" : false,
                            "needsRentOrBuy" : true,
                            "isOscarNominated": true
                        },
                        "parents": []
                    },
                    {
                        "uid": {
                            "type": "Show",
                            "id": "Buddies"
                        },
                        "attrs": {
                            "isFree" : false,
                            "releaseDate": "2024-10-10",
                            "isEarlyAccess": false
                        },
                        "parents": []
                    },
                    {
                        "uid": {
                            "type": "Show",
                            "id": "Breach"
                        },
                        "attrs": {
                            "isFree" : false,
                            "releaseDate": "2025-02-21",
                            "isEarlyAccess": true
                        },
                        "parents": []
                    }
                ]
                            ),
                Some(&schema()),
            )
            .unwrap()
        }

        #[test]
        fn run_tpe() {
            let schema = schema();
            let request = PartialRequest::new(
                PartialEntityUid::from_concrete(r#"Subscriber::"Alice""#.parse().unwrap()),
                r#"Action::"watch""#.parse().unwrap(),
                PartialEntityUid::new("Movie".parse().unwrap(), None),
                Some(
                    Context::from_pairs([(
                        "now".into(),
                        RestrictedExpression::new_record([
                            (
                                "datetime".into(),
                                RestrictedExpression::from_str(r#"datetime("2025-07-22")"#)
                                    .unwrap(),
                            ),
                            (
                                "localTimeOffset".into(),
                                RestrictedExpression::from_str(r#"duration("0h")"#).unwrap(),
                            ),
                        ])
                        .unwrap(),
                    )])
                    .unwrap(),
                ),
                &schema,
            )
            .unwrap();
            let policies = policy_set();
            let partial_entities = PartialEntities::from_concrete(entities(), &schema).unwrap();

            let response = policies
                .tpe(&request, &partial_entities, &schema)
                .expect("tpe should succeed");

            assert_eq!(response.policies().count(), policies.num_of_policies());
            for p in response.residual_policies() {
                assert_matches!(p.action_constraint(), ActionConstraint::Any);
                assert_matches!(p.principal_constraint(), PrincipalConstraint::Any);
                assert_matches!(p.resource_constraint(), ResourceConstraint::Any);
            }
            assert_eq!(
                response
                    .residual_policies()
                    .next()
                    .unwrap()
                    .annotation("id")
                    .unwrap(),
                "subscriber-content-access/movie"
            );

            assert_eq!(response.decision(), None);
            assert!(response.reason().is_none());

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
                .unwrap(),
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
                .unwrap(),
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
                .unwrap(),
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
                .unwrap(),
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
entity Issue  = {
  "repo": Repository,
  "reporter": User,
};
entity Org  = {
  "members": UserGroup,
  "owners": UserGroup,
};
entity Repository  = {
  "admins": UserGroup,
  "maintainers": UserGroup,
  "readers": UserGroup,
  "triagers": UserGroup,
  "writers": UserGroup,
};
entity User in [UserGroup, Team];

action push, pull, fork appliesTo {
  principal: [User],
  resource: [Repository]
};
action assign_issue, delete_issue, edit_issue appliesTo {
  principal: [User],
  resource: [Issue]
};
action add_reader, add_writer, add_maintainer, add_admin, add_triager appliesTo {
  principal: [User],
  resource: [Repository]
};
            "#,
            )
            .unwrap()
        }

        fn policy_set() -> PolicySet {
            PolicySet::from_str(
                r#"
                //Actions for readers
permit (
  principal,
  action == Action::"pull",
  resource
)
when { principal in resource.readers };

permit (
  principal,
  action == Action::"fork",
  resource
)
when { principal in resource.readers };

permit (
  principal,
  action == Action::"delete_issue",
  resource
)
when { principal in resource.repo.readers && principal == resource.reporter };

permit (
  principal,
  action == Action::"edit_issue",
  resource
)
when { principal in resource.repo.readers && principal == resource.reporter };

//Actions for triagers
permit (
  principal,
  action == Action::"assign_issue",
  resource
)
when { principal in resource.repo.triagers };

//Actions for writers
permit (
  principal,
  action == Action::"push",
  resource
)
when { principal in resource.writers };

permit (
  principal,
  action == Action::"edit_issue",
  resource
)
when { principal in resource.repo.writers };

//Actions for maintainers
permit (
  principal,
  action == Action::"delete_issue",
  resource
)
when { principal in resource.repo.maintainers };

//Actions for admins
permit (
  principal,
  action in
    [Action::"add_reader",
     Action::"add_triager",
     Action::"add_writer",
     Action::"add_maintainer",
     Action::"add_admin"],
  resource
)
when { principal in resource.admins };
//We use the same permissions for org owners, and rely on placing them in the admins group for every repository in the org
//The other option is to duplicate all policies for the org base permissions (with a separate heirarchy for each org)
"#,
            )
            .unwrap()
        }

        #[track_caller]
        fn entities() -> Entities {
            Entities::from_json_value(serde_json::json!(

                [
    {
      "uid": { "__entity": { "type": "User", "id": "alice"} },
      "attrs": {},
      "parents": [{ "__entity": { "type": "UserGroup", "id": "common_knowledge_writers"} }, { "__entity": { "type": "UserGroup", "id": "uncommon_knowledge_writers"} } ]
    },
    {
      "uid": { "__entity": { "type": "User", "id": "jane"} },
      "attrs": {},
      "parents": [{ "__entity": { "type": "UserGroup", "id": "common_knowledge_maintainers"} },  { "__entity": { "type": "Team", "id": "team_that_can_read_everything"} }]
    },
    {
        "uid": { "__entity": { "type": "User", "id": "bob"} },
        "attrs": {},
        "parents": []
    },
    {
        "uid": { "__entity": { "type": "Repository", "id": "common_knowledge"} },
        "attrs": {
            "readers" : { "__entity": { "type": "UserGroup", "id": "common_knowledge_readers"} },
            "triagers" : { "__entity": { "type": "UserGroup", "id": "common_knowledge_triagers"} },
            "writers" : { "__entity": { "type": "UserGroup", "id": "common_knowledge_writers"} },
            "maintainers" : { "__entity": { "type": "UserGroup", "id": "common_knowledge_maintainers"} },
            "admins" : { "__entity": { "type": "UserGroup", "id": "common_knowledge_admins"} }
        },
        "parents": []
    },
    {
        "uid": { "__entity": { "type": "UserGroup", "id": "common_knowledge_readers"} },
        "attrs": {
        },
        "parents": [  ]
    },
    {
        "uid": { "__entity": { "type": "UserGroup", "id": "common_knowledge_triagers"} },
        "attrs": {
        },
        "parents": [ { "__entity": { "type": "UserGroup", "id": "common_knowledge_readers"} } ]
    },
    {
        "uid": { "__entity": { "type": "UserGroup", "id": "common_knowledge_writers"} },
        "attrs": {
        },
        "parents": [ {"__entity": { "type": "UserGroup", "id": "common_knowledge_triagers"}} ]
    },
    {
        "uid": { "__entity": { "type": "UserGroup", "id": "common_knowledge_maintainers"} },
        "attrs": {
        },
        "parents": [ {"__entity": { "type": "UserGroup", "id": "common_knowledge_writers"}} ]
    },
    {
        "uid": { "__entity": { "type": "UserGroup", "id": "common_knowledge_admins"} },
        "attrs": {
        },
        "parents": [ {"__entity": { "type": "UserGroup", "id": "common_knowledge_maintainers"}} ]
    },
    {
        "uid": { "__entity": { "type": "Repository", "id": "secret"} },
        "attrs": {
            "readers" : { "__entity": { "type": "UserGroup", "id": "secret_readers"} },
            "triagers" : { "__entity": { "type": "UserGroup", "id": "secret_triagers"} },
            "writers" : { "__entity": { "type": "UserGroup", "id": "secret_writers"} },
            "maintainers" : { "__entity": { "type": "UserGroup", "id": "secret_maintainers"} },
            "admins" : { "__entity": { "type": "UserGroup", "id": "secret_admins"} }
        },
        "parents": []
    },
    {
        "uid": { "__entity": { "type": "UserGroup", "id": "secret_readers"} },
        "attrs": {
        },
        "parents": [  ]
    },
    {
        "uid": { "__entity": { "type": "UserGroup", "id": "secret_triagers"} },
        "attrs": {
        },
        "parents": [ { "__entity": { "type": "UserGroup", "id": "secret_readers"} } ]
    },
    {
        "uid": { "__entity": { "type": "UserGroup", "id": "secret_writers"} },
        "attrs": {
        },
        "parents": [ {"__entity": { "type": "UserGroup", "id": "secret_triagers"}} ]
    },
    {
        "uid": { "__entity": { "type": "UserGroup", "id": "secret_maintainers"} },
        "attrs": {
        },
        "parents": [ {"__entity": { "type": "UserGroup", "id": "secret_writers"}} ]
    },
    {
        "uid": { "__entity": { "type": "UserGroup", "id": "secret_admins"} },
        "attrs": {
        },
        "parents": [ {"__entity": { "type": "UserGroup", "id": "secret_maintainers"}} ]
    },
    {
        "uid": { "__entity": { "type": "Repository", "id": "uncommon_knowledge"} },
        "attrs": {
            "readers" : { "__entity": { "type": "UserGroup", "id": "uncommon_knowledge_readers"} },
            "triagers" : { "__entity": { "type": "UserGroup", "id": "uncommon_knowledge_triagers"} },
            "writers" : { "__entity": { "type": "UserGroup", "id": "uncommon_knowledge_writers"} },
            "maintainers" : { "__entity": { "type": "UserGroup", "id": "uncommon_knowledge_maintainers"} },
            "admins" : { "__entity": { "type": "UserGroup", "id": "uncommon_knowledge_admins"} }
        },
        "parents": []
    },
    {
        "uid": { "__entity": { "type": "UserGroup", "id": "uncommon_knowledge_readers"} },
        "attrs": {
        },
        "parents": [  ]
    },
    {
        "uid": { "__entity": { "type": "UserGroup", "id": "uncommon_knowledge_triagers"} },
        "attrs": {
        },
        "parents": [ { "__entity": { "type": "UserGroup", "id": "uncommon_knowledge_readers"} } ]
    },
    {
        "uid": { "__entity": { "type": "UserGroup", "id": "uncommon_knowledge_writers"} },
        "attrs": {
        },
        "parents": [ {"__entity": { "type": "UserGroup", "id": "uncommon_knowledge_triagers"}} ]
    },
    {
        "uid": { "__entity": { "type": "UserGroup", "id": "uncommon_knowledge_maintainers"} },
        "attrs": {
        },
        "parents": [ {"__entity": { "type": "UserGroup", "id": "uncommon_knowledge_writers"}} ]
    },
    {
        "uid": { "__entity": { "type": "UserGroup", "id": "uncommon_knowledge_admins"} },
        "attrs": {
        },
        "parents": [ {"__entity": { "type": "UserGroup", "id": "uncommon_knowledge_maintainers"}} ]
    },
    {
        "uid": { "__entity": { "type": "Team", "id": "team_that_can_read_everything"} },
        "attrs": {},
        "parents": [{ "__entity": { "type": "UserGroup", "id": "common_knowledge_readers"} }, { "__entity": { "type": "UserGroup", "id": "secret_readers"} }, { "__entity": { "type": "UserGroup", "id": "uncommon_knowledge_readers"} }]
    },
]
            ), Some(&schema())).unwrap()
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

        #[test]
        fn test_is_authorized_vs_is_authorized_batched() {
            use crate::{Authorizer, Request};

            let schema = schema();
            let policies = policy_set();
            let entities = entities();
            let authorizer = Authorizer::new();

            // Create a set of test requests
            let test_requests = vec![
                // Request 1: alice can push to common_knowledge (should be allowed)
                Request::new(
                    r#"User::"alice""#.parse().unwrap(),
                    r#"Action::"push""#.parse().unwrap(),
                    r#"Repository::"common_knowledge""#.parse().unwrap(),
                    Context::empty(),
                    Some(&schema),
                )
                .unwrap(),
                // Request 2: jane can pull from secret (should be allowed)
                Request::new(
                    r#"User::"jane""#.parse().unwrap(),
                    r#"Action::"pull""#.parse().unwrap(),
                    r#"Repository::"secret""#.parse().unwrap(),
                    Context::empty(),
                    Some(&schema),
                )
                .unwrap(),
                // Request 3: bob cannot push to common_knowledge (should be denied)
                Request::new(
                    r#"User::"bob""#.parse().unwrap(),
                    r#"Action::"push""#.parse().unwrap(),
                    r#"Repository::"common_knowledge""#.parse().unwrap(),
                    Context::empty(),
                    Some(&schema),
                )
                .unwrap(),
                // Request 4: alice can fork common_knowledge (should be allowed)
                Request::new(
                    r#"User::"alice""#.parse().unwrap(),
                    r#"Action::"fork""#.parse().unwrap(),
                    r#"Repository::"common_knowledge""#.parse().unwrap(),
                    Context::empty(),
                    Some(&schema),
                )
                .unwrap(),
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
                    r#"permit(principal, action, resource) when { principal.nonexistent_attr == "value" };"#
                ).unwrap();

            let request = Request::new(
                EntityUid::from_str("User::\"alice\"").unwrap(),
                EntityUid::from_str("Action::\"push\"").unwrap(),
                EntityUid::from_str("Repository::\"repo\"").unwrap(),
                Context::empty(),
                Some(&schema),
            )
            .unwrap();

            let entities = entities();
            let mut loader = TestEntityLoader::new(&entities);
            let result = policies.is_authorized_batched(&request, &schema, &mut loader, 10);

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

            let request = Request::new(
                r#"User::"alice""#.parse().unwrap(),
                r#"Action::"push""#.parse().unwrap(),
                r#"Repository::"common_knowledge""#.parse().unwrap(),
                Context::empty(),
                Some(&schema),
            )
            .unwrap();

            let mut loader = InvalidEntityLoader;
            let result = pset.is_authorized_batched(&request, &schema, &mut loader, 10);

            assert_matches!(result, Err(BatchedEvalError::Entities(_)));
        }

        #[test]
        #[cfg(feature = "partial-eval")]
        fn test_batched_evaluation_error_partial_entity() {
            use cedar_policy_core::{ast::PartialValueToValueError, tpe::err::EntitiesError};

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

            let request = Request::new(
                r#"User::"alice""#.parse().unwrap(),
                r#"Action::"push""#.parse().unwrap(),
                r#"Repository::"common_knowledge""#.parse().unwrap(),
                Context::empty(),
                Some(&schema),
            )
            .unwrap();

            let mut loader = PartialEntityLoader;
            let result = pset.is_authorized_batched(&request, &schema, &mut loader, 10);

            assert_matches!(
                result,
                Err(BatchedEvalError::Entities(
                    EntitiesError::PartialValueToValue(PartialValueToValueError::ContainsUnknown(
                        _
                    ))
                ))
            );
        }

        #[test]
        fn test_batched_evaluation_error_insufficient_iters() {
            let schema = schema();
            let policies = policy_set();
            let entities = entities();

            let request = Request::new(
                r#"User::"alice""#.parse().unwrap(),
                r#"Action::"push""#.parse().unwrap(),
                r#"Repository::"common_knowledge""#.parse().unwrap(),
                Context::empty(),
                Some(&schema),
            )
            .unwrap();

            let mut loader = TestEntityLoader::new(&entities);
            let result = policies.is_authorized_batched(&request, &schema, &mut loader, 0);

            assert_matches!(result, Err(BatchedEvalError::InsufficientIterations(_)));
        }
    }

    mod trivial {
        use cedar_policy_core::authorizer::Decision;
        use itertools::Itertools;

        use crate::{
            Context, Entities, PartialEntities, PartialEntityUid, PartialRequest, PolicyId,
            PolicySet, PrincipalQueryRequest, ResourceQueryRequest, Schema,
        };
        use std::{i64, str::FromStr};

        fn schema() -> Schema {
            Schema::from_str("entity P, R; action A appliesTo { principal: P, resource: R };")
                .unwrap()
        }

        fn entities() -> Entities {
            Entities::from_json_value(
                serde_json::json!([
                    { "uid": { "__entity": { "type": "P", "id": ""} }, "attrs": {}, "parents": [] },
                    { "uid": { "__entity": { "type": "R", "id": ""} }, "attrs": {}, "parents": [] },
                ]),
                None,
            )
            .unwrap()
        }

        #[test]
        fn trivial_permit_tpe() {
            let schema = schema();
            let partial_entities = PartialEntities::from_concrete(entities(), &schema).unwrap();
            let req = PartialRequest::new(
                PartialEntityUid::new("P".parse().unwrap(), None),
                r#"Action::"A""#.parse().unwrap(),
                PartialEntityUid::new("R".parse().unwrap(), None),
                None,
                &schema,
            )
            .unwrap();
            let response = PolicySet::from_str(r"permit(principal, action, resource);")
                .unwrap()
                .tpe(&req, &partial_entities, &schema)
                .unwrap();
            assert_eq!(response.decision(), Some(Decision::Allow));
            assert_eq!(
                response.reason().unwrap().collect::<Vec<_>>(),
                vec![&PolicyId::new("policy0")]
            );
        }

        #[test]
        fn trivial_permit_query_principal() {
            let schema = schema();
            let entities = entities();
            let req = PrincipalQueryRequest::new(
                "P".parse().unwrap(),
                r#"Action::"A""#.parse().unwrap(),
                r#"R::"""#.parse().unwrap(),
                Context::empty(),
                &schema,
            )
            .unwrap();

            let principals = PolicySet::from_str(r#"permit(principal, action, resource);"#)
                .unwrap()
                .query_principal(&req, &entities, &schema)
                .unwrap()
                .collect_vec();
            assert_eq!(&principals, &[r#"P::"""#.parse().unwrap()]);
        }

        #[test]
        fn trivial_permit_query_resource() {
            let schema = schema();
            let entities = entities();
            let req = ResourceQueryRequest::new(
                r#"P::"""#.parse().unwrap(),
                r#"Action::"A""#.parse().unwrap(),
                "R".parse().unwrap(),
                Context::empty(),
                &schema,
            )
            .unwrap();

            let resources = PolicySet::from_str(r#"permit(principal, action, resource);"#)
                .unwrap()
                .query_resource(&req, &entities, &schema)
                .unwrap()
                .collect_vec();
            assert_eq!(&resources, &[r#"R::"""#.parse().unwrap()]);
        }

        #[test]
        fn trivial_forbid_tpe() {
            let schema = schema();
            let partial_entities = PartialEntities::from_concrete(entities(), &schema).unwrap();
            let req = PartialRequest::new(
                PartialEntityUid::new("P".parse().unwrap(), None),
                r#"Action::"A""#.parse().unwrap(),
                PartialEntityUid::new("R".parse().unwrap(), None),
                None,
                &schema,
            )
            .unwrap();
            let response = PolicySet::from_str(r#"forbid(principal, action, resource);"#)
                .unwrap()
                .tpe(&req, &partial_entities, &schema)
                .unwrap();
            assert_eq!(response.decision(), Some(Decision::Deny));
            assert_eq!(
                response.reason().unwrap().collect::<Vec<_>>(),
                vec![&PolicyId::new("policy0")]
            );
            assert_eq!(
                response.true_forbids().collect::<Vec<_>>(),
                vec![&PolicyId::new("policy0")]
            );
        }

        #[test]
        fn trivial_forbid_query_principal() {
            let schema = schema();
            let entities = entities();
            let req = PrincipalQueryRequest::new(
                "P".parse().unwrap(),
                r#"Action::"A""#.parse().unwrap(),
                r#"R::"""#.parse().unwrap(),
                Context::empty(),
                &schema,
            )
            .unwrap();

            let principals = PolicySet::from_str(r#"forbid(principal, action, resource);"#)
                .unwrap()
                .query_principal(&req, &entities, &schema)
                .unwrap()
                .collect_vec();
            assert_eq!(&principals, &[]);
        }

        #[test]
        fn trivial_forbid_query_resource() {
            let schema = schema();
            let entities = entities();
            let req = ResourceQueryRequest::new(
                r#"P::"""#.parse().unwrap(),
                r#"Action::"A""#.parse().unwrap(),
                "R".parse().unwrap(),
                Context::empty(),
                &schema,
            )
            .unwrap();

            let resources = PolicySet::from_str(r#"forbid(principal, action, resource);"#)
                .unwrap()
                .query_resource(&req, &entities, &schema)
                .unwrap()
                .collect_vec();
            assert_eq!(&resources, &[]);
        }

        #[test]
        fn error_tpe() {
            let schema = schema();
            let partial_entities = PartialEntities::from_concrete(entities(), &schema).unwrap();
            let req = PartialRequest::new(
                PartialEntityUid::new("P".parse().unwrap(), None),
                r#"Action::"A""#.parse().unwrap(),
                PartialEntityUid::new("R".parse().unwrap(), None),
                None,
                &schema,
            )
            .unwrap();
            let response = PolicySet::from_str(&format!(
                r#"permit(principal, action, resource) when {{ ({} + 1) == 0 || true }};"#,
                i64::MAX
            ))
            .unwrap()
            .tpe(&req, &partial_entities, &schema)
            .unwrap();
            assert_eq!(response.decision(), Some(Decision::Deny));
            assert_eq!(
                response.reason().unwrap().collect::<Vec<_>>(),
                Vec::<&PolicyId>::new()
            );
        }

        #[test]
        fn error_query_principal() {
            let schema = schema();
            let entities = entities();
            let req = PrincipalQueryRequest::new(
                "P".parse().unwrap(),
                r#"Action::"A""#.parse().unwrap(),
                r#"R::"""#.parse().unwrap(),
                Context::empty(),
                &schema,
            )
            .unwrap();

            let principals = PolicySet::from_str(&format!(
                r#"permit(principal, action, resource) when {{ ({} + 1) == 0 || true }};"#,
                i64::MAX
            ))
            .unwrap()
            .query_principal(&req, &entities, &schema)
            .unwrap()
            .collect_vec();
            assert_eq!(&principals, &[]);
        }

        #[test]
        fn error_query_resource() {
            let schema = schema();
            let entities = entities();
            let req = ResourceQueryRequest::new(
                r#"P::"""#.parse().unwrap(),
                r#"Action::"A""#.parse().unwrap(),
                "R".parse().unwrap(),
                Context::empty(),
                &schema,
            )
            .unwrap();

            let resources = PolicySet::from_str(&format!(
                r#"permit(principal, action, resource) when {{ ({} + 1) == 0 || true }};"#,
                i64::MAX
            ))
            .unwrap()
            .query_resource(&req, &entities, &schema)
            .unwrap()
            .collect_vec();
            assert_eq!(&resources, &[]);
        }

        #[test]
        fn empty_tpe() {
            let schema = schema();
            let partial_entities = PartialEntities::from_concrete(entities(), &schema).unwrap();
            let req = PartialRequest::new(
                PartialEntityUid::new("P".parse().unwrap(), None),
                r#"Action::"A""#.parse().unwrap(),
                PartialEntityUid::new("R".parse().unwrap(), None),
                None,
                &schema,
            )
            .unwrap();
            let response = PolicySet::from_str(r#""#)
                .unwrap()
                .tpe(&req, &partial_entities, &schema)
                .unwrap();
            assert_eq!(response.decision(), Some(Decision::Deny));
            assert_eq!(
                response.reason().unwrap().collect::<Vec<_>>(),
                Vec::<&PolicyId>::new()
            );
        }

        #[test]
        fn empty_query_principal() {
            let schema = schema();
            let entities = entities();
            let req = PrincipalQueryRequest::new(
                "P".parse().unwrap(),
                r#"Action::"A""#.parse().unwrap(),
                r#"R::"""#.parse().unwrap(),
                Context::empty(),
                &schema,
            )
            .unwrap();

            let principals = PolicySet::from_str(r#""#)
                .unwrap()
                .query_principal(&req, &entities, &schema)
                .unwrap()
                .collect_vec();
            assert_eq!(&principals, &[]);
        }

        #[test]
        fn empty_query_resource() {
            let schema = schema();
            let entities = entities();
            let req = ResourceQueryRequest::new(
                r#"P::"""#.parse().unwrap(),
                r#"Action::"A""#.parse().unwrap(),
                "R".parse().unwrap(),
                Context::empty(),
                &schema,
            )
            .unwrap();

            let resources = PolicySet::from_str(r#""#)
                .unwrap()
                .query_resource(&req, &entities, &schema)
                .unwrap()
                .collect_vec();
            assert_eq!(&resources, &[]);
        }
    }

    mod response_iterators {
        use std::{i64, str::FromStr};

        use cedar_policy_core::authorizer::Decision;

        use crate::{
            PartialEntities, PartialEntityUid, PartialRequest, PolicyId, PolicySet, Schema,
        };

        #[test]
        fn all_policy_categories() {
            let schema = Schema::from_str(
                "entity P, R; action A appliesTo { principal: P, resource: R, context: { flag: Bool } };",
            )
            .unwrap();
            let req = PartialRequest::new(
                PartialEntityUid::new("P".parse().unwrap(), None),
                r#"Action::"A""#.parse().unwrap(),
                PartialEntityUid::new("R".parse().unwrap(), None),
                None,
                &schema,
            )
            .unwrap();

            let policies = PolicySet::from_str(&format!(
                r#"
                permit(principal, action, resource);
                permit(principal, action, resource) when {{ false }};
                permit(principal, action, resource) when {{ ({} + 1) == 0 || true }};
                permit(principal, action, resource) when {{ context.flag }};
                forbid(principal, action, resource);
                forbid(principal, action, resource) when {{ false }};
                forbid(principal, action, resource) when {{ ({} + 1) == 0 || true }};
                forbid(principal, action, resource) when {{ context.flag }};
                "#,
                i64::MAX,
                i64::MAX
            ))
            .unwrap();

            let entities = PartialEntities::empty();
            let response = policies.tpe(&req, &entities, &schema).unwrap();

            assert_eq!(response.decision(), Some(Decision::Deny));
            assert_eq!(
                response.reason().unwrap().collect::<Vec<_>>(),
                vec![&PolicyId::new("policy4")]
            );

            assert_eq!(
                response.true_permits().collect::<Vec<_>>(),
                vec![&PolicyId::new("policy0")]
            );
            assert_eq!(
                response.false_permits().collect::<Vec<_>>(),
                vec![&PolicyId::new("policy1")]
            );
            assert_eq!(
                response.error_permits().collect::<Vec<_>>(),
                vec![&PolicyId::new("policy2")]
            );
            assert_eq!(
                response.residual_permits().collect::<Vec<_>>(),
                vec![&PolicyId::new("policy3")]
            );
            assert_eq!(
                response.true_forbids().collect::<Vec<_>>(),
                vec![&PolicyId::new("policy4")]
            );
            assert_eq!(
                response.false_forbids().collect::<Vec<_>>(),
                vec![&PolicyId::new("policy5")]
            );
            assert_eq!(
                response.error_forbids().collect::<Vec<_>>(),
                vec![&PolicyId::new("policy6")]
            );
            assert_eq!(
                response.residual_forbids().collect::<Vec<_>>(),
                vec![&PolicyId::new("policy7")]
            );
        }
    }

    mod query_action {
        use cedar_policy_core::authorizer::Decision;

        use crate::{
            ActionQueryRequest, Context, PartialEntities, PartialEntityUid, PolicySet, Schema,
        };
        use similar_asserts::assert_eq;
        use std::str::FromStr;

        #[test]
        fn test() {
            let policies = PolicySet::from_str(
                r#"
            // Edit might be alowed, depending on context
            permit(principal, action == Action::"edit", resource)
            when {
                context.ip.isInRange(resource.allowed_edit_range)
            };

            // We pass a concrete resource, so we know this will be allowed
            permit(principal, action == Action::"view", resource)
            when {
                resource.public
            };

            // never allowed for any request
            forbid(principal, action == Action::"delete", resource);

            // allowed for this action, but it doesn't apply to the request types
            permit(principal, action == Action::"not_on_photo", resource);
        "#,
            )
            .unwrap();
            let schema = Schema::from_str(
                "
            entity User, Other;
            entity Photo {
              public: Bool,
              allowed_edit_range: ipaddr,
            };
            action view, edit, delete appliesTo {
              principal: User,
              resource: Photo,
              context: {
                ip: ipaddr,
              }
            };
            action not_on_photo appliesTo {
                principal: User,
                resource: Other
            };
        ",
            )
            .unwrap();
            let entities = PartialEntities::from_json_value(
                serde_json::json!([
                    {
                        "uid": { "__entity": { "type": "Photo", "id": "vacation.jpg"} },
                        "attrs": {
                            "public": true,
                            "allowed_edit_range": "192.0.2.0/24"
                        },
                        "parents": []
                    },
                ]),
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
            let schema = Schema::from_str(
                "entity User, Photo; action view appliesTo { principal: User, resource: Photo};",
            )
            .unwrap();
            let entities = PartialEntities::empty();

            let request = ActionQueryRequest::new(
                PartialEntityUid::from_concrete(r#"User::"alice""#.parse().unwrap()),
                PartialEntityUid::from_concrete(r#"Photo::"vacation.jpg""#.parse().unwrap()),
                None,
                schema,
            )
            .unwrap();

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

            let request = ActionQueryRequest::new(
                PartialEntityUid::from_concrete(r#"User::"alice""#.parse().unwrap()),
                PartialEntityUid::from_concrete(r#"Photo::"vacation.jpg""#.parse().unwrap()),
                None,
                schema,
            )
            .unwrap();

            let actions: Vec<_> = policies
                .query_action(&request, &entities)
                .unwrap()
                .collect();
            assert_eq!(actions, vec![(&r#"Action::"view""#.parse().unwrap(), None)]);
        }

        #[test]
        fn forbidden_action() {
            let policies = PolicySet::from_str("forbid(principal, action, resource);").unwrap();
            let schema = Schema::from_str(
                "entity User, Photo; action view appliesTo { principal: User, resource: Photo};",
            )
            .unwrap();
            let entities = PartialEntities::empty();

            let request = ActionQueryRequest::new(
                PartialEntityUid::from_concrete(r#"User::"alice""#.parse().unwrap()),
                PartialEntityUid::from_concrete(r#"Photo::"vacation.jpg""#.parse().unwrap()),
                None,
                schema,
            )
            .unwrap();

            let actions: Vec<_> = policies
                .query_action(&request, &entities)
                .unwrap()
                .collect();
            assert_eq!(actions, Vec::new(),);
        }

        #[test]
        fn invalid_permitted_action() {
            let policies = PolicySet::from_str("permit(principal, action, resource);").unwrap();
            let schema = Schema::from_str("entity User, Photo, Other; action view appliesTo { principal: User, resource: Other};").unwrap();
            let entities = PartialEntities::empty();

            let request = ActionQueryRequest::new(
                PartialEntityUid::from_concrete(r#"User::"alice""#.parse().unwrap()),
                PartialEntityUid::from_concrete(r#"Photo::"vacation.jpg""#.parse().unwrap()),
                None,
                schema,
            )
            .unwrap();

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

            let request = ActionQueryRequest::new(
                PartialEntityUid::from_concrete(r#"User::"alice""#.parse().unwrap()),
                PartialEntityUid::from_concrete(r#"Photo::"vacation.jpg""#.parse().unwrap()),
                Some(Context::empty()),
                schema,
            )
            .unwrap();

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

            let request = ActionQueryRequest::new(
                PartialEntityUid::from_concrete(r#"User::"alice""#.parse().unwrap()),
                PartialEntityUid::from_concrete(r#"Photo::"vacation.jpg""#.parse().unwrap()),
                None,
                schema,
            )
            .unwrap();

            let actions: Vec<_> = policies
                .query_action(&request, &entities)
                .unwrap()
                .collect();
            assert_eq!(actions, Vec::new());
        }

        #[test]
        fn permitted_action_error_permit() {
            let policies = PolicySet::from_str(&format!("permit(principal, action, resource);permit(principal, action, resource) when {{ {} + 1 == 0 || true }};", i64::MAX)).unwrap();
            let schema = Schema::from_str(
                "entity User, Photo; action view appliesTo { principal: User, resource: Photo};",
            )
            .unwrap();
            let entities = PartialEntities::empty();

            let request = ActionQueryRequest::new(
                PartialEntityUid::from_concrete(r#"User::"alice""#.parse().unwrap()),
                PartialEntityUid::from_concrete(r#"Photo::"vacation.jpg""#.parse().unwrap()),
                None,
                schema,
            )
            .unwrap();

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
            let schema = Schema::from_str(
                "entity User, Photo; action view appliesTo { principal: User, resource: Photo};",
            )
            .unwrap();
            let entities = PartialEntities::empty();

            let request = ActionQueryRequest::new(
                PartialEntityUid::from_concrete(r#"User::"alice""#.parse().unwrap()),
                PartialEntityUid::from_concrete(r#"Photo::"vacation.jpg""#.parse().unwrap()),
                None,
                schema,
            )
            .unwrap();

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
            let schema = Schema::from_str(
                "entity User, Photo; action view appliesTo { principal: User, resource: Photo};",
            )
            .unwrap();
            let entities = PartialEntities::empty();

            let request = ActionQueryRequest::new(
                PartialEntityUid::from_concrete(r#"User::"alice""#.parse().unwrap()),
                PartialEntityUid::from_concrete(r#"Photo::"vacation.jpg""#.parse().unwrap()),
                None,
                schema,
            )
            .unwrap();

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
    fn residual_error_to_pst_and_json() {
        use cedar_policy_core::pst;
        use std::str::FromStr;

        let (schema, _) = crate::Schema::from_cedarschema_str(
            r#"
            entity User = { score: Long };
            entity Document;
            action Read appliesTo {
                principal: [User],
                resource: [Document],
                context: { flag: Bool },
            };
            "#,
        )
        .unwrap();

        // Integer overflow: principal.score + 9223372036854775807 will error
        let policies = crate::PolicySet::from_str(
            r#"
            permit(
                principal is User,
                action == Action::"Read",
                resource is Document
            ) when {
                context.flag &&
                principal.score + 9223372036854775807 > 0
            };
            "#,
        )
        .unwrap();

        let entities = crate::Entities::from_json_value(
            serde_json::json!([
                {
                    "uid": { "type": "User", "id": "u1" },
                    "attrs": { "score": 1 },
                    "parents": []
                },
                {
                    "uid": { "type": "Document", "id": "d1" },
                    "attrs": {},
                    "parents": []
                }
            ]),
            Some(&schema),
        )
        .unwrap();

        let partial_entities = crate::PartialEntities::from_concrete(entities, &schema).unwrap();

        // Context is unknown — forces a residual, but the arithmetic overflows
        let request = crate::PartialRequest::new(
            crate::PartialEntityUid::from_concrete(r#"User::"u1""#.parse().unwrap()),
            r#"Action::"Read""#.parse().unwrap(),
            crate::PartialEntityUid::from_concrete(r#"Document::"d1""#.parse().unwrap()),
            None,
            &schema,
        )
        .unwrap();

        let response = policies
            .tpe(&request, &partial_entities, &schema)
            .expect("tpe should succeed");
        // There should be exactly one nontrivial residual
        let residual_policies: Vec<_> = response.residual_policies().collect();
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

        // We can serialize a policy with residual error to json
        let json_res = policy.to_json();
        assert!(json_res.is_ok());
        assert!(json_res.unwrap().to_string().contains(r#"{"error":[]}"#));

        // We can also convert it to PST
        let pst_policy = policy.to_pst().expect("to_pst should succeed");
        let clauses = pst_policy.body().clauses();
        assert_eq!(clauses.len(), 1);

        let expr = match &clauses[0] {
            pst::Clause::When(e) => e,
            pst::Clause::Unless(_) => panic!("expected when clause"),
        };

        // The expression should contain a ResidualError node (from
        // integer overflow in principal.score + MAX_LONG)
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
            assert_eq!(
                response.reason().unwrap().collect::<Vec<_>>(),
                vec![&PolicyId::new("l")]
            );
            assert_eq!(
                response.true_permits().collect::<Vec<_>>(),
                vec![&PolicyId::new("l")]
            );
        }

        #[test]
        fn templates_no_links_deny() {
            let schema = schema();
            let policies = template_policy_set();

            let request = partial_req();
            let es = PartialEntities::empty();
            let response = policies.tpe(&request, &es, &schema).unwrap();

            assert_eq!(response.decision(), Some(Decision::Deny));
            assert_eq!(
                response.reason().unwrap().collect::<Vec<_>>(),
                Vec::<&PolicyId>::new()
            );
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
            assert_eq!(
                response.reason().unwrap().collect::<Vec<_>>(),
                Vec::<&PolicyId>::new()
            );
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

            let residuals: Vec<_> = response.residual_policies().collect();
            assert_eq!(residuals[0].to_pst().unwrap().body(), expected.body());
            assert_eq!(response.decision(), None);
            assert!(response.reason().is_none());
            assert_eq!(residuals.len(), 1);
        }
    }
}
