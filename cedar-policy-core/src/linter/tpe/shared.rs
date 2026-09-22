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

//! Helpers shared by the TPE-based lints: iterating the schema's request
//! environments and running type-aware partial evaluation on a fully-unknown
//! request in each, plus scope-matching predicates that more than one lint uses.

use crate::{
    ast::{ActionConstraint, EntityType, EntityUID, PrincipalOrResourceConstraint},
    tpe::{
        entities::PartialEntities,
        is_authorized,
        request::{PartialEntityUID, PartialRequest},
        response::Response,
    },
    validator::{ValidationMode, ValidatorSchema},
};

/// For each request environment the schema admits, run TPE on a *fully unknown*
/// request (unknown principal/resource of the environment's types, unknown
/// context) and hand the environment and the [`Response`] to `f`.
///
/// This is the shape all three TPE lints share: enumerate `(principal, action,
/// resource)` triples, build the unknown [`PartialRequest`], and evaluate. An
/// environment whose request cannot be built, or whose evaluation errors, is
/// skipped. Each lint supplies only what to do with the response.
pub(super) fn for_each_env(
    policies: &crate::ast::PolicySet,
    schema: &ValidatorSchema,
    mut f: impl FnMut(&EntityType, &EntityUID, &EntityType, &Response<'_>),
) {
    for env in schema.unlinked_request_envs(ValidationMode::Strict) {
        let (Some(p), Some(a), Some(r)) = (
            env.principal_entity_type(),
            env.action_entity_uid(),
            env.resource_entity_type(),
        ) else {
            continue;
        };
        let request = match PartialRequest::new(
            PartialEntityUID {
                ty: p.clone(),
                eid: None,
            },
            a.clone(),
            PartialEntityUID {
                ty: r.clone(),
                eid: None,
            },
            None,
            schema,
        ) {
            Ok(req) => req,
            Err(_) => continue,
        };
        let entities = PartialEntities::new();
        let Ok(response) = is_authorized(policies, &request, &entities, schema) else {
            continue;
        };
        f(p, a, r, &response);
    }
}

/// Does an action scope constraint admit `action`?
pub(super) fn action_matches(constraint: &ActionConstraint, action: &EntityUID) -> bool {
    match constraint {
        ActionConstraint::Any => true,
        ActionConstraint::Eq(a) => a.as_ref() == action,
        ActionConstraint::In(as_) => as_.iter().any(|a| a.as_ref() == action),
        #[cfg(feature = "tolerant-ast")]
        ActionConstraint::ErrorConstraint => false,
    }
}

/// Is a principal/resource scope constraint *definitely* satisfied by every entity
/// of type `ty` — decidable from the type alone, leaving no residual?
pub(super) fn pr_admits(constraint: &PrincipalOrResourceConstraint, ty: &EntityType) -> bool {
    use PrincipalOrResourceConstraint as C;
    match constraint {
        // Unconstrained, or an `is` on the env's exact type: settled by the type.
        C::Any => true,
        C::Is(t) => t.as_ref() == ty,
        // `is in` has an `is` part settled by type but an `in` part that is an
        // entity-level residual; `==`/`in` against a specific entity are residuals
        // too. None is definitely true from the type alone.
        C::IsIn(_, _) | C::Eq(_) | C::In(_) => false,
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use crate::extensions::Extensions;
    use crate::validator::ValidatorSchema;

    /// The schema the TPE lint tests share.
    pub(crate) const SCHEMA: &str = r#"
        entity User;
        entity Admin;
        entity Photo;
        entity Album;
        action view appliesTo { principal: [User, Admin], resource: [Photo, Album] };
        action edit appliesTo { principal: [User], resource: [Photo], context: { n: Long } };
    "#;

    /// Parse [`SCHEMA`].
    pub(crate) fn schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(SCHEMA, Extensions::all_available())
            .expect("schema parse")
            .0
    }
}
