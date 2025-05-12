use std::{collections::BTreeMap, sync::Arc};

use anyhow::Ok;
use cedar_policy_core::{
    ast::{Eid, EntityType, EntityUID, Value},
    entities::conformance::validate_euid,
};
use cedar_policy_validator::{types::RequestEnv, CoreSchema, ValidationMode, ValidatorSchema};
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
    fn try_from(value: PartialEntityUID) -> std::result::Result<Self, Self::Error> {
        if let Some(eid) = value.eid {
            std::result::Result::Ok(EntityUID::from_components(value.ty, eid, None))
        } else {
            Err(())
        }
    }
}

/// Represents the request tuple <P, A, R, C> (see the Cedar design doc).
#[derive(Debug, Clone)]
pub struct PartialRequest {
    /// Principal associated with the request
    pub principal: PartialEntityUID,

    /// Action associated with the request
    pub action: EntityUID,

    /// Resource associated with the request
    pub resource: PartialEntityUID,

    /// Context associated with the request.
    /// `None` means that variable will result in a residual for partial evaluation.
    pub context: Option<Arc<BTreeMap<SmolStr, Value>>>,
}

impl PartialRequest {
    pub(crate) fn find_request_env<'s>(
        &self,
        schema: &'s ValidatorSchema,
    ) -> anyhow::Result<RequestEnv<'s>> {
        schema
            .unlinked_request_envs(ValidationMode::Strict)
            .find(|env| {
                env.action_entity_uid().unwrap() == &self.action
                    && env.principal_entity_type() == Some(&self.principal.ty)
                    && env.resource_entity_type() == Some(&self.resource.ty)
            })
            .ok_or(anyhow::anyhow!("cannot find matching request environment"))
    }

    pub(crate) fn validate_request(&self, schema: &ValidatorSchema) -> anyhow::Result<()> {
        let env = self.find_request_env(schema)?;
        let core_schema = CoreSchema::new(schema);
        if let Some(action_id) = schema.get_action_id(&self.action) {
            if !action_id.is_applicable_principal_type(&self.principal.ty) {
                return Err(anyhow::anyhow!("principal type not applicable"));
            }
            if !action_id.is_applicable_resource_type(&self.resource.ty) {
                return Err(anyhow::anyhow!("resource type not applicable"));
            }
            Ok(())
        } else {
            return Err(anyhow::anyhow!("action not found"));
        }
    }
}
