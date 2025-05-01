use std::{collections::BTreeMap, sync::Arc};

use anyhow::Ok;
use cedar_policy_core::ast::{EntityUID, Value};
use cedar_policy_validator::{types::RequestEnv, ValidationMode, ValidatorSchema};
use smol_str::SmolStr;

/// Represents the request tuple <P, A, R, C> (see the Cedar design doc).
#[derive(Debug, Clone)]
pub struct PartialRequest {
    /// Principal associated with the request
    pub principal: Option<EntityUID>,

    /// Action associated with the request
    pub action: EntityUID,

    /// Resource associated with the request
    pub resource: Option<EntityUID>,

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
            .find(|env| env.action_entity_uid().unwrap() == &self.action)
            .ok_or(anyhow::anyhow!("cannot find matching request environment"))
    }

    pub(crate) fn validate_request(&self, schema: &ValidatorSchema) -> anyhow::Result<()> {
        let env = self.find_request_env(schema)?;
        Ok(())
    }
}
