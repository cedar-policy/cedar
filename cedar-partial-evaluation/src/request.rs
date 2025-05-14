use std::{collections::BTreeMap, sync::Arc};

use anyhow::{anyhow, Ok};
use cedar_policy_core::{
    ast::{Eid, EntityType, EntityUID, PartialValue, Value},
    entities::conformance::{is_valid_enumerated_entity, validate_euids_in_partial_value},
    extensions::Extensions,
};
use cedar_policy_validator::{
    types::RequestEnv, CoreSchema, RequestValidationError, ValidationMode, ValidatorEntityType,
    ValidatorEntityTypeKind, ValidatorSchema,
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
        let core_schema = CoreSchema::new(schema);
        if let Some(action_id) = schema.get_action_id(&self.action) {
            if !action_id.is_applicable_principal_type(&self.principal.ty) {
                return Err(anyhow::anyhow!("principal type not applicable"));
            }
            if !action_id.is_applicable_resource_type(&self.resource.ty) {
                return Err(anyhow::anyhow!("resource type not applicable"));
            }
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
                return Err(anyhow::anyhow!("principal type not found"));
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
                return Err(anyhow::anyhow!("resource type not found"));
            }
            if let Some(m) = &self.context {
                let ctx = PartialValue::Value(Value::record_arc(m.clone(), None));
                validate_euids_in_partial_value(&core_schema, &ctx)
                    .map_err(RequestValidationError::InvalidEnumEntity)?;
                let expected_context_ty = action_id.context_type();
                if !expected_context_ty
                    .typecheck_partial_value(&ctx, Extensions::all_available())
                    .map_err(RequestValidationError::TypeOfContext)?
                {
                    return Err(anyhow!("invalid context value type"));
                }
            }
            Ok(())
        } else {
            Err(anyhow::anyhow!("action not found"))
        }
    }
}
