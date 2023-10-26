//! This module contains the definition of `ValidatorActionId` and the types it relies on

use cedar_policy_core::{
    ast::{EntityType, EntityUID, RestrictedExpr},
    transitive_closure::TCNode,
};
use serde::Serialize;
use smol_str::SmolStr;
use std::collections::{HashMap, HashSet};

use crate::types::{AttributeType, Attributes};

/// Contains information about actions used by the validator.  The contents of
/// the struct are the same as the schema entity type structure, but the
/// `member_of` relation is reversed to instead be `descendants`.
#[derive(Clone, Debug, Serialize)]
pub struct ValidatorActionId {
    /// The name of the action.
    pub(crate) name: EntityUID,

    /// The principals and resources that the action can be applied to.
    #[serde(rename = "appliesTo")]
    pub(crate) applies_to: ValidatorApplySpec,

    /// The set of actions that can be members of this action. When this
    /// structure is initially constructed, the field will contain direct
    /// children, but it will be updated to contain the closure of all
    /// descendants before it is used in any validation.
    pub(crate) descendants: HashSet<EntityUID>,

    /// The context attributes associated with this action. Keys are the context
    /// attribute identifiers while the values are the type of the attribute.
    pub(crate) context: Attributes,

    /// The attribute types for this action, used for typechecking.
    pub(crate) attribute_types: Attributes,

    /// The actual attribute value for this action, used to construct an
    /// `Entity` for this action. Could also be used for more precise
    /// typechecking by partial evaluation.
    pub(crate) attributes: HashMap<SmolStr, RestrictedExpr>,
}

impl ValidatorActionId {
    /// An iterator over the attributes of this action's required context
    pub fn context(&self) -> impl Iterator<Item = (&SmolStr, &AttributeType)> {
        self.context.iter()
    }
}

impl TCNode<EntityUID> for ValidatorActionId {
    fn get_key(&self) -> EntityUID {
        self.name.clone()
    }

    fn add_edge_to(&mut self, k: EntityUID) {
        self.descendants.insert(k);
    }

    fn out_edges(&self) -> Box<dyn Iterator<Item = &EntityUID> + '_> {
        Box::new(self.descendants.iter())
    }

    fn has_edge_to(&self, e: &EntityUID) -> bool {
        self.descendants.contains(e)
    }
}

/// The principals and resources that an action can be applied to.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ValidatorApplySpec {
    /// The principal entity types the action can be applied to. This set may
    /// be a singleton set containing the unspecified entity type when the
    /// `principalTypes` list is omitted in the schema. A non-singleton set
    /// shouldn't contain the unspecified entity type, but validation will give
    /// the same success/failure result as when it is the only element of the
    /// set, perhaps with extra type errors.
    #[serde(rename = "principalApplySpec")]
    principal_apply_spec: HashSet<EntityType>,

    /// The resource entity types the action can be applied to. See comments on
    /// `principal_apply_spec` about the unspecified entity type.
    #[serde(rename = "resourceApplySpec")]
    resource_apply_spec: HashSet<EntityType>,
}

impl ValidatorApplySpec {
    /// Create an apply spec for an action that can only be applied to some
    /// specific entities.
    pub(crate) fn new(
        principal_apply_spec: HashSet<EntityType>,
        resource_apply_spec: HashSet<EntityType>,
    ) -> Self {
        Self {
            principal_apply_spec,
            resource_apply_spec,
        }
    }

    /// Get the applicable principal types for this spec.
    pub(crate) fn applicable_principal_types(&self) -> impl Iterator<Item = &EntityType> {
        self.principal_apply_spec.iter()
    }

    /// Get the applicable resource types for this spec.
    pub(crate) fn applicable_resource_types(&self) -> impl Iterator<Item = &EntityType> {
        self.resource_apply_spec.iter()
    }
}
