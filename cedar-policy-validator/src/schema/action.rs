//! This module contains the definition of `ValidatorActionId` and the types it relies on

use cedar_policy_core::{
    ast::{EntityType, EntityUID, PartialValueSerializedAsExpr},
    transitive_closure::TCNode,
};
use serde::Serialize;
use smol_str::SmolStr;
use std::collections::{HashMap, HashSet};

use crate::types::{Attributes, Type};

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

    /// Indicate that the `member_of` set for this action entity was flagged
    /// as incomplete, or the `member_of` for any ancestor action entity is
    /// incomplete. This action may ultimately be a member of any other action,
    /// so an `in` expression where the left operand is this action, and the
    /// right operand is any other action, can have type `Boolean` but not
    /// `False`.
    pub(crate) open_ancestor_set: bool,

    /// The type of the context record associated with this action.
    pub(crate) context: Type,

    /// The attribute types for this action, used for typechecking.
    pub(crate) attribute_types: Attributes,

    /// The actual attribute value for this action, used to construct an
    /// `Entity` for this action. Could also be used for more precise
    /// typechecking by partial evaluation.
    ///
    /// Attributes are serialized as `RestrictedExpr`s, so that roundtripping
    /// works seamlessly.
    pub(crate) attributes: HashMap<SmolStr, PartialValueSerializedAsExpr>,
}

impl ValidatorActionId {
    /// The `Type` that this action requires for its context.
    ///
    /// This always returns a closed record type.
    pub fn context_type(&self) -> Type {
        self.context.clone()
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
    /// shouldn't contain the unspecified entity type, but (policy) validation
    /// will give the same success/failure result as when it is the only element
    /// of the set, perhaps with extra type errors.
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
    pub fn new(
        principal_apply_spec: HashSet<EntityType>,
        resource_apply_spec: HashSet<EntityType>,
    ) -> Self {
        Self {
            principal_apply_spec,
            resource_apply_spec,
        }
    }

    /// Is the given principal type applicable for this spec?
    pub fn is_applicable_principal_type(&self, ty: &EntityType) -> bool {
        self.principal_apply_spec.contains(ty)
    }

    /// Get the applicable principal types for this spec.
    pub fn applicable_principal_types(&self) -> impl Iterator<Item = &EntityType> {
        self.principal_apply_spec.iter()
    }

    /// Is the given resource type applicable for this spec?
    pub fn is_applicable_resource_type(&self, ty: &EntityType) -> bool {
        self.resource_apply_spec.contains(ty)
    }

    /// Get the applicable resource types for this spec.
    pub fn applicable_resource_types(&self) -> impl Iterator<Item = &EntityType> {
        self.resource_apply_spec.iter()
    }
}
