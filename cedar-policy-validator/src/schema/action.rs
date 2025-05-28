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

//! This module contains the definition of `ValidatorActionId` and the types it relies on

use cedar_policy_core::{
    ast::{self, EntityType, EntityUID, PartialValue},
    parser::{AsLocRef, Loc, MaybeLoc},
    transitive_closure::TCNode,
};
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashSet};

use super::internal_name_to_entity_type;
use crate::{
    partition_nonempty::PartitionNonEmpty,
    schema::{AllDefs, SchemaError},
    types::{Attributes, Type},
    ConditionalName,
};

/// Contains information about actions used by the validator.  The contents of
/// the struct are the same as the schema entity type structure, but the
/// `member_of` relation is reversed to instead be `descendants`.
#[derive(Clone, Debug)]
pub struct ValidatorActionId {
    /// The name of the action.
    pub(crate) name: EntityUID,

    /// The principals and resources that the action can be applied to.
    pub(crate) applies_to: ValidatorApplySpec<ast::EntityType>,

    /// The set of actions that are members of this action. When this
    /// structure is initially constructed, the field will contain direct
    /// children, but it will be updated to contain the closure of all
    /// descendants before it is used in any validation.
    pub(crate) descendants: HashSet<EntityUID>,

    /// The type of the context record associated with this action.
    pub(crate) context: Type,

    /// The attribute types for this action, used for typechecking.
    pub(crate) attribute_types: Attributes,

    /// The actual attribute value for this action, used to construct an
    /// `Entity` for this action. Could also be used for more precise
    /// typechecking by partial evaluation.
    pub(crate) attributes: BTreeMap<SmolStr, PartialValue>,
    /// Source location - if available
    pub(crate) loc: MaybeLoc,
}

impl ValidatorActionId {
    /// Construct a new `ValidatorActionId`.
    ///
    /// This constructor assumes that `descendants` has TC already computed.
    /// That is, caller is responsible for TC.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: EntityUID,
        principal_entity_types: impl IntoIterator<Item = ast::EntityType>,
        resource_entity_types: impl IntoIterator<Item = ast::EntityType>,
        descendants: impl IntoIterator<Item = EntityUID>,
        context: Type,
        attribute_types: Attributes,
        attributes: BTreeMap<SmolStr, PartialValue>,
        loc: MaybeLoc,
    ) -> Self {
        Self {
            name,
            applies_to: ValidatorApplySpec::new(
                principal_entity_types.into_iter().collect(),
                resource_entity_types.into_iter().collect(),
            ),
            descendants: descendants.into_iter().collect(),
            context,
            attribute_types,
            attributes,
            loc,
        }
    }

    /// The name of the action
    pub fn name(&self) -> &EntityUID {
        &self.name
    }

    /// The source location if available
    pub fn loc(&self) -> Option<&Loc> {
        self.loc.as_loc_ref()
    }

    /// Iterator over the actions that are members of this action
    pub fn descendants(&self) -> impl Iterator<Item = &EntityUID> {
        self.descendants.iter()
    }

    /// Context type for this action
    pub fn context(&self) -> &Type {
        &self.context
    }

    /// Returns an iterator over all the principals that this action applies to
    pub fn principals(&self) -> impl Iterator<Item = &EntityType> {
        self.applies_to.principal_apply_spec.iter()
    }

    /// Returns an iterator over all the resources that this action applies to
    pub fn resources(&self) -> impl Iterator<Item = &EntityType> {
        self.applies_to.resource_apply_spec.iter()
    }

    /// The `Type` that this action requires for its context.
    ///
    /// This always returns a closed record type.
    pub fn context_type(&self) -> &Type {
        &self.context
    }

    /// The [`ast::EntityType`]s that can be the `principal` for this action.
    pub fn applies_to_principals(&self) -> impl Iterator<Item = &ast::EntityType> {
        self.applies_to.applicable_principal_types()
    }

    /// The [`ast::EntityType`]s that can be the `resource` for this action.
    pub fn applies_to_resources(&self) -> impl Iterator<Item = &ast::EntityType> {
        self.applies_to.applicable_resource_types()
    }

    /// Is the given principal type applicable for this spec?
    pub fn is_applicable_principal_type(&self, ty: &ast::EntityType) -> bool {
        self.applies_to.is_applicable_principal_type(ty)
    }

    /// Is the given resource type applicable for this spec?
    pub fn is_applicable_resource_type(&self, ty: &ast::EntityType) -> bool {
        self.applies_to.is_applicable_resource_type(ty)
    }

    /// Attribute types for this action
    pub fn attribute_types(&self) -> &Attributes {
        &self.attribute_types
    }

    /// Attribute values for this action
    pub fn attributes(&self) -> impl Iterator<Item = (&SmolStr, &PartialValue)> {
        self.attributes.iter()
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

    // No-op as schema based TCs do not update
    fn reset_edges(&mut self) {}
}

/// The principals and resources that an action can be applied to.
///
/// The parameter `N` represents the type of entity type names stored in this
/// [`ValidatorApplySpec`]. For instance, this could be [`crate::RawName`],
/// [`crate::ConditionalName`], or [`InternalName`], depending on whether the
/// names have been resolved into fully-qualified names yet.
/// (It could also in principle be [`ast::EntityType`], which like
/// [`InternalName`] and [`Name`] always represents a fully-qualified name, but
/// as of this writing we always use [`Name`] or [`InternalName`] for the
/// parameter here when we want to indicate names have been fully qualified.)
#[derive(Clone, Debug)]
pub(crate) struct ValidatorApplySpec<N> {
    /// The principal entity types the action can be applied to.
    principal_apply_spec: HashSet<N>,

    /// The resource entity types the action can be applied to.
    resource_apply_spec: HashSet<N>,
}

impl<N> ValidatorApplySpec<N> {
    /// Create an apply spec for an action that can only be applied to some
    /// specific entities.
    pub fn new(principal_apply_spec: HashSet<N>, resource_apply_spec: HashSet<N>) -> Self {
        Self {
            principal_apply_spec,
            resource_apply_spec,
        }
    }
}

impl ValidatorApplySpec<ast::EntityType> {
    /// Is the given principal type applicable for this spec?
    pub fn is_applicable_principal_type(&self, ty: &ast::EntityType) -> bool {
        self.principal_apply_spec.contains(ty)
    }

    /// Get the applicable principal types for this spec.
    pub fn applicable_principal_types(&self) -> impl Iterator<Item = &ast::EntityType> {
        self.principal_apply_spec.iter()
    }

    /// Is the given resource type applicable for this spec?
    pub fn is_applicable_resource_type(&self, ty: &ast::EntityType) -> bool {
        self.resource_apply_spec.contains(ty)
    }

    /// Get the applicable resource types for this spec.
    pub fn applicable_resource_types(&self) -> impl Iterator<Item = &ast::EntityType> {
        self.resource_apply_spec.iter()
    }
}

impl ValidatorApplySpec<ConditionalName> {
    /// Convert this [`ValidatorApplySpec<ConditionalName>`] into a
    /// [`ValidatorApplySpec<ast::EntityType>`] by fully-qualifying all
    /// typenames that appear anywhere in any definitions, and checking that
    /// none of these typenames contain `__cedar`.
    ///
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> Result<ValidatorApplySpec<ast::EntityType>, crate::schema::SchemaError> {
        let principal_apply_spec = self
            .principal_apply_spec
            .into_iter()
            .map(|cname| {
                let internal_name = cname.resolve(all_defs)?;
                internal_name_to_entity_type(internal_name).map_err(Into::into)
            })
            .partition_nonempty();
        let resource_apply_spec = self
            .resource_apply_spec
            .into_iter()
            .map(|cname| {
                let internal_name = cname.resolve(all_defs)?;
                internal_name_to_entity_type(internal_name).map_err(Into::into)
            })
            .partition_nonempty();

        match (principal_apply_spec, resource_apply_spec) {
            (Ok(principal_apply_spec), Ok(resource_apply_spec)) => Ok(ValidatorApplySpec {
                principal_apply_spec,
                resource_apply_spec,
            }),
            (Ok(_), Err(errs)) => Err(SchemaError::join_nonempty(errs)),
            (Err(resource_errs), Ok(_)) => Err(SchemaError::join_nonempty(resource_errs)),
            (Err(principal_errs), Err(resource_errs)) => {
                let mut errs = principal_errs;
                errs.extend(resource_errs);
                Err(SchemaError::join_nonempty(errs))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn make_action() -> ValidatorActionId {
        ValidatorActionId {
            name: r#"Action::"foo""#.parse().unwrap(),
            applies_to: ValidatorApplySpec {
                principal_apply_spec: HashSet::from([
                    // Make sure duplicates are handled as expected
                    "User".parse().unwrap(),
                    "User".parse().unwrap(),
                ]),
                resource_apply_spec: HashSet::from([
                    "App".parse().unwrap(),
                    "File".parse().unwrap(),
                ]),
            },
            descendants: HashSet::new(),
            context: Type::any_record(),
            attribute_types: Attributes::default(),
            attributes: BTreeMap::default(),
            loc: None,
        }
    }

    #[test]
    fn test_resources() {
        let a = make_action();
        let got = a.resources().cloned().collect::<HashSet<EntityType>>();
        let expected = HashSet::from(["App".parse().unwrap(), "File".parse().unwrap()]);
        assert_eq!(got, expected);
    }

    #[test]
    fn test_principals() {
        let a = make_action();
        let got = a.principals().cloned().collect::<Vec<EntityType>>();
        let expected: [EntityType; 1] = ["User".parse().unwrap()];
        assert_eq!(got, &expected);
    }
}
