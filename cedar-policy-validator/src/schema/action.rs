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
    ast::{self, EntityType, EntityUID, PartialValueSerializedAsExpr},
    transitive_closure::TCNode,
};
use itertools::Itertools;
use nonempty::NonEmpty;
use serde::Serialize;
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashSet};

use super::internal_name_to_entity_type;
use crate::{
    schema::{AllDefs, SchemaError},
    types::{Attributes, Type},
    ConditionalName,
};

#[cfg(feature = "protobufs")]
use crate::proto;

#[cfg(feature = "protobufs")]
use cedar_policy_core::{evaluator::RestrictedEvaluator, extensions::Extensions};

/// Contains information about actions used by the validator.  The contents of
/// the struct are the same as the schema entity type structure, but the
/// `member_of` relation is reversed to instead be `descendants`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorActionId {
    /// The name of the action.
    pub(crate) name: EntityUID,

    /// The principals and resources that the action can be applied to.
    pub(crate) applies_to: ValidatorApplySpec<ast::EntityType>,

    /// The set of actions that can be members of this action. When this
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
    ///
    /// Attributes are serialized as `RestrictedExpr`s, so that roundtripping
    /// works seamlessly.
    pub(crate) attributes: BTreeMap<SmolStr, PartialValueSerializedAsExpr>,
}

impl ValidatorActionId {
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

#[cfg(feature = "protobufs")]
impl From<&ValidatorActionId> for proto::ValidatorActionId {
    fn from(v: &ValidatorActionId) -> Self {
        Self {
            name: Some(ast::proto::EntityUid::from(&v.name)),
            applies_to: Some(proto::ValidatorApplySpec::from(&v.applies_to)),
            descendants: v
                .descendants
                .iter()
                .map(ast::proto::EntityUid::from)
                .collect(),
            context: Some(proto::Type::from(&v.context)),
            attribute_types: Some(proto::Attributes::from(&v.attribute_types)),
            attributes: v
                .attributes
                .iter()
                .map(|(s, v)| {
                    let key = s.to_string();
                    let value = ast::proto::Expr::from(&ast::Expr::from(ast::PartialValue::from(
                        v.to_owned(),
                    )));
                    (key, value)
                })
                .collect(),
        }
    }
}

#[cfg(feature = "protobufs")]
impl From<&proto::ValidatorActionId> for ValidatorActionId {
    fn from(v: &proto::ValidatorActionId) -> Self {
        let extensions_none = Extensions::none();
        let eval = RestrictedEvaluator::new(&extensions_none);
        Self {
            name: ast::EntityUID::from(v.name.as_ref().unwrap()),
            applies_to: ValidatorApplySpec::from(v.applies_to.as_ref().unwrap()),
            descendants: v.descendants.iter().map(ast::EntityUID::from).collect(),
            context: Type::from(v.context.as_ref().unwrap()),
            attribute_types: Attributes::from(v.attribute_types.as_ref().unwrap()),
            attributes: v
                .attributes
                .iter()
                .map(|(k, v)| {
                    let pval = eval
                        .partial_interpret(
                            ast::BorrowedRestrictedExpr::new(&ast::Expr::from(v)).unwrap(),
                        )
                        .unwrap();
                    (k.into(), pval.into())
                })
                .collect(),
        }
    }
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
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ValidatorApplySpec<N> {
    /// The principal entity types the action can be applied to.
    principal_apply_spec: HashSet<N>,

    /// The resource entity types the action can be applied to.
    resource_apply_spec: HashSet<N>,
}

#[cfg(feature = "protobufs")]
impl From<&ValidatorApplySpec<ast::EntityType>> for proto::ValidatorApplySpec {
    fn from(v: &ValidatorApplySpec<ast::EntityType>) -> Self {
        Self {
            principal_apply_spec: v
                .principal_apply_spec
                .iter()
                .map(ast::proto::EntityType::from)
                .collect(),
            resource_apply_spec: v
                .resource_apply_spec
                .iter()
                .map(ast::proto::EntityType::from)
                .collect(),
        }
    }
}

#[cfg(feature = "protobufs")]
impl From<&proto::ValidatorApplySpec> for ValidatorApplySpec<ast::EntityType> {
    fn from(v: &proto::ValidatorApplySpec) -> Self {
        Self {
            principal_apply_spec: v
                .principal_apply_spec
                .iter()
                .map(ast::EntityType::from)
                .collect(),
            resource_apply_spec: v
                .resource_apply_spec
                .iter()
                .map(ast::EntityType::from)
                .collect(),
        }
    }
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
        let (principal_apply_spec, principal_errs) = self
            .principal_apply_spec
            .into_iter()
            .map(|cname| {
                let internal_name = cname.resolve(all_defs)?.clone();
                internal_name_to_entity_type(internal_name).map_err(Into::into)
            })
            .partition_result::<_, Vec<SchemaError>, _, _>();
        let (resource_apply_spec, resource_errs) = self
            .resource_apply_spec
            .into_iter()
            .map(|cname| {
                let internal_name = cname.resolve(all_defs)?.clone();
                internal_name_to_entity_type(internal_name).map_err(Into::into)
            })
            .partition_result::<_, Vec<SchemaError>, _, _>();
        match (
            NonEmpty::from_vec(principal_errs),
            NonEmpty::from_vec(resource_errs),
        ) {
            (None, None) => Ok(ValidatorApplySpec {
                principal_apply_spec,
                resource_apply_spec,
            }),
            (Some(principal_errs), None) => Err(SchemaError::join_nonempty(principal_errs)),
            (None, Some(resource_errs)) => Err(SchemaError::join_nonempty(resource_errs)),
            (Some(principal_errs), Some(resource_errs)) => {
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
