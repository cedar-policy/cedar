/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

use super::{FromJsonError, InstantiationError};
use crate::entities::{EntityUidJson, JsonDeserializationErrorContext};
use crate::{ast, FromNormalizedStr};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(feature = "wasm")]
extern crate tsify;

/// Serde JSON structure for a principal head constraint in the EST format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "op")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum PrincipalConstraint {
    /// No constraint (e.g., `principal,`)
    #[serde(alias = "all")]
    All,
    /// `==` constraint
    #[serde(rename = "==")]
    Eq(EqConstraint),
    /// `in` constraint
    #[serde(rename = "in")]
    In(PrincipalOrResourceInConstraint),
    /// `is` (and possibly `in`) constraint
    #[serde(rename = "is")]
    Is(PrincipalOrResourceIsConstraint),
}

/// Serde JSON structure for an action head constraint in the EST format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "op")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum ActionConstraint {
    /// No constraint (i.e., `action,`)
    #[serde(alias = "all")]
    All,
    /// `==` constraint
    #[serde(rename = "==")]
    Eq(EqConstraint),
    /// `in` constraint
    #[serde(rename = "in")]
    In(ActionInConstraint),
}

/// Serde JSON structure for a resource head constraint in the EST format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "op")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum ResourceConstraint {
    /// No constraint (e.g., `resource,`)
    #[serde(alias = "all")]
    All,
    /// `==` constraint
    #[serde(rename = "==")]
    Eq(EqConstraint),
    /// `in` constraint
    #[serde(rename = "in")]
    In(PrincipalOrResourceInConstraint),
    #[serde(rename = "is")]
    /// `is` (and possibly `in`) constraint
    Is(PrincipalOrResourceIsConstraint),
}

/// Serde JSON structure for a `==` head constraint in the EST format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum EqConstraint {
    /// `==` a literal entity
    Entity {
        /// Entity it must be `==` to
        entity: EntityUidJson,
    },
    /// Template slot
    Slot {
        /// slot
        #[cfg_attr(feature = "wasm", tsify(type = "string"))]
        slot: ast::SlotId,
    },
}

/// Serde JSON structure for an `in` head constraint for principal/resource in
/// the EST format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum PrincipalOrResourceInConstraint {
    /// `in` a literal entity
    Entity {
        /// Entity it must be `in`
        entity: EntityUidJson,
    },
    /// Template slot
    Slot {
        /// slot
        #[cfg_attr(feature = "wasm", tsify(type = "string"))]
        slot: ast::SlotId,
    },
}

/// Serde JSON structure for an `is` head constraint for principal/resource in
/// the EST format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct PrincipalOrResourceIsConstraint {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    entity_type: SmolStr,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "in")]
    in_entity: Option<PrincipalOrResourceInConstraint>,
}

/// Serde JSON structure for an `in` head constraint for action in the EST
/// format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum ActionInConstraint {
    /// Single entity
    Single {
        /// the single entity
        entity: EntityUidJson,
    },
    /// Set of entities
    Set {
        /// the set of entities
        entities: Vec<EntityUidJson>,
    },
}

impl PrincipalConstraint {
    /// Fill in any slots in the principal constraint using the values in
    /// `vals`. Throws an error if `vals` doesn't contain a necessary mapping,
    /// but does not throw an error if `vals` contains unused mappings.
    pub fn instantiate(
        self,
        vals: &HashMap<ast::SlotId, EntityUidJson>,
    ) -> Result<Self, InstantiationError> {
        match self {
            PrincipalConstraint::All => Ok(PrincipalConstraint::All),
            PrincipalConstraint::Eq(EqConstraint::Entity { entity }) => {
                Ok(PrincipalConstraint::Eq(EqConstraint::Entity { entity }))
            }
            PrincipalConstraint::In(PrincipalOrResourceInConstraint::Entity { entity }) => Ok(
                PrincipalConstraint::In(PrincipalOrResourceInConstraint::Entity { entity }),
            ),
            PrincipalConstraint::Eq(EqConstraint::Slot { slot }) => match vals.get(&slot) {
                Some(val) => Ok(PrincipalConstraint::Eq(EqConstraint::Entity {
                    entity: val.clone(),
                })),
                None => Err(InstantiationError::MissedSlot { slot }),
            },
            PrincipalConstraint::In(PrincipalOrResourceInConstraint::Slot { slot }) => {
                match vals.get(&slot) {
                    Some(val) => Ok(PrincipalConstraint::In(
                        PrincipalOrResourceInConstraint::Entity {
                            entity: val.clone(),
                        },
                    )),
                    None => Err(InstantiationError::MissedSlot { slot }),
                }
            }
            e @ PrincipalConstraint::Is(PrincipalOrResourceIsConstraint {
                entity_type: _,
                in_entity: None | Some(PrincipalOrResourceInConstraint::Entity { .. }),
            }) => Ok(e),
            PrincipalConstraint::Is(PrincipalOrResourceIsConstraint {
                entity_type,
                in_entity: Some(PrincipalOrResourceInConstraint::Slot { slot }),
            }) => Ok(PrincipalConstraint::Is(PrincipalOrResourceIsConstraint {
                entity_type,
                in_entity: Some(PrincipalOrResourceInConstraint::Entity {
                    entity: vals
                        .get(&slot)
                        .ok_or(InstantiationError::MissedSlot { slot })?
                        .clone(),
                }),
            })),
        }
    }
}

impl ResourceConstraint {
    /// Fill in any slots in the resource constraint using the values in
    /// `vals`. Throws an error if `vals` doesn't contain a necessary mapping,
    /// but does not throw an error if `vals` contains unused mappings.
    pub fn instantiate(
        self,
        vals: &HashMap<ast::SlotId, EntityUidJson>,
    ) -> Result<Self, InstantiationError> {
        match self {
            ResourceConstraint::All => Ok(ResourceConstraint::All),
            ResourceConstraint::Eq(EqConstraint::Entity { entity }) => {
                Ok(ResourceConstraint::Eq(EqConstraint::Entity { entity }))
            }
            ResourceConstraint::In(PrincipalOrResourceInConstraint::Entity { entity }) => Ok(
                ResourceConstraint::In(PrincipalOrResourceInConstraint::Entity { entity }),
            ),
            ResourceConstraint::Eq(EqConstraint::Slot { slot }) => match vals.get(&slot) {
                Some(val) => Ok(ResourceConstraint::Eq(EqConstraint::Entity {
                    entity: val.clone(),
                })),
                None => Err(InstantiationError::MissedSlot { slot }),
            },
            ResourceConstraint::In(PrincipalOrResourceInConstraint::Slot { slot }) => {
                match vals.get(&slot) {
                    Some(val) => Ok(ResourceConstraint::In(
                        PrincipalOrResourceInConstraint::Entity {
                            entity: val.clone(),
                        },
                    )),
                    None => Err(InstantiationError::MissedSlot { slot }),
                }
            }
            e @ ResourceConstraint::Is(PrincipalOrResourceIsConstraint {
                entity_type: _,
                in_entity: None | Some(PrincipalOrResourceInConstraint::Entity { .. }),
            }) => Ok(e),
            ResourceConstraint::Is(PrincipalOrResourceIsConstraint {
                entity_type,
                in_entity: Some(PrincipalOrResourceInConstraint::Slot { slot }),
            }) => Ok(ResourceConstraint::Is(PrincipalOrResourceIsConstraint {
                entity_type,
                in_entity: Some(PrincipalOrResourceInConstraint::Entity {
                    entity: vals
                        .get(&slot)
                        .ok_or(InstantiationError::MissedSlot { slot })?
                        .clone(),
                }),
            })),
        }
    }
}

impl ActionConstraint {
    /// Fill in any slots in the action constraint using the values in `vals`.
    /// Throws an error if `vals` doesn't contain a necessary mapping, but does
    /// not throw an error if `vals` contains unused mappings.
    pub fn instantiate(
        self,
        _vals: &HashMap<ast::SlotId, EntityUidJson>,
    ) -> Result<Self, InstantiationError> {
        // currently, slots are not allowed in action constraints
        Ok(self)
    }
}

impl std::fmt::Display for PrincipalConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => write!(f, "principal"),
            Self::Eq(ec) => {
                write!(f, "principal ")?;
                std::fmt::Display::fmt(ec, f)?;
                Ok(())
            }
            Self::In(ic) => {
                write!(f, "principal ")?;
                std::fmt::Display::fmt(ic, f)?;
                Ok(())
            }
            Self::Is(isc) => {
                write!(f, "principal ")?;
                std::fmt::Display::fmt(isc, f)?;
                Ok(())
            }
        }
    }
}

impl std::fmt::Display for ActionConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => write!(f, "action"),
            Self::Eq(ec) => {
                write!(f, "action ")?;
                std::fmt::Display::fmt(ec, f)?;
                Ok(())
            }
            Self::In(aic) => {
                write!(f, "action ")?;
                std::fmt::Display::fmt(aic, f)?;
                Ok(())
            }
        }
    }
}

impl std::fmt::Display for ResourceConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => write!(f, "resource"),
            Self::Eq(ec) => {
                write!(f, "resource ")?;
                std::fmt::Display::fmt(ec, f)?;
                Ok(())
            }
            Self::In(ic) => {
                write!(f, "resource ")?;
                std::fmt::Display::fmt(ic, f)?;
                Ok(())
            }
            Self::Is(isc) => {
                write!(f, "resource ")?;
                std::fmt::Display::fmt(isc, f)?;
                Ok(())
            }
        }
    }
}

impl std::fmt::Display for EqConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Entity { entity } => {
                match entity
                    .clone()
                    .into_euid(|| JsonDeserializationErrorContext::EntityUid)
                {
                    Ok(euid) => write!(f, "== {euid}"),
                    Err(e) => write!(f, "== (invalid entity uid: {e})"),
                }
            }
            Self::Slot { slot } => write!(f, "== {slot}"),
        }
    }
}

impl std::fmt::Display for PrincipalOrResourceInConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Entity { entity } => {
                match entity
                    .clone()
                    .into_euid(|| JsonDeserializationErrorContext::EntityUid)
                {
                    Ok(euid) => write!(f, "in {euid}"),
                    Err(e) => write!(f, "in (invalid entity uid: {e})"),
                }
            }
            Self::Slot { slot } => write!(f, "in {slot}"),
        }
    }
}

impl std::fmt::Display for PrincipalOrResourceIsConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "is {}", self.entity_type)?;
        if let Some(in_entity) = &self.in_entity {
            write!(f, " {}", in_entity)?;
        }
        Ok(())
    }
}

impl std::fmt::Display for ActionInConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single { entity } => {
                match entity
                    .clone()
                    .into_euid(|| JsonDeserializationErrorContext::EntityUid)
                {
                    Ok(euid) => write!(f, "in {euid}"),
                    Err(e) => write!(f, "in (invalid entity uid: {e})"),
                }
            }
            Self::Set { entities } => {
                write!(f, "in [")?;
                for (i, entity) in entities.iter().enumerate() {
                    match entity
                        .clone()
                        .into_euid(|| JsonDeserializationErrorContext::EntityUid)
                    {
                        Ok(euid) => write!(f, "{euid}"),
                        Err(e) => write!(f, "(invalid entity uid: {e})"),
                    }?;
                    if i < (entities.len() - 1) {
                        write!(f, ", ")?;
                    }
                }
                write!(f, "]")?;
                Ok(())
            }
        }
    }
}

impl From<ast::PrincipalConstraint> for PrincipalConstraint {
    fn from(constraint: ast::PrincipalConstraint) -> PrincipalConstraint {
        constraint.constraint.into()
    }
}

impl TryFrom<PrincipalConstraint> for ast::PrincipalConstraint {
    type Error = FromJsonError;
    fn try_from(constraint: PrincipalConstraint) -> Result<ast::PrincipalConstraint, Self::Error> {
        constraint.try_into().map(ast::PrincipalConstraint::new)
    }
}

impl From<ast::ResourceConstraint> for ResourceConstraint {
    fn from(constraint: ast::ResourceConstraint) -> ResourceConstraint {
        constraint.constraint.into()
    }
}

impl TryFrom<ResourceConstraint> for ast::ResourceConstraint {
    type Error = FromJsonError;
    fn try_from(constraint: ResourceConstraint) -> Result<ast::ResourceConstraint, Self::Error> {
        constraint.try_into().map(ast::ResourceConstraint::new)
    }
}

impl From<ast::PrincipalOrResourceConstraint> for PrincipalConstraint {
    fn from(constraint: ast::PrincipalOrResourceConstraint) -> PrincipalConstraint {
        match constraint {
            ast::PrincipalOrResourceConstraint::Any => PrincipalConstraint::All,
            ast::PrincipalOrResourceConstraint::Eq(ast::EntityReference::EUID(e)) => {
                PrincipalConstraint::Eq(EqConstraint::Entity {
                    entity: EntityUidJson::ImplicitEntityEscape((&*e).into()),
                })
            }
            ast::PrincipalOrResourceConstraint::Eq(ast::EntityReference::Slot) => {
                PrincipalConstraint::Eq(EqConstraint::Slot {
                    slot: ast::SlotId::principal(),
                })
            }
            ast::PrincipalOrResourceConstraint::In(ast::EntityReference::EUID(e)) => {
                PrincipalConstraint::In(PrincipalOrResourceInConstraint::Entity {
                    entity: EntityUidJson::ImplicitEntityEscape((&*e).into()),
                })
            }
            ast::PrincipalOrResourceConstraint::In(ast::EntityReference::Slot) => {
                PrincipalConstraint::In(PrincipalOrResourceInConstraint::Slot {
                    slot: ast::SlotId::principal(),
                })
            }
            ast::PrincipalOrResourceConstraint::IsIn(entity_type, euid) => {
                PrincipalConstraint::Is(PrincipalOrResourceIsConstraint {
                    entity_type: entity_type.to_string().into(),
                    in_entity: Some(match euid {
                        ast::EntityReference::EUID(e) => PrincipalOrResourceInConstraint::Entity {
                            entity: EntityUidJson::ImplicitEntityEscape((&*e).into()),
                        },
                        ast::EntityReference::Slot => PrincipalOrResourceInConstraint::Slot {
                            slot: ast::SlotId::principal(),
                        },
                    }),
                })
            }
            ast::PrincipalOrResourceConstraint::Is(entity_type) => {
                PrincipalConstraint::Is(PrincipalOrResourceIsConstraint {
                    entity_type: entity_type.to_string().into(),
                    in_entity: None,
                })
            }
        }
    }
}

impl From<ast::PrincipalOrResourceConstraint> for ResourceConstraint {
    fn from(constraint: ast::PrincipalOrResourceConstraint) -> ResourceConstraint {
        match constraint {
            ast::PrincipalOrResourceConstraint::Any => ResourceConstraint::All,
            ast::PrincipalOrResourceConstraint::Eq(ast::EntityReference::EUID(e)) => {
                ResourceConstraint::Eq(EqConstraint::Entity {
                    entity: EntityUidJson::ImplicitEntityEscape((&*e).into()),
                })
            }
            ast::PrincipalOrResourceConstraint::Eq(ast::EntityReference::Slot) => {
                ResourceConstraint::Eq(EqConstraint::Slot {
                    slot: ast::SlotId::resource(),
                })
            }
            ast::PrincipalOrResourceConstraint::In(ast::EntityReference::EUID(e)) => {
                ResourceConstraint::In(PrincipalOrResourceInConstraint::Entity {
                    entity: EntityUidJson::ImplicitEntityEscape((&*e).into()),
                })
            }
            ast::PrincipalOrResourceConstraint::In(ast::EntityReference::Slot) => {
                ResourceConstraint::In(PrincipalOrResourceInConstraint::Slot {
                    slot: ast::SlotId::resource(),
                })
            }
            ast::PrincipalOrResourceConstraint::IsIn(entity_type, euid) => {
                ResourceConstraint::Is(PrincipalOrResourceIsConstraint {
                    entity_type: entity_type.to_string().into(),
                    in_entity: Some(match euid {
                        ast::EntityReference::EUID(e) => PrincipalOrResourceInConstraint::Entity {
                            entity: EntityUidJson::ImplicitEntityEscape((&*e).into()),
                        },
                        ast::EntityReference::Slot => PrincipalOrResourceInConstraint::Slot {
                            slot: ast::SlotId::resource(),
                        },
                    }),
                })
            }
            ast::PrincipalOrResourceConstraint::Is(entity_type) => {
                ResourceConstraint::Is(PrincipalOrResourceIsConstraint {
                    entity_type: entity_type.to_string().into(),
                    in_entity: None,
                })
            }
        }
    }
}

impl TryFrom<PrincipalConstraint> for ast::PrincipalOrResourceConstraint {
    type Error = FromJsonError;
    fn try_from(
        constraint: PrincipalConstraint,
    ) -> Result<ast::PrincipalOrResourceConstraint, Self::Error> {
        match constraint {
            PrincipalConstraint::All => Ok(ast::PrincipalOrResourceConstraint::Any),
            PrincipalConstraint::Eq(EqConstraint::Entity { entity }) => Ok(
                ast::PrincipalOrResourceConstraint::Eq(ast::EntityReference::EUID(Arc::new(
                    entity.into_euid(|| JsonDeserializationErrorContext::EntityUid)?,
                ))),
            ),
            PrincipalConstraint::Eq(EqConstraint::Slot { slot }) => {
                if slot == ast::SlotId::principal() {
                    Ok(ast::PrincipalOrResourceConstraint::Eq(
                        ast::EntityReference::Slot,
                    ))
                } else {
                    Err(Self::Error::InvalidSlotName)
                }
            }
            PrincipalConstraint::In(PrincipalOrResourceInConstraint::Entity { entity }) => Ok(
                ast::PrincipalOrResourceConstraint::In(ast::EntityReference::EUID(Arc::new(
                    entity.into_euid(|| JsonDeserializationErrorContext::EntityUid)?,
                ))),
            ),
            PrincipalConstraint::In(PrincipalOrResourceInConstraint::Slot { slot }) => {
                if slot == ast::SlotId::principal() {
                    Ok(ast::PrincipalOrResourceConstraint::In(
                        ast::EntityReference::Slot,
                    ))
                } else {
                    Err(Self::Error::InvalidSlotName)
                }
            }
            PrincipalConstraint::Is(PrincipalOrResourceIsConstraint {
                entity_type,
                in_entity,
            }) => ast::Name::from_normalized_str(entity_type.as_str())
                .map_err(Self::Error::InvalidEntityType)
                .and_then(|entity_type| {
                    Ok(match in_entity {
                        None => ast::PrincipalOrResourceConstraint::is_entity_type(entity_type),
                        Some(PrincipalOrResourceInConstraint::Entity { entity }) => {
                            ast::PrincipalOrResourceConstraint::is_entity_type_in(
                                entity_type,
                                entity.into_euid(|| JsonDeserializationErrorContext::EntityUid)?,
                            )
                        }
                        Some(PrincipalOrResourceInConstraint::Slot { .. }) => {
                            ast::PrincipalOrResourceConstraint::is_entity_type_in_slot(entity_type)
                        }
                    })
                }),
        }
    }
}

impl TryFrom<ResourceConstraint> for ast::PrincipalOrResourceConstraint {
    type Error = FromJsonError;
    fn try_from(
        constraint: ResourceConstraint,
    ) -> Result<ast::PrincipalOrResourceConstraint, Self::Error> {
        match constraint {
            ResourceConstraint::All => Ok(ast::PrincipalOrResourceConstraint::Any),
            ResourceConstraint::Eq(EqConstraint::Entity { entity }) => Ok(
                ast::PrincipalOrResourceConstraint::Eq(ast::EntityReference::EUID(Arc::new(
                    entity.into_euid(|| JsonDeserializationErrorContext::EntityUid)?,
                ))),
            ),
            ResourceConstraint::Eq(EqConstraint::Slot { slot }) => {
                if slot == ast::SlotId::resource() {
                    Ok(ast::PrincipalOrResourceConstraint::Eq(
                        ast::EntityReference::Slot,
                    ))
                } else {
                    Err(Self::Error::InvalidSlotName)
                }
            }
            ResourceConstraint::In(PrincipalOrResourceInConstraint::Entity { entity }) => Ok(
                ast::PrincipalOrResourceConstraint::In(ast::EntityReference::EUID(Arc::new(
                    entity.into_euid(|| JsonDeserializationErrorContext::EntityUid)?,
                ))),
            ),
            ResourceConstraint::In(PrincipalOrResourceInConstraint::Slot { slot }) => {
                if slot == ast::SlotId::resource() {
                    Ok(ast::PrincipalOrResourceConstraint::In(
                        ast::EntityReference::Slot,
                    ))
                } else {
                    Err(Self::Error::InvalidSlotName)
                }
            }
            ResourceConstraint::Is(PrincipalOrResourceIsConstraint {
                entity_type,
                in_entity,
            }) => ast::Name::from_normalized_str(entity_type.as_str())
                .map_err(Self::Error::InvalidEntityType)
                .and_then(|entity_type| {
                    Ok(match in_entity {
                        None => ast::PrincipalOrResourceConstraint::is_entity_type(entity_type),
                        Some(PrincipalOrResourceInConstraint::Entity { entity }) => {
                            ast::PrincipalOrResourceConstraint::is_entity_type_in(
                                entity_type,
                                entity.into_euid(|| JsonDeserializationErrorContext::EntityUid)?,
                            )
                        }
                        Some(PrincipalOrResourceInConstraint::Slot { .. }) => {
                            ast::PrincipalOrResourceConstraint::is_entity_type_in_slot(entity_type)
                        }
                    })
                }),
        }
    }
}

impl From<ast::ActionConstraint> for ActionConstraint {
    fn from(constraint: ast::ActionConstraint) -> ActionConstraint {
        match constraint {
            ast::ActionConstraint::Any => ActionConstraint::All,
            ast::ActionConstraint::Eq(e) => ActionConstraint::Eq(EqConstraint::Entity {
                entity: EntityUidJson::ImplicitEntityEscape((&*e).into()),
            }),
            ast::ActionConstraint::In(es) => match &es[..] {
                [e] => ActionConstraint::In(ActionInConstraint::Single {
                    entity: EntityUidJson::ImplicitEntityEscape((&**e).into()),
                }),
                es => ActionConstraint::In(ActionInConstraint::Set {
                    entities: es
                        .iter()
                        .map(|e| EntityUidJson::ImplicitEntityEscape((&**e).into()))
                        .collect(),
                }),
            },
        }
    }
}

impl TryFrom<ActionConstraint> for ast::ActionConstraint {
    type Error = FromJsonError;
    fn try_from(constraint: ActionConstraint) -> Result<ast::ActionConstraint, Self::Error> {
        match constraint {
            ActionConstraint::All => Ok(ast::ActionConstraint::Any),
            ActionConstraint::Eq(EqConstraint::Entity { entity }) => Ok(ast::ActionConstraint::Eq(
                Arc::new(entity.into_euid(|| JsonDeserializationErrorContext::EntityUid)?),
            )),
            ActionConstraint::Eq(EqConstraint::Slot { .. }) => Err(Self::Error::ActionSlot),
            ActionConstraint::In(ActionInConstraint::Single { entity }) => {
                Ok(ast::ActionConstraint::In(vec![Arc::new(
                    entity.into_euid(|| JsonDeserializationErrorContext::EntityUid)?,
                )]))
            }
            ActionConstraint::In(ActionInConstraint::Set { entities }) => {
                Ok(ast::ActionConstraint::In(
                    entities
                        .into_iter()
                        .map(|e| {
                            e.into_euid(|| JsonDeserializationErrorContext::EntityUid)
                                .map(Arc::new)
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                ))
            }
        }
    }
}
