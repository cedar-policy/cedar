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
use crate::ast;
use crate::entities::{EntityUidJSON, JsonDeserializationErrorContext};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Serde JSON structure for a principal head constraint in the EST format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "op")]
pub enum PrincipalConstraint {
    /// No constraint (e.g., `principal,`)
    All,
    /// `==` constraint
    #[serde(rename = "==")]
    Eq(EqConstraint),
    /// `in` constraint
    #[serde(rename = "in")]
    In(PrincipalOrResourceInConstraint),
}

/// Serde JSON structure for an action head constraint in the EST format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "op")]
pub enum ActionConstraint {
    /// No constraint (i.e., `action,`)
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
pub enum ResourceConstraint {
    /// No constraint (e.g., `resource,`)
    All,
    /// `==` constraint
    #[serde(rename = "==")]
    Eq(EqConstraint),
    /// `in` constraint
    #[serde(rename = "in")]
    In(PrincipalOrResourceInConstraint),
}

/// Serde JSON structure for a `==` head constraint in the EST format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EqConstraint {
    /// `==` a literal entity
    Entity {
        /// Entity it must be `==` to
        entity: EntityUidJSON,
    },
    /// Template slot
    Slot {
        /// slot
        slot: ast::SlotId,
    },
}

/// Serde JSON structure for an `in` head constraint for principal/resource in
/// the EST format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PrincipalOrResourceInConstraint {
    /// `in` a literal entity
    Entity {
        /// Entity it must be `in`
        entity: EntityUidJSON,
    },
    /// Template slot
    Slot {
        /// slot
        slot: ast::SlotId,
    },
}

/// Serde JSON structure for an `in` head constraint for action in the EST
/// format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ActionInConstraint {
    /// Single entity
    Single {
        /// the single entity
        entity: EntityUidJSON,
    },
    /// Set of entities
    Set {
        /// the set of entities
        entities: Vec<EntityUidJSON>,
    },
}

impl PrincipalConstraint {
    /// Fill in any slots in the principal constraint using the values in
    /// `vals`. Throws an error if `vals` doesn't contain a necessary mapping,
    /// but does not throw an error if `vals` contains unused mappings.
    pub fn instantiate(
        self,
        vals: &HashMap<ast::SlotId, EntityUidJSON>,
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
        }
    }
}

impl ResourceConstraint {
    /// Fill in any slots in the resource constraint using the values in
    /// `vals`. Throws an error if `vals` doesn't contain a necessary mapping,
    /// but does not throw an error if `vals` contains unused mappings.
    pub fn instantiate(
        self,
        vals: &HashMap<ast::SlotId, EntityUidJSON>,
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
        }
    }
}

impl ActionConstraint {
    /// Fill in any slots in the action constraint using the values in `vals`.
    /// Throws an error if `vals` doesn't contain a necessary mapping, but does
    /// not throw an error if `vals` contains unused mappings.
    pub fn instantiate(
        self,
        _vals: &HashMap<ast::SlotId, EntityUidJSON>,
    ) -> Result<Self, InstantiationError> {
        // currently, slots are not allowed in action constraints
        Ok(self)
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
                    entity: EntityUidJSON::ImplicitEntityEscape((&*e).into()),
                })
            }
            ast::PrincipalOrResourceConstraint::Eq(ast::EntityReference::Slot) => {
                PrincipalConstraint::Eq(EqConstraint::Slot {
                    slot: ast::SlotId::principal(),
                })
            }
            ast::PrincipalOrResourceConstraint::In(ast::EntityReference::EUID(e)) => {
                PrincipalConstraint::In(PrincipalOrResourceInConstraint::Entity {
                    entity: EntityUidJSON::ImplicitEntityEscape((&*e).into()),
                })
            }
            ast::PrincipalOrResourceConstraint::In(ast::EntityReference::Slot) => {
                PrincipalConstraint::In(PrincipalOrResourceInConstraint::Slot {
                    slot: ast::SlotId::principal(),
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
                    entity: EntityUidJSON::ImplicitEntityEscape((&*e).into()),
                })
            }
            ast::PrincipalOrResourceConstraint::Eq(ast::EntityReference::Slot) => {
                ResourceConstraint::Eq(EqConstraint::Slot {
                    slot: ast::SlotId::resource(),
                })
            }
            ast::PrincipalOrResourceConstraint::In(ast::EntityReference::EUID(e)) => {
                ResourceConstraint::In(PrincipalOrResourceInConstraint::Entity {
                    entity: EntityUidJSON::ImplicitEntityEscape((&*e).into()),
                })
            }
            ast::PrincipalOrResourceConstraint::In(ast::EntityReference::Slot) => {
                ResourceConstraint::In(PrincipalOrResourceInConstraint::Slot {
                    slot: ast::SlotId::resource(),
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
        }
    }
}

impl From<ast::ActionConstraint> for ActionConstraint {
    fn from(constraint: ast::ActionConstraint) -> ActionConstraint {
        match constraint {
            ast::ActionConstraint::Any => ActionConstraint::All,
            ast::ActionConstraint::Eq(e) => ActionConstraint::Eq(EqConstraint::Entity {
                entity: EntityUidJSON::ImplicitEntityEscape((&*e).into()),
            }),
            ast::ActionConstraint::In(es) => match &es[..] {
                [e] => ActionConstraint::In(ActionInConstraint::Single {
                    entity: EntityUidJSON::ImplicitEntityEscape((&**e).into()),
                }),
                es => ActionConstraint::In(ActionInConstraint::Set {
                    entities: es
                        .iter()
                        .map(|e| EntityUidJSON::ImplicitEntityEscape((&**e).into()))
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
