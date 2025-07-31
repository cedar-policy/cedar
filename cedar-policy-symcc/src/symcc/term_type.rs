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
use cedar_policy_core::validator::types::OpenTag;

use crate::symcc::result;

use super::{entity_tag::EntityTag, type_abbrevs::*};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum TermType {
    Bool,
    Bitvec { n: Width },
    String,
    Option { ty: Arc<TermType> },
    Entity { ety: EntityType },
    Set { ty: Arc<TermType> },
    Record { rty: Arc<BTreeMap<Attr, TermType>> },
    Ext { xty: ExtType },
}

impl TermType {
    /// No corresponding Lean function; convenience constructor used in Rust
    pub fn set_of(ty: TermType) -> Self {
        Self::Set { ty: Arc::new(ty) }
    }

    pub fn tag_for(ety: EntityType) -> Self {
        Self::Record {
            rty: Arc::new(EntityTag::mk(TermType::Entity { ety }, TermType::String).0),
        }
    }

    pub fn is_prim_type(&self) -> bool {
        matches!(
            self,
            TermType::Bool
                | TermType::Bitvec { .. }
                | TermType::String
                | TermType::Entity { .. }
                | TermType::Ext { .. }
        )
    }

    pub fn is_entity_type(&self) -> bool {
        matches!(self, TermType::Entity { .. })
    }

    pub fn is_record_type(&self) -> bool {
        matches!(self, TermType::Record { .. })
    }

    pub fn is_option_type(&self) -> bool {
        matches!(self, TermType::Option { .. })
    }

    pub fn is_option_entity_type(&self) -> bool {
        matches!(self, TermType::Option { ty, .. } if ty.is_entity_type())
    }

    // This doesn't match the Lean because `cedar_policy_core::validator::types::Type` doesn't
    // TODO: test this
    pub fn of_type(ty: cedar_policy_core::validator::types::Type) -> Result<Self, result::Error> {
        use cedar_policy::EntityTypeName;
        use cedar_policy_core::validator::types::Type;
        use std::str::FromStr;
        match ty {
            Type::Primitive { primitive_type } => match primitive_type {
                cedar_policy_core::validator::types::Primitive::Bool => Ok(TermType::Bool),
                cedar_policy_core::validator::types::Primitive::Long => {
                    Ok(TermType::Bitvec { n: 64 })
                }
                cedar_policy_core::validator::types::Primitive::String => Ok(TermType::String),
            },
            Type::ExtensionType { name } => match name.basename().to_string().as_str() {
                "ipaddr" => Ok(TermType::Ext {
                    xty: ExtType::IpAddr,
                }),
                "decimal" => Ok(TermType::Ext {
                    xty: ExtType::Decimal,
                }),
                "datetime" => Ok(TermType::Ext {
                    xty: ExtType::DateTime,
                }),
                "duration" => Ok(TermType::Ext {
                    xty: ExtType::Duration,
                }),
                _ => Err(result::Error::UnsupportedError),
            },
            Type::EntityOrRecord(entity_record_kind) => {
                match entity_record_kind {
                    cedar_policy_core::validator::types::EntityRecordKind::Record {
                        attrs,
                        open_attributes,
                    } => {
                        if open_attributes == OpenTag::ClosedAttributes {
                            Ok(TermType::Record {
                                rty: Arc::new(
                                    attrs
                                        .into_iter()
                                        .map(|(k, v)| {
                                            match Self::of_type(v.attr_type) {
                                                Ok(vt) => Ok((
                                                    k,
                                                    //Inlining ofRecordType and ofQualifiedType here
                                                    if v.is_required {
                                                        vt
                                                    } else {
                                                        TermType::Option { ty: Arc::new(vt) }
                                                    },
                                                )),
                                                Err(e) => Err(e),
                                            }
                                        })
                                        .collect::<Result<_, _>>()?,
                                ),
                            })
                        } else {
                            // Attributes should be closed
                            Err(result::Error::UnsupportedError)
                        }
                    }
                    cedar_policy_core::validator::types::EntityRecordKind::AnyEntity => {
                        Err(result::Error::Unreachable(
                            "AnyEntity is not possible with Strict validation".into(),
                        ))
                    }
                    cedar_policy_core::validator::types::EntityRecordKind::Entity(entity_lub) => {
                        match entity_lub.get_single_entity() {
                            Some(name) => Ok(TermType::Entity {
                                ety: core_entity_type_into_entity_type(name).clone(),
                            }),
                            // EntityLUB has multiple elements
                            None => Err(result::Error::UnsupportedError),
                        }
                    }
                    cedar_policy_core::validator::types::EntityRecordKind::ActionEntity {
                        name,
                        ..
                    } => Ok(TermType::Entity {
                        // todo: expose `From<core::Name> for api::EntityTypeName`?
                        // PANIC SAFETY
                        #[allow(
                            clippy::expect_used,
                            reason = "conversion from core -> str -> public type should not error"
                        )]
                        ety: EntityTypeName::from_str(name.to_string().as_str())
                            .expect("Name should parse"),
                    }),
                }
            }
            Type::Set { element_type } => match element_type {
                Some(element_type) => Ok(TermType::Set {
                    ty: Arc::new(Self::of_type(*element_type)?),
                }),
                // Empty set. Unable to deduce type
                None => Err(result::Error::UnsupportedError),
            },
            // Analysis cannot handle Never,
            Type::Never => Err(result::Error::UnsupportedError),
            // Analysis cannot handle True,
            Type::True => Err(result::Error::UnsupportedError),
            // Analysis cannot handle False,
            Type::False => Err(result::Error::UnsupportedError),
        }
    }
}
