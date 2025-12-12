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

//! Definitions of term types.

use cedar_policy_core::validator::types::{OpenTag, Type};

use super::result::CompileError;

use super::{entity_tag::EntityTag, type_abbrevs::*};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Types of the intermediate [`super::term::Term`] representation.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[expect(missing_docs, reason = "fields are self explanatory")]
pub enum TermType {
    /// Bool type
    Bool,
    /// Bitvec type
    Bitvec { n: Width },
    /// String type
    String,
    /// Option type
    Option { ty: Arc<TermType> },
    /// Entity type
    Entity { ety: EntityType },
    /// (Finite) set type
    Set { ty: Arc<TermType> },
    /// Record type
    Record { rty: Arc<BTreeMap<Attr, TermType>> },
    /// Extension type
    Ext { xty: ExtType },
}

impl TermType {
    /// Constructs a set type with the given element type.
    ///
    /// No corresponding Lean function; convenience constructor used in Rust.
    pub fn set_of(ty: TermType) -> Self {
        Self::Set { ty: Arc::new(ty) }
    }

    /// Returns the type of tag keys in the symbolic representation of tags.
    pub fn tag_for(ety: EntityType) -> Self {
        Self::Record {
            rty: Arc::new(EntityTag::mk(TermType::Entity { ety }, TermType::String).0),
        }
    }

    /// Checks if the term type is a primitive type (i.e., not set or record).
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

    /// Checks if the term type is an entity type.
    pub fn is_entity_type(&self) -> bool {
        matches!(self, TermType::Entity { .. })
    }

    /// Checks if the term type is a record type.
    pub fn is_record_type(&self) -> bool {
        matches!(self, TermType::Record { .. })
    }

    /// Checks if the term type is an option type.
    pub fn is_option_type(&self) -> bool {
        matches!(self, TermType::Option { .. })
    }

    /// Checks if the term type is an entity type wrapped in an option type.
    pub fn is_option_entity_type(&self) -> bool {
        matches!(self, TermType::Option { ty, .. } if ty.is_entity_type())
    }

    /// Converts a Cedar [`Type`] into a [`TermType`].
    ///
    /// This doesn't match the Lean model because [`Type`] doesn't.
    pub fn of_type(ty: &Type) -> Result<Self, CompileError> {
        use cedar_policy_core::validator::types::{EntityRecordKind, Primitive};
        match ty {
            Type::Primitive { primitive_type } => match primitive_type {
                Primitive::Bool => Ok(TermType::Bool),
                Primitive::Long => Ok(TermType::Bitvec { n: 64 }),
                Primitive::String => Ok(TermType::String),
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
                name => Err(CompileError::UnsupportedFeature(format!(
                    "unsupported extension {name}"
                ))),
            },
            Type::EntityOrRecord(entity_record_kind) => {
                match entity_record_kind {
                    EntityRecordKind::Record {
                        attrs,
                        open_attributes,
                    } => {
                        if *open_attributes == OpenTag::ClosedAttributes {
                            Ok(TermType::Record {
                                rty: Arc::new(
                                    attrs
                                        .iter()
                                        .map(|(k, v)| {
                                            match Self::of_type(&v.attr_type) {
                                                Ok(vt) => Ok((
                                                    k.clone(),
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
                            Err(CompileError::UnsupportedFeature(
                                "unsupported open attributes".into(),
                            ))
                        }
                    }
                    EntityRecordKind::AnyEntity => Err(CompileError::UnsupportedFeature(
                        "AnyEntity is not supported".into(),
                    )),
                    EntityRecordKind::Entity(entity_lub) => match entity_lub.get_single_entity() {
                        Some(name) => Ok(TermType::Entity {
                            ety: core_entity_type_into_entity_type(name).clone(),
                        }),
                        None => Err(CompileError::UnsupportedFeature(
                            "EntityLUB has multiple elements".into(),
                        )),
                    },
                }
            }
            Type::Set { element_type } => match element_type {
                Some(element_type) => Ok(TermType::Set {
                    ty: Arc::new(Self::of_type(element_type)?),
                }),
                None => Err(CompileError::UnsupportedFeature(
                    "empty set type is unsupported".into(),
                )),
            },
            Type::Never => Err(CompileError::UnsupportedFeature(
                "never type is not supported".into(),
            )),
            Type::True => Err(CompileError::UnsupportedFeature(
                "singleton Bool type is not supported".into(),
            )),
            Type::False => Err(CompileError::UnsupportedFeature(
                "singleton Bool type is not supported".into(),
            )),
        }
    }
}
