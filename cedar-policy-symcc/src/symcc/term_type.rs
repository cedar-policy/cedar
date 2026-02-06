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
use strum::IntoStaticStr;

use super::result::CompileError;

use super::{entity_tag::EntityTag, type_abbrevs::*};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Types of the intermediate [`super::term::Term`] representation.
#[derive(Clone, Debug, PartialEq, Eq, IntoStaticStr)]
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

    /// Constructs an option type with the given inner type.
    ///
    /// No corresponding Lean function; convenience constructor used in Rust.
    pub fn option_of(ty: TermType) -> Self {
        Self::Option { ty: Arc::new(ty) }
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
        use cedar_policy_core::validator::types::{EntityKind, Primitive};
        match ty {
            Type::Primitive { primitive_type } => match primitive_type {
                Primitive::Bool => Ok(TermType::Bool),
                Primitive::Long => Ok(TermType::Bitvec { n: SIXTY_FOUR }),
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
            Type::Record {
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
                                                TermType::option_of(vt)
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
            Type::Entity(entity_kind) => match entity_kind {
                EntityKind::AnyEntity => Err(CompileError::UnsupportedFeature(
                    "AnyEntity is not supported".into(),
                )),
                EntityKind::Entity(entity_lub) => match entity_lub.get_single_entity() {
                    Some(name) => Ok(TermType::Entity {
                        ety: core_entity_type_into_entity_type(name).clone(),
                    }),
                    None => Err(CompileError::UnsupportedFeature(
                        "EntityLUB has multiple elements".into(),
                    )),
                },
            },
            Type::Set { element_type } => match element_type {
                Some(element_type) => Ok(TermType::set_of(Self::of_type(element_type)?)),
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

impl Ord for TermType {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (TermType::Bool, TermType::Bool) => std::cmp::Ordering::Equal,
            (TermType::Bitvec { n: a_n }, TermType::Bitvec { n: b_n }) => a_n.cmp(b_n),
            (TermType::String, TermType::String) => std::cmp::Ordering::Equal,
            (TermType::Option { ty: a_ty }, TermType::Option { ty: b_ty }) => a_ty.cmp(b_ty),
            (TermType::Entity { ety: a_ety }, TermType::Entity { ety: b_ety }) => a_ety.cmp(b_ety),
            (TermType::Set { ty: a_ty }, TermType::Set { ty: b_ty }) => a_ty.cmp(b_ty),
            (TermType::Record { rty: a_rty }, TermType::Record { rty: b_rty }) => a_rty.cmp(b_rty),
            (TermType::Ext { xty: a_xty }, TermType::Ext { xty: b_xty }) => a_xty.cmp(b_xty),
            _ => {
                // If the variants don't match, compare the string variant names.
                // Use "Prim" for primitive types when comparing against non-primitive types.
                // This is necesarry to maintain consistency with the Lean.
                let a_name: &'static str = if self.is_prim_type() && !other.is_prim_type() {
                    "Prim"
                } else {
                    self.into()
                };
                let b_name: &'static str = if other.is_prim_type() && !self.is_prim_type() {
                    "Prim"
                } else {
                    other.into()
                };
                a_name.cmp(b_name)
            }
        }
    }
}

impl PartialOrd for TermType {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
