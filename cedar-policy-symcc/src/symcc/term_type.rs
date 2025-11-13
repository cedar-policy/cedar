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
use hashconsing::{HConsed, HConsign, HashConsign};
use std::collections::BTreeMap;
use std::sync::Arc;

impl TermType {
    /// Constructs a set type with the given element type.
    ///
    /// No corresponding Lean function; convenience constructor used in Rust.
    pub fn set_of(ty: TermType, h: &mut HConsign<TermTypeInner>) -> Self {
        TermType {
            inner: h.mk(TermTypeInner::Set { ty: Arc::new(ty) }),
        }
    }

    /// Returns the type of tag keys in the symbolic representation of tags.
    pub fn tag_for(ety: EntityType, h: &mut HConsign<TermTypeInner>) -> Self {
        let entity_ty = TermType {
            inner: h.mk(TermTypeInner::Entity { ety }),
        };
        let string_ty = TermType {
            inner: h.mk(TermTypeInner::String),
        };
        TermType {
            inner: h.mk(TermTypeInner::Record {
                rty: Arc::new(EntityTag::mk(entity_ty, string_ty).0),
            }),
        }
    }

    /// Checks if the term type is a primitive type (i.e., not set or record).
    pub fn is_prim_type(&self) -> bool {
        matches!(
            self.inner.get(),
            TermTypeInner::Bool
                | TermTypeInner::Bitvec { .. }
                | TermTypeInner::String
                | TermTypeInner::Entity { .. }
                | TermTypeInner::Ext { .. }
        )
    }

    /// Checks if the term type is an entity type.
    pub fn is_entity_type(&self) -> bool {
        matches!(self.inner.get(), TermTypeInner::Entity { .. })
    }

    /// Checks if the term type is a record type.
    pub fn is_record_type(&self) -> bool {
        matches!(self.inner.get(), TermTypeInner::Record { .. })
    }

    /// Checks if the term type is an option type.
    pub fn is_option_type(&self) -> bool {
        matches!(self.inner.get(), TermTypeInner::Option { .. })
    }

    /// Checks if the term type is an entity type wrapped in an option type.
    pub fn is_option_entity_type(&self) -> bool {
        matches!(self.inner.get(), TermTypeInner::Option { ty } if ty.is_entity_type())
    }

    /// Converts a Cedar [`Type`] into a [`TermType`].
    ///
    /// This doesn't match the Lean model because [`Type`] doesn't.
    pub fn of_type(ty: &Type, h: &mut HConsign<TermTypeInner>) -> Result<Self, CompileError> {
        use cedar_policy_core::validator::types::{EntityRecordKind, Primitive};
        match ty {
            Type::Primitive { primitive_type } => match primitive_type {
                Primitive::Bool => Ok(TermType {
                    inner: h.mk(TermTypeInner::Bool),
                }),
                Primitive::Long => Ok(TermType {
                    inner: h.mk(TermTypeInner::Bitvec { n: 64 }),
                }),
                Primitive::String => Ok(TermType {
                    inner: h.mk(TermTypeInner::String),
                }),
            },
            Type::ExtensionType { name } => match name.basename().to_string().as_str() {
                "ipaddr" => Ok(TermType {
                    inner: h.mk(TermTypeInner::Ext {
                        xty: ExtType::IpAddr,
                    }),
                }),
                "decimal" => Ok(TermType {
                    inner: h.mk(TermTypeInner::Ext {
                        xty: ExtType::Decimal,
                    }),
                }),
                "datetime" => Ok(TermType {
                    inner: h.mk(TermTypeInner::Ext {
                        xty: ExtType::DateTime,
                    }),
                }),
                "duration" => Ok(TermType {
                    inner: h.mk(TermTypeInner::Ext {
                        xty: ExtType::Duration,
                    }),
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
                            let rty = attrs
                                .iter()
                                .map(|(k, v)| {
                                    let vt = Self::of_type(&v.attr_type, h)?;
                                    let field_ty = if v.is_required {
                                        vt
                                    } else {
                                        TermType {
                                            inner: h.mk(TermTypeInner::Option { ty: Arc::new(vt) }),
                                        }
                                    };
                                    Ok((k.clone(), field_ty))
                                })
                                .collect::<Result<BTreeMap<_, _>, CompileError>>()?;
                            Ok(TermType {
                                inner: h.mk(TermTypeInner::Record { rty: Arc::new(rty) }),
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
                        Some(name) => Ok(TermType {
                            inner: h.mk(TermTypeInner::Entity {
                                ety: core_entity_type_into_entity_type(name).clone(),
                            }),
                        }),
                        None => Err(CompileError::UnsupportedFeature(
                            "EntityLUB has multiple elements".into(),
                        )),
                    },
                }
            }
            Type::Set { element_type } => match element_type {
                Some(element_type) => {
                    let elem_ty = Self::of_type(element_type, h)?;
                    Ok(TermType {
                        inner: h.mk(TermTypeInner::Set {
                            ty: Arc::new(elem_ty),
                        }),
                    })
                }
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

// Hash consing version for future migration
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum TermTypeInner {
    Bool,
    Bitvec { n: Width },
    String,
    Option { ty: Arc<TermType> },
    Entity { ety: EntityType },
    Set { ty: Arc<TermType> },
    Record { rty: Arc<BTreeMap<Attr, TermType>> },
    Ext { xty: ExtType },
}

#[derive(Clone, Debug)]
pub struct TermType {
    pub inner: HConsed<TermTypeInner>,
}

impl PartialEq for TermType {
    fn eq(&self, other: &Self) -> bool {
        self.inner.get() == other.inner.get()
    }
}

impl Eq for TermType {}

impl PartialOrd for TermType {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TermType {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner.get().cmp(other.inner.get())
    }
}

impl std::hash::Hash for TermType {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.get().hash(state);
    }
}
