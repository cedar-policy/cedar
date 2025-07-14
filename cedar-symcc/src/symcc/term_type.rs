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

use super::{entity_tag::EntityTag, type_abbrevs::*};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum TermType {
    Bool,
    Bitvec { n: Nat },
    String,
    Option { ty: Box<TermType> },
    Entity { ety: EntityType },
    Set { ty: Box<TermType> },
    Record { rty: BTreeMap<Attr, TermType> },
    Ext { xty: ExtType },
}

impl TermType {
    /// No corresponding Lean function; convenience constructor used in Rust
    pub fn set_of(ty: TermType) -> Self {
        Self::Set { ty: Box::new(ty) }
    }

    pub fn tag_for(ety: EntityType) -> Self {
        Self::Record {
            rty: EntityTag::mk(TermType::Entity { ety }, TermType::String).0,
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
    pub fn of_type(ty: cedar_policy_core::validator::types::Type) -> Self {
        use cedar_policy::EntityTypeName;
        use cedar_policy_core::validator::types::Type;
        use std::str::FromStr;
        match ty {
            Type::Primitive { primitive_type } => match primitive_type {
                cedar_policy_core::validator::types::Primitive::Bool => TermType::Bool,
                cedar_policy_core::validator::types::Primitive::Long => TermType::Bitvec { n: 64 },
                cedar_policy_core::validator::types::Primitive::String => TermType::String,
            },
            Type::ExtensionType { name } => match name.basename().to_string().as_str() {
                "ipaddr" => TermType::Ext {
                    xty: ExtType::IpAddr,
                },
                "decimal" => TermType::Ext {
                    xty: ExtType::Decimal,
                },
                ext => unimplemented!("Missing extension handler for {ext}"),
            },
            Type::EntityOrRecord(entity_record_kind) => {
                match entity_record_kind {
                    cedar_policy_core::validator::types::EntityRecordKind::Record {
                        attrs,
                        open_attributes,
                    } => {
                        assert_eq!(
                            open_attributes,
                            OpenTag::ClosedAttributes,
                            "Attributes should be closed"
                        );
                        TermType::Record {
                            rty: attrs
                                .into_iter()
                                .map(|(k, v)| {
                                    (
                                        k,
                                        //Inlining ofRecordType and ofQualifiedType here
                                        if v.is_required {
                                            Self::of_type(v.attr_type)
                                        } else {
                                            TermType::Option {
                                                ty: Box::new(Self::of_type(v.attr_type)),
                                            }
                                        },
                                    )
                                })
                                .collect(),
                        }
                    }
                    cedar_policy_core::validator::types::EntityRecordKind::AnyEntity => {
                        panic!("Strict validation should prevent this")
                    }
                    cedar_policy_core::validator::types::EntityRecordKind::Entity(entity_lub) => {
                        match entity_lub.get_single_entity() {
                            Some(name) => TermType::Entity {
                                ety: core_entity_type_into_entity_type(name).clone(),
                            },
                            None => panic!("EntityLUB has multiple elements"),
                        }
                    }
                    cedar_policy_core::validator::types::EntityRecordKind::ActionEntity {
                        name, ..
                    } => TermType::Entity {
                        // todo: expose `From<core::Name> for api::EntityTypeName`?
                        ety: EntityTypeName::from_str(name.to_string().as_str())
                            .expect("Name should parse"),
                    },
                }
            }
            Type::Set { element_type } => match element_type {
                Some(element_type) => TermType::Set {
                    ty: Box::new(Self::of_type(*element_type)),
                },
                None => panic!("Empty set. Unable to deduce type"),
            },
            Type::Never => panic!("Analysis cannot handle Never"),
            Type::True => panic!("Analysis cannot handle True"),
            Type::False => panic!("Analysis cannot handle False"),
        }
    }
}
