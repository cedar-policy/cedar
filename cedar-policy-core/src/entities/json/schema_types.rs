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

use crate::ast::{EntityType, Name, Type};
use itertools::Itertools;
use smol_str::SmolStr;
use std::collections::BTreeMap;

/// Possible types that schema-based parsing can expect for Cedar values.
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum SchemaType {
    /// Boolean
    Bool,
    /// Signed integer
    Long,
    /// String
    String,
    /// Set, with homogeneous elements of the specified type
    Set {
        /// Element type
        element_ty: Box<SchemaType>,
    },
    /// Type of the empty set.  (Compatible with all `Set` types)
    EmptySet,
    /// Record, with the specified attributes having the specified types
    Record {
        /// Attributes and their types
        attrs: BTreeMap<SmolStr, AttributeType>,
        /// Can a record with this type have attributes other than those specified in `attrs`
        open_attrs: bool,
    },
    /// Entity
    Entity {
        /// Entity type
        ty: EntityType,
    },
    /// Extension types
    Extension {
        /// Name of the extension type.
        ///
        /// Cedar has nominal typing, so two values have the same type iff
        /// they have the same typename here.
        name: Name,
    },
}

/// Attribute type structure used in [`SchemaType`]
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct AttributeType {
    /// Type of the attribute
    pub(crate) attr_type: SchemaType,
    /// Is the attribute required
    pub(crate) required: bool,
}

impl SchemaType {
    /// Return the `SchemaType` corresponding to the given `Type`, if possible.
    ///
    /// Some `Type`s do not contain enough information to construct a full
    /// `SchemaType`.  In those cases, this function returns `None`.
    pub fn from_ty(ty: Type) -> Option<Self> {
        match ty {
            Type::Bool => Some(SchemaType::Bool),
            Type::Long => Some(SchemaType::Long),
            Type::String => Some(SchemaType::String),
            Type::Entity { ty } => Some(SchemaType::Entity { ty }),
            Type::Set => None,
            Type::Record => None,
            Type::Extension { name } => Some(SchemaType::Extension { name }),
        }
    }

    /// Does this SchemaType match the given Type.
    /// I.e., are they compatible, in the sense that there exist some concrete
    /// values that have the given SchemaType and the given Type.
    pub fn matches(&self, ty: &Type) -> bool {
        match (self, ty) {
            (SchemaType::Bool, Type::Bool) => true,
            (SchemaType::Long, Type::Long) => true,
            (SchemaType::String, Type::String) => true,
            (SchemaType::Set { .. }, Type::Set) => true,
            (SchemaType::EmptySet, Type::Set) => true,
            (SchemaType::Record { .. }, Type::Record) => true,
            (SchemaType::Entity { ty: ty1 }, Type::Entity { ty: ty2 }) => ty1 == ty2,
            (SchemaType::Extension { name: name1 }, Type::Extension { name: name2 }) => {
                name1 == name2
            }
            _ => false,
        }
    }

    /// Does this SchemaType match the given SchemaType.
    /// I.e., are they compatible, in the sense that there exist some concrete
    /// values that have both types.
    pub fn is_consistent_with(&self, other: &SchemaType) -> bool {
        if self == other {
            true
        } else {
            use SchemaType::*;
            match (self, other) {
                (Set { .. }, EmptySet) => true,
                (EmptySet, Set { .. }) => true,
                (Set { element_ty: elty1 }, Set { element_ty: elty2 }) => {
                    elty1.is_consistent_with(elty2)
                }
                (
                    Record {
                        attrs: attrs1,
                        open_attrs: open1,
                    },
                    Record {
                        attrs: attrs2,
                        open_attrs: open2,
                    },
                ) => {
                    attrs1.iter().all(|(k, v)| {
                        match attrs2.get(k) {
                            Some(ty) => {
                                // both have the attribute, doesn't matter if
                                // one or both consider it required or optional
                                ty.attr_type.is_consistent_with(&v.attr_type)
                            }
                            None => {
                                // attrs1 has the attribute, attrs2 does not.
                                // if required in attrs1 and attrs2 is
                                // closed, incompatible.  otherwise fine
                                !v.required || *open2
                            }
                        }
                    }) && attrs2.iter().all(|(k, v)| {
                        match attrs1.get(k) {
                            Some(ty) => {
                                // both have the attribute, doesn't matter if
                                // one or both consider it required or optional
                                ty.attr_type.is_consistent_with(&v.attr_type)
                            }
                            None => {
                                // attrs2 has the attribute, attrs1 does not.
                                // if required in attrs2 and attrs1 is closed,
                                // incompatible.  otherwise fine
                                !v.required || *open1
                            }
                        }
                    })
                }
                _ => false,
            }
        }
    }

    /// Iterate over all extension function types contained in this SchemaType
    pub fn contained_ext_types(&self) -> Box<dyn Iterator<Item = &Name> + '_> {
        match self {
            Self::Extension { name } => Box::new(std::iter::once(name)),
            Self::Set { element_ty } => element_ty.contained_ext_types(),
            Self::Record { attrs, .. } => Box::new(
                attrs
                    .values()
                    .flat_map(|ty| ty.attr_type.contained_ext_types()),
            ),
            Self::Bool | Self::Long | Self::String | Self::EmptySet | Self::Entity { .. } => {
                Box::new(std::iter::empty())
            }
        }
    }
}

impl AttributeType {
    /// Constuct a new required attribute type
    pub fn required(attr_type: SchemaType) -> Self {
        Self {
            attr_type,
            required: true,
        }
    }

    /// Construct a new optional attribute type
    pub fn optional(attr_type: SchemaType) -> Self {
        Self {
            attr_type,
            required: false,
        }
    }

    /// Is the attribute required
    pub fn is_required(&self) -> bool {
        self.required
    }

    /// Get the `SchemaType` of the attribute
    pub fn schema_type(&self) -> &SchemaType {
        &self.attr_type
    }
}

impl From<SchemaType> for Type {
    fn from(ty: SchemaType) -> Self {
        match ty {
            SchemaType::Bool => Type::Bool,
            SchemaType::Long => Type::Long,
            SchemaType::String => Type::String,
            SchemaType::Set { .. } => Type::Set,
            SchemaType::EmptySet => Type::Set,
            SchemaType::Record { .. } => Type::Record,
            SchemaType::Entity { ty } => Type::Entity { ty },
            SchemaType::Extension { name } => Type::Extension { name },
        }
    }
}

impl std::fmt::Display for SchemaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool => write!(f, "bool"),
            Self::Long => write!(f, "long"),
            Self::String => write!(f, "string"),
            Self::Set { element_ty } => write!(f, "[{element_ty}]"),
            Self::EmptySet => write!(f, "[]"),
            Self::Record { attrs, open_attrs } => {
                write!(f, "{{ ")?;
                // sorting attributes ensures that there is a single, deterministic
                // Display output for each `SchemaType`, which is important for
                // tests that check equality of error messages
                for (i, (k, v)) in attrs
                    .iter()
                    .sorted_unstable_by_key(|(k, _)| SmolStr::clone(k))
                    .enumerate()
                {
                    write!(f, "{k:?} => {v}")?;
                    if i < (attrs.len() - 1) {
                        write!(f, ", ")?;
                    }
                }
                if *open_attrs {
                    write!(f, ", ...")?;
                }
                write!(f, " }}")?;
                Ok(())
            }
            Self::Entity { ty } => write!(f, "`{ty}`"),
            Self::Extension { name } => write!(f, "{name}"),
        }
    }
}

impl std::fmt::Display for AttributeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "({}) {}",
            if self.required {
                "required"
            } else {
                "optional"
            },
            &self.attr_type
        )
    }
}
