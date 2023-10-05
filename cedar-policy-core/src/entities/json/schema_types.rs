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

use crate::ast::{EntityType, Name, Type};
use smol_str::SmolStr;
use std::collections::{HashMap, HashSet};

/// Possible types that schema-based parsing can expect for Cedar values.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SchemaType {
    /// Boolean
    Bool,
    /// Signed integer
    Long {
        // Here, a Long with bounds checking disabled is no different from a
        // Long with bounds [i64::MIN, i64::MAX], so we can avoid the need for
        // an option type (for now; we may later discover sufficient motivation
        // to use it).
        /// Lower bound on the Long values to accept.
        min: i64,
        /// Upper bound on the Long values to accept.
        max: i64,
    },
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
        attrs: HashMap<SmolStr, AttributeType>,
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
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AttributeType {
    /// Type of the attribute
    attr_type: SchemaType,
    /// Is the attribute required
    required: bool,
}

impl SchemaType {
    /// Does this SchemaType match the given Type.
    /// I.e., are they compatible, in the sense that there exist some concrete
    /// values that have the given SchemaType and the given Type.
    pub fn matches(&self, ty: &Type) -> bool {
        match (self, ty) {
            (SchemaType::Bool, Type::Bool) => true,
            (SchemaType::Long { .. }, Type::Long) => true,
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

    pub(crate) fn least_upper_bound(&self, other: &SchemaType) -> Option<SchemaType> {
        use SchemaType::*;
        match (self, other) {
            (Bool, Bool) => Some(Bool),
            (String, String) => Some(String),
            (
                Long {
                    min: min1,
                    max: max1,
                },
                Long {
                    min: min2,
                    max: max2,
                },
            ) => Some(Long {
                min: std::cmp::min(*min1, *min2),
                max: std::cmp::max(*max1, *max2),
            }),
            (
                Set {
                    element_ty: element_ty1,
                },
                Set {
                    element_ty: element_ty2,
                },
            ) => Some(Set {
                element_ty: Box::new(element_ty1.least_upper_bound(&element_ty2)?),
            }),
            (s @ Set { .. }, EmptySet) | (EmptySet, s @ Set { .. }) => Some(s.clone()),
            (EmptySet, EmptySet) => Some(EmptySet),
            (Record { attrs: attrs1 }, Record { attrs: attrs2 }) => {
                let keys: HashSet<_> = attrs1.keys().chain(attrs2.keys()).collect();
                let attrs = keys
                    .iter()
                    .map(|k| -> Option<(SmolStr, AttributeType)> {
                        match (attrs1.get(*k), attrs2.get(*k)) {
                            (Some(v0), Some(v1)) => {
                                let ty = v0.schema_type().least_upper_bound(v1.schema_type())?;
                                Some((
                                    (*k).clone(),
                                    if v0.is_required() && v1.is_required() {
                                        AttributeType::required(ty)
                                    } else {
                                        AttributeType::optional(ty)
                                    },
                                ))
                            }
                            (None, Some(v)) | (Some(v), None) => Some((
                                (*k).clone(),
                                AttributeType::optional(v.schema_type().clone()),
                            )),
                            (None, None) => None,
                        }
                    })
                    .collect::<Option<HashMap<_, _>>>()?;
                Some(Record { attrs })
            }
            (Entity { ty: ty1 }, Entity { ty: ty2 }) if ty1 == ty2 => Some(self.clone()),
            (Extension { name: name1 }, Extension { name: name2 }) if name1 == name2 => {
                Some(self.clone())
            }
            _ => None,
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
                (
                    Long {
                        min: min1,
                        max: max1,
                    },
                    Long {
                        min: min2,
                        max: max2,
                    },
                ) => i64::max(*min1, *min2) <= i64::min(*max1, *max2),
                (Set { .. }, EmptySet) => true,
                (EmptySet, Set { .. }) => true,
                (Set { element_ty: elty1 }, Set { element_ty: elty2 }) => {
                    elty1.is_consistent_with(elty2)
                }
                (Record { attrs: attrs1 }, Record { attrs: attrs2 }) => {
                    attrs1.iter().all(|(k, v)| {
                        match attrs2.get(k) {
                            Some(ty) => {
                                // both have the attribute, doesn't matter if
                                // one or both consider it required or optional
                                ty.attr_type.is_consistent_with(&v.attr_type)
                            }
                            None => {
                                // attrs1 has the attribute, attrs2 does not.
                                // if required in attrs1, incompatible.
                                // otherwise fine
                                !v.required
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
                                // if required in attrs2, incompatible.
                                // otherwise fine
                                !v.required
                            }
                        }
                    })
                }
                _ => false,
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

impl std::fmt::Display for SchemaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool => write!(f, "bool"),
            Self::Long { min, max } =>
            // REVIEW: Wording can probably be improved, and we may want to hide
            // the bounds when they are the entire range of Long.
            //
            // TODO: This leads to ugly and possibly confusing error messages,
            // e.g., "attribute was expected to have type long between 1 and 8
            // inclusive, but actually has type long between 9223372036854775799
            // and 9223372036854775799 inclusive". What's the cleanest way to
            // make a special case for a nicer error message?
            {
                write!(f, "long between {} and {} inclusive", min, max)
            }
            Self::String => write!(f, "string"),
            Self::Set { element_ty } => write!(f, "(set of {})", &element_ty),
            Self::EmptySet => write!(f, "empty-set"),
            Self::Record { attrs } => {
                if attrs.is_empty() {
                    write!(f, "empty record")
                } else {
                    write!(f, "record with attributes: (")?;
                    for (k, v) in attrs.iter() {
                        write!(f, "{k:?} => {v}, ")?;
                    }
                    write!(f, ")")?;
                    Ok(())
                }
            }
            Self::Entity { ty } => match ty {
                EntityType::Unspecified => write!(f, "(entity of unspecified type)"),
                EntityType::Concrete(name) => write!(f, "(entity of type `{}`)", name),
            },
            Self::Extension { name } => write!(f, "{}", name),
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
