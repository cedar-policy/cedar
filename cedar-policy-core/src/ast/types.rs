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

use crate::ast::{EntityType, Name};
use serde::{Deserialize, Serialize};

/// This represents the runtime type of a Cedar value.
/// Nominal types: two entity types are equal if they have the same Name.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Hash, PartialOrd, Ord)]
pub enum Type {
    /// Boolean type
    Bool,
    /// Signed integer type
    Long,
    /// String type
    String,
    /// Set type
    Set,
    /// Record type. Elements are accessed with `.foo` or `["foo"]` where
    /// `.foo` requires an identifier.
    /// This is used for anonymous records like `{ street: "foo", town: "bar" }`,
    /// or the `address` record in `principal.address.street`.
    Record,
    /// Entity type. This is different than record type, even though entity
    /// attributes are conceptually stored as a record, and are accessed in the
    /// same way.
    Entity {
        /// Entity type.
        ///
        /// Entities can be unspecified or nominally typed. Unspecified entity types
        /// are equal and nominal entity types are equal if they have the same typename.
        ty: EntityType,
    },
    /// Extension type. This is different from entity type.
    /// For instance, `IPAddr` type is implemented using this mechanism.
    Extension {
        /// Name of the extension type.
        ///
        /// Cedar has nominal typing, so two values have the same type iff
        /// they have the same typename here.
        ///
        /// Currently, an extension type and an entity type that have the same
        /// name are still considered different types. But probably don't do
        /// this, it would lead to confusion. Likewise, you probably shouldn't
        /// name an extension type "bool", "long", "string", "map", or "set".
        /// Not because Cedar can't handle it, but because it would lead to
        /// confusion.
        name: Name,
    },
}

impl Type {
    /// Shorthand for constructing an entity type.
    pub fn entity_type(name: Name) -> Self {
        Type::Entity {
            ty: EntityType::Concrete(name),
        }
    }
}

impl std::fmt::Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool => write!(f, "bool"),
            Self::Long => write!(f, "long"),
            Self::String => write!(f, "string"),
            Self::Set => write!(f, "set"),
            Self::Record => write!(f, "record"),
            Self::Entity { ty } => match ty {
                EntityType::Unspecified => write!(f, "(entity of unspecified type)"),
                EntityType::Concrete(name) => write!(f, "(entity of type `{}`)", name),
            },
            Self::Extension { name } => write!(f, "{}", name),
        }
    }
}

/// Trait for everything in Cedar that has a type known statically.
///
/// For instance, `Value` and `Entity` implement this, but `Expr` does not
/// (because its type may only be determinable dynamically).
pub trait StaticallyTyped {
    /// Get the object's type
    fn type_of(&self) -> Type;
}
