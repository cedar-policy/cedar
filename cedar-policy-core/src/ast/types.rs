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

use crate::ast::{EntityType, Name, proto};
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
            ty: EntityType::Specified(name),
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
                EntityType::Specified(name) => write!(f, "(entity of type `{}`)", name),
            },
            Self::Extension { name } => write!(f, "{}", name),
        }
    }
}

impl From<&proto::expr::expr_kind::unknown::Type> for Type {
    fn from(v: &proto::expr::expr_kind::unknown::Type) -> Self {
        let pty = proto::expr::expr_kind::unknown::r#type::TypeType::try_from(v.ty).unwrap();
        match pty {
            proto::expr::expr_kind::unknown::r#type::TypeType::Bool => Type::Bool,
            proto::expr::expr_kind::unknown::r#type::TypeType::Long => Type::Long,
            proto::expr::expr_kind::unknown::r#type::TypeType::String => Type::String,
            proto::expr::expr_kind::unknown::r#type::TypeType::Set => Type::Set,
            proto::expr::expr_kind::unknown::r#type::TypeType::Record => Type::Record,
            proto::expr::expr_kind::unknown::r#type::TypeType::Entity =>
                Type::Entity{ ty: EntityType::from(v.ety.as_ref().unwrap()) },
            proto::expr::expr_kind::unknown::r#type::TypeType::Extension =>
                Type::Extension{ name: Name::from(v.name.as_ref().unwrap()) }
        }
    }
}

impl From<&Type> for proto::expr::expr_kind::unknown::Type {
    fn from(v: &Type) -> Self {
        let mut result = Self {
            ty: 0, ety: None, name: None
        };
        match v {
            Type::Bool => {
                result.ty = proto::expr::expr_kind::unknown::r#type::TypeType::Bool.into();
            }
            Type::Long => {
                result.ty = proto::expr::expr_kind::unknown::r#type::TypeType::Long.into()
            }
            Type::String => {
                result.ty = proto::expr::expr_kind::unknown::r#type::TypeType::String.into();
            }
            Type::Set => {
                result.ty = proto::expr::expr_kind::unknown::r#type::TypeType::Set.into();
            }
            Type::Record => {
                result.ty = proto::expr::expr_kind::unknown::r#type::TypeType::Set.into();
            }
            Type::Entity { ty } => {
                result.ty = proto::expr::expr_kind::unknown::r#type::TypeType::Entity.into();
                result.ety = Some(proto::EntityType::from(ty));
            }
            Type::Extension { name } => {
                result.ty = proto::expr::expr_kind::unknown::r#type::TypeType::Extension.into();
                result.name = Some(proto::Name::from(name));
            }
        }
        result
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

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::FromNormalizedStr;

    #[test]
    fn protobuf_roundtrip() {
        assert_eq!(
            Type::Bool,
            Type::from(&proto::expr::expr_kind::unknown::Type::from(&Type::Bool))
        );

        let name: Name = Name::from_normalized_str("B::C::D").unwrap();

        let orig_type2: Type = Type::entity_type(name.to_owned());
        assert_eq!(orig_type2, Type::from(&proto::expr::expr_kind::unknown::Type::from(&orig_type2)));

        let orig_type3: Type = Type::Extension { name: name.to_owned() };
        assert_eq!(orig_type3, Type::from(&proto::expr::expr_kind::unknown::Type::from(&orig_type3)))

    }
}