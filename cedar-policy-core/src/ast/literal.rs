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

use crate::ast::{EntityUID, Integer, StaticallyTyped, Type};
use crate::parser;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::sync::Arc;

#[cfg(feature = "protobufs")]
use crate::ast::proto;

/// First-class values which may appear as literals in `Expr::Lit`.
///
/// Note that the auto-derived `PartialEq` and `Eq` are total equality -- using
/// == to compare `Literal`s of different types results in `false`, not a type
/// error.
///
/// `Literal` does not include set or record types. Although Cedar has syntax
/// for set literals (e.g., [2, -7, 8]), these can include arbitrary
/// expressions (e.g., [2+3, principal.foo]), so they have to become
/// `Expr::Set`, not `Expr::Lit`.
///
/// Cloning is O(1).
#[derive(Serialize, Deserialize, Hash, Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub enum Literal {
    /// Boolean value
    Bool(bool),
    /// Signed integer value
    Long(Integer),
    /// String value
    String(SmolStr),
    /// Entity, represented by its UID. To get the actual `Entity`, you have to
    /// look up this UID in a Store or Slice.
    EntityUID(Arc<EntityUID>),
}

impl StaticallyTyped for Literal {
    fn type_of(&self) -> Type {
        match self {
            Self::Bool(_) => Type::Bool,
            Self::Long(_) => Type::Long,
            Self::String(_) => Type::String,
            Self::EntityUID(uid) => uid.type_of(),
        }
    }
}

impl std::fmt::Display for Literal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool(b) => write!(f, "{}", b),
            Self::Long(i) => write!(f, "{}", i),
            // print string literals after the `escape_debug` transformation
            // note that it adds backslashes for more characters than we may want,
            // e.g., a single quote is printed as `\'`.
            Self::String(s) => write!(f, "\"{}\"", s.escape_debug()),
            Self::EntityUID(uid) => write!(f, "{}", uid),
        }
    }
}

impl std::str::FromStr for Literal {
    type Err = parser::err::LiteralParseError;

    fn from_str(s: &str) -> Result<Literal, Self::Err> {
        parser::parse_literal(s)
    }
}

/// Create a Literal directly from a bool
impl From<bool> for Literal {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

/// Create a Literal directly from an Integer
impl From<Integer> for Literal {
    fn from(i: Integer) -> Self {
        Self::Long(i)
    }
}

/// Create a Literal directly from a String
impl From<String> for Literal {
    fn from(s: String) -> Self {
        Self::String(SmolStr::new(s))
    }
}

/// Create a Literal directly from an &str
impl From<&str> for Literal {
    fn from(s: &str) -> Self {
        Self::String(SmolStr::new(s))
    }
}

impl From<SmolStr> for Literal {
    fn from(s: SmolStr) -> Self {
        Self::String(s)
    }
}

/// Create a Literal directly from an EntityUID
impl From<EntityUID> for Literal {
    fn from(e: EntityUID) -> Self {
        Self::EntityUID(Arc::new(e))
    }
}

impl From<Arc<EntityUID>> for Literal {
    fn from(ptr: Arc<EntityUID>) -> Self {
        Self::EntityUID(ptr)
    }
}

#[cfg(feature = "protobufs")]
impl From<&proto::expr::Literal> for Literal {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &proto::expr::Literal) -> Self {
        match v
            .lit
            .as_ref()
            .expect("`as_ref()` for field that should exist")
        {
            proto::expr::literal::Lit::B(b) => Literal::Bool(b.clone()),
            proto::expr::literal::Lit::I(l) => Literal::Long(l.clone()),
            proto::expr::literal::Lit::S(s) => Literal::String(s.clone().into()),
            proto::expr::literal::Lit::Euid(e) => Literal::EntityUID(EntityUID::from(e).into()),
        }
    }
}

#[cfg(feature = "protobufs")]
impl From<&Literal> for proto::expr::Literal {
    fn from(v: &Literal) -> Self {
        match v {
            Literal::Bool(b) => Self {
                lit: Some(proto::expr::literal::Lit::B(b.clone())),
            },
            Literal::Long(l) => Self {
                lit: Some(proto::expr::literal::Lit::I(l.clone())),
            },
            Literal::String(s) => Self {
                lit: Some(proto::expr::literal::Lit::S(s.to_string())),
            },
            Literal::EntityUID(euid) => Self {
                lit: Some(proto::expr::literal::Lit::Euid(proto::EntityUid::from(
                    euid.as_ref(),
                ))),
            },
        }
    }
}

impl Literal {
    /// Check if this literal is an entity reference
    ///
    /// This is used for policy scopes, where some syntax is
    /// required to be an entity reference.
    pub fn is_ref(&self) -> bool {
        matches!(self, Self::EntityUID(..))
    }
}

#[cfg(feature = "protobufs")]
#[cfg(test)]
mod test {
    use super::*;
    use proto;

    #[test]
    fn protobuf_roundtrip() {
        let bool_literal_f = Literal::from(false);
        assert_eq!(
            bool_literal_f,
            Literal::from(&proto::expr::Literal::from(&bool_literal_f))
        );

        let bool_literal_t = Literal::from(true);
        assert_eq!(
            bool_literal_t,
            Literal::from(&proto::expr::Literal::from(&bool_literal_t))
        );

        let long_literal0 = Literal::from(0);
        assert_eq!(
            long_literal0,
            Literal::from(&proto::expr::Literal::from(&long_literal0))
        );

        let long_literal1 = Literal::from(1);
        assert_eq!(
            long_literal1,
            Literal::from(&proto::expr::Literal::from(&long_literal1))
        );

        let str_literal0 = Literal::from("");
        assert_eq!(
            str_literal0,
            Literal::from(&proto::expr::Literal::from(&str_literal0))
        );

        let str_literal1 = Literal::from("foo");
        assert_eq!(
            str_literal1,
            Literal::from(&proto::expr::Literal::from(&str_literal1))
        );

        let euid_literal = Literal::from(EntityUID::with_eid("foo"));
        assert_eq!(
            euid_literal,
            Literal::from(&proto::expr::Literal::from(&euid_literal))
        );
    }
}
