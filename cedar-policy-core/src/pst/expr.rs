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

//! Expression types for PST.
//!
//! This module defines the expression tree used in Cedar policy conditions
//! (`when` / `unless` clauses). Expressions are recursive via [`Arc<Expr>`].

use super::err::{
    error_body::{self},
    PstConstructionError,
};
use crate::ast;
use crate::expr_builder::ExprBuilder;
use crate::extensions::Extensions;
use smol_str::{SmolStr, ToSmolStr};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Display;
use std::str::FromStr;
use std::sync::Arc;

/// Constants for core Cedar operator names
mod constants {
    // The operators that are defined only in syntax
    pub static NOT_EQ_STR: &str = "!=";
    pub static GREATER_STR: &str = ">";
    pub static GREATER_EQ_STR: &str = ">=";
    pub static AND_STR: &str = "&&";
    pub static OR_STR: &str = "||";
}

/// A validated Cedar identifier.
///
/// Wraps a [`SmolStr`] that has been checked to be a valid Cedar identifier
/// (not a reserved keyword, no special characters, etc.).
///
/// The only way to create an `Id` is through [`Id::new()`] (which validates
/// that the input is a valid identifier) or through conversion from other
/// validated identifier representations.
/// Accessing the inner string is free via [`as_str()`](Id::as_str) or
/// [`into_smolstr()`](Id::into_smolstr).
///
/// ```
/// # use cedar_policy_core::pst::Id;
/// let id = Id::new("userName").expect("valid identifier");
/// assert_eq!(id.as_str(), "userName");
///
/// // Reserved keywords are rejected:
/// assert!(Id::new("if").is_err());
/// assert!(Id::new("true").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id(SmolStr);

impl Id {
    /// Create a new `Id`, validating that the string is a legal Cedar identifier.
    pub fn new(s: impl AsRef<str>) -> Result<Self, PstConstructionError> {
        let ast_id = ast::Id::from_str(s.as_ref())?;
        Ok(Self(ast_id.into_smolstr()))
    }

    /// Get the underlying string as a `&str`. Zero-cost.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the `Id` and return the underlying `SmolStr`. Zero-cost.
    pub fn into_smolstr(self) -> SmolStr {
        self.0
    }
}

impl AsRef<str> for Id {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.0)
    }
}

/// Infallible: `ast::Id` is already validated.
impl From<ast::Id> for Id {
    fn from(id: ast::Id) -> Self {
        Id(id.into_smolstr())
    }
}

/// Slot identifier for template policies.
///
/// In Cedar, template slots are placeholders written as `?principal` or `?resource`
/// that get filled in when a template is instantiated into a concrete policy.
///
/// ```cedar
/// permit (
///   principal == ?principal,
///   action == Action::"view",
///   resource in ?resource
/// );
/// ```
///
/// This enum is `#[non_exhaustive]`; match arms must include a wildcard.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SlotId {
    /// `?principal` slot
    Principal,
    /// `?resource` slot
    Resource,
}

impl Display for SlotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b: ast::SlotId = (*self).into();
        write!(f, "{}", b)
    }
}

/// A qualified name (e.g., `Namespace::Type`).
///
/// Represents entity types, action names, and other identifiers in Cedar.
/// Names consist of a basename and optional namespace components.
///
/// ```cedar
/// // Unqualified: just a basename
/// User
/// Photo
///
/// // Qualified: namespace components followed by basename
/// MyApp::User
/// AWS::EC2::Instance
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Name {
    /// Basename (the final component of the name)
    pub id: Id,
    /// Namespace components (empty for unqualified names)
    pub namespace: Arc<Vec<Id>>,
}

impl Name {
    /// Constructs an unqualified name. This is a convenience constructor that validates
    /// that `id` is a legal Cedar identifier.
    ///
    /// If you have an `Id` (which is `AsRef<str>`), you can infallibly construct the name
    /// yourself.
    pub fn unqualified(id: impl AsRef<str>) -> Result<Self, PstConstructionError> {
        Ok(Name {
            id: Id::new(id)?,
            namespace: Arc::new(vec![]),
        })
    }

    /// Constructs a qualified name. Validates that all components are legal Cedar identifiers.
    ///
    /// If you have an `Id` and a namespace in the form of a `Vec<Id>`, you can infallibly
    /// construct the name yourself.
    pub fn qualified<I, T>(namespace: I, id: impl AsRef<str>) -> Result<Self, PstConstructionError>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let ns: Result<Vec<Id>, _> = namespace.into_iter().map(|s| Id::new(s)).collect();
        Ok(Name {
            id: Id::new(id)?,
            namespace: Arc::new(ns?),
        })
    }
}

impl Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for elem in self.namespace.as_ref() {
            write!(f, "{elem}::")?;
        }
        write!(f, "{}", self.id)?;
        Ok(())
    }
}

/// Entity type name.
///
/// Represents the type of an entity in Cedar.
///
/// ```cedar
/// User            // unqualified
/// MyApp::Photo    // qualified with namespace
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntityType(pub Name);

impl EntityType {
    /// Create an entity type from a name
    pub fn from_name(name: impl Into<Name>) -> Self {
        EntityType(name.into())
    }
}

impl Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ast_et: ast::EntityType = self.clone().into();
        write!(f, "{}", ast_et)
    }
}

/// Entity unique identifier (UID).
///
/// Represents a specific entity instance in Cedar, written as `Type::"id"`.
///
/// ```cedar
/// User::"alice"
/// Photo::"vacation.jpg"
/// MyApp::Action::"readFile"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntityUID {
    /// Type of the entity
    pub ty: EntityType,
    /// Entity identifier (EID)
    pub eid: SmolStr,
}

impl Display for EntityUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::\"{}\"", self.ty, self.eid.as_str().escape_default())
    }
}

/// Variables available in Cedar policy expressions.
///
/// Cedar provides four built-in variables that refer to the authorization request:
///
/// ```cedar
/// principal       // the entity making the request
/// action          // the action being requested
/// resource        // the entity the action targets
/// context         // the request context record
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Var {
    /// `principal` — the entity making the request
    Principal,
    /// `action` — the action being requested
    Action,
    /// `resource` — the entity the action targets
    Resource,
    /// `context` — the request context record
    Context,
}

/// Unary operators in Cedar expressions.
///
/// Includes built-in operators and extension functions that take a single argument.
///
/// This enum is `#[non_exhaustive]`; match arms must include a wildcard.
///
/// ```cedar
/// // Built-in operators
/// !context.is_admin           // Not
/// -(1)                        // Neg
/// [].isEmpty()                // IsEmpty
///
/// // Extension constructors
/// decimal("1.23")             // Decimal
/// ip("10.0.0.1")              // Ip
/// datetime("2024-01-01")      // Datetime
/// duration("1h30m")           // Duration
///
/// // IP extension methods
/// ip("10.0.0.1").isIpv4()     // IsIPv4
/// ip("::1").isIpv6()          // IsIPV6
/// ip("127.0.0.1").isLoopback()   // IsLoopback
/// ip("224.0.0.1").isMulticast()  // IsMulticast
///
/// // Datetime extension methods
/// datetime("2024-01-01").toDate()           // ToDate
/// datetime("2024-01-01T12:00:00Z").toTime() // ToTime
/// duration("1h30m").toMilliseconds()        // ToMilliseconds
/// duration("1h30m").toSeconds()             // ToSeconds
/// duration("1h30m").toMinutes()             // ToMinutes
/// duration("1h30m").toHours()               // ToHours
/// duration("30d").toDays()                  // ToDays
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UnaryOp {
    /// `!expr`
    Not,
    /// `-(expr)`
    Neg,
    /// `expr.isEmpty()`
    IsEmpty,
    /// `datetime("...")`
    Datetime,
    /// `decimal("...")`
    Decimal,
    /// `duration("...")`
    Duration,
    /// `ip("...")`
    Ip,
    /// `expr.isIpv4()`
    IsIPv4,
    /// `expr.isIpv6()`
    IsIPV6,
    /// `expr.isLoopback()`
    IsLoopback,
    /// `expr.isMulticast()`
    IsMulticast,
    /// `expr.toDate()`
    ToDate,
    /// `expr.toTime()`
    ToTime,
    /// `expr.toMilliseconds()`
    ToMilliseconds,
    /// `expr.toSeconds()`
    ToSeconds,
    /// `expr.toMinutes()`
    ToMinutes,
    /// `expr.toHours()`
    ToHours,
    /// `expr.toDays()`
    ToDays,
}

impl UnaryOp {
    pub(crate) fn to_name(self) -> Option<&'static ast::Name> {
        // We get the names of the extension functions from where they are defined: we don't duplicate
        // name definitions.
        use crate::extensions;
        match self {
            UnaryOp::IsEmpty | UnaryOp::Neg | UnaryOp::Not => None,
            UnaryOp::Datetime => Some(&extensions::datetime::constants::DATETIME_CONSTRUCTOR_NAME),
            UnaryOp::Decimal => Some(&extensions::decimal::constants::DECIMAL_FROM_STR_NAME),
            UnaryOp::Duration => Some(&extensions::datetime::constants::DURATION_CONSTRUCTOR_NAME),
            UnaryOp::Ip => Some(&extensions::ipaddr::names::IP_FROM_STR_NAME),
            UnaryOp::IsIPv4 => Some(&extensions::ipaddr::names::IS_IPV4),
            UnaryOp::IsIPV6 => Some(&extensions::ipaddr::names::IS_IPV6),
            UnaryOp::IsLoopback => Some(&extensions::ipaddr::names::IS_LOOPBACK),
            UnaryOp::IsMulticast => Some(&extensions::ipaddr::names::IS_MULTICAST),
            UnaryOp::ToDate => Some(&extensions::datetime::constants::TO_DATE_NAME),
            UnaryOp::ToTime => Some(&extensions::datetime::constants::TO_TIME_NAME),
            UnaryOp::ToMilliseconds => Some(&extensions::datetime::constants::TO_MILLISECONDS_NAME),
            UnaryOp::ToSeconds => Some(&extensions::datetime::constants::TO_SECONDS_NAME),
            UnaryOp::ToMinutes => Some(&extensions::datetime::constants::TO_MINUTES_NAME),
            UnaryOp::ToHours => Some(&extensions::datetime::constants::TO_HOURS_NAME),
            UnaryOp::ToDays => Some(&extensions::datetime::constants::TO_DAYS_NAME),
        }
    }

    /// Parse a unary operator from a function name
    pub(crate) fn from_function_name(name: &str) -> Option<Self> {
        match name {
            "decimal" => Some(UnaryOp::Decimal),
            "datetime" => Some(UnaryOp::Datetime),
            "duration" => Some(UnaryOp::Duration),
            "ip" => Some(UnaryOp::Ip),
            "isIpv4" => Some(UnaryOp::IsIPv4),
            "isIpv6" => Some(UnaryOp::IsIPV6),
            "isLoopback" => Some(UnaryOp::IsLoopback),
            "isMulticast" => Some(UnaryOp::IsMulticast),
            "toDate" => Some(UnaryOp::ToDate),
            "toTime" => Some(UnaryOp::ToTime),
            "toMilliseconds" => Some(UnaryOp::ToMilliseconds),
            "toSeconds" => Some(UnaryOp::ToSeconds),
            "toMinutes" => Some(UnaryOp::ToMinutes),
            "toHours" => Some(UnaryOp::ToHours),
            "toDays" => Some(UnaryOp::ToDays),
            _ => None,
        }
    }
}

impl Display for UnaryOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnaryOp::Not => write!(f, "{}", ast::UnaryOp::Not),
            UnaryOp::Neg => write!(f, "{}", ast::UnaryOp::Neg),
            UnaryOp::IsEmpty => write!(f, "{}", ast::UnaryOp::IsEmpty),
            // Extension functions - use their name
            _ => match self.to_name() {
                Some(name) => write!(f, "{}", name),
                None => write!(f, "<impossible operator>"),
            },
        }
    }
}

/// Binary operators in Cedar expressions.
///
/// Includes built-in operators and extension functions that take two arguments.
///
/// This enum is `#[non_exhaustive]`; match arms must include a wildcard.
///
/// ```cedar
/// // Comparison
/// principal == User::"alice"          // Eq
/// principal != User::"bob"            // NotEq
/// context.age < 18                    // Less
/// context.age <= 21                   // LessEq
/// context.age > 13                    // Greater
/// context.age >= 65                   // GreaterEq
///
/// // Logical
/// true && false                       // And
/// true || false                       // Or
///
/// // Arithmetic
/// context.x + 1                       // Add
/// context.x - 1                       // Sub
/// context.x * 2                       // Mul
///
/// // Hierarchy / set
/// principal in Group::"admins"        // In
/// [1, 2, 3].contains(2)              // Contains
/// [1, 2].containsAll([1])            // ContainsAll
/// [1, 2].containsAny([2, 3])         // ContainsAny
///
/// // Tags
/// resource.hasTag("env")              // HasTag
/// resource.getTag("env")              // GetTag
///
/// // IP extension
/// ip("10.0.0.1").isInRange(ip("10.0.0.0/24"))  // IsInRange
///
/// // Datetime extension
/// datetime("2024-01-01").offset(duration("1d")) // Offset
/// datetime("2024-01-02").durationSince(datetime("2024-01-01")) // DurationSince
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BinaryOp {
    /// `left == right`
    Eq,
    /// `left != right`
    NotEq,
    /// `left < right`
    Less,
    /// `left <= right`
    LessEq,
    /// `left > right`
    Greater,
    /// `left >= right`
    GreaterEq,
    /// `left && right`
    And,
    /// `left || right`
    Or,
    /// `left + right`
    Add,
    /// `left - right`
    Sub,
    /// `left * right`
    Mul,
    /// `left in right`
    In,
    /// `left.contains(right)`
    Contains,
    /// `left.containsAll(right)`
    ContainsAll,
    /// `left.containsAny(right)`
    ContainsAny,
    /// `left.getTag(right)`
    GetTag,
    /// `left.hasTag(right)`
    HasTag,
    /// `left.isInRange(right)`
    IsInRange,
    /// `left.offset(right)`
    Offset,
    /// `left.durationSince(right)`
    DurationSince,
    /// `left.lessThan(right)` (decimal less than)
    DecimalLessThan,
    /// `left.lessThanOrEqual(right)` (decimal less than or equal)
    DecimalLessEq,
    /// `left.greaterThan(right)` (decimal greater than)
    DecimalGreater,
    /// `left.greaterThanOrEqual(right)` (decimal greater than or equal)
    DecimalGreaterEq,
}

impl BinaryOp {
    pub(crate) fn to_name(self) -> Option<&'static ast::Name> {
        use crate::extensions;
        match self {
            BinaryOp::IsInRange => Some(&extensions::ipaddr::names::IS_IN_RANGE),
            BinaryOp::Offset => Some(&extensions::datetime::constants::OFFSET_METHOD_NAME),
            BinaryOp::DurationSince => Some(&extensions::datetime::constants::DURATION_SINCE_NAME),
            BinaryOp::DecimalLessThan => Some(&extensions::decimal::constants::LESS_THAN),
            BinaryOp::DecimalLessEq => Some(&extensions::decimal::constants::LESS_THAN_OR_EQUAL),
            BinaryOp::DecimalGreater => Some(&extensions::decimal::constants::GREATER_THAN),
            BinaryOp::DecimalGreaterEq => {
                Some(&extensions::decimal::constants::GREATER_THAN_OR_EQUAL)
            }
            // those are operators, not names
            BinaryOp::Eq
            | BinaryOp::NotEq
            | BinaryOp::And
            | BinaryOp::Or
            | BinaryOp::Less
            | BinaryOp::LessEq
            | BinaryOp::Greater
            | BinaryOp::GreaterEq
            | BinaryOp::Add
            | BinaryOp::Sub
            | BinaryOp::Mul
            | BinaryOp::In
            | BinaryOp::Contains
            | BinaryOp::ContainsAll
            | BinaryOp::ContainsAny
            | BinaryOp::GetTag
            | BinaryOp::HasTag => None,
        }
    }

    /// Parse a binary operator from a function name
    pub(crate) fn from_function_name(name: &str) -> Option<Self> {
        match name {
            "lessThan" => Some(BinaryOp::DecimalLessThan),
            "lessThanOrEqual" => Some(BinaryOp::DecimalLessEq),
            "greaterThan" => Some(BinaryOp::DecimalGreater),
            "greaterThanOrEqual" => Some(BinaryOp::DecimalGreaterEq),
            "isInRange" => Some(BinaryOp::IsInRange),
            "offset" => Some(BinaryOp::Offset),
            "durationSince" => Some(BinaryOp::DurationSince),
            _ => None,
        }
    }
}

impl Display for BinaryOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryOp::Eq => write!(f, "{}", ast::BinaryOp::Eq),
            BinaryOp::NotEq => write!(f, "{}", &constants::NOT_EQ_STR),
            BinaryOp::Less => write!(f, "{}", ast::BinaryOp::Less),
            BinaryOp::LessEq => write!(f, "{}", ast::BinaryOp::LessEq),
            BinaryOp::Greater => write!(f, "{}", &constants::GREATER_STR),
            BinaryOp::GreaterEq => write!(f, "{}", &constants::GREATER_EQ_STR),
            BinaryOp::And => write!(f, "{}", &constants::AND_STR),
            BinaryOp::Or => write!(f, "{}", &constants::OR_STR),
            BinaryOp::Add => write!(f, "{}", ast::BinaryOp::Add),
            BinaryOp::Sub => write!(f, "{}", ast::BinaryOp::Sub),
            BinaryOp::Mul => write!(f, "{}", ast::BinaryOp::Mul),
            BinaryOp::In => write!(f, "{}", ast::BinaryOp::In),
            BinaryOp::Contains => write!(f, "{}", ast::BinaryOp::Contains),
            BinaryOp::ContainsAll => write!(f, "{}", ast::BinaryOp::ContainsAll),
            BinaryOp::ContainsAny => write!(f, "{}", ast::BinaryOp::ContainsAny),
            BinaryOp::GetTag => write!(f, "{}", ast::BinaryOp::GetTag),
            BinaryOp::HasTag => write!(f, "{}", ast::BinaryOp::HasTag),
            // Extension functions - use their name
            _ => match self.to_name() {
                Some(name) => write!(f, "{}", name),
                None => write!(f, "<impossible operator>"),
            },
        }
    }
}

/// Literal values in Cedar expressions.
///
/// This enum is `#[non_exhaustive]`; match arms must include a wildcard.
///
/// ```cedar
/// true                    // Bool
/// 42                      // Long
/// "hello"                 // String
/// User::"alice"           // EntityUID
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Literal {
    /// `true` or `false`
    Bool(bool),
    /// Integer literal (e.g., `42`, `-1`)
    Long(i64),
    /// String literal (e.g., `"hello"`)
    String(SmolStr),
    /// Entity UID literal (e.g., `User::"alice"`)
    EntityUID(EntityUID),
}

/// Pattern element for `like` expressions.
///
/// A pattern is a sequence of literal characters and wildcards used with the `like` operator:
///
/// ```cedar
/// resource.name like "*.jpg"      // Wildcard then Char('.')...
/// resource.name like "photo_*"    // Char('p')... then Wildcard
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PatternElem {
    /// A literal character in the pattern
    Char(char),
    /// A wildcard (`*`) matching zero or more characters
    Wildcard,
}

/// PST Expression — the core expression type for Cedar policy conditions.
///
/// This enum is `#[non_exhaustive]`; match arms must include a wildcard.
///
/// Each variant corresponds to a Cedar syntax construct. See individual variant docs
/// for the Cedar syntax each one represents.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Expr {
    /// A literal value: `true`, `42`, `"hello"`, or `User::"alice"`.
    Literal(Literal),
    /// A built-in variable: `principal`, `action`, `resource`, or `context`.
    Var(Var),
    /// A template slot: `?principal` or `?resource`.
    Slot(SlotId),
    /// A unary operation.
    ///
    /// ```cedar
    /// !expr           // UnaryOp::Not
    /// -(expr)         // UnaryOp::Neg
    /// expr.isEmpty()  // UnaryOp::IsEmpty
    /// decimal("1.0")  // UnaryOp::Decimal
    /// ```
    UnaryOp {
        /// The operator
        op: UnaryOp,
        /// The operand
        expr: Arc<Expr>,
    },
    /// A binary operation.
    ///
    /// ```cedar
    /// context.age >= 18                   // BinaryOp::GreaterEq
    /// principal in Group::"admins"        // BinaryOp::In
    /// [1, 2].contains(1)                 // BinaryOp::Contains
    /// ```
    BinaryOp {
        /// The operator
        op: BinaryOp,
        /// Left operand
        left: Arc<Expr>,
        /// Right operand
        right: Arc<Expr>,
    },
    /// Attribute access.
    ///
    /// ```cedar
    /// principal.name
    /// context.request.ip
    /// ```
    GetAttr {
        /// Expression to get attribute from
        expr: Arc<Expr>,
        /// Attribute name
        attr: SmolStr,
    },
    /// Attribute existence check. Can check nested attributes.
    ///
    /// ```cedar
    /// principal has name
    /// principal has "0notACedarIdent"
    /// principal has address.street
    /// ```
    /// If there are more than one attribute, all attributes must be valid Cedar identifiers.
    HasAttr {
        /// Expression to check for attribute
        expr: Arc<Expr>,
        /// Attribute path (non-empty; multiple elements for nested checks)
        attrs: nonempty::NonEmpty<SmolStr>,
    },
    /// Pattern matching with the `like` operator.
    ///
    /// ```cedar
    /// resource.name like "*.jpg"
    /// ```
    Like {
        /// Expression to match
        expr: Arc<Expr>,
        /// Pattern to match against
        pattern: Vec<PatternElem>,
    },
    /// Entity type test, optionally combined with a hierarchy check.
    ///
    /// ```cedar
    /// principal is User
    /// principal is User in Group::"admins"
    /// ```
    Is {
        /// Expression to test
        expr: Arc<Expr>,
        /// Entity type to test for
        entity_type: EntityType,
        /// Optional `in` hierarchy parent
        in_expr: Option<Arc<Expr>>,
    },
    /// Conditional expression.
    ///
    /// ```cedar
    /// if context.is_admin then "yes" else "no"
    /// ```
    IfThenElse {
        /// Condition
        cond: Arc<Expr>,
        /// Then branch
        then_expr: Arc<Expr>,
        /// Else branch
        else_expr: Arc<Expr>,
    },
    /// Set literal.
    ///
    /// ```cedar
    /// [1, 2, 3]
    /// [User::"alice", User::"bob"]
    /// ```
    Set(Vec<Arc<Expr>>),
    /// Record literal.
    ///
    /// ```cedar
    /// {"key": "value", "count": 42}
    /// ```
    Record(BTreeMap<String, Arc<Expr>>),
    /// An unknown value for partial evaluation (not part of Cedar surface syntax).
    Unknown {
        /// Name of the unknown
        name: SmolStr,
    },
}

impl Expr {
    /// Transform a function call with arguments into a PST expression given the [`ast::Name`] of
    /// the function. Clones the string representation of the `ast::Name` given.
    pub(crate) fn from_function_ast_name_and_args(
        name: &ast::Name,
        args: Vec<Arc<Expr>>,
    ) -> Result<Expr, PstConstructionError> {
        Self::from_function_names_and_args(name.to_smolstr(), name, args)
    }

    /// Transform a function call with arguments into a PST expression given the [`ast::Name`] of
    /// the function, and its [SmolStr] name.
    /// Assumes the two names's representation as strings are equivalent, and does not clone.
    fn from_function_names_and_args(
        name: SmolStr,
        ast_name: &ast::Name,
        args: Vec<Arc<Expr>>,
    ) -> Result<Expr, PstConstructionError> {
        let extension = Extensions::all_available().func(ast_name)?;

        let expected = extension.arg_types().len();
        let got = args.len();

        if expected != got {
            return Err(error_body::WrongArityError::new(name.into(), expected, got).into());
        }
        Ok(match args.len() {
            1 => {
                #[expect(clippy::unwrap_used, reason = "length = 1 checked in arm")]
                let expr = args.into_iter().next().unwrap();
                // Special case: the unknown function
                if ast_name.to_string() == "unknown" {
                    return Ok(Expr::Unknown {
                        name: format!("{}", expr).into(),
                    });
                }
                let op = UnaryOp::from_function_name(&ast_name.to_string())
                    .ok_or_else(|| error_body::UnknownFunctionError::new(name.clone()))?;
                Expr::UnaryOp { op, expr }
            }
            2 => {
                let op = BinaryOp::from_function_name(&ast_name.to_string())
                    .ok_or_else(|| error_body::UnknownFunctionError::new(name.clone()))?;
                let mut iter = args.into_iter();
                Expr::BinaryOp {
                    op,
                    #[expect(clippy::unwrap_used, reason = "length = 2 checked in match arm")]
                    left: iter.next().unwrap(),
                    #[expect(clippy::unwrap_used, reason = "length = 2 checked in match arm")]
                    right: iter.next().unwrap(),
                }
            }
            _ => return Err(error_body::UnknownFunctionError::new(name).into()),
        })
    }

    // === Expression reduction functions ===

    /// Recursively accumulate a value over this expression tree.
    ///
    /// At each node, `f` is called first. If it returns `Some(t)`, that value is returned
    /// immediately without recursing into children. Otherwise, the results of recursing into
    /// all child expressions are merged pairwise with `op`. If a node has no children,
    /// `zero` is returned.
    pub fn reduce<T: Clone + Sized>(
        &self,
        f: &dyn Fn(&Self) -> Option<T>,
        op: &dyn Fn(T, T) -> T,
        zero: T,
    ) -> T {
        if let Some(t) = f(self) {
            return t;
        }
        let recurse = |e: &Arc<Self>| e.reduce(f, op, zero.clone());
        match self {
            Expr::Literal(_) | Expr::Var(_) | Expr::Slot(_) | Expr::Unknown { .. } => zero,
            Expr::UnaryOp { expr, .. }
            | Expr::GetAttr { expr, .. }
            | Expr::HasAttr { expr, .. }
            | Expr::Like { expr, .. } => recurse(expr),
            Expr::BinaryOp { left, right, .. } => op(recurse(left), recurse(right)),
            Expr::Is { expr, in_expr, .. } => match in_expr {
                Some(e) => op(recurse(expr), recurse(e)),
                None => recurse(expr),
            },
            Expr::IfThenElse {
                cond,
                then_expr,
                else_expr,
            } => op(op(recurse(cond), recurse(then_expr)), recurse(else_expr)),
            Expr::Set(exprs) => {
                let mut iter = exprs.iter();
                match iter.next() {
                    None => zero,
                    Some(first) => iter.fold(recurse(first), |acc, e| op(acc, recurse(e))),
                }
            }
            Expr::Record(map) => {
                let mut iter = map.values();
                match iter.next() {
                    None => zero,
                    Some(first) => iter.fold(recurse(first), |acc, e| op(acc, recurse(e))),
                }
            }
        }
    }

    /// Does this expression contain any slots?
    pub fn has_slots(&self) -> bool {
        self.reduce::<bool>(
            &|e| match e {
                Expr::Slot(_) => Some(true),
                _ => None,
            },
            &|a, b| a || b,
            false,
        )
    }

    /// Return the slots used in this expression
    pub fn slots(&self) -> HashSet<SlotId> {
        self.reduce::<HashSet<SlotId>>(
            &|e| match e {
                Expr::Slot(id) => Some(HashSet::from([*id])),
                _ => None,
            },
            &|a, b| a.union(&b).copied().collect(),
            HashSet::new(),
        )
    }
}

/// Builder to construct a PST [`Expr`] that implements the [`ExprBuilder`] interface. Unlike the
/// expression building functions, this does not perform any validation on the input and is meant
/// to be used internally.
#[derive(Clone, Debug)]
pub(crate) struct PstBuilder;

impl ExprBuilder for PstBuilder {
    type Expr = Expr;
    type Data = ();
    type BuildError = PstConstructionError;

    #[cfg(feature = "tolerant-ast")]
    type ErrorType = crate::parser::err::ParseErrors;

    fn with_data(_data: Self::Data) -> Self {
        Self
    }

    fn with_maybe_source_loc(self, _: Option<&crate::parser::Loc>) -> Self {
        // PST doesn't store source locations
        self
    }

    fn loc(&self) -> Option<&crate::parser::Loc> {
        None
    }

    fn data(&self) -> &Self::Data {
        &()
    }

    fn val(self, lit: impl Into<ast::Literal>) -> Expr {
        Expr::Literal(From::<ast::Literal>::from(lit.into()))
    }

    fn var(self, var: ast::Var) -> Expr {
        Expr::Var(var.into())
    }

    fn unknown(self, u: ast::Unknown) -> Expr {
        Expr::Unknown { name: u.name }
    }

    fn slot(self, s: ast::SlotId) -> Expr {
        Expr::Slot(s.into())
    }

    fn ite_arc(self, cond: Arc<Expr>, then_expr: Arc<Expr>, else_expr: Arc<Expr>) -> Expr {
        Expr::IfThenElse {
            cond,
            then_expr,
            else_expr,
        }
    }

    fn not(self, e: Expr) -> Expr {
        Expr::UnaryOp {
            op: UnaryOp::Not,
            expr: Arc::new(e),
        }
    }

    fn is_eq(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::Eq,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn noteq(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::NotEq,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn and(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::And,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn or(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::Or,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn less(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::Less,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn lesseq(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::LessEq,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn greater(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::Greater,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn greatereq(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::GreaterEq,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn add(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::Add,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn sub(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::Sub,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn mul(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::Mul,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn neg(self, e: Expr) -> Expr {
        Expr::UnaryOp {
            op: UnaryOp::Neg,
            expr: Arc::new(e),
        }
    }

    fn is_in_arc(self, left: Arc<Expr>, right: Arc<Expr>) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::In,
            left,
            right,
        }
    }

    fn contains(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::Contains,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn contains_all(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::ContainsAll,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn contains_any(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::ContainsAny,
            left: Arc::new(e1),
            right: Arc::new(e2),
        }
    }

    fn is_empty(self, expr: Expr) -> Expr {
        Expr::UnaryOp {
            op: UnaryOp::IsEmpty,
            expr: Arc::new(expr),
        }
    }

    fn get_tag(self, expr: Expr, tag: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::GetTag,
            left: Arc::new(expr),
            right: Arc::new(tag),
        }
    }

    fn has_tag(self, expr: Expr, tag: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::HasTag,
            left: Arc::new(expr),
            right: Arc::new(tag),
        }
    }

    fn set(self, exprs: impl IntoIterator<Item = Expr>) -> Expr {
        Expr::Set(exprs.into_iter().map(Arc::new).collect())
    }

    fn record(
        self,
        pairs: impl IntoIterator<Item = (SmolStr, Expr)>,
    ) -> Result<Expr, ast::ExpressionConstructionError> {
        let mut map = BTreeMap::new();
        for (k, v) in pairs {
            if map.insert(k.to_string(), Arc::new(v)).is_some() {
                return Err(ast::expression_construction_errors::DuplicateKeyError {
                    key: k,
                    context: "in record literal",
                }
                .into());
            }
        }
        Ok(Expr::Record(map))
    }

    fn call_extension_fn(
        self,
        fn_name: ast::Name,
        args: impl IntoIterator<Item = Expr>,
    ) -> Result<Expr, PstConstructionError> {
        Expr::from_function_ast_name_and_args(&fn_name, args.into_iter().map(Arc::new).collect())
    }

    fn get_attr_arc(self, expr: Arc<Expr>, attr: SmolStr) -> Expr {
        Expr::GetAttr { expr, attr }
    }

    fn has_attr_arc(self, expr: Arc<Expr>, attr: SmolStr) -> Expr {
        Expr::HasAttr {
            expr,
            attrs: nonempty::nonempty![attr],
        }
    }

    fn extended_has_attr_arc(self, expr: Arc<Expr>, attrs: nonempty::NonEmpty<SmolStr>) -> Expr {
        Expr::HasAttr { expr, attrs }
    }

    fn like(self, expr: Expr, pattern: ast::Pattern) -> Expr {
        Expr::Like {
            expr: Arc::new(expr),
            pattern: pattern.into(),
        }
    }

    fn is_entity_type_arc(self, expr: Arc<Expr>, entity_type: ast::EntityType) -> Expr {
        Expr::Is {
            expr,
            entity_type: entity_type.into(),
            in_expr: None,
        }
    }

    fn is_in_entity_type(self, e1: Expr, entity_type: ast::EntityType, e2: Expr) -> Expr {
        Expr::Is {
            expr: Arc::new(e1),
            entity_type: entity_type.into(),
            in_expr: Some(Arc::new(e2)),
        }
    }

    #[cfg(feature = "tolerant-ast")]
    fn error(
        self,
        parse_errors: crate::parser::err::ParseErrors,
    ) -> Result<Self::Expr, Self::ErrorType> {
        // PST doesn't support error nodes for now, it will propagate parse errors
        Err(parse_errors)
    }
}

impl std::fmt::Display for Expr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // This Display implementation is mostly for debugging purposes, and it does not print
        // valid Cedar expressions.
        // If you need to print a valid Cedar expression from a PST expression, you should convert
        // it to an EST expression first.
        match self {
            Expr::Literal(lit) => match lit {
                Literal::Bool(b) => write!(f, "{}", b),
                Literal::Long(i) => write!(f, "{}", i),
                Literal::String(s) => write!(f, "\"{}\"", s.escape_default()),
                Literal::EntityUID(uid) => write!(f, "{}", uid),
            },
            Expr::Var(v) => match v {
                Var::Principal => write!(f, "principal"),
                Var::Action => write!(f, "action"),
                Var::Resource => write!(f, "resource"),
                Var::Context => write!(f, "context"),
            },
            Expr::Slot(s) => write!(f, "{}", s),
            Expr::UnaryOp { op, expr } => write!(f, "{}({})", op, expr),
            Expr::BinaryOp { op, left, right } => write!(f, "({} {} {})", left, op, right),
            Expr::GetAttr { expr, attr } => write!(f, "{}.{}", expr, attr),
            Expr::HasAttr { expr, attrs } => {
                write!(
                    f,
                    "{} has {}",
                    expr,
                    attrs
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(".")
                )
            }
            Expr::Like { expr, pattern } => {
                write!(f, "{} like \"", expr)?;
                for elem in pattern {
                    match elem {
                        PatternElem::Char(c) => write!(f, "{}", c.escape_default())?,
                        PatternElem::Wildcard => write!(f, "*")?,
                    }
                }
                write!(f, "\"")
            }
            Expr::Is {
                expr,
                entity_type,
                in_expr,
            } => {
                if let Some(in_e) = in_expr {
                    write!(f, "{} is {} in {}", expr, entity_type, in_e)
                } else {
                    write!(f, "{} is {}", expr, entity_type)
                }
            }
            Expr::IfThenElse {
                cond,
                then_expr,
                else_expr,
            } => {
                write!(f, "if {} then {} else {}", cond, then_expr, else_expr)
            }
            Expr::Set(exprs) => {
                write!(
                    f,
                    "[{}]",
                    exprs
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Expr::Record(map) => {
                write!(
                    f,
                    "{{{}}}",
                    map.iter()
                        .map(|(k, v)| format!("\"{}\": {}", k.escape_default(), v))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Expr::Unknown { name } => write!(f, "{}", name),
        }
    }
}

#[expect(
    clippy::fallible_impl_from,
    reason = "AST records cannot have duplicate keys, so builder.record() cannot fail"
)]
#[cfg(test)]
mod tests {
    use cool_asserts::assertion_failure;

    use super::*;
    use std::str::FromStr;

    // --- Id tests ---

    #[test]
    fn test_id_valid_identifiers() {
        // Simple identifiers
        assert!(Id::new("x").is_ok());
        assert!(Id::new("userName").is_ok());
        assert!(Id::new("_private").is_ok());
        assert!(Id::new("a1").is_ok());
        assert!(Id::new("ABC").is_ok());
    }

    #[test]
    fn test_id_reserved_keywords_rejected() {
        for kw in [
            "if", "then", "else", "true", "false", "in", "is", "like", "has",
        ] {
            assert!(Id::new(kw).is_err(), "keyword `{kw}` should be rejected");
        }
    }

    #[test]
    fn test_id_invalid_strings_rejected() {
        assert!(Id::new("").is_err());
        assert!(Id::new("1abc").is_err()); // starts with digit
        assert!(Id::new("a b").is_err()); // space
        assert!(Id::new("a+b").is_err()); // special char
        assert!(Id::new("::").is_err());
    }

    #[test]
    fn test_id_accessors() {
        let id = Id::new("hello").unwrap();
        assert_eq!(id.as_str(), "hello");
        assert_eq!(id.as_ref(), "hello");
        assert_eq!(id.to_string(), "hello");
        assert_eq!(id.clone().into_smolstr(), SmolStr::from("hello"));
    }

    #[test]
    fn test_id_equality_and_ordering() {
        let a = Id::new("aaa").unwrap();
        let b = Id::new("bbb").unwrap();
        let a2 = Id::new("aaa").unwrap();
        assert_eq!(a, a2);
        assert_ne!(a, b);
        assert!(a < b);
    }

    #[test]
    fn test_id_from_ast_id() {
        let ast_id = crate::ast::Id::from_str("myIdent").unwrap();
        let pst_id = Id::from(ast_id);
        assert_eq!(pst_id.as_str(), "myIdent");
    }

    // --- Name tests ---

    #[test]
    fn test_name_unqualified() {
        let name = Name::unqualified("User").unwrap();
        assert_eq!(name.id.as_str(), "User");
        assert!(name.namespace.is_empty());
        assert_eq!(name.to_string(), "User");
    }

    #[test]
    fn test_name_qualified() {
        let name = Name::qualified(["MyApp", "Auth"], "User").unwrap();
        assert_eq!(name.id.as_str(), "User");
        assert_eq!(name.namespace.len(), 2);
        assert_eq!(name.namespace[0].as_str(), "MyApp");
        assert_eq!(name.namespace[1].as_str(), "Auth");
        assert_eq!(name.to_string(), "MyApp::Auth::User");
    }

    #[test]
    fn test_name_rejects_invalid_basename() {
        assert!(Name::unqualified("if").is_err());
        assert!(Name::unqualified("1bad").is_err());
        assert!(Name::qualified(["Good"], "if").is_err());
    }

    #[test]
    fn test_name_rejects_invalid_namespace_component() {
        assert!(Name::qualified(["true"], "User").is_err());
        assert!(Name::qualified(["ok", "1bad"], "User").is_err());
    }

    #[test]
    fn test_name_roundtrip_through_ast() {
        let pst_name = Name::qualified(["NS"], "Foo").unwrap();
        let ast_name: crate::ast::Name = pst_name.clone().into();
        let back: Name = ast_name.into();
        assert_eq!(pst_name, back);
    }

    // --- EntityType / EntityUID with validated names ---

    #[test]
    fn test_entity_type_display_with_valid_name() {
        let et = EntityType::from_name(Name::unqualified("User").unwrap());
        assert_eq!(et.to_string(), "User");
        let et = EntityType::from_name(Name::qualified(["App"], "Photo").unwrap());
        assert_eq!(et.to_string(), "App::Photo");
    }

    #[test]
    fn test_entity_uid_roundtrip_through_ast() {
        let uid = EntityUID {
            ty: EntityType::from_name(Name::qualified(["NS"], "Type").unwrap()),
            eid: SmolStr::from("eid123"),
        };
        let ast_uid: crate::ast::EntityUID = uid.clone().into();
        let back: EntityUID = ast_uid.into();
        assert_eq!(uid, back);
    }

    #[test]
    fn test_has_slots() {
        // Leaf with no slot
        assert!(!Expr::Literal(Literal::Long(1)).has_slots());
        // Var has no slot
        assert!(!Expr::Var(Var::Principal).has_slots());
        // Slot itself
        assert!(Expr::Slot(SlotId::Principal).has_slots());
        assert!(Expr::Slot(SlotId::Resource).has_slots());
        // Slot nested inside a BinaryOp
        let slot = Arc::new(Expr::Slot(SlotId::Principal));
        let lit = Arc::new(Expr::Literal(Literal::Long(42)));
        let binop = Expr::BinaryOp {
            op: BinaryOp::Eq,
            left: slot,
            right: lit.clone(),
        };
        assert!(binop.has_slots());
        // BinaryOp with no slots
        let binop_no_slot = Expr::BinaryOp {
            op: BinaryOp::Eq,
            left: lit.clone(),
            right: lit.clone(),
        };
        assert!(!binop_no_slot.has_slots());
        // Slot nested inside a Set
        let set_with_slot = Expr::Set(vec![lit.clone(), Arc::new(Expr::Slot(SlotId::Resource))]);
        assert!(set_with_slot.has_slots());
        // Empty set
        assert!(!Expr::Set(vec![]).has_slots());
        // IfThenElse with slot in else branch
        let ite = Expr::IfThenElse {
            cond: lit.clone(),
            then_expr: lit.clone(),
            else_expr: Arc::new(Expr::Slot(SlotId::Principal)),
        };
        assert!(ite.has_slots());
    }

    #[test]
    fn test_from_function_unknown_function() {
        let name = ast::Name::parse_unqualified_name("unknownFunc").unwrap();
        let args = vec![Arc::new(Expr::Literal(Literal::Long(1)))];

        let result = Expr::from_function_ast_name_and_args(&name, args);
        assert!(matches!(
            result,
            Err(PstConstructionError::UnknownFunction(..))
        ));
    }

    #[test]
    fn test_from_function_wrong_arity() {
        let name = ast::Name::parse_unqualified_name("decimal").unwrap();
        let args = vec![
            Arc::new(Expr::Literal(Literal::Long(1))),
            Arc::new(Expr::Literal(Literal::Long(2))),
        ];

        let result = Expr::from_function_ast_name_and_args(&name, args);
        assert!(matches!(result, Err(PstConstructionError::WrongArity(..))));
    }

    #[test]
    fn test_all_extension_functions_are_supported() {
        // This test ensures that all extension functions defined in Extensions
        // are properly mapped to PST operators (UnaryOp or BinaryOp)
        let extensions = Extensions::all_available();

        for func in extensions.all_funcs() {
            let name = func.name().clone();
            let arity = func.arg_types().len();

            // Create dummy "0" arguments based on arity, we don't typecheck here
            let args: Vec<Arc<Expr>> = (0..arity)
                .map(|_| Arc::new(Expr::Literal(Literal::Long(0))))
                .collect();

            let result = Expr::from_function_ast_name_and_args(&name, args);
            assert!(
                result.is_ok(),
                "Function {} should be supported but got error: {:?}",
                name,
                result.err()
            );
            let actual = result.unwrap();
            print!("Expression: {}", actual);
            match arity {
                1 => {
                    if &name.to_string() == "unknown" {
                        assert!(
                            matches!(actual, Expr::Unknown { .. }),
                            "Expected unary unknown function to be Unknown expr",
                        );
                    } else {
                        match actual {
                            Expr::UnaryOp { op, .. } => {
                                let op_name = op.to_name();
                                assert!(
                                    op_name.is_some(),
                                    "UnaryOp from extension {} should have known ast::Name",
                                    name
                                );
                                assert_eq!(
                                    UnaryOp::from_function_name(&name.as_ref().to_string()),
                                    Some(op)
                                );
                            }
                            _ => {
                                assertion_failure!("Unary function  should produce BinaryOp", name:name)
                            }
                        }
                    }
                }
                2 => match actual {
                    Expr::BinaryOp { op, .. } => {
                        let op_name = op.to_name();
                        assert!(
                            op_name.is_some(),
                            "BinaryOp from extension {} should have known ast::Name",
                            name
                        );
                        assert_eq!(
                            BinaryOp::from_function_name(&name.as_ref().to_string()),
                            Some(op)
                        );
                    }
                    _ => assertion_failure!("Binary function  should produce BinaryOp", name:name),
                },
                _ => (),
            }
        }
    }

    #[test]
    fn test_expr_construction_error_display() {
        let err: PstConstructionError =
            error_body::UnknownFunctionError::new("foo".to_smolstr()).into();
        assert!(err.to_string().contains("foo"));

        let err: PstConstructionError =
            error_body::WrongArityError::new("bar".to_string(), 2, 1).into();
        assert!(err.to_string().contains("bar"));
        assert!(err.to_string().contains("2"));
        assert!(err.to_string().contains("1"));
    }

    #[test]
    fn test_builder_additional_methods() {
        // Test unknown
        let expr = PstBuilder::new().unknown(ast::Unknown::new_untyped("test"));
        assert!(matches!(expr, Expr::Unknown { .. }));

        // Test like
        let base = PstBuilder::new().val("test");
        let pattern = ast::Pattern::from(vec![ast::PatternElem::Char('a')]);
        let expr = PstBuilder::new().like(base, pattern);
        assert!(matches!(expr, Expr::Like { .. }));

        // Test is_in_entity_type
        let base = PstBuilder::new().var(ast::Var::Principal);
        let entity_type = EntityType::from_name(ast::Name::parse_unqualified_name("User").unwrap());
        let uid = ast::EntityUID::from_components(
            ast::EntityType::from(ast::Name::parse_unqualified_name("User").unwrap()),
            ast::Eid::new("alice"),
            None,
        );
        let in_expr = PstBuilder::new().val(uid);
        let expr = PstBuilder::new().is_in_entity_type(
            base,
            entity_type.clone().try_into().unwrap(),
            in_expr,
        );
        if let Expr::Is {
            entity_type: et,
            in_expr: Some(_),
            ..
        } = expr
        {
            assert_eq!(et, entity_type);
        } else {
            panic!("Expected Is with in_expr");
        }
    }

    #[test]
    fn test_builder_record_duplicate_keys() {
        let pairs = vec![
            (SmolStr::new("key"), PstBuilder::new().val(1i64)),
            (SmolStr::new("key"), PstBuilder::new().val(2i64)),
        ];
        let result = PstBuilder::new().record(pairs);
        assert!(matches!(
            result,
            Err(ast::ExpressionConstructionError::DuplicateKey { .. })
        ));
    }

    mod display_tests {
        use super::*;
        use smol_str::SmolStr;

        #[test]
        fn invalid_name_rejected_at_construction() {
            let name = "!__Cedar!";
            assert!(Name::unqualified(name).is_err());
        }

        // NOTE: These tests verify Display output for expressions constructed via the
        // ExprBuilder trait (internal builder). Some operators are desugared during
        // construction (e.g., != becomes !(==), > becomes !(<=), && and || may become
        // if-then-else in AST but remain as BinaryOp in PST).
        //
        // Once a public expression builder API is implemented that constructs PST
        // directly without desugaring, Display will show all operators in their
        // original form (!=, >, >=, &&, ||, etc.).

        fn builder() -> PstBuilder {
            PstBuilder::new()
        }

        #[test]
        fn test_builder_display() {
            let cases = vec![
                // Literals
                (builder().val(true), "true"),
                (builder().val(false), "false"),
                (builder().val(42i64), "42"),
                (builder().val(-123i64), "-123"),
                (builder().val("hello"), "\"hello\""),
                (
                    builder().val(ast::EntityUID::from_components(
                        ast::Name::from_str("Photo").unwrap().into(),
                        ast::Eid::new("abc123"),
                        None,
                    )),
                    "Photo::\"abc123\"",
                ),
                // Variables
                (builder().var(ast::Var::Principal), "principal"),
                (builder().var(ast::Var::Action), "action"),
                (builder().var(ast::Var::Resource), "resource"),
                (builder().var(ast::Var::Context), "context"),
                // Slots
                (builder().slot(ast::SlotId::principal()), "?principal"),
                (builder().slot(ast::SlotId::resource()), "?resource"),
                // Basic unary ops
                (builder().not(builder().val(true)), "!(true)"),
                (builder().neg(builder().val(42i64)), "-(42)"),
                // Binary ops - comparison
                (
                    builder().is_eq(builder().val(1i64), builder().val(2i64)),
                    "(1 == 2)",
                ),
                (
                    builder().noteq(builder().val(1i64), builder().val(2i64)),
                    "(1 != 2)",
                ),
                (
                    builder().less(builder().val(1i64), builder().val(2i64)),
                    "(1 < 2)",
                ),
                (
                    builder().lesseq(builder().val(1i64), builder().val(2i64)),
                    "(1 <= 2)",
                ),
                (
                    builder().greater(builder().val(1i64), builder().val(2i64)),
                    "(1 > 2)",
                ),
                (
                    builder().greatereq(builder().val(1i64), builder().val(2i64)),
                    "(1 >= 2)",
                ),
                // Binary ops - logical
                (
                    builder().and(builder().val(true), builder().val(false)),
                    "(true && false)",
                ),
                (
                    builder().or(builder().val(true), builder().val(false)),
                    "(true || false)",
                ),
                // Binary ops - arithmetic
                (
                    builder().add(builder().val(1i64), builder().val(2i64)),
                    "(1 + 2)",
                ),
                (
                    builder().sub(builder().val(5i64), builder().val(3i64)),
                    "(5 - 3)",
                ),
                (
                    builder().mul(builder().val(2i64), builder().val(3i64)),
                    "(2 * 3)",
                ),
                // Binary ops - set/hierarchy
                (
                    builder().is_in(
                        builder().var(ast::Var::Principal),
                        builder().var(ast::Var::Resource),
                    ),
                    "(principal in resource)",
                ),
                (
                    builder().contains(builder().set([builder().val(1i64)]), builder().val(1i64)),
                    "([1] contains 1)",
                ),
                (
                    builder().contains_all(
                        builder().set([builder().val(1i64)]),
                        builder().set([builder().val(1i64)]),
                    ),
                    "([1] containsAll [1])",
                ),
                (
                    builder().contains_any(
                        builder().set([builder().val(1i64)]),
                        builder().set([builder().val(1i64)]),
                    ),
                    "([1] containsAny [1])",
                ),
                // Attribute access
                (
                    builder().get_attr(builder().var(ast::Var::Principal), SmolStr::from("name")),
                    "principal.name",
                ),
                (
                    builder().has_attr(builder().var(ast::Var::Principal), SmolStr::from("name")),
                    "principal has name",
                ),
                (
                    builder().is_entity_type(
                        builder().var(ast::Var::Resource),
                        ast::Name::from_str("Photo").unwrap().into(),
                    ),
                    "resource is Photo",
                ),
                // If-then-else
                (
                    builder().ite(
                        builder().val(true),
                        builder().val(1i64),
                        builder().val(2i64),
                    ),
                    "if true then 1 else 2",
                ),
                // Sets
                (builder().set([]), "[]"),
                (builder().set([builder().val(1i64)]), "[1]"),
                (
                    builder().set([
                        builder().val(1i64),
                        builder().val(2i64),
                        builder().val(3i64),
                    ]),
                    "[1, 2, 3]",
                ),
                // Records
                (builder().record([]).unwrap(), "{}"),
                (
                    builder()
                        .record([(SmolStr::from("a"), builder().val(1i64))])
                        .unwrap(),
                    "{\"a\": 1}",
                ),
                (
                    builder()
                        .record([
                            (SmolStr::from("a"), builder().val(1i64)),
                            (SmolStr::from("b"), builder().val(2i64)),
                        ])
                        .unwrap(),
                    "{\"a\": 1, \"b\": 2}",
                ),
                // Tags
                (
                    builder().has_tag(builder().var(ast::Var::Action), builder().val("tag")),
                    "(action hasTag \"tag\")",
                ),
                (
                    builder().get_tag(builder().var(ast::Var::Action), builder().val("tag")),
                    "(action getTag \"tag\")",
                ),
                // Like
                (
                    builder().like(
                        builder().val("hello"),
                        ast::Pattern::from(vec![
                            ast::PatternElem::Char('h'),
                            ast::PatternElem::Wildcard,
                        ]),
                    ),
                    "\"hello\" like \"h*\"",
                ),
                // Function calls
                (
                    builder()
                        .call_extension_fn(
                            Name::unqualified("decimal").unwrap().into(),
                            vec![builder().val("1.23")],
                        )
                        .unwrap(),
                    "decimal(\"1.23\")",
                ),
            ];

            for (expr, expected) in cases {
                assert_eq!(expr.to_string(), expected, "Failed for: {}", expected);
            }

            let fail_func = builder().call_extension_fn(
                Name::unqualified("notAFunc").unwrap().into(),
                vec![builder().val("12.3")],
            );
            assert!(fail_func.is_err());
        }

        #[test]
        fn test_complex_expressions() {
            // Nested binary ops
            let nested = builder().is_eq(
                builder().add(builder().val(1i64), builder().val(2i64)),
                builder().val(3i64),
            );
            assert_eq!(nested.to_string(), "((1 + 2) == 3)");

            // Complex if-then-else
            let complex = builder().ite(
                builder().greater(
                    builder().get_attr(builder().var(ast::Var::Principal), SmolStr::from("age")),
                    builder().val(18i64),
                ),
                builder().get_attr(builder().var(ast::Var::Principal), SmolStr::from("name")),
                builder().val("unknown"),
            );
            assert_eq!(
                complex.to_string(),
                "if (principal.age > 18) then principal.name else \"unknown\""
            );

            // isEmpty
            let is_empty = builder().is_empty(builder().set([]));
            assert_eq!(is_empty.to_string(), "isEmpty([])");
        }

        #[test]
        fn test_unary_op_display_no_impossible_operator() {
            // Test that all UnaryOp variants display without showing "<impossible operator>"
            let ops = [
                UnaryOp::Not,
                UnaryOp::Neg,
                UnaryOp::IsEmpty,
                UnaryOp::Datetime,
                UnaryOp::Decimal,
                UnaryOp::Duration,
                UnaryOp::Ip,
                UnaryOp::IsIPv4,
                UnaryOp::IsIPV6,
                UnaryOp::IsLoopback,
                UnaryOp::IsMulticast,
                UnaryOp::ToDate,
                UnaryOp::ToTime,
                UnaryOp::ToMilliseconds,
                UnaryOp::ToSeconds,
                UnaryOp::ToMinutes,
                UnaryOp::ToHours,
                UnaryOp::ToDays,
            ];

            for op in ops {
                let display = op.to_string();
                assert_ne!(
                    display, "<impossible operator>",
                    "UnaryOp::{:?} should not display as impossible operator",
                    op
                );
            }
        }

        #[test]
        fn test_binary_op_display_no_impossible_operator() {
            // Test that all BinaryOp variants display without showing "<impossible operator>"
            let ops = [
                BinaryOp::Eq,
                BinaryOp::NotEq,
                BinaryOp::Less,
                BinaryOp::LessEq,
                BinaryOp::Greater,
                BinaryOp::GreaterEq,
                BinaryOp::And,
                BinaryOp::Or,
                BinaryOp::Add,
                BinaryOp::Sub,
                BinaryOp::Mul,
                BinaryOp::In,
                BinaryOp::Contains,
                BinaryOp::ContainsAll,
                BinaryOp::ContainsAny,
                BinaryOp::GetTag,
                BinaryOp::HasTag,
                BinaryOp::IsInRange,
                BinaryOp::Offset,
                BinaryOp::DurationSince,
            ];

            for op in ops {
                let display = op.to_string();
                assert_ne!(
                    display, "<impossible operator>",
                    "BinaryOp::{:?} should not display as impossible operator",
                    op
                );
            }
        }
    }
}
