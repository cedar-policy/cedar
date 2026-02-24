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

//! Expression types for PST

use crate::ast;
use crate::expr_builder::ExprBuilder;
use crate::extensions::{ExtensionFunctionLookupError, Extensions};
use itertools::Itertools;
use smol_str::{SmolStr, ToSmolStr};
use std::collections::BTreeMap;
use std::fmt::Display;
use std::str::FromStr;
use std::sync::Arc;

/// Slot identifier for template policies
///
/// Cedar supports two slot types: `principal` and `resource`
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SlotId {
    /// Principal slot
    Principal,
    /// Resource slot
    Resource,
}

impl From<ast::SlotId> for SlotId {
    fn from(slot: ast::SlotId) -> Self {
        match slot.0 {
            ast::ValidSlotId::Principal => SlotId::Principal,
            ast::ValidSlotId::Resource => SlotId::Resource,
        }
    }
}

impl From<SlotId> for ast::SlotId {
    fn from(slot: SlotId) -> Self {
        match slot {
            SlotId::Principal => ast::SlotId::principal(),
            SlotId::Resource => ast::SlotId::resource(),
        }
    }
}

impl Display for SlotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b: ast::SlotId = (*self).into();
        write!(f, "{}", b)
    }
}

/// A qualified name (e.g., `Namespace::Type`)
///
/// Represents entity types, action names, and other identifiers in Cedar.
/// Names consist of a basename and optional namespace components.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Name {
    /// Basename (the final component of the name)
    pub id: SmolStr,
    /// Namespace components (empty for unqualified names)
    pub namespace: Arc<Vec<SmolStr>>,
}

impl Name {
    /// Constructs a simple (unqualified) name.
    pub fn simple(id: impl Into<SmolStr>) -> Self {
        Name {
            id: id.into(),
            namespace: Arc::new(vec![]),
        }
    }

    /// Constructs a qualified name (i.e. with a possible non-empty namespace)
    pub fn qualified<I, T>(namespace: I, id: impl Into<SmolStr>) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<SmolStr>,
    {
        Name {
            id: id.into(),
            namespace: Arc::new(namespace.into_iter().map(|x| x.into()).collect()),
        }
    }
}

impl From<ast::Name> for Name {
    fn from(name: ast::Name) -> Self {
        Name {
            id: name.basename().to_smolstr(),
            namespace: Arc::new(
                name.as_ref()
                    .namespace_components()
                    .map(|id| id.to_smolstr())
                    .collect(),
            ),
        }
    }
}

impl TryFrom<Name> for ast::Name {
    type Error = crate::parser::err::ParseErrors;

    fn try_from(name: Name) -> Result<Self, Self::Error> {
        let basename = ast::Id::from_str(&name.id)?;
        let path: Vec<ast::Id> = name
            .namespace
            .iter()
            .map(|s| ast::Id::from_str(s.as_str()))
            .try_collect()?;
        Ok(ast::Name(ast::InternalName::new(basename, path, None)))
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

/// Entity type name
///
/// Represents the type of an entity in Cedar (e.g., `User`, `Photo`, `Namespace::Resource`)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntityType(pub Name);

impl EntityType {
    /// Create an entity type from a name
    pub fn from_name(name: impl Into<Name>) -> Self {
        EntityType(name.into())
    }
}

impl From<ast::EntityType> for EntityType {
    fn from(et: ast::EntityType) -> Self {
        EntityType(Name {
            id: et.name().basename().to_smolstr(),
            namespace: Arc::new(
                et.name()
                    .0
                    .namespace_components()
                    .map(|id| id.to_smolstr())
                    .collect(),
            ),
        })
    }
}

impl TryFrom<EntityType> for ast::EntityType {
    type Error = crate::parser::err::ParseErrors;

    fn try_from(et: EntityType) -> Result<Self, Self::Error> {
        Ok(ast::EntityType::EntityType(et.0.try_into()?))
    }
}

impl Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ast_et: Result<ast::EntityType, _> = self.clone().try_into();
        match ast_et {
            Ok(n) => write!(f, "{}", n),
            Err(_) => write!(f, "<invalid entity type>"),
        }
    }
}

/// Entity unique identifier (UID)
///
/// Represents a specific entity instance in Cedar (e.g., `User::"alice"`)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntityUID {
    /// Type of the entity
    pub ty: EntityType,
    /// Entity identifier (EID)
    pub eid: SmolStr,
}

impl From<ast::EntityUID> for EntityUID {
    fn from(uid: ast::EntityUID) -> Self {
        let (ty, eid) = uid.components();
        EntityUID {
            ty: ty.into(),
            eid: eid.into_smolstr(),
        }
    }
}

impl Display for EntityUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::\"{}\"", self.ty, self.eid.as_str().escape_default())
    }
}

/// Variables available in Cedar policy expressions
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Var {
    /// The `principal` variable
    Principal,
    /// The `action` variable
    Action,
    /// The `resource` variable
    Resource,
    /// The `context` variable
    Context,
}

/// Unary operators in Cedar expressions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UnaryOp {
    /// Logical not (`!`)
    Not,
    /// Arithmetic negation (`-`)
    Neg,
    /// Test set empty
    IsEmpty,
    /// Parse string and construct a datetime
    Datetime,
    /// Parse string and construct a decimal
    Decimal,
    /// Parse string and construct a duration
    Duration,
    /// Parse string and construct an ip address
    Ip,
    /// Test for a valid ipv4 address
    IsIPv4,
    /// Test for a valid ipv6 address
    IsIPV6,
    /// Test for IP loopback address
    IsLoopback,
    /// Test for multicast address
    IsMulticast,
    /// Extract date portion as new datetime
    ToDate,
    /// Extract time as duration
    ToTime,
    /// Convert to milliseconds
    ToMilliseconds,
    /// Convert to seconds
    ToSeconds,
    /// Convert to minutes
    ToMinutes,
    /// Convert to hours
    ToHours,
    /// Convert to days
    ToDays,
}

impl UnaryOp {
    /// Get the Cedar syntax representation of this operator
    pub const fn as_str(self) -> &'static str {
        match self {
            UnaryOp::Not => "!",
            UnaryOp::Neg => "-",
            UnaryOp::IsEmpty => "isEmpty",
            UnaryOp::Datetime => "datetime",
            UnaryOp::Decimal => "decimal",
            UnaryOp::Duration => "duration",
            UnaryOp::Ip => "ip",
            UnaryOp::IsIPv4 => "isIpv4",
            UnaryOp::IsIPV6 => "isIpv6",
            UnaryOp::IsLoopback => "isLoopback",
            UnaryOp::IsMulticast => "isMulticast",
            UnaryOp::ToDate => "toDate",
            UnaryOp::ToTime => "toTime",
            UnaryOp::ToMilliseconds => "toMilliseconds",
            UnaryOp::ToSeconds => "toSeconds",
            UnaryOp::ToMinutes => "toMinutes",
            UnaryOp::ToHours => "toHours",
            UnaryOp::ToDays => "toDays",
        }
    }

    /// Parse a unary operator from a function name
    #[expect(dead_code, reason = "used by from_function")]
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
        f.write_str(self.as_str())
    }
}

/// Binary operators in Cedar expressions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BinaryOp {
    // Comparison
    /// Equality (`==`)
    Eq,
    /// Inequality (`!=`)
    NotEq,
    /// Less than (`<`)
    Less,
    /// Less than or equal (`<=`)
    LessEq,
    /// Greater than (`>`)
    Greater,
    /// Greater than or equal (`>=`)
    GreaterEq,
    // Logical
    /// Logical AND (`&&`)
    And,
    /// Logical OR (`||`)
    Or,
    // Arithmetic
    /// Addition (`+`)
    Add,
    /// Subtraction (`-`)
    Sub,
    /// Multiplication (`*`)
    Mul,
    // Set/hierarchy
    /// Hierarchy membership (`in`)
    In,
    /// Set contains element (`contains`)
    Contains,
    /// Set contains all elements (`containsAll`)
    ContainsAll,
    /// Set contains any element (`containsAny`)
    ContainsAny,
    // Tags
    /// Get tag value (`getTag`)
    GetTag,
    /// Check tag existence (`hasTag`)
    HasTag,
    // Ip operations
    /// Test for inclusion in IP address range
    IsInRange,
    // Datetime
    /// Compute a datetime offset by duration
    Offset,
    /// Compute difference between two datetimes
    DurationSince,
}

impl BinaryOp {
    /// Get the Cedar syntax representation of this operator
    pub const fn as_str(self) -> &'static str {
        match self {
            BinaryOp::Eq => "==",
            BinaryOp::NotEq => "!=",
            BinaryOp::Less => "<",
            BinaryOp::LessEq => "<=",
            BinaryOp::Greater => ">",
            BinaryOp::GreaterEq => ">=",
            BinaryOp::And => "&&",
            BinaryOp::Or => "||",
            BinaryOp::Add => "+",
            BinaryOp::Sub => "-",
            BinaryOp::Mul => "*",
            BinaryOp::In => "in",
            BinaryOp::Contains => "contains",
            BinaryOp::ContainsAll => "containsAll",
            BinaryOp::ContainsAny => "containsAny",
            BinaryOp::GetTag => "getTag",
            BinaryOp::HasTag => "hasTag",
            BinaryOp::IsInRange => "isInRange",
            BinaryOp::Offset => "offset",
            BinaryOp::DurationSince => "durationSince",
        }
    }

    /// Parse a binary operator from a function name
    #[expect(dead_code, reason = "used by from_function")]
    pub(crate) fn from_function_name(name: &str) -> Option<Self> {
        match name {
            "lessThan" => Some(BinaryOp::Less),
            "lessThanOrEqual" => Some(BinaryOp::LessEq),
            "greaterThan" => Some(BinaryOp::Greater),
            "greaterThanOrEqual" => Some(BinaryOp::GreaterEq),
            "isInRange" => Some(BinaryOp::IsInRange),
            "offset" => Some(BinaryOp::Offset),
            "durationSince" => Some(BinaryOp::DurationSince),
            _ => None,
        }
    }
}

impl Display for BinaryOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Literal values
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Literal {
    /// Boolean literal
    Bool(bool),
    /// Integer literal
    Long(i64),
    /// String literal
    String(String),
    /// Entity UID literal
    EntityUID(EntityUID),
}

/// Pattern element for `like` expressions
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PatternElem {
    /// A literal character
    Char(char),
    /// A wildcard (`*`)
    Wildcard,
}

impl From<ast::Pattern> for Vec<PatternElem> {
    fn from(pattern: ast::Pattern) -> Self {
        pattern
            .iter()
            .map(|elem| match elem {
                ast::PatternElem::Char(c) => PatternElem::Char(*c),
                ast::PatternElem::Wildcard => PatternElem::Wildcard,
            })
            .collect()
    }
}

/// PST Expression
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Expr {
    /// Literal value
    Literal(Literal),
    /// Variable (principal, action, resource, context)
    Var(Var),
    /// Template slot
    Slot(SlotId),
    /// Unary operation
    UnaryOp {
        /// The operator
        op: UnaryOp,
        /// The operand
        expr: Arc<Expr>,
    },
    /// Binary operation
    BinaryOp {
        /// The operator
        op: BinaryOp,
        /// Left operand
        left: Arc<Expr>,
        /// Right operand
        right: Arc<Expr>,
    },
    /// Attribute access (e.g., `principal.name`)
    GetAttr {
        /// Expression to get attribute from
        expr: Arc<Expr>,
        /// Attribute name
        attr: SmolStr,
    },
    /// Attribute existence check (e.g., `principal has name`)
    /// Can check nested attributes (e.g., `principal has address.street`)
    HasAttr {
        /// Expression to check for attribute
        expr: Arc<Expr>,
        /// Attribute path (non-empty)
        attrs: nonempty::NonEmpty<SmolStr>,
    },
    /// Pattern matching (e.g., `resource.name like "*.jpg"`)
    Like {
        /// Expression to match
        expr: Arc<Expr>,
        /// Pattern to match against
        pattern: Vec<PatternElem>,
    },
    /// Type test with optional hierarchy check
    /// `expr is Type` or `expr is Type in parent`
    Is {
        /// Expression to test
        expr: Arc<Expr>,
        /// Entity type to test for
        entity_type: EntityType,
        /// Optional hierarchy parent
        in_expr: Option<Arc<Expr>>,
    },
    /// Conditional expression
    IfThenElse {
        /// Condition
        cond: Arc<Expr>,
        /// Then branch
        then_expr: Arc<Expr>,
        /// Else branch
        else_expr: Arc<Expr>,
    },
    /// Set literal
    Set(Vec<Arc<Expr>>),
    /// Record literal
    Record(BTreeMap<String, Arc<Expr>>),
    /// Representation of an unknown for partial evaluation
    Unknown {
        /// Name of the unknown
        name: SmolStr,
    },
    /// An error occurred during construction
    #[expect(
        clippy::pub_underscore_fields,
        reason = "intentionally private to prevent clients from constructing error nodes"
    )]
    Error(ErrorNode),
}

/// A private error node is used when other internal APIs require infaillible methods
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ErrorNode {
    error: ExprConstructionError,
}

/// Error type for PST expression construction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExprConstructionError {
    /// Unknown function name
    UnknownFunction {
        /// The name of the unknown function
        name: String,
    },
    /// Extension function lookup error
    FunctionLookupError(ExtensionFunctionLookupError),
    /// Wrong number of arguments
    WrongArity {
        /// The name of the entity with the wrong number of arguments
        name: String,
        /// The expected number of arguments
        expected: usize,
        /// The actual number of arguments
        got: usize,
    },
}

impl std::fmt::Display for ExprConstructionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExprConstructionError::UnknownFunction { name } => {
                write!(f, "unknown function: {}", name)
            }
            ExprConstructionError::FunctionLookupError(e) => {
                write!(f, "{}", e)
            }
            ExprConstructionError::WrongArity {
                name,
                expected,
                got,
            } => write!(
                f,
                "function {} expects {} argument(s), got {}",
                name, expected, got
            ),
        }
    }
}

impl std::error::Error for ExprConstructionError {}

impl Expr {
    #[expect(dead_code, reason = "PST is under development")]
    fn from_function(
        name: &ast::Name,
        args: &Vec<Arc<Expr>>,
    ) -> Result<Expr, ExprConstructionError> {
        let extension = Extensions::all_available()
            .func(&name)
            .map_err(ExprConstructionError::FunctionLookupError)?;

        let expected = extension.arg_types().len();
        let got = args.len();

        if expected != got {
            return Err(ExprConstructionError::WrongArity {
                name: name.to_string(),
                expected,
                got,
            });
        }
        Ok(match args.len() {
            1 => {
                let op = UnaryOp::from_function_name(&name.to_string()).ok_or_else(|| {
                    ExprConstructionError::UnknownFunction {
                        name: name.to_string(),
                    }
                })?;
                Expr::UnaryOp {
                    op,
                    #[expect(clippy::indexing_slicing, reason = "length = 1 checked in arm")]
                    expr: Arc::clone(&args[0]),
                }
            }
            2 => {
                let op = BinaryOp::from_function_name(&name.to_string()).ok_or_else(|| {
                    ExprConstructionError::UnknownFunction {
                        name: name.to_string(),
                    }
                })?;
                Expr::BinaryOp {
                    op,
                    #[expect(clippy::indexing_slicing, reason = "length checked = 2 in arm")]
                    left: Arc::clone(&args[0]),
                    #[expect(clippy::indexing_slicing, reason = "length checked = 2 in arm")]
                    right: Arc::clone(&args[1]),
                }
            }
            _ => {
                return Err(ExprConstructionError::UnknownFunction {
                    name: name.to_string(),
                })
            }
        })
    }
}

/// Builder to construct a PST [`Expr`] that implements the [`ExprBuilder`] interface. Unlike the
/// expression building functions, this does not perform any validation on the input and is meant
/// to be used internally.
#[derive(Clone, Debug)]
#[expect(dead_code, reason = "PST is under development")]
pub(crate) struct PstBuilder;

impl ExprBuilder for PstBuilder {
    type Expr = Expr;
    type Data = ();

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
        Expr::Literal(match lit.into() {
            ast::Literal::Bool(b) => Literal::Bool(b),
            ast::Literal::Long(i) => Literal::Long(i),
            ast::Literal::String(s) => Literal::String(s.to_string()),
            ast::Literal::EntityUID(e) => Literal::EntityUID(e.as_ref().clone().into()),
        })
    }

    fn var(self, var: ast::Var) -> Expr {
        Expr::Var(match var {
            ast::Var::Principal => Var::Principal,
            ast::Var::Action => Var::Action,
            ast::Var::Resource => Var::Resource,
            ast::Var::Context => Var::Context,
        })
    }

    fn unknown(self, u: ast::Unknown) -> Expr {
        Expr::Unknown { name: u.name }
    }

    fn slot(self, s: ast::SlotId) -> Expr {
        Expr::Slot(s.into())
    }

    fn ite(self, test_expr: Expr, then_expr: Expr, else_expr: Expr) -> Expr {
        Expr::IfThenElse {
            cond: Arc::new(test_expr),
            then_expr: Arc::new(then_expr),
            else_expr: Arc::new(else_expr),
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

    fn is_in(self, e1: Expr, e2: Expr) -> Expr {
        Expr::BinaryOp {
            op: BinaryOp::In,
            left: Arc::new(e1),
            right: Arc::new(e2),
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

    fn call_extension_fn(self, fn_name: ast::Name, args: impl IntoIterator<Item = Expr>) -> Expr {
        let expr = Expr::from_function(&fn_name, &args.into_iter().map(Arc::new).collect());
        match expr {
            Ok(e) => e,
            Err(e) => Expr::Error(ErrorNode { error: e }),
        }
    }

    fn get_attr(self, expr: Expr, attr: SmolStr) -> Expr {
        Expr::GetAttr {
            expr: Arc::new(expr),
            attr,
        }
    }

    fn has_attr(self, expr: Expr, attr: SmolStr) -> Expr {
        Expr::HasAttr {
            expr: Arc::new(expr),
            attrs: nonempty::nonempty![attr],
        }
    }

    fn like(self, expr: Expr, pattern: ast::Pattern) -> Expr {
        Expr::Like {
            expr: Arc::new(expr),
            pattern: pattern.into(),
        }
    }

    fn is_entity_type(self, expr: Expr, entity_type: ast::EntityType) -> Expr {
        Expr::Is {
            expr: Arc::new(expr),
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
        // This Display implementation is mostly for debugging purposes
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
            Expr::Error(e) => write!(f, "<error: {}>", e.error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_function_unknown_function() {
        let name = ast::Name::parse_unqualified_name("unknownFunc").unwrap();
        let args = vec![Arc::new(Expr::Literal(Literal::Long(1)))];

        let result = Expr::from_function(&name, &args);
        assert!(matches!(
            result,
            Err(ExprConstructionError::FunctionLookupError { .. })
        ));
    }

    #[test]
    fn test_from_function_wrong_arity() {
        let name = ast::Name::parse_unqualified_name("decimal").unwrap();
        let args = vec![
            Arc::new(Expr::Literal(Literal::Long(1))),
            Arc::new(Expr::Literal(Literal::Long(2))),
        ];

        let result = Expr::from_function(&name, &args);
        assert!(matches!(
            result,
            Err(ExprConstructionError::WrongArity { .. })
        ));
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

            let result = Expr::from_function(&name, &args);
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
                    assert!(
                        matches!(actual, Expr::UnaryOp { .. }),
                        "Unary function {} should produce UnaryOp",
                        name
                    );
                }
                2 => {
                    assert!(
                        matches!(actual, Expr::BinaryOp { .. }),
                        "Binary function {} should produce BinaryOp",
                        name
                    );
                }
                _ => (),
            }
        }
    }

    #[test]
    fn test_expr_construction_error_display() {
        let err = ExprConstructionError::UnknownFunction {
            name: "foo".to_string(),
        };
        assert!(err.to_string().contains("foo"));

        let err = ExprConstructionError::WrongArity {
            name: "bar".to_string(),
            expected: 2,
            got: 1,
        };
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
        fn cant_display_unsparseable_entity_type() {
            let name = "!__Cedar!";
            let et = EntityType::from_name(Name::simple(name));
            assert_eq!(format!("{}", et), "<invalid entity type>");
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
                    "!((1 == 2))",
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
                    "!((1 <= 2))",
                ),
                (
                    builder().greatereq(builder().val(1i64), builder().val(2i64)),
                    "!((1 < 2))",
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
                    builder().call_extension_fn(
                        Name::simple("decimal").try_into().unwrap(),
                        vec![builder().val("1.23")],
                    ),
                    "decimal(\"1.23\")",
                ),
                (
                    builder().call_extension_fn(
                        Name::simple("notAFunc").try_into().unwrap(),
                        vec![builder().val("12.3")],
                    ),
                    "<error: extension function `notAFunc` does not exist>",
                ),
            ];

            for (expr, expected) in cases {
                assert_eq!(expr.to_string(), expected, "Failed for: {}", expected);
            }
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
                "if !((principal.age <= 18)) then principal.name else \"unknown\""
            );

            // isEmpty
            let is_empty = builder().is_empty(builder().set([]));
            assert_eq!(is_empty.to_string(), "isEmpty([])");
        }
    }
}
