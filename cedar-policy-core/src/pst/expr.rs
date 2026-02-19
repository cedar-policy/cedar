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

/// Binary operators in Cedar expressions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
pub enum Expr {
    /// Literal value
    Literal(Literal),
    /// Variable (principal, action, resource, context)
    Var(Var),
    /// Template slot
    Slot(SlotId),
    /// Logical not
    Not(Arc<Expr>),
    /// Arithmetic negation
    Neg(Arc<Expr>),
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
    /// Function call. Syntactically, this can be either a function-style or
    /// method-style call depending on the extension.
    FuncCall {
        /// Function name
        name: Name,
        /// Arguments
        args: Vec<Arc<Expr>>,
    },
    /// Check if set is empty
    IsEmpty(Arc<Expr>),
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

    fn val(self, lit: impl Into<crate::ast::Literal>) -> Expr {
        Expr::Literal(match lit.into() {
            crate::ast::Literal::Bool(b) => Literal::Bool(b),
            crate::ast::Literal::Long(i) => Literal::Long(i),
            crate::ast::Literal::String(s) => Literal::String(s.to_string()),
            crate::ast::Literal::EntityUID(e) => Literal::EntityUID(e.as_ref().clone().into()),
        })
    }

    fn var(self, var: crate::ast::Var) -> Expr {
        Expr::Var(match var {
            crate::ast::Var::Principal => Var::Principal,
            crate::ast::Var::Action => Var::Action,
            crate::ast::Var::Resource => Var::Resource,
            crate::ast::Var::Context => Var::Context,
        })
    }

    fn unknown(self, u: crate::ast::Unknown) -> Expr {
        // Represent unknown as a function call
        Expr::FuncCall {
            name: Name::simple("unknown"),
            args: vec![Arc::new(Expr::Literal(Literal::String(u.name.to_string())))],
        }
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
        Expr::Not(Arc::new(e))
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
        Expr::Neg(Arc::new(e))
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
        Expr::IsEmpty(Arc::new(expr))
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
    ) -> Result<Expr, crate::ast::ExpressionConstructionError> {
        let mut map = BTreeMap::new();
        for (k, v) in pairs {
            if map.insert(k.to_string(), Arc::new(v)).is_some() {
                return Err(
                    crate::ast::expression_construction_errors::DuplicateKeyError {
                        key: k,
                        context: "in record literal",
                    }
                    .into(),
                );
            }
        }
        Ok(Expr::Record(map))
    }

    fn call_extension_fn(
        self,
        fn_name: crate::ast::Name,
        args: impl IntoIterator<Item = Expr>,
    ) -> Expr {
        Expr::FuncCall {
            name: fn_name.into(),
            args: args.into_iter().map(Arc::new).collect(),
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

    fn like(self, expr: Expr, pattern: crate::ast::Pattern) -> Expr {
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
            Expr::Not(e) => write!(f, "!({})", e),
            Expr::Neg(e) => write!(f, "-({})", e),
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
            Expr::FuncCall { name, args } => {
                write!(
                    f,
                    "{}({})",
                    name,
                    args.iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Expr::IsEmpty(e) => write!(f, "{}.isEmpty()", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_literal() {
        let expr = PstBuilder::new().val(true);
        assert!(matches!(expr, Expr::Literal(Literal::Bool(true))));

        let expr = PstBuilder::new().val(42i64);
        assert!(matches!(expr, Expr::Literal(Literal::Long(42))));
    }

    #[test]
    fn test_builder_var() {
        let expr = PstBuilder::new().var(crate::ast::Var::Principal);
        assert!(matches!(expr, Expr::Var(Var::Principal)));
    }

    #[test]
    fn test_builder_binary_ops() {
        let left = PstBuilder::new().val(1i64);
        let right = PstBuilder::new().val(2i64);

        let expr = PstBuilder::new().add(left.clone(), right.clone());
        assert!(matches!(
            expr,
            Expr::BinaryOp {
                op: BinaryOp::Add,
                ..
            }
        ));

        let expr = PstBuilder::new().and(left.clone(), right.clone());
        assert!(matches!(
            expr,
            Expr::BinaryOp {
                op: BinaryOp::And,
                ..
            }
        ));

        let expr = PstBuilder::new().is_eq(left, right);
        assert!(matches!(
            expr,
            Expr::BinaryOp {
                op: BinaryOp::Eq,
                ..
            }
        ));
    }

    #[test]
    fn test_builder_unary_ops() {
        let inner = PstBuilder::new().val(true);
        let expr = PstBuilder::new().not(inner);
        assert!(matches!(expr, Expr::Not(_)));

        let inner = PstBuilder::new().val(42i64);
        let expr = PstBuilder::new().neg(inner);
        assert!(matches!(expr, Expr::Neg(_)));
    }

    #[test]
    fn test_builder_ite() {
        let cond = PstBuilder::new().val(true);
        let then_expr = PstBuilder::new().val(1i64);
        let else_expr = PstBuilder::new().val(2i64);

        let expr = PstBuilder::new().ite(cond, then_expr, else_expr);
        assert!(matches!(expr, Expr::IfThenElse { .. }));
    }

    #[test]
    fn test_builder_set() {
        let exprs = vec![
            PstBuilder::new().val(1i64),
            PstBuilder::new().val(2i64),
            PstBuilder::new().val(3i64),
        ];

        let expr = PstBuilder::new().set(exprs);
        if let Expr::Set(elements) = expr {
            assert_eq!(elements.len(), 3);
        } else {
            panic!("Expected Set");
        }
    }

    #[test]
    fn test_builder_record() {
        let pairs = vec![
            ("a".into(), PstBuilder::new().val(1i64)),
            ("b".into(), PstBuilder::new().val(2i64)),
        ];

        let expr = PstBuilder::new().record(pairs).unwrap();
        if let Expr::Record(map) = expr {
            assert_eq!(map.len(), 2);
            assert!(map.contains_key("a"));
            assert!(map.contains_key("b"));
        } else {
            panic!("Expected Record");
        }
    }

    #[test]
    fn test_builder_get_attr() {
        let base = PstBuilder::new().var(crate::ast::Var::Principal);
        let expr = PstBuilder::new().get_attr(base, "name".into());

        if let Expr::GetAttr { attr, .. } = expr {
            assert_eq!(attr, "name");
        } else {
            panic!("Expected GetAttr");
        }
    }

    #[test]
    fn test_builder_has_attr() {
        let base = PstBuilder::new().var(crate::ast::Var::Principal);
        let expr = PstBuilder::new().has_attr(base, "name".into());

        if let Expr::HasAttr { attrs, .. } = expr {
            assert_eq!(attrs.len(), 1);
            assert_eq!(attrs.head, "name");
        } else {
            panic!("Expected HasAttr");
        }
    }

    #[test]
    fn test_builder_is_entity_type() {
        let base = PstBuilder::new().var(ast::Var::Principal);
        let entity_type = EntityType::from_name(ast::Name::parse_unqualified_name("User").unwrap());
        let expr = PstBuilder::new().is_entity_type(base, entity_type.clone().try_into().unwrap());

        if let Expr::Is {
            entity_type: et,
            in_expr,
            ..
        } = expr
        {
            assert_eq!(et, entity_type);
            assert!(in_expr.is_none());
        } else {
            panic!("Expected Is");
        }
    }

    #[test]
    fn test_builder_func_call() {
        let args = vec![PstBuilder::new().val(1i64), PstBuilder::new().val(2i64)];
        let fn_name = crate::ast::Name::parse_unqualified_name("decimal").unwrap();
        let expr = PstBuilder::new().call_extension_fn(fn_name, args);

        if let Expr::FuncCall { name, args } = expr {
            assert_eq!(name, Name::simple("decimal"));
            assert_eq!(args.len(), 2);
        } else {
            panic!("Expected FuncCall");
        }
    }

    #[test]
    fn test_builder_display() {
        let expr = PstBuilder::new().val(42i64);
        let s = expr.to_string();
        assert!(s.contains("42"));
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
                // Variables
                (builder().var(ast::Var::Principal), "principal"),
                (builder().var(ast::Var::Action), "action"),
                (builder().var(ast::Var::Resource), "resource"),
                (builder().var(ast::Var::Context), "context"),
                // Slots
                (builder().slot(ast::SlotId::principal()), "?principal"),
                (builder().slot(ast::SlotId::resource()), "?resource"),
                // Unary ops
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
                // Function calls
                (
                    builder().call_extension_fn(Name::simple("foo").try_into().unwrap(), vec![]),
                    "foo()",
                ),
                (
                    builder().call_extension_fn(
                        Name::simple("decimal").try_into().unwrap(),
                        vec![builder().val("1.23")],
                    ),
                    "decimal(\"1.23\")",
                ),
                (
                    builder().call_extension_fn(
                        Name::simple("foo").try_into().unwrap(),
                        vec![builder().val(1i64), builder().val(2i64)],
                    ),
                    "foo(1, 2)",
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
            assert_eq!(is_empty.to_string(), "[].isEmpty()");
        }
    }
}
