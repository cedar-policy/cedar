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

use lalrpop_util::ParseError;
use smol_str::SmolStr;

// shortcut because we need CST nodes to potentially be empty,
// for example, if part of it failed the parse, we can
// still recover other parts
type Node<N> = super::node::Node<Option<N>>;

/// The set of policy statements that forms a policy set
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policies(pub Vec<Node<Policy>>);

/// Annotations: application-defined data, as a key-value pair
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    /// key
    pub key: Node<Ident>,
    /// value
    pub value: Option<Node<Str>>,
}

/// Literal strings
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Str {
    /// regular quoted string
    String(SmolStr),
    // this is not generated by the parser at time of comment,
    // but left as future improvement and to clarify the
    // validity of the above `String` form
    /// poorly formed string
    #[allow(unused)]
    Invalid(SmolStr),
}

/// Policy statement, the main building block of the language
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Annotations
    pub annotations: Vec<Node<Annotation>>,
    /// policy effect
    pub effect: Node<Ident>,
    /// Variables
    pub variables: Vec<Node<VariableDef>>,
    /// Conditions
    pub conds: Vec<Node<Cond>>,
}

/// The variable part of one of the main item of a policy
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableDef {
    /// identifier, expected:
    /// principal, action, resource
    pub variable: Node<Ident>,
    /// type of entity using previously considered `var : type` syntax. This is
    /// not used for anything other than error reporting.
    pub unused_type_name: Option<Node<Name>>,
    /// type of entity using current `var is type` syntax
    pub entity_type: Option<Node<Add>>,
    /// hierarchy of entity
    pub ineq: Option<(RelOp, Node<Expr>)>,
}

// #[derive(Debug, Clone, PartialEq, Eq)]
// pub struct ErrorNode {
//     pub err: String
// }

// #[derive(Debug, Clone, PartialEq, Eq)]
// pub enum VariableDef {
//     VariableDef(VariableDefImpl),
//     Error(ErrorNode)
// }

/// Any identifier, including special ones
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(unused)] // definitional, or for later improvements
pub enum Ident {
    // Variables
    /// principal
    Principal,
    /// action
    Action,
    /// resource
    Resource,
    /// context
    Context,

    // Other Identifiers
    /// true
    True,
    /// false
    False,
    /// permit
    Permit,
    /// forbid
    Forbid,
    /// when
    When,
    /// unless
    Unless,
    /// in
    In,
    /// has
    Has,
    /// like
    Like,
    /// is
    Is,
    /// if
    If,
    /// then
    Then,
    /// else
    Else,

    // Regular identifiers
    /// user-supplied, in the proper form
    Ident(SmolStr),
    // This is not generated from the parser a time of comment,
    // but here for future improvement and to clarify
    // the validity of the above `Ident` form
    /// user-supplied, not in the proper form
    Invalid(String),
}

/// Conditions: powerful extensions to a policy
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cond {
    /// initial ident, expected to be "when" or "unless"
    pub cond: Node<Ident>,
    /// related expression. expected to not be `None`, but if it's `None`, that
    /// indicates the body was empty (as in `when {}`), and we can report a good
    /// error message
    pub expr: Option<Node<Expr>>,
}

/// The main computation aspect of a policy, outer
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExprImpl {
    /// expression content
    pub expr: Box<ExprData>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// Expression that has been successfully parsed
    Expr(ExprImpl),
    /// To create a tolerant-ast, we keep a node to represented nodes that failed to parse
    #[cfg(feature = "tolerant-ast")]
    ErrorExpr
}

/// The main computation aspect of a policy, inner
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExprData {
    /// || Op
    Or(Node<Or>),
    /// if-then-else
    If(Node<Expr>, Node<Expr>, Node<Expr>),
}
/// Logical Or
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Or {
    /// a singleton is a wrapper for a higher-priority node
    pub initial: Node<And>,
    /// additional elements represent a chained `||` computation
    pub extended: Vec<Node<And>>,
}
/// Logical And
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct And {
    /// a singleton is a wrapper for a higher-priority node
    pub initial: Node<Relation>,
    /// additional elements represent a chained `&&` computation
    pub extended: Vec<Node<Relation>>,
}
/// Comparison relations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Relation {
    /// Regular relations
    Common {
        /// a singleton is a wrapper for a higher-priority node
        initial: Node<Add>,
        /// additional elements represent chained `>`, `<`, etc. computation
        extended: Vec<(RelOp, Node<Add>)>,
    },
    /// Built-in 'has' operation
    Has {
        /// element that may have a field
        target: Node<Add>,
        /// a field the element may have
        field: Node<Add>,
    },
    /// Built-in 'like' operation
    Like {
        /// element to test
        target: Node<Add>,
        /// pattern to match on
        pattern: Node<Add>,
    },
    /// Built-in '.. is .. (in ..)?' operation
    IsIn {
        /// element that may be an entity type and `in` an entity
        target: Node<Add>,
        /// entity type to check for
        entity_type: Node<Add>,
        /// entity that the target may be `in`
        in_entity: Option<Node<Add>>,
    },
}

/// The operation involved in a comparision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelOp {
    /// <
    Less,
    /// <=
    LessEq,
    /// >=
    GreaterEq,
    /// >
    Greater,
    /// !=
    NotEq,
    /// ==
    Eq,
    /// in
    In,
    /// =
    ///
    /// This is always invalid, but included so we can give a nice error suggesting '==' instead
    InvalidSingleEq,
}

/// Allowed Ops for Add
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddOp {
    /// +
    Plus,
    /// -
    Minus,
}

/// Allowed Ops for Mult
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultOp {
    /// *
    Times,
    /// /
    Divide,
    /// %
    Mod,
}

/// Allowed Ops for Neg
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegOp {
    /// count of `!`'s
    Bang(u8),
    /// too many `!`'s
    OverBang,
    /// count of `-`'s
    Dash(u8),
    /// too many `-`'s
    OverDash,
}

/// Additive arithmetic
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Add {
    /// a singleton is a wrapper for a higher-priority node
    pub initial: Node<Mult>,
    /// additional elements represent a chained `+`, `-`, etc. computation
    pub extended: Vec<(AddOp, Node<Mult>)>,
}
/// Multiplicative arithmetic
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mult {
    /// a singleton is a wrapper for a higher-priority node
    pub initial: Node<Unary>,
    /// additional elements represent a chained `*`, `/`, etc. computation
    pub extended: Vec<(MultOp, Node<Unary>)>,
}
/// Unary negations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unary {
    /// the negation operation, if any
    pub op: Option<NegOp>,
    /// higher-priority node the negation is applied to
    pub item: Node<Member>,
}
/// Members on a primary item, accessed with '.'
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Main element
    pub item: Node<Primary>,
    /// fields, indexes, etc.
    pub access: Vec<Node<MemAccess>>,
}
/// Forms of members and their accessors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemAccess {
    /// field identifier
    Field(Node<Ident>),
    /// function call
    Call(Vec<Node<Expr>>),
    /// index of a member
    Index(Node<Expr>),
}
/// Low-level elements like literals
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Primary {
    /// Literal
    Literal(Node<Literal>),
    /// References to entities
    Ref(Node<Ref>),
    /// Constructed elements with names
    Name(Node<Name>),
    /// Template Slots
    Slot(Node<Slot>),
    /// Parentheses
    Expr(Node<Expr>),
    /// Constructed array
    EList(Vec<Node<Expr>>),
    /// Constructed record
    RInits(Vec<Node<RecInit>>),
}

/// UID and Type of named items
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Name {
    /// path, like: "name0::name1::name"
    pub path: Vec<Node<Ident>>,
    /// Singleton name
    pub name: Node<Ident>,
}
/// Reference to an entity
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ref {
    /// UID
    Uid {
        /// The path/type of an entity
        path: Node<Name>,
        /// EID, quoted name
        eid: Node<Str>,
    },
    /// Lookup references
    Ref {
        /// The path/type of an entity
        path: Node<Name>,
        /// The indicated fields of the entity
        rinits: Vec<Node<RefInit>>,
    },
}
/// Elements in a ref: `field: data`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefInit(pub Node<Ident>, pub Node<Literal>);
/// Elements of records: `field_from_expr: data_from_expr`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecInit(pub Node<Expr>, pub Node<Expr>);

/// Raw values
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Literal {
    /// true
    True,
    /// false
    False,
    /// some integer
    Num(u64),
    /// some String
    Str(Node<Str>),
}

/// Template Slots
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    /// Slot for Principal Constraints
    Principal,
    /// Slot for Resource Constraints
    Resource,
    /// Slot other than one of the valid slots
    Other(SmolStr),
}

impl Slot {
    /// Check if a slot matches a scope variable.
    pub fn matches(&self, var: crate::ast::Var) -> bool {
        matches!(
            (self, var),
            (Slot::Principal, crate::ast::Var::Principal)
                | (Slot::Resource, crate::ast::Var::Resource)
        )
    }
}
