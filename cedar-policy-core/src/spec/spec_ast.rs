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

//! This module contains spec data structures modeling the Cedar AST

#![allow(missing_debug_implementations)] // vstd types Seq/Set/Map don't impl Debug
#![allow(missing_docs)] // just for now

pub use crate::verus_utils::*;
pub use vstd::{map::*, prelude::*, seq::*, set::*};

verus! {

//////////////////////////////////////////////////
// VALUES: see cedar-lean/Cedar/Spec/Value.lean //
//////////////////////////////////////////////////

pub enum Error {
  EntityDoesNotExist,
  AttrDoesNotExist,
  TagDoesNotExist,
  TypeError,
  ArithBoundsError,
  ExtensionError,
}

pub type SpecResult<T> = Result<T, Error>;

pub type Id = Seq<char>;

pub struct Name {
    pub id: Id,
    pub path: Seq<Id>,
}

pub type EntityType = Name;

pub struct EntityUID {
    pub ty: EntityType,
    pub eid: Seq<char>,
}

pub enum Prim {
    Bool { b: bool },
    Int { i: i64 },
    String { s: Seq<char> },
    EntityUID { uid: EntityUID },
}

impl Prim {
    #[verifier::inline]
    pub open spec fn pbool(b: bool) -> Prim {
        Prim::Bool { b }
    }

    #[verifier::inline]
    pub open spec fn int(i: i64) -> Prim {
        Prim::Int { i }
    }

    #[verifier::inline]
    pub open spec fn entity_uid(uid: EntityUID) -> Prim {
        Prim::EntityUID { uid }
    }
}


pub type Attr = Seq<char>;


pub enum Value {
    Prim { p: Prim },
    Set { s: FiniteSet<Value> }, // TODO switch to vstd finite set when it lands
    Record { m: Map<Attr, Value> },
    Ext { x: () } // TODO(Pratap): extensions
    // Ext { x: Ext } // TODO(Pratap): extensions
}

impl Value {
    #[verifier::inline]
    pub open spec fn prim(p: Prim) -> Value {
        Value::Prim { p }
    }

    #[verifier::inline]
    pub open spec fn bool(b: bool) -> Value {
        Value::Prim { p: Prim::Bool { b }}
    }

    #[verifier::inline]
    pub open spec fn int(i: i64) -> Value {
        Value::Prim { p: Prim::Int { i }}
    }

    #[verifier::inline]
    pub open spec fn entity_uid(uid: EntityUID) -> Value {
        Value::Prim { p: Prim::EntityUID { uid } }
    }
}

// Analogous to cedar-spec `vs.mapOrErr Value.asEntityUID .typeError`
pub open spec fn valueset_as_entity_uid(vs: FiniteSet<Value>) -> SpecResult<FiniteSet<EntityUID>> {
    if vs.all(|v:Value| v is Prim && v->p is EntityUID) {
        Ok(vs.map(|v:Value| v->p->uid))
    } else {
        Err(Error::TypeError)
    }
}


///////////////////////////////////////////////////////
// ENTITIES: see cedar-lean/Cedar/Spec/Entities.lean //
///////////////////////////////////////////////////////

pub type Tag = Seq<char>;

pub struct EntityData {
    pub attrs: Map<Attr, Value>,
    pub ancestors: Set<EntityUID>,
    pub tags: Map<Tag, Value>
}

pub type Entities = Map<EntityUID, EntityData>;

pub open spec fn entities_ancestors_or_empty(es: Entities, uid: EntityUID) -> Set<EntityUID> {
    match es.get(uid) {
        Some(d) => d.ancestors,
        None => Set::empty()
    }
}

pub open spec fn entities_attrs(es: Entities, uid: EntityUID) -> SpecResult<Map<Attr, Value>> {
    match es.get(uid) {
        Some(d) => Ok(d.attrs),
        None => Err(Error::EntityDoesNotExist)
    }
}

pub open spec fn entities_attrs_or_empty(es: Entities, uid: EntityUID) -> Map<Attr, Value> {
    match es.get(uid) {
        Some(d) => d.attrs,
        None => Map::empty()
    }
}

pub open spec fn entities_tags(es: Entities, uid: EntityUID) -> SpecResult<Map<Tag, Value>> {
    match es.get(uid) {
        Some(d) => Ok(d.tags),
        None => Err(Error::EntityDoesNotExist)
    }
}

pub open spec fn entities_tags_or_empty(es: Entities, uid: EntityUID) -> Map<Tag, Value> {
    match es.get(uid) {
        Some(d) => d.tags,
        None => Map::empty()
    }
}

//////////////////////////////////////////////////////
// EXPRESSIONS: see cedar-lean/Cedar/Spec/Expr.lean //
//////////////////////////////////////////////////////

pub enum Var {
    Principal,
    Action,
    Resource,
    Context
}

impl Var {
    #[verifier::inline]
    pub open spec fn eq_entity_uid(self, uid: EntityUID) -> Expr {
        Expr::BinaryApp {
            bop: BinaryOp::Eq,
            a: Box::new(Expr::var(self)),
            b: Box::new(Expr::lit(Prim::entity_uid(uid)))
        }
    }

    #[verifier::inline]
    pub open spec fn in_entity_uid(self, uid: EntityUID) -> Expr {
        Expr::BinaryApp {
            bop: BinaryOp::Mem,
            a: Box::new(Expr::var(self)),
            b: Box::new(Expr::lit(Prim::entity_uid(uid)))
        }
    }

    #[verifier::inline]
    pub open spec fn is_entity_type(self, ety: EntityType) -> Expr {
        Expr::UnaryApp {
            uop: UnaryOp::Is { ety },
            expr: Box::new(Expr::var(self)),
        }
    }
}

pub enum UnaryOp {
    Not,
    Neg,
    IsEmpty,
    // Like { p: Pattern }, // TODO(pratap): handle patterns later
    Is { ety: EntityType },
}

pub enum BinaryOp {
  Eq,
  Mem, // represents Cedar's in operator
  HasTag,
  GetTag,
  Less,
  LessEq,
  Add,
  Sub,
  Mul,
  Contains,
  ContainsAll,
  ContainsAny,
}

pub enum Expr {
    Lit { p: Prim },
    Var { v: Var },
    Ite {
        cond: Box<Expr>,
        then_expr: Box<Expr>,
        else_expr: Box<Expr>,
    },
    And { a: Box<Expr>, b: Box<Expr> },
    Or { a: Box<Expr>, b: Box<Expr> },
    UnaryApp {
        uop: UnaryOp,
        expr: Box<Expr>,
    },
    BinaryApp {
        bop: BinaryOp,
        a: Box<Expr>,
        b: Box<Expr>,
    },
    GetAttr {
        expr: Box<Expr>,
        attr: Attr,
    },
    HasAttr {
        expr: Box<Expr>,
        attr: Attr,
    },
    Set { ls: Seq<Expr> },
    Record { map: Map<Attr, Expr> },
    // Call { // TODO(Pratap): handle extension functions
    //     xfn: ExtFun,
    //     args: Seq<Expr>,
    // },
}

impl Expr {
    #[verifier::inline]
    pub open spec fn lit(p: Prim) -> Expr {
        Expr::Lit { p }
    }

    #[verifier::inline]
    pub open spec fn var(v: Var) -> Expr {
        Expr::Var { v }
    }

    #[verifier::inline]
    pub open spec fn and(a: Expr, b: Expr) -> Expr {
        Expr::And { a: Box::new(a), b: Box::new(b) }
    }

    #[verifier::inline]
    pub open spec fn set(ls: Seq<Expr>) -> Expr {
        Expr::Set { ls }
    }

    #[verifier::inline]
    pub open spec fn unary_app(uop: UnaryOp, expr: Expr) -> Expr {
        Expr::UnaryApp { uop, expr: Box::new(expr) }
    }

    #[verifier::inline]
    pub open spec fn binary_app(bop: BinaryOp, a: Expr, b: Expr) -> Expr {
        Expr::BinaryApp { bop, a: Box::new(a), b: Box::new(b) }
    }
}

/////////////////////////////////////////////////////
// POLICIES: see cedar-lean/Cedar/Spec/Polciy.lean //
/////////////////////////////////////////////////////

pub enum Effect {
    Permit,
    Forbid
}

pub enum Scope {
    Any,
    Eq { entity: EntityUID },
    Mem { entity: EntityUID },
    Is { ety: EntityType },
    IsMem { ety: EntityType, entity: EntityUID },
}

impl Scope {
    #[verifier::opaque]
    pub open spec fn to_expr(self, v: Var) -> Expr {
        match self {
            Scope::Any => Expr::lit(Prim::pbool(true)),
            Scope::Eq { entity: uid } => v.eq_entity_uid(uid),
            Scope::Mem { entity: uid } => v.in_entity_uid(uid),
            Scope::Is { ety: ety } => v.is_entity_type(ety),
            Scope::IsMem { ety: ety, entity: uid } => Expr::and(v.is_entity_type(ety), v.in_entity_uid(uid)),
        }
    }
}

pub struct PrincipalScope {
    pub principal_scope: Scope,
}

impl PrincipalScope {
    #[verifier::inline]
    pub open spec fn to_expr(self) -> Expr {
        self.principal_scope.to_expr(Var::Principal)
    }
}

pub struct ResourceScope {
    pub resource_scope: Scope,
}

impl ResourceScope {
    #[verifier::inline]
    pub open spec fn to_expr(self) -> Expr {
        self.resource_scope.to_expr(Var::Resource)
    }
}

pub enum ActionScope {
    ActionScope { scope: Scope },
    ActionInAny { ls: Seq<EntityUID> },
}

impl ActionScope {
    #[verifier::inline]
    pub open spec fn to_expr(self) -> Expr {
        match self {
            ActionScope::ActionScope { scope: s } => s.to_expr(Var::Action),
            ActionScope::ActionInAny { ls: es } => {
                let exprs = es.map_values(|e:EntityUID| Expr::lit(Prim::entity_uid(e)));
                Expr::BinaryApp {
                    bop: BinaryOp::Mem,
                    a: Box::new(Expr::var(Var::Action)),
                    b: Box::new(Expr::set(exprs))
                }
            }
        }
    }
}

pub type PolicyID = Seq<char>;

// pub enum ConditionKind {
//     When,
//     Unless
// }

// pub struct Condition {
//     pub kind: ConditionKind,
//     pub body: Expr
// }

// impl Condition {
//     #[verifier::inline]
//     pub open spec fn to_expr(self) -> Expr {
//         match self.kind {
//             ConditionKind::When => self.body,
//             ConditionKind::Unless => Expr::UnaryApp {
//                 uop: UnaryOp::Not,
//                 expr: Box::new(self.body)
//             }
//         }
//     }
// }

// pub type Conditions = Seq<Condition>;

// // Can't write `impl Conditions` since `Conditions` is a type synonym
// #[verifier::inline]
// pub open spec fn conditions_to_expr(conditions: Conditions) -> Expr {
//     conditions.fold_right(
//         |c:Condition, expr:Expr| Expr::and(c.to_expr(), expr),
//         Expr::lit(Prim::pbool(true)))
// }

pub struct Policy {
    pub id: PolicyID,
    pub effect: Effect,
    pub principal_scope: PrincipalScope,
    pub action_scope: ActionScope,
    pub resource_scope: ResourceScope,
    // Different from Lean spec, because in Rust the conversion from `when/unless`
    // clauses to a single expression happens in the parser
    pub condition: Expr,
}

impl Policy {
    #[verifier::opaque]
    pub open spec fn to_expr(self) -> Expr {
        Expr::and(
            self.principal_scope.to_expr(),
            Expr::and(
                self.action_scope.to_expr(),
                Expr::and(
                    self.resource_scope.to_expr(),
                    self.condition)))
    }
}

pub type Policies = Seq<Policy>;

//////////////////////////////////////////////////////
// REQUESTS: see cedar-lean/Cedar/Spec/Request.lean //
//////////////////////////////////////////////////////

pub struct Request {
    pub principal: EntityUID,
    pub action: EntityUID,
    pub resource: EntityUID,
    pub context: Map<Attr, Value>,
}

////////////////////////////////////////////////////////
// RESPONSES: see cedar-lean/Cedar/Spec/Response.lean //
////////////////////////////////////////////////////////

pub enum Decision {
    Allow,
    Deny
}

pub struct Response {
    pub decision: Decision,
    pub determining_policies: Set<PolicyID>,
    pub erroring_policies: Set<PolicyID>
}

} // verus!
