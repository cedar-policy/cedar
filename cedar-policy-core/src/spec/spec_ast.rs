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

pub type Attr = Seq<char>;


pub enum Value {
    Prim { p: Prim },
    Set { s: FiniteSet<Value> }, // TODO switch to vstd finite set when it lands
    Record { m: Map<Attr, Value> },
    Ext { x: () } // TODO(Pratap): extensions
    // Ext { x: Ext } // TODO(Pratap): extensions
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


//////////////////////////////////////////////////////
// EXPRESSIONS: see cedar-lean/Cedar/Spec/Expr.lean //
//////////////////////////////////////////////////////

pub enum Var {
    Principal,
    Action,
    Resource,
    Context
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

pub struct PrincipalScope {
    pub principal_scope: Scope,
}

pub struct ResourceScope {
    pub resource_scope: Scope,
}

pub enum ActionScope {
    ActionScope { scope: Scope },
    ActionInAny { ls: Seq<EntityUID> },
}

pub type PolicyID = Seq<char>;

pub enum ConditionKind {
    When,
    Unless
}

pub struct Condition {
    pub kind: ConditionKind,
    pub body: Expr
}

pub type Conditions = Seq<Condition>;

pub struct Policy {
    pub id: PolicyID,
    pub effect: Effect,
    pub prinicpal_scope: PrincipalScope,
    pub action_scope: ActionScope,
    pub resource_scope: ResourceScope,
    pub condition: Conditions,
}

impl Policy {
    // TODO(Pratap): implement as part of evaluator
    pub uninterp spec fn toExpr(self) -> Expr;
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
