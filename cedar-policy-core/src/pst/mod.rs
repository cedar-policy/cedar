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

// NOTE: Unlike most modules in this crate, all types in the PST are intentionally
// public. This is by design — the PST is meant for programmatic policy construction,
// so users need direct access to all constituent types.

//! The PST is a syntax tree representation of Cedar policies designed for programmatic
//! manipulation.
//!
//! # Constructing a policy
//!
//! Build a PST [`Template`] directly from its constituent types. This example constructs:
//! ```cedar
//! permit (
//!   principal == User::"alice",
//!   action == Action::"view",
//!   resource in Album::"vacation"
//! ) when { resource.public == true };
//! ```
//!
//! ```
//! # use cedar_policy_core::pst::*;
//! # use smol_str::SmolStr;
//! # use std::sync::Arc;
//! # use std::collections::BTreeMap;
//! let template = Template::new(
//!     PolicyID(SmolStr::from("policy0")),
//!     Effect::Permit,
//!     PrincipalConstraint::Eq(EntityOrSlot::Entity(EntityUID {
//!         ty: EntityType::from_name(Name::unqualified("User")),
//!         eid: SmolStr::from("alice"),
//!     })),
//!     ActionConstraint::Eq(EntityUID {
//!         ty: EntityType::from_name(Name::unqualified("Action")),
//!         eid: SmolStr::from("view"),
//!     }),
//!     ResourceConstraint::In(EntityOrSlot::Entity(EntityUID {
//!         ty: EntityType::from_name(Name::unqualified("Album")),
//!         eid: SmolStr::from("vacation"),
//!     })),
//! )
//! .try_with_clauses(vec![Clause::When(Arc::new(Expr::BinaryOp {
//!     op: BinaryOp::Eq,
//!     left: Arc::new(Expr::GetAttr {
//!         expr: Arc::new(Expr::Var(Var::Resource)),
//!         attr: SmolStr::from("public"),
//!     }),
//!     right: Arc::new(Expr::Literal(Literal::Bool(true))),
//! }))])
//! .unwrap();
//! // If there are no slots, it can be converted into a static policy
//! let policy : Policy = Policy::Static(template.try_into().unwrap());
//! assert_eq!(policy.body().effect, Effect::Permit);
//! ```
//!
//! # Matching / inspecting a policy
//!
//! The PST types that are likely to be extended in the future are marked `#[non_exhaustive]`
//! ([`Expr`], [`Literal`], [`BinaryOp`], [`UnaryOp`], [`SlotId`]), so match arms must include
//! a wildcard. Types that are *not* `#[non_exhaustive]` (constraints, [`Effect`], [`Clause`],
//! [`Var`], [`PatternElem`]) can be exhaustively matched.
//!
//! ```
//! # use cedar_policy_core::pst::*;
//! # use smol_str::SmolStr;
//! # use std::sync::Arc;
//! # use std::collections::BTreeMap;
//! # let template = Template::new(
//! #     PolicyID(SmolStr::from("policy0")),
//! #     Effect::Permit,
//! #     PrincipalConstraint::Eq(EntityOrSlot::Entity(EntityUID {
//! #         ty: EntityType::from_name(Name::unqualified("User")),
//! #         eid: SmolStr::from("alice"),
//! #     })),
//! #     ActionConstraint::Eq(EntityUID {
//! #         ty: EntityType::from_name(Name::unqualified("Action")),
//! #         eid: SmolStr::from("view"),
//! #     }),
//! #     ResourceConstraint::Any,
//! # )
//! # .try_with_clauses(vec![Clause::When(Arc::new(Expr::BinaryOp {
//! #     op: BinaryOp::Eq,
//! #     left: Arc::new(Expr::GetAttr {
//! #         expr: Arc::new(Expr::Var(Var::Resource)),
//! #         attr: SmolStr::from("public"),
//! #     }),
//! #     right: Arc::new(Expr::Literal(Literal::Bool(true))),
//! # }))])
//! # .unwrap();
//! // Effect and constraints are exhaustively matchable:
//! let is_permit = match template.effect {
//!     Effect::Permit => true,
//!     Effect::Forbid => false,
//! };
//!
//! // PrincipalConstraint is also exhaustively matchable:
//! let principal_entity = match &template.principal {
//!     PrincipalConstraint::Eq(EntityOrSlot::Entity(uid)) => Some(uid),
//!     PrincipalConstraint::Any
//!     | PrincipalConstraint::Eq(EntityOrSlot::Slot(_))
//!     | PrincipalConstraint::In(_)
//!     | PrincipalConstraint::Is(_)
//!     | PrincipalConstraint::IsIn(_, _) => None,
//! };
//!
//! // Expr is #[non_exhaustive] — a wildcard arm is required:
//! for clause in template.clauses() {
//!     let expr = match clause {
//!         Clause::When(e) => e,
//!         Clause::Unless(e) => e,
//!     };
//!     match expr.as_ref() {
//!         Expr::BinaryOp { op, left, right } => {
//!             // BinaryOp is also #[non_exhaustive]:
//!             match op {
//!                 BinaryOp::Eq => println!("found equality check"),
//!                 _ => {}
//!             }
//!         }
//!         Expr::Literal(lit) => {
//!             // Literal is #[non_exhaustive]:
//!             match lit {
//!                 Literal::Bool(b) => println!("bool: {b}"),
//!                 _ => {}
//!             }
//!         }
//!         _ => {} // required for Expr
//!     }
//! }
//! ```

pub(crate) mod ast_conversions;
mod constraints;
mod err;
pub(crate) mod est_conversions;
mod expr;
mod policy;
mod policy_set;

pub use constraints::{ActionConstraint, EntityOrSlot, PrincipalConstraint, ResourceConstraint};
pub use err::error_body;
pub use err::PstConstructionError;
pub use expr::{
    BinaryOp, EntityType, EntityUID, Expr, Literal, Name, PatternElem, SlotId, UnaryOp, Var,
};
pub use policy::{Clause, Effect, LinkedPolicy, Policy, PolicyID, StaticPolicy, Template};
pub use policy_set::{PolicySet, TemplateLink};
