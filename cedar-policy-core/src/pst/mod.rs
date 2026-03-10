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

//! Public Syntax Tree (PST) - Ergonomic representation for programmatic policy construction
//!
//! PST is a separate owned data structure designed for building and manipulating Cedar policies
//! programmatically. It provides a cleaner API than EST (which is JSON-driven) and AST (which is
//! evaluation-optimized).
//!
//! # Design Principles
//! - All types are PST-owned (no `ast::` or `est::` leakage)
//! - Simplified from EST (single `Expr` enum, unified operators)
//! - Converts to/from AST and EST at boundaries
//! - Uses `Arc<Expr>` for cheap cloning during manipulation

pub(crate) mod ast_conversions;
mod constraints;
mod err;
pub(crate) mod est_conversions;
mod expr;
mod policy;

pub use constraints::{ActionConstraint, EntityOrSlot, PrincipalConstraint, ResourceConstraint};
pub use err::PstConstructionError;
pub use err::error_body;
pub use expr::{
    BinaryOp, EntityType, EntityUID, Expr, Literal, Name, PatternElem, SlotId, UnaryOp, Var,
};
pub use policy::{Clause, Effect, Policy, PolicyID};

use crate::ast;

impl Policy {
    /// Convert this PST policy to an AST policy for evaluation.
    /// Fails if the policy contains slots (`SlotId::Principal` or `SlotId::Resource`).
    pub fn try_into_ast_policy(self) -> Result<ast::Policy, PstConstructionError> {
        self.try_into()
    }

    /// Convert this PST policy to an AST template.
    /// Works for both static policies and templates (policies with slots).
    pub fn try_into_ast_template(self) -> Result<ast::Template, PstConstructionError> {
        self.try_into()
    }
}

impl Expr {
    /// Convert this PST expression to an AST expression for evaluation
    pub fn try_into_ast_expr(self) -> Result<ast::Expr, PstConstructionError> {
        // Similar to try_into_ast for Policy, this is the public boundary
        self.try_into()
    }

    /// Create a PST expression from an AST expression
    pub fn from_ast_expr(expr: ast::Expr) -> Self {
        expr.into()
    }
}
