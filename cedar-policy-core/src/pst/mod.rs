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

mod ast_conversions;
mod builders;
mod constraints;
mod est_conversions;
mod expr;
mod policy;

pub use ast_conversions::ConversionError;
pub use constraints::{ActionConstraint, EntityOrSlot, PrincipalConstraint, ResourceConstraint};
pub use expr::{
    BinaryOp, EntityType, EntityUID, Expr, ExprConstructionError, Literal, Name, PatternElem,
    SlotId, UnaryOp, Var,
};
pub use policy::{Clause, Effect, Policy};
