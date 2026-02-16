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

//! Policy types for PST

use super::constraints::{ActionConstraint, PrincipalConstraint, ResourceConstraint};
use super::expr::Expr;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Policy effect
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    /// Permit effect
    Permit,
    /// Forbid effect
    Forbid,
}

/// When or unless clause
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Clause {
    /// A `when` clause
    When(Arc<Expr>),
    /// An `unless` clause
    Unless(Arc<Expr>),
}

/// Cedar policy
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Permit or forbid
    pub effect: Effect,
    /// Principal constraint
    pub principal: PrincipalConstraint,
    /// Action constraint
    pub action: ActionConstraint,
    /// Resource constraint
    pub resource: ResourceConstraint,
    /// When/unless clauses (preserves order)
    pub clauses: Vec<Clause>,
    /// Annotations (empty string for no value)
    pub annotations: BTreeMap<String, String>,
}
