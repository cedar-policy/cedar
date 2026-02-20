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
use crate::ast;
use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::sync::Arc;

/// A unique identifier for a policy statement
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub struct PolicyID(pub SmolStr);

impl From<PolicyID> for ast::PolicyID {
    fn from(id: PolicyID) -> Self {
        ast::PolicyID::from_string(id.0.as_str())
    }
}

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
    /// Policy ID
    pub id: PolicyID,
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

impl std::fmt::Display for Effect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Effect::Permit => write!(f, "permit"),
            Effect::Forbid => write!(f, "forbid"),
        }
    }
}

impl std::fmt::Display for Clause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Clause::When(expr) => write!(f, "when {{ {} }}", expr),
            Clause::Unless(expr) => write!(f, "unless {{ {} }}", expr),
        }
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display in Cedar syntax
        write!(f, "{} (", self.effect)?;
        write!(f, "principal {}, ", self.principal)?;
        write!(f, "action {}, ", self.action)?;
        write!(f, "resource {}", self.resource)?;
        write!(f, ")")?;

        for clause in &self.clauses {
            write!(f, " {}", clause)?;
        }

        write!(f, ";")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pst::expr::{Literal, Var};

    #[test]
    fn test_policy_construction_matrix() {
        // Test all combinations of policy attributes
        let effects = vec![Effect::Permit, Effect::Forbid];

        let clause_variants = vec![
            vec![],
            vec![Clause::When(Arc::new(Expr::Literal(Literal::Bool(true))))],
            vec![Clause::Unless(Arc::new(Expr::Literal(Literal::Bool(
                false,
            ))))],
            vec![
                Clause::When(Arc::new(Expr::Var(Var::Principal))),
                Clause::Unless(Arc::new(Expr::Literal(Literal::Bool(false)))),
            ],
        ];

        let annotation_variants = vec![
            BTreeMap::new(),
            {
                let mut map = BTreeMap::new();
                map.insert("author".to_string(), "alice".to_string());
                map
            },
            {
                let mut map = BTreeMap::new();
                map.insert("author".to_string(), "bob".to_string());
                map.insert("version".to_string(), "1.0".to_string());
                map
            },
        ];

        let mut count = 0;
        for effect in &effects {
            for clauses in &clause_variants {
                for annotations in &annotation_variants {
                    let policy = Policy {
                        id: PolicyID(SmolStr::from(format!("policy_{}", count))),
                        effect: *effect,
                        principal: PrincipalConstraint::Any,
                        action: ActionConstraint::Any,
                        resource: ResourceConstraint::Any,
                        clauses: clauses.clone(),
                        annotations: annotations.clone(),
                    };

                    // Verify construction succeeded
                    assert_eq!(policy.effect, *effect);
                    assert_eq!(policy.clauses.len(), clauses.len());
                    assert_eq!(policy.annotations.len(), annotations.len());

                    count += 1;
                }
            }
        }

        // Verify we tested all combinations: 2 effects × 4 clause variants × 3 annotation variants
        assert_eq!(count, 24);
    }

    #[test]
    fn test_policy_id_conversion() {
        let pst_id = PolicyID(SmolStr::from("test_policy"));
        let ast_id: ast::PolicyID = pst_id.into();
        assert_eq!(ast_id.to_string(), "test_policy");
    }
}
