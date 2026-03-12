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

//! Policy types for PST.
//!
//! This module defines the top-level [`Template`], [`StaticPolicy`], [`LinkedPolicy`],
//! and [`Policy`] types, along with [`Effect`], [`Clause`], and [`PolicyID`].

use super::constraints::{ActionConstraint, PrincipalConstraint, ResourceConstraint};
use super::expr::{EntityUID, Expr, SlotId};
use crate::ast;
use crate::pst::err::error_body::ContainsSlotError;
use crate::pst::PstConstructionError;
use smol_str::{SmolStr, ToSmolStr};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

/// A unique identifier for a policy statement
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub struct PolicyID(pub SmolStr);

impl From<PolicyID> for ast::PolicyID {
    fn from(id: PolicyID) -> Self {
        ast::PolicyID::from_string(id.0.as_str())
    }
}

impl From<ast::PolicyID> for PolicyID {
    fn from(id: ast::PolicyID) -> Self {
        Self(id.to_smolstr())
    }
}

impl From<&str> for PolicyID {
    fn from(s: &str) -> Self {
        Self(s.into())
    }
}

/// Policy effect.
///
/// ```cedar
/// permit (...);   // Permit
/// forbid (...);   // Forbid
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    /// `permit` — allow the request
    Permit,
    /// `forbid` — deny the request
    Forbid,
}

/// A `when` or `unless` condition clause attached to a policy.
///
/// ```cedar
/// permit (principal, action, resource)
///   when { resource.public == true }
///   unless { context.is_blocked };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Clause {
    /// `when { <expr> }`
    When(Arc<Expr>),
    /// `unless { <expr> }`
    Unless(Arc<Expr>),
}

/// A Cedar policy template.
///
/// Represents a complete Cedar policy template including its scope constraints,
/// condition clauses, and annotations. If there are no slots used, this is effectively
/// a policy.
///
/// ```cedar
/// @id("policy0")
/// permit (
///   principal == User::"alice",
///   action == Action::"view",
///   resource in Album::"vacation"
/// )
/// when { resource.public == true }
/// unless { context.is_blocked };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// Template ID
    pub id: PolicyID,
    /// Permit or forbid
    pub effect: Effect,
    /// Principal constraint
    pub principal: PrincipalConstraint,
    /// Action constraint
    pub action: ActionConstraint,
    /// Resource constraint
    pub resource: ResourceConstraint,
    /// When/unless clauses, can only be added through methods because they need to be checked
    pub(crate) clauses: Vec<Clause>,
    /// Annotations (empty string for no value)
    pub annotations: BTreeMap<String, SmolStr>,
    _private: (),
}

impl Template {
    /// Create a new policy with the given id, effect and scope.
    /// Constraints need to be added with try_with_clauses (or try_add_clause)
    pub fn new(
        id: impl Into<PolicyID>,
        effect: Effect,
        principal: PrincipalConstraint,
        action: ActionConstraint,
        resource: ResourceConstraint,
    ) -> Self {
        Self {
            id: id.into(),
            effect,
            principal,
            action,
            resource,
            clauses: vec![],
            annotations: BTreeMap::new(),
            _private: (),
        }
    }

    /// Get a reference to the clauses of the policy
    pub fn clauses(&self) -> &Vec<Clause> {
        &self.clauses
    }

    /// Get the clauses of the policy
    pub fn into_clauses(self) -> Vec<Clause> {
        self.clauses
    }

    /// Replace all clauses on this template. Fails if any clause contains a slot.
    pub fn try_with_clauses(
        self,
        clauses: impl IntoIterator<Item = Clause>,
    ) -> Result<Self, PstConstructionError> {
        let clauses: Vec<Clause> = clauses.into_iter().collect();
        // check that none of the clauses contain slots
        for clause in &clauses {
            match clause {
                Clause::When(e) | Clause::Unless(e) => {
                    if e.has_slots() {
                        return Err(ContainsSlotError { slots: e.slots() }.into());
                    }
                }
            }
        }
        Ok(Self { clauses, ..self })
    }

    /// Append a single clause to this template. Fails if the clause contains a slot.
    pub fn try_add_clause(&mut self, clause: Clause) -> Result<(), PstConstructionError> {
        match &clause {
            Clause::When(e) | Clause::Unless(e) => {
                if e.has_slots() {
                    return Err(ContainsSlotError { slots: e.slots() }.into());
                }
            }
        }
        self.clauses.push(clause);
        Ok(())
    }

    /// Set the annotations on this template, replacing any existing annotations.
    pub fn with_annotations(self, annotations: BTreeMap<String, SmolStr>) -> Self {
        Self {
            annotations,
            ..self
        }
    }

    /// Fill in any slots in this policy using the values in `vals`.
    /// Performing the link operation should result in a StaticPolicy.
    /// If there are unfilled slots, this results in an Error.
    pub fn link(
        self,
        vals: &HashMap<SlotId, EntityUID>,
    ) -> Result<StaticPolicy, PstConstructionError> {
        Ok(StaticPolicy::try_new(Template {
            id: self.id,
            effect: self.effect,
            principal: self.principal.link(vals)?,
            action: self.action.link(vals)?,
            resource: self.resource.link(vals)?,
            clauses: self.clauses,
            annotations: self.annotations,
            _private: (),
        })?)
    }

    /// Get the slots used by the template
    pub fn slots(&self) -> HashSet<SlotId> {
        let mut slots = HashSet::new();
        slots.extend(self.principal.slot());
        slots.extend(self.action.slot());
        slots.extend(self.resource.slot());
        slots
    }

    /// Check if the template has any slots
    pub fn is_static(&self) -> bool {
        // Currently only principal or resource could actually have slots
        !(self.principal.has_slot() || self.resource.has_slot() || self.action.has_slot())
    }
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

impl std::fmt::Display for Template {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // This Display implementation is only for debugging purposes. It does not print valid
        // Cedar syntax.
        // Currently, there is no goal to display valid Cedar syntax from the PST directly.
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

/// A static policy, i.e. a policy without slots.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StaticPolicy {
    /// The body of the static policy: a policy template that doesn't have any slots
    pub body: Template,
}

impl StaticPolicy {
    /// Checks if the body has any slots, and return a `StaticPolicy` if none are found,
    /// a `ContainsSlotError` otherwise.
    fn try_new(body: Template) -> Result<Self, ContainsSlotError> {
        // Check that all slots have been filled
        if body.principal.has_slot() || body.resource.has_slot() || body.resource.has_slot() {
            Err(ContainsSlotError {
                slots: body.slots(),
            })
        } else {
            Ok(StaticPolicy { body })
        }
    }

    /// The id of a static policy is the id of its slot-free body
    pub fn id(&self) -> &PolicyID {
        &self.body.id
    }
}

impl TryFrom<Template> for StaticPolicy {
    type Error = ContainsSlotError;
    fn try_from(value: Template) -> Result<Self, Self::Error> {
        StaticPolicy::try_new(value)
    }
}

/// A linked policy, i.e. a template with information to fill the slots and the id of the link.
#[derive(Debug, Clone)]
pub struct LinkedPolicy {
    /// The body of the policy is a template with slots
    pub body: Template,
    /// The values are the values the slots should be replaced with
    pub values: HashMap<SlotId, EntityUID>,
    /// The instance id is the id of the static policy that will be generated by the linking
    pub instance_id: PolicyID,
}

impl LinkedPolicy {
    /// Get the static policy that this linked policy represents
    pub fn link(&self) -> Result<StaticPolicy, PstConstructionError> {
        let mut policy = self.body.clone().link(&self.values)?;
        policy.body.id = self.instance_id.clone();
        Ok(policy)
    }

    /// The id of the linked policy is its instance id.
    pub fn id(&self) -> &PolicyID {
        &self.instance_id
    }
}

/// A Policy can be represented either as a static policy or a linked policy. A linked policy
/// can be transformed into a static one, but information about the template id and which slots
/// are linked would be lost.
#[derive(Debug)]
pub enum Policy {
    /// Static policy, i.e. a policy with no slots
    Static(StaticPolicy),
    /// Linked policy, i.e. a policy with slots and their instantiation
    Linked(LinkedPolicy),
}

impl Policy {
    /// Get a reference to the body of the policy
    pub fn body(&self) -> &Template {
        match self {
            Policy::Static(p) => &p.body,
            Policy::Linked(p) => &p.body,
        }
    }
}

#[cfg(test)]
mod tests {
    use smol_str::ToSmolStr;

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
                map.insert("author".to_string(), "alice".to_smolstr());
                map
            },
            {
                let mut map = BTreeMap::new();
                map.insert("author".to_string(), "bob".to_smolstr());
                map.insert("version".to_string(), "1.0".to_smolstr());
                map
            },
        ];

        let mut count = 0;
        for effect in &effects {
            for clauses in &clause_variants {
                for annotations in &annotation_variants {
                    let policy = Template::new(
                        PolicyID(SmolStr::from(format!("policy_{}", count))),
                        *effect,
                        PrincipalConstraint::Any,
                        ActionConstraint::Any,
                        ResourceConstraint::Any,
                    )
                    .with_annotations(annotations.clone())
                    .try_with_clauses(clauses.clone())
                    .unwrap();

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

    fn make_uid(ty: &str, id: &str) -> EntityUID {
        EntityUID {
            ty: crate::pst::EntityType::from_name(crate::pst::Name::unqualified(ty)),
            eid: SmolStr::from(id),
        }
    }

    #[test]
    fn test_policy_link_replaces_all_slots() {
        use crate::pst::constraints::*;
        use crate::pst::expr::SlotId;

        // Clauses with slots are rejected
        let mut template = Template::new(
            "t1",
            Effect::Permit,
            PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal)),
            ActionConstraint::Eq(make_uid("Action", "view")),
            ResourceConstraint::In(EntityOrSlot::Slot(SlotId::Resource)),
        );
        assert!(matches!(
            template
                .clone()
                .try_add_clause(Clause::When(Arc::new(Expr::Slot(SlotId::Principal)))),
            Err(PstConstructionError::ContainsSlots(..))
        ));

        // Linking replaces slots in constraints; valid (slot-free) clauses are preserved
        template
            .try_add_clause(Clause::When(Arc::new(Expr::Literal(Literal::Bool(true)))))
            .unwrap();

        let mut vals = HashMap::new();
        vals.insert(SlotId::Principal, make_uid("User", "alice"));
        vals.insert(SlotId::Resource, make_uid("Album", "vacation"));

        let linked = template.link(&vals).unwrap();

        assert_eq!(
            linked.body.principal,
            PrincipalConstraint::Eq(EntityOrSlot::Entity(make_uid("User", "alice")))
        );
        assert_eq!(
            linked.body.resource,
            ResourceConstraint::In(EntityOrSlot::Entity(make_uid("Album", "vacation")))
        );
        assert_eq!(
            linked.body.clauses,
            vec![Clause::When(Arc::new(Expr::Literal(Literal::Bool(true))))]
        );
    }

    #[test]
    fn test_policy_link_missing_slot_errors() {
        use crate::pst::constraints::*;
        use crate::pst::expr::SlotId;

        let template = Template::new(
            "t2",
            Effect::Forbid,
            PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal)),
            ActionConstraint::Any,
            ResourceConstraint::Any,
        );

        let result = template.link(&HashMap::new());
        assert!(matches!(
            result,
            Err(PstConstructionError::LinkingFailed(..))
        ));
    }

    #[test]
    fn test_policy_link_no_slots_passthrough() {
        let mut template = Template::new(
            "p1",
            Effect::Permit,
            PrincipalConstraint::Any,
            ActionConstraint::Any,
            ResourceConstraint::Any,
        );
        template
            .try_add_clause(Clause::When(Arc::new(Expr::Literal(Literal::Bool(true)))))
            .unwrap();

        let original = template.clone();
        let static_policy: StaticPolicy = template.try_into().unwrap();
        assert_eq!(static_policy.body, original);
    }
}
