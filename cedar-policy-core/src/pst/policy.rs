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
use crate::pst::err::error_body::{ContainsSlotError, LinkingError};
use crate::pst::PstConstructionError;
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Display;
use std::sync::Arc;

/// A unique identifier for a policy statement
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub struct PolicyID(pub SmolStr);

impl From<PolicyID> for ast::PolicyID {
    fn from(id: PolicyID) -> Self {
        ast::PolicyID::from_smolstr(id.0)
    }
}

impl From<ast::PolicyID> for PolicyID {
    fn from(id: ast::PolicyID) -> Self {
        Self(id.into_smolstr())
    }
}

impl From<&str> for PolicyID {
    fn from(s: &str) -> Self {
        Self(s.into())
    }
}

impl Display for PolicyID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
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

impl std::fmt::Display for Effect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Effect::Permit => write!(f, "permit"),
            Effect::Forbid => write!(f, "forbid"),
        }
    }
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

impl std::fmt::Display for Clause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Clause::When(expr) => write!(f, "when {{ {} }}", expr),
            Clause::Unless(expr) => write!(f, "unless {{ {} }}", expr),
        }
    }
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
        Ok(StaticPolicy::try_from(Template {
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
    /// The id of a static policy is the id of its slot-free body
    pub fn id(&self) -> &PolicyID {
        &self.body.id
    }
}

impl TryFrom<Template> for StaticPolicy {
    type Error = ContainsSlotError;
    fn try_from(body: Template) -> Result<Self, Self::Error> {
        // This is the only way one should be able to create a StaticPolicy outside of the crate.
        // Check that all slots have been filled
        if body.principal.has_slot() || body.resource.has_slot() || body.action.has_slot() {
            Err(ContainsSlotError {
                slots: body.slots(),
            })
        } else {
            Ok(StaticPolicy { body })
        }
    }
}

/// A linked policy, i.e. a template with information to fill the slots and the id of the link.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LinkedPolicy {
    /// The body of the policy is a template with slots
    pub body: Arc<Template>,
    /// The values are the values the slots should be replaced with
    pub values: HashMap<SlotId, EntityUID>,
    /// The instance id is the id of the static policy that will be generated by the linking
    pub instance_id: PolicyID,
}

impl LinkedPolicy {
    /// Create a new `LinkedPolicy` from a template, slot values, and an instance id.
    /// Returns an error if any slot in the template is not provided a value.
    pub fn new(
        template: Arc<Template>,
        values: HashMap<SlotId, EntityUID>,
        instance_id: PolicyID,
    ) -> Result<Self, LinkingError> {
        for slot in template.slots() {
            if !values.contains_key(&slot) {
                return Err(LinkingError::MissedSlot { slot });
            }
        }
        Ok(Self {
            body: template,
            values,
            instance_id,
        })
    }

    /// Get the static policy statement that this linked policy represents.
    /// Loses the link between the template and the instantiation (the template is cloned
    /// and then the slots are replaced by the values in `vals` and the id is changed
    /// to `instance_id`)
    pub fn into_static_policy(&self) -> Result<StaticPolicy, PstConstructionError> {
        let mut policy = self.body.as_ref().clone().link(&self.values)?;
        policy.body.id = self.instance_id.clone();
        Ok(policy)
    }

    /// The id of the linked policy is its instance id.
    pub fn id(&self) -> &PolicyID {
        &self.instance_id
    }
}

impl From<StaticPolicy> for Policy {
    fn from(p: StaticPolicy) -> Self {
        Policy::Static(p)
    }
}

impl From<LinkedPolicy> for Policy {
    fn from(p: LinkedPolicy) -> Self {
        Policy::Linked(p)
    }
}

/// A Policy can be represented either as a static policy or a linked policy. A linked policy
/// can be transformed into a static one, but information about the template id and which slots
/// are linked would be lost.
#[derive(Debug, Clone)]
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

    /// Clone this `Policy` with a new ID
    pub fn new_id(&self, id: PolicyID) -> Self {
        match self {
            Policy::Static(sp) => {
                let mut body = sp.body.clone();
                body.id = id;
                Policy::Static(StaticPolicy { body })
            }
            Policy::Linked(lp) => Policy::Linked(LinkedPolicy {
                body: lp.body.clone(),
                values: lp.values.clone(),
                instance_id: id,
            }),
        }
    }
}

impl std::fmt::Display for StaticPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.body)
    }
}

impl std::fmt::Display for LinkedPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.body)
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.body())
    }
}

#[cfg(test)]
mod tests {
    use smol_str::ToSmolStr;

    use super::*;
    use crate::pst::expr::Literal;

    #[test]
    fn test_with_annotations() {
        let mut annotations = BTreeMap::new();
        annotations.insert("author".to_string(), "alice".to_smolstr());
        annotations.insert("version".to_string(), "1.0".to_smolstr());
        let template = Template::new(
            "p",
            Effect::Permit,
            PrincipalConstraint::Any,
            ActionConstraint::Any,
            ResourceConstraint::Any,
        )
        .with_annotations(annotations.clone());
        assert_eq!(template.annotations, annotations);
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
    fn test_policy_link_or_new_linked_policy_missing_slot_errors() {
        use crate::pst::constraints::*;
        use crate::pst::expr::SlotId;

        let template = Template::new(
            "t2",
            Effect::Forbid,
            PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal)),
            ActionConstraint::Any,
            ResourceConstraint::Any,
        );

        let result = template.clone().link(&HashMap::new());
        assert!(matches!(
            result,
            Err(PstConstructionError::LinkingFailed(..))
        ));
        let new_policy = LinkedPolicy::new(Arc::new(template), HashMap::new(), "test0".into());
        assert!(matches!(
            new_policy,
            Err(LinkingError::MissedSlot {
                slot: SlotId::Principal
            })
        ));
    }

    #[test]
    fn test_static_policy() {
        let mut template = Template::new(
            "my_policy",
            Effect::Permit,
            PrincipalConstraint::Any,
            ActionConstraint::Any,
            ResourceConstraint::Any,
        );
        template
            .try_add_clause(Clause::When(Arc::new(Expr::Literal(Literal::Bool(true)))))
            .unwrap();
        let original = template.clone();
        let static_policy = StaticPolicy::try_from(template).unwrap();
        assert_eq!(static_policy.id().0.as_str(), "my_policy");
        assert_eq!(static_policy.body, original);
        let _ = static_policy.to_string();
    }

    #[test]
    fn test_effect_and_clause_display() {
        assert_eq!(Effect::Permit.to_string(), "permit");
        assert_eq!(Effect::Forbid.to_string(), "forbid");
        assert_eq!(
            Clause::When(Arc::new(Expr::Literal(Literal::Bool(true)))).to_string(),
            "when { true }"
        );
        assert_eq!(
            Clause::Unless(Arc::new(Expr::Literal(Literal::Bool(false)))).to_string(),
            "unless { false }"
        );
    }

    #[test]
    fn test_template_methods() {
        use crate::pst::constraints::*;
        use crate::pst::expr::SlotId;

        let clause = Clause::When(Arc::new(Expr::Literal(Literal::Bool(true))));
        let mut template = Template::new(
            "p",
            Effect::Permit,
            PrincipalConstraint::Any,
            ActionConstraint::Any,
            ResourceConstraint::Any,
        );
        template.try_add_clause(clause.clone()).unwrap();

        assert_eq!(template.clauses(), &vec![clause.clone()]);
        assert!(template.is_static());
        assert!(template.slots().is_empty());
        let s = template.to_string();
        assert!(s.contains("permit") && s.contains("when"));
        assert_eq!(template.into_clauses(), vec![clause]);

        let slotted = Template::new(
            "t",
            Effect::Permit,
            PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal)),
            ActionConstraint::Any,
            ResourceConstraint::Any,
        );
        assert!(!slotted.is_static());
        assert!(slotted.slots().contains(&SlotId::Principal));
    }

    #[test]
    fn test_slot_error_paths() {
        use crate::pst::constraints::*;
        use crate::pst::expr::SlotId;

        let template = Template::new(
            "t",
            Effect::Permit,
            PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal)),
            ActionConstraint::Any,
            ResourceConstraint::Any,
        );
        assert!(matches!(
            template
                .clone()
                .try_with_clauses(vec![Clause::When(Arc::new(Expr::Slot(SlotId::Principal)))]),
            Err(PstConstructionError::ContainsSlots(..))
        ));
        assert!(StaticPolicy::try_from(template).is_err());
    }

    #[test]
    fn test_linked_policy() {
        use crate::pst::constraints::*;
        use crate::pst::expr::SlotId;

        let mut vals = HashMap::new();
        vals.insert(SlotId::Principal, make_uid("User", "alice"));
        let linked = LinkedPolicy {
            body: Arc::new(Template::new(
                "tmpl",
                Effect::Permit,
                PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal)),
                ActionConstraint::Any,
                ResourceConstraint::Any,
            )),
            values: vals,
            instance_id: PolicyID("link1".into()),
        };
        assert_eq!(linked.id().0.as_str(), "link1");
        let _ = linked.to_string();
        let static_policy = linked.into_static_policy().unwrap();
        assert_eq!(static_policy.id().0.as_str(), "link1");

        // Policy enum: body() and Display for both variants
        let static_p = Policy::Static(
            StaticPolicy::try_from(Template::new(
                "p",
                Effect::Permit,
                PrincipalConstraint::Any,
                ActionConstraint::Any,
                ResourceConstraint::Any,
            ))
            .unwrap(),
        );
        let _ = static_p.body();
        let _ = static_p.to_string();

        let linked_p = Policy::Linked(LinkedPolicy {
            body: Arc::new(Template::new(
                "tmpl2",
                Effect::Permit,
                PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal)),
                ActionConstraint::Any,
                ResourceConstraint::Any,
            )),
            values: {
                let mut m = HashMap::new();
                m.insert(SlotId::Principal, make_uid("User", "bob"));
                m
            },
            instance_id: PolicyID("link2".into()),
        });
        let _ = linked_p.body();
        let _ = linked_p.to_string();
    }

    #[test]
    fn test_new_id_static() {
        let policy = Policy::Static(
            StaticPolicy::try_from(Template::new(
                "old",
                Effect::Permit,
                PrincipalConstraint::Any,
                ActionConstraint::Any,
                ResourceConstraint::Any,
            ))
            .unwrap(),
        );
        let renamed = policy.new_id("new".into());
        match &renamed {
            Policy::Static(sp) => assert_eq!(sp.id().0.as_str(), "new"),
            Policy::Linked(_) => panic!("expected Static"),
        }
    }

    #[test]
    fn test_new_id_linked() {
        use crate::pst::constraints::*;
        use crate::pst::expr::SlotId;

        let template = Arc::new(Template::new(
            "tmpl",
            Effect::Permit,
            PrincipalConstraint::Eq(EntityOrSlot::Slot(SlotId::Principal)),
            ActionConstraint::Any,
            ResourceConstraint::Any,
        ));
        let policy = Policy::Linked(
            LinkedPolicy::new(
                template.clone(),
                HashMap::from([(SlotId::Principal, make_uid("User", "alice"))]),
                "old_link".into(),
            )
            .unwrap(),
        );
        let renamed = policy.new_id("new_link".into());
        match &renamed {
            Policy::Linked(lp) => {
                assert_eq!(lp.id().0.as_str(), "new_link");
                // Template body should be unchanged
                assert_eq!(lp.body.id.0.as_str(), "tmpl");
            }
            Policy::Static(_) => panic!("expected Linked"),
        }
    }
}
