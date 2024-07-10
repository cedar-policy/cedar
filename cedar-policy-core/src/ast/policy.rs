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

use crate::ast::*;
use crate::parser::Loc;
use itertools::Itertools;
use miette::Diagnostic;
use nonempty::{nonempty, NonEmpty};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;

#[cfg(feature = "wasm")]
extern crate tsify;

/// Top level structure for a policy template.
/// Contains both the AST for template, and the list of open slots in the template.
///
/// Note that this "template" may have no slots, in which case this `Template` represents a static policy
#[derive(Clone, Hash, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(from = "TemplateBody")]
#[serde(into = "TemplateBody")]
pub struct Template {
    body: TemplateBody,
    /// INVARIANT (slot cache correctness): This Vec must contain _all_ of the open slots in `body`
    /// This is maintained by the only two public constructors, `new` and `link_inline_policy`
    ///
    /// Note that `slots` may be empty, in which case this `Template` represents a static policy
    slots: Vec<Slot>,
}

impl From<Template> for TemplateBody {
    fn from(val: Template) -> Self {
        val.body
    }
}

impl Template {
    /// Checks the invariant (slot cache correctness)
    #[cfg(test)]
    pub fn check_invariant(&self) {
        for slot in self.body.condition().slots() {
            assert!(self.slots.contains(&slot));
        }
        for slot in self.slots() {
            assert!(self.body.condition().slots().contains(slot));
        }
    }
    // by default, Coverlay does not track coverage for lines after a line
    // containing #[cfg(test)].
    // we use the following sentinel to "turn back on" coverage tracking for
    // remaining lines of this file, until the next #[cfg(test)]
    // GRCOV_BEGIN_COVERAGE

    /// Construct a `Template` from its components
    pub fn new(
        id: PolicyID,
        loc: Option<Loc>,
        annotations: Annotations,
        effect: Effect,
        principal_constraint: PrincipalConstraint,
        action_constraint: ActionConstraint,
        resource_constraint: ResourceConstraint,
        non_scope_constraint: Expr,
    ) -> Self {
        let body = TemplateBody::new(
            id,
            loc,
            annotations,
            effect,
            principal_constraint,
            action_constraint,
            resource_constraint,
            non_scope_constraint,
        );
        // INVARIANT (slot cache correctness)
        // This invariant is maintained in the body of the From impl
        Template::from(body)
    }

    /// Construct a template from an expression/annotations that are already [`std::sync::Arc`] allocated
    pub fn new_shared(
        id: PolicyID,
        loc: Option<Loc>,
        annotations: Arc<Annotations>,
        effect: Effect,
        principal_constraint: PrincipalConstraint,
        action_constraint: ActionConstraint,
        resource_constraint: ResourceConstraint,
        non_scope_constraint: Arc<Expr>,
    ) -> Self {
        let body = TemplateBody::new_shared(
            id,
            loc,
            annotations,
            effect,
            principal_constraint,
            action_constraint,
            resource_constraint,
            non_scope_constraint,
        );
        // INVARIANT (slot cache correctness)
        // This invariant is maintained in the body of the From impl
        Template::from(body)
    }

    /// Get the principal constraint on the body
    pub fn principal_constraint(&self) -> &PrincipalConstraint {
        self.body.principal_constraint()
    }

    /// Get the action constraint on the body
    pub fn action_constraint(&self) -> &ActionConstraint {
        self.body.action_constraint()
    }

    /// Get the resource constraint on the body
    pub fn resource_constraint(&self) -> &ResourceConstraint {
        self.body.resource_constraint()
    }

    /// Get the non-scope constraint on the body
    pub fn non_scope_constraints(&self) -> &Expr {
        self.body.non_scope_constraints()
    }

    /// Get Arc to non-scope constraint on the body
    pub fn non_scope_constraints_arc(&self) -> &Arc<Expr> {
        self.body.non_scope_constraints_arc()
    }

    /// Get the PolicyID of this template
    pub fn id(&self) -> &PolicyID {
        self.body.id()
    }

    /// Clone this Policy with a new ID
    pub fn new_id(&self, id: PolicyID) -> Self {
        Template {
            body: self.body.new_id(id),
            slots: self.slots.clone(),
        }
    }

    /// Get the location of this policy
    pub fn loc(&self) -> Option<&Loc> {
        self.body.loc()
    }

    /// Get the `Effect` (`Permit` or `Deny`) of this template
    pub fn effect(&self) -> Effect {
        self.body.effect()
    }

    /// Get data from an annotation.
    pub fn annotation(&self, key: &AnyId) -> Option<&Annotation> {
        self.body.annotation(key)
    }

    /// Get all annotation data.
    pub fn annotations(&self) -> impl Iterator<Item = (&AnyId, &Annotation)> {
        self.body.annotations()
    }

    /// Get [`Arc`] owning the annotation data.
    pub fn annotations_arc(&self) -> &Arc<Annotations> {
        self.body.annotations_arc()
    }

    /// Get the condition expression of this template.
    ///
    /// This will be a conjunction of the template's scope constraints (on
    /// principal, resource, and action); the template's "when" conditions; and
    /// the negation of each of the template's "unless" conditions.
    pub fn condition(&self) -> Expr {
        self.body.condition()
    }

    /// List of open slots in this template
    pub fn slots(&self) -> impl Iterator<Item = &Slot> {
        self.slots.iter()
    }

    /// Check if this template is a static policy
    ///
    /// Static policies can be linked without any slots,
    /// and all links will be identical.
    pub fn is_static(&self) -> bool {
        self.slots.is_empty()
    }

    /// Ensure that every slot in the template is bound by values,
    /// and that no extra values are bound in values
    /// This upholds invariant (values total map)
    pub fn check_binding(
        template: &Template,
        values: &HashMap<SlotId, EntityUID>,
    ) -> Result<(), LinkingError> {
        // Verify all slots bound
        let unbound = template
            .slots
            .iter()
            .filter(|slot| !values.contains_key(&slot.id))
            .collect::<Vec<_>>();

        let extra = values
            .iter()
            .filter_map(|(slot, _)| {
                if !template
                    .slots
                    .iter()
                    .any(|template_slot| template_slot.id == *slot)
                {
                    Some(slot)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if unbound.is_empty() && extra.is_empty() {
            Ok(())
        } else {
            Err(LinkingError::from_unbound_and_extras(
                unbound.into_iter().map(|slot| slot.id),
                extra.into_iter().copied(),
            ))
        }
    }

    /// Attempt to create a template-linked policy from this template.
    /// This will fail if values for all open slots are not given.
    /// `new_instance_id` is the `PolicyId` for the created template-linked policy.
    pub fn link(
        template: Arc<Template>,
        new_id: PolicyID,
        values: HashMap<SlotId, EntityUID>,
    ) -> Result<Policy, LinkingError> {
        // INVARIANT (policy total map) Relies on check_binding to uphold the invariant
        Template::check_binding(&template, &values)
            .map(|_| Policy::new(template, Some(new_id), values))
    }

    /// Take a static policy and create a template and a template-linked policy for it.
    /// They will share the same ID
    pub fn link_static_policy(p: StaticPolicy) -> (Arc<Template>, Policy) {
        let body: TemplateBody = p.into();
        // INVARIANT (slot cache correctness):
        // StaticPolicy by invariant (inline policy correctness)
        // can have no slots, so it is safe to make `slots` the empty vec
        let t = Arc::new(Self {
            body,
            slots: vec![],
        });
        #[cfg(test)]
        {
            t.check_invariant();
        }
        // by default, Coverlay does not track coverage for lines after a line
        // containing #[cfg(test)].
        // we use the following sentinel to "turn back on" coverage tracking for
        // remaining lines of this file, until the next #[cfg(test)]
        // GRCOV_BEGIN_COVERAGE
        let p = Policy::new(Arc::clone(&t), None, HashMap::new());
        (t, p)
    }
}

impl From<TemplateBody> for Template {
    fn from(body: TemplateBody) -> Self {
        // INVARIANT: (slot cache correctness)
        // Pull all the slots out of the template body's condition.
        let slots = body.condition().slots().collect::<Vec<_>>();
        Self { body, slots }
    }
}

impl std::fmt::Display for Template {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.body)
    }
}

/// Errors linking templates
#[derive(Debug, Clone, PartialEq, Eq, Diagnostic, Error)]
pub enum LinkingError {
    /// An error with the slot arguments provided
    // INVARIANT: `unbound_values` and `extra_values` can't both be empty
    #[error("{}", describe_arity_error(.unbound_values, .extra_values))]
    ArityError {
        /// Error for when some Slots were not provided values
        unbound_values: Vec<SlotId>,
        /// Error for when more values than Slots are provided
        extra_values: Vec<SlotId>,
    },

    /// The attempted linking failed as the template did not exist.
    #[error("failed to find a template with id `{id}`")]
    NoSuchTemplate {
        /// [`PolicyID`] of the template we failed to find
        id: PolicyID,
    },

    /// The new instance conflicts with an existing [`PolicyID`].
    #[error("template-linked policy id `{id}` conflicts with an existing policy id")]
    PolicyIdConflict {
        /// [`PolicyID`] where the conflict exists
        id: PolicyID,
    },
}

impl LinkingError {
    fn from_unbound_and_extras(
        unbound: impl Iterator<Item = SlotId>,
        extra: impl Iterator<Item = SlotId>,
    ) -> Self {
        Self::ArityError {
            unbound_values: unbound.collect(),
            extra_values: extra.collect(),
        }
    }
}

fn describe_arity_error(unbound_values: &[SlotId], extra_values: &[SlotId]) -> String {
    match (unbound_values.len(), extra_values.len()) {
        // PANIC SAFETY 0,0 case is not an error
        #[allow(clippy::unreachable)]
        (0,0) => unreachable!(),
        (_unbound, 0) => format!("the following slots were not provided as arguments: {}", unbound_values.iter().join(",")),
        (0, _extra) => format!("the following slots were provided as arguments, but did not exist in the template: {}", extra_values.iter().join(",")),
        (_unbound, _extra) => format!("the following slots were not provided as arguments: {}. The following slots were provided as arguments, but did not exist in the template: {}", unbound_values.iter().join(","), extra_values.iter().join(","))
    }
}

/// A Policy that contains:
///   a pointer to its template
///   an link ID (unless it's an static policy)
///   the bound values for slots in the template
///
/// Policies are not serializable (due to the pointer), and can be serialized
/// by converting to/from LiteralPolicy
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Policy {
    /// Reference to the template
    template: Arc<Template>,
    /// Id of this link
    /// None in the case that this is an instance of a Static Policy
    link: Option<PolicyID>,
    // INVARIANT (values total map)
    // All of the slots in `template` MUST be bound by `values`
    /// values the slots are bound to.
    /// The constructor `new` is only visible in this module,
    /// so it is the responsibility of callers to maintain
    values: HashMap<SlotId, EntityUID>,
}

impl Policy {
    /// Link a policy to its template
    /// INVARIANT (values total map):
    /// `values` must bind every open slot in `template`
    fn new(template: Arc<Template>, link_id: Option<PolicyID>, values: SlotEnv) -> Self {
        #[cfg(test)]
        {
            Template::check_binding(&template, &values).expect("(values total map) does not hold!");
        }
        // by default, Coverlay does not track coverage for lines after a line
        // containing #[cfg(test)].
        // we use the following sentinel to "turn back on" coverage tracking for
        // remaining lines of this file, until the next #[cfg(test)]
        // GRCOV_BEGIN_COVERAGE
        Self {
            template,
            link: link_id,
            values,
        }
    }

    /// Build a policy with a given effect, given when clause, and unconstrained scope variables
    pub fn from_when_clause(effect: Effect, when: Expr, id: PolicyID, loc: Option<Loc>) -> Self {
        Self::from_when_clause_annos(
            effect,
            Arc::new(when),
            id,
            loc,
            Arc::new(Annotations::default()),
        )
    }

    /// Build a policy with a given effect, given when clause, and unconstrained scope variables
    pub fn from_when_clause_annos(
        effect: Effect,
        when: Arc<Expr>,
        id: PolicyID,
        loc: Option<Loc>,
        annotations: Arc<Annotations>,
    ) -> Self {
        let t = Template::new_shared(
            id,
            loc,
            annotations,
            effect,
            PrincipalConstraint::any(),
            ActionConstraint::any(),
            ResourceConstraint::any(),
            when,
        );
        Self::new(Arc::new(t), None, SlotEnv::new())
    }

    /// Get pointer to the template for this policy
    pub fn template(&self) -> &Template {
        &self.template
    }

    /// Get pointer to the template for this policy, as an `Arc`
    pub(crate) fn template_arc(&self) -> Arc<Template> {
        Arc::clone(&self.template)
    }

    /// Get the effect (forbid or permit) of this policy.
    pub fn effect(&self) -> Effect {
        self.template.effect()
    }

    /// Get data from an annotation.
    pub fn annotation(&self, key: &AnyId) -> Option<&Annotation> {
        self.template.annotation(key)
    }

    /// Get all annotation data.
    pub fn annotations(&self) -> impl Iterator<Item = (&AnyId, &Annotation)> {
        self.template.annotations()
    }

    /// Get [`Arc`] owning annotation data.
    pub fn annotations_arc(&self) -> &Arc<Annotations> {
        self.template.annotations_arc()
    }

    /// Get the principal constraint for this policy.
    ///
    /// By the invariant, this principal constraint will not contain
    /// (unresolved) slots, so you will not get `EntityReference::Slot` anywhere
    /// in it.
    pub fn principal_constraint(&self) -> PrincipalConstraint {
        let constraint = self.template.principal_constraint().clone();
        match self.values.get(&SlotId::principal()) {
            None => constraint,
            Some(principal) => constraint.with_filled_slot(Arc::new(principal.clone())),
        }
    }

    /// Get the action constraint for this policy.
    pub fn action_constraint(&self) -> &ActionConstraint {
        self.template.action_constraint()
    }

    /// Get the resource constraint for this policy.
    ///
    /// By the invariant, this resource constraint will not contain
    /// (unresolved) slots, so you will not get `EntityReference::Slot` anywhere
    /// in it.
    pub fn resource_constraint(&self) -> ResourceConstraint {
        let constraint = self.template.resource_constraint().clone();
        match self.values.get(&SlotId::resource()) {
            None => constraint,
            Some(resource) => constraint.with_filled_slot(Arc::new(resource.clone())),
        }
    }

    /// Get the non-scope constraints for the policy
    pub fn non_scope_constraints(&self) -> &Expr {
        self.template.non_scope_constraints()
    }

    /// Get the [`Arc`] owning non-scope constraints for the policy
    pub fn non_scope_constraints_arc(&self) -> &Arc<Expr> {
        self.template.non_scope_constraints_arc()
    }

    /// Get the expression that represents this policy.
    pub fn condition(&self) -> Expr {
        self.template.condition()
    }

    /// Get the mapping from SlotIds to EntityUIDs for this policy. (This will
    /// be empty for inline policies.)
    pub fn env(&self) -> &SlotEnv {
        &self.values
    }

    /// Get the ID of this policy.
    pub fn id(&self) -> &PolicyID {
        self.link.as_ref().unwrap_or_else(|| self.template.id())
    }

    /// Clone this policy or instance with a new ID
    pub fn new_id(&self, id: PolicyID) -> Self {
        match self.link {
            None => Policy {
                template: Arc::new(self.template.new_id(id)),
                link: None,
                values: self.values.clone(),
            },
            Some(_) => Policy {
                template: self.template.clone(),
                link: Some(id),
                values: self.values.clone(),
            },
        }
    }

    /// Get the location of this policy
    pub fn loc(&self) -> Option<&Loc> {
        self.template.loc()
    }

    /// Returns true if this policy is an inline policy
    pub fn is_static(&self) -> bool {
        self.link.is_none()
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_static() {
            write!(f, "{}", self.template())
        } else {
            write!(
                f,
                "Template Instance of {}, slots: [{}]",
                self.template().id(),
                display_slot_env(self.env())
            )
        }
    }
}

/// Map from Slot Ids to Entity UIDs which fill the slots
pub type SlotEnv = HashMap<SlotId, EntityUID>;

/// Represents either an static policy or a template linked policy
/// This is the serializable version because it simply refers to the Template by its Id;
#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct LiteralPolicy {
    /// ID of the template this policy is an instance of
    template_id: PolicyID,
    /// ID of this link
    /// This is `None` for Static Policies,
    /// and the link's ID is defined as the Static Policy's ID
    link_id: Option<PolicyID>,
    /// Values of the slots
    values: SlotEnv,
}

/// A borrowed version of LiteralPolicy exclusively for serialization
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BorrowedLiteralPolicy<'a> {
    /// ID of the template this policy is an instance of
    template_id: &'a PolicyID,
    /// ID of this link
    /// This is `None` for Static Policies,
    /// and the link's ID is defined as the Static Policy's ID
    link_id: Option<&'a PolicyID>,
    /// Values of the slots
    values: &'a SlotEnv,
}

impl<'a> From<&'a Policy> for BorrowedLiteralPolicy<'a> {
    fn from(p: &'a Policy) -> Self {
        Self {
            template_id: p.template.id(),
            link_id: p.link.as_ref(),
            values: &p.values,
        }
    }
}

// Can we verify the hash property?

impl std::hash::Hash for LiteralPolicy {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.template_id.hash(state);
        // this shouldn't be a performance issue as these vectors should be small
        let mut buf = self.values.iter().collect::<Vec<_>>();
        buf.sort();
        for (id, euid) in buf {
            id.hash(state);
            euid.hash(state);
        }
    }
}

impl std::cmp::PartialEq for LiteralPolicy {
    fn eq(&self, other: &Self) -> bool {
        self.template_id() == other.template_id()
            && self.link_id == other.link_id
            && self.values == other.values
    }
}

// These would be great as property tests
#[cfg(test)]
mod hashing_tests {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    use super::*;

    fn compute_hash(ir: LiteralPolicy) -> u64 {
        let mut s = DefaultHasher::new();
        ir.hash(&mut s);
        s.finish()
    }

    fn build_template_linked_policy() -> LiteralPolicy {
        let mut map = HashMap::new();
        map.insert(SlotId::principal(), EntityUID::with_eid("eid"));
        LiteralPolicy {
            template_id: PolicyID::from_string("template"),
            link_id: Some(PolicyID::from_string("id")),
            values: map,
        }
    }

    #[test]
    fn hash_property_instances() {
        let a = build_template_linked_policy();
        let b = build_template_linked_policy();
        assert_eq!(a, b);
        assert_eq!(compute_hash(a), compute_hash(b));
    }
}
// by default, Coverlay does not track coverage for lines after a line
// containing #[cfg(test)].
// we use the following sentinel to "turn back on" coverage tracking for
// remaining lines of this file, until the next #[cfg(test)]
// GRCOV_BEGIN_COVERAGE

/// Errors that can happen during policy reification
#[derive(Debug, Diagnostic, Error)]
pub enum ReificationError {
    /// The [`PolicyID`] linked to did not exist
    #[error("the id linked to does not exist")]
    NoSuchTemplate(PolicyID),
    /// Error linking the policy
    #[error(transparent)]
    #[diagnostic(transparent)]
    Linking(#[from] LinkingError),
}

impl LiteralPolicy {
    /// Attempt to reify this template linked policy.
    /// Ensures the linked template actually exists, replaces the id with a reference to the underlying template.
    /// Fails if the template does not exist.
    /// Consumes the policy.
    pub fn reify(
        self,
        templates: &HashMap<PolicyID, Arc<Template>>,
    ) -> Result<Policy, ReificationError> {
        let template = templates
            .get(&self.template_id)
            .ok_or_else(|| ReificationError::NoSuchTemplate(self.template_id().clone()))?;
        // INVARIANT (values total map)
        Template::check_binding(template, &self.values).map_err(ReificationError::Linking)?;
        Ok(Policy::new(template.clone(), self.link_id, self.values))
    }

    /// Lookup the euid bound by a SlotId
    pub fn get(&self, id: &SlotId) -> Option<&EntityUID> {
        self.values.get(id)
    }

    /// Get the `PolicyId` of this instance
    /// If this is an inline policy, returns the ID of the inline policy
    pub fn id(&self) -> &PolicyID {
        self.link_id.as_ref().unwrap_or(&self.template_id)
    }

    /// Return the `PolicyId` of the template or inline policy that defines this policy
    pub fn template_id(&self) -> &PolicyID {
        &self.template_id
    }

    /// Is this a static policy
    pub fn is_static(&self) -> bool {
        self.link_id.is_none()
    }
}

fn display_slot_env(env: &SlotEnv) -> String {
    env.iter()
        .map(|(slot, value)| format!("{slot} -> {value}"))
        .join(",")
}

impl std::fmt::Display for LiteralPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_static() {
            write!(f, "Static policy w/ ID {}", self.template_id())
        } else {
            write!(
                f,
                "Template linked policy of {}, slots: [{}]",
                self.template_id(),
                display_slot_env(&self.values),
            )
        }
    }
}

impl From<Policy> for LiteralPolicy {
    fn from(p: Policy) -> Self {
        Self {
            template_id: p.template.id().clone(),
            link_id: p.link,
            values: p.values,
        }
    }
}

/// Static Policies are policy that do not come from templates.
/// They have the same structure as a template definition, but cannot contain slots
// INVARIANT: (Static Policy Correctness): A Static Policy TemplateBody must have zero slots
#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq, Debug)]
pub struct StaticPolicy(TemplateBody);

impl StaticPolicy {
    /// Get the `Id` of this policy.
    pub fn id(&self) -> &PolicyID {
        self.0.id()
    }

    /// Clone this policy with a new `Id`.
    pub fn new_id(&self, id: PolicyID) -> Self {
        StaticPolicy(self.0.new_id(id))
    }

    /// Get the location of this policy
    pub fn loc(&self) -> Option<&Loc> {
        self.0.loc()
    }

    /// Get the `Effect` of this policy.
    pub fn effect(&self) -> Effect {
        self.0.effect()
    }

    /// Get data from an annotation.
    pub fn annotation(&self, key: &AnyId) -> Option<&Annotation> {
        self.0.annotation(key)
    }

    /// Get all annotation data.
    pub fn annotations(&self) -> impl Iterator<Item = (&AnyId, &Annotation)> {
        self.0.annotations()
    }

    /// Get the `principal` scope constraint of this policy.
    pub fn principal_constraint(&self) -> &PrincipalConstraint {
        self.0.principal_constraint()
    }

    /// Get the `principal` scope constraint as an expression.
    /// This will be a boolean-valued expression: either `true` (if the policy
    /// just has `principal,`), or an equality or hierarchy constraint
    pub fn principal_constraint_expr(&self) -> Expr {
        self.0.principal_constraint_expr()
    }

    /// Get the `action` scope constraint of this policy.
    pub fn action_constraint(&self) -> &ActionConstraint {
        self.0.action_constraint()
    }

    /// Get the `action` scope constraint of this policy as an expression.
    /// This will be a boolean-valued expression: either `true` (if the policy
    /// just has `action,`), or an equality or hierarchy constraint
    pub fn action_constraint_expr(&self) -> Expr {
        self.0.action_constraint_expr()
    }

    /// Get the `resource` scope constraint of this policy.
    pub fn resource_constraint(&self) -> &ResourceConstraint {
        self.0.resource_constraint()
    }

    /// Get the `resource` scope constraint of this policy as an expression.
    /// This will be a boolean-valued expression: either `true` (if the policy
    /// just has `resource,`), or an equality or hierarchy constraint
    pub fn resource_constraint_expr(&self) -> Expr {
        self.0.resource_constraint_expr()
    }

    /// Get the non-scope constraints of this policy.
    ///
    /// This will be a conjunction of the policy's `when` conditions and the
    /// negation of each of the policy's `unless` conditions.
    pub fn non_scope_constraints(&self) -> &Expr {
        self.0.non_scope_constraints()
    }

    /// Get the condition expression of this policy.
    ///
    /// This will be a conjunction of the policy's scope constraints (on
    /// principal, resource, and action); the policy's "when" conditions; and
    /// the negation of each of the policy's "unless" conditions.
    pub fn condition(&self) -> Expr {
        self.0.condition()
    }

    /// Construct a `StaticPolicy` from its components
    pub fn new(
        id: PolicyID,
        loc: Option<Loc>,
        annotations: Annotations,
        effect: Effect,
        principal_constraint: PrincipalConstraint,
        action_constraint: ActionConstraint,
        resource_constraint: ResourceConstraint,
        non_scope_constraints: Expr,
    ) -> Result<Self, UnexpectedSlotError> {
        let body = TemplateBody::new(
            id,
            loc,
            annotations,
            effect,
            principal_constraint,
            action_constraint,
            resource_constraint,
            non_scope_constraints,
        );
        let first_slot = body.condition().slots().next();
        // INVARIANT (inline policy correctness), checks that no slots exists
        match first_slot {
            Some(slot) => Err(UnexpectedSlotError::FoundSlot(slot))?,
            None => Ok(Self(body)),
        }
    }
}

impl TryFrom<Template> for StaticPolicy {
    type Error = UnexpectedSlotError;

    fn try_from(value: Template) -> Result<Self, Self::Error> {
        // INVARIANT (Static policy correctness): Must ensure StaticPolicy contains no slots
        let o = value.slots().next().cloned();
        match o {
            Some(slot_id) => Err(Self::Error::FoundSlot(slot_id)),
            None => Ok(Self(value.body)),
        }
    }
}

impl From<StaticPolicy> for Policy {
    fn from(inline: StaticPolicy) -> Policy {
        let (_, policy) = Template::link_static_policy(inline);
        policy
    }
}

impl From<StaticPolicy> for Arc<Template> {
    fn from(p: StaticPolicy) -> Self {
        let (t, _) = Template::link_static_policy(p);
        t
    }
}

/// Policy datatype. This is used for both templates (in which case it contains
/// slots) and static policies (in which case it contains zero slots).
#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq, Debug)]
pub struct TemplateBody {
    /// ID of this policy
    id: PolicyID,
    /// Source location spanning the entire policy
    loc: Option<Loc>,
    /// Annotations available for external applications, as key-value store.
    /// Note that the keys are `AnyId`, so Cedar reserved words like `if` and `has`
    /// are explicitly allowed as annotations.
    annotations: Arc<Annotations>,
    /// `Effect` of this policy
    effect: Effect,
    /// Scope constraint for principal. This will be a boolean-valued expression:
    /// either `true` (if the policy just has `principal,`), or an equality or
    /// hierarchy constraint
    principal_constraint: PrincipalConstraint,
    /// Scope constraint for action. This will be a boolean-valued expression:
    /// either `true` (if the policy just has `action,`), or an equality or
    /// hierarchy constraint
    action_constraint: ActionConstraint,
    /// Scope constraint for resource. This will be a boolean-valued expression:
    /// either `true` (if the policy just has `resource,`), or an equality or
    /// hierarchy constraint
    resource_constraint: ResourceConstraint,
    /// Conjunction of all of the non-scope constraints in the policy.
    ///
    /// This will be a conjunction of the policy's `when` conditions and the
    /// negation of each of the policy's `unless` conditions.
    non_scope_constraints: Arc<Expr>,
}

impl TemplateBody {
    /// Get the `Id` of this policy.
    pub fn id(&self) -> &PolicyID {
        &self.id
    }

    /// Get the location of this policy
    pub fn loc(&self) -> Option<&Loc> {
        self.loc.as_ref()
    }

    /// Clone this policy with a new `Id`.
    pub fn new_id(&self, id: PolicyID) -> Self {
        let mut new = self.clone();
        new.id = id;
        new
    }

    /// Get the `Effect` of this policy.
    pub fn effect(&self) -> Effect {
        self.effect
    }

    /// Get data from an annotation.
    pub fn annotation(&self, key: &AnyId) -> Option<&Annotation> {
        self.annotations.get(key)
    }

    /// Get shared ref to annotations
    pub fn annotations_arc(&self) -> &Arc<Annotations> {
        &self.annotations
    }

    /// Get all annotation data.
    pub fn annotations(&self) -> impl Iterator<Item = (&AnyId, &Annotation)> {
        self.annotations.iter()
    }

    /// Get the `principal` scope constraint of this policy.
    pub fn principal_constraint(&self) -> &PrincipalConstraint {
        &self.principal_constraint
    }

    /// Get the `principal` scope constraint as an expression.
    /// This will be a boolean-valued expression: either `true` (if the policy
    /// just has `principal,`), or an equality or hierarchy constraint
    pub fn principal_constraint_expr(&self) -> Expr {
        self.principal_constraint.as_expr()
    }

    /// Get the `action` scope constraint of this policy.
    pub fn action_constraint(&self) -> &ActionConstraint {
        &self.action_constraint
    }

    /// Get the `action` scope constraint of this policy as an expression.
    /// This will be a boolean-valued expression: either `true` (if the policy
    /// just has `action,`), or an equality or hierarchy constraint
    pub fn action_constraint_expr(&self) -> Expr {
        self.action_constraint.as_expr()
    }

    /// Get the `resource` scope constraint of this policy.
    pub fn resource_constraint(&self) -> &ResourceConstraint {
        &self.resource_constraint
    }

    /// Get the `resource` scope constraint of this policy as an expression.
    /// This will be a boolean-valued expression: either `true` (if the policy
    /// just has `resource,`), or an equality or hierarchy constraint
    pub fn resource_constraint_expr(&self) -> Expr {
        self.resource_constraint.as_expr()
    }

    /// Get the non-scope constraints of this policy.
    ///
    /// This will be a conjunction of the policy's `when` conditions and the
    /// negation of each of the policy's `unless` conditions.
    pub fn non_scope_constraints(&self) -> &Expr {
        &self.non_scope_constraints
    }

    /// Get the Arc owning the non scope constraints
    pub fn non_scope_constraints_arc(&self) -> &Arc<Expr> {
        &self.non_scope_constraints
    }

    /// Get the condition expression of this policy.
    ///
    /// This will be a conjunction of the policy's scope constraints (on
    /// principal, resource, and action); the policy's "when" conditions; and
    /// the negation of each of the policy's "unless" conditions.
    pub fn condition(&self) -> Expr {
        Expr::and(
            Expr::and(
                Expr::and(
                    self.principal_constraint_expr(),
                    self.action_constraint_expr(),
                )
                .with_maybe_source_loc(self.loc.clone()),
                self.resource_constraint_expr(),
            )
            .with_maybe_source_loc(self.loc.clone()),
            self.non_scope_constraints.as_ref().clone(),
        )
        .with_maybe_source_loc(self.loc.clone())
    }

    /// Construct a `Policy` from components that are already [`std::sync::Arc`] allocated
    pub fn new_shared(
        id: PolicyID,
        loc: Option<Loc>,
        annotations: Arc<Annotations>,
        effect: Effect,
        principal_constraint: PrincipalConstraint,
        action_constraint: ActionConstraint,
        resource_constraint: ResourceConstraint,
        non_scope_constraints: Arc<Expr>,
    ) -> Self {
        Self {
            id,
            loc,
            annotations,
            effect,
            principal_constraint,
            action_constraint,
            resource_constraint,
            non_scope_constraints,
        }
    }

    /// Construct a `Policy` from its components
    pub fn new(
        id: PolicyID,
        loc: Option<Loc>,
        annotations: Annotations,
        effect: Effect,
        principal_constraint: PrincipalConstraint,
        action_constraint: ActionConstraint,
        resource_constraint: ResourceConstraint,
        non_scope_constraints: Expr,
    ) -> Self {
        Self {
            id,
            loc,
            annotations: Arc::new(annotations),
            effect,
            principal_constraint,
            action_constraint,
            resource_constraint,
            non_scope_constraints: Arc::new(non_scope_constraints),
        }
    }
}

impl From<StaticPolicy> for TemplateBody {
    fn from(p: StaticPolicy) -> Self {
        p.0
    }
}

impl std::fmt::Display for TemplateBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (k, v) in self.annotations.iter() {
            writeln!(f, "@{}(\"{}\")", k, v.val.escape_debug())?
        }
        write!(
            f,
            "{}(\n  {},\n  {},\n  {}\n) when {{\n  {}\n}};",
            self.effect(),
            self.principal_constraint(),
            self.action_constraint(),
            self.resource_constraint(),
            self.non_scope_constraints()
        )
    }
}

/// Struct which holds the annotations for a policy
#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub struct Annotations(BTreeMap<AnyId, Annotation>);

impl Annotations {
    /// Create a new empty `Annotations` (with no annotations)
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Get an annotation by key
    pub fn get(&self, key: &AnyId) -> Option<&Annotation> {
        self.0.get(key)
    }

    /// Iterate over all annotations
    pub fn iter(&self) -> impl Iterator<Item = (&AnyId, &Annotation)> {
        self.0.iter()
    }
}

/// Wraps the [`BTreeMap`]` into an opaque type so we can change it later if need be
#[derive(Debug)]
pub struct IntoIter(std::collections::btree_map::IntoIter<AnyId, Annotation>);

impl Iterator for IntoIter {
    type Item = (AnyId, Annotation);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl IntoIterator for Annotations {
    type Item = (AnyId, Annotation);

    type IntoIter = IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter(self.0.into_iter())
    }
}

impl Default for Annotations {
    fn default() -> Self {
        Self::new()
    }
}

impl FromIterator<(AnyId, Annotation)> for Annotations {
    fn from_iter<T: IntoIterator<Item = (AnyId, Annotation)>>(iter: T) -> Self {
        Self(BTreeMap::from_iter(iter))
    }
}

impl From<BTreeMap<AnyId, Annotation>> for Annotations {
    fn from(value: BTreeMap<AnyId, Annotation>) -> Self {
        Self(value)
    }
}

/// Struct which holds the value of a particular annotation
#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq, Debug, PartialOrd, Ord)]
pub struct Annotation {
    /// Annotation value
    pub val: SmolStr,
    /// Source location. Note this is the location of _the entire key-value
    /// pair_ for the annotation, not just `val` above
    pub loc: Option<Loc>,
}

impl AsRef<str> for Annotation {
    fn as_ref(&self) -> &str {
        &self.val
    }
}

/// Template constraint on principal scope variables
#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub struct PrincipalConstraint {
    pub(crate) constraint: PrincipalOrResourceConstraint,
}

impl PrincipalConstraint {
    /// Construct a principal constraint
    pub fn new(constraint: PrincipalOrResourceConstraint) -> Self {
        PrincipalConstraint { constraint }
    }

    /// Get constraint as ref
    pub fn as_inner(&self) -> &PrincipalOrResourceConstraint {
        &self.constraint
    }

    /// Get constraint by value
    pub fn into_inner(self) -> PrincipalOrResourceConstraint {
        self.constraint
    }

    /// Get the constraint as raw AST
    pub fn as_expr(&self) -> Expr {
        self.constraint.as_expr(PrincipalOrResource::Principal)
    }

    /// Unconstrained.
    pub fn any() -> Self {
        PrincipalConstraint {
            constraint: PrincipalOrResourceConstraint::any(),
        }
    }

    /// Constrained to equal a specific euid.
    pub fn is_eq(euid: Arc<EntityUID>) -> Self {
        PrincipalConstraint {
            constraint: PrincipalOrResourceConstraint::is_eq(euid),
        }
    }

    /// Constrained to be equal to a slot
    pub fn is_eq_slot() -> Self {
        Self {
            constraint: PrincipalOrResourceConstraint::is_eq_slot(),
        }
    }

    /// Hierarchical constraint.
    pub fn is_in(euid: Arc<EntityUID>) -> Self {
        PrincipalConstraint {
            constraint: PrincipalOrResourceConstraint::is_in(euid),
        }
    }

    /// Hierarchical constraint to Slot
    pub fn is_in_slot() -> Self {
        Self {
            constraint: PrincipalOrResourceConstraint::is_in_slot(),
        }
    }

    /// Type constraint additionally constrained to be in a slot.
    pub fn is_entity_type_in_slot(entity_type: Arc<EntityType>) -> Self {
        Self {
            constraint: PrincipalOrResourceConstraint::is_entity_type_in_slot(entity_type),
        }
    }

    /// Type constraint, with a hierarchical constraint.
    pub fn is_entity_type_in(entity_type: Arc<EntityType>, in_entity: Arc<EntityUID>) -> Self {
        Self {
            constraint: PrincipalOrResourceConstraint::is_entity_type_in(entity_type, in_entity),
        }
    }

    /// Type constraint, with no hierarchical constraint or slot.
    pub fn is_entity_type(entity_type: Arc<EntityType>) -> Self {
        Self {
            constraint: PrincipalOrResourceConstraint::is_entity_type(entity_type),
        }
    }

    /// Fill in the Slot, if any, with the given EUID
    pub fn with_filled_slot(self, euid: Arc<EntityUID>) -> Self {
        match self.constraint {
            PrincipalOrResourceConstraint::Eq(EntityReference::Slot) => Self {
                constraint: PrincipalOrResourceConstraint::Eq(EntityReference::EUID(euid)),
            },
            PrincipalOrResourceConstraint::In(EntityReference::Slot) => Self {
                constraint: PrincipalOrResourceConstraint::In(EntityReference::EUID(euid)),
            },
            _ => self,
        }
    }
}

impl std::fmt::Display for PrincipalConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.constraint.display(PrincipalOrResource::Principal)
        )
    }
}

/// Template constraint on resource scope variables
#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub struct ResourceConstraint {
    pub(crate) constraint: PrincipalOrResourceConstraint,
}

impl ResourceConstraint {
    /// Construct from constraint
    pub fn new(constraint: PrincipalOrResourceConstraint) -> Self {
        ResourceConstraint { constraint }
    }

    /// Get constraint as ref
    pub fn as_inner(&self) -> &PrincipalOrResourceConstraint {
        &self.constraint
    }

    /// Get constraint by value
    pub fn into_inner(self) -> PrincipalOrResourceConstraint {
        self.constraint
    }

    /// Convert into an Expression. It will be a boolean valued expression.
    pub fn as_expr(&self) -> Expr {
        self.constraint.as_expr(PrincipalOrResource::Resource)
    }

    /// Unconstrained.
    pub fn any() -> Self {
        ResourceConstraint {
            constraint: PrincipalOrResourceConstraint::any(),
        }
    }

    /// Constrained to equal a specific euid.
    pub fn is_eq(euid: Arc<EntityUID>) -> Self {
        ResourceConstraint {
            constraint: PrincipalOrResourceConstraint::is_eq(euid),
        }
    }

    /// Constrained to equal a slot.
    pub fn is_eq_slot() -> Self {
        Self {
            constraint: PrincipalOrResourceConstraint::is_eq_slot(),
        }
    }

    /// Constrained to be in a slot
    pub fn is_in_slot() -> Self {
        Self {
            constraint: PrincipalOrResourceConstraint::is_in_slot(),
        }
    }

    /// Hierarchical constraint.
    pub fn is_in(euid: Arc<EntityUID>) -> Self {
        ResourceConstraint {
            constraint: PrincipalOrResourceConstraint::is_in(euid),
        }
    }

    /// Type constraint additionally constrained to be in a slot.
    pub fn is_entity_type_in_slot(entity_type: Arc<EntityType>) -> Self {
        Self {
            constraint: PrincipalOrResourceConstraint::is_entity_type_in_slot(entity_type),
        }
    }

    /// Type constraint, with a hierarchical constraint.
    pub fn is_entity_type_in(entity_type: Arc<EntityType>, in_entity: Arc<EntityUID>) -> Self {
        Self {
            constraint: PrincipalOrResourceConstraint::is_entity_type_in(entity_type, in_entity),
        }
    }

    /// Type constraint, with no hierarchical constraint or slot.
    pub fn is_entity_type(entity_type: Arc<EntityType>) -> Self {
        Self {
            constraint: PrincipalOrResourceConstraint::is_entity_type(entity_type),
        }
    }

    /// Fill in the Slot, if any, with the given EUID
    pub fn with_filled_slot(self, euid: Arc<EntityUID>) -> Self {
        match self.constraint {
            PrincipalOrResourceConstraint::Eq(EntityReference::Slot) => Self {
                constraint: PrincipalOrResourceConstraint::Eq(EntityReference::EUID(euid)),
            },
            PrincipalOrResourceConstraint::In(EntityReference::Slot) => Self {
                constraint: PrincipalOrResourceConstraint::In(EntityReference::EUID(euid)),
            },
            _ => self,
        }
    }
}

impl std::fmt::Display for ResourceConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.as_inner().display(PrincipalOrResource::Resource)
        )
    }
}

/// A reference to an EntityUID that may be a Slot
#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub enum EntityReference {
    /// Reference to a literal EUID
    EUID(Arc<EntityUID>),
    /// Template Slot
    Slot,
}

impl EntityReference {
    /// Create an entity reference to a specific EntityUID
    pub fn euid(euid: Arc<EntityUID>) -> Self {
        Self::EUID(euid)
    }

    /// Transform into an expression AST
    ///
    /// `slot` indicates what `SlotId` would be implied by
    /// `EntityReference::Slot`, which is always clear from the caller's
    /// context.
    pub fn into_expr(&self, slot: SlotId) -> Expr {
        match self {
            EntityReference::EUID(euid) => Expr::val(euid.clone()),
            EntityReference::Slot => Expr::slot(slot),
        }
    }
}

/// Error for unexpected slots
#[derive(Debug, Clone, PartialEq, Error)]
pub enum UnexpectedSlotError {
    /// Found this slot where slots are not allowed
    #[error("found slot `{}` where slots are not allowed", .0.id)]
    FoundSlot(Slot),
}

impl Diagnostic for UnexpectedSlotError {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        match self {
            Self::FoundSlot(Slot { loc, .. }) => loc.as_ref().map(|loc| {
                let label = miette::LabeledSpan::underline(loc.span);
                Box::new(std::iter::once(label)) as Box<dyn Iterator<Item = miette::LabeledSpan>>
            }),
        }
    }
}

impl From<EntityUID> for EntityReference {
    fn from(euid: EntityUID) -> Self {
        Self::EUID(Arc::new(euid))
    }
}

/// Subset of AST variables that have the same constraint form
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum PrincipalOrResource {
    /// The principal of a request
    Principal,
    /// The resource of a request
    Resource,
}

impl std::fmt::Display for PrincipalOrResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = Var::from(*self);
        write!(f, "{v}")
    }
}

impl TryFrom<Var> for PrincipalOrResource {
    type Error = Var;

    fn try_from(value: Var) -> Result<Self, Self::Error> {
        match value {
            Var::Principal => Ok(Self::Principal),
            Var::Action => Err(Var::Action),
            Var::Resource => Ok(Self::Resource),
            Var::Context => Err(Var::Context),
        }
    }
}

/// Represents the constraints for principals and resources.
/// Can either not constrain, or constrain via `==` or `in` for a single entity literal.
#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub enum PrincipalOrResourceConstraint {
    /// Unconstrained
    Any,
    /// Hierarchical constraint
    In(EntityReference),
    /// Equality constraint
    Eq(EntityReference),
    /// Type constraint,
    Is(Arc<EntityType>),
    /// Type constraint with a hierarchy constraint
    IsIn(Arc<EntityType>, EntityReference),
}

impl PrincipalOrResourceConstraint {
    /// Unconstrained.
    pub fn any() -> Self {
        PrincipalOrResourceConstraint::Any
    }

    /// Constrained to equal a specific euid.
    pub fn is_eq(euid: Arc<EntityUID>) -> Self {
        PrincipalOrResourceConstraint::Eq(EntityReference::euid(euid))
    }

    /// Constrained to equal a slot
    pub fn is_eq_slot() -> Self {
        PrincipalOrResourceConstraint::Eq(EntityReference::Slot)
    }

    /// Constrained to be in a slot
    pub fn is_in_slot() -> Self {
        PrincipalOrResourceConstraint::In(EntityReference::Slot)
    }

    /// Hierarchical constraint.
    pub fn is_in(euid: Arc<EntityUID>) -> Self {
        PrincipalOrResourceConstraint::In(EntityReference::euid(euid))
    }

    /// Type constraint additionally constrained to be in a slot.
    pub fn is_entity_type_in_slot(entity_type: Arc<EntityType>) -> Self {
        PrincipalOrResourceConstraint::IsIn(entity_type, EntityReference::Slot)
    }

    /// Type constraint with a hierarchical constraint.
    pub fn is_entity_type_in(entity_type: Arc<EntityType>, in_entity: Arc<EntityUID>) -> Self {
        PrincipalOrResourceConstraint::IsIn(entity_type, EntityReference::euid(in_entity))
    }

    /// Type constraint, with no hierarchical constraint or slot.
    pub fn is_entity_type(entity_type: Arc<EntityType>) -> Self {
        PrincipalOrResourceConstraint::Is(entity_type)
    }

    /// Turn the constraint into an expr
    /// # arguments
    /// * `v` - The variable name to be used in the expression.
    pub fn as_expr(&self, v: PrincipalOrResource) -> Expr {
        match self {
            PrincipalOrResourceConstraint::Any => Expr::val(true),
            PrincipalOrResourceConstraint::Eq(euid) => {
                Expr::is_eq(Expr::var(v.into()), euid.into_expr(v.into()))
            }
            PrincipalOrResourceConstraint::In(euid) => {
                Expr::is_in(Expr::var(v.into()), euid.into_expr(v.into()))
            }
            PrincipalOrResourceConstraint::IsIn(entity_type, euid) => Expr::and(
                Expr::is_entity_type(Expr::var(v.into()), entity_type.as_ref().clone()),
                Expr::is_in(Expr::var(v.into()), euid.into_expr(v.into())),
            ),
            PrincipalOrResourceConstraint::Is(entity_type) => {
                Expr::is_entity_type(Expr::var(v.into()), entity_type.as_ref().clone())
            }
        }
    }

    /// Pretty print the constraint
    /// # arguments
    /// * `v` - The variable name to be used in the expression.
    pub fn display(&self, v: PrincipalOrResource) -> String {
        match self {
            PrincipalOrResourceConstraint::In(euid) => {
                format!("{} in {}", v, euid.into_expr(v.into()))
            }
            PrincipalOrResourceConstraint::Eq(euid) => {
                format!("{} == {}", v, euid.into_expr(v.into()))
            }
            PrincipalOrResourceConstraint::IsIn(entity_type, euid) => {
                format!("{} is {} in {}", v, entity_type, euid.into_expr(v.into()))
            }
            PrincipalOrResourceConstraint::Is(entity_type) => {
                format!("{} is {}", v, entity_type)
            }
            PrincipalOrResourceConstraint::Any => format!("{}", v),
        }
    }

    /// Get the entity uid in this constraint or `None` if there are no uids in the constraint
    pub fn get_euid(&self) -> Option<&Arc<EntityUID>> {
        match self {
            PrincipalOrResourceConstraint::Any => None,
            PrincipalOrResourceConstraint::In(EntityReference::EUID(euid)) => Some(euid),
            PrincipalOrResourceConstraint::In(EntityReference::Slot) => None,
            PrincipalOrResourceConstraint::Eq(EntityReference::EUID(euid)) => Some(euid),
            PrincipalOrResourceConstraint::Eq(EntityReference::Slot) => None,
            PrincipalOrResourceConstraint::IsIn(_, EntityReference::EUID(euid)) => Some(euid),
            PrincipalOrResourceConstraint::IsIn(_, EntityReference::Slot) => None,
            PrincipalOrResourceConstraint::Is(_) => None,
        }
    }

    /// Get an iterator over all of the entity type names in this constraint.
    pub fn iter_entity_type_names(&self) -> impl Iterator<Item = &'_ EntityType> {
        self.get_euid()
            .into_iter()
            .map(|euid| euid.entity_type())
            .chain(match self {
                PrincipalOrResourceConstraint::Is(entity_type)
                | PrincipalOrResourceConstraint::IsIn(entity_type, _) => Some(entity_type.as_ref()),
                _ => None,
            })
    }
}

/// Constraint for action scope variables.
/// Action variables can be constrained to be in any variable in a list.
#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub enum ActionConstraint {
    /// Unconstrained
    Any,
    /// Constrained to being in a list.
    In(Vec<Arc<EntityUID>>),
    /// Constrained to equal a specific euid.
    Eq(Arc<EntityUID>),
}

impl std::fmt::Display for ActionConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let render_euids =
            |euids: &Vec<Arc<EntityUID>>| euids.iter().map(|euid| format!("{euid}")).join(",");
        match self {
            ActionConstraint::Any => write!(f, "action"),
            ActionConstraint::In(euids) => {
                write!(f, "action in [{}]", render_euids(euids))
            }
            ActionConstraint::Eq(euid) => write!(f, "action == {}", euid),
        }
    }
}

impl ActionConstraint {
    /// Unconstrained action.
    pub fn any() -> Self {
        ActionConstraint::Any
    }

    /// Action constrained to being in a list of euids.
    pub fn is_in(euids: impl IntoIterator<Item = EntityUID>) -> Self {
        ActionConstraint::In(euids.into_iter().map(Arc::new).collect())
    }

    /// Action constrained to being equal to a euid.
    pub fn is_eq(euid: EntityUID) -> Self {
        ActionConstraint::Eq(Arc::new(euid))
    }

    fn euids_into_expr(euids: impl IntoIterator<Item = Arc<EntityUID>>) -> Expr {
        Expr::set(euids.into_iter().map(Expr::val))
    }

    /// Turn the constraint into an expression.
    pub fn as_expr(&self) -> Expr {
        match self {
            ActionConstraint::Any => Expr::val(true),
            ActionConstraint::In(euids) => Expr::is_in(
                Expr::var(Var::Action),
                ActionConstraint::euids_into_expr(euids.iter().cloned()),
            ),
            ActionConstraint::Eq(euid) => {
                Expr::is_eq(Expr::var(Var::Action), Expr::val(euid.clone()))
            }
        }
    }

    /// Get an iterator over all of the entity uids in this constraint.
    pub fn iter_euids(&self) -> impl Iterator<Item = &'_ EntityUID> {
        match self {
            ActionConstraint::Any => EntityIterator::None,
            ActionConstraint::In(euids) => {
                EntityIterator::Bunch(euids.iter().map(Arc::as_ref).collect())
            }
            ActionConstraint::Eq(euid) => EntityIterator::One(euid),
        }
    }

    /// Get an iterator over all of the entity types in this constraint.
    pub fn iter_entity_type_names(&self) -> impl Iterator<Item = &'_ EntityType> {
        self.iter_euids().map(|euid| euid.entity_type())
    }

    /// Check that all of the EUIDs in an action constraint have the type
    /// `Action`, under an arbitrary namespace.
    pub fn contains_only_action_types(self) -> Result<Self, NonEmpty<Arc<EntityUID>>> {
        match self {
            ActionConstraint::Any => Ok(self),
            ActionConstraint::In(ref euids) => {
                if let Some(euids) =
                    NonEmpty::collect(euids.iter().filter(|euid| !euid.is_action()).cloned())
                {
                    Err(euids)
                } else {
                    Ok(self)
                }
            }
            ActionConstraint::Eq(ref euid) => {
                if euid.is_action() {
                    Ok(self)
                } else {
                    Err(nonempty![euid.clone()])
                }
            }
        }
    }
}

impl std::fmt::Display for StaticPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (k, v) in self.0.annotations.iter() {
            writeln!(f, "@{}(\"{}\")", k, v.val.escape_debug())?
        }
        write!(
            f,
            "{}(\n  {},\n  {},\n  {}\n) when {{\n  {}\n}};",
            self.effect(),
            self.principal_constraint(),
            self.action_constraint(),
            self.resource_constraint(),
            self.non_scope_constraints()
        )
    }
}

/// A unique identifier for a policy statement
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub struct PolicyID(SmolStr);

impl PolicyID {
    /// Create a PolicyID from a string or string-like
    pub fn from_string(id: impl AsRef<str>) -> Self {
        Self(SmolStr::from(id.as_ref()))
    }

    /// Create a PolicyID from a `SmolStr`
    pub fn from_smolstr(id: SmolStr) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for PolicyID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.escape_debug())
    }
}

impl AsRef<str> for PolicyID {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "arbitrary")]
impl<'u> arbitrary::Arbitrary<'u> for PolicyID {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<PolicyID> {
        let s: String = u.arbitrary()?;
        Ok(PolicyID::from_string(s))
    }
    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        <String as arbitrary::Arbitrary>::size_hint(depth)
    }
}

/// the Effect of a policy
#[derive(Serialize, Deserialize, Hash, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum Effect {
    /// this is a Permit policy
    Permit,
    /// this is a Forbid policy
    Forbid,
}

impl std::fmt::Display for Effect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Permit => write!(f, "permit"),
            Self::Forbid => write!(f, "forbid"),
        }
    }
}

enum EntityIterator<'a> {
    None,
    One(&'a EntityUID),
    Bunch(Vec<&'a EntityUID>),
}

impl<'a> Iterator for EntityIterator<'a> {
    type Item = &'a EntityUID;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            EntityIterator::None => None,
            EntityIterator::One(euid) => {
                let eptr = *euid;
                let mut ptr = EntityIterator::None;
                std::mem::swap(self, &mut ptr);
                Some(eptr)
            }
            EntityIterator::Bunch(v) => v.pop(),
        }
    }
}

#[cfg(test)]
pub mod test_generators {
    use super::*;

    pub fn all_por_constraints() -> impl Iterator<Item = PrincipalOrResourceConstraint> {
        let euid = Arc::new(EntityUID::with_eid("test"));
        let v = vec![
            PrincipalOrResourceConstraint::any(),
            PrincipalOrResourceConstraint::is_eq(euid.clone()),
            PrincipalOrResourceConstraint::Eq(EntityReference::Slot),
            PrincipalOrResourceConstraint::is_in(euid),
            PrincipalOrResourceConstraint::In(EntityReference::Slot),
        ];

        v.into_iter()
    }

    pub fn all_principal_constraints() -> impl Iterator<Item = PrincipalConstraint> {
        all_por_constraints().map(|constraint| PrincipalConstraint { constraint })
    }

    pub fn all_resource_constraints() -> impl Iterator<Item = ResourceConstraint> {
        all_por_constraints().map(|constraint| ResourceConstraint { constraint })
    }

    pub fn all_actions_constraints() -> impl Iterator<Item = ActionConstraint> {
        let euid: EntityUID = "Action::\"test\""
            .parse()
            .expect("Invalid action constraint euid");
        let v = vec![
            ActionConstraint::any(),
            ActionConstraint::is_eq(euid.clone()),
            ActionConstraint::is_in([euid.clone()]),
            ActionConstraint::is_in([euid.clone(), euid]),
        ];

        v.into_iter()
    }

    pub fn all_templates() -> impl Iterator<Item = Template> {
        let mut buf = vec![];
        let permit = PolicyID::from_string("permit");
        let forbid = PolicyID::from_string("forbid");
        for principal in all_principal_constraints() {
            for action in all_actions_constraints() {
                for resource in all_resource_constraints() {
                    let permit = Template::new(
                        permit.clone(),
                        None,
                        Annotations::new(),
                        Effect::Permit,
                        principal.clone(),
                        action.clone(),
                        resource.clone(),
                        Expr::val(true),
                    );
                    let forbid = Template::new(
                        forbid.clone(),
                        None,
                        Annotations::new(),
                        Effect::Forbid,
                        principal.clone(),
                        action.clone(),
                        resource.clone(),
                        Expr::val(true),
                    );
                    buf.push(permit);
                    buf.push(forbid);
                }
            }
        }
        buf.into_iter()
    }
}

#[cfg(test)]
// PANIC SAFETY: Unit Test Code
#[allow(clippy::indexing_slicing)]
// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
mod test {
    use cool_asserts::assert_matches;
    use std::collections::HashSet;

    use super::{test_generators::*, *};
    use crate::{
        parser::{
            parse_policy,
            test_utils::{expect_exactly_one_error, expect_some_error_matches},
        },
        test_utils::ExpectedErrorMessageBuilder,
    };

    #[test]
    fn literal_and_borrowed() {
        for template in all_templates() {
            let t = Arc::new(template);
            let env = t
                .slots()
                .map(|slot| (slot.id, EntityUID::with_eid("eid")))
                .collect();
            let p = Template::link(t, PolicyID::from_string("id"), env).expect("Linking failed");

            let b_literal = BorrowedLiteralPolicy::from(&p);
            let src = serde_json::to_string(&b_literal).expect("ser error");
            let literal: LiteralPolicy = serde_json::from_str(&src).expect("de error");

            assert_eq!(b_literal.template_id, &literal.template_id);
            assert_eq!(b_literal.link_id, literal.link_id.as_ref());
            assert_eq!(b_literal.values, &literal.values);
        }
    }

    #[test]
    fn template_roundtrip() {
        for template in all_templates() {
            template.check_invariant();
            let json = serde_json::to_string(&template).expect("Serialization Failed");
            let t2 = serde_json::from_str::<Template>(&json).expect("Deserialization failed");
            t2.check_invariant();
            assert_eq!(template, t2);
        }
    }

    #[test]
    fn test_template_rebuild() {
        for template in all_templates() {
            let id = template.id().clone();
            let effect = template.effect();
            let p = template.principal_constraint().clone();
            let a = template.action_constraint().clone();
            let r = template.resource_constraint().clone();
            let non_scope = template.non_scope_constraints().clone();
            let t2 = Template::new(id, None, Annotations::new(), effect, p, a, r, non_scope);
            assert_eq!(template, t2);
        }
    }

    #[test]
    fn test_inline_policy_rebuild() {
        for template in all_templates() {
            if let Ok(ip) = StaticPolicy::try_from(template.clone()) {
                let id = ip.id().clone();
                let e = ip.effect();
                let anno = ip
                    .annotations()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                let p = ip.principal_constraint().clone();
                let a = ip.action_constraint().clone();
                let r = ip.resource_constraint().clone();
                let non_scope = ip.non_scope_constraints().clone();
                let ip2 = StaticPolicy::new(id, None, anno, e, p, a, r, non_scope)
                    .expect("Policy Creation Failed");
                assert_eq!(ip, ip2);
                let (t2, inst) = Template::link_static_policy(ip2);
                assert!(inst.is_static());
                assert_eq!(&template, t2.as_ref());
            }
        }
    }

    #[test]
    fn ir_binding_too_many() {
        let tid = PolicyID::from_string("tid");
        let iid = PolicyID::from_string("iid");
        let t = Arc::new(Template::new(
            tid,
            None,
            Annotations::new(),
            Effect::Forbid,
            PrincipalConstraint::is_eq_slot(),
            ActionConstraint::Any,
            ResourceConstraint::any(),
            Expr::val(true),
        ));
        let mut m = HashMap::new();
        m.insert(SlotId::resource(), EntityUID::with_eid("eid"));
        assert_matches!(Template::link(t, iid, m), Err(LinkingError::ArityError { unbound_values, extra_values }) => {
            assert_eq!(unbound_values, vec![SlotId::principal()]);
            assert_eq!(extra_values, vec![SlotId::resource()]);
        });
    }

    #[test]
    fn ir_binding_too_few() {
        let tid = PolicyID::from_string("tid");
        let iid = PolicyID::from_string("iid");
        let t = Arc::new(Template::new(
            tid,
            None,
            Annotations::new(),
            Effect::Forbid,
            PrincipalConstraint::is_eq_slot(),
            ActionConstraint::Any,
            ResourceConstraint::is_in_slot(),
            Expr::val(true),
        ));
        assert_matches!(Template::link(t.clone(), iid.clone(), HashMap::new()), Err(LinkingError::ArityError { unbound_values, extra_values }) => {
            assert_eq!(unbound_values, vec![SlotId::resource(), SlotId::principal()]);
            assert_eq!(extra_values, vec![]);
        });
        let mut m = HashMap::new();
        m.insert(SlotId::principal(), EntityUID::with_eid("eid"));
        assert_matches!(Template::link(t, iid, m), Err(LinkingError::ArityError { unbound_values, extra_values }) => {
            assert_eq!(unbound_values, vec![SlotId::resource()]);
            assert_eq!(extra_values, vec![]);
        });
    }

    #[test]
    fn ir_binding() {
        let tid = PolicyID::from_string("template");
        let iid = PolicyID::from_string("linked");
        let t = Arc::new(Template::new(
            tid,
            None,
            Annotations::new(),
            Effect::Permit,
            PrincipalConstraint::is_in_slot(),
            ActionConstraint::any(),
            ResourceConstraint::is_eq_slot(),
            Expr::val(true),
        ));

        let mut m = HashMap::new();
        m.insert(SlotId::principal(), EntityUID::with_eid("theprincipal"));
        m.insert(SlotId::resource(), EntityUID::with_eid("theresource"));

        let r = Template::link(t, iid.clone(), m).expect("Should Succeed");
        assert_eq!(r.id(), &iid);
        assert_eq!(
            r.env().get(&SlotId::principal()),
            Some(&EntityUID::with_eid("theprincipal"))
        );
        assert_eq!(
            r.env().get(&SlotId::resource()),
            Some(&EntityUID::with_eid("theresource"))
        );
    }

    #[test]
    fn isnt_template_implies_from_succeeds() {
        for template in all_templates() {
            if template.slots().count() == 0 {
                StaticPolicy::try_from(template).expect("Should succeed");
            }
        }
    }

    #[test]
    fn is_template_implies_from_fails() {
        for template in all_templates() {
            if template.slots().count() != 0 {
                assert!(
                    StaticPolicy::try_from(template.clone()).is_err(),
                    "Following template did convert {template}"
                );
            }
        }
    }

    #[test]
    fn non_template_iso() {
        for template in all_templates() {
            if let Ok(p) = StaticPolicy::try_from(template.clone()) {
                let (t2, _) = Template::link_static_policy(p);
                assert_eq!(&template, t2.as_ref());
            }
        }
    }

    #[test]
    fn template_into_expr() {
        for template in all_templates() {
            if let Ok(p) = StaticPolicy::try_from(template.clone()) {
                let t: Template = template;
                assert_eq!(p.condition(), t.condition());
                assert_eq!(p.effect(), t.effect());
            }
        }
    }

    #[test]
    fn template_por_iter() {
        let e = Arc::new(EntityUID::with_eid("eid"));
        assert_eq!(PrincipalOrResourceConstraint::Any.get_euid(), None);
        assert_eq!(
            PrincipalOrResourceConstraint::In(EntityReference::EUID(e.clone())).get_euid(),
            Some(&e)
        );
        assert_eq!(
            PrincipalOrResourceConstraint::In(EntityReference::Slot).get_euid(),
            None
        );
        assert_eq!(
            PrincipalOrResourceConstraint::Eq(EntityReference::EUID(e.clone())).get_euid(),
            Some(&e)
        );
        assert_eq!(
            PrincipalOrResourceConstraint::Eq(EntityReference::Slot).get_euid(),
            None
        );
        assert_eq!(
            PrincipalOrResourceConstraint::IsIn(
                Arc::new("T".parse().unwrap()),
                EntityReference::EUID(e.clone())
            )
            .get_euid(),
            Some(&e)
        );
        assert_eq!(
            PrincipalOrResourceConstraint::Is(Arc::new("T".parse().unwrap())).get_euid(),
            None
        );
        assert_eq!(
            PrincipalOrResourceConstraint::IsIn(
                Arc::new("T".parse().unwrap()),
                EntityReference::Slot
            )
            .get_euid(),
            None
        );
    }

    #[test]
    fn action_iter() {
        assert_eq!(ActionConstraint::Any.iter_euids().count(), 0);
        let a = ActionConstraint::Eq(Arc::new(EntityUID::with_eid("test")));
        let v = a.iter_euids().collect::<Vec<_>>();
        assert_eq!(vec![&EntityUID::with_eid("test")], v);
        let a =
            ActionConstraint::is_in([EntityUID::with_eid("test1"), EntityUID::with_eid("test2")]);
        let set = a.iter_euids().collect::<HashSet<_>>();
        let e1 = EntityUID::with_eid("test1");
        let e2 = EntityUID::with_eid("test2");
        let correct = vec![&e1, &e2].into_iter().collect::<HashSet<_>>();
        assert_eq!(set, correct);
    }

    #[test]
    fn test_iter_none() {
        let mut i = EntityIterator::None;
        assert_eq!(i.next(), None);
    }

    #[test]
    fn test_iter_once() {
        let id = EntityUID::from_components(
            name::Name::unqualified_name(id::Id::new_unchecked("s")).into(),
            entity::Eid::new("eid"),
            None,
        );
        let mut i = EntityIterator::One(&id);
        assert_eq!(i.next(), Some(&id));
        assert_eq!(i.next(), None);
    }

    #[test]
    fn test_iter_mult() {
        let id1 = EntityUID::from_components(
            name::Name::unqualified_name(id::Id::new_unchecked("s")).into(),
            entity::Eid::new("eid1"),
            None,
        );
        let id2 = EntityUID::from_components(
            name::Name::unqualified_name(id::Id::new_unchecked("s")).into(),
            entity::Eid::new("eid2"),
            None,
        );
        let v = vec![&id1, &id2];
        let mut i = EntityIterator::Bunch(v);
        assert_eq!(i.next(), Some(&id2));
        assert_eq!(i.next(), Some(&id1));
        assert_eq!(i.next(), None)
    }

    #[test]
    fn euid_into_expr() {
        let e = EntityReference::Slot;
        assert_eq!(
            e.into_expr(SlotId::principal()),
            Expr::slot(SlotId::principal())
        );
        let e = EntityReference::euid(Arc::new(EntityUID::with_eid("eid")));
        assert_eq!(
            e.into_expr(SlotId::principal()),
            Expr::val(EntityUID::with_eid("eid"))
        );
    }

    #[test]
    fn por_constraint_display() {
        let t = PrincipalOrResourceConstraint::Eq(EntityReference::Slot);
        let s = t.display(PrincipalOrResource::Principal);
        assert_eq!(s, "principal == ?principal");
        let t = PrincipalOrResourceConstraint::Eq(EntityReference::euid(Arc::new(
            EntityUID::with_eid("test"),
        )));
        let s = t.display(PrincipalOrResource::Principal);
        assert_eq!(s, "principal == test_entity_type::\"test\"");
    }

    #[test]
    fn unexpected_templates() {
        let policy_str = r#"permit(principal == ?principal, action, resource);"#;
        assert_matches!(parse_policy(Some(PolicyID::from_string("id")), policy_str), Err(e) => {
            expect_exactly_one_error(policy_str, &e, &ExpectedErrorMessageBuilder::error(
                "expected a static policy, got a template containing the slot ?principal"
                )
                .help("try removing the template slot(s) from this policy")
                .exactly_one_underline("permit(principal == ?principal, action, resource);")
                .build()
            );
        });

        let policy_str =
            r#"permit(principal == ?principal, action, resource) when { ?principal == 3 } ;"#;
        assert_matches!(parse_policy(Some(PolicyID::from_string("id")), policy_str), Err(e) => {
            expect_some_error_matches(policy_str, &e, &ExpectedErrorMessageBuilder::error(
                "expected a static policy, got a template containing the slot ?principal"
                )
                .help("try removing the template slot(s) from this policy")
                .exactly_one_underline("?principal")
                .build()
            );
            assert_eq!(e.len(), 2);
        });
    }
}
