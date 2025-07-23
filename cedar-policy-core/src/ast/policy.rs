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
use crate::parser::{AsLocRef, IntoMaybeLoc, Loc, MaybeLoc};
use annotation::{Annotation, Annotations};
use educe::Educe;
use itertools::Itertools;
use miette::Diagnostic;
use nonempty::{nonempty, NonEmpty};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
};
use thiserror::Error;

#[cfg(feature = "wasm")]
extern crate tsify;

macro_rules! cfg_tolerant_ast {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "tolerant-ast")]
            $item
        )*
    };
}

cfg_tolerant_ast! {
    use super::expr_allows_errors::AstExprErrorKind;
    use crate::ast::expr_allows_errors::ExprWithErrsBuilder;
    use crate::expr_builder::ExprBuilder;
    use crate::parser::err::ParseErrors;
    use crate::parser::err::ToASTError;
    use crate::parser::err::ToASTErrorKind;

    static DEFAULT_ANNOTATIONS: std::sync::LazyLock<Arc<Annotations>> =
        std::sync::LazyLock::new(|| Arc::new(Annotations::default()));

    static DEFAULT_PRINCIPAL_CONSTRAINT: std::sync::LazyLock<PrincipalConstraint> =
        std::sync::LazyLock::new(PrincipalConstraint::any);

    static DEFAULT_RESOURCE_CONSTRAINT: std::sync::LazyLock<ResourceConstraint> =
        std::sync::LazyLock::new(ResourceConstraint::any);

    static DEFAULT_ACTION_CONSTRAINT: std::sync::LazyLock<ActionConstraint> =
        std::sync::LazyLock::new(ActionConstraint::any);

    static DEFAULT_ERROR_EXPR: std::sync::LazyLock<Arc<Expr>> = std::sync::LazyLock::new(|| {
        // Non scope constraint expression of an Error policy should also be an error
        // This const represents an error expression that is part of an Error policy
        // PANIC SAFETY: Infallible error type - can never fail
        #[allow(clippy::unwrap_used)]
        Arc::new(
            <ExprWithErrsBuilder as ExprBuilder>::new()
                .error(ParseErrors::singleton(ToASTError::new(
                    ToASTErrorKind::ASTErrorNode,
                    Loc::new(0..1, "ASTErrorNode".into()).into_maybe_loc(),
                )))
                .unwrap(),
        )
    });
}

/// Top level structure for a policy template.
/// Contains both the AST for template, and the list of open slots in the template.
///
/// Note that this "template" may have no slots, in which case this `Template` represents a static policy
#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct Template {
    body: TemplateBody,
    /// INVARIANT (slot cache correctness): This Vec must contain _all_ of the open slots in `body`
    /// This is maintained by the only public constructors: `new()`, `new_shared()`, and `link_static_policy()`
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
    ///
    /// This function is a no-op in release builds, but checks the invariant (and panics if it fails) in debug builds.
    pub fn check_invariant(&self) {
        #[cfg(debug_assertions)]
        {
            for slot in self.body.condition().slots() {
                assert!(self.slots.contains(&slot));
            }
            for slot in self.slots() {
                assert!(self.body.condition().slots().contains(slot));
            }
        }
    }

    /// Construct a `Template` from its components
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: PolicyID,
        loc: MaybeLoc,
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

    #[cfg(feature = "tolerant-ast")]
    /// Generate a template representing a policy that is unparsable
    pub fn error(id: PolicyID, loc: MaybeLoc) -> Self {
        let body = TemplateBody::error(id, loc);
        Template::from(body)
    }

    /// Construct a template from an expression/annotations that are already [`std::sync::Arc`] allocated
    #[allow(clippy::too_many_arguments)]
    pub fn new_shared(
        id: PolicyID,
        loc: MaybeLoc,
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
        t.check_invariant();
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
    #[error(fmt = describe_arity_error)]
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

fn describe_arity_error(
    unbound_values: &[SlotId],
    extra_values: &[SlotId],
    fmt: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    match (unbound_values.len(), extra_values.len()) {
        // PANIC SAFETY 0,0 case is not an error
        #[allow(clippy::unreachable)]
        (0,0) => unreachable!(),
        (_unbound, 0) => write!(fmt, "the following slots were not provided as arguments: {}", unbound_values.iter().join(",")),
        (0, _extra) => write!(fmt, "the following slots were provided as arguments, but did not exist in the template: {}", extra_values.iter().join(",")),
        (_unbound, _extra) => write!(fmt, "the following slots were not provided as arguments: {}. The following slots were provided as arguments, but did not exist in the template: {}", unbound_values.iter().join(","), extra_values.iter().join(",")),
    }
}

/// A Policy that contains:
///   - a pointer to its template
///   - a link ID (unless it's a static policy)
///   - the bound values for slots in the template
///
/// Policies are not serializable (due to the pointer), and can be serialized
/// by converting to/from LiteralPolicy
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Policy {
    /// Reference to the template
    template: Arc<Template>,
    /// Id of this link
    ///
    /// None in the case that this is an instance of a Static Policy
    link: Option<PolicyID>,
    // INVARIANT (values total map)
    // All of the slots in `template` MUST be bound by `values`
    //
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
        #[cfg(debug_assertions)]
        {
            // PANIC SAFETY: asserts (value total map invariant) which is justified at call sites
            #[allow(clippy::expect_used)]
            Template::check_binding(&template, &values).expect("(values total map) does not hold!");
        }
        Self {
            template,
            link: link_id,
            values,
        }
    }

    /// Build a policy with a given effect, given when clause, and unconstrained scope variables
    pub fn from_when_clause(effect: Effect, when: Expr, id: PolicyID, loc: MaybeLoc) -> Self {
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
        loc: MaybeLoc,
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

    /// Returns all the unknown entities in the policy during evaluation
    pub fn unknown_entities(&self) -> HashSet<EntityUID> {
        self.condition()
            .unknowns()
            .filter_map(
                |Unknown {
                     name,
                     type_annotation,
                 }| {
                    if matches!(type_annotation, Some(Type::Entity { .. })) {
                        EntityUID::from_str(name.as_str()).ok()
                    } else {
                        None
                    }
                },
            )
            .collect()
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

/// Represents either a static policy or a template linked policy.
///
/// Contains less rich information than `Policy`. In particular, this form is
/// easier to convert to/from the Protobuf representation of a `Policy`, because
/// it simply refers to the `Template` by its Id and does not contain a
/// reference to the `Template` itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiteralPolicy {
    /// ID of the template this policy is an instance of
    template_id: PolicyID,
    /// ID of this link.
    /// This is `None` for static policies, and the static policy ID is defined
    /// as the `template_id`
    link_id: Option<PolicyID>,
    /// Values of the slots
    values: SlotEnv,
}

impl LiteralPolicy {
    /// Create a `LiteralPolicy` representing a static policy with the given ID.
    ///
    /// The policy set should also contain a (zero-slot) `Template` with the given ID.
    pub fn static_policy(template_id: PolicyID) -> Self {
        Self {
            template_id,
            link_id: None,
            values: SlotEnv::new(),
        }
    }

    /// Create a `LiteralPolicy` representing a template-linked policy.
    ///
    /// The policy set should also contain the associated `Template`.
    pub fn template_linked_policy(
        template_id: PolicyID,
        link_id: PolicyID,
        values: SlotEnv,
    ) -> Self {
        Self {
            template_id,
            link_id: Some(link_id),
            values,
        }
    }

    /// Get the `EntityUID` associated with the given `SlotId`, if it exists
    pub fn value(&self, slot: &SlotId) -> Option<&EntityUID> {
        self.values.get(slot)
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

// These would be great as property tests
#[cfg(test)]
mod hashing_tests {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    use super::*;

    fn compute_hash(ir: &LiteralPolicy) -> u64 {
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
        assert_eq!(compute_hash(&a), compute_hash(&b));
    }
}

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

    /// Get the [`PolicyID`] of this static or template-linked policy.
    pub fn id(&self) -> &PolicyID {
        self.link_id.as_ref().unwrap_or(&self.template_id)
    }

    /// Get the [`PolicyID`] of the template associated with this policy.
    ///
    /// For static policies, this is just the static policy ID.
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
#[derive(Clone, Hash, Eq, PartialEq, Debug)]
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: PolicyID,
        loc: MaybeLoc,
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
        // INVARIANT (static policy correctness), checks that no slots exists
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
    fn from(p: StaticPolicy) -> Policy {
        let (_, policy) = Template::link_static_policy(p);
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
#[derive(Educe, Clone, Debug)]
#[educe(PartialEq, Eq, Hash)]
pub struct TemplateBodyImpl {
    /// ID of this policy
    id: PolicyID,
    /// Source location spanning the entire policy
    #[educe(PartialEq(ignore))]
    #[educe(Hash(ignore))]
    loc: MaybeLoc,
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

/// Policy datatype. This is used for both templates (in which case it contains
/// slots) and static policies (in which case it contains zero slots).
#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub enum TemplateBody {
    /// Represents a valid template body
    TemplateBody(TemplateBodyImpl),
    #[cfg(feature = "tolerant-ast")]
    /// Represents a policy that failed to parse
    TemplateBodyError(PolicyID, MaybeLoc),
}

impl TemplateBody {
    /// Get the `Id` of this policy.
    pub fn id(&self) -> &PolicyID {
        match self {
            TemplateBody::TemplateBody(TemplateBodyImpl { id, .. }) => id,
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(id, _) => id,
        }
    }

    /// Get the location of this policy
    pub fn loc(&self) -> Option<&Loc> {
        match self {
            TemplateBody::TemplateBody(TemplateBodyImpl { loc, .. }) => loc.as_loc_ref(),
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(_, loc) => loc.as_loc_ref(),
        }
    }

    /// Clone this policy with a new `Id`.
    pub fn new_id(&self, id: PolicyID) -> Self {
        match self {
            TemplateBody::TemplateBody(t) => {
                let mut new = t.clone();
                new.id = id;
                TemplateBody::TemplateBody(new)
            }
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(_, loc) => {
                TemplateBody::TemplateBodyError(id, loc.clone())
            }
        }
    }

    #[cfg(feature = "tolerant-ast")]
    /// Create a template body representing a policy that failed to parse
    pub fn error(id: PolicyID, loc: MaybeLoc) -> Self {
        TemplateBody::TemplateBodyError(id, loc)
    }

    /// Get the `Effect` of this policy.
    pub fn effect(&self) -> Effect {
        match self {
            TemplateBody::TemplateBody(TemplateBodyImpl { effect, .. }) => *effect,
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(_, _) => Effect::Forbid,
        }
    }

    /// Get data from an annotation.
    pub fn annotation(&self, key: &AnyId) -> Option<&Annotation> {
        match self {
            TemplateBody::TemplateBody(TemplateBodyImpl { annotations, .. }) => {
                annotations.get(key)
            }
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(_, _) => None,
        }
    }

    /// Get shared ref to annotations
    pub fn annotations_arc(&self) -> &Arc<Annotations> {
        match self {
            TemplateBody::TemplateBody(TemplateBodyImpl { annotations, .. }) => annotations,
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(_, _) => &DEFAULT_ANNOTATIONS,
        }
    }

    /// Get all annotation data.
    pub fn annotations(&self) -> impl Iterator<Item = (&AnyId, &Annotation)> {
        match self {
            TemplateBody::TemplateBody(TemplateBodyImpl { annotations, .. }) => annotations.iter(),
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(_, _) => DEFAULT_ANNOTATIONS.iter(),
        }
    }

    /// Get the `principal` scope constraint of this policy.
    pub fn principal_constraint(&self) -> &PrincipalConstraint {
        match self {
            TemplateBody::TemplateBody(TemplateBodyImpl {
                principal_constraint,
                ..
            }) => principal_constraint,
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(_, _) => &DEFAULT_PRINCIPAL_CONSTRAINT,
        }

        // &self.principal_constraint
    }

    /// Get the `principal` scope constraint as an expression.
    /// This will be a boolean-valued expression: either `true` (if the policy
    /// just has `principal,`), or an equality or hierarchy constraint
    pub fn principal_constraint_expr(&self) -> Expr {
        match self {
            TemplateBody::TemplateBody(TemplateBodyImpl {
                principal_constraint,
                ..
            }) => principal_constraint.as_expr(),
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(_, _) => DEFAULT_PRINCIPAL_CONSTRAINT.as_expr(),
        }
    }

    /// Get the `action` scope constraint of this policy.
    pub fn action_constraint(&self) -> &ActionConstraint {
        match self {
            TemplateBody::TemplateBody(TemplateBodyImpl {
                action_constraint, ..
            }) => action_constraint,
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(_, _) => &DEFAULT_ACTION_CONSTRAINT,
        }
    }

    /// Get the `action` scope constraint of this policy as an expression.
    /// This will be a boolean-valued expression: either `true` (if the policy
    /// just has `action,`), or an equality or hierarchy constraint
    pub fn action_constraint_expr(&self) -> Expr {
        match self {
            TemplateBody::TemplateBody(TemplateBodyImpl {
                action_constraint, ..
            }) => action_constraint.as_expr(),
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(_, _) => DEFAULT_ACTION_CONSTRAINT.as_expr(),
        }
    }

    /// Get the `resource` scope constraint of this policy.
    pub fn resource_constraint(&self) -> &ResourceConstraint {
        match self {
            TemplateBody::TemplateBody(TemplateBodyImpl {
                resource_constraint,
                ..
            }) => resource_constraint,
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(_, _) => &DEFAULT_RESOURCE_CONSTRAINT,
        }
    }

    /// Get the `resource` scope constraint of this policy as an expression.
    /// This will be a boolean-valued expression: either `true` (if the policy
    /// just has `resource,`), or an equality or hierarchy constraint
    pub fn resource_constraint_expr(&self) -> Expr {
        match self {
            TemplateBody::TemplateBody(TemplateBodyImpl {
                resource_constraint,
                ..
            }) => resource_constraint.as_expr(),
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(_, _) => DEFAULT_RESOURCE_CONSTRAINT.as_expr(),
        }
    }

    /// Get the non-scope constraints of this policy.
    ///
    /// This will be a conjunction of the policy's `when` conditions and the
    /// negation of each of the policy's `unless` conditions.
    pub fn non_scope_constraints(&self) -> &Expr {
        match self {
            TemplateBody::TemplateBody(TemplateBodyImpl {
                non_scope_constraints,
                ..
            }) => non_scope_constraints,
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(_, _) => &DEFAULT_ERROR_EXPR,
        }
    }

    /// Get the Arc owning the non scope constraints
    pub fn non_scope_constraints_arc(&self) -> &Arc<Expr> {
        match self {
            TemplateBody::TemplateBody(TemplateBodyImpl {
                non_scope_constraints,
                ..
            }) => non_scope_constraints,
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(_, _) => &DEFAULT_ERROR_EXPR,
        }
    }

    /// Get the condition expression of this policy.
    ///
    /// This will be a conjunction of the policy's scope constraints (on
    /// principal, resource, and action); the policy's "when" conditions; and
    /// the negation of each of the policy's "unless" conditions.
    pub fn condition(&self) -> Expr {
        match self {
            TemplateBody::TemplateBody(TemplateBodyImpl { .. }) => Expr::and(
                Expr::and(
                    Expr::and(
                        self.principal_constraint_expr(),
                        self.action_constraint_expr(),
                    )
                    .with_maybe_source_loc(self.loc().into_maybe_loc()),
                    self.resource_constraint_expr(),
                )
                .with_maybe_source_loc(self.loc().into_maybe_loc()),
                self.non_scope_constraints().clone(),
            )
            .with_maybe_source_loc(self.loc().into_maybe_loc()),
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(_, _) => DEFAULT_ERROR_EXPR.as_ref().clone(),
        }
    }

    /// Construct a `Policy` from components that are already [`std::sync::Arc`] allocated
    #[allow(clippy::too_many_arguments)]
    pub fn new_shared(
        id: PolicyID,
        loc: MaybeLoc,
        annotations: Arc<Annotations>,
        effect: Effect,
        principal_constraint: PrincipalConstraint,
        action_constraint: ActionConstraint,
        resource_constraint: ResourceConstraint,
        non_scope_constraints: Arc<Expr>,
    ) -> Self {
        Self::TemplateBody(TemplateBodyImpl {
            id,
            loc,
            annotations,
            effect,
            principal_constraint,
            action_constraint,
            resource_constraint,
            non_scope_constraints,
        })
    }

    /// Construct a `Policy` from its components
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: PolicyID,
        loc: MaybeLoc,
        annotations: Annotations,
        effect: Effect,
        principal_constraint: PrincipalConstraint,
        action_constraint: ActionConstraint,
        resource_constraint: ResourceConstraint,
        non_scope_constraints: Expr,
    ) -> Self {
        Self::TemplateBody(TemplateBodyImpl {
            id,
            loc,
            annotations: Arc::new(annotations),
            effect,
            principal_constraint,
            action_constraint,
            resource_constraint,
            non_scope_constraints: Arc::new(non_scope_constraints),
        })
    }
}

impl From<StaticPolicy> for TemplateBody {
    fn from(p: StaticPolicy) -> Self {
        p.0
    }
}

impl std::fmt::Display for TemplateBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateBody::TemplateBody(template_body_impl) => {
                template_body_impl.annotations.fmt(f)?;
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
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(policy_id, _) => {
                write!(f, "TemplateBody::TemplateBodyError({policy_id})")
            }
        }
    }
}

/// Template constraint on principal scope variables
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Debug)]
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
            PrincipalOrResourceConstraint::Eq(EntityReference::Slot(_)) => Self {
                constraint: PrincipalOrResourceConstraint::Eq(EntityReference::EUID(euid)),
            },
            PrincipalOrResourceConstraint::In(EntityReference::Slot(_)) => Self {
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
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Debug)]
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
            PrincipalOrResourceConstraint::Eq(EntityReference::Slot(_)) => Self {
                constraint: PrincipalOrResourceConstraint::Eq(EntityReference::EUID(euid)),
            },
            PrincipalOrResourceConstraint::In(EntityReference::Slot(_)) => Self {
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
#[derive(Educe, Clone, Debug, Eq)]
#[educe(Hash, PartialEq, PartialOrd, Ord)]
pub enum EntityReference {
    /// Reference to a literal EUID
    EUID(Arc<EntityUID>),
    /// Template Slot
    Slot(
        #[educe(PartialEq(ignore))]
        #[educe(PartialOrd(ignore))]
        #[educe(Hash(ignore))]
        MaybeLoc,
    ),
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
            EntityReference::Slot(loc) => Expr::slot(slot).with_maybe_source_loc(loc.clone()),
        }
    }
}

/// Error for unexpected slots
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UnexpectedSlotError {
    /// Found this slot where slots are not allowed
    #[error("found slot `{}` where slots are not allowed", .0.id)]
    FoundSlot(Slot),
}

impl Diagnostic for UnexpectedSlotError {
    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        match self {
            Self::FoundSlot(Slot { loc, .. }) => loc.as_loc_ref().map(|loc| {
                let label = miette::LabeledSpan::underline(loc.span);
                Box::new(std::iter::once(label)) as _
            }),
        }
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        match self {
            Self::FoundSlot(Slot { loc, .. }) => {
                loc.as_loc_ref().map(|l| l as &dyn miette::SourceCode)
            }
        }
    }
}

impl From<EntityUID> for EntityReference {
    fn from(euid: EntityUID) -> Self {
        Self::EUID(Arc::new(euid))
    }
}

/// Subset of AST variables that have the same constraint form
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
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
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Debug)]
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
        PrincipalOrResourceConstraint::Eq(EntityReference::Slot(None))
    }

    /// Constrained to be in a slot
    pub fn is_in_slot() -> Self {
        PrincipalOrResourceConstraint::In(EntityReference::Slot(None))
    }

    /// Hierarchical constraint.
    pub fn is_in(euid: Arc<EntityUID>) -> Self {
        PrincipalOrResourceConstraint::In(EntityReference::euid(euid))
    }

    /// Type constraint additionally constrained to be in a slot.
    pub fn is_entity_type_in_slot(entity_type: Arc<EntityType>) -> Self {
        PrincipalOrResourceConstraint::IsIn(entity_type, EntityReference::Slot(None))
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
                format!("{v} is {entity_type}")
            }
            PrincipalOrResourceConstraint::Any => format!("{v}"),
        }
    }

    /// Get the entity uid in this constraint or `None` if there are no uids in the constraint
    pub fn get_euid(&self) -> Option<&Arc<EntityUID>> {
        match self {
            PrincipalOrResourceConstraint::Any => None,
            PrincipalOrResourceConstraint::In(EntityReference::EUID(euid)) => Some(euid),
            PrincipalOrResourceConstraint::In(EntityReference::Slot(_)) => None,
            PrincipalOrResourceConstraint::Eq(EntityReference::EUID(euid)) => Some(euid),
            PrincipalOrResourceConstraint::Eq(EntityReference::Slot(_)) => None,
            PrincipalOrResourceConstraint::IsIn(_, EntityReference::EUID(euid)) => Some(euid),
            PrincipalOrResourceConstraint::IsIn(_, EntityReference::Slot(_)) => None,
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
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub enum ActionConstraint {
    /// Unconstrained
    Any,
    /// Constrained to being in a list.
    In(Vec<Arc<EntityUID>>),
    /// Constrained to equal a specific euid.
    Eq(Arc<EntityUID>),
    #[cfg(feature = "tolerant-ast")]
    /// Error node representing an action constraint that failed to parse
    ErrorConstraint,
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
            ActionConstraint::Eq(euid) => write!(f, "action == {euid}"),
            #[cfg(feature = "tolerant-ast")]
            ActionConstraint::ErrorConstraint => write!(f, "<invalid_action_constraint>"),
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
            #[cfg(feature = "tolerant-ast")]
            ActionConstraint::ErrorConstraint => Expr::new(
                ExprKind::Error {
                    error_kind: AstExprErrorKind::InvalidExpr(
                        "Invalid action constraint".to_string(),
                    ),
                },
                None,
                (),
            ),
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
            #[cfg(feature = "tolerant-ast")]
            ActionConstraint::ErrorConstraint => EntityIterator::None,
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
            #[cfg(feature = "tolerant-ast")]
            ActionConstraint::ErrorConstraint => Ok(self),
        }
    }
}

impl std::fmt::Display for StaticPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let policy_template = &self.0;
        match policy_template {
            TemplateBody::TemplateBody(template_body_impl) => {
                for (k, v) in template_body_impl.annotations.iter() {
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
            #[cfg(feature = "tolerant-ast")]
            TemplateBody::TemplateBodyError(policy_id, _) => {
                write!(f, "TemplateBody::TemplateBodyError({policy_id})")
            }
        }
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
impl arbitrary::Arbitrary<'_> for PolicyID {
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
pub(crate) mod test_generators {
    use super::*;

    pub fn all_por_constraints() -> impl Iterator<Item = PrincipalOrResourceConstraint> {
        let euid = Arc::new(EntityUID::with_eid("test"));
        let v = vec![
            PrincipalOrResourceConstraint::any(),
            PrincipalOrResourceConstraint::is_eq(euid.clone()),
            PrincipalOrResourceConstraint::Eq(EntityReference::Slot(None)),
            PrincipalOrResourceConstraint::is_in(euid),
            PrincipalOrResourceConstraint::In(EntityReference::Slot(None)),
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
    fn link_templates() {
        for template in all_templates() {
            template.check_invariant();
            let t = Arc::new(template);
            let env = t
                .slots()
                .map(|slot| (slot.id, EntityUID::with_eid("eid")))
                .collect();
            let _ = Template::link(t, PolicyID::from_string("id"), env).expect("Linking failed");
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
    fn test_static_policy_rebuild() {
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
            PrincipalOrResourceConstraint::In(EntityReference::Slot(None)).get_euid(),
            None
        );
        assert_eq!(
            PrincipalOrResourceConstraint::Eq(EntityReference::EUID(e.clone())).get_euid(),
            Some(&e)
        );
        assert_eq!(
            PrincipalOrResourceConstraint::Eq(EntityReference::Slot(None)).get_euid(),
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
                EntityReference::Slot(None)
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
            name::Name::parse_unqualified_name("s").unwrap().into(),
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
            name::Name::parse_unqualified_name("s").unwrap().into(),
            entity::Eid::new("eid1"),
            None,
        );
        let id2 = EntityUID::from_components(
            name::Name::parse_unqualified_name("s").unwrap().into(),
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
        let e = EntityReference::Slot(None);
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
        let t = PrincipalOrResourceConstraint::Eq(EntityReference::Slot(None));
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
                .exactly_one_underline("?principal")
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

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn template_body_error_methods() {
        use std::str::FromStr;

        let policy_id = PolicyID::from_string("error_policy");
        let error_loc = Loc::new(0..1, "ASTErrorNode".into()).into_maybe_loc();
        let error_body = TemplateBody::TemplateBodyError(policy_id.clone(), error_loc.clone());

        let expected_error = <ExprWithErrsBuilder as ExprBuilder>::new()
            .error(ParseErrors::singleton(ToASTError::new(
                ToASTErrorKind::ASTErrorNode,
                Loc::new(0..1, "ASTErrorNode".into()).into_maybe_loc(),
            )))
            .unwrap();

        // Test id() method
        assert_eq!(error_body.id(), &policy_id);

        // Test loc() method
        assert_eq!(error_body.loc(), error_loc.as_loc_ref());

        // Test new_id() method
        let new_policy_id = PolicyID::from_string("new_error_policy");
        let updated_error_body = error_body.new_id(new_policy_id.clone());
        assert_matches!(updated_error_body,
            TemplateBody::TemplateBodyError(id, loc) if id == new_policy_id && loc.clone() == error_loc
        );

        // Test effect() method
        assert_eq!(error_body.effect(), Effect::Forbid);

        // Test annotation() method
        assert_eq!(
            error_body.annotation(&AnyId::from_str("test").unwrap()),
            None
        );

        // Test annotations() method
        assert!(error_body.annotations().count() == 0);

        // Test principal_constraint() method
        assert_eq!(
            *error_body.principal_constraint(),
            PrincipalConstraint::any()
        );

        // Test action_constraint() method
        assert_eq!(*error_body.action_constraint(), ActionConstraint::any());

        // Test resource_constraint() method
        assert_eq!(*error_body.resource_constraint(), ResourceConstraint::any());

        // Test non_scope_constraints() method
        assert_eq!(*error_body.non_scope_constraints(), expected_error);

        // Test condition() method
        assert_eq!(error_body.condition(), expected_error);

        // Test Display implementation
        let display_str = format!("{error_body}");
        assert!(display_str.contains("TemplateBodyError"));
        assert!(display_str.contains("error_policy"));
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn template_error_methods() {
        let policy_id = PolicyID::from_string("error_policy");
        let error_loc = Loc::new(0..1, "ASTErrorNode".into()).into_maybe_loc();
        let error_template = Template::error(policy_id.clone(), error_loc.clone());

        // Check template properties
        assert_eq!(error_template.id(), &policy_id);

        // Check slots are empty
        assert!(error_template.slots().count() == 0);

        // Check body is an error template body
        assert_matches!(error_template.body,
            TemplateBody::TemplateBodyError(ref id, ref loc) if id == &policy_id && loc.clone() == error_loc
        );

        // Test principal_constraint() method
        assert_eq!(
            error_template.principal_constraint(),
            &PrincipalConstraint::any()
        );

        // Test action_constraint() method
        assert_eq!(*error_template.action_constraint(), ActionConstraint::any());

        // Test resource_constraint() method
        assert_eq!(
            *error_template.resource_constraint(),
            ResourceConstraint::any()
        );

        // Verify effect is Forbid
        assert_eq!(error_template.effect(), Effect::Forbid);

        // Verify condition is the default error expression
        assert_eq!(
            error_template.condition(),
            DEFAULT_ERROR_EXPR.as_ref().clone()
        );

        // Verify location is None
        assert_eq!(error_template.loc(), error_loc.as_loc_ref());

        // Verify annotations are default
        assert!(error_template.annotations().count() == 0);

        // Verify display implementation
        let display_str = format!("{error_template}");
        assert!(display_str.contains("TemplateBody::TemplateBodyError"));
        assert!(display_str.contains(&policy_id.to_string()));
    }
}
