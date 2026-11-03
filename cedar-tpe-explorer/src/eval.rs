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

//! Running type-aware partial evaluation over [`Facts`].

use cedar_policy::pst::{self, Expr};
use cedar_policy_core::ast::{Effect, EntityUID, PolicyID};
use cedar_policy_core::authorizer::Decision;
use smol_str::SmolStr;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use crate::analysis::{self, Need, NeedKind};
use crate::facts::{AttrFact, Facts, SlotId};
use crate::project::Project;

/// Outcome of one policy under the current facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// Still depends on unknown facts.
    Residual,
    /// Satisfied: the policy applies.
    True,
    /// Not satisfied.
    False,
    /// Evaluation errors (the policy does not apply).
    Error,
}

/// One policy's partial evaluation result.
#[derive(Debug, Clone)]
pub struct PolicyEval {
    pub id: PolicyID,
    pub effect: Effect,
    pub status: Status,
    /// The remaining condition, from the public TPE API's residual policy.
    pub residual: Arc<Expr>,
    /// Whether this policy can still affect (or is the reason for) the outcome.
    pub relevant: bool,
    /// Slots this residual depends on.
    pub needs: Vec<Need>,
}

impl PolicyEval {
    /// `permit «id»`
    pub fn title(&self) -> String {
        format!("{} «{}»", effect_str(self.effect), self.id)
    }
}

pub fn effect_str(e: Effect) -> &'static str {
    match e {
        Effect::Permit => "permit",
        Effect::Forbid => "forbid",
    }
}

/// Result of partially evaluating every policy.
#[derive(Debug, Clone)]
pub struct Evaluation {
    pub decision: Option<Decision>,
    /// In source order.
    pub policies: Vec<PolicyEval>,
    /// Non-fatal problems building the TPE inputs.
    pub warnings: Vec<String>,
}

/// How a slot is needed by the policies that still matter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotNeed {
    /// The decision is final.
    Settled,
    /// Needed by these policies.
    Needed(NeedKind, Vec<PolicyID>),
    /// Not needed by any relevant policy.
    NotNeeded,
}

impl Evaluation {
    pub fn policy(&self, id: &PolicyID) -> Option<&PolicyEval> {
        self.policies.iter().find(|p| &p.id == id)
    }

    pub fn count(&self, status: Status) -> usize {
        self.policies.iter().filter(|p| p.status == status).count()
    }

    pub fn irrelevant_count(&self) -> usize {
        self.policies.iter().filter(|p| !p.relevant).count()
    }

    /// Policies that determine the decision, if it is known.
    pub fn reasons(&self) -> Vec<&PolicyEval> {
        match self.decision {
            Some(_) => self.policies.iter().filter(|p| p.relevant).collect(),
            None => vec![],
        }
    }

    /// Slots needed by relevant residual policies.
    pub fn needed_slots(&self) -> BTreeSet<SlotId> {
        self.policies
            .iter()
            .filter(|p| p.relevant && p.status == Status::Residual)
            .flat_map(|p| p.needs.iter().map(|n| n.slot.clone()))
            .collect()
    }

    /// Entities referenced by any residual (relevant or not).
    pub fn referenced_entities(&self) -> BTreeSet<EntityUID> {
        self.policies
            .iter()
            .filter(|p| p.status == Status::Residual)
            .flat_map(|p| p.needs.iter().filter_map(|n| n.slot.entity().cloned()))
            .collect()
    }

    /// Is `slot` (or something inside it) needed by a relevant policy?
    pub fn is_needed(&self, slot: &SlotId) -> bool {
        self.needed_slots()
            .iter()
            .any(|n| slot.contains(n) || n.contains(slot))
    }

    /// Why (and by whom) `slot` is needed.
    pub fn slot_need(&self, slot: &SlotId) -> SlotNeed {
        if self.decision.is_some() {
            return SlotNeed::Settled;
        }
        let mut kinds = BTreeSet::new();
        let mut ids = Vec::new();
        for p in &self.policies {
            if !(p.relevant && p.status == Status::Residual) {
                continue;
            }
            for n in &p.needs {
                if slot.contains(&n.slot) || n.slot.contains(slot) {
                    kinds.insert(n.kind);
                    if !ids.contains(&p.id) {
                        ids.push(p.id.clone());
                    }
                }
            }
        }
        match kinds.iter().next() {
            Some(k) => SlotNeed::Needed(*k, ids),
            None => SlotNeed::NotNeeded,
        }
    }

    /// One-line explanation for a slot, e.g.
    /// `needed: a value, for permit «allow same dept»`.
    pub fn describe_slot_need(&self, slot: &SlotId) -> String {
        match self.slot_need(slot) {
            SlotNeed::Settled => self.describe_settled(),
            SlotNeed::NotNeeded => "not needed by any policy that still matters".into(),
            SlotNeed::Needed(kind, ids) => {
                let who = ids
                    .iter()
                    .filter_map(|id| self.policy(id))
                    .map(PolicyEval::title)
                    .collect::<Vec<_>>()
                    .join(", ");
                match kind {
                    NeedKind::Id => format!("needed: an entity id, for {who}"),
                    NeedKind::BlockedOnId => {
                        format!("blocked — first supply an entity id, for {who}")
                    }
                    NeedKind::Value => format!("needed: a value, for {who}"),
                    NeedKind::Parents => format!("needed: its parents, for {who}"),
                    NeedKind::Tags => format!("needed: its tags, for {who}"),
                }
            }
        }
    }

    /// e.g. `ALLOW is settled by permit «admin_override» — no further fact can change it`.
    pub fn describe_settled(&self) -> String {
        let Some(d) = self.decision else {
            return String::new();
        };
        let reasons: Vec<String> = self.reasons().iter().map(|p| p.title()).collect();
        if reasons.is_empty() {
            format!(
                "{} is settled — no permit can apply, so no further fact can change it",
                decision_str(d)
            )
        } else {
            format!(
                "{} is settled by {} — no further fact can change it",
                decision_str(d),
                reasons.join(", ")
            )
        }
    }
}

pub fn decision_str(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "ALLOW",
        Decision::Deny => "DENY",
    }
}

/// Partially evaluate all policies under `facts`, using Cedar's public TPE API.
pub fn evaluate(project: &Project, facts: &Facts) -> Result<Evaluation, String> {
    let schema = &project.schema;
    let mut warnings = Vec::new();
    let request = build_request(facts, schema)?;
    let entities = build_entities(facts, schema, &mut warnings)?;
    let response = project
        .policy_set
        .tpe(&request, &entities, schema)
        .map_err(|e| e.to_string())?;

    let ids = |it: &mut dyn Iterator<Item = &cedar_policy::PolicyId>| -> HashSet<String> {
        it.map(|id| id.to_string()).collect()
    };
    let true_ids = ids(&mut response.true_permits().chain(response.true_forbids()));
    let false_ids = ids(&mut response.false_permits().chain(response.false_forbids()));
    let error_ids = ids(&mut response.error_permits().chain(response.error_forbids()));

    let env = analysis::TypeEnv {
        schema: project.vschema(),
        action: &facts.action,
    };
    let mut policies = Vec::new();
    for info in &project.policies {
        let key = info.id.to_string();
        let (status, residual) = if true_ids.contains(&key) {
            (Status::True, literal(true))
        } else if false_ids.contains(&key) {
            (Status::False, literal(false))
        } else if error_ids.contains(&key) {
            (Status::Error, Arc::new(Expr::ResidualError))
        } else {
            let policy = response
                .get_policy(&cedar_policy::PolicyId::new(&key))
                .ok_or_else(|| format!("TPE returned no residual for «{key}»"))?;
            (Status::Residual, residual_condition(&policy)?)
        };
        // TPE can leave conditions whose outcome is already determined, like
        // `x && false`; read it off the condition's set of possible outcomes.
        let status = match status {
            Status::Residual => match analysis::conclude(&residual) {
                analysis::Conclusion::Applies => Status::True,
                analysis::Conclusion::CannotApply => Status::False,
                analysis::Conclusion::Unknown => Status::Residual,
            },
            s => s,
        };
        let needs = if status == Status::Residual {
            analysis::needs(&residual, env)
        } else {
            vec![]
        };
        policies.push(PolicyEval {
            id: info.id.clone(),
            effect: info.effect,
            status,
            residual,
            relevant: false,
            needs,
        });
    }

    // TPE's own decision, refined by the conditions found never to hold above.
    let tpe_decision = response.decision().map(|d| match d {
        cedar_policy::Decision::Allow => Decision::Allow,
        cedar_policy::Decision::Deny => Decision::Deny,
    });
    let decision = tpe_decision.or_else(|| decide(&policies));
    for p in &mut policies {
        p.relevant = match decision {
            Some(Decision::Deny) => p.effect == Effect::Forbid && p.status == Status::True,
            Some(Decision::Allow) => p.effect == Effect::Permit && p.status == Status::True,
            None => matches!(p.status, Status::Residual | Status::True),
        };
    }
    Ok(Evaluation {
        decision,
        policies,
        warnings,
    })
}

/// Cedar's decision rule, given each policy's status. `None` if a residual
/// policy could still change it.
fn decide(policies: &[PolicyEval]) -> Option<Decision> {
    let any = |e: Effect, s: Status| policies.iter().any(|p| p.effect == e && p.status == s);
    let permit_possible =
        any(Effect::Permit, Status::True) || any(Effect::Permit, Status::Residual);
    if any(Effect::Forbid, Status::True) || !permit_possible {
        Some(Decision::Deny)
    } else if any(Effect::Permit, Status::True) && !any(Effect::Forbid, Status::Residual) {
        Some(Decision::Allow)
    } else {
        None
    }
}

fn literal(b: bool) -> Arc<Expr> {
    Arc::new(Expr::Literal(pst::Literal::Bool(b)))
}

/// The condition of a residual policy (its single `when` clause).
fn residual_condition(policy: &cedar_policy::Policy) -> Result<Arc<Expr>, String> {
    let pst = policy.to_pst().map_err(|e| e.to_string())?;
    let mut when = pst.body().clauses().iter().filter_map(|c| match c {
        pst::Clause::When(e) => Some(e.clone()),
        pst::Clause::Unless(_) => None,
    });
    Ok(when.next().unwrap_or_else(|| literal(true)))
}

fn public_uid(u: &EntityUID) -> cedar_policy::EntityUid {
    u.clone().into()
}

fn build_request(
    facts: &Facts,
    schema: &cedar_policy::Schema,
) -> Result<cedar_policy::PartialRequest, String> {
    let partial = |u: &crate::facts::PartialUid| {
        cedar_policy::PartialEntityUid::new(
            u.ty.clone().into(),
            u.eid
                .as_ref()
                .map(|e| cedar_policy::EntityId::new(e.as_ref())),
        )
    };
    let action = public_uid(&facts.action);
    let context = cedar_policy::PartialContext::from_partial_record(
        to_partial_record(&facts.context),
        &action,
        schema,
    )
    .map_err(|e| e.to_string())?;
    cedar_policy::PartialRequest::new(
        partial(&facts.principal),
        action,
        partial(&facts.resource),
        context,
        schema,
    )
    .map_err(|e| e.to_string())
}

fn to_partial_attribute(f: &AttrFact) -> cedar_policy::PartialAttribute {
    use cedar_policy::PartialAttribute as A;
    match f {
        AttrFact::Value(v) => A::Value(cedar_policy::RestrictedExpression::from(
            cedar_policy_core::ast::RestrictedExpr::from(v.clone()),
        )),
        AttrFact::Unknown => A::Present,
        AttrFact::Absent => A::Absent,
        AttrFact::UnknownExistence => A::Unknown,
        AttrFact::Record(m) => A::Record(to_partial_record(m)),
    }
}

pub(crate) fn to_partial_record(m: &BTreeMap<SmolStr, AttrFact>) -> cedar_policy::PartialRecord {
    cedar_policy::PartialRecord::new(
        m.iter()
            .map(|(k, f)| (k.to_string(), to_partial_attribute(f))),
    )
}

fn build_entities(
    facts: &Facts,
    schema: &cedar_policy::Schema,
    warnings: &mut Vec<String>,
) -> Result<cedar_policy::PartialEntities, String> {
    // TPE requires that an entity used as a known ancestor has known
    // ancestors itself. Leave such entities out (treating them as fully
    // unknown) rather than failing.
    let mut excluded: BTreeSet<EntityUID> = BTreeSet::new();
    for ent in facts.entities.values() {
        for p in ent.parents.iter().flatten() {
            if let Some(pe) = facts.entities.get(p) {
                if pe.parents.is_none() {
                    excluded.insert(p.clone());
                }
            }
        }
    }
    for e in &excluded {
        warnings.push(format!(
            "{e} is used as a parent, so its own parents must be known; its facts are ignored"
        ));
    }
    let mut out = Vec::new();
    for (uid, ent) in &facts.entities {
        if excluded.contains(uid) {
            continue;
        }
        if schema.as_ref().get_entity_type(uid.entity_type()).is_none() {
            warnings.push(format!("{uid}: entity type not in schema"));
            continue;
        }
        match cedar_policy::PartialEntity::new(
            public_uid(uid),
            Some(to_partial_record(&ent.attrs)),
            ent.parents
                .as_ref()
                .map(|p| p.iter().map(public_uid).collect()),
            ent.tags.as_ref().map(to_partial_record),
            schema,
        ) {
            Ok(pe) => out.push(pe),
            Err(e) => warnings.push(format!("{uid}: {e}")),
        }
    }
    cedar_policy::PartialEntities::from_partial_entities(out, schema).map_err(|e| e.to_string())
}
