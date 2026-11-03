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

//! Suggesting small sets of facts that settle a policy.
//!
//! A [`ModelFinder`] (e.g. SymCC + CVC5) finds one concrete request in which
//! a residual policy is (or isn't) satisfied. We map that model onto the
//! unknown facts, then drop facts greedily while TPE still reaches the same
//! outcome. TPE is (nearly, see `eval::build_entities`) monotone in the facts,
//! so one greedy pass leaves a set none of whose facts can be removed.

mod minimize;
mod models;
mod query;

use cedar_policy_core::ast::{EntityUID, PolicyID};
use cedar_policy_core::authorizer::Decision;
use cedar_policy_core::validator::types::Type;
use smol_str::SmolStr;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use crate::eval::{decision_str, evaluate, Evaluation, SlotNeed, Status};
use crate::facts::{describe_assignment, AttrFact, Facts, SlotId, SlotValue};
use crate::project::Project;

pub use minimize::minimize;

/// A concrete request and entity store, e.g. a solver model.
#[derive(Debug, Clone)]
pub struct Model {
    pub request: cedar_policy::Request,
    pub entities: cedar_policy::Entities,
}

/// Finds concrete inputs for which a policy matches. Async so that it can
/// call out to a solver process, a web worker, or a service.
pub trait ModelFinder {
    fn find_model(
        &mut self,
        project: &Project,
        policy: &cedar_policy::Policy,
        env: &cedar_policy::RequestEnv,
    ) -> impl Future<Output = Result<Option<Model>, String>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub slot: SlotId,
    pub value: SlotValue,
}

impl Assignment {
    pub fn describe(&self) -> String {
        describe_assignment(&self.slot, &self.value)
    }
}

/// A consequence of applying a suggestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Decides(Decision),
    Applies(PolicyID),
    Irrelevant(PolicyID),
}

impl Effect {
    pub fn describe(&self) -> String {
        match self {
            Self::Decides(d) => format!("decides the request: {}", decision_str(*d)),
            Self::Applies(id) => format!("«{id}» applies"),
            Self::Irrelevant(id) => format!("«{id}» becomes irrelevant"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Suggestion {
    pub assignments: Vec<Assignment>,
    pub effects: Vec<Effect>,
}

/// `facts` with `asg` applied.
pub fn apply(project: &Project, facts: &Facts, asg: &[Assignment]) -> Result<Facts, String> {
    let mut f = facts.clone();
    for a in asg {
        f.set(&a.slot, a.value.clone(), project.vschema())?;
    }
    Ok(f)
}

/// Does `pred` hold once `asg` is applied?
fn holds(
    project: &Project,
    facts: &Facts,
    asg: &[Assignment],
    pred: impl Fn(&Evaluation) -> bool,
) -> bool {
    apply(project, facts, asg)
        .and_then(|f| evaluate(project, &f))
        .is_ok_and(|e| pred(&e))
}

/// What changes between `before` and `after`, with `target` first.
fn effects(before: &Evaluation, after: &Evaluation, target: Option<&PolicyID>) -> Vec<Effect> {
    let change = |id: &PolicyID| -> Option<Effect> {
        let (b, a) = (before.policy(id)?, after.policy(id)?);
        if b.status != Status::Residual || !b.relevant {
            None
        } else if a.status == Status::True {
            Some(Effect::Applies(id.clone()))
        } else if !a.relevant {
            Some(Effect::Irrelevant(id.clone()))
        } else {
            None
        }
    };
    let mut out: Vec<Effect> = target.and_then(change).into_iter().collect();
    if let (None, Some(d)) = (before.decision, after.decision) {
        out.push(Effect::Decides(d));
    }
    let (applies, irrelevant): (Vec<_>, Vec<_>) = before
        .policies
        .iter()
        .filter(|p| Some(&p.id) != target)
        .filter_map(|p| change(&p.id))
        .partition(|e| matches!(e, Effect::Applies(_)));
    out.extend(applies);
    out.extend(irrelevant);
    out
}

/// Whether policy `id` evaluates to `satisfied` (errors count as not).
fn settled(id: &PolicyID, satisfied: bool, e: &Evaluation) -> bool {
    match e.policy(id).map(|p| p.status) {
        Some(Status::True) => satisfied,
        Some(Status::False | Status::Error) => !satisfied,
        _ => false,
    }
}

/// The fewest facts that settle policy `id`, one way and the other.
pub async fn suggest_for_policy<F: ModelFinder>(
    project: &Project,
    facts: &Facts,
    eval: &Evaluation,
    id: &PolicyID,
    finder: &mut F,
) -> Result<Vec<Suggestion>, String> {
    let p = eval.policy(id).ok_or_else(|| format!("no policy «{id}»"))?;
    if p.status != Status::Residual {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    let mut failure = None;
    for satisfied in [true, false] {
        match settle(project, facts, eval, id, satisfied, finder).await {
            Ok(Some(min)) => {
                let after = evaluate(project, &apply(project, facts, &min)?)?;
                out.push(Suggestion {
                    effects: effects(eval, &after, Some(id)),
                    assignments: min,
                });
            }
            Ok(None) => {}
            Err(e) => failure = failure.or(Some(e)),
        }
    }
    found_or(out, failure)
}

/// The suggestions found, or the first error if there are none.
fn found_or(out: Vec<Suggestion>, failure: Option<String>) -> Result<Vec<Suggestion>, String> {
    match failure {
        Some(e) if out.is_empty() => Err(e),
        _ => Ok(out),
    }
}

/// How many solver models to try per outcome.
const ATTEMPTS: usize = 4;

/// Minimized facts under which policy `id` is `satisfied`, if any. The
/// solver doesn't see facts about entities the residual doesn't mention, so
/// it may pick a known principal or resource whose facts rule the model out;
/// then we exclude that entity and ask again.
async fn settle<F: ModelFinder>(
    project: &Project,
    facts: &Facts,
    eval: &Evaluation,
    id: &PolicyID,
    satisfied: bool,
    finder: &mut F,
) -> Result<Option<Vec<Assignment>>, String> {
    let env = query::request_env(facts);
    let pred = |e: &Evaluation| settled(id, satisfied, e);
    let mut exclude: Vec<EntityUID> = Vec::new();
    for _ in 0..ATTEMPTS {
        let policy = query::outcome_policy(project, facts, eval, id, satisfied, &exclude)?;
        let Some(model) = finder.find_model(project, &policy, &env).await? else {
            return Ok(None);
        };
        let asg = models::model_assignments(project, facts, eval, &model);
        if let Some(min) = minimize::minimize_readable(project, facts, asg, pred) {
            return Ok(Some(min));
        }
        let req: &cedar_policy_core::ast::Request = model.request.as_ref();
        let known: Vec<EntityUID> = [req.principal().uid(), req.resource().uid()]
            .into_iter()
            .flatten()
            .filter(|u| facts.entities.contains_key(u) && !exclude.contains(u))
            .cloned()
            .collect();
        if known.is_empty() {
            return Ok(None);
        }
        exclude.extend(known);
    }
    Ok(None)
}

/// Values for one slot that, on their own, change something.
pub async fn suggest_for_slot<F: ModelFinder>(
    project: &Project,
    facts: &Facts,
    eval: &Evaluation,
    slot: &SlotId,
    finder: &mut F,
) -> Result<Vec<Suggestion>, String> {
    let schema = project.vschema();
    let mut candidates: Vec<SlotValue> = Vec::new();
    let mut push = |v: SlotValue| {
        if !candidates.contains(&v) {
            candidates.push(v);
        }
    };
    // Values from models that satisfy or falsify each policy needing the slot.
    // A failed query (e.g. a timeout) only loses its own candidates.
    let mut failure = None;
    if let SlotNeed::Needed(_, ids) = eval.slot_need(slot) {
        let env = query::request_env(facts);
        for id in ids {
            for satisfied in [true, false] {
                let model = match query::outcome_policy(project, facts, eval, &id, satisfied, &[]) {
                    Ok(policy) => finder.find_model(project, &policy, &env).await,
                    Err(e) => Err(e),
                };
                match model {
                    Ok(Some(model)) => {
                        let asg = models::model_assignments(project, facts, eval, &model);
                        if let Some(v) = value_for_slot(slot, &asg) {
                            push(v);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => failure = failure.or(Some(e)),
                }
            }
        }
    }
    // Values that need no solver.
    match slot {
        SlotId::Context(_) | SlotId::Attr(_, _) => {
            if let Some(Type::Bool(_)) = facts.slot_type(slot, schema) {
                push(SlotValue::Attr(AttrFact::Value(true.into())));
                push(SlotValue::Attr(AttrFact::Value(false.into())));
            }
            if !facts.slot_required(slot, schema) {
                push(SlotValue::Attr(AttrFact::Absent));
            }
        }
        SlotId::Parents(_) => push(SlotValue::Parents(Some(BTreeSet::new()))),
        _ => {}
    }

    let current = facts.get_or_unknown(slot, schema);
    let mut out: Vec<Suggestion> = Vec::new();
    for value in candidates {
        if Some(&value) == current.as_ref() {
            continue;
        }
        let mut asg = vec![Assignment {
            slot: slot.clone(),
            value,
        }];
        let Ok(after) = apply(project, facts, &asg).and_then(|f| evaluate(project, &f)) else {
            continue;
        };
        let eff = effects(eval, &after, None);
        if eff.is_empty() {
            continue;
        }
        // Prefer a readable value with the same effects.
        let same = |a: &[Assignment]| holds(project, facts, a, |e| effects(eval, e, None) == eff);
        minimize::readable_names(project, facts, &mut asg, &same);
        if !out.iter().any(|s| s.assignments == asg) {
            out.push(Suggestion {
                assignments: asg,
                effects: eff,
            });
        }
    }
    out.sort_by_key(|s| {
        (
            !s.effects.iter().any(|e| matches!(e, Effect::Decides(_))),
            std::cmp::Reverse(s.effects.len()),
        )
    });
    found_or(out, failure)
}

/// The value `asg` gives `slot`, collecting individual tags for a tags slot.
fn value_for_slot(slot: &SlotId, asg: &[Assignment]) -> Option<SlotValue> {
    if let SlotId::Tags(e) = slot {
        let tags: BTreeMap<SmolStr, AttrFact> = asg
            .iter()
            .filter_map(|a| match (&a.slot, &a.value) {
                (SlotId::Tag(e2, k), SlotValue::Tag(Some(f))) if e2 == e => {
                    Some((k.clone(), f.clone()))
                }
                _ => None,
            })
            .collect();
        return Some(SlotValue::Tags(Some(tags)));
    }
    asg.iter()
        .find(|a| &a.slot == slot)
        .map(|a| a.value.clone())
}
