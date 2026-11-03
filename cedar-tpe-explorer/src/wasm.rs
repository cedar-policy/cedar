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

//! WASM bindings for the TPE explorer.
//!
//! Values cross the boundary as JSON strings. Facts are addressed by *slot
//! keys*: the JSON encoding of a [`SlotId`] (see [`slot_key`]), which stay
//! valid across edits.
//!
//! Suggestions take a JavaScript function `(script: string) => Promise<string>`
//! that runs one SMT-LIB script in CVC5 and resolves to its standard output.

use cedar_policy_core::ast::PolicyID;
use serde_json::{json, Value as Json};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen::prelude::*;

use crate::edit;
use crate::eval::decision_str;
use crate::model::{parse_slot_key, parse_state, slot_key};
use crate::suggest::{suggest_for_policy, suggest_for_slot, Effect};
use crate::symcc::{BatchSolver, SmtRunner, SymccModelFinder};
use crate::{Evaluation, Facts, Project, Session, Suggestion};

fn suggestion_json(id: u32, s: &Suggestion) -> Json {
    json!({
        "id": id,
        "assignments": s.assignments.iter().map(|a| a.describe()).collect::<Vec<_>>(),
        "slots": s.assignments.iter().map(|a| slot_key(&a.slot)).collect::<Vec<_>>(),
        "effects": s.effects.iter().map(Effect::describe).collect::<Vec<_>>(),
    })
}

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

/// Runs SMT-LIB scripts through a JavaScript function.
#[derive(Debug)]
struct JsRunner(send_wrapper::SendWrapper<js_sys::Function>);

impl SmtRunner for JsRunner {
    #[expect(clippy::future_not_send, reason = "JS promises are single-threaded")]
    async fn run(&mut self, script: String) -> Result<String, String> {
        let promise = self
            .0
            .call1(&JsValue::NULL, &JsValue::from_str(&script))
            .map_err(|e| format!("solver call failed: {e:?}"))?;
        let out = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&promise))
            .await
            .map_err(|e| {
                e.as_string()
                    .or_else(|| {
                        js_sys::Reflect::get(&e, &"message".into())
                            .ok()
                            .and_then(|m| m.as_string())
                    })
                    .unwrap_or_else(|| format!("solver failed: {e:?}"))
            })?;
        out.as_string()
            .ok_or_else(|| "solver did not return a string".to_string())
    }
}

#[derive(Debug)]
struct Inner {
    session: Session,
    /// Suggestions handed out, by id, with the facts they were computed for.
    suggestions: HashMap<u32, (Rc<Facts>, Suggestion)>,
    next_suggestion: u32,
}

/// An exploration session over one schema and policy set.
#[wasm_bindgen]
#[derive(Debug)]
pub struct Explorer {
    inner: Rc<RefCell<Inner>>,
}

#[wasm_bindgen]
impl Explorer {
    /// Load a schema (Cedar or JSON syntax) and policies, with nothing known
    /// about the request.
    #[wasm_bindgen(constructor)]
    pub fn new(schema: &str, policies: &str) -> Result<Explorer, JsError> {
        let project = Project::new(schema, policies).map_err(err)?;
        let facts = Facts::initial(&project).map_err(err)?;
        Ok(Explorer {
            inner: Rc::new(RefCell::new(Inner {
                session: Session::new(project, facts),
                suggestions: Default::default(),
                next_suggestion: 0,
            })),
        })
    }

    /// Replace the policies, keeping the schema and every known fact.
    pub fn set_policies(&self, policies: &str) -> Result<(), JsError> {
        let mut inner = self.inner.borrow_mut();
        let project = Project::new(&inner.session.project.schema_src, policies).map_err(err)?;
        let facts = inner.session.facts.clone();
        inner.session = Session::new(project, facts);
        inner.suggestions.clear();
        Ok(())
    }

    /// The structured model for graphical front ends; see
    /// `crate::model` for its shape.
    pub fn model(&self) -> String {
        let inner = self.inner.borrow();
        let s = &inner.session;
        let mut m = crate::model::model_json(&s.project, &s.facts, s.eval.as_ref());
        if let Some(o) = m.as_object_mut() {
            o.insert("canUndo".into(), s.can_undo().into());
            o.insert("canRedo".into(), s.can_redo().into());
        }
        m.to_string()
    }

    /// Change the principal's or resource's entity type, keeping its id
    /// (if any). `key` must be the principal or resource slot.
    pub fn set_entity_type(&self, key: &str, entity_type: &str) -> Result<(), JsError> {
        let mut inner = self.inner.borrow_mut();
        let slot = parse_slot_key(key).map_err(err)?;
        let s = &mut inner.session;
        let ty: cedar_policy_core::ast::EntityType = entity_type.parse().map_err(err)?;
        let cur = match slot {
            crate::SlotId::Principal => &s.facts.principal,
            crate::SlotId::Resource => &s.facts.resource,
            _ => {
                return Err(err(
                    "only the principal and resource have a selectable type",
                ))
            }
        };
        let action = s
            .project
            .vschema()
            .get_action_id(&s.facts.action)
            .ok_or_else(|| err("unknown action"))?;
        let ok = match slot {
            crate::SlotId::Principal => action.applies_to_principals().any(|t| *t == ty),
            _ => action.applies_to_resources().any(|t| *t == ty),
        };
        if !ok {
            return Err(err(format!("{} does not apply to {ty}", s.facts.action)));
        }
        let next = crate::PartialUid {
            ty,
            eid: cur.eid.clone(),
        };
        s.set(&slot, crate::SlotValue::Uid(next)).map_err(err)
    }

    /// Forget all facts (undoable).
    pub fn reset(&self) -> Result<(), JsError> {
        let mut inner = self.inner.borrow_mut();
        let facts = Facts::initial(&inner.session.project).map_err(err)?;
        inner.session.replace_facts(facts);
        Ok(())
    }

    /// Parse typed input for a slot and set it.
    pub fn set_input(&self, key: &str, text: &str) -> Result<(), JsError> {
        let mut inner = self.inner.borrow_mut();
        let slot = parse_slot_key(key).map_err(err)?;
        let s = &mut inner.session;
        let v = edit::parse_input(&s.project, &s.facts, &slot, text).map_err(err)?;
        s.set(&slot, v).map_err(err)
    }

    /// Put a slot into `present`, `absent`, or `unknown`.
    pub fn set_state(&self, key: &str, state: &str) -> Result<(), JsError> {
        let mut inner = self.inner.borrow_mut();
        let slot = parse_slot_key(key).map_err(err)?;
        let st = parse_state(state).map_err(err)?;
        let s = &mut inner.session;
        let v = edit::state_value(&s.project, &s.facts, &slot, st).map_err(err)?;
        s.set(&slot, v).map_err(err)
    }

    pub fn undo(&self) -> bool {
        self.inner.borrow_mut().session.undo()
    }

    pub fn redo(&self) -> bool {
        self.inner.borrow_mut().session.redo()
    }

    /// Minimal known facts that force the current decision (no solver).
    pub fn explain(&self) -> Result<String, JsError> {
        let inner = self.inner.borrow();
        let s = &inner.session;
        Ok(match crate::explain::explain(&s.project, &s.facts).map_err(err)? {
            None => json!({ "decision": null }),
            Some(ex) => json!({
                "decision": decision_str(ex.decision),
                "reasons": ex.evaluation.reasons().iter().map(|p| p.title()).collect::<Vec<_>>(),
                "facts": ex.facts.iter().map(|a| a.describe()).collect::<Vec<_>>(),
                "known": s.facts.known_slots(s.project.vschema()).len(),
            }),
        }
        .to_string())
    }

    /// Values for one slot that change something on their own. Resolves to a
    /// JSON array of `{ id, assignments, slots, effects }`.
    #[expect(clippy::future_not_send, reason = "JS promises are single-threaded")]
    pub async fn suggest_slot(
        &self,
        key: String,
        solver: js_sys::Function,
    ) -> Result<String, JsError> {
        let slot = parse_slot_key(&key).map_err(err)?;
        let (project, facts, eval) = self.snapshot()?;
        let items = suggest_for_slot(&project, &facts, &eval, &slot, &mut finder(solver)?)
            .await
            .map_err(err)?;
        Ok(self.store(&facts, items))
    }

    /// The fewest facts that settle policy `id` either way.
    #[expect(clippy::future_not_send, reason = "JS promises are single-threaded")]
    pub async fn suggest_policy(
        &self,
        id: String,
        solver: js_sys::Function,
    ) -> Result<String, JsError> {
        let id = PolicyID::from_string(id);
        let (project, facts, eval) = self.snapshot()?;
        let items = suggest_for_policy(&project, &facts, &eval, &id, &mut finder(solver)?)
            .await
            .map_err(err)?;
        Ok(self.store(&facts, items))
    }

    /// Apply a suggestion by the `id` it was returned with. Fails if the
    /// facts changed since it was computed. Returns its first effect.
    pub fn apply_suggestion(&self, id: u32) -> Result<String, JsError> {
        let mut inner = self.inner.borrow_mut();
        let (facts, sug) = inner
            .suggestions
            .get(&id)
            .cloned()
            .ok_or_else(|| err("no such suggestion"))?;
        if *facts != inner.session.facts {
            return Err(err("the facts changed since this was suggested; ask again"));
        }
        inner.session.apply(&sug.assignments).map_err(err)?;
        inner.suggestions.clear();
        Ok(sug
            .effects
            .first()
            .map(Effect::describe)
            .unwrap_or_default())
    }
}

fn finder(solver: js_sys::Function) -> Result<SymccModelFinder<BatchSolver<JsRunner>>, JsError> {
    let runner = JsRunner(send_wrapper::SendWrapper::new(solver));
    SymccModelFinder::with_solver(BatchSolver::new(runner)).map_err(err)
}

impl Explorer {
    /// A copy of the session state, so no borrow is held across awaits.
    fn snapshot(&self) -> Result<(Project, Facts, Evaluation), JsError> {
        let inner = self.inner.borrow();
        let s = &inner.session;
        let eval = s.eval.clone().map_err(err)?;
        Ok((s.project.clone(), s.facts.clone(), eval))
    }

    /// Remember suggestions computed for `facts`; returns them as JSON.
    fn store(&self, facts: &Facts, items: Vec<Suggestion>) -> String {
        let mut inner = self.inner.borrow_mut();
        // Suggestions for other facts can no longer be applied.
        inner.suggestions.retain(|_, (f, _)| **f == *facts);
        let facts = Rc::new(facts.clone());
        let mut out = Vec::new();
        for sug in items {
            let id = inner.next_suggestion;
            inner.next_suggestion = id.wrapping_add(1);
            out.push(suggestion_json(id, &sug));
            inner.suggestions.insert(id, (Rc::clone(&facts), sug));
        }
        Json::Array(out).to_string()
    }
}
