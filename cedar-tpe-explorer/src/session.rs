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

//! An editing session: facts plus their evaluation, with undo and redo.

use crate::eval::{evaluate, Evaluation};
use crate::facts::{Facts, SlotId, SlotValue};
use crate::project::Project;
use crate::suggest::Assignment;

#[derive(Debug)]
pub struct Session {
    pub project: Project,
    pub facts: Facts,
    /// The evaluation of `facts`, or the error that prevented it.
    pub eval: Result<Evaluation, String>,
    undo: Vec<Facts>,
    redo: Vec<Facts>,
}

impl Session {
    pub fn new(project: Project, facts: Facts) -> Self {
        let mut s = Self {
            project,
            facts,
            eval: Err("not evaluated".into()),
            undo: Vec::new(),
            redo: Vec::new(),
        };
        s.refresh();
        s
    }

    /// Re-evaluate, adding entities that residuals reference and dropping
    /// entities that are neither known nor referenced.
    pub fn refresh(&mut self) {
        let schema = self.project.vschema();
        self.eval = evaluate(&self.project, &self.facts);
        if let Ok(e) = &self.eval {
            let referenced = e.referenced_entities();
            let before = self.facts.clone();
            for uid in &referenced {
                self.facts.ensure_entity(uid, schema);
            }
            self.facts.prune(&referenced, schema);
            if self.facts != before {
                // Adding or dropping fully-unknown entities doesn't change the
                // outcome, but re-evaluate so `eval` matches `facts` exactly.
                self.eval = evaluate(&self.project, &self.facts);
            }
        }
    }

    /// Set one slot, recording an undo point.
    pub fn set(&mut self, slot: &SlotId, value: SlotValue) -> Result<(), String> {
        let mut next = self.facts.clone();
        next.set(slot, value, self.project.vschema())?;
        self.commit(next);
        Ok(())
    }

    /// Apply several assignments as one undoable step.
    pub fn apply(&mut self, asg: &[Assignment]) -> Result<(), String> {
        let next = crate::suggest::apply(&self.project, &self.facts, asg)?;
        self.commit(next);
        Ok(())
    }

    /// Replace the facts wholesale (e.g. after loading a file).
    pub fn replace_facts(&mut self, facts: Facts) {
        self.commit(facts);
    }

    fn commit(&mut self, next: Facts) {
        if next != self.facts {
            self.undo.push(std::mem::replace(&mut self.facts, next));
            // A new edit starts a new branch of history.
            self.redo.clear();
        }
        self.refresh();
    }

    pub fn can_undo(&self) -> bool {
        !self.undo.is_empty()
    }

    pub fn undo(&mut self) -> bool {
        match self.undo.pop() {
            Some(f) => {
                self.redo.push(std::mem::replace(&mut self.facts, f));
                self.refresh();
                true
            }
            None => false,
        }
    }

    pub fn can_redo(&self) -> bool {
        !self.redo.is_empty()
    }

    /// Re-apply the most recently undone step.
    pub fn redo(&mut self) -> bool {
        match self.redo.pop() {
            Some(f) => {
                self.undo.push(std::mem::replace(&mut self.facts, f));
                self.refresh();
                true
            }
            None => false,
        }
    }
}
