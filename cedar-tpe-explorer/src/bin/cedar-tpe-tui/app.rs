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

//! Application state and input handling.

use std::io;

use cedar_policy_core::ast::PolicyID;
use cedar_tpe_explorer::doc::render_facts;
use cedar_tpe_explorer::edit::{self, EditState};
use cedar_tpe_explorer::suggest::{suggest_for_policy, suggest_for_slot, Effect};
use cedar_tpe_explorer::symcc::{LocalModelFinder, SymccModelFinder};
use cedar_tpe_explorer::{Facts, Session, SlotId, Suggestion};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;

use crate::files::{load_project, Paths};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Facts,
    Residuals,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Residuals,
    Policies,
    Schema,
}

impl Tab {
    pub const ALL: [Tab; 3] = [Tab::Residuals, Tab::Policies, Tab::Schema];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Residuals => "Residuals",
            Tab::Policies => "Policies",
            Tab::Schema => "Schema",
        }
    }
}

pub struct EditMode {
    pub slot: SlotId,
    pub state: EditState,
    pub allowed: Vec<EditState>,
    pub buf: String,
    /// The buffer holds the pre-filled current value; typing replaces it.
    pub fresh: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub enum SuggestTarget {
    Slot(SlotId),
    Policy(PolicyID),
}

pub struct SuggestMode {
    pub target: SuggestTarget,
    pub items: Vec<Suggestion>,
    pub sel: usize,
    /// Shown instead of items while solving, or when there are none.
    pub message: Option<String>,
}

pub enum Mode {
    Normal,
    Edit(EditMode),
    Suggest(SuggestMode),
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashKind {
    Info,
    Error,
}

pub struct Flash {
    pub text: String,
    pub kind: FlashKind,
}

/// Work that must happen outside of key handling (it needs to redraw first).
enum Job {
    Redraw,
    Suggest,
}

pub struct App {
    pub session: Session,
    finder: Option<Result<LocalModelFinder, String>>,
    solver_timeout_ms: u32,
    rt: tokio::runtime::Runtime,
    pub focus: Focus,
    pub tab: Tab,
    pub sel_slot: Option<SlotId>,
    pub sel_policy: Option<PolicyID>,
    pub mode: Mode,
    pub flash: Option<Flash>,
    /// Slots changed by the last action, highlighted until the next one.
    pub changed: Vec<SlotId>,
    pub facts_scroll: usize,
    pub right_scroll: usize,
    job: Option<Job>,
    quit: bool,
}

impl App {
    pub fn load(paths: &Paths, solver_timeout_ms: u32) -> Result<Self, String> {
        let project = load_project(paths)?;
        let facts = Facts::initial(&project)?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let mut app = Self {
            session: Session::new(project, facts),
            finder: None,
            solver_timeout_ms,
            rt,
            focus: Focus::Facts,
            tab: Tab::Residuals,
            sel_slot: Some(SlotId::Principal),
            sel_policy: None,
            mode: Mode::Normal,
            flash: None,
            changed: vec![],
            facts_scroll: 0,
            right_scroll: 0,
            job: None,
            quit: false,
        };
        app.sel_policy = app.policy_order().into_iter().next();
        Ok(app)
    }

    pub fn run(mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        while !self.quit {
            terminal.draw(|f| crate::ui::draw(f, &mut self))?;
            if let Some(job) = self.job.take() {
                match job {
                    Job::Redraw => terminal.clear()?,
                    Job::Suggest => self.compute_suggestions(),
                }
                continue;
            }
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    self.on_key(k);
                }
            }
        }
        Ok(())
    }

    fn info(&mut self, text: impl Into<String>) {
        self.flash = Some(Flash {
            text: text.into(),
            kind: FlashKind::Info,
        });
    }

    fn error(&mut self, text: impl Into<String>) {
        self.flash = Some(Flash {
            text: text.into(),
            kind: FlashKind::Error,
        });
    }

    /// Selectable fact slots, in display order.
    pub fn slot_order(&self) -> Vec<SlotId> {
        let eval = self.session.eval.as_ref().ok();
        let mut out: Vec<SlotId> = Vec::new();
        for l in render_facts(&self.session.project, &self.session.facts, eval) {
            for s in l.spans.iter().filter_map(|s| s.slot.as_ref()) {
                if !out.contains(s) {
                    out.push(s.clone());
                }
            }
        }
        out
    }

    /// Policies in the order the residuals pane shows them.
    pub fn policy_order(&self) -> Vec<PolicyID> {
        match &self.session.eval {
            Ok(e) => {
                let (rel, irr): (Vec<_>, Vec<_>) = e.policies.iter().partition(|p| p.relevant);
                rel.into_iter().chain(irr).map(|p| p.id.clone()).collect()
            }
            Err(_) => vec![],
        }
    }

    fn fix_selection(&mut self) {
        let order = self.slot_order();
        if !self.sel_slot.as_ref().is_some_and(|s| order.contains(s)) {
            self.sel_slot = order.first().cloned();
        }
        let porder = self.policy_order();
        if !self.sel_policy.as_ref().is_some_and(|p| porder.contains(p)) {
            self.sel_policy = porder.first().cloned();
        }
    }

    fn move_sel(&mut self, delta: isize) {
        match self.focus {
            Focus::Facts => {
                let order = self.slot_order();
                self.sel_slot = step(&order, self.sel_slot.as_ref(), delta);
            }
            Focus::Residuals => match self.tab {
                Tab::Residuals => {
                    let order = self.policy_order();
                    self.sel_policy = step(&order, self.sel_policy.as_ref(), delta);
                }
                _ => {
                    self.right_scroll = (self.right_scroll as isize + delta).max(0) as usize;
                }
            },
        }
    }

    /// After an edit, move to the next slot that a relevant policy needs.
    fn advance(&mut self) {
        let Ok(eval) = &self.session.eval else {
            return;
        };
        let order = self.slot_order();
        let start = self
            .sel_slot
            .as_ref()
            .and_then(|s| order.iter().position(|o| o == s))
            .map_or(0, |i| i + 1);
        if let Some(next) = order
            .get(start..)
            .unwrap_or_default()
            .iter()
            .find(|s| eval.is_needed(s))
        {
            self.sel_slot = Some(next.clone());
        }
    }

    fn on_key(&mut self, k: KeyEvent) {
        if k.modifiers.contains(KeyModifiers::CONTROL) {
            match k.code {
                KeyCode::Char('c') => self.quit = true,
                KeyCode::Char('l') => self.job = Some(Job::Redraw),
                KeyCode::Char('r') if matches!(self.mode, Mode::Normal) => {
                    self.on_key_normal(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
                    self.fix_selection();
                }
                KeyCode::Char('u') => {
                    if let Mode::Edit(e) = &mut self.mode {
                        e.buf.clear();
                    }
                }
                _ => {}
            }
            return;
        }
        match std::mem::replace(&mut self.mode, Mode::Normal) {
            Mode::Normal => self.on_key_normal(k),
            Mode::Help => {}
            Mode::Edit(e) => self.on_key_edit(k, e),
            Mode::Suggest(s) => self.on_key_suggest(k, s),
        }
        self.fix_selection();
    }

    fn on_key_normal(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') => self.mode = Mode::Help,
            KeyCode::Left
            | KeyCode::Right
            | KeyCode::Char('h')
            | KeyCode::Char('l')
            | KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Facts => Focus::Residuals,
                    Focus::Residuals => Focus::Facts,
                };
                if self.focus == Focus::Residuals {
                    self.tab = Tab::Residuals;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_sel(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_sel(1),
            KeyCode::PageUp => self.move_sel(-10),
            KeyCode::PageDown => self.move_sel(10),
            KeyCode::Char('v') => {
                self.tab = cycle(&Tab::ALL, self.tab, true);
                self.right_scroll = 0;
            }
            KeyCode::Char('u') => {
                if self.session.undo() {
                    self.changed.clear();
                    self.info("undo");
                } else {
                    self.error("nothing to undo");
                }
            }
            KeyCode::Char('r') => {
                if self.session.redo() {
                    self.changed.clear();
                    self.info("redo");
                } else {
                    self.error("nothing to redo");
                }
            }
            KeyCode::Esc => {
                self.flash = None;
                self.changed.clear();
            }
            KeyCode::Enter | KeyCode::Char('s') => match self.focus {
                Focus::Facts if k.code == KeyCode::Enter => self.begin_edit(EditState::Value),
                Focus::Facts => {
                    if let Some(slot) = self.sel_slot.clone() {
                        self.begin_suggest(SuggestTarget::Slot(slot));
                    }
                }
                Focus::Residuals => {
                    if let Some(id) = self.sel_policy.clone() {
                        self.begin_suggest(SuggestTarget::Policy(id));
                    }
                }
            },
            KeyCode::Char(c @ '1'..='4') if self.focus == Focus::Facts => {
                let state = match c {
                    '1' => EditState::Value,
                    '2' => EditState::Present,
                    '3' => EditState::Absent,
                    _ => EditState::Unknown,
                };
                if state == EditState::Value {
                    self.begin_edit(state);
                } else {
                    self.set_state(state);
                }
            }
            _ => {}
        }
    }

    fn begin_edit(&mut self, state: EditState) {
        let Some(slot) = self.sel_slot.clone() else {
            return;
        };
        let s = &self.session;
        let allowed = edit::allowed_states(&s.project, &s.facts, &slot);
        let buf = edit::current_text(&s.project, &s.facts, &slot);
        self.mode = Mode::Edit(EditMode {
            slot,
            state,
            allowed,
            fresh: !buf.is_empty(),
            buf,
            error: None,
        });
    }

    fn set_state(&mut self, state: EditState) {
        let Some(slot) = self.sel_slot.clone() else {
            return;
        };
        let s = &self.session;
        match edit::state_value(&s.project, &s.facts, &slot, state)
            .and_then(|v| self.session.set(&slot, v))
        {
            Ok(()) => {
                self.changed.clear();
                self.flash = None;
            }
            Err(e) => self.error(e),
        }
    }

    fn on_key_edit(&mut self, k: KeyEvent, mut e: EditMode) {
        match k.code {
            KeyCode::Esc => return,
            KeyCode::Enter => {
                let s = &self.session;
                let value = if e.state == EditState::Value {
                    edit::parse_input(&s.project, &s.facts, &e.slot, &e.buf)
                } else {
                    edit::state_value(&s.project, &s.facts, &e.slot, e.state)
                };
                match value.and_then(|v| self.session.set(&e.slot, v)) {
                    Ok(()) => {
                        self.changed.clear();
                        self.flash = None;
                        self.advance();
                        return;
                    }
                    Err(err) => e.error = Some(err),
                }
            }
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down => {
                let forward = matches!(k.code, KeyCode::Tab | KeyCode::Down);
                e.state = cycle(&e.allowed, e.state, forward);
                e.error = None;
            }
            KeyCode::Backspace => {
                e.buf.pop();
                e.fresh = false;
                e.error = None;
            }
            KeyCode::Left | KeyCode::Right | KeyCode::End => e.fresh = false,
            KeyCode::Char(c) => {
                if e.fresh {
                    e.buf.clear();
                    e.fresh = false;
                }
                e.buf.push(c);
                e.state = EditState::Value;
                e.error = None;
            }
            _ => {}
        }
        self.mode = Mode::Edit(e);
    }

    fn on_key_suggest(&mut self, k: KeyEvent, mut s: SuggestMode) {
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') => return,
            KeyCode::Up | KeyCode::Char('k') => s.sel = s.sel.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                s.sel = (s.sel + 1).min(s.items.len().saturating_sub(1))
            }
            KeyCode::Enter => {
                if let Some(sug) = s.items.get(s.sel) {
                    match self.session.apply(&sug.assignments) {
                        Ok(()) => {
                            self.changed = sug.assignments.iter().map(|a| a.slot.clone()).collect();
                            let first = sug
                                .effects
                                .first()
                                .map(Effect::describe)
                                .unwrap_or_default();
                            self.info(format!("applied: {first}"));
                        }
                        Err(e) => self.error(e),
                    }
                    return;
                }
            }
            _ => {}
        }
        self.mode = Mode::Suggest(s);
    }

    fn begin_suggest(&mut self, target: SuggestTarget) {
        self.mode = Mode::Suggest(SuggestMode {
            target,
            items: vec![],
            sel: 0,
            message: Some("solving with SymCC + CVC5…".into()),
        });
        self.job = Some(Job::Suggest);
    }

    fn compute_suggestions(&mut self) {
        let Mode::Suggest(s) = &mut self.mode else {
            return;
        };
        // The solver process must be spawned inside the runtime.
        let _rt = self.rt.enter();
        let finder = self
            .finder
            .get_or_insert_with(|| SymccModelFinder::new(self.solver_timeout_ms));
        let finder = match finder {
            Ok(f) => f,
            Err(e) => {
                s.message = Some(e.clone());
                self.finder = None;
                return;
            }
        };
        let Ok(eval) = &self.session.eval else {
            s.message = Some("cannot suggest while evaluation fails".into());
            return;
        };
        let (project, facts) = (&self.session.project, &self.session.facts);
        let result = self.rt.block_on(async {
            match &s.target {
                SuggestTarget::Slot(slot) => {
                    suggest_for_slot(project, facts, eval, slot, finder).await
                }
                SuggestTarget::Policy(id) => {
                    suggest_for_policy(project, facts, eval, id, finder).await
                }
            }
        });
        match result {
            Ok(items) if items.is_empty() => {
                s.message = Some(match &s.target {
                    SuggestTarget::Slot(_) => "no value for this field changes anything on its own — try settling a policy from the residuals pane".into(),
                    SuggestTarget::Policy(_) => "this policy is already settled, or no assignment could be found".into(),
                });
            }
            Ok(items) => {
                s.items = items;
                s.message = None;
            }
            Err(e) => {
                s.message = Some(e);
                // The solver process may be unusable after an error.
                self.finder = None;
            }
        }
    }
}

fn step<T: Clone + PartialEq>(order: &[T], cur: Option<&T>, delta: isize) -> Option<T> {
    let i = cur
        .and_then(|c| order.iter().position(|o| o == c))
        .unwrap_or(0);
    order
        .get(i.saturating_add_signed(delta))
        .or_else(|| order.last())
        .cloned()
}

/// The item after (or before) `cur`, wrapping around; `cur` if not found.
fn cycle<T: Copy + PartialEq>(items: &[T], cur: T, forward: bool) -> T {
    let n = items.len();
    let i = items.iter().position(|x| *x == cur).unwrap_or(0);
    let j = if forward {
        i + 1
    } else {
        i + n.saturating_sub(1)
    };
    j.checked_rem(n)
        .and_then(|j| items.get(j))
        .copied()
        .unwrap_or(cur)
}
