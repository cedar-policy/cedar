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

//! Front-end agnostic engine for exploring Cedar type-aware partial evaluation.
//!
//! The crate is deliberately free of terminal, filesystem, and process IO so
//! that it can be compiled to WASM. Front ends (the TUI, a future web app, or a
//! CI tool) drive it by:
//!
//! 1. loading a [`Project`] (schema + policies) from source strings,
//! 2. building up partial [`Facts`] about a request,
//! 3. calling [`evaluate`] to get residual policies and what each still needs,
//! 4. optionally asking the [`suggest`] engine (backed by a [`ModelFinder`],
//!    e.g. SymCC + CVC5) for small sets of facts that would settle a policy,
//! 5. rendering [`doc`] lines, which carry semantic styles rather than colors.

pub mod analysis;
pub mod doc;
pub mod edit;
pub mod eval;
pub mod explain;
pub mod facts;
pub mod model;
pub mod project;
pub mod session;
pub mod suggest;
pub mod symcc;
pub mod values;
#[cfg(feature = "wasm")]
pub mod wasm;

pub use eval::{evaluate, Evaluation, PolicyEval, Status};
pub use facts::{AttrFact, EntityFacts, Facts, PartialUid, SlotId, SlotValue};
pub use project::{PolicyInfo, Project, ProjectError};
pub use session::Session;
pub use suggest::{Assignment, Effect, Model, ModelFinder, Suggestion};
