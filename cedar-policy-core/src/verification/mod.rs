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

//! Verus proofs that production Cedar agrees with the model in
//! `cedar-rust-model` (`verus` feature only, for `cargo verus verify`).
//! The proof obligations are the `verus_spec` annotations on production code.
//!
//! * `trusted`, `ext_trusted`, `authorizer_lean_theorems`: the assumptions
//!   (`cedar-rust-model/TRUSTED.md`).
//! * `*_abs`: abstraction functions from production types to model types.
//! * `authorizer_theorems`: the Lean authorization theorems, proved about production.
#![allow(unsafe_code, missing_docs, unused_imports, elided_lifetimes_in_paths, clippy::all)]

use vstd::prelude::*;

#[path = "../../../../cedar-rust-model/src/lib.rs"]
pub mod model;

pub mod abs;
pub mod authorizer_lemmas;
pub mod conversions;
pub mod expr_abs;
pub mod ext_abs;
pub mod ext_lemmas;
pub mod ext_trusted;
pub mod lemmas;
pub mod map_entries;
pub mod model_lemmas;
pub mod policy_abs;
pub mod trusted;
pub mod value_abs;
pub mod wildcard_lemmas;
