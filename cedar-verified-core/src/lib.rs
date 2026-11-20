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

//! Graph algorithms used by `cedar-policy-core`, verified with Verus
//! (`verify.sh`).
//!
//! A graph is a `Vec<Vec<usize>>`: node `i` has the out-edges `g[i]`, and
//! every target is a node (`< g.len()`). The specifications are in
//! [`graph`]; the theorem of [`transitive_closure`] states that its result
//! has an edge from `u` to `v` iff `g` has a path of length at least 1 from
//! `u` to `v`. [`repair_closure`] computes the same closure in place, from a
//! graph whose rows outside a given set are already closed, when the graph
//! has no cycle. [`first_self_loop`] is the DAG check on the result: on the
//! closure, it reports a node iff the graph has a cycle.
//!
//! The Verus annotations are `cfg_attr(verus_keep_ghost, …)` attributes and
//! `proof!` blocks; without Verus they are erased, so Cargo sees plain Rust.
//! The code therefore uses `while` loops over indices, no iterators or
//! closures, and `match` instead of `?`.

#![cfg_attr(verus_keep_ghost, feature(proc_macro_hygiene))]
#![forbid(unsafe_code)]
#![allow(
    clippy::needless_range_loop,
    clippy::ptr_arg,
    clippy::collapsible_if,
    clippy::manual_range_contains,
    clippy::len_zero,
    clippy::needless_else
)]

/// Without Verus, proof blocks are erased.
#[cfg(not(verus_keep_ghost))]
macro_rules! proof {
    ($($t:tt)*) => {};
}

/// Without Verus, ghost declarations are erased.
#[cfg(not(verus_keep_ghost))]
macro_rules! proof_decl {
    ($($t:tt)*) => {};
}

/// Without Verus, ghost call arguments are erased.
#[cfg(not(verus_keep_ghost))]
macro_rules! proof_with {
    ($($t:tt)*) => {};
}

pub mod dag;
pub mod graph;
pub mod scc;
pub mod tc;

pub use dag::first_self_loop;
pub use tc::{repair_closure, transitive_closure};
