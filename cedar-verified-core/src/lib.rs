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

//! The transitive closure of a graph, and its repair after some rows
//! changed, verified with Verus. `cedar-policy-core` calls this crate under
//! its feature `verified-core`, through the unverified adapter
//! `cedar-policy-core/src/transitive_closure/verified.rs`.
//!
//! A graph is a `Vec<Vec<usize>>` over dense indices: row `g[u]` lists the
//! targets of the out-edges of node `u`, possibly with duplicates. The spec
//! fn `wf(g)` states that every target is below `g.len()`. `reach(g, u, v)`
//! states that `g` has a path of length at least 1 from `u` to `v`, so
//! `reach(g, u, u)` holds iff `u` is on a cycle; `has_cycle(g)` states that
//! some node reaches itself; `closed_at(g, h, u)` states that row `u` of `h`
//! is the set of nodes that `u` reaches in `g`. These spec fns are in
//! [`graph`].
//!
//! # Entry points
//!
//! The exact statements are the `verus_spec` attributes of these items in
//! `tc.rs`.
//!
//! - [`transitive_closure`]`(g)`, for `wf(g)`, returns `(r, cyc)`. Row `r[u]`
//!   holds the nodes that `u` reaches and that are not in `g[u]`, so
//!   `g[u] ∪ r[u]` is the closure row of `u`; `cyc` is `None` iff `g` has no
//!   cycle, and otherwise the smallest node on a cycle.
//! - [`repair_closure`]`(g, fix)`, for `wf(g)` and every `fix[i] < g.len()`,
//!   repairs `g` in place at the nodes of `fix`, in order. Rows outside `fix`
//!   are unchanged (R1), rows only grow by appending (R2), every edge of the
//!   result is a path of the input (R3), and if the input has no cycle and
//!   its rows outside `fix` are closed, every row of the result is closed
//!   (R4). It returns the first node of `fix` whose row contains itself:
//!   `Some` implies a cycle (D1), and an acyclic input gives `None` (D2).
//! - `restricts(g0, h, fix)` (spec fn) states that every row of `h` is the
//!   row of `g0` or empty, and is the row of `g0` at each node of `fix` and
//!   at each target of those rows. `lemma_repair_restrict(g0, h, fix)`
//!   (proof fn) is for callers that repair `h` instead of `g0`: paths and
//!   cycles of `h` are paths and cycles of `g0`, and when the rows of `g0`
//!   outside `fix` are closed, so are the rows of `h` outside `fix`, and a
//!   node of `fix` reaches the same nodes in `h` and in `g0`. With R4, the
//!   repaired rows of `fix` in `h` are the closure rows of `g0` when `g0` has
//!   no cycle. Both items exist only under Verus.
//!
//! # How it is checked
//!
//! `verify.sh` runs Verus on `src/lib.rs` with `--no-external-by-default`,
//! so every function is checked against its `verus_spec`, for termination,
//! and for absence of panics (indexing, `unwrap`) and arithmetic overflow.
//! Cargo builds the same files without the `verus_keep_ghost` cfg: the
//! `verus_spec` attributes are `cfg_attr(verus_keep_ghost, …)`, the `verus!`
//! blocks holding spec and proof fns are `cfg(verus_keep_ghost)`, and the
//! `proof!`, `proof_decl!` and `proof_with!` macros below expand to nothing.
//! The exec code uses `while` loops over indices and no iterators, closures
//! or `?`, so that the same text is valid for both. The unit tests are
//! `#[cfg(test)]` and are not verified.
//!
//! # Trusted base
//!
//! - Verus 0.2026.10.18.7d82994, the default binary of `verify.sh`.
//! - Z3 4.16.0, passed with `VERUS_Z3_PATH`; the Z3 bundled with Verus needs
//!   glibc 2.38 and is not used.
//! - vstd's specs of the std items the exec code calls: `Vec::new`,
//!   `Vec::with_capacity`, `Vec::len`, `Vec::push`, `Vec::pop`,
//!   `Vec::truncate`, `Index` and `IndexMut` on `Vec`, and `std::mem::swap`.
//! - Cargo erasing only ghost code: the code Cargo compiles is the code
//!   Verus checked, minus the `verus_spec` attributes, the `verus!` blocks,
//!   and the arguments of `proof!`, `proof_decl!` and `proof_with!`.
//!
//! The crate has no `assume`, `admit` or `external_body`. The three
//! `#[verifier::opaque]` attributes, on `inv_q` and `loop_inv` in `scc.rs`
//! and on `anc_loop` in `tc.rs`, hide a definition from the solver until it
//! is revealed; they add nothing to the trusted base.
//!
//! # Not proved
//!
//! - SCC maximality. `transitive_closure` needs only P1–P3 of `scc.rs`.
//! - On cyclic inputs, `repair_closure` is only sound: R1–R3 and D1 hold,
//!   and the result can miss paths. Its cycle check is not complete: a cycle
//!   that does not go through a node of `fix` is not reported. The deferred
//!   property, that the result is `Some` iff the input has a cycle when the
//!   rows outside `fix` are closed and have no self-edge, is not proved; no
//!   counterexample is known.
//! - On cyclic inputs, or when the rows of `g0` outside `fix` are not closed,
//!   repairing the restriction `h` is not proved to give the same rows at
//!   `fix` as repairing `g0`. Only soundness carries over: by R3 and
//!   `lemma_repair_restrict`, every added edge, a reported self-edge
//!   included, is a path of `g0`.

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

mod dag;
pub mod graph;
mod scc;
mod tc;

// The entry points listed in the crate doc.
#[cfg(verus_keep_ghost)]
pub use tc::{lemma_repair_restrict, restricts};
pub use tc::{repair_closure, transitive_closure};
