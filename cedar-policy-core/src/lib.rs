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

//! Implementation of the Cedar parser and evaluation engine in Rust.
//!
//! This package exposes low-level and advanced Cedar APIs, e.g.,
//! for interacting with policy ASTs directly.
//!
//! **WARNING** Anyone simply wanting to use Cedar from a Rust client (e.g.,
//! to make authorization decisions) should use
//! [`cedar-policy`](https://docs.rs/cedar-policy) instead.
//!
//! # Feature flags
//!
//! ## Default features
//!
//! The following features are enabled by default and provide the built-in Cedar
//! extension functions:
//!
//! - `ipaddr` — IP address extension functions (`ip`, `isIpv4`, `isIpv6`,
//!   `isLoopback`, `isMulticast`, `isInRange`).
//! - `decimal` — Decimal number extension functions (`decimal`, `lessThan`,
//!   `lessThanOrEqual`, `greaterThan`, `greaterThanOrEqual`).
//! - `datetime` — Date and time extension functions (`datetime`, `duration`,
//!   `offset`, `durationSince`, `toDate`, `toTime`). Enables the `chrono`
//!   dependency.
//!
//! ## Optional features
//!
//! - `arbitrary` — Enables [`Arbitrary`](https://docs.rs/arbitrary) implementations
//!   for several types in this crate. Useful for fuzzing.
//! - `test-util` — Exposes the [`test_utils`] module with helpers for testing.
//! - `wasm` — Enables WebAssembly bindings via `wasm-bindgen` and `tsify`.
//!
//! ## Experimental features
//!
//! **WARNING:** Experimental features are unstable and subject to breaking
//! changes in any release, including patch releases. Use those features at your
//! own risk.
//!
//! - `experimental` — Enables all experimental features listed below.
//! - `variadic-is-in-range` — Variadic overload for the `isInRange` function.
//! - `tpe` — Type-aware partial evaluation / batched authorization. Enables the
//!   [`batched_evaluator`] and [`tpe`] modules.
//! - `partial-eval` — Partial evaluation of Cedar policies. You should prefer `tpe` above.
//! - `partial-validate` — Partial validation of Cedar policies.
//! - (deprecated) `entity-manifest` — Entity manifest computation for entity slicing.
//!   This feature is deprecated; you should use `tpe` instead.
//!
//! ## Unstable tooling features
//!
//! **WARNING** Unstable tooling features are subject to breaking changes in
//! any release, including patch releases. They should never be enabled by clients.
//! They are intended for language servers and other tools that need to use internal
//! functionality, and manipulate error tolerant representations of the language
//! to provide helpful error messages.
//!
//! They **must not** be used in an authorization path. This includes, but is not
//! limited to, parsing, serializing, and deserializing policies. Use them only
//! for development, testing, or prototyping purposes.
//!
//! - `tolerant-ast` — Error-tolerant parsing that produces a (possibly
//!   incomplete) AST even when the input contains syntax errors. This should
//!   only be used for providing helpful error handling in language servers.
//! - `extended-schema` — The extended schema feature is also intended for language servers.
//!
#![warn(missing_docs)]
// enable doc_cfg feature when building on docs.rs
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(
    feature = "wasm",
    allow(
        non_snake_case,
        reason = "Wasm/TypeScript doesn't use snake case identifiers by convention"
    )
)]

#[macro_use]
extern crate lalrpop_util;

pub mod ast;
pub mod authorizer;
mod from_normalized_str;
pub use from_normalized_str::*;
pub mod entities;
#[macro_use]
mod error_macros;
#[cfg(feature = "tpe")]
#[cfg_attr(docsrs, doc(cfg(feature = "tpe")))]
pub mod batched_evaluator;
pub mod est;
pub mod evaluator;
pub mod expr_builder;
pub mod extensions;
pub mod fuzzy_match;
pub mod jsonvalue;
pub mod parser;
pub mod pst;
#[cfg(feature = "tpe")]
#[cfg_attr(docsrs, doc(cfg(feature = "tpe")))]
pub mod tpe;
pub mod transitive_closure;
pub mod validator;

#[cfg(any(test, feature = "test-util"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_utils;
