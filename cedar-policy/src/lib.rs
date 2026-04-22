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

// Includes the cedar-policy README as the top-level documentation for this
// crate. This also acts as a test that the example code in the README
// compiles. If changing the docs away from using the readme verbatim, be sure
// to add a separate test specifically for README examples by introducing a
// private, empty, and unused function with `#[doc = include_str!("../README.md")]`.
#![doc = include_str!("../README.md")]
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
//! - `heap-profiling` — Enables heap profiling via `dhat`.
//! - `corpus-timing` — Enables corpus timing instrumentation.
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
//! - `tpe` — Type-aware partial evaluation / batched authorization.
//! - `partial-eval` — Partial evaluation of Cedar policies. You should prefer `tpe` above.
//! - `partial-validate` — Partial validation of Cedar policies.
//! - `permissive-validate` — Permissive validation mode.
//! - `protobufs` — Protocol Buffers serialization support for Cedar types.
//!   Enables the `proto` module.
//! - `tolerant-ast` — Error-tolerant parsing that produces a (possibly
//!   incomplete) AST even when the input contains syntax errors. This feature is intended
//!   only for use in language servers, and should never be used on the authorization path.
//! - `extended-schema` — Extended schema support intended for language servers.
//! - (deprecated) `deprecated-schema-compat` — Support for deprecated schema parsing
//!   behavior. API is stable, but will be removed in a future release.
//! - (deprecated) `entity-manifest` — Entity manifest computation for entity slicing.
//!   This feature is deprecated; you should use `tpe` instead.
#![warn(clippy::pedantic, clippy::use_self, clippy::option_if_let_else)]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_html_tags,
    rustdoc::invalid_rust_codeblocks,
    rustdoc::bare_urls,
    clippy::doc_markdown,
    clippy::doc_lazy_continuation,
    clippy::too_long_first_doc_paragraph
)]
#![allow(
    clippy::must_use_candidate,
    reason = "in the future we can enable this lint but currently it doesn't pass"
)]
// enable doc_cfg feature if docsrs cfg is present
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(
    feature = "wasm",
    allow(
        non_snake_case,
        reason = "Wasm/TypeScript doesn't use snake case identifiers by convention"
    )
)]

/// Rust public API
mod api;

pub use api::version::{get_lang_version, get_sdk_version};
pub use api::*;

/// FFI utilities, see comments in the module itself
pub mod ffi;

/// Protobuf models of cedar-policy types
#[cfg(feature = "protobufs")]
#[cfg_attr(docsrs, doc(cfg(feature = "protobufs")))]
pub mod proto;

mod test;
