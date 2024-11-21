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
#![warn(clippy::pedantic, clippy::nursery)]
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
    clippy::needless_doctest_main,
    clippy::must_use_candidate,
    clippy::missing_const_for_fn
)]
// enable doc_auto_cfg feature if docsrs cfg is present
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(feature = "wasm", allow(non_snake_case))]

/// Rust public API
mod api;

pub use api::version::{get_lang_version, get_sdk_version};
pub use api::*;

/// FFI utilities, see comments in the module itself
pub mod ffi;

mod prop_test_policy_set;
mod tests;
