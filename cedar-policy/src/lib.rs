//! Public Rust interface for Cedar
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    missing_debug_implementations,
    rust_2018_idioms,
    clippy::pedantic,
    clippy::nursery
)]
#![allow(clippy::must_use_candidate, clippy::missing_const_for_fn)]

/// Rust public API
mod api;
pub use api::*;

/// Frontend utilities, see comments in the module itself
pub mod frontend;

#[cfg(feature = "integration_testing")]
pub mod integration_testing;
