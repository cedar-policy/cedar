// Not currently enforcing panic lints in the LSP crate.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::missing_errors_doc,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::panic
)]
pub mod document;
mod entities;
mod lsp;
mod markdown;
pub mod policy;
pub mod schema;
#[cfg(feature = "bin")]
pub mod server;
mod utils;
