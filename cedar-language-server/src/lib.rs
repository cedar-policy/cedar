// Not currently enforcing panic lints in the LSP crate. We judge this less
// critical than the core Cedar authorization code, so the possibility of panics
// is more acceptable. Still, we should eventual remove these exceptions, at
// least pushing them more localized regions of code.
#![allow(
    clippy::cast_possible_truncation,
    //clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
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
