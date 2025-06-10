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
