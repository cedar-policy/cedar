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

#![warn(clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::string_slice,
    reason = "existing code"
)]
#![cfg_attr(not(feature = "bin"), allow(dead_code, unused_imports))]

#[cfg(feature = "bin")]
pub mod document;
mod documentation;
mod entities;
mod lsp;
mod markdown;
pub mod policy;
pub mod schema;
#[cfg(feature = "bin")]
pub mod server;
mod utils;
