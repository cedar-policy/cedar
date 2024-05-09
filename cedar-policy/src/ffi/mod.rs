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

#![cfg_attr(feature = "wasm", allow(non_snake_case))]

//! Functions for interacting with `cedar_policy`, intended to be easier to use
//! in an FFI context than the root-level `cedar_policy` interface

mod is_authorized;
pub use is_authorized::*;
mod utils;
pub use utils::{DetailedError, PolicySet, Schema, Severity, SourceLabel, SourceLocation};
mod validate;
pub use validate::*;
