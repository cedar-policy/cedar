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
//! Verus proofs lifting the authorization theorems of
//! `cedar_policy_core::verification` to the public `Authorizer`
//! (`verus` feature only, for `cargo verus`).
#![allow(unsafe_code, missing_docs, unused_imports, elided_lifetimes_in_paths, clippy::all)]

use vstd::prelude::*;

pub use cedar_policy_core::verification::model;

pub mod abs;
// Must precede `authorizer_theorems`, or Verus doesn't use the
// `FromSpecImpl` of `Response` when verifying its `From` impl.
pub mod conversions;
pub mod trusted;
pub mod authorizer_theorems;
