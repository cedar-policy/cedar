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
#![warn(missing_docs)]
#![cfg_attr(feature = "wasm", allow(non_snake_case))]

#[macro_use]
extern crate lalrpop_util;

pub mod ast;
pub mod authorizer;
mod from_normalized_str;
pub use from_normalized_str::*;
pub mod entities;
#[macro_use]
mod error_macros;
pub mod est;
pub mod evaluator;
pub mod expr_builder;
pub mod extensions;
pub mod fuzzy_match;
pub mod jsonvalue;
pub mod parser;
#[cfg(feature = "tpe")]
pub mod tpe;
pub mod transitive_closure;
pub mod validator;

#[cfg(any(test, feature = "test-util"))]
pub mod test_utils;
