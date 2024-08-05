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

#![cfg(test)]
// PANIC SAFETY unit tests
#![allow(clippy::panic)]
// PANIC SAFETY unit tests
#![allow(clippy::indexing_slicing)]

pub(crate) mod test_utils;

mod expr;
mod extensions;
mod namespace;
mod optional_attributes;
#[cfg(feature = "partial-validate")]
mod partial;
mod policy;
mod strict;
mod type_annotation;
mod unspecified_entity;
