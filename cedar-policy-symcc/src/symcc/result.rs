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

//! This module would more typically be called `err` or similar, but we call it
//! `result` to match the Lean

use thiserror::Error;

#[allow(
    clippy::enum_variant_names,
    reason = "UnsupportedError reads better than just Unsupported"
)]
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Error {
    #[error("noSuchEntityType")]
    NoSuchEntityType,
    #[error("noSuchAttribute")]
    NoSuchAttribute,
    #[error("typeError")]
    TypeError,
    #[error("unsupportedError")]
    UnsupportedError,
    #[error("unreachableError: {0}")]
    Unreachable(String),
}
