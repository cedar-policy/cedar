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

use cedar_policy::EntityTypeName;
use miette::Diagnostic;
use thiserror::Error;

use super::bitvec::BitVecError;
use super::extension_types::ipaddr::IPError;

/// Errors that can occur during symbolic compilation.
/// Corresponds to `Cedar.SymCC.Result.Error` in the Lean version.
#[derive(Debug, Diagnostic, Error)]
pub enum CompileError {
    /// Failed to find an entity type.
    #[error("entity type {0} does not exist")]
    NoSuchEntityType(EntityTypeName),
    /// Failed to find an attribute.
    #[error("attribute {0} does not exist")]
    NoSuchAttribute(String),
    /// Type error when constructing a [`Term`].
    #[error("term type error")]
    TypeError,
    /// Unsupported features.
    #[error("unsupported feature in SymCC")]
    UnsupportedFeature(String),
    /// Bit-vector error.
    #[error("bit-vector error ")]
    BitVecError(#[from] BitVecError),
    /// IP address error.
    #[error("IP address error")]
    IPError(#[from] IPError),
    /// Context type is not a record.
    #[error("context type is not a record")]
    NonRecordContext,
}
