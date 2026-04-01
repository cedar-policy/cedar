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

//! All error types in SymCC.

use cedar_policy_core::validator::ValidationError;
use miette::Diagnostic;
use thiserror::Error;

pub use crate::symcc::{
    ext::ExtError, extension_types::datetime::DatetimeError,
    extension_types::decimal::DecimalError, extension_types::ipaddr::IPError, term::Term,
    BitVecError, CompileError, ConcretizeError, DecodeError, EncodeError, SolverError,
};

/// Top-level errors from the whole `cedar-policy-symcc` crate.
#[derive(Debug, Diagnostic, Error)]
pub enum Error {
    /// Action not found in schema.
    #[error("action not found in schema: {0}")]
    ActionNotInSchema(String),
    /// Errors during symbolic compilation.
    #[error("symbolic compilation failed: {0}")]
    CompileError(#[from] CompileError),
    /// Errors from the SMT encoder.
    #[error("failed to encode SMT terms: {0}")]
    EncodeError(#[from] EncodeError),
    /// Solver-related errors.
    #[error(transparent)]
    SolverError(#[from] SolverError),
    /// Solver returned `unknown`.
    #[error("solver returned `unknown`")]
    SolverUnknown,
    /// Policy is not well-typed.
    #[error("input policy (set) is not well typed with respect to the schema {errs:?}")]
    PolicyNotWellTyped {
        /// Errors from the policy validator.
        errs: Vec<ValidationError>,
    },
    /// Failed to decode the SMT model.
    #[error("failed to decode model: {0}")]
    DecodeModel(#[from] DecodeError),
    /// Errors during concretization.
    #[error("failed to recover a concrete counterexample: {0}")]
    ConcretizeError(#[from] ConcretizeError),
    /// Model successfully decoded and concretized, but the resulting model is invalid.
    #[error("model is invalid: violates assertion {assert}")]
    ModelInvalid {
        /// Assertion that was violated
        assert: Term,
    },
    /// Empty-list of policies was passed to a function that expects at least one policy
    #[error("expected to have at least one policy")]
    NoPolicies,
}

/// A result type that potentially returns a SymCC [`enum@Error`].
pub type Result<T> = std::result::Result<T, Error>;
