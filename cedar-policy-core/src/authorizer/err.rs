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

use crate::ast::*;
use crate::evaluator::EvaluationError;
use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

/// Errors that can occur during authorization
#[derive(Debug, PartialEq, Eq, Clone, Diagnostic, Error)]
pub enum AuthorizationError {
    /// An error occurred when evaluating a policy.
    #[error("while evaluating policy `{id}`: {error}")]
    PolicyEvaluationError {
        /// Id of the policy with an error
        id: PolicyID,
        /// Underlying evaluation error
        #[diagnostic(transparent)]
        error: EvaluationError,
    },
}

#[derive(Debug, Error, Diagnostic)]
pub enum ConcretizationError {
    #[error("invalid value {given_value} of {id}: expected type {expected_type}")]
    ValueError {
        id: SmolStr,
        expected_type: &'static str,
        given_value: Value,
    },
    #[error("concretizing existing value {existing_value} of {id} with value {given_value}")]
    VarConfictError {
        id: SmolStr,
        existing_value: Value,
        given_value: Value,
    },
}

#[derive(Debug, Error, Diagnostic)]
pub enum ReauthorizationError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    PolicySetError(#[from] PolicySetError),
    #[error(transparent)]
    #[diagnostic(transparent)]
    ConcretizationError(#[from] ConcretizationError),
}
