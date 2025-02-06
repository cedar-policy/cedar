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

/// Errors that occur during concretizing a partial request
#[derive(Debug, Error, Diagnostic)]
pub enum ConcretizationError {
    /// Errors that occur when binding unknowns with values of unexpected types
    #[error("invalid value {given_value} of {id}: expected type {expected_type}")]
    ValueError {
        /// String representation of PARC
        id: SmolStr,
        /// Expected type of the provided value
        expected_type: &'static str,
        /// The provided value
        given_value: Value,
    },
    /// Errors that occur when binding variables with known values
    #[error("concretizing existing value {existing_value} of {id} with value {given_value}")]
    VarConfictError {
        /// String representation of PARC
        id: SmolStr,
        /// Existing value of PARC
        existing_value: PartialValue,
        /// The provided value
        given_value: Value,
    },
    /// Errors that occur when binding variables with known values
    #[error("concretizing existing but unknown entity value of type {existing_value} of {id} with value {given_value}")]
    EntityTypeConfictError {
        /// String representation of PARC
        id: SmolStr,
        /// Existing value of PARC
        existing_value: EntityType,
        /// The provided value
        given_value: Value,
    },
    /// Errors that occur when evaluating partial values
    #[error(transparent)]
    #[diagnostic(transparent)]
    ValueEval(#[from] EvaluationError),
}

/// Errors that occur during reauthorizing partial responses
#[derive(Debug, Error, Diagnostic)]
pub enum ReauthorizationError {
    /// Errors that occur during re-constructing policy sets
    #[error(transparent)]
    #[diagnostic(transparent)]
    PolicySetError(#[from] PolicySetError),
    /// Errors that occur during concretizing a partial request
    #[error(transparent)]
    #[diagnostic(transparent)]
    ConcretizationError(#[from] ConcretizationError),
}
