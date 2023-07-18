/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
use thiserror::Error;

/// Errors that can occur during authorization
#[derive(Debug, PartialEq, Clone, Error)]
pub enum AuthorizationError {
    /// Failed to eagerly evaluate entity attributes when initializing the `Evaluator`.
    #[error("error occurred while evaluating entity attributes: {0}")]
    AttributeEvaluationError(EvaluationError),

    /// An error occurred when evaluating a policy.
    #[error("error occurred while evaluating policy `{}`: {}", &.id, &.error)]
    PolicyEvaluationError {
        /// Id of the policy with an error
        id: PolicyID,
        /// Specific evaluation error
        error: EvaluationError,
    },
}
