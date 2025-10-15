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

//! This module contains possible errors thrown by batched evaluation

use thiserror::Error;

use crate::ast::PartialValueToValueError;
use crate::tpe::err::{EntitiesError, MissingEntitiesError, PartialRequestError, TpeError};
use crate::validator::RequestValidationError;

/// Errors for Batched Evaluation
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BatchedEvalError {
    /// Error thrown by TPE
    #[error(transparent)]
    TPE(#[from] TpeError),
    /// Error when the request is not valid
    #[error(transparent)]
    RequestValidation(#[from] RequestValidationError),
    /// Error when the request is partial
    #[error(transparent)]
    PartialRequest(#[from] PartialRequestError),
    /// Error when the loaded entities are not valid
    #[error(transparent)]
    Entities(#[from] EntitiesError),
    /// Error thrown when a entity loader provided entity was partial instead of fully concrete
    #[error(transparent)]
    PartialValueToValue(#[from] PartialValueToValueError),
    /// Error the entity loader failed to load all requested entities
    #[error(transparent)]
    MissingEntities(#[from] MissingEntitiesError),
    /// Error when batched evaluation did not converge due to the iteration limit
    #[error(transparent)]
    InsufficientIterations(#[from] InsufficientIterationsError),
}

/// Batched evaluation may not return an answer when the maximum
/// iterations is too low.
#[derive(Debug, Error)]
#[error("Batched evaluation failed: insufficient iteration limit.")]
pub struct InsufficientIterationsError {}
