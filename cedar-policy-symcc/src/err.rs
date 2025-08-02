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
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Error from the `symcc` module (except its `solver` module)
    #[error(transparent)]
    Symcc(crate::symcc::Error),
    /// Error from the `solver` module
    #[error(transparent)]
    Solver(#[from] crate::symcc::solver::Error),
    /// Solver returned `unknown`
    #[error("Solver returned `unknown`")]
    SolverUnknown,
    /// Internal error
    #[error("{message}")]
    Internal { message: String },
}
pub type Result<T> = std::result::Result<T, Error>;

impl From<crate::symcc::Error> for Error {
    fn from(err: crate::symcc::Error) -> Self {
        match err {
            crate::symcc::Error::SolverUnknown => Self::SolverUnknown,
            e => Self::Symcc(e),
        }
    }
}

impl From<crate::symcc::result::Error> for Error {
    fn from(err: crate::symcc::result::Error) -> Self {
        let err: crate::symcc::Error = err.into();
        err.into()
    }
}
