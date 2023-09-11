/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

use std::error::Error;

use miette::{Diagnostic, Report};
use thiserror::Error;

/// Internal adapter from Rust's standard [`Error`] to [`miette`]'s
/// [`Diagnostic`], with an attached diagnostic code.
#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
#[diagnostic(code(cedar_policy_cli::other_err))]
struct DiagnosticError(Box<dyn Error + Send + Sync + 'static>);

/// Alternative to [`miette::IntoDiagnostic`] which attaches diagnostic codes
/// to adapted [`Error`]s for better-formatted output.
pub trait IntoDiagnostic<T, E> {
    fn into_diagnostic(self) -> Result<T, Report>;
}

impl<T, E: Error + Send + Sync + 'static> IntoDiagnostic<T, E> for Result<T, E> {
    fn into_diagnostic(self) -> Result<T, Report> {
        self.map_err(|err| DiagnosticError(Box::new(err)).into())
    }
}
