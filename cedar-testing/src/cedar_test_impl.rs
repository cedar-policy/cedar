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

//! Definition of a `CedarTestImplementation` trait that describes an
//! implementation of Cedar to use during testing.

pub use cedar_policy::frontend::is_authorized::InterfaceResponse;
use cedar_policy_core::ast::{Expr, PolicySet, Request, Value};
use cedar_policy_core::authorizer::Authorizer;
use cedar_policy_core::entities::Entities;
use cedar_policy_core::evaluator::Evaluator;
use cedar_policy_core::extensions::Extensions;
use cedar_policy_validator::{ValidationMode, Validator, ValidatorSchema};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Return type for `CedarTestImplementation` methods
#[derive(Debug, Deserialize)]
pub enum TestResult<T> {
    /// The request succeeded
    Success(T),
    /// The request failed (e.g., due to a parse error)
    Failure(String),
}

impl<T> TestResult<T> {
    /// Get the underlying value of a `TestResult`.
    /// # Panics
    /// If the `TestResult` is a `Failure`.
    /// PANIC SAFETY only used in testing code
    #[allow(clippy::panic)]
    pub fn expect(self, msg: &str) -> T {
        match self {
            Self::Success(t) => t,
            Self::Failure(err) => panic!("{msg}: {err}"),
        }
    }
}

/// Simple wrapper around u128 to remind ourselves that timing info is in microseconds.
#[derive(Debug, Deserialize)]
pub struct Micros(pub u128);

/// Version of `Response` used for testing. Includes an `InterfaceResponse` and
/// a map with timing information.
#[derive(Debug, Deserialize)]
pub struct TestResponse {
    /// Actual response
    pub response: InterfaceResponse,
    /// Timing info in microseconds. This field is a `HashMap` to allow timing
    /// multiple components (or none at all).
    pub timing_info: HashMap<String, Micros>,
}

/// Version of `ValidationResult` used for testing.
#[derive(Debug, Deserialize)]
pub struct TestValidationResult {
    /// Validation errors
    pub errors: Vec<String>,
    /// Timing info in microseconds. This field is a `HashMap` to allow timing
    /// multiple components (or none at all).
    pub timing_info: HashMap<String, Micros>,
}

impl TestValidationResult {
    /// Check if validation succeeded
    pub fn validation_passed(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Custom implementation of the Cedar authorizer, evaluator, and validator for testing.
pub trait CedarTestImplementation {
    /// Custom authorizer entry point.
    fn is_authorized(
        &self,
        request: &Request,
        policies: &PolicySet,
        entities: &Entities,
    ) -> TestResult<TestResponse>;

    /// Custom evaluator entry point. The bool return value indicates the whether
    /// evaluating the provided expression produces the expected value.
    /// `expected` is optional to allow for the case where no return value is
    /// expected due to errors.
    fn interpret(
        &self,
        request: &Request,
        entities: &Entities,
        expr: &Expr,
        enable_extensions: bool,
        expected: Option<Value>,
    ) -> TestResult<bool>;

    /// Custom validator entry point.
    fn validate(
        &self,
        schema: &ValidatorSchema,
        policies: &PolicySet,
        mode: ValidationMode,
    ) -> TestResult<TestValidationResult>;

    /// `ErrorComparisonMode` that should be used for this `CedarTestImplementation`
    fn error_comparison_mode(&self) -> ErrorComparisonMode;
}

/// Specifies how errors coming from a `CedarTestImplementation` should be
/// compared against errors coming from the Rust implementation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ErrorComparisonMode {
    /// Don't compare errors at all; the `CedarTestImplementation` is not
    /// expected to produce errors matching the Rust implementation's errors in
    /// any way.
    /// In fact, the `CedarTestImplementation` will be expected to never report
    /// errors.
    Ignore,
    /// The `CedarTestImplementation` is expected to produce "error messages" that
    /// are actually just the id of the erroring policy. This will be compared to
    /// ensure that the `CedarTestImplementation` agrees with the Rust
    /// implementation on which policies produce errors.
    PolicyIds,
    /// The `CedarTestImplementation` is expected to produce error messages that
    /// exactly match the Rust implementation's error messages' `Display` text.
    Full,
}

/// Basic struct to support implementing the `CedarTestImplementation` trait
#[derive(Debug, Default)]
pub struct RustEngine {}

impl RustEngine {
    /// Create a new `RustEngine`
    pub fn new() -> Self {
        Self {}
    }
}

/// Timing function
pub fn time_function<X, F>(f: F) -> (X, Duration)
where
    F: FnOnce() -> X,
{
    let start = Instant::now();
    let result = f();
    (result, start.elapsed())
}

/// An implementation of `CedarTestImplementation` using `cedar-policy`.
/// Used for running integration tests.
impl CedarTestImplementation for RustEngine {
    fn is_authorized(
        &self,
        request: &Request,
        policies: &PolicySet,
        entities: &Entities,
    ) -> TestResult<TestResponse> {
        let authorizer = Authorizer::new();
        let (response, duration) =
            time_function(|| authorizer.is_authorized(request.clone(), policies, entities));
        // Error messages should only include the policy id to use the
        // `ErrorComparisonMode::PolicyIds` mode.
        let response = cedar_policy::Response::from(response);
        let response = InterfaceResponse::new(
            response.decision(),
            response.diagnostics().reason().cloned().collect(),
            response
                .diagnostics()
                .errors()
                .map(cedar_policy::AuthorizationError::id)
                .map(ToString::to_string)
                .collect(),
        );
        let response = TestResponse {
            response,
            timing_info: HashMap::from([("authorize".into(), Micros(duration.as_micros()))]),
        };
        TestResult::Success(response)
    }

    fn interpret(
        &self,
        request: &Request,
        entities: &Entities,
        expr: &Expr,
        enable_extensions: bool,
        expected: Option<Value>,
    ) -> TestResult<bool> {
        let exts = if enable_extensions {
            Extensions::all_available()
        } else {
            Extensions::none()
        };
        let evaluator = Evaluator::new(request.clone(), entities, &exts);
        let result = evaluator.interpret(expr, &HashMap::default());
        let response = result.ok() == expected;
        TestResult::Success(response)
    }

    fn validate(
        &self,
        schema: &ValidatorSchema,
        policies: &PolicySet,
        mode: ValidationMode,
    ) -> TestResult<TestValidationResult> {
        let validator = Validator::new(schema.clone());
        let (result, duration) = time_function(|| validator.validate(policies, mode));
        let response = TestValidationResult {
            errors: result
                .validation_errors()
                .map(|err| format!("{err:?}"))
                .collect(),
            timing_info: HashMap::from([("validate".into(), Micros(duration.as_micros()))]),
        };
        TestResult::Success(response)
    }

    fn error_comparison_mode(&self) -> ErrorComparisonMode {
        ErrorComparisonMode::PolicyIds
    }
}
