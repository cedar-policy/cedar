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

//! Definition of a `CedarTestImplementation` trait that describes an
//! implementation of Cedar to use during testing. This trait is used for
//! running the integration tests and for performing randomized differential
//! testing (see <https://github.com/cedar-policy/cedar-spec>).

pub use cedar_policy::ffi;
use cedar_policy_core::ast::PartialValue;
use cedar_policy_core::ast::{Expr, PolicySet, Request, Value};
use cedar_policy_core::authorizer::Authorizer;
use cedar_policy_core::entities::Entities;
use cedar_policy_core::evaluator::Evaluator;
use cedar_policy_core::extensions::Extensions;
use cedar_policy_validator::{ValidationMode, Validator, ValidatorSchema};
use miette::miette;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Return type for `CedarTestImplementation` methods
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
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

    /// Apply a function to the success value.
    pub fn map<F: FnOnce(T) -> T>(self, f: F) -> Self {
        match self {
            Self::Success(t) => Self::Success(f(t)),
            Self::Failure(err) => Self::Failure(err),
        }
    }
}

/// Simple wrapper around u128 to remind ourselves that timing info is in microseconds.
#[derive(Debug, Deserialize)]
#[serde(transparent)]
pub struct Micros(pub u128);

/// Version of `Response` used for testing. Includes a
/// `ffi::Response` and a map with timing information.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestResponse {
    /// Actual response
    pub response: ffi::Response,
    /// Timing info in microseconds. This field is a `HashMap` to allow timing
    /// multiple components (or none at all).
    pub timing_info: HashMap<String, Micros>,
}

/// Version of `ValidationResult` used for testing.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestValidationResult {
    /// Validation errors
    pub errors: Vec<String>,
    /// Timing info in microseconds. This field is a `HashMap` to allow timing
    /// multiple components (or none at all).
    pub timing_info: HashMap<String, Micros>,
}

pub mod partial {
    use super::*;
    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase")]
    pub struct FlatPartialResponse {
        pub known_permits: HashSet<String>,
        pub known_forbids: HashSet<String>,
        pub determining_under_approx: HashSet<String>,
        pub determining_over_approx: HashSet<String>,
        pub decision: Decision,
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase")]
    pub enum Decision {
        Allow,
        Deny,
        Unknown,
    }

    impl Decision {
        pub fn from_core(o: Option<cedar_policy_core::authorizer::Decision>) -> Self {
            match o {
                Some(cedar_policy_core::authorizer::Decision::Allow) => Self::Allow,
                Some(cedar_policy_core::authorizer::Decision::Deny) => Self::Deny,
                None => Self::Unknown,
            }
        }
    }
}

impl TestValidationResult {
    /// Check if validation succeeded
    pub fn validation_passed(&self) -> bool {
        self.errors.is_empty()
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum ExprOrValue {
    Expr(Expr),
    Value(Expr),
}

impl ExprOrValue {
    pub fn value(v: Value) -> Self {
        Self::Value(v.into())
    }
}

impl std::fmt::Display for ExprOrValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expr(e) => write!(f, "Expr: `{e}`"),
            Self::Value(v) => write!(f, "Value: `{v}`"),
        }
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

    fn partial_is_authorized(
        &self,
        request: &Request,
        entities: &Entities,
        policies: &PolicySet,
    ) -> TestResult<partial::FlatPartialResponse>;

    /// Custom partial evaluator entry point. The bool return value indicates the whether
    /// evaluating the provided expression produces the expected value.
    /// `expected` is optional to allow for the case where no return value is
    /// expected due to errors.
    fn partial_evaluate(
        &self,
        request: &Request,
        entities: &Entities,
        expr: &Expr,
        enable_extensions: bool,
        expected: Option<ExprOrValue>,
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

    /// `ValidationComparisonMode` that should be used for this `CedarTestImplementation`
    fn validation_comparison_mode(&self) -> ValidationComparisonMode;
}

/// Specifies how authorization errors coming from this [`CedarTestImplementation`]
///  should be compared against errors coming from another implementation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ErrorComparisonMode {
    /// Don't compare errors at all. The [`CedarTestImplementation`] will be
    /// expected to never report errors.
    Ignore,
    /// The [`CedarTestImplementation`] is expected to produce "error messages"
    /// that are actually just the id of the erroring policy. This will used to
    /// ensure that different implementations agree on which policies produce
    /// errors.
    PolicyIds,
    /// The [`CedarTestImplementation`] is expected to produce error messages that
    /// exactly match the Rust implementation's error messages' `Display` text.
    Full,
}

/// Specifies how validation results from this [`CedarTestImplementation`] should
/// be compared against validation results from another implementation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValidationComparisonMode {
    /// When comparing this [`CedarTestImplementation`] against another
    /// implementation, `validate` should return a `validation_passed` result
    /// for any input that the other implementation says is valid. This allows
    /// for flexibility in cases where the other implementation (incorrectly)
    /// says the input is invalid due to weaker typing precision.
    AgreeOnValid,
    /// When comparing this [`CedarTestImplementation`] against another
    /// implementation, the valid / not valid decision should agree for all
    /// inputs, although the exact validation errors may differ.
    AgreeOnAll,
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
        let response = cedar_policy::Response::from(response);
        let response = ffi::Response::new(
            response.decision(),
            response.diagnostics().reason().cloned().collect(),
            response
                .diagnostics()
                .errors()
                .map(|e| {
                    // Error messages should only include the policy id to use the
                    // `ErrorComparisonMode::PolicyIds` mode.
                    let policy_id = match e {
                        cedar_policy::AuthorizationError::PolicyEvaluationError(e) => e.policy_id(),
                    };
                    ffi::AuthorizationError::new_from_report(
                        policy_id.clone(),
                        miette!("{policy_id}"),
                    )
                })
                .collect(),
        );
        let response = TestResponse {
            response,
            timing_info: HashMap::from([("authorize".into(), Micros(duration.as_micros()))]),
        };
        TestResult::Success(response)
    }

    fn partial_is_authorized(
        &self,
        request: &Request,
        entities: &Entities,
        policies: &PolicySet,
    ) -> TestResult<partial::FlatPartialResponse> {
        let a = Authorizer::new();
        let pr = a.is_authorized_core(request.clone(), policies, entities);

        let r = partial::FlatPartialResponse {
            known_permits: pr.satisfied_permits.keys().map(|x| x.to_string()).collect(),
            known_forbids: pr.satisfied_forbids.keys().map(|x| x.to_string()).collect(),
            decision: partial::Decision::from_core(pr.decision()),
            determining_over_approx: pr
                .may_be_determining()
                .map(|x| x.id().to_string())
                .collect(),
            determining_under_approx: pr
                .must_be_determining()
                .map(|x| x.id().to_string())
                .collect(),
        };

        TestResult::Success(r)
    }

    fn partial_evaluate(
        &self,
        request: &Request,
        entities: &Entities,
        expr: &Expr,
        enable_extensions: bool,
        expected: Option<ExprOrValue>,
    ) -> TestResult<bool> {
        let exts = if enable_extensions {
            Extensions::all_available()
        } else {
            Extensions::none()
        };
        let e = Evaluator::new(request.clone(), entities, &exts);
        let result = e.partial_interpret(expr, &HashMap::default());
        match (result, expected) {
            (Ok(PartialValue::Residual(r)), Some(ExprOrValue::Expr(e))) => {
                TestResult::Success(r == e)
            }
            (Ok(PartialValue::Value(v)), Some(ExprOrValue::Value(e))) => {
                let v_as_e: Expr = v.into();
                TestResult::Success(v_as_e == e)
            }

            (Err(_), None) => TestResult::Success(true),
            _ => TestResult::Success(false),
        }
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

    fn validation_comparison_mode(&self) -> ValidationComparisonMode {
        ValidationComparisonMode::AgreeOnAll
    }
}
