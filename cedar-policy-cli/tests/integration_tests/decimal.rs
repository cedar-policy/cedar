//! Integration tests targeting the decimal extension
//!
//! These files exist separately in the `CedarIntegrationTests` package

use super::perform_integration_test_from_json;
use std::path::Path;

/// Path of the folder containing the JSON tests
fn folder() -> &'static Path {
    Path::new("tests/decimal")
}

#[test]
fn decimal_1() {
    perform_integration_test_from_json(folder().join("1.json"));
}

#[test]
fn decimal_2() {
    perform_integration_test_from_json(folder().join("2.json"));
}
