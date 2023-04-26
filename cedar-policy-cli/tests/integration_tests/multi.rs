//! Integration tests which involve interactions between multiple policies
//!
//! These files exist separately in the `CedarIntegrationTests` package

use super::perform_integration_test_from_json;
use std::path::Path;

/// Path of the folder containing the JSON tests
fn folder() -> &'static Path {
    Path::new("tests/multi")
}

#[test]
fn multi_1() {
    perform_integration_test_from_json(folder().join("1.json"));
}

#[test]
fn multi_2() {
    perform_integration_test_from_json(folder().join("2.json"));
}

#[test]
fn multi_3() {
    perform_integration_test_from_json(folder().join("3.json"));
}

#[test]
fn multi_4() {
    perform_integration_test_from_json(folder().join("4.json"));
}

#[test]
fn multi_5() {
    perform_integration_test_from_json(folder().join("5.json"));
}
