//! Integration tests targeting the decimal extension
//!

use cedar_policy::integration_testing::perform_integration_test_from_json;
use std::path::Path;

/// Path of the folder containing the JSON tests
fn folder() -> &'static Path {
    Path::new("tests/decimal")
}

#[test]
#[cfg(feature = "decimal")]
fn decimal_1() {
    perform_integration_test_from_json(folder().join("1.json"));
}

#[test]
#[cfg(feature = "decimal")]
fn decimal_2() {
    perform_integration_test_from_json(folder().join("2.json"));
}
