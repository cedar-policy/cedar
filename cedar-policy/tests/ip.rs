//! Integration tests targeting the ipaddr extension
//!

use cedar_policy::integration_testing::perform_integration_test_from_json;
use std::path::Path;

/// Path of the folder containing the JSON tests
fn folder() -> &'static Path {
    Path::new("tests/ip")
}

#[test]
#[cfg(feature = "ipaddr")]
fn ip_1() {
    perform_integration_test_from_json(folder().join("1.json"));
}

#[test]
#[cfg(feature = "ipaddr")]
fn ip_2() {
    perform_integration_test_from_json(folder().join("2.json"));
}

#[test]
#[cfg(feature = "ipaddr")]
fn ip_3() {
    perform_integration_test_from_json(folder().join("3.json"));
}
