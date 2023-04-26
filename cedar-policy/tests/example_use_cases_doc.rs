use cedar_policy::integration_testing::perform_integration_test_from_json;
use std::path::Path;

/// Path of the folder containing the JSON tests
fn folder() -> &'static Path {
    Path::new("tests/example_use_cases_doc")
}

#[test]
fn scenario_1a() {
    perform_integration_test_from_json(folder().join("1a.json"));
}

#[test]
fn scenario_2a() {
    perform_integration_test_from_json(folder().join("2a.json"));
}

#[test]
fn scenario_2b() {
    perform_integration_test_from_json(folder().join("2b.json"));
}

#[test]
fn scenario_2c() {
    perform_integration_test_from_json(folder().join("2c.json"));
}

// note: 2d and 2e currently omitted, mostly to avoid cluttering the entity
// hierarchy in sandbox_a (which is used in the introductory CLI sandbox)

#[test]
fn scenario_3a() {
    perform_integration_test_from_json(folder().join("3a.json"));
}

#[test]
fn scenario_3b() {
    perform_integration_test_from_json(folder().join("3b.json"));
}

#[test]
fn scenario_3c() {
    perform_integration_test_from_json(folder().join("3c.json"));
}

#[test]
fn scenario_4a() {
    perform_integration_test_from_json(folder().join("4a.json"));
}

// note: 4b currently omitted because it requires date/timestamp functionality

/// currently failing, as the validator does not support action attributes
#[should_panic]
#[test]
fn scenario_4c() {
    perform_integration_test_from_json(folder().join("4c.json"));
}

#[test]
fn scenario_4d() {
    perform_integration_test_from_json(folder().join("4d.json"));
}

#[test]
fn scenario_4e() {
    perform_integration_test_from_json(folder().join("4e.json"));
}

#[test]
fn scenario_4f() {
    perform_integration_test_from_json(folder().join("4f.json"));
}

// note: 5a currently omitted because IP-related tests are covered in a separate folder

#[test]
fn scenario_5b() {
    perform_integration_test_from_json(folder().join("5b.json"));
}

// note: 6a and 6b currently omitted because they require date/timestamp functionality
// note: 6c currently omitted because it's covered instead in multi/3.json. Tests with
// only a forbid policy, and no permit policies, wouldn't be terribly enlightening

// note: 7c currently omitted because it requires date/timestamp functionality
