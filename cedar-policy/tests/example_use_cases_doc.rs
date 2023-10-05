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
#[should_panic(
    expected = "error occurred while evaluating policy `policy0`: entity `Action::\\\"view\\\"` does not exist"
)]
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
