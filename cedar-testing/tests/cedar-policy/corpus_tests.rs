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

//! Integration tests auto-generated using the differential tester.

use crate::integration_testing::perform_integration_test_from_json;
use crate::integration_testing::resolve_integration_test_path;
use std::path::Path;

/// Path of the folder containing the corpus tests
fn folder() -> &'static Path {
    Path::new("corpus_tests")
}

// PANIC SAFETY: Corpus Tests
#[allow(clippy::panic)]
// for now we have a single #[test] that runs all the corpus tests.
// The disadvantage of this is that only one error message will be displayed,
// even if many of the corpus tests fail.
// TODO(#438): figure out if we can procedurally generate one #[test]
// per corpus test.
#[test]
// Don't run the corpus tests by default because they can take a minute to
// complete, slowing things down substantially.
#[ignore]
fn corpus_tests() {
    let corpus_tests_folder = resolve_integration_test_path(folder());
    let test_jsons = std::fs::read_dir(&corpus_tests_folder)
        .unwrap_or_else(|e| {
            panic!(
                "failed to read corpus_tests folder {}: {e}",
                corpus_tests_folder.display()
            )
        })
        .map(|e| e.expect("failed to access file in corpus_tests").path())
        .filter(|p| {
            let filename = p
                .file_name()
                .expect("didn't expect subdirectories in corpus_tests")
                .to_str()
                .expect("expected filenames to be valid UTF-8");
            filename.ends_with(".json") && !filename.starts_with("schema_")
        });
    for test_json in test_jsons {
        perform_integration_test_from_json(test_json);
    }
}
