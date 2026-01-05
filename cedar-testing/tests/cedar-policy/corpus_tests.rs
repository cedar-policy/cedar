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

//! Integration tests auto-generated using the differential tester.

use cedar_testing::integration_testing::perform_integration_test_from_json;
use cedar_testing::test_files::get_corpus_tests;
use rstest::rstest;

// for now we have a single #[test] that runs all the corpus tests.
// The disadvantage of this is that only one error message will be displayed,
// even if many of the corpus tests fail.
#[rstest]
// Don't run the corpus tests by default because they can take a minute to
// complete, slowing things down substantially.
#[ignore]
#[expect(clippy::panic, reason = "Corpus Tests")]
fn corpus_tests(
    // TODO(#438): rstest can use a glob to have one test for each matching
    // file, but we're dynamically resolving the corpus test folder, so this
    // doesn't work.
    #[values(
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"
    )]
    prefix: &str,
) {
    for test_json in get_corpus_tests(prefix) {
        perform_integration_test_from_json(test_json);
    }
}
