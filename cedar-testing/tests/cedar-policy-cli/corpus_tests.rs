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

use super::perform_integration_test_from_json;
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
    // As of this writing, runtime to run all of the corpus tests is excessively
    // long.  Until/unless we optimize this somehow, we just run a subset of the
    // corpus tests.  Specifically, we choose all the tests whose hash begins
    // with 0; this should function as a random, but deterministically stable,
    // sample (we still get the same behavior when running `cargo test` twice)
    #[values(
        "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e",
        "0f"
    )]
    prefix: &str,
) {
    for test_json in get_corpus_tests(prefix) {
        println!("testing {}", test_json.display());
        perform_integration_test_from_json(test_json);
    }
}
