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

//! Tests SymCC on policy sets from the cedar-examples repo.

mod utils;

use std::{collections::HashMap, io::{Cursor, Read}, str::FromStr};

use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
use cedar_policy_symcc::{solver::LocalSolver, CedarSymCompiler};
use rstest::rstest;
use tar::Archive;
use flate2::read::GzDecoder;

use crate::utils::{
    assert_always_allows_ok, assert_always_denies_ok, assert_disjoint_ok, assert_equivalent,
    assert_equivalent_ok, assert_implies, assert_implies_ok, assert_never_errors_ok, Environments,
};

#[rstest]
#[case::document_cloud(
    include_str!("data/cedar-examples/document_cloud/policies.cedar"),
    include_str!("data/cedar-examples/document_cloud/policies.cedarschema"),
)]
#[case::github_example(
    include_str!("data/cedar-examples/github_example/policies.cedar"),
    include_str!("data/cedar-examples/github_example/policies.cedarschema"),
)]
#[case::hotel_chains(
    include_str!("data/cedar-examples/hotel_chains/policies.cedar"),
    include_str!("data/cedar-examples/hotel_chains/policies.cedarschema"),
)]
#[case::sales_orgs(
    include_str!("data/cedar-examples/sales_orgs/policies.cedar"),
    include_str!("data/cedar-examples/sales_orgs/policies.cedarschema"),
)]
#[case::streaming_service(
    include_str!("data/cedar-examples/streaming_service/policies.cedar"),
    include_str!("data/cedar-examples/streaming_service/policies.cedarschema"),
)]
#[case::tags_n_roles(
    include_str!("data/cedar-examples/tags_n_roles/policies.cedar"),
    include_str!("data/cedar-examples/tags_n_roles/policies.cedarschema"),
)]
#[case::tax_preparer(
    include_str!("data/cedar-examples/tax_preparer/policies.cedar"),
    include_str!("data/cedar-examples/tax_preparer/policies.cedarschema"),
)]
#[case::tinytodo(
    include_str!("data/cedar-examples/tinytodo/policies.cedar"),
    include_str!("data/cedar-examples/tinytodo/policies.cedarschema"),
)]
#[tokio::test]
async fn test_cedar_examples(#[case] policy_set_src: &str, #[case] schema_src: &str) {
    let schema = utils::schema_from_cedarstr(schema_src);
    let validator = Validator::new(schema.clone());
    let pset = utils::pset_from_text(policy_set_src, &validator);
    let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
    let envs = Environments::get_all_from_schema(validator.schema());

    for env in &envs {
        // Sanity checks to make sure various verification tasks do not error
        // and produce valid counterexamples if they exist.

        assert_always_allows_ok(&mut compiler, &pset, env).await;
        assert_always_denies_ok(&mut compiler, &pset, env).await;
        assert_implies(&mut compiler, &pset, &pset, env).await;
        assert_equivalent(&mut compiler, &pset, &pset, env).await;

        for policy1 in pset.policies() {
            let pset1 = PolicySet::from_policies(std::iter::once(policy1.clone())).unwrap();
            assert_never_errors_ok(&mut compiler, &policy1, env).await;
            assert_always_allows_ok(&mut compiler, &pset1, env).await;
            assert_always_denies_ok(&mut compiler, &pset1, env).await;
            assert_implies(&mut compiler, &pset1, &pset1, env).await;
            assert_equivalent(&mut compiler, &pset1, &pset1, env).await;

            for policy2 in pset.policies() {
                let pset2 = PolicySet::from_policies(std::iter::once(policy2.clone())).unwrap();
                assert_implies_ok(&mut compiler, &pset1, &pset2, env).await;
                assert_equivalent_ok(&mut compiler, &pset1, &pset2, env).await;
                assert_disjoint_ok(&mut compiler, &pset1, &pset2, env).await;
            }
        }
    }
}

struct CorpusTest {
    name: String,
    schema_src: String,
    pset_src: String,
}

/// Load randomly generated corpus tests from cedar-integration-tests
/// https://github.com/cedar-policy/cedar-integration-tests/blob/858d8bdc9ad4abd41020544f798a327bcf741b7e/corpus-tests.tar.gz
fn load_corpus_tests() -> Vec<CorpusTest> {
    // TODO: if this gets too large, maybe load it dynamically
    const CORPUS_TESTS_ARCHIVE: &[u8] = include_bytes!("data/corpus-tests.tar.gz");

    // Remove tests with the following keywords
    const FILTER_KEYWORDS: &[&str] = &[
        // // Special characters
        // // TODO: fix cvc5 parsing issue with these characters
        // "\\u{",
        // "\\0",
        // "\\t",
        // "\\n",
        // "\\\"",
        // // Unsupported extensions
        // "::datetime",
        // "::duration",
    ];

    // Final validated list of tests
    let mut tests = Vec::new();

    // Decompress in memory
    let cursor = Cursor::new(CORPUS_TESTS_ARCHIVE);
    let decompressed = GzDecoder::new(cursor);
    let mut archive = Archive::new(decompressed);

    // Maps corpus test hash to contents
    let mut schema_sources = HashMap::new();
    let mut pset_sources = HashMap::new();

    // Find all .cedar and .cedarschema files in the archive
    for entry in archive.entries().unwrap() {
        let mut file = entry.unwrap();
        let path = file.path().unwrap();

        // Skip directories
        if path.is_dir() {
            continue;
        }

        if path.extension().and_then(|s| s.to_str()) == Some("cedar") {
            let name = path.file_stem().unwrap().to_str().unwrap().to_string();
            let mut src = String::new();
            file.read_to_string(&mut src).unwrap();
            pset_sources.insert(name, src);
        } else if path.extension().and_then(|s| s.to_str()) == Some("cedarschema") {
            let name = path.file_stem().unwrap().to_str().unwrap().to_string();
            let mut src = String::new();
            file.read_to_string(&mut src).unwrap();
            schema_sources.insert(name, src);
        }
    }

    'outer: for (name, schema_src) in schema_sources {
        let Some(pset_src) = pset_sources.get(&name) else {
            // Skip if no corresponding policy set
            continue;
        };

        // Skip if found a filter keyword
        for keyword in FILTER_KEYWORDS {
            if schema_src.contains(keyword) || pset_src.contains(keyword) {
                continue 'outer;
            }
        }

        // Parse and validate the schema and policy set
        // ignore ones that fail to parse/validate
        let Ok(schema) = Schema::from_cedarschema_str(&schema_src) else {
            continue;
        };
        let schema = schema.0;
        let validator = Validator::new(schema.clone());
        let Ok(pset) = PolicySet::from_str(&pset_src) else {
            continue;
        };

        let res = validator.validate(&pset, ValidationMode::Strict);
        if !res.validation_passed() {
            continue;
        }

        tests.push(CorpusTest {
            name,
            schema_src,
            pset_src: pset_src.clone(),
        });
    }

    tests
}

#[tokio::test]
async fn test_corpus_tests() {
    let tests = load_corpus_tests();

    for test in tests {
        eprintln!("Running corpus test: {}", test.name);
        test_cedar_examples(&test.pset_src, &test.schema_src).await;
    }
}
