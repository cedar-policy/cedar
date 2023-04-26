//! These integration tests are auto-generated using the differential tester.
//! See notes in CedarDRT.
//!
//! The test files themselves exist separately in the
//! `CedarIntegrationTests` package.

use cedar_policy::integration_testing::perform_integration_test_from_json;
use cedar_policy::integration_testing::resolve_integration_test_path;
use std::path::Path;
#[cfg(feature = "corpus-timing")]
use std::time::Instant;

#[cfg(feature = "heap-profiling")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Path of the folder containing the corpus tests
fn folder() -> &'static Path {
    Path::new("corpus_tests")
}

// for now we have a single #[test] that runs all the corpus tests.
// The disadvantage of this is that only one error message will be displayed,
// even if many of the corpus tests fail.
// TODO for the future: figure out if we can procedurally generate one #[test]
// per corpus test.
#[test]
// Don't run the corpus tests by default because they can take a minute to
// complete, slowing things down substantially.
#[ignore]
fn corpus_tests() {
    #[cfg(feature = "heap-profiling")]
    let _profiler = dhat::Profiler::new_heap();
    let corpus_tests_folder = resolve_integration_test_path(folder());
    let test_jsons = std::fs::read_dir(&corpus_tests_folder)
        .unwrap_or_else(|e| {
            panic!(
                "failed to read corpus_tests folder {}: {e}",
                corpus_tests_folder.display()
            )
        })
        .map(|e| e.expect("failed to access file in corpus_tests").path())
        // ignore non-JSON files
        .filter(|p| {
            p.extension()
                .map(|ext| ext.eq_ignore_ascii_case("json"))
                .unwrap_or(false)
        })
        // ignore files that start with policies_, entities_, or schema_
        .filter(|p| {
            let filename = p
                .file_name()
                .expect("didn't expect subdirectories in corpus_tests")
                .to_str()
                .expect("expected filenames to be valid UTF-8");
            !filename.starts_with("policies_")
                && !filename.starts_with("entities_")
                && !filename.starts_with("schema_")
        });
    #[cfg(feature = "corpus-timing")]
    let mut sum_micros = 0;
    #[cfg(feature = "corpus-timing")]
    let mut count = 0;
    for test_json in test_jsons {
        #[cfg(feature = "corpus-timing")]
        let start = Instant::now();
        perform_integration_test_from_json(test_json);
        #[cfg(feature = "corpus-timing")]
        {
            let elapsed = start.elapsed().as_micros();
            sum_micros += elapsed;
            count += 1;
        }
    }
    #[cfg(feature = "corpus-timing")]
    println!(
        "Average corpus test duration (micros): {}",
        sum_micros / count
    );
}
