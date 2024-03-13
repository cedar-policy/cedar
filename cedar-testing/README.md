# Cedar Testing

This package contains utility code for testing `cedar-policy` and `cedar-policy-cli`.
It is used for running integration tests in CI and by our fuzzing infrastructure in [`cedar-spec`](https://github.com/cedar-policy/cedar-spec).

## Running integration tests

The integration tests are run by default in CI (e.g., as a part of each pull request), but you can also run them locally.
In order to do this, you need to have the [`cedar-integration-tests`](https://github.com/cedar-policy/cedar-integration-tests) repository cloned in the top-level directory (`..`).
Then, run `cargo test --features "integration-testing" -- --ignored`.
(Omit `--ignored` if you want to skip the corpus tests.)

```bash
# starting in the top-level directory (..)
git clone https://github.com/cedar-policy/cedar-integration-tests
cd cedar-integration-tests
tar xzf corpus-tests.tar.gz
cd ..
cargo test --features "integration-testing" -- --ignored
```
