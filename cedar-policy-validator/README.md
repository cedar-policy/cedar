# Cedar Policy Validator

This package contains the validator for Cedar policies.

This package exposes low-level and advanced APIs for Cedar policy validation.
Anyone simply wanting to use Cedar from a Rust client (e.g., to validate that
policies do not contain run time type errors) should use
[`cedar-policy`](../cedar-policy) instead.

## Development

Build and test this crate independently by running `cargo build` and `cargo test`
from this directory. Run these commands from the root directory of this
repository to build and test this package and all other crates in this
repository. Some crates consume this crate as a dependency, so a change here may
precipitate test failures elsewhere.

## Documentation

Generated documentation for the latest version can be accessed
[on docs.rs](https://docs.rs/cedar-policy-validator).
