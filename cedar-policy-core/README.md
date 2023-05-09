# Cedar Policy Core

This package contains the Cedar parser and evaluation engine.

This package exposes low-level and advanced Cedar APIs, e.g.,
for interacting with policy ASTs directly.
Anyone simply wanting to use Cedar from a Rust client (e.g.,
to make authorization decisions) should use
[`cedar-policy`](../cedar-policy) instead.

For more information about the Cedar language/project, please take a look
at [cedarpolicy.com](https://www.cedarpolicy.com).

## Development

Build and test this crate independently by running `cargo build` and `cargo test`
from this directory. Run these commands from the root directory of this
repository to build and test this package and all other crates in this
repository. This crate is consumed either directly or indirectly by all other
crates in this repository, so a change here may precipitate test failures
elsewhere.

## Documentation

Generated documentation for the latest version can be accessed
[on docs.rs](https://docs.rs/cedar-policy-core).
