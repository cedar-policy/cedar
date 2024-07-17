# Cedar CLI

This package contains the Command Line Interface (CLI) for Cedar.

For more information about the Cedar language/project, please take a look
at [cedarpolicy.com](https://www.cedarpolicy.com).
See also the [`cedar-policy`](../cedar-policy) package, which is the main public Rust API for
Cedar.

This app uses the annotation `@id("PID")` as a simple way to define policy ids.
This usage is not standard and annotations have custom use depending on the app.

## Install

To install the CLI, run `cargo install cedar-policy-cli`.

## Build

You will need to install Rust, via [rustup](https://rustup.rs).

To build the CLI, run `cargo build` or `cargo build --release`.

## Run

Run `cargo run -- --help` to list the available CLI commands.

The [`sample-data`](sample-data) folder contains examples for the CLI. Refer to the instructions in each `README.md` to run the examples.

## What's New

Changelogs for all release branches and the `main` branch of this repository are
all maintained on the `main` branch; the most up-to-date changelog for this
crate is
[here](https://github.com/cedar-policy/cedar/blob/main/cedar-policy-cli/CHANGELOG.md).

For a list of the current and past releases, see [crates.io](https://crates.io/crates/cedar-policy-cli) or [Releases](https://github.com/cedar-policy/cedar/releases).

## Security

See [SECURITY](../SECURITY.md) for more information.

## Contributing

We welcome contributions from the community. Please either file an issue, or see [CONTRIBUTING](../CONTRIBUTING.md)

## License

This project is licensed under the Apache-2.0 License.
