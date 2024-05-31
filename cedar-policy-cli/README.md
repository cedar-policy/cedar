# Cedar CLI

This package contains the Command Line Interface (CLI) for Cedar.

For more information about the Cedar language/project, please take a look
at [cedarpolicy.com](https://www.cedarpolicy.com).
See also the [`cedar-policy`](../cedar-policy) package, which is the main public Rust API for
Cedar.

This app uses the annotation `@id("PID")` as a simple way to define policy ids.
This usage is not standard and annotations have custom use depending on the app.

## Usage

CLI is a command line tool. It supports the following subcommands:
 * authorize:      Evaluate an authorization request
 * evaluate:       Evaluate a Cedar expression
 * validate:       Validate a policy set against a schema
 * check-parse:    Check that policies successfully parse
 * link:           Link a template
 * format:         Format a policy set
 * help:           Print this message or the help of the given subcommand(s)

### Build

You will need to install Rust, via [rustup](https://rustup.rs).

To build the CLI, run `cargo build` or `cargo build --release`.

### Run

To run the CLI, try `cargo run -- --help`. The sub-folder [`sample-data`](sample-data) contains examples for the CLI. Please refer to the instructions in each `README.md` to run the examples.

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
