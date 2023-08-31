# Cedar Policy Formatter

This package contains a simple formatter library for Cedar policies based on the [`pretty`](https://docs.rs/pretty/latest/pretty/index.html#) crate. We integrate it into [Cedar CLI](../cedar-policy-cli) so that you can format your Cedar policies directly. You can also use it as a library in your Cedar applications.

Please share your opinions about the format using a [feature request](https://github.com/cedar-policy/cedar/issues/new?assignees=&labels=pending-triage&template=feature_request.yml). And report any bugs you find using a [bug report](https://github.com/cedar-policy/cedar/issues/new?assignees=&labels=pending-triage&template=bug_report.yml).

## Quick Start
The easiest way to format your Cedar policies is via [Cedar CLI](../cedar-policy-cli)'s `format` subcommand.

```shell
# Default indentation is two spaces.
# Default line width is 80.
cedar format my-policies.cedar
# I want more indentation.
cedar format -i 4 my-policies.cedar
# I like shorter lines.
cedar format -l 40 my-policies.cedar
```

## Usage

### Build

To build, simply run `cargo build` (or `cargo build --release`).

### Run
The formatter is invoked via [Cedar CLI](../cedar-policy-cli)'s `format` subcommand. Its options can be found using the following command.

```shell
cedar format -h
```

## Documentation

Generated documentation for the latest version can be accessed on
[docs.rs](https://docs.rs/cedar-policy-formatter).
