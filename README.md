# Cedar

![Cedar Logo](./logo.svg)

[![Crates.io](https://img.shields.io/crates/v/cedar-policy.svg)](https://crates.io/crates/cedar-policy)
[![docs.rs](https://img.shields.io/docsrs/cedar-policy)](https://docs.rs/cedar-policy/latest/cedar_policy/)
![nightly](https://github.com/cedar-policy/cedar/actions/workflows/nightly_build.yml/badge.svg)

This repository contains source code of the Rust crates that implement the [Cedar](https://www.cedarpolicy.com/) policy language.

Cedar is a language for writing and enforcing authorization policies in your applications. Using Cedar, you can write policies that specify your applications' fine-grained permissions. Your applications then authorize access requests by calling Cedar's authorization engine. Because Cedar policies are separate from application code, they can be independently authored, updated, analyzed, and audited. You can use Cedar's validator to check that Cedar policies are consistent with a declared schema which defines your application's authorization model.

Cedar is:
### Expressive
Cedar is a simple yet expressive language that is purpose-built to support authorization use cases for common authorization models such as RBAC and ABAC.
### Performant
Cedar is fast and scalable. The policy structure is designed to be indexed for quick retrieval and to support fast and scalable real-time evaluation, with bounded latency.
### Analyzable
Cedar is designed for analysis using Automated Reasoning. This enables analyzer tools capable of optimizing your policies and proving that your security model is what you believe it is.

## Using Cedar
Cedar can be used in your application by depending on the `cedar-policy` crate.

Just add `cedar-policy` as a dependency in your `Cargo.toml`:
```toml
[dependencies]
cedar-policy = "2.0"
```
## Crates in this workspace

* [cedar-policy](./cedar-policy) : Main crate for using Cedar to authorize access requests in your applications, and validate Cedar policies against a schema
* [cedar-policy-cli](./cedar-policy-cli) : Crate containing a simple command-line interface (CLI) for interacting with Cedar
* [cedar-policy-core](./cedar-policy-core) : Internal crate containing the Cedar parser and evaluator
* [cedar-policy-validator](./cedar-policy-validator) : Internal crate containing the Cedar validator
* [cedar-policy-formatter](./cedar-policy-formatter) : Internal crate containing an auto-formatter for Cedar policies
* [cedar-integration-tests](./cedar-integration-tests) : Crate containing integration tests

## Quick Start

Let's put the policy in policy.cedar and the entities in entities.json:

policy.cedar
```
permit (
  principal == User::"alice",
  action == Action::"view",
  resource in Album::"jane_vacation"
);
```
This policy specifies that `alice` is allowed to view the photos in the `"jane_vacation"` album.

entities.json
```json
[
    {
        "uid": { "type": "User", "id": "alice"} ,
        "attrs": {"age": 18},
        "parents": []
    },
    {
        "uid": { "type": "Photo", "id": "VacationPhoto94.jpg"},
        "attrs": {},
        "parents": [{ "type": "Album", "id": "jane_vacation" }]
    }
]

```
Cedar represents principals, resources, and actions as entities. An entity has a type (e.g., `User`) and an id (e.g., `alice`). They can also have attributes (e.g., `User::"alice"`'s `age` attribute is the integer `18`).

Now, let's test our policy with the CLI
```rust
 cargo run authorize \
    --policies policy.cedar \
    --entities entities.json \
    --principal 'User::"alice"' \
    --action 'Action::"view"' \
    --resource 'Photo::"VacationPhoto94.jpg"'
```

CLI output:
```
ALLOW
```
It is allowed because `VacationPhoto94.jpg` belongs to `Album::"jane_vacation"`, and `alice` can view photos in `Album::"jane_vacation"`.

If you'd like to see more details on what can be expressed as Cedar policies, see the [documentation](https://docs.cedarpolicy.com/what-is-cedar.html).

Examples of how to use Cedar in an application are contained in the repository [cedar-examples](https://github.com/cedar-policy/cedar-examples). [TinyTodo](https://github.com/cedar-policy/cedar-examples/tree/main/tinytodo) is a simple task list management app whose users' requests, sent as HTTP messages, are authorized by Cedar. It shows how you can integrate Cedar into your own Rust program.

## Documentation

General documentation for Cedar is available at [docs.cedarpolicy.com](https://docs.cedarpolicy.com), with docs source code in the [cedar-policy/cedar-docs](https://github.com/cedar-policy/cedar-docs/) repository.

Generated documentation for the latest version of the Rust crates can be accessed
[on docs.rs](https://docs.rs/cedar-policy).

## Building

To build, simply run `cargo build` (or `cargo build --release`).

## Security

See [SECURITY](SECURITY.md) for more information.

## Contributing

We welcome contributions from the community. Please either file an issue, or see [CONTRIBUTING](CONTRIBUTING.md)

## License

This project is licensed under the Apache-2.0 License.
