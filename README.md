# Cedar

![Cedar Logo](./logo.svg)

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

### Installing Rust
Install Rust and its build system via [rustup](https://rustup.rs).

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

Let's write a super simple Cedar policy and test it:
```
permit(principal == User::"alice", action == Action::"view", resource == File::"93");
```
This policy permits _exactly_ one authorization request, `alice` is allowed to `view` file `93`. 
Any other authorization request will be implicitly denied. Let's embed this policy in Rust and use the Cedar Authorizer:

```rust
    const POLICY_SRC: &str = r#"
permit(principal == User::"alice", action == Action::"view", resource == File::"93");
"#;
    let policy: PolicySet = POLICY_SRC.parse().unwrap();
    let alice = r#"User::"alice""#.parse().unwrap();
    let action = r#"Action::"view""#.parse().unwrap();
    let file = r#"File::"93""#.parse().unwrap();

    let entities = Entities::empty();

    let request = Request::new(Some(alice), Some(action), Some(file), Context::empty());

    let authorizer = Authorizer::new();
    let answer = authorizer.is_authorized(&request, &policy, &entities);

    // Should give us ALLOW
    println!("{:?}", answer.decision());

    let bob: EntityUid = r#"User::"bob""#.parse().unwrap();
    let action = r#"Action::"view""#.parse().unwrap();
    let file = r#"File::"93""#.parse().unwrap();
    let request = Request::new(Some(bob), Some(action), Some(file), Context::empty());
    let answer = authorizer.is_authorized(&request, &policy, &entities);
    // Should give us DENY
    println!("{:?}", answer.decision());
}
```

If you'd like to see more details on what can be expressed as Cedar policies, see the [documentation](https://docs.cedarpolicy.com/what-is-cedar.html).

Examples of how to use Cedar in an application are contained in the repository [cedar-examples](https://github.com/cedar-policy/cedar-examples). The most full-featured of these is [TinyTodo](https://github.com/cedar-policy/cedar-examples/tree/main/tinytodo), which is a simple task list management service whose users' requests, sent as HTTP messages, are authorized by Cedar.

## Documentation

General documentation for Cedar is available at [docs.cedarpolicy.com](https://docs.cedarpolicy.com), with docs source code in the [cedar-policy/cedar-docs](https://github.com/cedar-policy/cedar-docs/) repository.

Generated documentation for the latest version of the Rust crates can be accessed
[on docs.rs](https://docs.rs/cedar-policy).

## Building

To build, simply run `cargo build`.

## Security

See [security](security.md) for more information.

## Contributing

We welcome contribututions from the community. Please either file an issue, or see [CONTRIBUTING](CONTRIBUTING.md)

## License

This project is licensed under the Apache-2.0 License.

