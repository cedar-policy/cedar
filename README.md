# Cedar

![Cedar Logo](./logo.svg)


Repo containing the crates for the Rust implementation of the [Cedar](https://www.cedarpolicy.com/) policy language.

Cedar is a language for defining permissions as policies, which describe who should have access to what. It is also a specification for evaluating those policies. Use Cedar policies to control what each user of your application is permitted to do and what resources they may access.


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

* [cedar-policy](./cedar-policy) : Main front-end crate for using Cedar in your applications
* [cedar-policy-cli](./cedar-policy-cli) : Crate containing a simple CLI for interacting with Cedar
* [cedar-policy-core](./cedar-policy-core) : Internal crate containing the parser and evaluator
* [cedar-policy-validator](./cedar-policy-validator) : Internal crate containing the Cedar validator 
* [cedar-policy-formatter](./cedar-policy-formatter) : Internal crate containing an auto-formatter for Cedar policies
* [cedar-integration-tests](./cedar-integration-tests) : Crate containing integrations tests





## Examples

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

If you'd like to see more details on what can be expressed as Cedar policies, see [https://docs.cedarpolicy.com/what-is-cedar.html](the documentations).

If you'd like to see more examples on using Cedar, please see our examples repo [https://github.com/cedar-policy/cedar-examples](cedar-examples).


Specifically the [https://github.com/cedar-policy/cedar-examples/tree/main/tinytodo](Tiny Todo) example shows how to use Cedar policies in a simple HTTP API.

## Documentation

General documentation for Cedar is available at [https://docs.cedarpolicy.com](docs.cedarpolicy.com).

Generated documentation for the latest version can be accessed
[on docs.rs](https://docs.rs/cedar-policy).

## Building
To build, simply run `cargo build`.


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## Contributing

We welcome contribututions from the community. Please either file an issue, or see [CONTRIBUTING](CONTRIBUTING.md)

## License

This project is licensed under the Apache-2.0 License.

