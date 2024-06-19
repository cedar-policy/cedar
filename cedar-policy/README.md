# Cedar-Policy

![Cedar Logo](https://raw.githubusercontent.com/cedar-policy/cedar/c1267afab93ed03788d9702da0addbfb8761067f/logo.svg)

Cedar is a language for defining permissions as policies, which describe who should have access to what. It is also a specification for evaluating those policies. Use Cedar policies to control what each user of your application is permitted to do and what resources they may access.

## Using Cedar

Cedar can be used in your application by depending on the [`cedar-policy` crate](https://crates.io/crates/cedar-policy).

Just add `cedar-policy` as a dependency by running

```sh
cargo add cedar-policy
```

## Quick Start

Let's write a super simple Cedar policy and test it:

```cedar
permit(principal == User::"alice", action == Action::"view", resource == File::"93");
```

This policy permits _exactly_ one authorization request, `alice` is allowed to `view` file `93`.
Any other authorization request will be implicitly denied. Let's embed this policy in Rust and use the Cedar Authorizer:

```rust
use cedar_policy::*;

fn main() {
    const POLICY_SRC: &str = r#"
permit(principal == User::"alice", action == Action::"view", resource == File::"93");
"#;
    let policy: PolicySet = POLICY_SRC.parse().unwrap();

    let action = r#"Action::"view""#.parse().unwrap();
    let alice = r#"User::"alice""#.parse().unwrap();
    let file = r#"File::"93""#.parse().unwrap();
    let request = Request::new(alice, action, file, Context::empty(), None).unwrap();

    let entities = Entities::empty();
    let authorizer = Authorizer::new();
    let answer = authorizer.is_authorized(&request, &policy, &entities);

    // Should output `Allow`
    println!("{:?}", answer.decision());

    let action = r#"Action::"view""#.parse().unwrap();
    let bob = r#"User::"bob""#.parse().unwrap();
    let file = r#"File::"93""#.parse().unwrap();
    let request = Request::new(bob, action, file, Context::empty(), None).unwrap();

    let answer = authorizer.is_authorized(&request, &policy, &entities);

    // Should output `Deny`
    println!("{:?}", answer.decision());
}
```

If you'd like to see more details on what can be expressed as Cedar policies, see the [documentation](https://docs.cedarpolicy.com).

Examples of how to use Cedar in an application are contained in the repository [cedar-examples](https://github.com/cedar-policy/cedar-examples). The most full-featured of these is [TinyTodo](https://github.com/cedar-policy/cedar-examples/tree/main/tinytodo), which is a simple task list management service whose users' requests, sent as HTTP messages, are authorized by Cedar.

## Documentation

General documentation for Cedar is available at [docs.cedarpolicy.com](https://docs.cedarpolicy.com), with source code in the [cedar-policy/cedar-docs](https://github.com/cedar-policy/cedar-docs/) repository.

Generated documentation for the latest version of the Rust crates can be accessed
[on docs.rs](https://docs.rs/cedar-policy).

If you're looking to integrate Cedar into a production system, please be sure the read the [security best practices](https://docs.cedarpolicy.com/other/security.html)

## Building

To build, simply run `cargo build` (or `cargo build --release`).

## What's New

Changelogs for all release branches and the `main` branch of this repository are
all maintained on the `main` branch; the most up-to-date changelog for this
crate is
[here](https://github.com/cedar-policy/cedar/blob/main/cedar-policy/CHANGELOG.md).

For a list of the current and past releases, see [crates.io](https://crates.io/crates/cedar-policy) or [Releases](https://github.com/cedar-policy/cedar/releases).

## Security

See [SECURITY](../SECURITY.md)

## Contributing

We welcome contributions from the community. Please either file an issue, or see [CONTRIBUTING](../CONTRIBUTING.md)

## License

This project is licensed under the Apache-2.0 License.
