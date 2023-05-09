# Cedar-Policy

![Cedar Logo](../logo.svg)

Cedar is a language for defining permissions as policies, which describe who should have access to what. It is also a specification for evaluating those policies. Use Cedar policies to control what each user of your application is permitted to do and what resources they may access.

## Using Cedar
Cedar can be used in your application by depending on the `cedar-policy` crate.

Just add `cedar-policy` as a dependency in your `Cargo.toml`:
```toml
[dependencies]
cedar-policy = "2.0"
```


## Quick Start

Let's write a super simple Cedar policy and test it:
policy.txt
```
permit (
  principal == User::"alice",
  action == Action::"view",
  resource == Photo::"VacationPhoto94.jpg"
);
```
This policy permits _exactly_ one authorization request, `alice` is allowed to `view` the photo `Photo::"VacationPhoto94.jpg"`. 
Any other authorization request will be implicitly denied. Let's test it with the CLI

```rust
cargo run  authorize \             
    --policies policy.txt \
    --entities entity.json \
    --principal 'User::"alice"' \
    --action 'Action::"view"' \
    --resource 'Photo::"VacationPhoto94.jpg"'
```
CLI output: 
```
ALLOW
```

If you'd like to see more details on what can be expressed as Cedar policies, see the [documentation](https://docs.cedarpolicy.com/what-is-cedar.html).

Examples of how to use Cedar in an application are contained in the repository [cedar-examples](https://github.com/cedar-policy/cedar-examples). The most full-featured of these is [TinyTodo](https://github
.com/cedar-policy/cedar-examples/tree/main/tinytodo), which is a simple task list management service whose users' requests, sent as HTTP messages, are authorized by Cedar.


## Documentation

General documentation for Cedar is available at [docs.cedarpolicy.com](https://docs.cedarpolicy.com), with docs source code in the [cedar-policy/cedar-docs](https://github.com/cedar-policy/cedar-docs/) rep
ository.

Generated documentation for the latest version of the Rust crates can be accesse
[on docs.rs](https://docs.rs/cedar-policy).

## Building
To build, simply run `cargo build`.


## Security

See [security](../security.md)

## Contributing

We welcome contribututions from the community. Please either file an issue, or see [CONTRIBUTING](CONTRIBUTING.md)

## License

This project is licensed under the Apache-2.0 License.

