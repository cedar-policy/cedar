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


## Crates in this workspace

* [cedar-policy](./cedar-policy) : Main front-end crate for using Cedar in your applications
* [cedar-policy-cli](./cedar-policy-cli) : Crate containing a simple CLI for interacting with Cedar
* [cedar-policy-core](./cedar-policy-core) : Internal crate containing the parser and evaluator
* [cedar-policy-validator](./cedar-policy-validator) : Internal crate containing the Cedar validator 
* [cedar-policy-formatter](./cedar-policy-formatter) : Internal crate containing an auto-formatter for Cedar policies
* [cedar-integration-tests](./cedar-integration-tests) : Crate containing integrations tests

## Building
To build, simply run `cargo build`.

## Examples
If you'd like to see some examples on using Cedar, please see our examples repo [https://github.com/cedar-policy/cedar-examples](cedar-examples)


Specifically the [https://github.com/cedar-policy/cedar-examples/tree/main/tinytodo](Tiny Todo) example shows how to use Cedar policies in a simple HTTP API.


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

