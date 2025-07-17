# Cedar Symbolic Compiler

Converts queries about Cedar polices to SMT queries.

Structure:

`symcc` is the core library. It maps directly to the Lean code.

`lib.rs` is the frontend for `symcc`, and does not directly correspond to the
Lean, but provides an interface in terms of `cedar-policy` types rather than
`cedar-policy-core` and `cedar-policy-validator` types.

# Usage

The Cedar Symbolic Compiler can be used to answer queries about Cedar policies.

TODO: describe high level usage

## Setup

TODO: add info about installing cvc and setting cvc5 environment variable

## Examples

TODO: provide some example use cases