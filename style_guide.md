# Cedar Style Guide

Cedar relies on automated tooling for the majority of its code style enforcement.
Code must be formatted as enforced by `cargo fmt`, there must not be any `unsafe` code, `cargo check` must not report any warnings, and `cargo clippy` must not report any errors (clippy warnings are acceptable).
These are all enforced in our GitHub Actions workflows, so any violation will be reported to you upon opening a pull request.

The rest of this guide describes some aspects of style which are not automatically enforced.

## Conventions for Cedar Documentation

Everything publicly exported from `cedar-policy` (functions, types, modules, etc.) must be documented with a doc comment (a comment delimited by `///`).
There is no minimum standard for the length of documentation. A comment may be as short as a single sentence fragment.

**Capitalization:** Doc comments (sentence fragments or otherwise) should always begin with a capital letter.

**Punctuation:** Sentence fragments (e.g., ``Errors that can occur when adding to a `PolicySet` ``) do not need a period, but
proper sentences (e.g., ``There was a duplicate `PolicyId` encountered in either the set of templates or the set of policies.``) do.
In the case of a mixture of sentence fragments and full sentences, use periods.

**Invariants:** We often document internal invariants in our code with `// INVARIANT: ` comments.
These invariants should not generally be included in doc comments, i.e., they should start with `//` instead of `///`.

**Other:** When describing an identifier, use "id", not "Id" or "ID" (applies to both doc strings and error messages).

## Conventions for Cedar Errors

### Error Types

Methods that can return errors should return a `Result` type where the error type is a public enum.
Each variant of that enum should be either another error enum or a single struct with private field(s).
The structs for a particular error enum are typically gathered into a submodule.
The names of all error enums and structs should end in `Error`, but each variant of an error enum should not end in `Error`.

Error enums are often annotated with `#[non_exhaustive]`, though we omit this annotation when we feel callers _should_ have their build break when we introduce new error variants.
For example, `#[non_exhaustive]` should never be used for `EvaluationError` or other errors that are returned from the `is_authorized` API, but parsing and validation errors generally should be `#[non_exhaustive]`.

The enum itself, and also each of the member structs, should implement `miette::Diagnostic` and `thiserror::Error`.
Both of these should be automatically derived when possible, and the `#[error(...)]` macro should be used to generate `Display` implementations.
For more complex errors, it is occasionally easier to manually implement `Display`.
Manual implementation of `miette::Diagnostic` is less common but is occasionally necessary to work around limitations in the derive macro.
We use [a module of internal macros](https://github.com/cedar-policy/cedar/blob/main/cedar-policy-core/src/error_macros.rs) to help in these situations.

By ensuring the internal structs have private fields, we are free to change details in the error without making a breaking change to our API.
The enum and all member structs may also provide additional public methods to expose certain details.
We are generally conservative in what we expose this way to make future changes to our error types easier.

For example, `RequestValidationError` is an enum with each variant containing a struct like `UndeclaredActionError`.

```rust
/// The request does not conform to the schema
#[derive(Debug, Diagnostic, Error)]
#[non_exhaustive]
pub enum RequestValidationError {
    /// Request action is not declared in the schema
    #[error(transparent)]
    #[diagnostic(transparent)]
    UndeclaredAction(#[from] request_validation_errors::UndeclaredActionError),

    // more error variants...
}

/// Error subtypes for [`RequestValidationError`]
pub mod request_validation_errors {
    /// Request action is not declared in the schema
    #[derive(Debug, Diagnostic, Error)]
    #[error(transparent)]
    #[diagnostic(transparent)]
    pub struct UndeclaredActionError(
        #[from] cedar_policy_core::validator::request_validation_errors::UndeclaredActionError,
    );

    impl UndeclaredActionError {
        /// The action which was not declared in the schema
        pub fn action(&self) -> &EntityUid {
            RefCast::ref_cast(self.0.action())
        }
    }

    // more error structs...
}
```

See [issue #745](https://github.com/cedar-policy/cedar/issues/745) for further discussion and alternatives considered.

### Error Documentation

Error type documentation follows the same conventions as documentation on other types.
Each error needs to be documented twice (once on the enum variant and again on the struct).
To avoid duplicating large comments, we prefer to place detailed documentation on the enum variant with a shorter comment on the struct.

### Error Messages

* Single-sentence error messages should not use capitalization or periods.
  If multiple sentences are needed, then use grammatical capitalization and punctuation only on the message's interior.
  Example: `wrong number of arguments in extension function application. Expected {}, got {}` (note the initial lowercase letter and lack of final period).
* Strongly consider breaking multi-sentence error messages into a main error message together with a [help message](https://docs.rs/miette/latest/miette/#-help-text) and [labeled snippets](https://docs.rs/miette/latest/miette/#-snippets).
  These should independently follow the recommendations for error message punctuation and capitalization.
* User-provided input (e.g., attributes, entity uids, policy ids) should be surrounded with backticks or be placed after a colon at the end of the message. Use of backticks is preferred. Examples: ``undeclared action `foo` ``, `undeclared entity type(s): {"Foo"}`.
* Whenever possible, include a [source span](https://docs.rs/miette/latest/miette/#-snippets) indicating where in the input the error occurred. Consider if this span adequately replaces any verbatim copies of user-provided input included in the error message.
* Related error messages should be concatenated with colons. Example: ``error occurred while evaluating policy `policy0`: `User::"alive"` does not have the attribute `foo` ``.
* Error messages should not refer to specific Rust type names (like `PolicyId`), preferring to refer to generic Cedar concepts (like policy id). Remember that these errors will be viewed by Cedar users who may never interact directly with the Rust library.
* Error messages must not include line breaks.
