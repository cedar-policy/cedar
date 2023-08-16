# Changelog

## Unreleased

- Move public API for partial evaluation behind experimental feature flag.
- Added an option to eagerly evaluate entity attributes and re-use across calls to `is_authorized`
- Revamped errors in cst-to-ast transformation
- Adds APIs to `Entities` to make it easy to add a collection of entities to an existing `Entities` structure

### Added

- Export `entities::EntitiesError` error type.
- New methods exported for `EntityTypeName`.
  - `basename` to get the basename (without namespaces).
  - `namespace_components` to get the namespace as an iterator over its components.
  - `namespace` to get the namespace as a single string.
- Fixed bug (#150) around implicit namespaces in action definitions.
- Support `Request`s with `Unknown` fields for partial evaluation.
- Export the `cedar_policy_core::evaluator::{EvaluationError, EvaluationErrorKind}` and
  `cedar_policy_core::authorizer::AuthorizationError` error types.

### Changed

- Added list of attributes that do exist to `RecordAttrDoesNotExist` error message.
- Removed deprecated `__expr` escapes from integration tests.
- Improved error detection in schema based parsing (fix issues #73, #74).
  - Detect entities with parents of an incorrect entity type.
  - Detect entities with an undeclared entity type.
- Slightly improved error text on some validation type errors
- Improved error messages for some schema type parsing errors
  - When an entity type shape or action context is declared with type other
    than `Record`, the error message will indicate the effected entity type or
    action.
  - Parsing a schema type without the `"type"` field will generate an error
    stating that `"type"` is a required field instead of an inscrutable error
    complaining about the untagged enum `SchemaType`.
  - Parsing a schema type with a `"type"` field corresponding to one of the
    builtin types but missing a required field for that type will generate an
    error stating that a required field is missing instead of claiming that it
    could not find "common types" definition for that builtin type.
- Some error types now carry more information about the error, with error
  messages updated appropriately
- Update how record types are treated by the validator to support "open" and
  "closed" record types.  Record types written in schema are now closed. In
  particular, this applies to the action context, so `context has attr` can now
  have type False where before it had type Boolean, creating some new
  short-circuiting opportunities.  The same applies to record literals.
- Improved error messages and documentation for some errors raised during
  policy evaluation.
- Fix a panic in `PolicySet::link` that could occur when the function was called
  with a policy id corresponding to a static policy.
- Renamed `cedar_policy_core::est::EstToAstError` to `cedar_policy_core::est::FromJsonError`
- More precise "expected tokens" lists in some parse errors
- Renamed `cedar_policy_core::entities::JsonDeserializationError::ExtensionsError` to `cedar_policy_core::entities::JsonDeserializationError::FailedExtensionsFunctionLookup`.
- Renamed variants in `cedar_policy::SchemaError`
- The `Diagnostics::errors()` function now returns an iterator over `AuthorizationError`s.
- The `Response::new()` constructor now expects a `Vec<AuthorizationError>` as its third argument.

## 2.3.0

### Changed

- Implementation of
[RFC 9](https://github.com/cedar-policy/rfcs/blob/main/text/0009-disallow-whitespace-in-entityuid.md)
which disallows embedded whitespace, comments, and control characters in the
inputs to several Rust API functions including `EntityTypeName::from_str()` and
`EntityNamespace::from_str()`, as well as in some fields of the Cedar JSON
schema format (e.g., namespace declarations, entity type names), Cedar JSON
entities format (e.g., entity type names, extension function names) and the
Cedar JSON policy format used by `Policy::from_json()` (e.g., entity type names,
extension function names). The risk that this may be a breaking change for some
Cedar users was accepted due to the potential security ramifications; see
discussion in the RFC.

## 2.2.0

### Added

- `Entities::write_to_json` function to api.rs

## 2.1.0

### Added

- `Schema::action_entities` to provide access to action entities defined in a schema.

### Changed

- Update `cedar-policy-core` dependency.

### Fixed

- Resolve warning in `Cargo.toml` due to having both `license` and `license-file` metadata entries.

## 2.0.3

### Fixed

- Update `Cargo.toml` metadata to correctly represent this crate as Apache-2.0 licensed.

## 2.0.2

## 2.0.1

## 2.0.0

Initial release of `cedar-policy`.
