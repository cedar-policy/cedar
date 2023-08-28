# Changelog

## Unreleased

### Added

- New methods exported for `EntityTypeName`.
  - `basename` to get the basename (without namespaces).
  - `namespace_components` to get the namespace as an iterator over its components.
  - `namespace` to get the namespace as a single string.

### Changed
- Some error types now carry more information about the error, with error
  messages updated appropriately
- Renamed `cedar_policy_core::est::EstToAstError` to `cedar_policy_core::est::FromJsonError`

## 2.3.3

### Added
- Re-export `cedar_policy_core::entities::EntitiesError`.
- Fixed bug (#150) around implicit namespaces for actions in `memberOf` lists in
  schemas. An action without an explicit namespace in a `memberOf` now
  correctly uses the default namespace.

### Changed
- Improved error messages and documentation for some errors raised during
  policy parsing, validation, and evaluation.
- More precise "expected tokens" lists in some parse errors.

## 2.3.2

### Removed
- Move public API for partial evaluation behind experimental feature flag. To
  continue using this feature you must enable the `partial-eval` feature flag.

### Changed

- Added list of attributes that do exist to `RecordAttrDoesNotExist` error message.
- Removed deprecated `__expr` escapes from integration tests.
- Improved error detection in schema based parsing (fix issues #73, #74).
  - Detect entities with parents of an incorrect entity type.
  - Detect entities with an undeclared entity type.
- Slightly improved error text on some validation type errors
- Improved error messages for some schema type parsing errors
  - Parsing a schema type without the `"type"` field will generate an error
    stating that `"type"` is a required field instead of an inscrutable error
    complaining about the untagged enum `SchemaType`.
  - Parsing a schema type with a `"type"` field corresponding to one of the
    builtin types but missing a required field for that type will generate an
    error stating that a required field is missing instead of claiming that it
    could not find "common types" definition for that builtin type.

## 2.3.1

### Fixed

- Fix a panic in `PolicySet::link()` that could occur when the function was called
  with a policy id corresponding to a static policy.

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
