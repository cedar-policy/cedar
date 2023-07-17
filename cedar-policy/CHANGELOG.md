# Changelog

## Unreleased
- Move public API for partial evaluation behind experimental feature flag.

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
