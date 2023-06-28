# Changelog

## Unreleased

### Added

- Export `entities::EntitiesError` error type.
- New methods exported for `EntityTypeName`.
  - `basename` to get the basename (without namespaces).
  - `namespace_components` to get the namespace as an iterator over its components.
  - `namespace` to get the namespace as a single string.

### Changed

- Improved error detection in schema based parsing (fix issues #73, #74).
  - Detect entities with parents of an incorrect entity type.
  - Detect entities with an undeclared entity type.
- Slightly improved error text on some validation type errors
- Disallow whitespace in entity type names when parsed by `EntityTypeName::from_str()`, `EntityNamespace::from_str()` and `EntityUid::from_str()` (implement rfc #9).

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
