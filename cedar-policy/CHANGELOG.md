# Changelog

## Unreleased

## 2.2.1

### Fixed

- Fix a panic in `PolicySet::link()` that could occur when the function was called
  with a policy id corresponding to a static policy.

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
