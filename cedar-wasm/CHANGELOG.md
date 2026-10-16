# Changelog

## Unreleased

## 4.14.0

### Added

- `linkSchemas` binding for schema linking (RFC 116), resolving the `external` entity type and action declarations of one schema against definitions in the others. The result may itself be partial. (#2615)
- `schemaCompleteness` binding, reporting whether a schema still has `external` declarations and naming the ones it has. (#2615)

### Changed

- Upgraded tsify dependency and migrated wasm bindings to use the new `Ts<T>` wrapper pattern, fixing memory leak potential when passing malformed inputs. (#2534)

## 4.13.0

## 4.12.0

## 4.11.1

## 4.11.0

### Fixed

- `isAuthorizedPartial` will now error when `preparsedSchemaName` is not found in cache, matching behavior for preparsed policy sets. (#2348)

## 4.10.0

## 4.9.1

### Added
- `isAuthorizedPartial` binding for partial evaluation (experimental)

## 4.9.0

## 4.8.2

## 4.8.1

## 4.8.0

## 4.7.1

## 4.7.0

## 4.6.2

## 4.6.1

## 4.6.0

## 4.5.2

## 4.5.1

## 4.5.0

## 4.4.2

## 4.4.1

## 4.4.0

## 4.3.4

## 4.3.3

## 4.3.2

## 4.3.1

## 4.3.0

## 4.2.3

## 4.2.2

## 4.2.1

## 4.2.0

### Fixed
- Fixed import logic (https://github.com/cedar-policy/cedar/issues/1227
  and https://github.com/cedar-policy/cedar/issues/1226)

## 4.1.1

## 4.1.0

## 4.0.1

## 4.0.0

### Added

Initial release of the Wasm bindings

## 3.4.2

## 3.3.1

## 3.2.5

## 3.2.x

Initial pre-release of the Wasm bindings
