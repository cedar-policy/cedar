# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Option to eagerly evaluate entity attributes and re-use across calls to `is_authorized`.
- New APIs to `Entities` to make it easy to add a collection of entities to an existing `Entities` structure.
- Export the `cedar_policy_core::evaluator::{EvaluationError, EvaluationErrorKind}` and
  `cedar_policy_core::authorizer::AuthorizationError` error types.
- `ParseError::primary_source_span` to get the primary source span locating an error.
- Experimental API `PolicySet::unknown_entities` to collect unknown entity UIDs from a `PartialResponse`.
- `PolicySet::remove_static`, `PolicySet::remove_template` and `PolicySet::unlink` to remove policies from the policy set.
- `PolicySet::get_linked_policies` to get the policies linked to a `Template`.

### Changed

- Removed `__expr` escape from Cedar JSON formats
- Rename `cedar_policy_core::est::EstToAstError` to `cedar_policy_core::est::FromJsonError`.
- Rename `cedar_policy_core::entities::JsonDeserializationError::ExtensionsError` to `cedar_policy_core::entities::JsonDeserializationError::ExtensionFunctionLookup`.
- Rename variants in `cedar_policy::SchemaError`.
- `Diagnostics::errors()` now returns an iterator over `AuthorizationError`s.
- `Response::new()` now expects a `Vec<AuthorizationError>` as its third argument.
- Implement [RFC 19](https://github.com/cedar-policy/rfcs/blob/main/text/0019-stricter-validation.md),
  making validation slightly more strict, but more explainable.
- Implement [RFC 20](https://github.com/cedar-policy/rfcs/blob/main/text/0020-unique-record-keys.md),
  disallowing duplicate keys in record values (including record literals in policies, request `context`,
  and records in entity attributes).
- `Entities::from_*()` methods now automatically add action entities present in the `schema`
  to the constructed `Entities`, if a `schema` is provided.
- `Entities::from_*()` methods now validate the entities against the `schema`, if a `schema`
  is provided.
- `Entities::from_entities()` and `Entities::add_entities()` now take an optional schema argument.
- `Request::new()` now takes an optional schema argument, and returns a `Result`.
- Change the semantics of equality for IP ranges. For example,
  `ip("192.168.0.1/24") == ip("192.168.0.3/24")` was previously `true` and is now
  `false`. The behavior of equality on single IP addresses is unchanged, and so is
  the behavior of `.isInRange()`.
- Standardize on duplicates being errors instead of last-write-wins in the
  JSON-based APIs in the `frontend` module.
- `<EntityId as FromStr>::Error` is now `Infallible` instead of `ParseErrors`.
- Improve the `Display` impls for `Policy` and `PolicySet`, and add a `Display`
  impl for `Template`.  The displayed representations now more closely match the
  original input, whether the input was in string or JSON form.
- `ValidationWarning::location` and `ValidationWarning::to_kind_and_location`
  now return `&SourceLocation<'a>` instead of `&'a PolicyID`, matching
  `ValidationError::location`.

### Fixed

- Evaluation order of operand to `>` and `>=` (#112). They now evaluate left to right,
  matching all other operators. This affects what error is reported when there is
  an evaluation error in both operands, but does not otherwise change the result
  of evaluation.

## [2.4.2] - 2023-10-23
Cedar Language Version: 2.1.2

### Fixed

- Issue #370 related to how the validator handles template-linked policies.
  The validator will now produce the same result for an equivalent static
  and template-linked policy.

## [2.4.1] - 2023-10-12
Cedar Language Version: 2.1.1

### Added

- Experimental API to construct queries with `Unknown` fields for partial evaluation.

### Changed

- Improve validation error messages for access to undeclared attributes and
  unsafe access to optional attributes to report the target of the access (issue #175).
- `EntityUid`'s impl of `FromStr` is no longer marked as deprecated.

### Fixed

- Issue #299 related to how partial evaluation handled conditions of `if`,
  resulting in a panic on some inputs.
- `Request::principal()`, `Request::action()`, and `Request::resource()` will
  now return `None` if the entities are unspecified (i.e., constructed by passing
  `None` to `Request::new()`).

## [2.4.0] - 2023-09-21
Cedar Language Version: 2.1.1

### Added

- New methods for `EntityTypeName`.
  - `basename` to get the basename (without namespaces).
  - `namespace_components` to get the namespace as an iterator over its components.
  - `namespace` to get the namespace as a single string.

### Changed

- Some error types now carry more information about the error, with error
  messages updated appropriately. For instance, the `RecordAttrDoesNotExist` error
  message now contains a list of attributes that _do_ exist.
- Improve error messages for some schema parsing errors.
  - When an entity type shape or action context is declared with type other than
  `Record`, the error message will indicated the affected entity type or action.
- Various other improvements to error messages and documentation for errors raised during
  policy parsing, validation, and evaluation.
- Increase precision for validating records.  Previously,
  `permit(principal, action, resource) when {{"foo": 5} has bar};` would validate.
  Now it will not, since we know `{"foo": 5} has bar` is `False`, and the
  validator will return an error for a policy that can never fire.

### Removed

- Uses of deprecated `__expr` escapes from integration tests.

## [2.3.3] - 2023-08-29
Cedar Language Version: 2.1.0

### Added

- Re-export `cedar_policy_core::entities::EntitiesError`.

### Changed

- Improve error messages and documentation for some errors raised during
  policy parsing, validation, and evaluation.
- More precise "expected tokens" lists in some parse errors.

### Fixed

- Issue #150 related to implicit namespaces for actions in `memberOf` lists in
  schemas. An action without an explicit namespace in a `memberOf` now
  correctly uses the default namespace.

## [2.3.2] - 2023-08-04
Cedar Language Version: 2.1.0

### Changed

- Improve error messages for some validation errors
- Improve error messages for some schema parsing errors.
  - Parsing a schema type without the `"type"` field will generate an error
    stating that `"type"` is a required field instead of an inscrutable error
    complaining about the untagged enum `SchemaType`.
  - Parsing a schema type with a `"type"` field corresponding to one of the
    builtin types but missing a required field for that type will generate an
    error stating that a required field is missing instead of claiming that it
    could not find "common types" definition for that builtin type.

### Fixed

- Issues #73 and #74 related to schema-based parsing.
  - Detect entities with parents of an incorrect entity type.
  - Detect entities with an undeclared entity type.

### Removed

- Move public API for partial evaluation behind experimental feature flag. To
  continue using this feature you must enable the `partial-eval` feature flag.

## [2.3.1] - 2023-07-20
Cedar Language Version: 2.1.0

### Fixed

- Panic in `PolicySet::link()` that could occur when the function was called
  with a policy id corresponding to a static policy.

## [2.3.0] - 2023-06-29
Cedar Language Version: 2.1.0

### Changed

- Implement
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

## 2.2.0 - 2023-05-25
Cedar Language Version: 2.0.0

### Added

- `Entities::write_to_json` function to api.rs.

## 2.1.0 - 2023-05-23
Cedar Language Version: 2.0.0

### Added

- `Schema::action_entities` to provide access to action entities defined in a schema.

### Changed

- Update `cedar-policy-core` dependency.

### Fixed

- Resolve warning in `Cargo.toml` due to having both `license` and `license-file` metadata entries.

## 2.0.3 - 2023-05-17
Cedar Language Version: 2.0.0

### Fixed

- Update `Cargo.toml` metadata to correctly represent this crate as Apache-2.0 licensed.

## 2.0.2 - 2023-05-10
Cedar Language Version: 2.0.0

## 2.0.1 - 2023-05-10
Cedar Language Version: 2.0.0

## 2.0.0 - 2023-05-10
Cedar Language Version: 2.0.0
- Initial release of `cedar-policy`.

[unreleased]: https://github.com/cedar-policy/cedar/compare/v2.4.2...main
[2.4.2]: https://github.com/cedar-policy/cedar/compare/v2.4.1...v2.4.2
[2.4.1]: https://github.com/cedar-policy/cedar/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/cedar-policy/cedar/compare/v2.3.3...v2.4.0
[2.3.3]: https://github.com/cedar-policy/cedar/compare/v2.3.2...v2.3.3
[2.3.2]: https://github.com/cedar-policy/cedar/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/cedar-policy/cedar/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/cedar-policy/cedar/releases/tag/v2.3.0
