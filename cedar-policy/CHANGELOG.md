# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `PolicyId::new()` added to `PolicyId` (#587, resolving #551)
- `AsRef<str>` implementation for `PolicyId`. (#504, resolving #503)
- New API `template_links` for `Policy` to retrieve the linked values for a
  template-linked policy. (#515, resolving #489)
- Added `EntityId::new()` constructor (#583, resolving #553)
- New feature for cedar-policy and cedar-policy core to allow targeting wasm

### Changed

- Better integration with `miette` for various error types. If you have
  previously been just using the `Display` trait to get the error message from a
  Cedar error type, you may want to consider also examining other data provided
  by the `miette::Diagnostic` trait, for instance `.help()`.
  Alternately, you can use `miette` and its `fancy` feature to format the error
  and all associated information in a pretty human-readable format or as JSON.
  For more details, see `miette`'s
  [documentation](https://docs.rs/miette/latest/miette/index.html). (#477)
- Moved `(PolicyId as FromStr)::Err` to `Infallible` (#588, resolving #551)
- Add hints suggesting how to fix some type errors. (#513)
- The `ValidationResult` returned from `Validator::validate` now has a static
  lifetime, allowing it to be used in more contexts. The lifetime parameter
  will be removed in a future major version. (#512)
- Improve parse error around invalid `is` expressions. (#491, resolving #409)
- Improve parser error message when a policy includes an invalid template slot.
  The error now identifies that the policy used an invalid slot and suggests using
  one of the valid slots. (#487, resolving #451)
- Improve parser error messages to more reliably notice that a function or
  method does exists when it is called with an incorrect number of arguments or
  using the wrong call style. (#482)
- Include source spans on more parser error messages. (#471, resolving #465)
- Include source spans on more evaluation error messages. (#582)
- For the `partial-eval` experimental feature: make the return values of
  `RequestBuilder`'s `principal`, `action`, `resource`, `context` and
  `schema` functions `#[must_use]`. (#502)
- For the `partial-eval` experimental feature: make `RequestBuilder::schema`
return a `RequestBuilder<&Schema>` so the `RequestBuilder<&Schema>::build`
method checks the request against the schema provided and the 
`RequestBuilder<UnsetSchema>::build` method becomes infallible. (#559)

### Fixed

- Action entities in the store will pass schema-based validation without requiring
  the transitive closure to be pre-computed. (#581, resolving #285)
- Variables qualified by a namespace with a single element are correctly
  rejected. E.g., `foo::principal` is an error and is not parsed as
  `principal`. Variables qualified by a namespace of any size comprised entirely
  of Cedar keywords are correctly rejected. E.g., `if::then::else::principal` is an error.
  (#594 and #596)
- The entity type tested for by an `is` expression may be an identifier shared
  with a builtin variable. E.g., `... is principal` and `... is action` are now
  accepted by the Cedar parser. (#558)

## [3.0.1] - 2023-12-21
Cedar Language Version: 3.0.0

### Fixed

- Possible panic (when stack size limit reached) in `Context::empty()` (#524,
  fixed by #526)

## [3.0.0] - 2023-12-15
Cedar Language Version: 3.0.0

### Added

- Marked the `Template::from_json` and `Template::to_json` apis as public (#458)
- New APIs to `Entities` to make it easy to add a collection of entities to an
  existing `Entities` structure. (#276)
- Export the `cedar_policy_core::evaluator::{EvaluationError, EvaluationErrorKind}` and
  `cedar_policy_core::authorizer::AuthorizationError` error types. (#260, #271)
- `ParseError::primary_source_span` to get the primary source span locating an
  error. (#324)
- Experimental API `PolicySet::unknown_entities` to collect unknown entity UIDs
  from a `PartialResponse`. (#353, resolving #321)
- `PolicySet::remove_static`, `PolicySet::remove_template` and
  `PolicySet::unlink` to remove policies from the policy set. (#337, resolving #328)
- `PolicySet::get_linked_policies` to get the policies linked to a `Template`. (#337)
- `ValidationResult::validation_warnings` to access non-fatal warnings returned
  by the validator and `ValidationResult::validation_passed_without_warnings`.
  The main validation entry point now checks for warnings previously only
  available through `confusable_string_checker`. (#404)
- The `is` operation as described in
  [RFC 5](https://github.com/cedar-policy/rfcs/blob/main/text/0005-is-operator.md).
  (#396)
- `Entity::new_no_attrs()` which provides an infallible constructor for `Entity`
  in the case that there are no attributes. (See changes to `Entity::new()`
  below.) (#430)
- `RestrictedExpression::new_entity_uid()` (#442, resolving #350)

### Changed

- Rename `cedar_policy_core::est::EstToAstError` to
  `cedar_policy_core::est::FromJsonError`. (#197)
- Rename `cedar_policy_core::entities::JsonDeserializationError::ExtensionsError`
  to `cedar_policy_core::entities::JsonDeserializationError::ExtensionFunctionLookup`.
  (#360)
- Rename variants in `SchemaError`. (#231)
- `SchemaError` has a new variant corresponding to errors evaluating action
  attributes. (#430)
- `Diagnostics::errors()` now returns an iterator over `AuthorizationError`s.
  (#260)
- `Response::new()` now expects a `Vec<AuthorizationError>` as its third
  argument. (#260)
- Implement [RFC 19](https://github.com/cedar-policy/rfcs/blob/main/text/0019-stricter-validation.md),
  making validation slightly more strict, but more explainable. (#282)
- Implement [RFC 20](https://github.com/cedar-policy/rfcs/blob/main/text/0020-unique-record-keys.md),
  disallowing duplicate keys in record values (including record literals in
  policies, request `context`, and records in entity attributes). (#375)
- `Entities::from_*()` methods now automatically add action entities present in
  the `schema` to the constructed `Entities`, if a `schema` is provided. (#360)
- `Entities::from_*()` methods now validate the entities against the `schema`,
  if a `schema` is provided. (#360)
- `Entities::from_entities()` and `Entities::add_entities()` now take an
  optional schema argument. (#360)
- `Request::new()` now takes an optional schema argument, and validates the request
  against that schema. To signal validation errors, it now returns a `Result`.
  (#393, resolving #191)
- Change the semantics of equality for IP ranges. For example,
  `ip("192.168.0.1/24") == ip("192.168.0.3/24")` was previously `true` and is now
  `false`. The behavior of equality on single IP addresses is unchanged, and so is
  the behavior of `.isInRange()`. (#348)
- Standardize on duplicates being errors instead of last-write-wins in the
  JSON-based APIs in the `frontend` module. This also means some error types
  have changed. (#365, #448)
- `Entity::new()` now eagerly evaluates entity attributes, leading to
  performance improvements (particularly when entity data is reused across
  multiple `is_authorized` calls). As a result, it returns `Result`, because
  attribute evaluation can fail. (#430)
- `Entities::from_json_*()` also now eagerly evaluates entity attributes, and as
  a result returns errors when attribute evaluation fails. (#430)
- `Entity::attr()` now returns errors in many fewer cases (because the attribute
  is stored in already-evaluated form), and its error type has changed. (#430)
- `Context::from_*()` methods also now eagerly evaluate the `Context`, and as
  a result return errors when evaluation fails. (#430)
- `<EntityId as FromStr>::Error` is now `Infallible` instead of `ParseErrors`.
  (#372)
- Improve the `Display` impls for `Policy` and `PolicySet`, and add a `Display`
  impl for `Template`.  The displayed representations now more closely match the
  original input, whether the input was in string or JSON form. (#167, resolving
  #125)
- `ValidationWarning::location` and `ValidationWarning::to_kind_and_location`
  now return `&SourceLocation<'a>` instead of `&'a PolicyID`, matching
  `ValidationError::location`. (#405)
- `ValidationWarningKind` is now `non_exhaustive`, allowing future warnings to
  be added without a breaking change. (#404)
- Improve schema parsing error messages when a cycle exists in the action
  hierarchy to includes an action which is part of the cycle (#436, resolving
  #416).

### Fixed

- Evaluation order of operand to `>` and `>=`. They now evaluate left to right,
  matching all other operators. This affects what error is reported when there is
  an evaluation error in both operands, but does not otherwise change the result
  of evaluation. (#402, resolving #112)
- Updated `PolicySet::link` to not mutate internal state when failing to link a static
  policy. With this fix it is possible to create a link with a policy id
  after previously failing to create that link with the same id from a static
  policy. (#412)
- Fixed schema-based parsing of entity data that includes unknowns (for the
  `partial-eval` experimental feature). (#419, resolving #418)

### Removed

- Removed `__expr` escape from Cedar JSON formats, which has been deprecated
  since Cedar 1.2. (#333)
- Move `ValidationMode::Permissive` behind an experimental feature flag.
  To continue using this feature you must enable the `permissive-validate`
  feature flag. (#428)


## [2.4.3] - 2023-12-21

Cedar Language Version: 2.1.3

### Fixed

- Reverted accidental breaking change to schema format introduced in the 2.3.2
  release.
  Attribute types in schema files may now contain unexpected keys (as they could
  before 2.3.2).
  As a side effect, schema parsing error messages are less useful when an
  attribute type is missing a required key.
  The 2.4.2 behavior, including the more useful error messages, remain available
  in all 3.x versions of Cedar.
  (#520)

## [2.4.2] - 2023-10-23
Cedar Language Version: 2.1.2

### Fixed

- Issue #370 related to how the validator handles template-linked policies.
  The validator will now produce the same result for an equivalent static
  and template-linked policy. (#371, resolving #370)

## [2.4.1] - 2023-10-12
Cedar Language Version: 2.1.1

### Added

- Experimental API to construct queries with `Unknown` fields for partial evaluation.

### Changed

- Improve validation error messages for access to undeclared attributes and
  unsafe access to optional attributes to report the target of the access. (#295)
- `EntityUid`'s impl of `FromStr` is no longer marked as deprecated. (#319)

### Fixed

- Issue #299 related to how partial evaluation handled conditions of `if`,
  resulting in a panic on some inputs.
- `Request::principal()`, `Request::action()`, and `Request::resource()` will
  now return `None` if the entities are unspecified (i.e., constructed by passing
  `None` to `Request::new()`). (#339)

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
  correctly uses the default namespace. (#151)

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
  with a policy id corresponding to a static policy. (#203)

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

[Unreleased]: https://github.com/cedar-policy/cedar/compare/v3.0.1...main
[3.0.1]: https://github.com/cedar-policy/cedar/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/cedar-policy/cedar/compare/v2.4.3...v3.0.0
[2.4.3]: https://github.com/cedar-policy/cedar/compare/v2.4.2...v2.4.3
[2.4.2]: https://github.com/cedar-policy/cedar/compare/v2.4.1...v2.4.2
[2.4.1]: https://github.com/cedar-policy/cedar/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/cedar-policy/cedar/compare/v2.3.3...v2.4.0
[2.3.3]: https://github.com/cedar-policy/cedar/compare/v2.3.2...v2.3.3
[2.3.2]: https://github.com/cedar-policy/cedar/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/cedar-policy/cedar/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/cedar-policy/cedar/releases/tag/v2.3.0
