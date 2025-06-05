# Changelog

All notable changes to this project will be documented in this file.
Changes affecting only the CLI are documented [separately](../cedar-policy-cli/CHANGELOG.md).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The "Cedar Language Version" refers to the language version as documented in the [Cedar Policy Language Guide](https://docs.cedarpolicy.com/other/doc-history.html). The language version may differ from the Rust crate version because a breaking change for the Cedar Rust API may or may not be a breaking change for the Cedar language.

Starting with version 3.2.4, changes marked with a star (*) are _language breaking changes_, meaning that they have the potential to affect users of Cedar, beyond users of the `cedar-policy` Rust crate. Changes marked with a star change the behavior of a Cedar parser, the authorization engine, or policy validator.

## [Unreleased]
Cedar Language Version: TBD

### Added

- Added `Entities::upsert_entities()` to add or update `Entity`s in an `Entities` struct (resolving #1479)
- Added schema parsing functions to improve compatibility with JSON schema originally writing for versions 2.5.0
  and earlier. These functions will ignore unrecognized keys in some positions where they are currently an error,
  matching the behavior of earlier versions.  This is intended help some users migrate to the current 4.0 schema
  format. The new functions are deprecated and placed behind the `deprecated-schema-compat` feature. (#1600)
- `Expression::new_duration`, `Expression::new_datetime`, `RestrictedExpression::new_duration`,
   and `RestrictedExpression::new_datetime` (#1614)
- Added a function to be able to split a policy set parsed from a single string into its component static
  policies and templates. The relevant function is `policy_set_text_to_parts` in the `ffi` module (#1629).
- Added the `raw-parsing` feature flag which provides alternative parsing APIs (`parse_raw`) for
  `PolicySet`, `Policy`, and `Template`. These APIs don't retain source code information, trading detailed error
  reporting for reduced memory usage and faster parsing. The feature is only intended for use with raw parsing
  APIs, as regular parsing performance is degraded when the `raw-parsing` feature is enabled.
- Implemented [RFC 71 (trailing commas)](https://github.com/cedar-policy/rfcs/blob/main/text/0071-trailing-commas.md)
  for Cedar policy files. (#1606)

### Changed

- Changed experimental `entity-manifest` function `compute_entity_manifest` to
  accept an `&Validator` instead of `&Schema`. Callers can construct a `Validator`
  from a schema with `Validator::new` afterwhich a reference to the original
  schema can be retrieved using `Validator::schema`. (#1584)
- Bumped MSRV to 1.82 (#1611)

## [4.4.1] - 2025-05-22

Cedar Language Version: 4.3

### Fixed

- Apply entity conformance checking to tags (#1604)

## [4.4.0] - 2025-04-23

Cedar Language Version: 4.3

### Added

- Stabilized [RFC 76](https://github.com/cedar-policy/rfcs/blob/main/text/0076-entity-slice-validation.md), removing
  the experimental `level-validate` feature flag. That functionality is now available
  without the feature flag. Stabilization comes with changes to fix bugs in the features.
  Level validation is now more permissive when checking `if` expressions (fixing #1507),
  and stricter when checking record literals and entity tag operations (fixing #1505 and #1503). (#1567)
- Implemented [RFC 53 (enumerated entity types)](https://github.com/cedar-policy/rfcs/blob/main/text/0053-enum-entities.md)  (#1377)
- Stabilized [RFC 80 (`datetime` extension)](https://github.com/cedar-policy/rfcs/blob/main/text/0080-datetime-extension.md), making `datetime` a default feature. (#1541)
- Added `Entities::remove_entities()` to remove `Entity`s from an `Entities` struct (#1453, resolving #701)
- Added `PolicySet::merge()` to merge a `PolicySet` into another `PolicySet` struct (#1476, resolving #610)
- Added `to_cedar` functions for `PolicySet`, `Policy`, and `Template` that
  render the policy in the Cedar syntax. These functions can be used to convert
  JSON formatted policies into the human-readable syntax (#1510, resolving #461)
- Added `Validator::schema()` to get a reference to the `Schema` even after it has been
  consumed to construct a `Validator` (#1524)
- Added `Schema::request_envs()` to get all of the `RequestEnv`s that are valid
  according to the schema. (This joins the existing `Policy::get_valid_request_envs()`
  and `Template::get_valid_request_envs()` that return the subset of request envs that
  are valid for a particular policy or template.) (#1547)
- Added `EntityId::unescaped()`, analogous to `EntityId::escaped()`. This is simply an
  alias for `EntityId::as_ref()` with the `AsRef` impl that produces `&str`. (#1555)
- Added `PartialResponse::unknown_entities` method (#1557)
- Added `Entities::len` and `Entities::is_empty` methods (#1562, resolving #1523)

### Changed

- Changed `Entities::add_entities` and `Entities::from_entities` to ignore structurally equal entities with the same Entity UID.
- For `protobufs` experimental feature, a number of changes to the interface and
  the Protobuf format definitions, as we continue to iterate towards making this
  feature stable. (#1488, #1495, #1506, #1535)
- Bump MSRV to 1.81 (#1542)
- `HierarchyNotRespected` validation error is no longer returned (although the
  error variant remains, to avoid a breaking change). This means that in some
  edge cases, policies that previously failed to validate under strict validation
  will now pass validation, probably with an `ImpossiblePolicy` warning. (#1355,
  resolving #638)

## [4.3.3] - 2025-02-25

Cedar Language Version: 4.2

### Changed

- Significant changes to the API for the experimental `protobufs` feature
  (#1452, #1467, others)

### Fixed

- Fixed the experimental `protobufs` feature so that code depending on `cedar-policy`
  with this feature now successfully builds, even if that code is not part of the
  same Cargo workspace as `cedar-policy`, `cedar-policy-core`, etc (#1452).
- Fixed a bug in the experimental `entity-manifest` feature. If an entity appears as
  both a possible value for a scope variable and an entity literal, slicing
  using entity manifests will now correctly capture all necessary attributes (#1429).
- Fixed a bug in the experimental `entity-manifest` and `level-validate`
  features. These features failed to consider any attribute accesses occurring
  inside the guard of an `if` expression when guard expression had a singleton
  boolean type (#1462).

## [4.3.2] - 2025-02-12
Cedar Language Version: 4.2

### Fixed

- Assume sufficient stack space when it cannot be determined (#1446, resolving #1443).
  Note that on platforms not supported by `stacker` (e.g., Wasm, Android), this means
  that large inputs may result in stack overflows and crashing the process.
  On all platforms supported by `stacker` (Linux, macOS, ...), Cedar will
  continue to return the graceful error `RecursionLimit` instead of crashing.

## [4.3.1] - 2025-01-23
Cedar Language Version: 4.2

### Fixed

- Disable doc generation for feature `protobufs`, unblocking that for other features (#1434)

## [4.3.0] - 2025-01-21
Cedar Language Version: 4.2

### Added

- Implemented [RFC 62 (extended `has` operator)](https://github.com/cedar-policy/rfcs/blob/main/text/0062-extended-has.md)  (#1327, resolving #1329)
- Implemented [RFC 80 (`datetime` extension)](https://github.com/strongdm/cedar-rfcs/blob/datetime-rfc/text/0080-datetime-extension.md) as an experimental feature under flag `datetime` (#1276, #1415)
- Added new `.isEmpty()` operator on sets (#1358, resolving #1356)
- Implemented [RFC 48 (schema annotations)](https://github.com/cedar-policy/rfcs/blob/main/text/0048-schema-annotations.md) (#1316)
- Implemented [RFC 74 (entity manifests and slicing)](https://github.com/cedar-policy/rfcs/pull/74) behind the experimental `entity-manifest` flag (#1239)
- Added protobuf schemas and (de)serialization behind the experimental `protobufs` flag (#1277, #1345)
- New `Entity::new_with_tags()` and `Entity::tag()` functions (#1402, resolving #1374)
- Added `Request::context` and `Context::get` methods to allow easy extraction of  values from the context by key (#1318)
- For the `partial-eval` experimental feature, added `PartialResponse::reauthorize_with_bindings` to accept substitutions from an iterator and deprecated `PartialResponse::reauthorize` (#1387)
- For the `partial-eval` experimental feature, added `RequestBuild::unknown_principal_with_type` and `RequestBuild::unknown_resource_with_type` methods, allowing an unknown principal or resource to be constrained to a certain entity type (#1391)
- Added `Clone` implementations for more types (#1324)

### Changed

- Stopped emitting warnings for identifiers containing certain printable ASCII
  characters (e.g., `/` and `:`) (#1336, resolving #621)

### Fixed

- Attach source code to certain errors so that `miette::Report`s derived from these errors are self-contained (#1351, resolving #977 and #1335)

## [4.2.2] - 2024-11-11
Cedar Language version: 4.1

### Changed

- The error associated with parsing a non-existent extension function additionally
  includes a suggestion based on available extension functions (#1280, resolving #332).
- The error associated with parsing a non-existent extension method additionally
  includes a suggestion based on available extension methods (#1289, resolving #246).
- Improved entity validation speed, particularly for large schemas with many
  actions (#1290 and #1296, resolving #1285)

### Fixed

- Some misleading parser errors for JSON schema with mistakes in nested attribute definitions (#1270, resolving #417)
- Cedar schema printer now correctly prints entity tags (#1304)

## [4.2.1] - 2024-10-08
Cedar Language version: 4.1

### Fixed

- Fixes a minor issues preventing documentation from building on docs.rs

## [4.2.0] - 2024-10-07
Cedar Language version: 4.1

### Added

- Added `sub_entity_literals` API (#1233).
- Added level validation [RFC 76](https://github.com/cedar-policy/rfcs/pull/76) as an experimental feature.
- Annotations without explicit values. It is now possible to write an annotation `@my_annotation` as
  short-hand for `@my_annotation("")` (#1231, resolving #1031).
- Stabilized [RFC 82](https://github.com/cedar-policy/rfcs/pull/82), removing
  the experimental `entity-tags` feature flag. That functionality is now available
  without the feature flag.

### Changed

- The validator provides a more specific hint when an action ID cannot be found
  and the same action ID with `Action::` has been defined (#1258, resolving #166)

## [4.1.0] - 2024-09-30
Cedar Language Version: 4.0

### Added

- Added `get_entity_literals` API (#1149).
- Implemented [RFC 82](https://github.com/cedar-policy/rfcs/pull/82), adding
  entity tags to the Cedar language under experimental flag `entity-tags` (#1204, #1207, #1213, #1218)
- Added public APIs to get language and SDK version numbers (#1219).

### Fixed

- The formatter will now consistently add a trailing newline. (resolving #1217)

## [4.0.0] - 2024-09-16
Cedar Language Version: 4.0

### Added

- Additional functionality to the JSON FFI including parsing utilities (#1079)
  and conversion between the Cedar and JSON formats (#1087)
- (*) Schema JSON syntax now accepts a type `EntityOrCommon` representing a
  typename that can resolve to either an entity or common type, matching the
  behavior of typenames written in the human-readable (Cedar) syntax. (#1060, as
  part of resolving #579)

### Changed

- (*) Implemented [RFC 70](https://github.com/cedar-policy/rfcs/blob/main/text/0070-disallow-empty-namespace-shadowing.md).
  In both the Cedar and JSON schema syntaxes, it is now illegal to define the
  same entity name, common type name, or action name in both the empty namespace
  and a nonempty namespace.
- (*) Implemented [RFC 52](https://github.com/cedar-policy/rfcs/blob/main/text/0052-reserved-namespaces.md).
  Names containing `__cedar` (e.g., `__cedar`, `A::__cedar`, `__cedar::A`, and
  `A::__cedar::B`) are now invalid. (#969)
- The API around `Request::new` has changed to remove the `Option`s
  around the entity type arguments. See [RFC 55](https://github.com/cedar-policy/rfcs/blob/main/text/0055-remove-unspecified.md).
- Replaced uses of "natural", "human", "human-readable", and "custom" with "Cedar" (#1114).
  APIs with these names are changed accordingly. E.g., `Schema::from_str_natural` to `Schema::from_cedarschema_str`.
  Moreover, the `FromStr` implementations of `Schema` and `SchemaFragment`
  now parse strings in the Cedar schema format. Use `Schema::from_json_str` and `SchemaFragment::from_json_str`
  to parse strings in the JSON schema format.
- Significantly reworked all public-facing error types to address some issues
  and improve consistency. See issue #745.
- Finalized the `ffi` module and `cedar-wasm` crate which were preview-released
  in 3.2.0. This involved API breaking changes in both. See #757 and #854.
- (*) Changed policy validation to reject comparisons and conditionals between
  record types that differ in whether an attribute is required or optional. (#769)
- (*) Improved consistency between JSON and Cedar schema formats. Both now
  forbid using `Bool`, `Boolean`, `Entity`, `Extension`, `Long`, `Record`, `Set`,
  and `String` as common type names. (#1150, resolving #1139)
- Changed the FFI to error on typos or unexpected fields in the input JSON (#1041)
- Changed `Policy::parse` and `Template::parse` to accept an `Option<PolicyId>`
  instead of `Option<String>` to set the policy id (#1055, resolving #1049)
- `PolicySet::template_annotation` now returns `Option<&str>` as opposed to
  `Option<String>` in the previous version (#1131, resolving #1116)
- Moved `<PolicyId as FromStr>::Err` to `Infallible` (#588, resolving #551)
- Removed unnecessary lifetimes from some validation related structs (#715)
- Marked errors/warnings related to parsing and validation as `non_exhaustive`,
  allowing future variants to be added without a breaking change. (#1137, #1169)

### Removed

- (*) Removed unspecified entity type. See [RFC 55](https://github.com/cedar-policy/rfcs/blob/main/text/0055-remove-unspecified.md).
- Removed integration testing harness from the `cedar-policy` crate. It is now
  in an internal crate, allowing us to make semver incompatible changes. (#857)
- Removed the (deprecated) `frontend` module in favor of the new `ffi` module
  introduced in 3.2.0. See #757.
- Removed `ParseErrors::errors_as_strings`.  Callers should consider examining
  the rich data provided by `miette::Diagnostic`, for instance `.help()` and
  `labels()`. Callers can continue using the same behavior by calling
  `.iter().map(ToString::to_string)`. (#882, resolving #543)
- Removed `ParseError::primary_source_span`. Callers should use the location
  information provided by `miette::Diagnostic` via `.labels()` and
  `.source_code()` instead. (#908)
- Removed `Display` impl for `EntityId` in favor of explicit `.escaped()` and
  `.as_ref()` for escaped and unescaped representations (respectively) of the
  `EntityId`; see note there (#921, resolving #884)

### Fixed

- (*) JSON format Cedar schemas will now fail to parse if they reference an unknown
  extension type. This was already an error for human-readable schema syntax. (#890, resolving #875)
- (*) Schemas can now reference entity and common types defined in the empty namespace,
  even in contexts occurring in a non-empty namespace. (#1060, resolving #579)

## [3.4.1] - 2024-09-23
Cedar Language Version: 3.4

### Fixed

- The schema format conversion method `SchemaFragment::to_cedarschema` will now
  return a name collision error when trying to convert a schema where any
  namespaced type name collides with an unqualified type. This avoids a
  situation where format conversion could change the target of an entity type
  reference. (#1212, resolving #1063) This _does not_ change what schema are
  accepted by the parsing functions for either format.

## [3.4.0] - 2024-09-16
Cedar Language Version: 3.4

### Added

- Convenience methods `num_of_policies()` and `num_of_templates()` to see how
  many policies and templates a policy set has (#1180)
- `Entity` is now `Hash`. The hash implementation compares the hash of
  the entity UID (#1186)

### Fixed

- (*) `Entities::from_entities()` will now correctly reject record
  attributes with superfluous attributes. (#1177, resolving #1176)

## [3.3.0] - 2024-08-19
Cedar Language Version: 3.4

### Added

- JSON representation for Policy Sets, along with methods like
  `::from_json_value/file/str` and `::to_json` for `PolicySet`. (#783,
  resolving #549)
- Methods for reading and writing individual `Entity`s as JSON (#924,
  resolving #807)
- `Context::into_iter` to get the contents of a `Context` and `Context::merge`
  to combine `Context`s, returning an error on duplicate keys (#1027,
  resolving #1013)
- Several new APIs for schemas to allow accessing principal and resource
  types, action entity uids, etc. (#1141, resolving #1134)

### Changed

- Added deprecation warnings to APIs that will be removed in the upcoming 4.0
  release, as well as wrapper methods with the new names, where appropriate.
  See the notes under that release for more details. (#1128)
- Reduced precision of partial evaluation for `||`, `&&`,  and conditional
  expressions. `if { foo : <unknown> }.foo then 1 + "hi" else false` now
  evaluates to `if <unknown> then 1 + "hi" else false`. (#874)
- Removed the `error` extension function, which was previously used during
  partial evaluation. (#874)

### Fixed

- (*) JSON format Cedar policies will now fail to parse if the action scope
  constraint contains a non-action entity type, matching the behavior for
  human-readable Cedar policies. (#943, resolving #925)
- `Template` parsing functions (e.g., `Template::parse()`) will now fail when
  passed a static policy as input. Use the `Policy` parsing functions instead.
  (#1108, resolving #1095)

## [3.2.4] - 2024-08-07
Cedar Language Version: 3.3

_Note:_ 3.2.2 and 3.2.3 skipped to maintain consistency with the `cedar-wasm` package

### Fixed

- (*) JSON format Cedar policies will now fail to parse if any annotations are not
  valid Cedar identifiers. (#1004, resolving #994)
- (*) `unknown()` is no longer a valid extension function if `partial-eval`
  is not enabled as a feature. (#1101, resolving #1096)

## [3.2.1] - 2024-05-31
Cedar Language Version: 3.3

### Fixed

- Fixed policy formatter dropping newlines in string literals. (#870, #910, resolving #862)
- Fixed a performance issue when constructing an error for accessing
  a non-existent attribute on sufficiently large records (#887, resolving #754)
- Fixed identifier parsing in human-readable schemas (#914, resolving #913)
- Fixed the typescript generated type for `ffi::AuthorizationCall` to remove
  unsupported string option (#939)
- Fixed Wasm build script to be multi-target in JS ecosystem (#933)

## [3.2.0] - 2024-05-17
Cedar Language Version: 3.3

### Added

- `Expression::new_ip`, `Expression::new_decimal`, `RestrictedExpression::new_ip`,
   and `RestrictedExpression::new_decimal` (#661, resolving #659)
- `Entities::into_iter` (#713, resolving #680)
- `Entity::into_inner` (#685, resolving #636)
- New `ffi` module with an improved FFI interface. This will replace the
  `frontend` module in the 4.0 release, but is available now for early adopters;
  the `frontend` module is now deprecated.
  This should be considered a preview-release of `ffi`; more API breaking
  changes are anticipated for Cedar 4.0. (#852)
- `wasm` Cargo feature for targeting Wasm (and the `cedar-wasm` crate was added
  to this repo).
  This should be considered a preview-release of `cedar-wasm`; more API
  breaking changes are anticipated for Cedar 4.0. (#858)

### Changed

- Common type definitions in both human-readable and JSON schemas may now
  reference other common type definitions. There may not be any cycles formed by
  these references. (#766, resolving #154)
- Improved validation error messages when incompatible types appear in
  `if`, `==`, `contains`, `containsAll`, and `containsAny` expressions. (#809, resolving #346)
- Deprecated error `TypeErrorKind::ImpossiblePolicy` in favor of warning
  `ValidationWarningKind::ImpossiblePolicy` so future improvements to Cedar
  typing precision will not result in breaking changes. (#716, resolving #539)
- Rework API for the `partial-eval` experimental feature (#714, #817, #838).
- Validation errors for unknown entity types and action entities now
  report the precise source location where the unknown type was encountered.
  Error for invalid use of an action now includes a source location containing
  the offending policy. (#802, #808, resolving #522)
- Deprecated the `frontend` module in favor of the new `ffi` module. The
  `frontend` module will be removed from `cedar-policy` in the next major version.
  See notes above about `ffi`. (#852)
- Deprecated the integration testing harness code. It will be removed from the
  `cedar-policy` crate in the next major version. (#707)

### Fixed

- Validation error message for an invalid attribute access now reports the
  correct attribute and entity type when accessing an optional attribute that is
  itself an entity. (#811)
- The error message returned when parsing an invalid action scope constraint
  `action == ?action` no longer suggests that `action == [...]` would be a
  valid scope constraint. (#818, resolving #563)
- Fixed policy formatter reordering some comments around if-then-else and
  entity identifier expressions. (#861, resolving #787)

## [3.1.4] - 2024-05-17
Cedar Language Version: 3.2

### Fixed

- The formatter will now fail with an error if it changes a policy's semantics. (#865)

## [3.1.3] - 2024-04-15
Cedar Language Version: 3.2

### Changed

- Improve parser errors on unexpected tokens. (#698, partially resolving #176)
- Validation error messages render types in the new, more readable, schema
  syntax. (#708, resolving #242)
- Improved error messages when `null` occurs in entity json data. (#751,
  resolving #530)
- Improved source location reporting for error `found template slot in a when clause`.
  (#758, resolving #736)
- Improved `Display` implementation for Cedar schemas, both JSON and human
  syntax. (#780)

### Fixed

- Support identifiers in context declarations in the human-readable schema
  format. (#734, resolving #681)

## [3.1.2] - 2024-03-29
Cedar Language Version: 3.2

### Changed

- Implement [RFC 57](https://github.com/cedar-policy/rfcs/pull/57): policies can
  now include multiplication of arbitrary expressions, not just multiplication of
  an expression and a constant.

## [3.1.1] - 2024-03-14
Cedar Language Version: 3.1

### Fixed

- `ValidationResult` methods `validation_errors` and `validation_warnings`, along with
  `confusable_string_checker`, now return iterators with static lifetimes instead of
  custom lifetimes, fixing build for latest nightly Rust. (#712)
- Validation for the `in` operator to no longer reports an error when comparing actions
  in different namespaces. (#704, resolving #642)

## [3.1.0] - 2024-03-08
Cedar Language Version: 3.1

### Added

- Implementation of the human-readable schema format proposed in
  [RFC 24](https://github.com/cedar-policy/rfcs/blob/main/text/0024-schema-syntax.md).
  New public APIs `SchemaFragment::from_*_natural`,
  `SchemaFragment::as_natural`, and `Schema::from_*_natural` (#557)
- `PolicyId::new()` (#587, resolving #551)
- `EntityId::new()` (#583, resolving #553)
- `AsRef<str>` implementation for `PolicyId` (#504, resolving #503)
- `Policy::template_links()` to retrieve the linked values for a
  template-linked policy (#515, resolving #489)
- `AuthorizationError::id()` to get the id of the policy associated with an
  authorization error (#589)
- For the `partial-eval` experimental feature: added
  `Authorizer::evaluate_policies_partial()` (#593, resolving #474)
- For the `partial-eval` experimental feature: added
  `json_is_authorized_partial()` (#571, resolving #570)

### Changed

- Better integration with `miette` for various error types. If you have
  previously been just using the `Display` trait to get the error message from a
  Cedar error type, you may want to consider also examining other data provided
  by the `miette::Diagnostic` trait, for instance `.help()`.
  Alternately, you can use `miette` and its `fancy` feature to format the error
  and all associated information in a pretty human-readable format or as JSON.
  For more details, see `miette`'s
  [documentation](https://docs.rs/miette/latest/miette/index.html). (#477)
- Cedar reserved words like `if`, `has`, and `true` are now allowed as policy
  annotation keys. (#634, resolving #623)
- Add hints suggesting how to fix some type errors. (#513)
- The `ValidationResult` returned from `Validator::validate` now has a static
  lifetime, allowing it to be used in more contexts. The lifetime parameter
  will be removed in a future major version. (#512)
- Improve parse error around invalid `is` expressions. (#491, resolving #409)
- Improve parse error message when a policy includes an invalid template slot.
  The error now identifies that the policy used an invalid slot and suggests using
  one of the valid slots. (#487, resolving #451)
- Improve parse error messages to more reliably notice that a function or
  method does exist when it is called with an incorrect number of arguments or
  using the wrong call style. (#482)
- Include source spans on more parse error messages. (#471, resolving #465)
- Include source spans on more evaluation error messages. (#582)
- Changed error message on `SchemaError::UndeclaredCommonTypes` to report
  fully qualified type names. (#652, resolving #580)
- For the `partial-eval` experimental feature: make the return values of
  `RequestBuilder`'s `principal`, `action`, `resource`, `context` and
  `schema` functions `#[must_use]`. (#502)
- For the `partial-eval` experimental feature: make `RequestBuilder::schema`
  return a `RequestBuilder<&Schema>` so the `RequestBuilder<&Schema>::build`
  method checks the request against the schema provided and the
  `RequestBuilder<UnsetSchema>::build` method becomes infallible. (#591,
  resolving #559)
- For the `permissive-validate` experimental feature: `X in []` is typed `False`
  for all `X`, including unspecified `X`. (#615)

### Fixed

- Action entities in the store will pass schema-based validation without requiring
  the transitive closure to be pre-computed. (#581, resolving #285)
- Variables qualified by a namespace with a single element are correctly
  rejected. E.g., `foo::principal` is an error and is not parsed as
  `principal`. Variables qualified by a namespace of any size comprised entirely
  of Cedar keywords are correctly rejected. E.g., `if::then::else::principal` is
  an error. (#594 and #597)
- The entity type tested for by an `is` expression may be an identifier shared
  with a builtin variable. E.g., `... is principal` and `... is action` are now
  accepted by the Cedar parser. (#595, resolving #558)
- Policies containing the literal `i64::MIN` can now be properly converted to
  the JSON policy format. (#601, resolving #596)
- `Policy::to_json` does not error on policies containing special identifiers
  such as `principal`, `then`, and `true`. (#628, resolving #604)
- `Template::from_json` errors when there are slots in template conditions.
  (#626, resolving #606)

## [3.0.1] - 2023-12-21
Cedar Language Version: 3.0

### Fixed

- Possible panic (when stack size limit reached) in `Context::empty()` (#524,
  fixed by #526)

## [3.0.0] - 2023-12-15
Cedar Language Version: 3.0

### Added

- The `is` operation as described in
  [RFC 5](https://github.com/cedar-policy/rfcs/blob/main/text/0005-is-operator.md).
  (#396)
- Marked the `Template::from_json` and `Template::to_json` apis as public (#458)
- New APIs to `Entities` to make it easy to add a collection of entities to an
  existing `Entities` structure. (#276)
- `PolicySet::remove_static`, `PolicySet::remove_template` and
  `PolicySet::unlink` to remove policies from the policy set. (#337, resolving #328)
- `PolicySet::get_linked_policies` to get the policies linked to a `Template`. (#337)
- Export the `cedar_policy_core::evaluator::{EvaluationError, EvaluationErrorKind}` and
  `cedar_policy_core::authorizer::AuthorizationError` error types. (#260, #271)
- `ParseError::primary_source_span` to get the primary source span locating an
  error. (#324)
- `ValidationResult::validation_warnings` to access non-fatal warnings returned
  by the validator and `ValidationResult::validation_passed_without_warnings`.
  The main validation entry point now checks for warnings previously only
  available through `confusable_string_checker`. (#404)
- `Entity::new_no_attrs()` which provides an infallible constructor for `Entity`
  in the case that there are no attributes. (See changes to `Entity::new()`
  below.) (#430)
- `RestrictedExpression::new_entity_uid()` (#442, resolving #350)
- Experimental API `PolicySet::unknown_entities` to collect unknown entity UIDs
  from a `PartialResponse`. (#353, resolving #321)

### Changed

- Implement [RFC 19](https://github.com/cedar-policy/rfcs/blob/main/text/0019-stricter-validation.md),
  making validation slightly more strict, but more explainable. (#282)
- Implement [RFC 20](https://github.com/cedar-policy/rfcs/blob/main/text/0020-unique-record-keys.md),
  disallowing duplicate keys in record values (including record literals in
  policies, request `context`, and records in entity attributes). (#375)
- `Request::new()` now takes an optional schema argument, and validates the request
  against that schema. To signal validation errors, it now returns a `Result`.
  (#393, resolving #191)
- `Entities::from_*()` methods now automatically add action entities present in
  the `schema` to the constructed `Entities`, if a `schema` is provided. (#360)
- `Entities::from_*()` methods now validate the entities against the `schema`,
  if a `schema` is provided. (#360)
- `Entities::from_entities()` and `Entities::add_entities()` now take an
  optional schema argument. (#360)
- `Diagnostics::errors()` now returns an iterator over `AuthorizationError`s.
  (#260)
- `Response::new()` now expects a `Vec<AuthorizationError>` as its third
  argument. (#260)
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
- Rename `cedar_policy_core::est::EstToAstError` to
  `cedar_policy_core::est::FromJsonError`. (#197)
- Rename `cedar_policy_core::entities::JsonDeserializationError::ExtensionsError`
  to `cedar_policy_core::entities::JsonDeserializationError::ExtensionFunctionLookup`.
  (#360)
- Rename variants in `SchemaError`. (#231)
- `SchemaError` has a new variant corresponding to errors evaluating action
  attributes. (#430)
- Improve schema parsing error messages when a cycle exists in the action
  hierarchy to includes an action which is part of the cycle (#436, resolving
  #416).
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

## [2.5.0] - 2024-09-16
Cedar Language Version: 2.2

### Added

- Convenience methods `num_of_policies()` and `num_of_templates()` to see how
  many policies and templates a policy set has (#1180)

## [2.4.7] - 2024-05-31
Cedar Language Version: 2.2

### Fixed

- Fixed policy formatter reordering some comments around if-then-else and
  entity identifier expressions. (#861, resolving #787)
- Fixed policy formatter dropping newlines in string literals. (#870, #910, resolving #862)

## [2.4.6] - 2024-05-17
Cedar Language Version: 2.2

### Fixed

- The formatter will now fail with an error if it changes a policy's semantics. (#865)

## [2.4.5] - 2024-04-01
Cedar Language Version: 2.2

### Changed

- Implement [RFC 57](https://github.com/cedar-policy/rfcs/pull/57): policies can
  now include multiplication of arbitrary expressions, not just multiplication of
  an expression and a constant.

## [2.4.4] - 2024-03-08
Cedar Language Version: 2.1

### Changed

- Calling `add_template` with a `PolicyId` that is an existing link will now error. (#671, backport of #456)

### Fixed

- Updated `PolicySet::link` to not mutate internal state when failing to link a static
  policy. With this fix it is possible to create a link with a policy id
  after previously failing to create that link with the same id from a static
  policy. (#669, backport of #412)
- Action entities in the store will pass schema-based validation without requiring
  the transitive closure to be pre-computed. (#688, backport of #581)
- Policies containing the literal `i64::MIN` can now be properly converted to the JSON policy format. (#672, backport of #601)
- `Template::from_json` errors when there are slots in template conditions. (#672, backport of #626)
- `Policy::to_json` does not error on policies containing special identifiers such as `principal`, `then`, and `true`. (#672, backport of #628)

## [2.4.3] - 2023-12-21
Cedar Language Version: 2.1

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
Cedar Language Version: 2.1

### Fixed

- Issue #370 related to how the validator handles template-linked policies.
  The validator will now produce the same result for an equivalent static
  and template-linked policy. (#371, resolving #370)

## [2.4.1] - 2023-10-12
Cedar Language Version: 2.1

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
Cedar Language Version: 2.1

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
Cedar Language Version: 2.1

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
Cedar Language Version: 2.1

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
Cedar Language Version: 2.1

### Fixed

- Panic in `PolicySet::link()` that could occur when the function was called
  with a policy id corresponding to a static policy. (#203)

## [2.3.0] - 2023-06-29
Cedar Language Version: 2.1

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
Cedar Language Version: 2.0

### Added

- `Entities::write_to_json` function to api.rs.

## 2.1.0 - 2023-05-23
Cedar Language Version: 2.0

### Added

- `Schema::action_entities` to provide access to action entities defined in a schema.

### Changed

- Update `cedar-policy-core` dependency.

### Fixed

- Resolve warning in `Cargo.toml` due to having both `license` and `license-file` metadata entries.

## 2.0.3 - 2023-05-17
Cedar Language Version: 2.0

### Fixed

- Update `Cargo.toml` metadata to correctly represent this crate as Apache-2.0 licensed.

## 2.0.2 - 2023-05-10
Cedar Language Version: 2.0

## 2.0.1 - 2023-05-10
Cedar Language Version: 2.0

## 2.0.0 - 2023-05-10
Cedar Language Version: 2.0
- Initial release of `cedar-policy`.

[Unreleased]: https://github.com/cedar-policy/cedar/compare/v4.4.0...main
[4.4.0]: https://github.com/cedar-policy/cedar/compare/v4.3.3...v4.4.0
[4.3.3]: https://github.com/cedar-policy/cedar/compare/v4.3.2...v4.3.3
[4.3.2]: https://github.com/cedar-policy/cedar/compare/v4.3.1...v4.3.2
[4.3.1]: https://github.com/cedar-policy/cedar/compare/v4.3.0...v4.3.1
[4.3.0]: https://github.com/cedar-policy/cedar/compare/v4.2.2...v4.3.0
[4.2.2]: https://github.com/cedar-policy/cedar/compare/v4.2.1...v4.2.2
[4.2.1]: https://github.com/cedar-policy/cedar/compare/v4.2.0...v4.2.1
[4.2.0]: https://github.com/cedar-policy/cedar/compare/v4.1.0...v4.2.0
[4.1.0]: https://github.com/cedar-policy/cedar/compare/v4.0.0...v4.1.0
[4.0.0]: https://github.com/cedar-policy/cedar/compare/v3.4.0...v4.0.0
[3.4.1]: https://github.com/cedar-policy/cedar/compare/v3.4.0...v3.4.1
[3.4.0]: https://github.com/cedar-policy/cedar/compare/v3.3.0...v3.4.0
[3.3.0]: https://github.com/cedar-policy/cedar/compare/v3.2.4...v3.3.0
[3.2.4]: https://github.com/cedar-policy/cedar/compare/v3.2.1...v3.2.4
[3.2.1]: https://github.com/cedar-policy/cedar/compare/v3.2.0...v3.2.1
[3.2.0]: https://github.com/cedar-policy/cedar/compare/v3.1.4...v3.2.0
[3.1.4]: https://github.com/cedar-policy/cedar/compare/v3.1.3...v3.1.4
[3.1.3]: https://github.com/cedar-policy/cedar/compare/v3.1.2...v3.1.3
[3.1.2]: https://github.com/cedar-policy/cedar/compare/v3.1.1...v3.1.2
[3.1.1]: https://github.com/cedar-policy/cedar/compare/v3.1.0...v3.1.1
[3.1.0]: https://github.com/cedar-policy/cedar/compare/v3.0.1...v3.1.0
[3.0.1]: https://github.com/cedar-policy/cedar/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/cedar-policy/cedar/compare/v2.5.0...v3.0.0
[2.5.0]: https://github.com/cedar-policy/cedar/compare/v2.4.7...v2.5.0
[2.4.7]: https://github.com/cedar-policy/cedar/compare/v2.4.6...v2.4.7
[2.4.6]: https://github.com/cedar-policy/cedar/compare/v2.4.5...v2.4.6
[2.4.5]: https://github.com/cedar-policy/cedar/compare/v2.4.4...v2.4.5
[2.4.4]: https://github.com/cedar-policy/cedar/compare/v2.4.3...v2.4.4
[2.4.3]: https://github.com/cedar-policy/cedar/compare/v2.4.2...v2.4.3
[2.4.2]: https://github.com/cedar-policy/cedar/compare/v2.4.1...v2.4.2
[2.4.1]: https://github.com/cedar-policy/cedar/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/cedar-policy/cedar/compare/v2.3.3...v2.4.0
[2.3.3]: https://github.com/cedar-policy/cedar/compare/v2.3.2...v2.3.3
[2.3.2]: https://github.com/cedar-policy/cedar/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/cedar-policy/cedar/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/cedar-policy/cedar/releases/tag/v2.3.0
