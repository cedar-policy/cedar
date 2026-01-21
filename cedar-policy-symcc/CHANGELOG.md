# Changelog

All notable changes to crate `cedar-policy-symcc` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
Cedar Language Version: TBD

### Added

- `matches_equivalent`, `matches_implies`, and `matches_disjoint` primitives
for single policies (#2047)
- `.effect()` for `CompiledPolicy` (#2047)
- `CompiledPolicy::policy()` and `CompiledPolicies::policies()` (#2103)
- `CompiledPolicy::compile_with_custom_symenv()` and
`CompiledPolicies::compile_with_custom_symenv()` experimental APIs -- note the
documented caveats and use at your own risk (#2102)
- Performance optimizations (#2070, #2073, #2079, #2093, #2094)

### Changed

- Deprecated the unoptimized interface on `CedarSymCompiler` in favor of the
optimized interface (`*_opt` methods) introduced in 0.2.0 (#2095)
- Experimental functions `compile_always_matches()` and friends were refactored
and renamed to `always_matches_asserts()` and friends. Under the hood, these now
use the performance-optimized primitives introduced in 0.2.0. (#2102)

### Fixed

- Bug where returned counterexamples could occasionally be invalid by containing
cycles in the entity data for entities irrelevant to the given policies (#2089)

### Removed

- Experimental `WellFormedAsserts::from_asserts_unchecked()` API. But note the
addition of `CedarSymCompiler::check_unsat_raw()` as an experimental API. (#2102)

## [0.2.0] - 2025-12-12
Cedar Language Version: 4.4

### Added

- New optimized interface (`*_opt` methods on `CedarSymCompiler`) allowing you
to precompile policies (see `CompiledPolicy` and `CompiledPolicies`) and reuse
them across many queries. (#2013, #2019)
- `always_matches` and `never_matches` primitives for single policies (#2014)
- Performance optimizations (#1947, #1970, #2017, #2020, #2021)

## [0.1.3] - 2025-12-12
Cedar Language Version: 4.4

### Fixed
- Ensured that this crate depends on compatible versions of `cedar-policy` and
`cedar-policy-core` (#1954)

## [0.1.2] - 2025-11-26
Cedar Language Version: 4.4

### Fixed
- Fixed parsing of small negative decimal literals. (#1964)

## [0.1.1] - 2025-11-20
Cedar Language Version: 4.4

### Changed

- Lock `cedar-policy-core` version to 4.7.0

## [0.1.0] - 2025-11-10
Cedar Language Version: 4.4

- Initial release
