# Changelog

All notable changes to crate `cedar-policy-symcc` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
Cedar Language Version: TBD

### Added

- New optimized interface (`*_opt` methods on `CedarSymCompiler`) allowing you
to precompile policies (see `CompiledPolicy` and `CompiledPolicies`) and reuse
them across many queries. (#2013, #2019)
- `always_matches` and `never_matches` primitives for single policies (#2014)
- Performance optimizations (#1947, #1970, #2017, #2020, #2021)

## [0.1.3] - Coming soon
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
