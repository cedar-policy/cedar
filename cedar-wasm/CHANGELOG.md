# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Exposed cedar-wasm functionality for policies and templates: `check_parse_policy_set`,
  `policy_text_to_json`, and `policy_text_from_json`. (#616)
- Exposed cedar-wasm functionality for authorization and validation: `wasm_is_authorized`
  and `wasm_validate`. (#657)
- Exposed types through `tsify` for `ValidateCall` and the schema. (#692)
