# Changelog

## Unreleased

### Added

- Added command `translate-policy` that translates a policy set in its human-readable format to the JSON format (except comments). (#987)
- Added a `visualize` option to the command-line interface, allowing entity json
files to be visualized using the graphviz format. (#960)
- All commands that read policies in JSON format now accept a policy set in addition to a single policy or a policy template. (#1057)

### Changed

- The default `--schema-format` is now `human` for all subcommands that take
  `--schema-format`. (#750)
- The `--partial-validate` option has been replaced with `--validation-mode`,
  taking the values `strict`, `permissive` (new) and `partial`.
  The latter two are kept behind their respective feature flags. (#915)
- CLI arguments `--policy-format` and `--schema-format` now take options
  `cedar` or `json`, as opposed to previous `human` or `json`. (#1114)

## 3.2.4

## 3.2.1

## 3.2.0

### Added

- A `--write` flag for the `format` subcommand. This flag writes the formatted
  policy to the file specified by the `--policies` flag. (#795)
- A `--check` flag for the `format` subcommand. This flag checks if the policy
  is already formatted and exits with a non-zero status if it is not. (#798, resolving #796)

## 3.1.3

- The `translate-schema` command now produces prettier output.

## 3.1.2

## 3.1.1

## 3.1.0

Now uses Cedar language version 3.1.0.

### Added

- Added support for the human-readable schema format (`--schema-format human`
  when a schema is needed). The default schema format is still JSON for backward
  compatibility.
- Added command `translate-schema` that translates a schema in the JSON format
  to its human-readable format and vice versa (except comments).
- The `-p`/`--policies` flag can now be omitted across all subcommands where it
  is present. If the flag is omitted, policies will be read from `stdin`.
- `--policy-format` flag to many subcommands, allowing you to pass policies in
  JSON format. The default remains `human` format.
- The `validate` command now takes a `--template-linked` / `-k` optional argument,
  allowing you to validate template-linked policies.
- The `check-parse` command also now takes a `--template-linked` / `-k` optional
  argument, allowing you to check whether a template-linked-policies file parses.
- The `--template-linked` / `-k` argument is now also optional to `link`
  (previously required). If not provided, the linked policy will only be shown on
  stdout; if it is provided, the indicated file will be updated with the new link
  (as before).
- The `evaluate` command now shows source spans on parse errors.

### Fixed

- The `link` command now accepts templates in the Cedar JSON (EST) syntax.

## 3.0.1

## 3.0.0

Now uses Cedar language version 3.0.0.

### Added

- `--deny-warnings` option to `validate` command. This option turns non-fatal
  warnings into errors.
- Requests are now validated by default if a schema is provided. This can be
  disabled with `--request-validation=false`.
- The `-s` short form can now be used for `--schema` across all subcommands.

### Changed

- The `-p` flag now always refers to `--policies` (not `--principal`) across all
  subcommands, while `-l` refers to `--principal`. Relatedly, the `--policies`
  long form of the flag is also now accepted across all subcommands.
- The short form of `--template-linked` was changed from `-t` to `-k`.
- The `format` subcommand no longer takes a positional file argument.

## 2.4.7

## 2.4.6

## 2.4.5

## 2.4.4

## 2.4.3

Now uses Cedar language version 2.1.3.

## 2.4.2

Now uses Cedar language version 2.1.2.

## 2.4.1

## 2.4.0

Now uses Cedar language version 2.1.1.

### Changed

- Input policies for `check-parse` command can be read from standard input.

### Fixed

- Duplicate policy ids in `@id` annotations cause the CLI to exit gracefully
  instead of panicking.

## 2.3.3

## 2.3.2

## 2.3.1

## 2.3.0

Now uses Cedar language version 2.1.0.

## 2.2.0

### Changed

- Update `cedar-policy` and `cedar-policy-core` dependencies.

## 2.1.0

### Changed

- Update `cedar-policy` and `cedar-policy-formater` dependencies.

### Fixed

- Resolve warning in `Cargo.toml` due to having both `license` and `license-file` metadata entries.

## 2.0.3

### Fixed

- Update `Cargo.toml` metadata to correctly represent this crate as Apache-2.0 licensed.

## 2.0.2

## 2.0.1

## 2.0.0

Initial release of `cedar-policy-cli`.

Uses Cedar language version 2.0.0.
