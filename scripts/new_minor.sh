#!/usr/bin/env bash
#
# Usage: bash ./scripts/new_minor.sh
#
# Performs pre-release steps for a release in which a minor version
# of core, symcc, and cli are performed together.
#
# Must be run from the root directory of the cedar repository.

set -euo pipefail

# Bump crate versions.
(yes || true) | cargo release version minor \
    --exclude cedar-language-server \
    --execute

# Get the (newly bumped) crate version of cedar-policy.
crate_version() {
    cargo metadata --no-deps --format-version 1 \
        | jq -r ".packages[] | select(.name == \"$1\") | .version"
}
cedar_policy_version=$(crate_version cedar-policy)

# Update cedar-policy/src/test/test.rs to fill in the new crate version:
# ```
#     #[test]
#     fn test_sdk_version() {
#         assert_eq!(get_sdk_version().to_string(), "<CEDAR_POLICY_CRATE_VERSION>");
#     }
# ```
sed -i -E \
    "s|(get_sdk_version\(\)\.to_string\(\), \")[^\"]*(\")|\1${cedar_policy_version}\2|" \
    cedar-policy/src/test/test.rs

# Record the current Cedar language version.
language_version=$(cargo run -p cedar-policy-cli -- language-version | awk '{print $NF}')

# Update changes logs.
(yes || true) | cargo release replace --execute

# Fill-in the placeholders for the language version.
sed -i 's|\$CEDAR_LANGUAGE_VERSION\$|'"${language_version}"'|g' \
    cedar-policy/CHANGELOG.md \
    cedar-policy-symcc/CHANGELOG.md