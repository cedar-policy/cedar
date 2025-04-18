#!/bin/bash

# Replace the changelog files by the static changelog files used for release branches.
# Only replace the files if they could be found in their expected location. Do nothing otherwise.

CEDAR_POLICY_CHANGELOG="cedar-policy/CHANGELOG.md"
CEDAR_POLICY_CLI_CHANGELOG="cedar-policy-cli/CHANGELOG.md"
CEDAR_WASM_CHANGELOG="cedar-wasm/CHANGELOG.md"

STATIC_CEDAR_POLICY_CHANGELOG="scripts/static_changelogs/cedar-policy_CHANGELOG.md"
STATIC_CEDAR_POLICY_CLI_CHANGELOG="scripts/static_changelogs/cedar-policy-cli_CHANGELOG.md"
STATIC_CEDAR_WASM_CHANGELOG="scripts/static_changelogs/cedar-wasm_CHANGELOG.md"

if [ -f "$CEDAR_POLICY_CHANGELOG" ] && [ -f "$CEDAR_POLICY_CLI_CHANGELOG" ] && [ -f "$CEDAR_WASM_CHANGELOG" ]; then
    cp $STATIC_CEDAR_POLICY_CHANGELOG $CEDAR_POLICY_CHANGELOG
    cp $STATIC_CEDAR_POLICY_CLI_CHANGELOG $CEDAR_POLICY_CLI_CHANGELOG
    cp $STATIC_CEDAR_WASM_CHANGELOG $CEDAR_WASM_CHANGELOG

    echo "Success! The changelog files have been normalized"
else
    echo "Error: The changelogs files could not be located. No actions taken."
    echo "This script must be run from the root directory. Did you run it from another directory?"
fi
