#!/bin/bash

# Publishes the Cedar crates to crates.io in the specified order.

CRATES=(
    "cedar-policy-core"
    "cedar-policy-validator"
    "cedar-policy-formatter"
    "cedar-policy"
    "cedar-policy-cli"
)

for crate in "${CRATES[@]}"; do
    echo "Publishing $crate..."
    if ! cargo publish -p "$crate"; then
        echo "Failed to publish $crate"
        exit 1
    fi
done

echo "All crates published successfully!"
