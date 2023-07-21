#!/bin/bash
set -euo pipefail

cedar_policy_version="$(
  cd head &&
  cargo metadata --format-version 1 |
    jq --raw-output '.packages[] | select(.name == "cedar-policy") | .version'
)"
echo "HEAD has cedar-policy at ${cedar_policy_version}"

tmp_dir="$(mktemp -d)"
function cleanup {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

(
  cd "${tmp_dir}"

  cat <<EOF >Cargo.toml
[package]
name = "cedar-semver-checks"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
cedar-policy = "<=${cedar_policy_version}"
EOF

  mkdir src
  touch src/lib.rs

  cargo vendor
)

mkdir base
mv "${tmp_dir}/vendor/cedar-policy" base/
cat <<EOF >base/Cargo.toml
[workspace]
members = ["cedar-policy"]
EOF
