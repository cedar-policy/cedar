#!/usr/bin/env bash
# Build the TPE explorer's WASM bindings into OUT_DIR (default: ./pkg) as an
# ES module for bundlers (webpack's asyncWebAssembly).
#
# Requires: the wasm32-unknown-unknown target, and the wasm-bindgen CLI at
# the exact version pinned in Cargo.toml.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT_DIR="${1:-pkg}"
PROFILE="${PROFILE:-wasm}"

want=$(sed -n 's/^wasm-bindgen = { version = "=\([^"]*\)".*/\1/p' Cargo.toml)
have=$(wasm-bindgen --version 2>/dev/null | awk '{print $2}' || true)
if [ "$want" != "$have" ]; then
  echo "need wasm-bindgen CLI $want (found '${have:-none}'): cargo install wasm-bindgen-cli --version $want" >&2
  exit 1
fi

cargo build -p cedar-tpe-explorer --no-default-features --features wasm \
  --target wasm32-unknown-unknown --profile "$PROFILE"
dir=$([ "$PROFILE" = dev ] && echo debug || echo "$PROFILE")
target="${CARGO_TARGET_DIR:-$(cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')}"
wasm-bindgen --target bundler --out-dir "$OUT_DIR" \
  "$target/wasm32-unknown-unknown/$dir/cedar_tpe_explorer.wasm"
echo "wrote $OUT_DIR"
