#!/usr/bin/env bash
# Verify the crate with Verus. Every function is verified
# (--no-external-by-default): no panic, no arithmetic overflow, termination,
# and the `verus_spec` contracts.
#
# VERUS: the verus binary (default ~/tools/verus-dl/verus-x86-linux/verus).
# VERUS_Z3_PATH: a z3 that runs on this host (the bundled one needs glibc 2.38;
# default: ~/tools/z3-4.16.0/bin/z3).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERUS="${VERUS:-$HOME/tools/verus-dl/verus-x86-linux/verus}"
export VERUS_Z3_PATH="${VERUS_Z3_PATH:-$HOME/tools/z3-4.16.0/bin/z3}"
"$VERUS" --crate-type=lib --no-external-by-default --edition=2021 "$here/src/lib.rs" "$@" 2>&1 | grep -v GLIBC
