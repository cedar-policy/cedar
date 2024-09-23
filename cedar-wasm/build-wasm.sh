#!/bin/bash
# Copyright Cedar Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script calls wasm-pack build and post-processes the generated TS types to fix them.
# It also produces three sets of outputs for different needs of different consumers
# Without this, the built wasm still works, but the Typescript definitions made by tsify don't.
#
# This sript requires wasm-pack and (if TEST_TS is set) tsc. To install wasm-pack, run
# `cargo install wasm-pack`. To install tsc, run `npm install -g typescript`.
#
# This script may not work on macOS. If you encounter an error like
# `error: failed to build archive: 'wasm32.o': section too large`,
# please upgrade the LLVM version using homebrew.

set -e
main () {
    rm -rf pkg || true
    mkdir pkg
    cargo build
    wasm-pack build --scope cedar-policy --target bundler --out-dir pkg/esm
    wasm-pack build --scope cedar-policy --target nodejs  --out-dir pkg/nodejs
    wasm-pack build --scope cedar-policy --target web  --out-dir pkg/web
    cp pkg/esm/README.md pkg/README.md

    fix_package_json_files

    # Post-process TS types
    process_types_file "pkg/esm/cedar_wasm.d.ts"
    process_types_file "pkg/nodejs/cedar_wasm.d.ts"
    process_types_file "pkg/web/cedar_wasm.d.ts"

    if [[ -n "${TEST_TS}" ]]; then
        # Check that then modified TS files are valid
        check_types_file "pkg/esm/cedar_wasm.d.ts"
        check_types_file "pkg/nodejs/cedar_wasm.d.ts"
        check_types_file "pkg/web/cedar_wasm.d.ts"
    fi
}

fix_package_json_files() {
    jq -s '.[0] * .[1]' pkg/esm/package.json package.json.patch > pkg/package.json
    echo "Created root package.json"
    mv pkg/esm/package.json pkg/esm/package.json.bak
    mv pkg/web/package.json pkg/web/package.json.bak
    mv pkg/nodejs/package.json pkg/nodejs/package.json.bak
    jq '. + {"type": "module"}' pkg/esm/package.json.bak > pkg/esm/package.json
    jq '. + {"type": "module"}' pkg/web/package.json.bak > pkg/web/package.json
    jq '. + {"type": "commonjs"}' pkg/nodejs/package.json.bak > pkg/nodejs/package.json
    rm pkg/esm/package.json.bak
    rm pkg/web/package.json.bak
    rm pkg/nodejs/package.json.bak
    echo "Patched sub-package json files"
}

process_types_file() {
    local types_file="$1"
    echo "processing types file: $1"

    sed -e '
    s/{[[:space:]]*!: /{ "!": /g
    s/{[[:space:]]*==: /{ "==": /g
    s/{[[:space:]]*!=: /{ "!=": /g
    s/{[[:space:]]*<: /{ "<": /g
    s/{[[:space:]]*<=: /{ "<=": /g
    s/{[[:space:]]*>: /{ ">": /g
    s/{[[:space:]]*>=: /{ ">=": /g
    s/{[[:space:]]*&&: /{ "\&\&": /g
    s/{[[:space:]]*||: /{ "||": /g
    s/{[[:space:]]*+: /{ "+": /g
    s/{[[:space:]]*-: /{ "-": /g
    s/{[[:space:]]*\*: /{ "*": /g
    s/{[[:space:]]*\.: /{ ".": /g
    s/ | __skip//g
    s/ { .*: __skip } |//g
    ' "$types_file" > "$types_file.tmp" && mv "$types_file.tmp" "$types_file"

    echo "type SmolStr = string;" >> "$types_file"
    echo "export type TypeOfAttribute<N> = Type<N> & { required?: boolean };" >> "$types_file"
}

check_types_file() {
    local types_file="$1"
    echo "checking types file: $1"
    tsc --noEmit "$types_file"
}

main
echo "Finished custom build script"
