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

    process_types_file "pkg/esm/cedar_wasm.d.ts"
    process_types_file "pkg/nodejs/cedar_wasm.d.ts"
    process_types_file "pkg/web/cedar_wasm.d.ts"
}

fix_package_json_files() {
    jq -s '.[0] * .[1]' pkg/esm/package.json package.json.patch > pkg/package.json
    echo "Created root package.json"
    mv esm/package.json esm/package.json.bak
    mv web/package.json web/package.json.bak
    mv nodejs/package.json nodejs/package.json.bak
    jq -s '. + {"type": "module"}' esm/package.json.bak > esm/package.json
    jq -s '. + {"type": "module"}' web/package.json.bak > web/package.json
    jq -s '. + {"type": "commonjs"}' nodejs/package.json.bak > nodejs/package.json
    rm esm/package.json.bak
    rm web/package.json.bak
    rm nodejs/package.json.bak
    echo "Patched sub-package json files"
}

process_types_file() {
    local types_file="$1"
    echo "processing types file: $1"
    sed -i "s/[{]\s*!: /{ \"!\": /g" "$types_file"
    sed -i "s/[{]\s*==: /{ \"==\": /g" "$types_file"
    sed -i "s/[{]\s*!=: /{ \"!=\": /g" "$types_file"
    sed -i "s/[{]\s*<: /{ \"<\": /g" "$types_file"
    sed -i "s/[{]\s*<=: /{ \"<=\": /g" "$types_file"
    sed -i "s/[{]\s*>: /{ \">\": /g" "$types_file"
    sed -i "s/[{]\s*>=: /{ \">=\": /g" "$types_file"
    sed -i "s/[{]\s*&&: /{ \"\&\&\": /g" "$types_file"
    sed -i "s/[{]\s*||: /{ \"||\": /g" "$types_file"
    sed -i "s/[{]\s*[+]: /{ \"+\": /g" "$types_file"
    sed -i "s/[{]\s*-: /{ \"-\": /g" "$types_file"
    sed -i "s/[{]\s*[*]: /{ \"*\": /g" "$types_file"
    sed -i "s/[{]\s*\.: /{ \".\": /g" "$types_file"
    sed -i "s/ | __skip//g" "$types_file"
    sed -i "s/SchemaFragment/SchemaJson/g" "$types_file"
    sed -i "s/[{] json: JsonValueWithNoDuplicateKeys /{ json: SchemaJson /g" "$types_file"

    echo "type SmolStr = string;" >> "$types_file"
    echo "type Name = string;" >> "$types_file"
    echo "type Id = string;" >> "$types_file"
    echo "export type TypeOfAttribute = SchemaType & { required?: boolean };" >> "$types_file"
    echo "export type Context = Record<string, CedarValueJson>;" >> "$types_file"
}


main
echo "Finished custom build script"
