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
# Without this, the built wasm still works, but the Typescript definitions made by tsify don't.
set -e
cargo build
wasm-pack build --scope amzn --target bundler

sed -i "s/[{]\s*!: /{ \"!\": /g" pkg/cedar_wasm.d.ts
sed -i "s/[{]\s*==: /{ \"==\": /g" pkg/cedar_wasm.d.ts
sed -i "s/[{]\s*!=: /{ \"!=\": /g" pkg/cedar_wasm.d.ts
sed -i "s/[{]\s*<: /{ \"<\": /g" pkg/cedar_wasm.d.ts
sed -i "s/[{]\s*<=: /{ \"<=\": /g" pkg/cedar_wasm.d.ts
sed -i "s/[{]\s*>: /{ \">\": /g" pkg/cedar_wasm.d.ts
sed -i "s/[{]\s*>=: /{ \">=\": /g" pkg/cedar_wasm.d.ts
sed -i "s/[{]\s*&&: /{ \"\&\&\": /g" pkg/cedar_wasm.d.ts
sed -i "s/[{]\s*||: /{ \"||\": /g" pkg/cedar_wasm.d.ts
sed -i "s/[{]\s*[+]: /{ \"+\": /g" pkg/cedar_wasm.d.ts
sed -i "s/[{]\s*-: /{ \"-\": /g" pkg/cedar_wasm.d.ts
sed -i "s/[{]\s*[*]: /{ \"*\": /g" pkg/cedar_wasm.d.ts
sed -i "s/[{]\s*\.: /{ \".\": /g" pkg/cedar_wasm.d.ts
sed -i "s/ | __skip//g" pkg/cedar_wasm.d.ts
sed -i "s/SchemaFragment/Schema/g" pkg/cedar_wasm.d.ts

echo "type SmolStr = string;" >> pkg/cedar_wasm.d.ts
echo "type Name = string;" >> pkg/cedar_wasm.d.ts
echo "type Id = string;" >> pkg/cedar_wasm.d.ts
echo "export type TypeOfAttribute = SchemaType & { required?: boolean };" >> pkg/cedar_wasm.d.ts
echo "export type Context = Record<string, CedarValueJson>;" >> pkg/cedar_wasm.d.ts
echo "Finished post-processing types file"