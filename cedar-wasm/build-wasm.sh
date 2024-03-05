#!/bin/bash
# This script calls wasm-pack build and post-processes the generated TS types to fix them.
# Without this, the built wasm still works, but the Typescript definitions made by tsify don't.
set -e
cargo build
wasm-pack build --scope amzn --target web

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
echo "export type TypeOfAttribute = SchemaType & { required?: boolean };" >> pkg/cedar_wasm.d.ts
echo "Finished post-processing types file"