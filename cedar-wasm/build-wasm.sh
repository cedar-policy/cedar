#!/bin/bash
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

echo "type SmolStr = string;" >> pkg/cedar_wasm.d.ts
echo "Finished post-processing types file"