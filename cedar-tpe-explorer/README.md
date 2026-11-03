# cedar-tpe-explorer

An interactive explorer for Cedar's type-aware partial evaluation (TPE).
Fill in what you know about a request, and each policy shows its residual: what is
already decided and what it still depends on. Suggestions come from Cedar's
symbolic compiler (SymCC) with CVC5. They are minimized with TPE down to a few facts
that settle a policy.

## Terminal UI

Needs `cvc5` on `PATH` (or set `$CVC5`).

```sh
cargo run -p cedar-tpe-explorer -- cedar-tpe-explorer/sample-data/photoapp
```

The TUI reads the `*.cedarschema` and `*.cedar` files in the given directory
(default `.`). Press `?` for keys.

## Web

`scripts/build-wasm.sh OUT_DIR` builds the WASM bindings (`--features wasm`) for
the explorer page on the Cedar website. You need the `wasm32-unknown-unknown` target
and the `wasm-bindgen` CLI version pinned in `Cargo.toml`.
