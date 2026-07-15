# cedar-lean-symc

Transpile a Cedar policy-set into the equivalent Cedar Lean AST.

## Usage

```sh
cargo run -- --policy-file path/to/policies.cedar
```

produces:

```lean
import Cedar.Spec

open Cedar.Spec

def policy0 : Policy :=
  ⟨ "policy0",
    .permit,
    .principalScope (.any),
    .actionScope .any,
    .resourceScope (.any),
    [⟨.when, .getAttr (.var .resource) "isPublic"⟩] ⟩

def policies : Policies := [policy0]
```

## Properties

`--property <name>` appends a stubbed Lean theorem about the emitted policy set(s).

```sh
cargo run -- --policy-file policies.cedar --property always-allows
cargo run -- --policy-file policies.cedar --policy-file-b other.cedar --property equivalent
```

```lean
theorem policies_always_allows :
    ∀ (req : Request) (es : Entities),
      (isAuthorized req es policies).decision = .allow := by
  sorry

theorem policies_equivalent :
    ∀ (req : Request) (es : Entities),
      (isAuthorized req es policies).decision
        = (isAuthorized req es policiesB).decision := by
  sorry
```

## Proofs

This crate doesn't handle proving the properties. It only states properties for you.
The indented workflow with is something like

* Get Lean policy AST and stubbed theorem form this CLI
* In the `cedar-lean` directory of the `cedar-spec` repository, start `claude` or other similar AI development tool.
* Paste the policy definitions and stubbed theorem into the CLI with instructions to "prove or disprove".
* Wait for a proof.

## Testing

The tests check that everything compiles against a stubbed version of symcc.
This means `lean` must be on `PATH`.

## TODO

- More properties, for parity with SymCC's `verify*` (always-denies, implies,
  disjoint, never-errors, matches-* ...).
- Schema transpilation, and well-typed-input preconditions on the emitted
  theorems.
- Transitively-closed and acyclic entity-hierarchy preconditions.
- Entity-reference resolution precondition.
- Automate Claude Code proof interaction (discharge the emitted `sorry`s).
- Implement alternate compilation modes.
- Template linking: templates are emitted as `Template` defs but excluded from
  `policies` (which is `List Policy`); emit `TemplateLinkedPolicy`/link envs.
