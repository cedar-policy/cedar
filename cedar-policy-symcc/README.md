# Symbolic Cedar Compiler (SymCC)

With this library, you can
- Compile [Cedar](https://www.cedarpolicy.com/) policies to logical constraints in [SMT-LIB](https://smt-lib.org/).
- Formally verify a number of useful properties about your Cedar policies with concrete counterexamples.

Our symbolic compiler and verifiers themselves have been [formally modeled and verified in Lean](https://github.com/cedar-policy/cedar-spec/tree/main/cedar-lean#verified-properties)
to guarantee trustworthy verification results.

Currently SymCC supports formally verifying the following properties:
- Policy never errors (`CedarSymCompiler::check_never_errors`).
- Policy set always allows (`CedarSymCompiler::check_always_allows`).
- Policy set always denies (`CedarSymCompiler::check_always_denies`).
- Policy set subsumption (`CedarSymCompiler::check_implies`).
- Policy set equivalence (`CedarSymCompiler::check_equivalent`).
- Policy set disjointness (`CedarSymCompiler::check_disjoint`).

For each of them, we also have the `CedarSymCompiler::check_*_with_counterexample` counterparts that
produce a counterexample (a synthesized request and entity store) if the property is not true.

## Setup

To get started, first download or compile the [cvc5-1.2.1](https://github.com/cvc5/cvc5/releases/tag/cvc5-1.2.1) SMT solver.
The following example assumes that you have set the following environment variable:
```sh
CVC5=<path to cvc5 1.2.1 executable>
```

## Example

To verify that a policy set does not always allow:
```rust
use tokio;
use std::str::FromStr;
use cedar_policy::{Schema, PolicySet, Authorizer, Decision};
use cedar_policy_symcc::{solver::LocalSolver, CedarSymCompiler, SymEnv, WellTypedPolicies};

#[tokio::main]
async fn main() {
    // Parse Cedar schema
    let schema = Schema::from_cedarschema_str(r#"
        entity User;
        entity Document { owner: User };
        action view appliesTo {
            principal: [User],
            resource: [Document]
        };
    "#).unwrap().0;

    // Parse Cedar policy set
    let policy_set = PolicySet::from_str(r#"
        permit(principal, action == Action::"view", resource)
        when { resource.owner == principal };
    "#).unwrap();

    // Initialize the symbolic compiler
    let cvc5 = LocalSolver::cvc5().unwrap();
    let mut compiler = CedarSymCompiler::new(cvc5).unwrap();

    // Iterate through all request environments and check the property
    for req_env in schema.request_envs() {
        // Encode the request environment symbolically
        let sym_env = SymEnv::new(&schema, &req_env).unwrap();

        // Validate/type check the policy set
        let typed_policies = WellTypedPolicies::from_policies(&policy_set, &req_env, &schema).unwrap();

        // Verify that `policy_set` does not always allow any request
        let always_denies = compiler.check_always_allows(&typed_policies, &sym_env).await.unwrap();
        assert!(!always_denies);

        // Similar to above, but returns a counterexample (synthesized request and entity store)
        let cex = compiler.check_always_allows_with_counterexample(&typed_policies, &sym_env).await.unwrap().unwrap();
        let resp = Authorizer::new().is_authorized(&cex.request, &policy_set, &cex.entities);
        assert!(resp.decision() == Decision::Deny);
    }
}
```

To learn more about what you can do with SymCC, see the documentation of `CedarSymCompiler`.

## Developement

To build and test this crate, run from the root of the repository:
```sh
cargo build -p cedar-policy-symcc
CVC5=<absolute path to cvc5 1.2.1 executable> cargo test -p cedar-policy-symcc
```

Structure of this crate:
- `symcc` is the core library. It maps directly to the [Lean model](https://github.com/cedar-policy/cedar-spec/tree/main/cedar-lean/Cedar/SymCC).
- `lib.rs` is the frontend for `symcc`, and does not directly correspond to the Lean,
  but it provides an interface in terms of `cedar-policy` types rather than
  `cedar-policy-core` and `cedar-policy-validator` types.
