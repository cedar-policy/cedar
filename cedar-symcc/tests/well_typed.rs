/*
 * Copyright Cedar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use cedar_policy::{Policy, Schema, Validator};
use cedar_symcc::{solver::LocalSolver, SymCompiler, SymEnv, WellTypedPolicy};
use utils::Environments;
mod utils;

// Comment from corresponding Lean test in
// https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/SymTest/WellTyped.lean

// This file contains unit tests that show the symbolic compiler (`compile()`)
// does not error on policies that are well-typed according to the `WellTyped`
// constraints established by Cedar's typechecker; see
// `Cedar.Thm.Validation.WellTyped.Definition` and `Cedar.Thm.WellTyped` for
// details.  We also include tests that show that the symbolic compiler can error
// on policies that do not satisfy `WellTyped` constraints .

// Eventually, we will want to _prove_ that the symbolic compiler never errors on
// `WellTyped` policies.

// In practice, this means that we have to ensure that an analysis calls the
// symbolic compiler _only_ on policies that are well-typed, as established by
// `symcc::well_typed_policy()` or `symcc::well_typed_policies()`.

// To see why the compiler may fail on policies that pass validation (but are not
// made to be well-typed through validator transformations), consider the following
// policy where the type of `context` is `{foo: Long, bar?: Bool}`:

// ```
// // Policy A
// permit(principal, action, resource)
// when {
//   if ((- context.foo < 0) && (context has baz))  // condition
//   then 1
//   else context has bar
// };
// ```

// Policy A passes validation. In particular, the validator types the entire
// condition as `ff` because `context has baz` is known to be false from the type
// of `context`. Given this, the validator concludes that the `then`-branch, which
// is ill-typed, can never be executed so it can be safely ignored.  The `else`
// branch is well-typed (as a boolean), so validation as a whole passes.

// However, the symbolic compiler _rejects_ this policy with a type error because
// it sees that the `then`-branch does not have a boolean type.  The compiler must
// examine the `then` branch since it concludes, correctly, that the condition does
// _not_ always evaluate to `false`. The condition evaluates to _either_ an
// arithmetic overflow error _or_ false, and the compiler's encoding reflects this
// fact, in order to be sound and complete with respect to full Cedar semantics.
// (The validator is free to ignore all errors that aren't type errors, but the
// compiler is not.)

// This brings up a natural question: can't we just make the symbolic compiler
// smarter? After all, while the condition is not always false, it is indeed the
// case that we _can_ safely ignore the `then` branch here because it can _never_
// be executed:  either execution fails when checking the condition due to an
// arithmetic overflow error, or execution succeeds with `false`, falling through
// to the `else` branch. So, it seems like it should be possible to develop a set
// of _local_ rewrites of Terms that are "either error or a boolean constant" to
// infer when a branch cannot be executed.

// Unfortunately, this is not possible because of two lines of code in the
// validator:
//  * https://github.com/cedar-policy/cedar-spec/blob/356b86d13971224ff0553af6c33f19e1a3f7bd2a/cedar-lean/Cedar/Validation/Typechecker.lean#L190
//  * https://github.com/cedar-policy/cedar-spec/blob/356b86d13971224ff0553af6c33f19e1a3f7bd2a/cedar-lean/Cedar/Validation/Typechecker.lean#L244

// These two lines use capability information to infer that the type of a `has` or
// `hasTag` expression is the constant `tt`. Note that these are the only two lines
// in the validator that do this---everywhere else, deciding if the type of an
// expression is `tt` or `ff` is done from bottom-up (local) information, without
// referencing capabilities, which are pushing context-sensitive information
// top-down.

// Here is an example policy, with the same `context` type as before, where the
// validator uses this code to conclude that the policy is well-typed:

// ```
// // Policy B
// permit(principal, action, resource)
// when {
//   if context has bar
//   then if context has bar then context.bar else 1
//   else true
// };
// ```

// If it weren't for these two lines of code, it would indeed be possible for the
// symbolic compiler to use local rewrites to eliminate dead branches as often as
// the validator.  And we cannot eliminate these two lines of code because it would
// reduce validator precision (i.e., reject more policies), which is a breaking
// change.

// For the symbolic compiler to reproduce these inferences, we would need to start
// propagating contextual information---specifically, the path condition---from the
// top down, just like the validator. It is possible to do this and to prove it
// correct (see https://dl.acm.org/doi/10.1145/3498709), but it would require
// invasive changes to both the compiler and all the accompanying proofs.  We can
// do this if we find that calling the typechecker prior to symbolic compilation
// introduces too much of a burden in practice (e.g., by making debugging difficult
// due to the deepening of the analysis pipeline).

fn schema() -> Schema {
    utils::schema_from_cedarstr(
        r#"
        entity P;
        entity R;
        type Context = {
            foo: Long,
            bar?: Bool
        };
        action view
            appliesTo {
            principal: [P],
            resource: [R],
            context: Context
            };
    "#,
    )
}

fn policy_a(validator: &Validator) -> Policy {
    utils::policy_from_text(
        "policy_a",
        r#"permit(principal, action, resource)
        when {
        if ((- context.foo < 0) && (context has baz))  // condition
        then 1
        else context has bar
        };"#,
        validator,
    )
}

fn policy_b(validator: &Validator) -> Policy {
    utils::policy_from_text(
        "policy_b",
        r#"permit(principal, action, resource)
            when {
            if context has bar
            then if context has bar then context.bar else 1
            else true
            };"#,
        validator,
    )
}

async fn test_fail_on_ill_typed(
    p: &Policy,
    symenv: &SymEnv,
    compiler: &mut SymCompiler<LocalSolver>,
) {
    let res = compiler.check_never_errors(p.as_ref(), symenv).await;
    assert!(
        res.is_err(),
        "check_never_error of {p} fails due to type errors",
    );
}

async fn test_succeeds_on_well_typed(
    p: &Policy,
    env: &Environments<'_>,
    compiler: &mut SymCompiler<LocalSolver>,
    expected: bool,
) {
    let p = WellTypedPolicy::from_policy(p, &env.req_env, env.schema).unwrap();
    let res = compiler.check_never_errors(p.policy(), &env.symenv).await;
    assert!(
        res.is_ok_and(|r| r == expected),
        "check_never_error of {} succeeds with outcome {}",
        p,
        expected
    );
}

#[tokio::test]
async fn tests_for_ill_typed() {
    let schema = schema();
    let validator = Validator::new(schema);
    let policy_a = policy_a(&validator);
    let policy_b = policy_b(&validator);

    let mut compiler = SymCompiler::new(LocalSolver::cvc5().unwrap());
    let envs = Environments::new(validator.schema(), "P", "Action::\"view\"", "R");
    test_fail_on_ill_typed(&policy_a, &envs.symenv, &mut compiler).await;
    test_fail_on_ill_typed(&policy_b, &envs.symenv, &mut compiler).await;
}

#[tokio::test]
async fn tests_for_well_typed() {
    let schema = schema();
    let validator = Validator::new(schema);
    let policy_a = policy_a(&validator);
    let policy_b = policy_b(&validator);

    let mut compiler = SymCompiler::new(LocalSolver::cvc5().unwrap());
    let envs = Environments::new(validator.schema(), "P", "Action::\"view\"", "R");
    test_succeeds_on_well_typed(&policy_a, &envs, &mut compiler, false).await;
    test_succeeds_on_well_typed(&policy_b, &envs, &mut compiler, true).await;
}
