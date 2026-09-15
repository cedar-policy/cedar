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

//! Test-only helpers shared across `symcc` unit tests.
//!
//! In particular, the "deep has-chain" helpers below are used by the
//! exponential-blowup regression tests in both `encoder.rs` (encoding) and
//! `interpretation.rs` (interpretation), which guard against un-memoized
//! `Term` walks unfolding the shared `Term` DAG into an exponentially larger
//! tree.

#![cfg(test)]
#![expect(clippy::panic, reason = "test utilities")]

use std::fmt::Write;
use std::str::FromStr;

use cedar_policy::{RequestEnv, Schema};
use cedar_policy_core::ast::Expr;

use super::env::SymEnv;

/// Schema giving `User.deep` a chain of `depth` nested optional records:
/// `Deep0 { next?: Deep1 }`, ..., `Deep{depth-1} { next?: String }`, so that
/// `User.deep` has an attribute path of length `depth`.
pub(crate) fn deep_chain_schema(depth: usize) -> Schema {
    let mut src = String::new();
    for i in 0..depth {
        let next_ty = if i + 1 < depth {
            format!("Deep{}", i + 1)
        } else {
            "String".to_string()
        };
        // Infallible: writing to a String cannot fail.
        let _ = writeln!(src, "type Deep{i} = {{ next?: {next_ty} }};");
    }
    src += "entity User { deep: Deep0 };\n";
    src += "action View appliesTo { principal: [User], resource: [User] };\n";
    Schema::from_cedarschema_str(&src)
        .unwrap_or_else(|e| panic!("{:?}", miette::Report::new(e)))
        .0
}

/// A [`SymEnv`] for [`deep_chain_schema`] of the given depth, with a
/// `User`/`Action::"View"`/`User` request environment.
pub(crate) fn deep_chain_sym_env(depth: usize) -> SymEnv {
    SymEnv::new(
        &deep_chain_schema(depth),
        &RequestEnv::new(
            "User".parse().unwrap(),
            "Action::\"View\"".parse().unwrap(),
            "User".parse().unwrap(),
        ),
    )
    .expect("Malformed sym env.")
}

/// The expression `(if (principal has <path>) then principal else principal) has <path>`
/// where `<path>` is `deep.next.next...` of the given depth.
pub(crate) fn deep_has_chain_expr(depth: usize) -> Expr {
    let path = format!("deep{}", ".next".repeat(depth));
    let expr_str = format!("(if (principal has {path}) then principal else principal) has {path}");
    Expr::from_str(&expr_str)
        .unwrap_or_else(|e| panic!("Could not parse expression: {expr_str}: {e}"))
}
