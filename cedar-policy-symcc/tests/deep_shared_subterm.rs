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

//! Encoding a `||` chain whose disjuncts all share one subterm must finish in bounded
//! time. Without the `Ord` pointer-identity fast path the encoder's `BTreeMap<Term, _>`
//! re-walks that shared subterm on every lookup and this does not terminate in any
//! practical time.

#![expect(clippy::panic, reason = "test asserts by panicking on timeout")]

use std::{sync::mpsc, thread, time::Duration};

use cedar_policy::Validator;
use cedar_policy_symcc::{solver::WriterSolver, CedarSymCompiler};

mod utils;
use utils::Environments;

/// Parsing a deeply nested expression overflows the default test-thread stack in debug.
const STACK_SIZE: usize = 64 << 20;
const TIMEOUT: Duration = Duration::from_secs(60);
const DISJUNCTS: usize = 48;

/// `forbid(...) when { c like "0" || c like "1" || ... }`, where every disjunct reads the
/// same `context.comment`.
fn policy_text() -> String {
    let d = (0..DISJUNCTS)
        .map(|i| format!(r#"(((context.input).comment) like "{i}*")"#))
        .collect::<Vec<_>>()
        .join(" || ");
    format!(
        r#"forbid(principal, action, resource) when {{ ((context.input) has comment) && ({d}) }};"#
    )
}

#[test]
fn encoding_a_deep_shared_subterm_terminates() {
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(move || {
            let schema = utils::schema_from_cedarstr(
                r#"
                entity User;
                entity Doc;
                action "read" appliesTo {
                  principal: [User],
                  resource: [Doc],
                  context: { input: { comment?: String } }
                };
                "#,
            );
            let validator = Validator::new(schema.clone());
            let policy = utils::policy_from_text("p", &policy_text(), &validator);
            let envs = Environments::new(&schema, "User", r#"Action::"read""#, "Doc");
            let compiled = envs.compile_policy(&policy);

            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(async {
                let mut compiler = CedarSymCompiler::new(WriterSolver {
                    w: tokio::io::sink(),
                })
                .unwrap();
                // The sink solver always answers `Unknown`, so the returned `Result` says
                // nothing; reaching this point at all is what the test asserts.
                let _ = compiler.check_never_matches_opt(&compiled).await;
            });
            let _ = tx.send(());
        })
        .unwrap();

    match rx.recv_timeout(TIMEOUT) {
        Ok(()) => {}
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!(
                "encoding {DISJUNCTS} shared-subterm disjuncts did not finish within {TIMEOUT:?}"
            )
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!("worker panicked; see output above"),
    }
}
