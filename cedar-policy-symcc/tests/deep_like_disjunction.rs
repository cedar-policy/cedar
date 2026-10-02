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

//! Checks that encoding a policy whose `when` clause is a deep `||` chain of
//! `like` checks on an optional attribute finishes in bounded time.

#![expect(clippy::panic, clippy::unwrap_used, reason = "unit test code")]

use std::{sync::mpsc, thread, time::Duration};

use cedar_policy::{Schema, Validator};
use cedar_policy_symcc::{solver::WriterSolver, CedarSymCompiler};

mod utils;
use utils::Environments;

/// Parsing `POLICY` overflows the default test-thread stack in debug builds.
const STACK_SIZE: usize = 64 << 20;

const TIMEOUT: Duration = Duration::from_secs(600);

fn sample_schema() -> Schema {
    utils::schema_from_cedarstr(
        r#"
        entity Gateway;
        entity OAuthUser tags String;

        action "action001" appliesTo {
          principal: [OAuthUser],
          resource: [Gateway],
          context: {
            input: {
              comment: String,
            },
          }
        };

        action "action002" appliesTo {
          principal: [OAuthUser],
          resource: [Gateway],
          context: {
            input: {
              comment?: String,
            },
          }
        };
    "#,
    )
}

const POLICY: &str = r#"forbid(
  principal is OAuthUser,
  action in [Action::"action001",Action::"action002"],
  resource is Gateway
) when {
  ((principal.hasTag("run_kind")) && ((principal.getTag("run_kind")) == "triggered")) && (((context.input) has comment) && ((((((((((((((((((((((((((((((((((((((((((((((((context.input).comment) like "/*") || (((context.input).comment) like " /*")) || (((context.input).comment) like "\t/*")) || (((context.input).comment) like "  /*")) || (((context.input).comment) like " \t/*")) || (((context.input).comment) like "\t /*")) || (((context.input).comment) like "\t\t/*")) || (((context.input).comment) like "   /*")) || (((context.input).comment) like "  \t/*")) || (((context.input).comment) like " \t /*")) || (((context.input).comment) like " \t\t/*")) || (((context.input).comment) like "\t  /*")) || (((context.input).comment) like "\t \t/*")) || (((context.input).comment) like "\t\t /*")) || (((context.input).comment) like "\t\t\t/*")) || (((context.input).comment) like "*\n/*")) || (((context.input).comment) like "*\n /*")) || (((context.input).comment) like "*\n\t/*")) || (((context.input).comment) like "*\n  /*")) || (((context.input).comment) like "*\n \t/*")) || (((context.input).comment) like "*\n\t /*")) || (((context.input).comment) like "*\n\t\t/*")) || (((context.input).comment) like "*\n   /*")) || (((context.input).comment) like "*\n  \t/*")) || (((context.input).comment) like "*\n \t /*")) || (((context.input).comment) like "*\n \t\t/*")) || (((context.input).comment) like "*\n\t  /*")) || (((context.input).comment) like "*\n\t \t/*")) || (((context.input).comment) like "*\n\t\t /*")) || (((context.input).comment) like "*\n\t\t\t/*")) || (((context.input).comment) like "*\r/*")) || (((context.input).comment) like "*\r /*")) || (((context.input).comment) like "*\r\t/*")) || (((context.input).comment) like "*\r  /*")) || (((context.input).comment) like "*\r \t/*")) || (((context.input).comment) like "*\r\t /*")) || (((context.input).comment) like "*\r\t\t/*")) || (((context.input).comment) like "*\r   /*")) || (((context.input).comment) like "*\r  \t/*")) || (((context.input).comment) like "*\r \t /*")) || (((context.input).comment) like "*\r \t\t/*")) || (((context.input).comment) like "*\r\t  /*")) || (((context.input).comment) like "*\r\t \t/*")) || (((context.input).comment) like "*\r\t\t /*")) || (((context.input).comment) like "*\r\t\t\t/*")) || (((context.input).comment) like "*<!-- teleagent*")))
};"#;

#[derive(Debug, Clone, Copy)]
enum Check {
    AlwaysMatches,
    NeverMatches,
}

/// Compiles `POLICY` for `action002` and encodes `check`, panicking if that
/// takes longer than `TIMEOUT`.
fn compile_and_encode_within_timeout(check: Check) {
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(move || {
            let schema = sample_schema();
            let validator = Validator::new(schema.clone());
            let policy = utils::policy_from_text("policy20", POLICY, &validator);
            let envs = Environments::new(&schema, "OAuthUser", r#"Action::"action002""#, "Gateway");
            let compiled = envs.compile_policy(&policy);
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(async {
                let mut compiler = CedarSymCompiler::new(WriterSolver {
                    w: tokio::io::sink(),
                })
                .unwrap();
                match check {
                    Check::AlwaysMatches => compiler.check_always_matches_opt(&compiled).await,
                    Check::NeverMatches => compiler.check_never_matches_opt(&compiled).await,
                }
                .unwrap();
            });
            let _ = tx.send(());
        })
        .unwrap();
    match rx.recv_timeout(TIMEOUT) {
        Ok(()) => {}
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("{check:?} for the policy did not finish within {TIMEOUT:?}")
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("worker thread for {check:?} panicked; see output above")
        }
    }
}

#[test]
fn deep_like_disjunction_always_matches() {
    compile_and_encode_within_timeout(Check::AlwaysMatches);
}

#[test]
fn deep_like_disjunction_never_matches() {
    compile_and_encode_within_timeout(Check::NeverMatches);
}
