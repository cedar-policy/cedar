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

//! A [`ModelFinder`] backed by Cedar's symbolic compiler (SymCC) and CVC5,
//! either as a local process ([`LocalModelFinder`]) or through a
//! [`BatchSolver`], which runs each query in one shot (e.g. CVC5 in WASM).

use cedar_policy_symcc::solver::{Decision, DecisionWithModel, Solver, SolverError};
use cedar_policy_symcc::{CedarSymCompiler, CompiledPolicy, SmtLibScript};
use std::fmt;
use std::future::Future;

use crate::{Model, ModelFinder, Project};

pub struct SymccModelFinder<S: Solver> {
    compiler: CedarSymCompiler<S>,
}

impl<S: Solver> fmt::Debug for SymccModelFinder<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymccModelFinder").finish_non_exhaustive()
    }
}

/// SymCC with a local `cvc5` process (found via `$CVC5` or `PATH`).
#[cfg(feature = "local-solver")]
pub type LocalModelFinder = SymccModelFinder<cedar_policy_symcc::solver::LocalSolver>;

#[cfg(feature = "local-solver")]
impl LocalModelFinder {
    /// Start a CVC5 process with a per-query time limit.
    pub fn new(time_limit_ms: u32) -> Result<Self, String> {
        let solver = cedar_policy_symcc::solver::LocalSolver::cvc5_with_args([format!(
            "--tlimit-per={time_limit_ms}"
        )])
        .map_err(|e| format!("could not start cvc5: {e}"))?;
        Self::with_solver(solver)
    }
}

impl<S: Solver> SymccModelFinder<S> {
    pub fn with_solver(solver: S) -> Result<Self, String> {
        Ok(Self {
            compiler: CedarSymCompiler::new(solver).map_err(|e| e.to_string())?,
        })
    }
}

impl<S: Solver> ModelFinder for SymccModelFinder<S> {
    async fn find_model(
        &mut self,
        project: &Project,
        policy: &cedar_policy::Policy,
        env: &cedar_policy::RequestEnv,
    ) -> Result<Option<Model>, String> {
        let compiled =
            CompiledPolicy::compile(policy, env, &project.schema).map_err(|e| e.to_string())?;
        // A counterexample to "never matches" is an input where it matches.
        let env = self
            .compiler
            .check_never_matches_with_counterexample_opt(&compiled)
            .await
            .map_err(|e| e.to_string())?;
        Ok(env.map(|e| Model {
            request: e.request,
            entities: e.entities,
        }))
    }
}

/// Runs a complete SMT-LIB script and returns the solver's standard output.
pub trait SmtRunner {
    fn run(&mut self, script: String) -> impl Future<Output = Result<String, String>>;
}

/// A [`Solver`] that buffers each query and runs it in one shot. This works
/// because SymCC starts every query with `(reset)`.
pub struct BatchSolver<R> {
    script: Vec<u8>,
    runner: R,
}

impl<R> fmt::Debug for BatchSolver<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BatchSolver").finish_non_exhaustive()
    }
}

impl<R: SmtRunner> BatchSolver<R> {
    pub fn new(runner: R) -> Self {
        Self {
            script: Vec::new(),
            runner,
        }
    }

    async fn run(&mut self, get_model: bool) -> Result<String, SolverError> {
        let mut script = String::from_utf8(std::mem::take(&mut self.script))
            .map_err(|e| SolverError::Solver(e.to_string()))?;
        script.push_str("(check-sat)\n");
        if get_model {
            script.push_str("(get-model)\n");
        }
        // `Solver` needs `Send` futures, but a runner's may not be (in WASM it
        // wraps a JS promise). We run on one thread; `SendWrapper` checks that.
        send_wrapper::SendWrapper::new(self.runner.run(script))
            .await
            .map_err(SolverError::Solver)
    }
}

/// Split solver output into the `check-sat` answer and the rest.
fn parse_decision(out: &str) -> Result<(Decision, &str), SolverError> {
    let out = out.trim_start();
    let (first, rest) = out.split_once('\n').unwrap_or((out, ""));
    let d = match first.trim() {
        "sat" => Decision::Sat,
        "unsat" => Decision::Unsat,
        "unknown" => Decision::Unknown,
        other => return Err(SolverError::UnrecognizedSolverOutput(other.to_string())),
    };
    Ok((d, rest))
}

impl<R: SmtRunner + Send> Solver for BatchSolver<R> {
    fn smtlib_input(&mut self) -> &mut (dyn tokio::io::AsyncWrite + Unpin + Send) {
        &mut self.script
    }

    async fn enable_models(&mut self) -> Result<(), SolverError> {
        Ok(self.script.set_option("produce-models", "true").await?)
    }

    async fn check_sat(&mut self) -> Result<Decision, SolverError> {
        let out = self.run(false).await?;
        Ok(parse_decision(&out)?.0)
    }

    async fn check_sat_with_model(&mut self) -> Result<DecisionWithModel, SolverError> {
        let out = self.run(true).await?;
        Ok(match parse_decision(&out)? {
            (Decision::Sat, model) => {
                let model = model.trim();
                if !model.starts_with('(') || model.starts_with("(error") {
                    return Err(SolverError::Solver(model.to_string()));
                }
                DecisionWithModel::Sat {
                    model: format!("{model}\n"),
                }
            }
            (Decision::Unsat, _) => DecisionWithModel::Unsat,
            (Decision::Unknown, _) => DecisionWithModel::Unknown,
        })
    }
}
