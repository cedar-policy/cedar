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

//! A simple interface to an SMT solver.
//!
//! Callers communicate with the solver by issuing commands with s-expressions
//! encoded as strings. The interface is based on
//! [lean-smt](https://github.com/ufmg-smite/lean-smt/).
//!
//! Currently, we support only CVC5, running locally in a separate process. The
//! function `LocalSolver::cvc5()` creates a fresh CVC5 solver process. This
//! uses the value of the environment variable `CVC5` as the absolute path to
//! the CVC5 executable, or if the environment variable is not set, looks for
//! `cvc5` on the `PATH`.
//!
//! This module does not correspond in lockstep to Lean's `Solver.lean`, partly
//! because Rust and Lean have different needs for solver functionality, and
//! partly because the functionality in this module is not difftested and has no
//! proofs about it on the Lean side.

use super::smtlib_script::SmtLibScript;
use miette::Diagnostic;
use std::{future::Future, path::Path, process::Stdio};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout, Command};

/// Satisfiability decision from the SMT solver.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[allow(missing_docs)]
pub enum Decision {
    Sat,
    Unsat,
    Unknown,
}

/// Errors when interacting with a [`Solver`] instance.
/// Corresponds to various errors in the Lean version at `Cedar.SymCC.Solver`
#[derive(Debug, Diagnostic, Error)]
pub enum SolverError {
    /// IO error.
    #[error("IO error during a solver operation")]
    Io(#[from] std::io::Error),
    /// Error from the solver.
    #[error("solver error: {0}")]
    Solver(String),
    /// Unrecognized solver output.
    #[error("unrecognized solver output: {0}")]
    UnrecognizedSolverOutput(String),
}
type Result<T> = std::result::Result<T, SolverError>;

/// Trait for things which are capable of solving SMTLib queries
///
/// Does not really correspond to Lean's `Solver` type; see comments on this
/// module
pub trait Solver {
    /// Get the input stream for the solver, so that you can write (more) input
    /// to it. This input is expected to be in SMTLib format.
    ///
    /// Returns a `&mut dyn tokio::io::AsyncWrite`, which gets the methods in
    /// the trait `SmtLibScript` for free, as long as the `SmtLibScript` trait
    /// is brought into scope.
    fn smtlib_input(&mut self) -> &mut (dyn tokio::io::AsyncWrite + Unpin + Send);
    /// Execute the query that has been written via `script()`, returning the `Decision`.
    ///
    /// This function is also responsible for adding `SmtLibScript::check_sat()`.
    ///
    /// This signature could be written
    /// `async fn check_sat(&mut self) -> Result<Decision>;`
    /// but that would not allow us to include the `Send` bound we need.
    /// What you see here is basically a desugaring of the above, plus the
    /// `Send` bound. See <https://blog.rust-lang.org/2023/12/21/async-fn-rpit-in-traits/#async-fn-in-public-traits>
    ///
    /// Note that implementors of this trait, like `LocalSolver` and
    /// `WriterSolver` below, can still use the `async fn` syntax sugar to
    /// implement this.
    fn check_sat(&mut self) -> impl Future<Output = Result<Decision>> + Send;
    /// Call `(get-model)` and return the SMT model as a string.
    fn get_model(&mut self) -> impl Future<Output = Result<Option<String>>> + Send;
}

/// Implements `Solver` by launching an SMT solver in a new process and
/// communicating with it
#[derive(Debug)]
pub struct LocalSolver {
    solver_stdin: BufWriter<ChildStdin>,
    solver_stdout: BufReader<ChildStdout>,
    #[expect(unused)]
    solver_stderr: BufReader<ChildStderr>,
}

impl LocalSolver {
    fn new<'a>(path: impl AsRef<Path>, args: impl IntoIterator<Item = &'a str>) -> Result<Self> {
        let child = Command::new(path.as_ref())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let (stdin, stdout, stderr) = match (child.stdin, child.stdout, child.stderr) {
            (Some(stdin), Some(stdout), Some(stderr)) => (stdin, stdout, stderr),
            _ => {
                return Err(SolverError::Solver(
                    "Failed to fetch IO pipes for solver process".into(),
                ))
            }
        };
        Ok(Self {
            solver_stdin: BufWriter::new(stdin),
            solver_stdout: BufReader::new(stdout),
            solver_stderr: BufReader::new(stderr),
        })
    }

    /// Spawns a cvc5 solver process by looking up the
    /// executable using the `CVC5` environment variable
    /// or the `cvc5` binary in `PATH`.
    pub fn cvc5() -> Result<Self> {
        Self::new(
            std::env::var("CVC5").unwrap_or_else(|_| "cvc5".into()),
            ["--lang", "smt", "--tlimit=60000"], // limit of 60000ms = 1 min of wall time for local solves, for now
        )
    }
}

impl Solver for LocalSolver {
    fn smtlib_input(&mut self) -> &mut (dyn tokio::io::AsyncWrite + Unpin + Send) {
        &mut self.solver_stdin
    }

    async fn check_sat(&mut self) -> Result<Decision> {
        self.smtlib_input().check_sat().await?;
        self.solver_stdin.flush().await?;
        let mut output = String::new();
        self.solver_stdout.read_line(&mut output).await?;
        match output.as_str() {
            "sat\n" => Ok(Decision::Sat),
            "unsat\n" => Ok(Decision::Unsat),
            "unknown\n" => Ok(Decision::Unknown),
            s => match s
                .strip_prefix("(error \"")
                .and_then(|s| s.strip_suffix("\")\n"))
            {
                Some(e) => Err(SolverError::Solver(e.to_string())),
                _ => Err(SolverError::UnrecognizedSolverOutput(output)),
            },
        }
    }

    async fn get_model(&mut self) -> Result<Option<String>> {
        self.smtlib_input().get_model().await?;
        self.solver_stdin.flush().await?;
        let mut output = String::new();

        // We assume that the output is one of the following forms:
        // 1. "(\n<the actual model>\n)\n"
        // 2. "(error ...)\n"

        // Read the first line
        self.solver_stdout.read_line(&mut output).await?;
        match output.as_str() {
            "(\n" => {
                // Read until a line ")\n"
                loop {
                    let len: usize = self.solver_stdout.read_line(&mut output).await?;
                    if &output[output.len() - len..] == ")\n" {
                        break;
                    }
                }
                Ok(Some(output))
            }

            s => match s
                .strip_prefix("(error \"")
                .and_then(|s| s.strip_suffix("\")\n"))
            {
                Some(e) => Err(SolverError::Solver(e.to_string())),
                _ => Err(SolverError::UnrecognizedSolverOutput(output)),
            },
        }
    }
}

/// Implements `Solver` by writing all issued commands to the given
/// `tokio::io::AsyncWrite`.
/// `check_sat()` writes the command to `f` and then returns `Decision::Unknown`,
/// which is sound but not very useful.
/// The purpose of this is for testing that only cares about the contents of the
/// script.
#[derive(Debug)]
pub struct WriterSolver<W> {
    /// where the `WriterSolver` will write the SMTLib commands to
    pub w: W,
}

impl<W: tokio::io::AsyncWrite + Unpin + Send> Solver for WriterSolver<W> {
    fn smtlib_input(&mut self) -> &mut (dyn tokio::io::AsyncWrite + Unpin + Send) {
        &mut self.w
    }
    async fn check_sat(&mut self) -> Result<Decision> {
        self.smtlib_input().check_sat().await?;
        self.w.flush().await?;
        Ok(Decision::Unknown)
    }
    async fn get_model(&mut self) -> Result<Option<String>> {
        self.smtlib_input().get_model().await?;
        self.w.flush().await?;
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn empty_cvc5_run() {
        let mut my_solver = LocalSolver::cvc5().unwrap();
        let decision = my_solver.check_sat().await.unwrap();
        assert_eq!(decision, Decision::Sat);
    }

    #[tokio::test]
    async fn set_logic_test() {
        let mut my_solver = LocalSolver::cvc5().unwrap();
        my_solver.smtlib_input().set_logic("ALL").await.unwrap();
        let decision = my_solver.check_sat().await.unwrap();
        assert_eq!(decision, Decision::Sat);
    }

    #[tokio::test]
    async fn comment_test() {
        let mut my_solver = LocalSolver::cvc5().unwrap();
        my_solver
            .smtlib_input()
            .comment("(assert false)")
            .await
            .unwrap();
        let decision = my_solver.check_sat().await.unwrap();
        assert_eq!(decision, Decision::Sat);
    }

    #[tokio::test]
    async fn comment_escaping_test() {
        let mut my_solver = LocalSolver::cvc5().unwrap();
        my_solver
            .smtlib_input()
            .comment("\n(assert false)")
            .await
            .unwrap();
        let decision = my_solver.check_sat().await.unwrap();
        assert_eq!(decision, Decision::Sat);
    }

    #[tokio::test]
    async fn unsat_test() {
        let mut my_solver = LocalSolver::cvc5().unwrap();
        my_solver.smtlib_input().assert("false").await.unwrap();
        let decision = my_solver.check_sat().await.unwrap();
        assert_eq!(decision, Decision::Unsat);
    }

    #[tokio::test]
    async fn get_model_sat() {
        let mut my_solver = LocalSolver::cvc5().unwrap();
        my_solver
            .smtlib_input()
            .set_option("produce-models", "true")
            .await
            .unwrap();
        my_solver.smtlib_input().assert("true").await.unwrap();
        let decision = my_solver.check_sat().await.unwrap();
        assert_eq!(decision, Decision::Sat);
        let model = my_solver.get_model().await.unwrap();
        assert!(model.is_some());
    }

    #[tokio::test]
    async fn get_model_unsat() {
        let mut my_solver = LocalSolver::cvc5().unwrap();
        my_solver
            .smtlib_input()
            .set_option("produce-models", "true")
            .await
            .unwrap();
        my_solver.smtlib_input().assert("false").await.unwrap();
        let decision = my_solver.check_sat().await.unwrap();
        assert_eq!(decision, Decision::Unsat);
        assert!(my_solver.get_model().await.is_err());
    }
}
