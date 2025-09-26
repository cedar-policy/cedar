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
use std::ffi::OsStr;
use std::future::Future;
use std::process::Stdio;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

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

/// A solver instance that communicates with a local SMT solver process
/// through stdin/stdout.
///
/// We officially support [cvc5](https://github.com/cvc5/cvc5),
/// but other SMT solvers such as [Z3](https://github.com/Z3Prover/z3)
/// may also work with a subset of SymCC's functionality.
///
/// Examples:
/// ```no_run
/// use tokio::process::Command;
/// use cedar_policy_symcc::solver::LocalSolver;
///
/// // Spawns a cvc5 process with the default arguments
/// let solver = LocalSolver::cvc5().unwrap();
///
/// // Spawns a cvc5 process with custom arguments
/// let solver = LocalSolver::cvc5_with_args(["--rlimit=1000"]).unwrap();
///
/// // Spawns a custom solver process
/// let solver = LocalSolver::from_command(Command::new("z3").args(["rlimit", "1000"])).unwrap();
/// ```
#[derive(Debug)]
pub struct LocalSolver {
    /// The spawned solver process.
    child: Child,
    solver_stdin: BufWriter<ChildStdin>,
    solver_stdout: BufReader<ChildStdout>,
    #[expect(unused)]
    solver_stderr: BufReader<ChildStderr>,
}

impl LocalSolver {
    /// Creates a new [`LocalSolver`] from a custom [`Command`].
    ///
    /// The input command is expected to behave as an interactive SMT solver
    /// that reads queries from stdin in SMT-LIB 2 format (e.g., `cvc5 --lang smt` or `z3`).
    pub fn from_command(cmd: &mut Command) -> Result<Self> {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let (stdin, stdout, stderr) =
            match (child.stdin.take(), child.stdout.take(), child.stderr.take()) {
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
            child,
        })
    }

    /// Spawns a cvc5 solver process by looking up the
    /// executable using the `CVC5` environment variable
    /// or the `cvc5` binary in `PATH`.
    pub fn cvc5() -> Result<Self> {
        let path = std::env::var("CVC5").unwrap_or_else(|_| "cvc5".into());
        // Limit of 60000ms = 1 min of wall time for local solves, for now
        Self::from_command(Command::new(path).args(["--lang", "smt", "--tlimit=60000"]))
    }

    /// Similar to [`Self::cvc5`] but with custom arguments.
    pub fn cvc5_with_args(args: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Result<Self> {
        let path = std::env::var("CVC5").unwrap_or_else(|_| "cvc5".into());
        Self::from_command(Command::new(path).args(["--lang", "smt"]).args(args))
    }
}

impl Solver for LocalSolver {
    fn smtlib_input(&mut self) -> &mut (dyn tokio::io::AsyncWrite + Unpin + Send) {
        &mut self.solver_stdin
    }

    async fn check_sat(&mut self) -> Result<Decision> {
        if let Some(status) = self.child.try_wait()? {
            Err(SolverError::Solver(format!(
                "Solver process terminated unexpectedly with status: {:?}",
                status.code()
            )))?
        }
        self.smtlib_input().check_sat().await?;
        self.solver_stdin.flush().await?;
        let mut output = String::new();
        self.read_line(&mut output).await?;
        match output.as_str() {
            "sat\n" => Ok(Decision::Sat),
            "unsat\n" => Ok(Decision::Unsat),
            "unknown\n" => Ok(Decision::Unknown),
            s => Err(Self::process_error_output(s).await),
        }
    }

    async fn get_model(&mut self) -> Result<Option<String>> {
        if let Some(status) = self.child.try_wait()? {
            Err(SolverError::Solver(format!(
                "Solver process terminated unexpectedly with status: {:?}",
                status.code()
            )))?
        }
        self.smtlib_input().get_model().await?;
        self.solver_stdin.flush().await?;
        let mut output = String::new();

        // We assume that the output is one of the following forms:
        // 1. "(\n<the actual model>\n)\n"
        // 2. "(error ...)\n"

        // Read the first line
        self.read_line(&mut output).await?;
        match output.as_str() {
            "(\n" => {
                // Read until a line ")\n"
                loop {
                    let len: usize = self.read_line(&mut output).await?;
                    if &output[output.len() - len..] == ")\n" {
                        break;
                    }
                }
                Ok(Some(output))
            }
            s => Err(Self::process_error_output(s).await),
        }
    }
}

impl LocalSolver {
    async fn read_line(&mut self, buffer: &mut String) -> Result<usize> {
        let len = self.solver_stdout.read_line(buffer).await?;
        if len == 0 {
            Err(SolverError::Solver(
                "Encountered EOF while reading from solver output".to_string(),
            ))
        } else {
            Ok(len)
        }
    }

    async fn process_error_output(s: &str) -> SolverError {
        match s
            .strip_prefix("(error \"")
            .and_then(|s| s.strip_suffix("\")\n"))
        {
            Some(e) => SolverError::Solver(e.to_string()),
            _ => SolverError::UnrecognizedSolverOutput(s.to_string()),
        }
    }

    /// Forces this solver's child process to exit.
    /// Waits for the child to exit completely.
    pub async fn clean_up(mut self) -> Result<()> {
        self.child.kill().await.map_err(|e| e.into())
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
    use cool_asserts::assert_matches;

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

    #[tokio::test]
    async fn parse_error_test() {
        let mut my_solver = LocalSolver::cvc5().unwrap();
        // Send an invalid expression to the solver.
        my_solver.smtlib_input().assert("tomato").await.unwrap();
        // Check that the solver reports an error.
        assert_matches!(my_solver.check_sat().await, Err(SolverError::Solver(_)));
        // Attempt to reset the solver.
        my_solver.smtlib_input().reset().await.unwrap();
        assert_matches!(my_solver.check_sat().await, Err(SolverError::Solver(x)) => { assert_eq!(x, "Encountered EOF while reading from solver output"); });
    }

    #[tokio::test]
    async fn clean_up_succeeds() {
        let my_solver = LocalSolver::cvc5().unwrap();
        my_solver.clean_up().await.unwrap();
    }
}
