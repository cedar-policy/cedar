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

//! A pool of warm CVC5 solver processes for reusing across queries.
//!
//! This module provides [`SolverPool`], which maintains a pool of pre-warmed
//! solver processes that can be acquired and released efficiently, avoiding
//! the overhead of spawning a new process for each query.
//!
//! # Example
//!
//! ```no_run
//! use cedar_policy_symcc::solver_pool::{SolverPool, SolverPoolConfig};
//! use cedar_policy_symcc::CedarSymCompiler;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a pool with default configuration
//! let pool = SolverPool::new(SolverPoolConfig::default()).await?;
//!
//! // Acquire a solver from the pool
//! let solver = pool.acquire().await?;
//!
//! // Use the solver with CedarSymCompiler
//! let mut compiler = CedarSymCompiler::new(solver)?;
//! // ... perform queries ...
//!
//! // Solver is automatically returned to the pool when dropped
//! # Ok(())
//! # }
//! ```

use super::smtlib_script::SmtLibScript;
use super::solver::{Decision, LocalSolver, Solver, SolverError};
use miette::Diagnostic;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncWrite;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

/// Errors that can occur when acquiring a solver from a [`SolverPool`].
#[derive(Debug, Diagnostic, Error)]
pub enum SolverPoolError {
    /// The pool's internal semaphore was closed unexpectedly.
    /// This indicates a bug or that the pool has been corrupted.
    #[error("solver pool semaphore closed unexpectedly")]
    SemaphoreClosed,

    /// Timed out waiting for a solver to become available from the pool.
    /// This occurs when all solvers are in use and `acquire_timeout` is set.
    #[error("timeout waiting for solver from pool")]
    AcquireTimeout,

    /// An error occurred while spawning or interacting with the underlying solver.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Solver(#[from] SolverError),
}

/// A writer that always returns an error, used when a solver has been marked as failed.
#[derive(Debug, Default)]
struct FailedWriter;

impl FailedWriter {
    fn error() -> io::Error {
        io::Error::new(ErrorKind::Other, SolverError::SolverMarkedFailed)
    }
}

impl AsyncWrite for FailedWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(Self::error()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(Self::error()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(Self::error()))
    }
}

/// Configuration for a [`SolverPool`].
#[derive(Clone, Debug)]
pub struct SolverPoolConfig {
    /// Minimum number of solvers to pre-warm at pool creation.
    /// Defaults to 1.
    pub min_solvers: usize,
    /// Maximum number of concurrent solvers allowed.
    /// Defaults to 4.
    pub max_solvers: usize,
    /// Timeout for acquiring a solver from the pool.
    /// `None` means wait indefinitely.
    /// Defaults to `None`.
    pub acquire_timeout: Option<Duration>,
}

impl Default for SolverPoolConfig {
    fn default() -> Self {
        Self {
            min_solvers: 1,
            max_solvers: 4,
            acquire_timeout: None,
        }
    }
}

/// A pool of warm CVC5 solver processes.
///
/// The pool maintains a set of pre-warmed solver processes that can be
/// efficiently reused across queries. This avoids the overhead of spawning
/// a new process for each query.
///
/// Solvers are acquired using [`SolverPool::acquire`], which returns a
/// [`PooledSolver`] that implements the [`Solver`] trait. When the
/// [`PooledSolver`] is dropped, it attempts to reset and return the solver
/// to the pool. If the reset fails (e.g., due to a parse error that killed
/// the solver), the solver is discarded.
#[derive(Debug)]
pub struct SolverPool {
    /// Available solvers ready for use
    available: Arc<Mutex<Vec<LocalSolver>>>,
    /// Semaphore to limit maximum concurrent solvers
    semaphore: Arc<Semaphore>,
    /// Pool configuration
    config: SolverPoolConfig,
}

impl SolverPool {
    /// Creates a new solver pool with the given configuration.
    ///
    /// This will pre-warm `config.min_solvers` solver processes eagerly.
    /// Returns an error if any of the pre-warmed solvers fail to spawn.
    pub async fn new(config: SolverPoolConfig) -> Result<Self, SolverError> {
        let semaphore = Arc::new(Semaphore::new(config.max_solvers));
        let mut solvers = Vec::with_capacity(config.max_solvers);

        // Eagerly spawn min_solvers
        for _ in 0..config.min_solvers {
            solvers.push(LocalSolver::cvc5()?);
        }

        Ok(Self {
            available: Arc::new(Mutex::new(solvers)),
            semaphore,
            config,
        })
    }

    /// Acquires a solver from the pool.
    ///
    /// If a warm solver is available, it is returned immediately.
    /// If no solvers are available but the pool hasn't reached `max_solvers`,
    /// a new solver is spawned.
    /// If the pool is at capacity, this method blocks until a solver becomes
    /// available or the `acquire_timeout` is exceeded.
    ///
    /// Returns a [`PooledSolver`] that implements [`Solver`] and will be
    /// returned to the pool when dropped.
    pub async fn acquire(&self) -> Result<PooledSolver, SolverPoolError> {
        // Acquire a permit from the semaphore (blocks if at max capacity)
        let permit = match self.config.acquire_timeout {
            Some(timeout) => {
                match tokio::time::timeout(timeout, Arc::clone(&self.semaphore).acquire_owned())
                    .await
                {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => return Err(SolverPoolError::SemaphoreClosed),
                    Err(_) => return Err(SolverPoolError::AcquireTimeout),
                }
            }
            None => Arc::clone(&self.semaphore)
                .acquire_owned()
                .await
                .map_err(|_| SolverPoolError::SemaphoreClosed)?,
        };

        // Get an available solver from the pool
        let solver = {
            let mut available = self.available.lock().await;
            available.pop()
        };

        let solver = match solver {
            Some(s) => s,
            None => {
                // No available solver, spawn a new one
                LocalSolver::cvc5()?
            }
        };

        Ok(PooledSolver {
            solver: Some(solver),
            pool: Arc::clone(&self.available),
            permit: Some(permit),
            failed_writer: FailedWriter,
        })
    }

    /// Returns the current number of available (idle) solvers in the pool.
    pub async fn available_count(&self) -> usize {
        self.available.lock().await.len()
    }

    /// Returns the number of permits currently available in the semaphore.
    /// This indicates how many more solvers can be acquired before blocking.
    pub fn permits_available(&self) -> usize {
        self.semaphore.available_permits()
    }
}

/// A solver acquired from a [`SolverPool`].
///
/// This type implements [`Solver`] by delegating to the underlying [`LocalSolver`].
/// When dropped, it attempts to reset and return the solver to the pool.
/// If the reset fails, the solver is discarded.
#[derive(Debug)]
pub struct PooledSolver {
    /// The underlying solver. This is an Option so we can take it in drop().
    solver: Option<LocalSolver>,
    /// Reference to the pool's available solvers
    pool: Arc<Mutex<Vec<LocalSolver>>>,
    /// Semaphore permit - released after the solver is returned to the pool.
    /// This is an Option so we can move it into the async drop task.
    permit: Option<OwnedSemaphorePermit>,
    /// Writer returned when the solver has been marked as failed
    failed_writer: FailedWriter,
}

impl PooledSolver {
    /// Marks this solver as failed, so it will be discarded instead of returned to the pool.
    ///
    /// This is useful when you know the solver is in a bad state (e.g., after a parse error)
    /// and should not be reused.
    pub fn mark_failed(&mut self) {
        self.solver = None;
    }
}

impl Solver for PooledSolver {
    fn smtlib_input(&mut self) -> &mut (dyn tokio::io::AsyncWrite + Unpin + Send) {
        match &mut self.solver {
            Some(s) => s.smtlib_input(),
            None => &mut self.failed_writer,
        }
    }

    async fn check_sat(&mut self) -> Result<Decision, SolverError> {
        let solver = self
            .solver
            .as_mut()
            .ok_or(SolverError::SolverMarkedFailed)?;
        solver.check_sat().await
    }

    async fn get_model(&mut self) -> Result<Option<String>, SolverError> {
        let solver = self
            .solver
            .as_mut()
            .ok_or(SolverError::SolverMarkedFailed)?;
        solver.get_model().await
    }
}

impl Drop for PooledSolver {
    fn drop(&mut self) {
        let pool = Arc::clone(&self.pool);
        let solver = self.solver.take();
        let permit = self.permit.take();

        // Spawn a task to reset and return the solver to the pool.
        // The permit is moved into the task so it's only released after
        // the solver is returned to the pool (or discarded).
        tokio::spawn(async move {
            if let Some(mut solver) = solver {
                // Try to reset the solver
                if solver.smtlib_input().reset().await.is_ok() {
                    // Reset succeeded, return to pool
                    pool.lock().await.push(solver);
                }
                // If reset failed, the solver is discarded (not returned to pool)
            }
            // Permit is released here when the task completes
            drop(permit);
        });
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use cool_asserts::assert_matches;

    /// Polls an async condition with retries to avoid flaky tests.
    /// Retries every 10ms for up to 100ms total.
    async fn poll_until<F, Fut>(mut condition: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        for _ in 0..10 {
            if condition().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition not met after 100ms of polling");
    }

    #[tokio::test]
    async fn test_pool_creation() {
        let pool = SolverPool::new(SolverPoolConfig {
            min_solvers: 2,
            max_solvers: 4,
            acquire_timeout: None,
        })
        .await
        .unwrap();

        // Should have 2 pre-warmed solvers
        assert_eq!(pool.available_count().await, 2);
        assert_eq!(pool.permits_available(), 4);
    }

    #[tokio::test]
    async fn test_acquire_release() {
        let pool = SolverPool::new(SolverPoolConfig {
            min_solvers: 1,
            max_solvers: 4,
            acquire_timeout: None,
        })
        .await
        .unwrap();

        assert_eq!(pool.available_count().await, 1);

        {
            let mut solver = pool.acquire().await.unwrap();
            // Pool should now be empty
            assert_eq!(pool.available_count().await, 0);

            // Basic solver operation should work
            let decision = solver.check_sat().await.unwrap();
            assert_eq!(decision, Decision::Sat);
        }

        // Wait for the async drop task to return the solver to the pool
        poll_until(|| async { pool.available_count().await == 1 }).await;
    }

    #[tokio::test]
    async fn test_solver_reuse() {
        let pool = SolverPool::new(SolverPoolConfig {
            min_solvers: 1,
            max_solvers: 1,
            acquire_timeout: None,
        })
        .await
        .unwrap();

        // First acquire
        {
            let mut solver = pool.acquire().await.unwrap();
            solver.smtlib_input().assert("false").await.unwrap();
            let decision = solver.check_sat().await.unwrap();
            assert_eq!(decision, Decision::Unsat);
        }

        // Wait for the async drop task to return the solver to the pool
        poll_until(|| async { pool.available_count().await == 1 }).await;

        // Second acquire - should reuse the same solver (after reset)
        {
            let mut solver = pool.acquire().await.unwrap();
            // The solver was reset, so this should work fresh
            solver.smtlib_input().assert("true").await.unwrap();
            let decision = solver.check_sat().await.unwrap();
            assert_eq!(decision, Decision::Sat);
        }
    }

    #[tokio::test]
    async fn test_concurrent_acquire() {
        let pool = Arc::new(
            SolverPool::new(SolverPoolConfig {
                min_solvers: 2,
                max_solvers: 4,
                acquire_timeout: None,
            })
            .await
            .unwrap(),
        );

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let pool = Arc::clone(&pool);
                tokio::spawn(async move {
                    let mut solver = pool.acquire().await.unwrap();
                    let decision = solver.check_sat().await.unwrap();
                    assert_eq!(decision, Decision::Sat);
                })
            })
            .collect();

        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_pool_exhaustion_blocks() {
        let pool = Arc::new(
            SolverPool::new(SolverPoolConfig {
                min_solvers: 1,
                max_solvers: 1,
                acquire_timeout: Some(Duration::from_millis(100)),
            })
            .await
            .unwrap(),
        );

        // Acquire the only available solver
        let _solver = pool.acquire().await.unwrap();

        // Trying to acquire another should timeout
        let result = pool.acquire().await;
        assert_matches!(result, Err(SolverPoolError::AcquireTimeout));
    }

    #[tokio::test]
    async fn test_failed_solver_discarded() {
        let pool = SolverPool::new(SolverPoolConfig {
            min_solvers: 1,
            max_solvers: 1,
            acquire_timeout: None,
        })
        .await
        .unwrap();

        {
            let mut solver = pool.acquire().await.unwrap();
            // Send invalid input to cause a parse error (which kills the solver)
            solver.smtlib_input().assert("tomato").await.unwrap();
            // This should fail with a solver error
            let result = solver.check_sat().await;
            assert_matches!(result, Err(SolverError::Solver(_)));
            // Mark as failed so it won't be returned to pool
            solver.mark_failed();
        }

        // Wait for the drop to release the permit (proves drop completed)
        poll_until(|| async { pool.permits_available() == 1 }).await;

        // Pool should be empty since the failed solver was discarded
        assert_eq!(pool.available_count().await, 0);

        // But we should still be able to acquire (spawns a new one)
        let mut solver = pool.acquire().await.unwrap();
        let decision = solver.check_sat().await.unwrap();
        assert_eq!(decision, Decision::Sat);
    }

    #[tokio::test]
    async fn test_methods_after_mark_failed() {
        use tokio::io::AsyncWriteExt;

        let pool = SolverPool::new(SolverPoolConfig::default()).await.unwrap();
        let mut solver = pool.acquire().await.unwrap();

        // Mark the solver as failed
        solver.mark_failed();

        // check_sat should return SolverMarkedFailed error
        let result = solver.check_sat().await;
        assert_matches!(result, Err(SolverError::SolverMarkedFailed));

        // get_model should return SolverMarkedFailed error
        let result = solver.get_model().await;
        assert_matches!(result, Err(SolverError::SolverMarkedFailed));

        // Writing to smtlib_input should return an IO error
        let result = solver.smtlib_input().write_all(b"test").await;
        assert!(result.is_err());

        // Flushing should also return an IO error
        let result = solver.smtlib_input().flush().await;
        assert!(result.is_err());

        // Shutdown should also return an IO error
        let result = solver.smtlib_input().shutdown().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_default_config() {
        let config = SolverPoolConfig::default();
        assert_eq!(config.min_solvers, 1);
        assert_eq!(config.max_solvers, 4);
        assert!(config.acquire_timeout.is_none());
    }

    #[tokio::test]
    async fn test_pooled_solver_with_symcompiler() {
        use crate::symcc::SymCompiler;

        let pool = SolverPool::new(SolverPoolConfig::default()).await.unwrap();

        // Acquire a solver from the pool
        let solver = pool.acquire().await.unwrap();

        // Create a SymCompiler with the pooled solver
        let mut compiler = SymCompiler::new(solver);

        // Perform a simple check using the compiler
        // We'll check that `assert false` is unsat
        compiler
            .solver_mut()
            .smtlib_input()
            .set_logic("ALL")
            .await
            .unwrap();
        compiler
            .solver_mut()
            .smtlib_input()
            .assert("(= 1 2)")
            .await
            .unwrap();
        let decision = compiler.solver_mut().check_sat().await.unwrap();
        assert_eq!(decision, Decision::Unsat);
    }
}
