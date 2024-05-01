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

use miette::Diagnostic;
use std::fmt::Debug;
use std::fmt::Display;
use thiserror::Error;

/// Error type for errors raised during transitive closure computation. This
/// error type is parametrized by a type `K` which is the type of a unique
/// identifier for graph nodes and the type returned by `get_key` on the
/// `TCNode` trait.
#[derive(Debug, Diagnostic, Error, PartialEq, Eq)]
pub enum TcError<K: Debug + Display> {
    /// Error raised when `TCComputation::EnforceAlreadyComputed` finds that the
    /// TC was in fact not already computed
    #[error("expected all transitive edges to exist, but `{}` -> `{}` and `{}` -> `{}` exists, while `{}` -> `{}` does not", .0.child, .0.parent, .0.parent, .0.grandparent, .0.child, .0.grandparent)]
    MissingTcEdge(MissingTcEdge<K>),
    /// Error raised when enforce_dag finds that the graph is not a DAG
    #[error("input graph has a cycle containing vertex `{}`", .0.vertex_with_loop)]
    HasCycle(HasCycle<K>),
}

impl<K: Debug + Display> TcError<K> {
    pub(crate) fn missing_tc_edge(child: K, parent: K, grandparent: K) -> Self {
        Self::MissingTcEdge(MissingTcEdge {
            child,
            parent,
            grandparent,
        })
    }

    pub(crate) fn has_cycle(vertex_with_loop: K) -> Self {
        Self::HasCycle(HasCycle { vertex_with_loop })
    }
}

/// Error raised when `TCComputation::EnforceAlreadyComputed` finds that the
/// TC was in fact not already computed
#[derive(Debug, PartialEq, Eq)]
pub struct MissingTcEdge<K: Debug + Display> {
    child: K,
    parent: K,
    grandparent: K,
}

/// Error raised when enforce_dag finds that the graph is not a DAG
#[derive(Debug, PartialEq, Eq)]
pub struct HasCycle<K: Debug + Display> {
    /// Because DAG enforcement can only be called after compute_tc/enforce_tc, a cycle will manifest as a vertex with a loop
    vertex_with_loop: K,
}

impl<K: Debug + Display> HasCycle<K> {
    /// Graph vertex that contained a loop
    pub fn vertex_with_loop(&self) -> &K {
        &self.vertex_with_loop
    }
}

/// Type alias for convenience
pub type Result<T, K> = std::result::Result<T, TcError<K>>;
