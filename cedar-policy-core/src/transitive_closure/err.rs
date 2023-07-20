/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

use std::fmt::Debug;
use std::fmt::Display;
use thiserror::Error;

/// Error type for errors raised during transitive closure computation. This
/// error type is parametrized by a type `K` which is the type of a unique
/// identifier for graph nodes and the type returned by `get_key` on the
/// `TCNode` trait.
#[derive(Debug, Error)]
pub enum TcError<K: Debug + Display> {
    /// Error raised when `TCComputation::EnforceAlreadyComputed` finds that the
    /// TC was in fact not already computed
    #[error("expected all transitive edges to exist, but `{child}` -> `{parent}` and `{parent}` -> `{grandparent}` exists, while `{child}` -> `{grandparent}` does not")]
    MissingTcEdge {
        /// Child entity at fault
        child: K,
        /// Parent entity at fault
        parent: K,
        /// Grandparent entity at fault. This is a parent of `parent` but not an
        /// ancestor of `child`.
        grandparent: K,
    },
    /// Error raised when enforce_dag finds that the graph is not a DAG
    #[error("input graph has a cycle. Vertex {} has a loop.", .vertex_with_loop)]
    HasCycle {
        /// Because DAG enforcement can only be called after compute_tc/enforce_tc, a cycle will manifest as a vertex with a loop
        vertex_with_loop: K,
    },
}

/// Type alias for convenience
pub type Result<T, K> = std::result::Result<T, TcError<K>>;
