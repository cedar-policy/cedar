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

use std::fmt::{self, Debug, Display};
use std::hash::{Hash, Hasher};

use miette::Diagnostic;
use serde::{Deserialize, Serialize};

use super::err::{ToASTError, ToASTErrorKind};
use super::loc::Loc;

/// Metadata for our syntax trees
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Node<T> {
    /// Main data represented
    pub node: T,

    /// Source location
    pub loc: Loc,
}

impl<T> Node<T> {
    /// Create a new Node with the given source location
    pub fn with_source_loc(node: T, loc: Loc) -> Self {
        Node { node, loc }
    }

    /// Transform the inner value while retaining the attached source info.
    pub fn map<R>(self, f: impl FnOnce(T) -> R) -> Node<R> {
        Node {
            node: f(self.node),
            loc: self.loc.clone(),
        }
    }

    /// Converts from `&Node<T>` to `Node<&T>`.
    pub fn as_ref(&self) -> Node<&T> {
        Node {
            node: &self.node,
            loc: self.loc.clone(),
        }
    }

    /// Converts from `&mut Node<T>` to `Node<&mut T>`.
    pub fn as_mut(&mut self) -> Node<&mut T> {
        Node {
            node: &mut self.node,
            loc: self.loc.clone(),
        }
    }

    /// Consume the `Node`, yielding the node and attached source info.
    pub fn into_inner(self) -> (T, Loc) {
        (self.node, self.loc)
    }

    /// Utility to construct a `ToAstError` with the source location taken from this node.
    pub fn to_ast_err(&self, error_kind: impl Into<ToASTErrorKind>) -> ToASTError {
        ToASTError::new(error_kind.into(), self.loc.clone())
    }
}

impl<T: Clone> Node<&T> {
    /// Converts a `Node<&T>` to a `Node<T>` by cloning the inner value.
    pub fn cloned(self) -> Node<T> {
        self.map(|value| value.clone())
    }
}

impl<T: Copy> Node<&T> {
    /// Converts a `Node<&T>` to a `Node<T>` by copying the inner value.
    pub fn copied(self) -> Node<T> {
        self.map(|value| *value)
    }
}

impl<T: Display> Display for Node<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.node, f)
    }
}

impl<T: std::error::Error> std::error::Error for Node<T> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.node.source()
    }

    #[allow(deprecated)]
    fn description(&self) -> &str {
        self.node.description()
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        #[allow(deprecated)]
        self.node.cause()
    }
}

// impl Diagnostic by taking `labels()` and `source_code()` from .loc and everything else from .node
impl<T: Diagnostic> Diagnostic for Node<T> {
    impl_diagnostic_from_source_loc_field!(loc);

    fn code<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.node.code()
    }

    fn severity(&self) -> Option<miette::Severity> {
        self.node.severity()
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.node.help()
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.node.url()
    }

    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        self.node.related()
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.node.diagnostic_source()
    }
}

// Ignore the metadata this node contains
impl<T: PartialEq> PartialEq for Node<T> {
    /// ignores metadata
    fn eq(&self, other: &Self) -> bool {
        self.node == other.node
    }
}
impl<T: Eq> Eq for Node<T> {}
impl<T: Hash> Hash for Node<T> {
    /// ignores metadata
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.node.hash(state);
    }
}

/// Convenience methods on `Node<Option<T>>`
impl<T> Node<Option<T>> {
    /// Get the inner data as `&T`, if it exists
    pub fn as_inner(&self) -> Option<&T> {
        self.node.as_ref()
    }

    /// `None` if the node is empty, otherwise a node without the `Option`
    pub fn collapse(&self) -> Option<Node<&T>> {
        self.node.as_ref().map(|node| Node {
            node,
            loc: self.loc.clone(),
        })
    }

    /// Apply the function `f` to the main data and source info. Returns `None`
    /// if no main data or if `f` returns `None`.
    pub fn apply<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&T, &Loc) -> Option<R>,
    {
        f(self.node.as_ref()?, &self.loc)
    }

    /// Apply the function `f` to the main data and `Loc`, consuming them.
    /// Returns `None` if no main data or if `f` returns `None`.
    pub fn into_apply<F, R>(self, f: F) -> Option<R>
    where
        F: FnOnce(T, Loc) -> Option<R>,
    {
        f(self.node?, self.loc)
    }

    /// Get node data if present or return the error `EmptyNodeInvariantViolation`
    pub fn try_as_inner(&self) -> Result<&T, ToASTError> {
        self.node
            .as_ref()
            .ok_or_else(|| self.to_ast_err(ToASTErrorKind::EmptyNodeInvariantViolation))
    }

    /// Get node data if present or return the error `EmptyNodeInvariantViolation`
    pub fn try_into_inner(self) -> Result<T, ToASTError> {
        self.node.ok_or_else(|| {
            ToASTError::new(
                ToASTErrorKind::EmptyNodeInvariantViolation,
                self.loc.clone(),
            )
        })
    }
}
