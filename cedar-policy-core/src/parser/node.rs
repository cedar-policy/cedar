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

use std::fmt::{self, Debug, Display};
use std::hash::{Hash, Hasher};

use miette::Diagnostic;
use serde::{Deserialize, Serialize};

use super::err::{ToASTError, ToASTErrorKind};

/// Metadata for our syntax trees
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ASTNode<N> {
    /// Main data represented
    pub node: N,

    /// Source location
    pub loc: miette::SourceSpan,
}

impl<N> ASTNode<N> {
    /// Create a new Node with the source location [left, right)
    pub fn new(node: N, left: usize, right: usize) -> Self {
        ASTNode::with_source_loc(node, left..right)
    }

    /// Create a new Node with the given source location
    pub fn with_source_loc(node: N, loc: impl Into<miette::SourceSpan>) -> Self {
        ASTNode {
            node,
            loc: loc.into(),
        }
    }

    /// Transform the inner value while retaining the attached source info.
    pub fn map<M>(self, f: impl FnOnce(N) -> M) -> ASTNode<M> {
        ASTNode {
            node: f(self.node),
            loc: self.loc,
        }
    }

    /// Converts from `&ASTNode<N>` to `ASTNode<&N>`.
    pub fn as_ref(&self) -> ASTNode<&N> {
        ASTNode {
            node: &self.node,
            loc: self.loc,
        }
    }

    /// Converts from `&mut ASTNode<N>` to `ASTNode<&mut N>`.
    pub fn as_mut(&mut self) -> ASTNode<&mut N> {
        ASTNode {
            node: &mut self.node,
            loc: self.loc,
        }
    }

    /// Consume the `ASTNode`, yielding the node and attached source info.
    pub fn into_inner(self) -> (N, miette::SourceSpan) {
        (self.node, self.loc)
    }

    /// Utility to construct a `ToAstError` with the source location taken from this node.
    pub fn to_ast_err(&self, error_kind: impl Into<ToASTErrorKind>) -> ToASTError {
        ToASTError::new(error_kind.into(), self.loc)
    }
}

impl<N: Clone> ASTNode<&N> {
    /// Converts a `ASTNode<&N>` to a `ASTNode<N>` by cloning the inner value.
    pub fn cloned(self) -> ASTNode<N> {
        self.map(|value| value.clone())
    }
}

impl<N: Copy> ASTNode<&N> {
    /// Converts a `ASTNode<&N>` to a `ASTNode<N>` by copying the inner value.
    pub fn copied(self) -> ASTNode<N> {
        self.map(|value| *value)
    }
}

impl<N: Display> Display for ASTNode<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.node, f)
    }
}

impl<N: std::error::Error> std::error::Error for ASTNode<N> {
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

// impl Diagnostic by taking `labels()` from .loc and everything else from .node
impl<N: Diagnostic> Diagnostic for ASTNode<N> {
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

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        self.node.source_code()
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        Some(Box::new(std::iter::once(miette::LabeledSpan::underline(
            self.loc,
        ))))
    }

    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        self.node.related()
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.node.diagnostic_source()
    }
}

// Ignore the metadata this node contains
impl<N: PartialEq> PartialEq for ASTNode<N> {
    /// ignores metadata
    fn eq(&self, other: &Self) -> bool {
        self.node == other.node
    }
}
impl<N: Eq> Eq for ASTNode<N> {}
impl<N: Hash> Hash for ASTNode<N> {
    /// ignores metadata
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.node.hash(state);
    }
}

/// Convenience methods on `ASTNode<Option<N>>`
impl<N> ASTNode<Option<N>> {
    /// Similar to `.as_inner()`, but also gives access to the `SourceSpan`
    pub fn as_inner_pair(&self) -> (Option<&N>, miette::SourceSpan) {
        (self.node.as_ref(), self.loc)
    }

    /// Get the inner data as `&N`, if it exists
    pub fn as_inner(&self) -> Option<&N> {
        self.node.as_ref()
    }

    /// `None` if the node is empty, otherwise a node without the `Option`
    pub fn collapse(&self) -> Option<ASTNode<&N>> {
        self.node.as_ref().map(|node| ASTNode {
            node,
            loc: self.loc,
        })
    }

    /// Apply the function `f` to the main data and source info. Returns `None`
    /// if no main data or if `f` returns `None`.
    pub fn apply<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&N, miette::SourceSpan) -> Option<R>,
    {
        f(self.node.as_ref()?, self.loc)
    }

    /// Apply the function `f` to the main data and source info, consuming them.
    /// Returns `None` if no main data or if `f` returns `None`.
    pub fn into_apply<F, R>(self, f: F) -> Option<R>
    where
        F: FnOnce(N, miette::SourceSpan) -> Option<R>,
    {
        f(self.node?, self.loc)
    }

    /// Get node data if present, or return an error result for `MissingNodeData`
    /// if it is `None`.
    pub fn ok_or_missing(&self) -> Result<&N, ToASTError> {
        self.node
            .as_ref()
            .ok_or_else(|| self.to_ast_err(ToASTErrorKind::MissingNodeData))
    }
}
