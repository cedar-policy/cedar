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

use std::cmp::Ordering;
use std::error::Error;
use std::fmt::{self, Debug, Display};
use std::hash::{Hash, Hasher};
use std::ops::Range;

use miette::{Diagnostic, LabeledSpan, Severity, SourceCode};
use serde::{Deserialize, Serialize};

/// Describes where in policy source code a node in the CST or expression AST
/// occurs.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct SourceInfo(pub Range<usize>);

impl SourceInfo {
    /// Construct a new [`SourceInfo`] from a start offset and a length, in
    /// bytes.
    pub const fn new(start: usize, len: usize) -> Self {
        SourceInfo(start..(start + len))
    }

    /// Construct a new zero-length [`SourceInfo`] pointing to a specific
    /// offset.
    pub const fn from_offset(offset: usize) -> Self {
        SourceInfo(offset..offset)
    }

    /// Get the start of range, in bytes.
    pub const fn range_start(&self) -> usize {
        self.0.start
    }

    /// Get the end of range, in bytes.
    pub const fn range_end(&self) -> usize {
        self.0.end
    }

    /// Get the length of the source range, in bytes.
    ///
    /// # Panics
    ///
    /// Panics if the end of the range is before the start.
    pub const fn len(&self) -> usize {
        assert!(self.range_start() <= self.range_end());
        self.range_end() - self.range_start()
    }

    /// Tests whether this [`SourceInfo`] range is a zero-length offset.
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Display for SourceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            write!(f, "{}", self.range_start())
        } else {
            write!(f, "[{}, {})", self.range_start(), self.range_end())
        }
    }
}

impl Ord for SourceInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.range_start()
            .cmp(&other.range_start())
            .then_with(|| self.len().cmp(&other.len()))
    }
}

impl PartialOrd for SourceInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<usize> for SourceInfo {
    fn from(offset: usize) -> Self {
        SourceInfo::from_offset(offset)
    }
}

impl From<Range<usize>> for SourceInfo {
    fn from(range: Range<usize>) -> Self {
        SourceInfo(range)
    }
}

impl From<SourceInfo> for Range<usize> {
    fn from(info: SourceInfo) -> Self {
        info.0
    }
}

/// Metadata for our syntax trees
#[derive(Clone, Deserialize, Serialize)]
pub struct ASTNode<N> {
    /// Main data represented
    pub node: N,

    /// additional information
    pub info: SourceInfo,
}

impl<N> ASTNode<N> {
    /// Create a new Node from main data
    pub fn new(node: N, left: usize, right: usize) -> Self {
        ASTNode::from_source(left..right, node)
    }

    /// Create a new Node from main data
    pub fn from_source(info: impl Into<SourceInfo>, node: N) -> Self {
        ASTNode {
            node,
            info: info.into(),
        }
    }

    /// Transform the inner value while retaining the attached source info.
    pub fn map<M>(self, f: impl FnOnce(N) -> M) -> ASTNode<M> {
        ASTNode {
            node: f(self.node),
            info: self.info,
        }
    }

    /// Converts from `&ASTNode<N>` to `ASTNode<&N>`.
    pub fn as_ref(&self) -> ASTNode<&N> {
        ASTNode {
            node: &self.node,
            info: self.info.clone(),
        }
    }

    /// Converts from `&mut ASTNode<N>` to `ASTNode<&mut N>`.
    pub fn as_mut(&mut self) -> ASTNode<&mut N> {
        ASTNode {
            node: &mut self.node,
            info: self.info.clone(),
        }
    }

    /// Consume the `ASTNode`, yielding the node and attached source info.
    pub fn into_inner(self) -> (N, SourceInfo) {
        (self.node, self.info)
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

impl<N: Debug> Debug for ASTNode<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.node, f)?;
        write!(f, " @ {}", self.info)
    }
}

impl<N: Display> Display for ASTNode<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.node, f)
    }
}

impl<N: Error> Error for ASTNode<N> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.node.source()
    }

    fn description(&self) -> &str {
        #[allow(deprecated)]
        self.node.description()
    }

    fn cause(&self) -> Option<&dyn Error> {
        #[allow(deprecated)]
        self.node.cause()
    }
}

impl<N: Diagnostic> Diagnostic for ASTNode<N> {
    fn code<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.node.code()
    }

    fn severity(&self) -> Option<Severity> {
        self.node.severity()
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.node.help()
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.node.url()
    }

    fn source_code(&self) -> Option<&dyn SourceCode> {
        self.node.source_code()
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        self.node.labels()
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
    /// Similar to `.as_inner()`, but also gives access to the `SourceInfo`
    pub fn as_inner_pair(&self) -> (&SourceInfo, Option<&N>) {
        (&self.info, self.node.as_ref())
    }

    /// Get the inner data as `&N`, if it exists
    pub fn as_inner(&self) -> Option<&N> {
        self.node.as_ref()
    }

    /// `None` if the node is empty, otherwise a node without the `Option`
    pub fn collapse(&self) -> Option<ASTNode<&N>> {
        self.node.as_ref().map(|node| ASTNode {
            node,
            info: self.info.clone(),
        })
    }

    /// Apply the function `f` to the main data and source info. Returns `None`
    /// if no main data or if `f` returns `None`.
    pub fn apply<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&N, &SourceInfo) -> Option<R>,
    {
        f(self.node.as_ref()?, &self.info)
    }

    /// Apply the function `f` to the main data and source info, consuming them.
    /// Returns `None` if no main data or if `f` returns `None`.
    pub fn into_apply<F, R>(self, f: F) -> Option<R>
    where
        F: FnOnce(N, SourceInfo) -> Option<R>,
    {
        f(self.node?, self.info)
    }
}
