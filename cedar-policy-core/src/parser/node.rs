use serde::{Deserialize, Serialize};

/// Describes where in policy source code a node in the CST or expression AST
/// occurs.
#[derive(Serialize, Deserialize, Hash, Debug, Clone, PartialEq, Eq)]
pub struct SourceInfo(pub std::ops::Range<usize>);

impl SourceInfo {
    /// Get the start of range.
    pub fn range_start(&self) -> usize {
        self.0.start
    }

    /// Get the end of range.
    pub fn range_end(&self) -> usize {
        self.0.end
    }
}

/// Metadata for our syntax trees
// Note that these derives are likely to need explicit impls as we develop further
#[derive(Debug, Clone)]
pub struct ASTNode<N> {
    /// Main data represented
    pub node: N,

    /// additional information
    pub info: SourceInfo,
}

impl<N> ASTNode<N> {
    /// Create a new Node from main data
    pub fn new(node: N, left: usize, right: usize) -> Self {
        let info = SourceInfo(left..right);
        ASTNode { node, info }
    }

    /// Create a new Node from main data
    pub fn from_source(node: N, info: SourceInfo) -> Self {
        ASTNode { node, info }
    }

    /// like Option.as_ref()
    pub fn as_ref(&self) -> ASTNode<&N> {
        ASTNode {
            node: &self.node,
            info: self.info.clone(),
        }
    }

    /// map the main data, leaving the SourceInfo alone
    pub fn map<D>(self, f: impl FnOnce(N) -> D) -> ASTNode<D> {
        ASTNode {
            node: f(self.node),
            info: self.info,
        }
    }

    /// consume the Node, producing the main data and the SourceInfo
    pub fn into_inner(self) -> (N, SourceInfo) {
        (self.node, self.info)
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

/// Convenience methods on `ASTNode<Option<T>>`
impl<T> ASTNode<Option<T>> {
    /// Similar to `.as_inner()`, but also gives access to the `SourceInfo`
    pub fn as_inner_pair(&self) -> (&SourceInfo, Option<&T>) {
        (&self.info, self.node.as_ref())
    }

    /// Get the inner data as `&T`, if it exists
    pub fn as_inner(&self) -> Option<&T> {
        self.node.as_ref()
    }

    /// `None` if the node is empty, otherwise a node without the `Option`
    pub fn collapse(&self) -> Option<ASTNode<&T>> {
        self.node.as_ref().map(|node| ASTNode {
            node,
            info: self.info.clone(),
        })
    }

    /// Apply the function `f` to the main data and source info. Returns `None`
    /// if no main data or if `f` returns `None`.
    pub fn apply<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&T, &SourceInfo) -> Option<R>,
    {
        f(self.node.as_ref()?, &self.info)
    }

    /// Apply the function `f` to the main data and source info, consuming them.
    /// Returns `None` if no main data or if `f` returns `None`.
    pub fn into_apply<F, R>(self, f: F) -> Option<R>
    where
        F: FnOnce(T, SourceInfo) -> Option<R>,
    {
        f(self.node?, self.info)
    }
}
