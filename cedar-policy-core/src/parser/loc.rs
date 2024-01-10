use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Represents a source location: index/range, and a reference to the source
/// code which that index/range indexes into
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct Loc {
    /// `SourceSpan` indicating a specific source code location or range
    pub span: miette::SourceSpan,

    /// Original source code (which the above source span indexes into)
    pub src: Arc<str>,
}

impl Loc {
    /// Create a new `Loc`
    pub fn new(span: impl Into<miette::SourceSpan>, src: Arc<str>) -> Self {
        Self {
            span: span.into(),
            src,
        }
    }

    /// Create a new `Loc` with the same source code but a different span
    pub fn span(&self, span: impl Into<miette::SourceSpan>) -> Self {
        Self {
            span: span.into(),
            src: Arc::clone(&self.src),
        }
    }

    /// Get the index representing the start of the source span
    pub fn start(&self) -> usize {
        self.span.offset()
    }

    /// Get the index representing the end of the source span
    pub fn end(&self) -> usize {
        self.span.offset() + self.span.len()
    }

    /// Get the actual source snippet indicated, or `None` if the `Loc` isn't
    /// internally consistent (its `SourceSpan` isn't a valid index into its
    /// `src`)
    pub fn snippet(&self) -> Option<&str> {
        self.src.get(self.start()..self.end())
    }
}
