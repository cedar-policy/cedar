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

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::ast::proto;

/// Represents a source location: index/range, and a reference to the source
/// code which that index/range indexes into
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, PartialOrd, Ord)]
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

impl From<Loc> for miette::SourceSpan {
    fn from(loc: Loc) -> Self {
        loc.span
    }
}

impl From<&Loc> for miette::SourceSpan {
    fn from(loc: &Loc) -> Self {
        loc.span
    }
}

impl miette::SourceCode for Loc {
    fn read_span<'a>(
        &'a self,
        span: &miette::SourceSpan,
        context_lines_before: usize,
        context_lines_after: usize,
    ) -> Result<Box<dyn miette::SpanContents<'a> + 'a>, miette::MietteError> {
        self.src
            .read_span(span, context_lines_before, context_lines_after)
    }
}

impl miette::SourceCode for &Loc {
    fn read_span<'a>(
        &'a self,
        span: &miette::SourceSpan,
        context_lines_before: usize,
        context_lines_after: usize,
    ) -> Result<Box<dyn miette::SpanContents<'a> + 'a>, miette::MietteError> {
        self.src
            .read_span(span, context_lines_before, context_lines_after)
    }
}

impl From<proto::Loc> for Loc {
    fn from(v: proto::Loc) -> Self {
        let offset_usize: usize = v.offset.try_into().unwrap();
        Loc::new(
            miette::SourceSpan::new(
                miette::SourceOffset::from(offset_usize),
                v.length.try_into().unwrap()
            ),
            v.src.into()
        )
    }
}

impl From<Loc> for proto::Loc {
    fn from(v: Loc) -> Self {
        let offset_u32 : u32 = v.span.offset().try_into().unwrap();
        let length_u32 : u32 = v.span.len().try_into().unwrap();
        Self {
            offset: offset_u32,
            length: length_u32,
            src: v.src.to_string()
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn protobuf_roundtrip() {
        let loc : Loc = Loc::new(
            miette::SourceSpan::new(
                miette::SourceOffset::from(0),
                5
            ),
            "test".into()
        );
        assert_eq!(loc, Loc::from(proto::Loc::from(loc.clone())));

        let loc2 : Loc = Loc::new(
            miette::SourceSpan::new(
                miette::SourceOffset::from(1000),
                500000
            ),
            "test".into()
        );
        assert_eq!(loc2, Loc::from(proto::Loc::from(loc2.clone())));
    }

}