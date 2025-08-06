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

use std::sync::Arc;

use vstd::prelude::*;

verus! {
/// Represents an optional `Loc`.
#[cfg(not(feature = "raw-parsing"))]
pub type MaybeLoc = Option<Loc>;

/// Represents an optional `Loc`.
///
/// This definition uses heap allocation (Box) to reduce the memory
/// footprint of structures containing `MaybeLoc`.
///
/// The computational performance compared to the unboxed `Option<Loc>` depends on its value:
/// - `Some` case: Slightly slower due to heap allocation and indirect access
/// - `None` case: More memory efficient as no space is reserved for the location data
///
/// When the `raw-parsing` feature is enabled, we use this type and avoid
/// storing locations during parsing, maximizing the parsing performance.
#[cfg(feature = "raw-parsing")]
pub type MaybeLoc = Option<Box<Loc>>;

/// Represents a source location: index/range, and a reference to the source
/// code which that index/range indexes into
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[verifier::external_derive]
#[verifier::external_body]
pub struct Loc {
    /// `SourceSpan` indicating a specific source code location or range
    pub span: miette::SourceSpan,

    /// Original source code (which the above source span indexes into)
    pub src: Arc<str>,
}


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

verus! {

/// Trait to define conversions to `Option<&Loc>`
pub trait AsLocRef {
    /// Automatic conversion to `Option<&Loc>`
    fn as_loc_ref(&self) -> Option<&Loc>;
}

impl AsLocRef for Option<Loc> {
    #[inline]
    fn as_loc_ref(&self) -> Option<&Loc> {
        self.as_ref()
    }
}

impl AsLocRef for Option<Box<Loc>> {
    #[inline]
    #[verifier::external_body]
    fn as_loc_ref(&self) -> Option<&Loc> {
        self.as_deref()
    }
}

/// Trait to define conversions into `MaybeLoc`
pub trait IntoMaybeLoc {
    /// Automatic conversion to `MaybeLoc`
    fn into_maybe_loc(self) -> MaybeLoc;
}

impl IntoMaybeLoc for Loc {
    #[inline]
    fn into_maybe_loc(self) -> MaybeLoc {
        #[cfg(not(feature = "raw-parsing"))]
        {
            Some(self)
        }
        #[cfg(feature = "raw-parsing")]
        {
            Some(Box::new(self))
        }
    }
}

impl IntoMaybeLoc for Option<Loc> {
    #[inline]
    fn into_maybe_loc(self) -> MaybeLoc {
        #[cfg(not(feature = "raw-parsing"))]
        {
            self
        }
        #[cfg(feature = "raw-parsing")]
        {
            self.map(Box::new)
        }
    }
}

impl IntoMaybeLoc for Option<&Loc> {
    #[inline]
    #[allow(clippy::single_option_map)]
    fn into_maybe_loc(self) -> MaybeLoc {
        #[cfg(not(feature = "raw-parsing"))]
        {
            self.cloned()
        }
        #[cfg(feature = "raw-parsing")]
        {
            self.map(|loc| Box::new(loc.clone()))
        }
    }
}

impl IntoMaybeLoc for Option<Box<Loc>> {
    #[inline]
    fn into_maybe_loc(self) -> MaybeLoc {
        #[cfg(not(feature = "raw-parsing"))]
        {
            self.map(|loc| *loc)
        }
        #[cfg(feature = "raw-parsing")]
        {
            self
        }
    }
}

} // verus!

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
