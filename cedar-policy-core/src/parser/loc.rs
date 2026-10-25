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

use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// The source code that a [`Loc`] indexes into.
///
/// This is a cheap-to-clone handle to the text, which also stores a hash of the
/// text, computed once when the `SourceText` is created. The source is usually
/// a whole policy set or schema, so hashing a [`Loc`] (e.g. to de-duplicate
/// errors) uses that stored hash instead of hashing the whole text again.
#[derive(Clone)]
pub struct SourceText(Arc<SourceTextInner>);

struct SourceTextInner {
    text: Box<str>,
    hash: u64,
}

impl SourceText {
    /// Create a new `SourceText`, computing the hash of `text`
    pub fn new(text: impl Into<Box<str>>) -> Self {
        let text = text.into();
        let mut hasher = std::hash::DefaultHasher::new();
        text.hash(&mut hasher);
        Self(Arc::new(SourceTextInner {
            hash: hasher.finish(),
            text,
        }))
    }
}

impl std::ops::Deref for SourceText {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0.text
    }
}

impl AsRef<str> for SourceText {
    fn as_ref(&self) -> &str {
        &self.0.text
    }
}

impl PartialEq for SourceText {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
            || (self.0.hash == other.0.hash && self.0.text == other.0.text)
    }
}

impl Eq for SourceText {}

impl Hash for SourceText {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.0.hash);
    }
}

impl PartialOrd for SourceText {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SourceText {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.text.cmp(&other.0.text)
    }
}

impl std::fmt::Debug for SourceText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&*self.0.text, f)
    }
}

impl miette::SourceCode for SourceText {
    fn read_span<'a>(
        &'a self,
        span: &miette::SourceSpan,
        context_lines_before: usize,
        context_lines_after: usize,
    ) -> Result<Box<dyn miette::SpanContents<'a> + 'a>, miette::MietteError> {
        self.0
            .text
            .read_span(span, context_lines_before, context_lines_after)
    }
}

impl From<&str> for SourceText {
    fn from(text: &str) -> Self {
        Self::new(text)
    }
}

impl From<String> for SourceText {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

impl From<Arc<str>> for SourceText {
    fn from(text: Arc<str>) -> Self {
        Self::new(&*text)
    }
}

/// Represents a source location: index/range, and a reference to the source
/// code which that index/range indexes into
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Loc {
    /// `SourceSpan` indicating a specific source code location or range
    pub span: miette::SourceSpan,

    /// Original source code (which the above source span indexes into)
    pub src: SourceText,
}

impl Loc {
    /// Create a new `Loc`
    pub fn new(span: impl Into<miette::SourceSpan>, src: impl Into<SourceText>) -> Self {
        Self {
            span: span.into(),
            src: src.into(),
        }
    }

    /// Create a new `Loc` with the same source code but a different span
    pub fn span(&self, span: impl Into<miette::SourceSpan>) -> Self {
        Self {
            span: span.into(),
            src: self.src.clone(),
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

impl std::fmt::Debug for Loc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.snippet() {
            Some(snippet) => write!(f, r#"Loc(`{snippet}`)"#),
            None => write!(
                f,
                r#"Loc(span: {:?}, src: "{}")"#,
                self.span,
                self.src.escape_debug()
            ),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Loc, SourceText};
    use std::hash::{BuildHasher, Hash, Hasher, RandomState};

    /// A hasher that only counts the bytes written to it
    #[derive(Default)]
    struct CountingHasher(usize);

    impl Hasher for CountingHasher {
        fn finish(&self) -> u64 {
            0
        }
        fn write(&mut self, bytes: &[u8]) {
            self.0 += bytes.len();
        }
    }

    #[test]
    fn hashing_a_loc_does_not_hash_its_source() {
        let src = SourceText::from("permit(principal, action, resource);".repeat(30_000));
        let loc = Loc::new(0..6, src);
        let mut hasher = CountingHasher::default();
        loc.hash(&mut hasher);
        // The span and the stored hash of the source, not the ~1 MB of text
        assert!(hasher.0 <= 64, "hashed {} bytes", hasher.0);
    }

    #[test]
    fn source_text_eq_and_hash() {
        let hasher = RandomState::new();
        let src = SourceText::from("permit(principal, action, resource);");
        // The same text in a different allocation
        let same = SourceText::from(String::from("permit(principal, action, resource);"));
        let other = SourceText::from("forbid(principal, action, resource);");
        assert_eq!(src, same);
        assert_eq!(hasher.hash_one(&src), hasher.hash_one(&same));
        assert_ne!(src, other);
        assert_eq!(src.cmp(&same), std::cmp::Ordering::Equal);
        assert_eq!(src.cmp(&other), "permit".cmp("forbid"));

        let l = Loc::new(0..6, src.clone());
        assert_eq!(l, Loc::new(0..6, same));
        assert_eq!(hasher.hash_one(&l), hasher.hash_one(l.span(0..6)));
        assert_ne!(l, Loc::new(0..6, other));
        assert_ne!(l, Loc::new(0..5, src));
    }

    #[test]
    fn test_loc_debug() {
        let str: std::sync::Arc<str> =
            r#"permit(principal, action, resource) when { a == b && b == "c" }"#.into();
        let l = super::Loc::new(43..49, str.clone());
        let l2 = super::Loc::new(53..61, str);
        assert_eq!(format!("{l:?}"), r#"Loc(`a == b`)"#);
        assert_eq!(format!("{l2:?}"), r#"Loc(`b == "c"`)"#);
    }
}
