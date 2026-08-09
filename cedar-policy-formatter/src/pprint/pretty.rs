use std::marker::PhantomData;

use pretty_expressive::{self, Doc};

#[derive(Clone, Debug)]
pub struct RcDoc<'src> {
    doc: Doc,
    contains_full: bool,
    trailing_hardline: bool,
    is_empty: bool,
    source: PhantomData<&'src str>,
}

pub trait IntoRcDoc<'src> {
    fn into_rc_doc(self) -> RcDoc<'src>;
}

impl<'src> IntoRcDoc<'src> for RcDoc<'src> {
    fn into_rc_doc(self) -> RcDoc<'src> {
        self
    }
}

impl<'src> IntoRcDoc<'src> for Option<RcDoc<'src>> {
    fn into_rc_doc(self) -> RcDoc<'src> {
        self.unwrap_or_else(RcDoc::nil)
    }
}

impl<'src> RcDoc<'src> {
    fn new(doc: Doc, is_empty: bool) -> Self {
        Self {
            doc,
            contains_full: false,
            trailing_hardline: false,
            is_empty,
            source: PhantomData,
        }
    }

    fn with_state(doc: Doc, contains_full: bool, trailing_hardline: bool, is_empty: bool) -> Self {
        Self {
            doc,
            contains_full,
            trailing_hardline,
            is_empty,
            source: PhantomData,
        }
    }

    pub fn nil() -> Self {
        Self::new(pretty_expressive::text(""), true)
    }

    pub fn text(text: impl Into<String>) -> Self {
        let text = text.into();
        if text.is_empty() {
            return Self::nil();
        }
        if !text.contains('\n') {
            return Self::new(pretty_expressive::text(text), false);
        }

        let mut lines = text.split('\n');
        let first_line: Doc = pretty_expressive::text(lines.next().unwrap_or_default());
        let multiline = lines.fold(first_line, |document, line| {
            document & pretty_expressive::hard_nl() & pretty_expressive::text(line)
        });
        Self::new(pretty_expressive::reset(multiline), false)
    }

    pub fn as_string<T: ToString + ?Sized>(value: &T) -> Self {
        Self::text(value.to_string())
    }

    pub fn space() -> Self {
        Self::new(pretty_expressive::space(), false)
    }

    pub fn line() -> Self {
        Self::new(pretty_expressive::nl(), false)
    }

    pub fn line_() -> Self {
        Self::new(pretty_expressive::brk(), false)
    }

    pub fn hardline() -> Self {
        Self::new(pretty_expressive::hard_nl(), false)
    }

    pub fn trailing_hardline() -> Self {
        Self::with_state(pretty_expressive::text(""), false, true, false)
    }

    pub fn append(self, other: impl IntoRcDoc<'src>) -> Self {
        let other = other.into_rc_doc();
        if self.is_empty {
            return other;
        }
        if other.is_empty {
            return self;
        }

        let document = if self.trailing_hardline {
            self.doc & pretty_expressive::hard_nl()
        } else {
            self.doc
        };
        Self::with_state(
            document & other.doc,
            self.contains_full || other.contains_full,
            other.trailing_hardline,
            false,
        )
    }

    pub fn group(self) -> Self {
        if self.contains_full || self.trailing_hardline {
            self
        } else {
            Self::with_state(
                pretty_expressive::group(self.doc),
                false,
                self.trailing_hardline,
                self.is_empty,
            )
        }
    }

    pub fn nest(self, offset: isize) -> Self {
        let Ok(offset) = usize::try_from(offset) else {
            return Self::new(pretty_expressive::fail(), false);
        };
        Self::with_state(
            pretty_expressive::nest(offset, self.doc),
            self.contains_full,
            self.trailing_hardline,
            self.is_empty,
        )
    }

    pub fn full(self) -> Self {
        Self::with_state(
            pretty_expressive::full(self.doc),
            true,
            self.trailing_hardline,
            false,
        )
    }

    pub fn intersperse<I, D>(documents: I, separator: &Self) -> Self
    where
        I: IntoIterator<Item = D>,
        D: IntoRcDoc<'src>,
    {
        let mut documents = documents.into_iter().map(IntoRcDoc::into_rc_doc);
        let Some(first) = documents.next() else {
            return Self::nil();
        };
        documents.fold(first, |document, next| {
            document.append(separator.clone()).append(next)
        })
    }

    pub fn render(&self, line_width: usize) -> pretty_expressive::Result<String> {
        let document = if self.trailing_hardline {
            self.doc.clone() & pretty_expressive::hard_nl()
        } else {
            self.doc.clone()
        };
        document
            .validate(line_width)
            .map(|layout| layout.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::RcDoc;

    #[test]
    fn full_is_preserved_by_grouping() {
        let document = RcDoc::text("// comment")
            .full()
            .append(RcDoc::line())
            .append(RcDoc::text("next"))
            .group();

        assert_eq!(document.render(80).unwrap(), "// comment\nnext");
    }

    #[test]
    fn full_rejects_following_text() {
        let document = RcDoc::text("// comment")
            .full()
            .append(RcDoc::text(" next"));

        assert!(document.render(80).is_err());
    }

    #[test]
    fn multiline_text_temporarily_resets_indentation() {
        let document = RcDoc::hardline()
            .append(RcDoc::text("a\n  b"))
            .append(RcDoc::hardline())
            .append(RcDoc::text("c"))
            .nest(4);

        assert_eq!(document.render(80).unwrap(), "\n    a\n  b\n    c");
    }

    #[test]
    fn trailing_hardline_escapes_inner_nesting() {
        let inner = RcDoc::text("value")
            .append(RcDoc::space())
            .append(RcDoc::text("// comment").full())
            .append(RcDoc::trailing_hardline())
            .nest(2);
        let document = RcDoc::hardline()
            .append(inner)
            .append(RcDoc::text(","))
            .nest(2);

        assert_eq!(document.render(80).unwrap(), "\n  value // comment\n  ,");
    }
}
