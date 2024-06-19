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

// PANIC SAFETY: testing code
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used
)]

//! Shared test utilities.

/// Describes the contents of an error message. Fields are based on the contents
/// of `miette::Diagnostic`.
#[derive(Debug)]
pub struct ExpectedErrorMessage<'a> {
    /// Expected contents of `Display`, or expected prefix of `Display` if `prefix` is `true`
    error: &'a str,
    /// Expected contents of `help()`, or `None` if no help, or expected prefix of `help()` if `prefix` is `true`
    help: Option<&'a str>,
    /// If `true`, then `error`, `help`, and `source` are interpreted as expected
    /// prefixes of the relevant messages, and [`expect_err()`] will allow the
    /// actual messages to have additional characters after the ones that are expected.
    prefix: bool,
    /// Expected text that is underlined by miette (text found at the error's
    /// source location(s)) plus (optional) help text associated with the
    /// underline.
    /// If this is an empty vec, we expect the error to have no associated
    /// source location.
    /// If this is a vec with one or more elements, we expect the same number of
    /// miette `labels` in the same order, and the vec elements represent the
    /// expected contents of the labels.
    underlines: Vec<(&'a str, Option<&'a str>)>,
    /// A message describing the cause of this error
    source: Option<&'a str>,
}

/// Builder struct for [`ExpectedErrorMessage`]
#[derive(Debug)]
pub struct ExpectedErrorMessageBuilder<'a> {
    /// ExpectedErrorMessage::error
    error: &'a str,
    /// ExpectedErrorMessage::help
    help: Option<&'a str>,
    /// ExpectedErrorMessage::prefix
    prefix: bool,
    /// ExpectedErrorMessage::underlines
    underlines: Vec<(&'a str, Option<&'a str>)>,
    /// ExpectedErrorMessage::source
    source: Option<&'a str>,
}

impl<'a> ExpectedErrorMessageBuilder<'a> {
    /// Create a builder expecting the given main error message (contents of
    /// `Display`)
    pub fn error(msg: &'a str) -> Self {
        Self {
            error: msg,
            help: None,
            prefix: false,
            underlines: vec![],
            source: None,
        }
    }

    /// Create a builder expecting the main error message (contents of
    /// `Display`) to _start with_ the given text.
    ///
    /// (If you later add expected help text to this builder, that will
    /// also be an expected prefix, not the entire expected help text.)
    pub fn error_starts_with(msg: &'a str) -> Self {
        Self {
            error: msg,
            help: None,
            prefix: true,
            underlines: vec![],
            source: None,
        }
    }

    /// Add expected contents of `help()`, or expected prefix of `help()` if
    /// this builder was originally constructed with `error_starts_with()`
    pub fn help(self, msg: &'a str) -> Self {
        Self {
            help: Some(msg),
            ..self
        }
    }

    /// Add expected underlined text. The error message will be expected to have
    /// exactly one miette label, and the underlined portion should be `snippet`.
    /// The underlined text should have no associated label text.
    pub fn exactly_one_underline(self, snippet: &'a str) -> Self {
        Self {
            underlines: vec![(snippet, None)],
            ..self
        }
    }

    /// Add expected underlined text. The error message will be expected to have
    /// exactly one miette label, and the underlined portion should be `snippet`.
    /// The label text is expected to match `label`.
    pub fn exactly_one_underline_with_label(self, snippet: &'a str, label: &'a str) -> Self {
        Self {
            underlines: vec![(snippet, Some(label))],
            ..self
        }
    }

    /// Add expected contents of `source()`, or expected prefix of `source()` if
    /// this builder was originally constructed with `error_starts_with()`
    pub fn source(self, msg: &'a str) -> Self {
        Self {
            source: Some(msg),
            ..self
        }
    }

    /// Build the [`ExpectedErrorMessage`]
    pub fn build(self) -> ExpectedErrorMessage<'a> {
        ExpectedErrorMessage {
            error: self.error,
            help: self.help,
            prefix: self.prefix,
            underlines: self.underlines,
            source: self.source,
        }
    }
}

impl<'a> ExpectedErrorMessage<'a> {
    /// Return a boolean indicating whether a given error matches this expected message.
    /// (If you want to assert that it matches, use [`expect_err()`] instead,
    /// for much better assertion-failure messages.)
    ///
    /// `src` is the full source text (which the miette labels index into).
    /// It can be omitted only in the case where we expect no underlines.
    /// Panics if this invariant is violated.
    pub fn matches(&self, src: Option<&'a str>, error: &impl miette::Diagnostic) -> bool {
        self.matches_error(error)
            && self.matches_help(error)
            && self.matches_source(error)
            && self.matches_underlines(src, error)
    }

    /// Internal helper: whether the main error message matches
    fn matches_error(&self, error: &impl miette::Diagnostic) -> bool {
        let e_string = error.to_string();
        if self.prefix {
            e_string.starts_with(self.error)
        } else {
            e_string == self.error
        }
    }

    /// Internal helper: assert the main error message matches
    #[track_caller]
    fn expect_error_matches(&self, src: impl Into<OriginalInput<'a>>, error: &miette::Report) {
        let e_string = error.to_string();
        if self.prefix {
            assert!(
                e_string.starts_with(self.error),
                "for the following input:\n{}\nfor the following error:\n{error:?}\n\nactual error did not start with the expected prefix\n  actual error: {error}\n  expected prefix: {}", // the Debug representation of miette::Report is the pretty one
                src.into(),
                self.error,
            );
        } else {
            assert_eq!(
                &e_string,
                self.error,
                "for the following input:\n{}\nfor the following error:\n{error:?}\n\nactual error did not match expected", // assert_eq! will print the actual and expected messages
                src.into(),
            );
        }
    }

    /// Internal helper: whether the help message matches
    fn matches_help(&self, error: &impl miette::Diagnostic) -> bool {
        let h_string = error.help().map(|h| h.to_string());
        if self.prefix {
            match (h_string.as_deref(), self.help) {
                (Some(actual), Some(expected)) => actual.starts_with(expected),
                (None, None) => true,
                _ => false,
            }
        } else {
            h_string.as_deref() == self.help
        }
    }

    /// Internal helper: whether the source message matches
    fn matches_source(&self, error: &impl miette::Diagnostic) -> bool {
        let s_string = error.source().map(|s| s.to_string());
        if self.prefix {
            match (s_string.as_deref(), self.source) {
                (Some(actual), Some(expected)) => actual.starts_with(expected),
                (None, None) => true,
                _ => false,
            }
        } else {
            s_string.as_deref() == self.source
        }
    }

    /// Internal helper used to check help or source messages
    #[track_caller]
    fn expect_help_or_source_matches(
        &self,
        src: impl Into<OriginalInput<'a>>,
        error: &miette::Report,
        h_or_s: &str,
        actual: Option<&str>,
        expected: Option<&str>,
    ) {
        if self.prefix {
            match (actual, expected) {
                (Some(actual), Some(expected)) => {
                    assert!(
                        actual.starts_with(expected),
                        "for the following input:\n{}\nfor the following error:\n{error:?}\n\nactual {h_or_s} did not start with the expected prefix\n  actual {h_or_s}: {actual}\n  expected {h_or_s}: {expected}", // the Debug representation of miette::Report is the pretty one
                        src.into(),
                    )
                }
                (None, None) => (),
                (Some(actual), None) => panic!(
                    "for the following input:\n{}\nfor the following error:\n{error:?}\n\ndid not expect a {h_or_s} message, but found one: {actual}", // the Debug representation of miette::Report is the pretty one
                    src.into(),
                ),
                (None, Some(expected)) => panic!(
                    "for the following input:\n{}\nfor the following error:\n{error:?}\n\ndid not find a {h_or_s} message, but expected one: {expected}", // the Debug representation of miette::Report is the pretty one
                    src.into(),
                ),
            }
        } else {
            assert_eq!(
                actual,
                expected,
                "for the following input:\n{}\nfor the following error:\n{error:?}\n\nactual {h_or_s} did not match expected", // assert_eq! will print the actual and expected messages
                src.into(),
            );
        }
    }

    /// Internal helper: assert the help message matches
    #[track_caller]
    fn expect_help_matches(&self, src: impl Into<OriginalInput<'a>>, error: &miette::Report) {
        let h_string = error.help().map(|h| h.to_string());
        self.expect_help_or_source_matches(src, error, "help", h_string.as_deref(), self.help);
    }

    /// Internal helper: assert the source message matches
    #[track_caller]
    fn expect_source_matches(&self, src: impl Into<OriginalInput<'a>>, error: &miette::Report) {
        let s_string = error.source().map(|s| s.to_string());
        self.expect_help_or_source_matches(src, error, "source", s_string.as_deref(), self.source);
    }

    /// Internal helper: whether the underlines match
    ///
    /// `src` is the full source text (which the miette labels index into).
    /// It can be omitted only in the case where we expect no underlines.
    /// Panics if this invariant is violated.
    fn matches_underlines(&self, src: Option<&'a str>, err: &impl miette::Diagnostic) -> bool {
        let expected_num_labels = self.underlines.len();
        let actual_num_labels = err.labels().map(|iter| iter.count()).unwrap_or(0);
        if expected_num_labels != actual_num_labels {
            return false;
        }
        if expected_num_labels == 0 {
            true
        } else {
            let src =
                src.expect("src can be `None` only in the case where we expect no underlines");
            for (expected, actual) in self
                .underlines
                .iter()
                .zip(err.labels().unwrap_or_else(|| Box::new(std::iter::empty())))
            {
                let (expected_snippet, expected_label) = expected;
                let actual_snippet = {
                    let span = actual.inner();
                    if span.offset() < src.len() {
                        &src[span.offset()..span.offset() + span.len()]
                    } else {
                        ""
                    }
                };
                let actual_label = actual.label();
                if expected_snippet != &actual_snippet {
                    return false;
                }
                if expected_label != &actual_label {
                    return false;
                }
            }
            true
        }
    }

    /// Internal helper: assert the underlines match
    ///
    /// `src` is the full source text (which the miette labels index into).
    /// It can be omitted only in the case where we expect no underlines.
    /// Panics if this invariant is violated.
    #[track_caller]
    fn expect_underlines_match(&self, src: Option<&'a str>, err: &miette::Report) {
        let expected_num_labels = self.underlines.len();
        let actual_num_labels = err.labels().map(|iter| iter.count()).unwrap_or(0);
        assert_eq!(expected_num_labels, actual_num_labels, "in the following error:\n{err:?}\n\nexpected {expected_num_labels} underlines but found {actual_num_labels}"); // the Debug representation of miette::Report is the pretty one
        if expected_num_labels != 0 {
            let src =
                src.expect("src can be `None` only in the case where we expect no underlines");
            for (expected, actual) in self
                .underlines
                .iter()
                .zip(err.labels().unwrap_or_else(|| Box::new(std::iter::empty())))
            {
                let (expected_snippet, expected_label) = expected;
                let actual_snippet = {
                    let span = actual.inner();
                    if span.offset() < src.len() {
                        &src[span.offset()..span.offset() + span.len()]
                    } else {
                        ""
                    }
                };
                let actual_label = actual.label();
                assert_eq!(
                    expected_snippet,
                    &actual_snippet,
                    "in the following error:\n{err:?}\n\nexpected underlined portion to be:\n  {expected_snippet}\nbut it was:\n  {actual_snippet}", // the Debug representation of miette::Report is the pretty one
                );
                assert_eq!(
                    expected_label,
                    &actual_label,
                    "in the following error:\n{err:?}\n\nexpected underlined help text to be:\n  {expected_label:?}\nbut it was:\n  {actual_label:?}", // the Debug representation of miette::Report is the pretty one
                );
            }
        }
    }
}

impl<'a> std::fmt::Display for ExpectedErrorMessage<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.prefix {
            writeln!(f, "expected error to start with: {}", self.error)?;
            match self.help {
                Some(help) => writeln!(f, "expected help to start with: {help}")?,
                None => writeln!(f, "  with no help message")?,
            }
        } else {
            writeln!(f, "expected error: {}", self.error)?;
            match self.help {
                Some(help) => writeln!(f, "expected help: {help}")?,
                None => writeln!(f, "  with no help message")?,
            }
        }
        if self.underlines.is_empty() {
            writeln!(f, "and expected no source locations / underlined segments.")?;
        } else {
            writeln!(f, "and expected the following underlined segments:")?;
            for (underline, label) in &self.underlines {
                writeln!(f, "  {underline}")?;
                match label {
                    Some(label) => writeln!(f, "  with label {label}")?,
                    None => (),
                }
            }
        }
        Ok(())
    }
}

/// Forms in which [`expect_err()`] accepts the original input text.
/// See notes on [`expect_err()`].
#[derive(Debug)]
pub enum OriginalInput<'a> {
    /// A plain string
    String(&'a str),
    /// A JSON value. We will not incur the cost of formatting this to
    /// string unless it is actually needed.
    Json(&'a serde_json::Value),
}

impl<'a> From<&'a str> for OriginalInput<'a> {
    fn from(value: &'a str) -> Self {
        Self::String(value)
    }
}

impl<'a> From<&'a serde_json::Value> for OriginalInput<'a> {
    fn from(value: &'a serde_json::Value) -> Self {
        Self::Json(value)
    }
}

impl<'a> std::fmt::Display for OriginalInput<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(s) => write!(f, "{s}"),
            Self::Json(val) => write!(f, "{}", serde_json::to_string_pretty(val).unwrap()),
        }
    }
}

/// Expect that the given `err` is an error with the given `ExpectedErrorMessage`.
///
/// `src` is the original input text, just for better assertion-failure messages.
/// This function accepts any `impl Into<OriginalInput>` for `src`,
/// including `&str` and `&serde_json::Value`.
#[track_caller] // report the caller's location as the location of the panic, not the location in this function
pub fn expect_err<'a>(
    src: impl Into<OriginalInput<'a>> + Copy,
    err: &miette::Report,
    msg: &ExpectedErrorMessage<'a>,
) {
    msg.expect_error_matches(src, err);
    msg.expect_help_matches(src, err);
    msg.expect_source_matches(src, err);
    if msg.underlines.is_empty() {
        msg.expect_underlines_match(None, err);
    } else {
        match src.into() {
            OriginalInput::String(s) => {
                msg.expect_underlines_match(Some(s), err);
            }
            OriginalInput::Json(val) => {
                // need to convert to string so we can compute the underlines
                let src = serde_json::to_string_pretty(val).unwrap();
                msg.expect_underlines_match(Some(&src), err);
            }
        }
    }
}
