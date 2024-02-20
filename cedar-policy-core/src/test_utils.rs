// PANIC SAFETY: testing code
#![allow(clippy::panic)]

pub struct ExpectedErrorMessage<'a> {
    /// Expected contents of `Display`, or expected prefix of `Display` if `prefix` is `true`
    error: &'a str,
    /// Expected contents of `help()`, or `None` if no help, or expected prefix of `help()` if `prefix` is `true`
    help: Option<&'a str>,
    /// If `true`, then `error` and `help` are interpreted as expected prefixes
    /// of the error and help messages, and [`expect_err()`] will allow the
    /// actual error message and help text to have additional characters after
    /// the ones that are expected.
    prefix: bool,
}

impl<'a> ExpectedErrorMessage<'a> {
    /// Expect the given exact error message and no help text.
    pub fn error(msg: &'a str) -> Self {
        Self {
            error: msg,
            help: None,
            prefix: false,
        }
    }

    /// Expect the given exact error message and help text.
    pub fn error_and_help(error: &'a str, help: &'a str) -> Self {
        Self {
            error,
            help: Some(help),
            prefix: false,
        }
    }

    /// Expect the error message to start with the given text, and expect no help text.
    pub fn error_starts_with(msg: &'a str) -> Self {
        Self {
            error: msg,
            help: None,
            prefix: true,
        }
    }

    /// Expected the error message and help text to start with the given text respectively.
    #[allow(dead_code)] // not currently used as of this writing, but included for completeness
    pub fn error_and_help_start_with(error: &'a str, help: &'a str) -> Self {
        Self {
            error,
            help: Some(help),
            prefix: true,
        }
    }

    /// Return a boolean indicating whether a given error matches this expected message.
    /// (If you want to assert that it matches, use [`expect_err()`] instead,
    /// for much better assertion-failure messages.)
    pub fn matches(&self, error: &impl miette::Diagnostic) -> bool {
        let e_string = error.to_string();
        let h_string = error.help().map(|h| h.to_string());
        if self.prefix {
            e_string.starts_with(self.error)
                && match (h_string.as_deref(), self.help) {
                    (Some(actual), Some(expected)) => actual.starts_with(expected),
                    (None, None) => true,
                    _ => false,
                }
        } else {
            e_string == self.error && h_string.as_deref() == self.help
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
        Ok(())
    }
}

/// Forms in which [`expect_err()`] accepts the original input text.
/// See notes on [`expect_err()`].
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
    src: impl Into<OriginalInput<'a>>,
    err: &impl miette::Diagnostic,
    msg: &ExpectedErrorMessage<'_>,
) {
    let error = err.to_string();
    let help = err.help().map(|h| h.to_string());
    if msg.prefix {
        assert!(
            error.starts_with(msg.error),
            "for the following input:\n{}\nactual error did not start with the expected prefix\n  actual error: {error}\n  expected prefix: {}", src.into(), msg.error,
        );
        match (help.as_deref(), &msg.help) {
            (Some(actual), Some(expected)) => {
                assert!(
                    actual.starts_with(expected),
                    "for the following input:\n{}\nactual help did not start with the expected prefix\n  actual help: {actual}\n  expected help: {expected}", src.into(),
                )
            }
            (None, None) => (),
            (Some(actual), None) => panic!(
                "for the following input:\n{}\ndid not expect a help message, but found one: {actual}",
                src.into()
            ),
            (None, Some(expected)) => panic!(
                "for the following input:\n{}\ndid not find a help message, but expected one: {expected}",
                src.into()
            ),
        }
    } else {
        assert_eq!(
            &error,
            msg.error,
            "for the following input:\n{}\nactual error did not match expected", // assert_eq! will print the actual and expected messages
            src.into()
        );
        assert_eq!(
            help.as_deref(),
            msg.help,
            "for the following input:\n{}\nactual help did not match expected", // assert_eq! will print the actual and expected messages
            src.into()
        );
    }
}

/// Expect that the given `err` has a (single) source location, where the
/// contents of that source location are `snippet`.
///
/// `src` is the original input text, used both for assertion-failure messages
/// but also as the source we assume the error's source location indexes into.
#[track_caller]
// PANIC SAFETY: testing
#[allow(clippy::indexing_slicing)]
pub fn expect_source_snippet(
    src: impl AsRef<str>,
    err: &impl miette::Diagnostic,
    snippet: impl AsRef<str>,
) {
    use itertools::Itertools;
    let src = src.as_ref();
    let snippet = snippet.as_ref();
    let labels = err.labels().unwrap_or_else(|| {
        panic!("for the following input:\n{src}\ndid not find a source location, but expected one")
    });
    let label = labels.exactly_one().unwrap_or_else(|labels| {
        panic!(
            "for the following input:\n{src}\nexpected exactly one source location, but found {}",
            labels.count(),
        )
    });
    let actual_snippet = {
        let span = label.inner();
        &src[span.offset()..span.offset() + span.len()]
    };
    assert_eq!(
        actual_snippet,
        snippet,
        "for the following input:\n{src}\nexpected source snippet to be:\n  {snippet}\nbut it was:\n  {actual_snippet}\n",
    );
}
