//! Errors produced while transpiling a Cedar policy-set into Cedar Lean AST source.

use cedar_policy_core::parser::err::ParseErrors;
use thiserror::Error;

/// Errors that can occur while parsing a Cedar policy-set or emitting the
/// equivalent Cedar Lean AST.
#[derive(Debug, Error)]
pub enum Error {
    /// The input text could not be parsed as a Cedar policy-set.
    #[error("failed to parse Cedar policy-set:\n{0}")]
    Parse(#[from] Box<ParseErrors>),

    /// The parsed AST contains a construct that has no representation in the
    /// Cedar Lean specification AST (e.g. a partial-evaluation `unknown`, or an
    /// AST error node).
    #[error("cannot translate to Cedar Lean AST: {0}")]
    Unsupported(String),
}

/// Convenience result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;
