//! This module provides a trait to define Cedar error codes.

use smol_str::SmolStr;

/// A trait that returns an error code
/// By default, `Self::error_code` returns the concatenation
/// of `Self::prefix` and `Self::error_id`
pub trait ErrorCode {
    /// Return the prefix of an error code
    fn prefix() -> SmolStr;
    /// Return an id for an error kind
    fn error_id(&self) -> u8;
    /// Return the error code
    /// The error id is printed as 2 decimal digits, padded with 0s
    fn error_code(&self) -> SmolStr {
        format!("{}{:02}", Self::prefix(), self.error_id()).into()
    }
}
