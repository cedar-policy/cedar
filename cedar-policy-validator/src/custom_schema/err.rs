use combine::{error::StreamError, ParseError};
use logos::Span;
use smol_str::SmolStr;
use thiserror::Error;

use super::lexer::Token;

/// Parse errors
#[derive(Debug, Clone, PartialEq, Error)]
pub enum ParseErrors {
    #[error("Lexer error: {0}")]
    Lexing(SmolStr),
    #[error("Expecting: {0}")]
    Expected(SmolStr),
    #[error("Unexpected: {0}")]
    Unexpected(SmolStr),
    #[error("Parser error: {0}")]
    Message(SmolStr),
    #[error("End of input")]
    Eoi,
    #[error("Other error: {0}")]
    Other(SmolStr),
}

impl<'a> StreamError<(Token, Span), &'a [(Token, Span)]> for ParseErrors {
    fn unexpected_token(token: (Token, Span)) -> Self {
        Self::Unexpected(SmolStr::new(format!("{token:?}")))
    }
    fn unexpected_range(tokens: &'a [(Token, Span)]) -> Self {
        Self::Unexpected(SmolStr::new(format!("{tokens:?}")))
    }
    fn unexpected_format<T>(msg: T) -> Self
    where
        T: std::fmt::Display,
    {
        Self::Unexpected(SmolStr::new(msg.to_string()))
    }
    fn expected_token(token: (Token, Span)) -> Self {
        Self::Expected(SmolStr::new(format!("{token:?}")))
    }
    fn expected_range(tokens: &'a [(Token, Span)]) -> Self {
        Self::Expected(SmolStr::new(format!("{tokens:?}")))
    }
    fn expected_format<T>(msg: T) -> Self
    where
        T: std::fmt::Display,
    {
        Self::Expected(SmolStr::new(msg.to_string()))
    }
    fn message_token(token: (Token, Span)) -> Self {
        Self::Message(SmolStr::new(format!("{token:?}")))
    }
    fn message_range(tokens: &'a [(Token, Span)]) -> Self {
        Self::Message(SmolStr::new(format!("{tokens:?}")))
    }
    fn message_format<T>(msg: T) -> Self
    where
        T: std::fmt::Display,
    {
        Self::Message(SmolStr::new(msg.to_string()))
    }
    fn is_unexpected_end_of_input(&self) -> bool {
        match self {
            Self::Eoi => true,
            _ => false,
        }
    }
    fn into_other<T>(self) -> T
    where
        T: StreamError<(Token, Span), &'a [(Token, Span)]>,
    {
        match self {
            Self::Lexing(s) => T::message_format(s),
            Self::Eoi => T::end_of_input(),
            Self::Expected(s) => T::expected_format(s),
            Self::Message(s) => T::message_format(s),
            Self::Unexpected(s) => T::unexpected_format(s),
            Self::Other(s) => T::message_format(s),
        }
    }
}

impl<'a> ParseError<(Token, Span), &'a [(Token, Span)], ()> for ParseErrors {
    type StreamError = Self;
    fn empty(_position: ()) -> Self {
        Self::Eoi
    }
    fn set_position(&mut self, _position: ()) {
        unimplemented!("set_position")
    }
    fn add(&mut self, err: Self::StreamError) {
        *self = err;
    }
    fn set_expected<F>(_self_: &mut combine::error::Tracked<Self>, _info: Self::StreamError, _f: F)
    where
        F: FnOnce(&mut combine::error::Tracked<Self>),
    {
        unimplemented!("set_expected")
    }
    fn is_unexpected_end_of_input(&self) -> bool {
        StreamError::is_unexpected_end_of_input(self)
    }
    fn into_other<T>(self) -> T
    where
        T: ParseError<(Token, Span), &'a [(Token, Span)], ()>,
    {
        unimplemented!("into_other")
    }
}
