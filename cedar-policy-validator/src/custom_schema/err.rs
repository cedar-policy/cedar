use combine::{error::StreamError, ParseError};
use logos::Span;
use smol_str::SmolStr;
use thiserror::Error;

use super::lexer::Token;

/// Parse errors
#[derive(Debug, Clone, PartialEq, Error)]
pub enum ParseErrors {
    #[error("Lexer error: invalid token at {0:?}")]
    Lexing(Span),
    #[error("Expecting: {0} at {1:?}")]
    Expected(SmolStr, Option<Span>),
    #[error("Unexpected: {0} at {1:?}")]
    Unexpected(SmolStr, Option<Span>),
    #[error("Parser error: {0}")]
    Message(SmolStr, Option<Span>),
    #[error("End of input")]
    Eoi,
    #[error("Other error: {0}")]
    Other(SmolStr),
}

impl<'a> StreamError<(Token, Span), &'a [(Token, Span)]> for ParseErrors {
    fn unexpected_token(token: (Token, Span)) -> Self {
        Self::Unexpected(token.0.to_string().into(), Some(token.1))
    }
    fn unexpected_range(tokens: &'a [(Token, Span)]) -> Self {
        Self::Unexpected(tokens[0].0.to_string().into(), Some(tokens[0].clone().1))
    }
    fn unexpected_format<T>(msg: T) -> Self
    where
        T: std::fmt::Display,
    {
        Self::Unexpected(msg.to_string().into(), None)
    }
    fn expected_token(token: (Token, Span)) -> Self {
        Self::Expected(token.0.to_string().into(), Some(token.1))
    }
    fn expected_range(tokens: &'a [(Token, Span)]) -> Self {
        Self::Expected(tokens[0].0.to_string().into(), Some(tokens[0].clone().1))
    }
    fn expected_format<T>(msg: T) -> Self
    where
        T: std::fmt::Display,
    {
        Self::Expected(msg.to_string().into(), None)
    }
    fn message_token(token: (Token, Span)) -> Self {
        Self::Message(token.0.to_string().into(), Some(token.1))
    }
    fn message_range(tokens: &'a [(Token, Span)]) -> Self {
        Self::Message(tokens[0].0.to_string().into(), Some(tokens[0].clone().1))
    }
    fn message_format<T>(msg: T) -> Self
    where
        T: std::fmt::Display,
    {
        Self::Message(msg.to_string().into(), None)
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
            Self::Lexing(_) => T::message_format(self),
            Self::Eoi => T::end_of_input(),
            Self::Expected(msg, _) => T::expected_format(msg),
            Self::Message(msg, _) => T::message_format(msg),
            Self::Unexpected(msg, _) => T::unexpected_format(msg),
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
