/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

// PANIC SAFETY: there's little we can do about Logos.
#![allow(clippy::indexing_slicing)]
use itertools::Itertools;
use logos::{Logos, Span};
use regex::Regex;
use smol_str::SmolStr;
use std::fmt::{self, Display};

pub fn get_comment(text: &str) -> String {
    // PANIC SAFETY: this regex pattern is valid
    #[allow(clippy::unwrap_used)]
    let mut comment = Regex::new(r"//[^\n\r]*")
        .unwrap()
        .find_iter(text)
        .map(|c| c.as_str().trim_end())
        .join("\n");
    if comment.is_empty() {
        comment
    } else {
        comment.push('\n');
        comment
    }
}

// Represent Cedar comments
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Comment {
    pub leading_comment: String,
    pub trailing_comment: String,
}

impl Comment {
    pub fn add_leading_comment(&mut self, comment: &str) {
        self.leading_comment.push_str(&get_comment(comment));
    }

    pub fn add_trailing_comment(&mut self, comment: &str) {
        self.trailing_comment.push_str(&get_comment(comment));
    }
}

impl Display for Comment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.leading_comment.is_empty() {
            self.trailing_comment.fmt(f)
        } else {
            write!(f, "{}\n{}", self.leading_comment, self.trailing_comment)
        }
    }
}

// Cedar tokens
#[derive(Logos, Clone, Debug, PartialEq)]
pub enum Token {
    #[error]
    #[regex(r"\s*", logos::skip)]
    Whitespace,

    #[regex(r"//[^\n\r]*[\n\r]*", logos::skip)]
    Comment,

    #[token("true")]
    True,

    #[token("false")]
    False,

    #[token("if")]
    If,

    #[token("permit")]
    Permit,

    #[token("forbid")]
    Forbid,

    #[token("when")]
    When,

    #[token("unless")]
    Unless,

    #[token("in")]
    In,

    #[token("has")]
    Has,

    #[token("like")]
    Like,

    #[token("then")]
    Then,

    #[token("else")]
    Else,

    #[token("principal")]
    Principal,

    #[token("action")]
    Action,

    #[token("resource")]
    Resource,

    #[token("context")]
    Context,

    #[token("?principal")]
    PrincipalSlot,

    #[token("?resource")]
    ResourceSlot,

    #[regex(r"[_a-zA-Z][_a-zA-Z0-9]*", |lex| SmolStr::new(lex.slice()))]
    Identifier(SmolStr),

    #[regex("[0-9]+", |lex| SmolStr::new(lex.slice()))]
    Number(SmolStr),

    #[regex(r#""(\\.|[^"\\])*""#, |lex| SmolStr::new(lex.slice()))]
    Str(SmolStr),

    #[token("@")]
    At,

    #[token(".")]
    Dot,

    #[token(",")]
    Comma,

    #[token(";")]
    SemiColon,

    #[token(":")]
    Colon,

    #[token("::")]
    DoubleColon,

    #[token("(")]
    LParen,

    #[token(")")]
    RParen,

    #[token("{")]
    LBrace,

    #[token("}")]
    RBrace,

    #[token("[")]
    LBracket,

    #[token("]")]
    RBracket,

    #[token("==")]
    Equal,

    #[token("!=")]
    NotEqual,

    #[token("<")]
    Lt,

    #[token("<=")]
    Le,

    #[token(">")]
    Gt,

    #[token(">=")]
    Ge,

    #[token("||")]
    Or,

    #[token("&&")]
    And,

    #[token("+")]
    Add,

    #[token("-")]
    Dash,

    #[token("*")]
    Mul,

    #[token("/")]
    Div,

    #[token("%")]
    Modulo,

    #[token("!")]
    Neg,
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Action => write!(f, "action"),
            Self::Add => write!(f, "+"),
            Self::And => write!(f, "&&"),
            Self::At => write!(f, "@"),
            Self::Colon => write!(f, ":"),
            Self::Comma => write!(f, ","),
            // PANIC SAFETY: comment should be ignored as specified by the lexer regex
            #[allow(clippy::unreachable)]
            Self::Comment => unreachable!("comment should be skipped!"),
            Self::Context => write!(f, "context"),
            Self::Dash => write!(f, "-"),
            Self::Div => write!(f, "/"),
            Self::Dot => write!(f, "."),
            Self::DoubleColon => write!(f, "::"),
            Self::Else => write!(f, "else"),
            Self::Equal => write!(f, "=="),
            Self::False => write!(f, "false"),
            Self::Forbid => write!(f, "forbid"),
            Self::Ge => write!(f, ">="),
            Self::Gt => write!(f, ">"),
            Self::Has => write!(f, "has"),
            Self::Identifier(i) => write!(f, "{}", i),
            Self::If => write!(f, "if"),
            Self::In => write!(f, "in"),
            Self::LBrace => write!(f, "{{"),
            Self::LBracket => write!(f, "["),
            Self::LParen => write!(f, "("),
            Self::Le => write!(f, "<="),
            Self::Like => write!(f, "like"),
            Self::Lt => write!(f, "<"),
            Self::Modulo => write!(f, "%"),
            Self::Mul => write!(f, "*"),
            Self::Neg => write!(f, "!"),
            Self::NotEqual => write!(f, "!="),
            Self::Number(n) => write!(f, "{}", n),
            Self::Or => write!(f, "||"),
            Self::Permit => write!(f, "permit"),
            Self::Principal => write!(f, "principal"),
            Self::PrincipalSlot => write!(f, "principal?"),
            Self::RBrace => write!(f, "}}"),
            Self::RBracket => write!(f, "]"),
            Self::RParen => write!(f, ")"),
            Self::Resource => write!(f, "resource"),
            Self::ResourceSlot => write!(f, "resource?"),
            Self::SemiColon => write!(f, ";"),
            Self::Str(s) => write!(f, "{}", s),
            Self::Then => write!(f, "then"),
            Self::True => write!(f, "true"),
            Self::Unless => write!(f, "unless"),
            Self::When => write!(f, "when"),
            // PANIC SAFETY: whitespace should be ignored as specified by the lexer regex
            #[allow(clippy::unreachable)]
            Self::Whitespace => unreachable!("whitespace should be skipped!"),
        }
    }
}

// A wrapper for token span (i.e., (Token, Span))
// We use this wrapper for easier processing of comments
#[derive(Debug, Clone, PartialEq)]
pub struct WrappedToken {
    pub token: Token,
    pub comment: Comment,
    pub span: Span,
}

impl WrappedToken {
    pub fn new(token: Token, comment: Comment, span: Span) -> Self {
        Self {
            token,
            comment,
            span,
        }
    }

    pub fn add_leading_comment(&mut self, comment: &str) {
        self.comment.add_leading_comment(comment);
    }

    pub fn add_trailing_comment(&mut self, comment: &str) {
        self.comment.add_trailing_comment(comment);
    }

    fn clear_leading_comment(&mut self) {
        self.comment.leading_comment.clear();
    }

    fn clear_trailing_comment(&mut self) {
        self.comment.trailing_comment.clear();
    }

    pub fn consume_leading_comment(&mut self) -> String {
        let comment = self.comment.leading_comment.clone();
        self.clear_leading_comment();
        comment
    }

    pub fn consume_comment(&mut self) -> Comment {
        let comment = self.comment.clone();
        self.clear_leading_comment();
        self.clear_trailing_comment();
        comment
    }
}

impl Display for WrappedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{} {}",
            self.comment.leading_comment, self.token, self.comment.trailing_comment
        )
    }
}
