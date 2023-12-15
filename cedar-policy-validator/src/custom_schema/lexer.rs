use logos::{Logos, Span};
use smol_str::SmolStr;
use std::fmt::Display;

use super::err::ParseErrors;

// Cedar tokens
#[derive(Logos, Clone, Debug, PartialEq)]
pub enum Token {
    #[regex(r"\s*", logos::skip)]
    Whitespace,
    #[regex(r"//[^\n\r]*[\n\r]*", logos::skip)]
    Comment,
    #[regex(r"[_a-zA-Z][_a-zA-Z0-9]*", |lex| SmolStr::new(lex.slice()))]
    Identifier(SmolStr),
    #[regex(r#""(\\.|[^"\\])*""#, |lex| SmolStr::new(lex.slice()))]
    Str(SmolStr),
    // PRIMTYPE  := 'Long' | 'String' | 'Bool'
    #[token("Long")]
    TyLong,
    #[token("String")]
    TyString,
    #[token("Bool")]
    TyBool,
    // VAR := 'principal' | 'action' | 'resource' | 'context'
    #[token("principal")]
    VarPrincipal,
    #[token("action")]
    VarAction,
    #[token("resource")]
    VarResource,
    #[token("context")]
    VarContext,
    #[token("entity")]
    Entity,
    #[token("in")]
    In,
    #[token("type")]
    Type,
    #[token("Set")]
    Set,
    #[token("appliesTo")]
    AppliesTo,
    #[token("namespace")]
    Namespace,
    #[token(",")]
    Comma,
    #[token(";")]
    SemiColon,
    #[token(":")]
    Colon,
    #[token("::")]
    DoubleColon,
    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,
    #[token("[")]
    LBracket,
    #[token("]")]
    RBracket,
    #[token("<")]
    LAngle,
    #[token(">")]
    RAngle,
    #[token("=")]
    Eq,
    #[token("?")]
    Question,
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AppliesTo => write!(f, "appliesTo"),
            Self::Colon => write!(f, ":"),
            Self::Comma => write!(f, ","),
            Self::Comment => write!(f, ""),
            Self::DoubleColon => write!(f, "::"),
            Self::Entity => write!(f, "entity"),
            Self::Eq => write!(f, "="),
            Self::Identifier(d) => write!(f, "{d}"),
            Self::In => write!(f, "in"),
            Self::LAngle => write!(f, "<"),
            Self::LBrace => write!(f, "{{"),
            Self::LBracket => write!(f, "["),
            Self::Namespace => write!(f, "namespace"),
            Self::Question => write!(f, "?"),
            Self::RAngle => write!(f, ">"),
            Self::RBrace => write!(f, "}}"),
            Self::RBracket => write!(f, "]"),
            Self::SemiColon => write!(f, ";"),
            Self::Set => write!(f, "Set"),
            Self::Str(s) => write!(f, "{s}"),
            Self::TyBool => write!(f, "Bool"),
            Self::TyLong => write!(f, "Long"),
            Self::TyString => write!(f, "String"),
            Self::Type => write!(f, "type"),
            Self::VarAction => write!(f, "action"),
            Self::VarContext => write!(f, "context"),
            Self::VarResource => write!(f, "resource"),
            Self::VarPrincipal => write!(f, "principal"),
            Self::Whitespace => write!(f, " "),
        }
    }
}

impl Token {
    // Special Ids match the Ident regex pattern but also serve as keywords
    pub fn is_special_id(&self) -> bool {
        matches!(
            self,
            Self::AppliesTo
                | Self::Entity
                | Self::In
                | Self::Namespace
                | Self::Set
                | Self::Type
                | Self::VarAction
                | Self::VarContext
                | Self::VarPrincipal
                | Self::VarResource
        )
    }
}

pub fn get_tokens(input: &str) -> Result<Vec<(Token, Span)>, ParseErrors> {
    Token::lexer(input)
        .spanned()
        .map(|(token, span)| match token {
            Ok(t) => Ok((t, span)),
            Err(_) => Err(ParseErrors::Lexing(span)),
        })
        .collect()
}

#[cfg(test)]
mod test_lexer {
    use super::Token;
    use logos::Logos;
    #[test]
    fn errs() {
        let tokens: Vec<_> = Token::lexer(r#"🤪""#).spanned().collect();
        assert!(tokens.into_iter().all(|(t, _)| t.is_err()));
    }
    #[test]
    fn example() {
        let tokens: Vec<_> = Token::lexer(
            r#"namespace "" {
            entity Application;
            entity User in [Team,Application] { name: String };
            entity Team in [Team,Application];
            entity List in [Application] {
                owner: User,
                name: String,
                readers: Team,
                editors: Team,
                tasks: Set<{name: String, id: Long, state: String}>
            };

            action CreateList, GetLists
                appliesTo { principal: [User], resource: [Application] };

            action GetList, UpdateList, DeleteList, CreateTask, UpdateTask, DeleteTask, EditShares
                appliesTo { principal: [User], resource:[List] };
        }"#,
        )
        .spanned()
        .collect();
        assert!(tokens.into_iter().all(|(t, _)| t.is_ok()));
    }
}
