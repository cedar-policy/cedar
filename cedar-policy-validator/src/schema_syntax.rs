use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

use cedar_policy_core::ast::{Id, Name};
use combine::{
    between, choice, many, many1, optional, parser, satisfy_map, sep_by1, Parser, Stream,
};
use itertools::Itertools;
use logos::{Logos, Span};
use smol_str::SmolStr;

use crate::{
    AttributesOrContext, EntityType, NamespaceDefinition, SchemaType, SchemaTypeVariant,
    TypeOfAttribute,
};

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
    #[token("\"")]
    Quote,
    #[token("=")]
    Eq,
}

fn parse_id<'a>() -> impl Parser<&'a [Token], Output = Id> {
    satisfy_map(|t| match t {
        Token::Identifier(d) => Some(Id::from_str(&d).unwrap()),
        _ => None,
    })
}

fn accept<'a>(t: Token) -> impl Parser<&'a [Token], Output = ()> {
    satisfy_map(move |tt| if tt == t { Some(()) } else { None })
}

fn parse_keyword<'a>(keyword: Token) -> impl Parser<&'a [Token], Output = ()> {
    accept(keyword)
}

fn parse_punct<'a>(punct: Token) -> impl Parser<&'a [Token], Output = ()> {
    accept(punct)
}

fn parse_keyword_namespace<'a>() -> impl Parser<&'a [Token], Output = ()> {
    parse_keyword(Token::Namespace)
}

fn parse_builtin_ty<'a>(ty: Token) -> impl Parser<&'a [Token], Output = ()> {
    parse_keyword(ty)
}

struct AttrParser();

impl<'a> Parser<&'a [Token]> for AttrParser {
    type Output = BTreeMap<SmolStr, TypeOfAttribute>;
    type PartialState = ();
    fn parse_lazy(
        &mut self,
        input: &mut &'a [Token],
    ) -> combine::ParseResult<Self::Output, <&'a [Token] as combine::StreamOnce>::Error> {
        match self.parse(input) {
            Ok((res, tokens)) => {
                *input = tokens;
                combine::ParseResult::CommitOk(res)
            }
            Err(_) => combine::ParseResult::PeekErr(combine::error::Tracked::from(
                combine::error::UnexpectedParse::Unexpected,
            )),
        }
    }
    fn parse(
        &mut self,
        input: &'a [Token],
    ) -> Result<(Self::Output, &'a [Token]), <&'a [Token] as combine::StreamOnce>::Error> {
        if let Ok((id, tokens)) = parse_id().parse(input) {
            if let Ok((_, tokens)) = accept(Token::Colon).parse(tokens) {
                if let Ok((ty, tokens)) = TypeParser().parse(tokens) {
                    let mut pair = BTreeMap::new();
                    pair.insert(
                        SmolStr::new(id.as_ref()),
                        TypeOfAttribute { ty, required: true },
                    );
                    if let Ok((_, tokens)) = accept(Token::Comma).parse(tokens) {
                        if let Ok((mut pairs, tokens)) = self.parse(tokens) {
                            pairs.extend(pair);
                            return Ok((pairs, tokens));
                        }
                        return Ok((pair, tokens));
                    }
                    return Ok((pair, tokens));
                }
            }
        }
        return Err(combine::error::UnexpectedParse::Unexpected);
    }
}

struct TypeParser();

impl<'a> Parser<&'a [Token]> for TypeParser {
    type Output = SchemaType;
    type PartialState = ();

    fn parse_lazy(
        &mut self,
        input: &mut &'a [Token],
    ) -> combine::ParseResult<Self::Output, <&'a [Token] as combine::StreamOnce>::Error> {
        match self.parse(input) {
            Ok((res, tokens)) => {
                *input = tokens;
                combine::ParseResult::CommitOk(res)
            }
            Err(_) => combine::ParseResult::PeekErr(combine::error::Tracked::from(
                combine::error::UnexpectedParse::Unexpected,
            )),
        }
    }

    fn parse(
        &mut self,
        input: &'a [Token],
    ) -> Result<(Self::Output, &'a [Token]), <&'a [Token] as combine::StreamOnce>::Error> {
        if let Ok((_, tokens)) = accept(Token::TyBool).parse(input) {
            return Ok((SchemaType::Type(SchemaTypeVariant::Boolean), tokens));
        }
        if let Ok((_, tokens)) = accept(Token::TyLong).parse(input) {
            return Ok((SchemaType::Type(SchemaTypeVariant::Long), tokens));
        }
        if let Ok((_, tokens)) = accept(Token::TyString).parse(input) {
            return Ok((SchemaType::Type(SchemaTypeVariant::String), tokens));
        }
        if let Ok((_, tokens)) = accept(Token::Set).parse(input) {
            if let Ok((_, tokens)) = accept(Token::LAngle).parse(tokens) {
                if let Ok((elem_ty, tokens)) = parse_type().parse(tokens) {
                    if let Ok((_, tokens)) = accept(Token::RAngle).parse(tokens) {
                        return Ok((
                            SchemaType::Type(SchemaTypeVariant::Set {
                                element: (Box::new(elem_ty)),
                            }),
                            tokens,
                        ));
                    }
                }
            }
        }
        if let Ok((_, tokens)) = accept(Token::LBrace).parse(input) {
            if let Ok((attrs, tokens)) = AttrParser().parse(tokens) {
                if let Ok((_, tokens)) = accept(Token::RBrace).parse(tokens) {
                    return Ok((
                        SchemaType::Type(SchemaTypeVariant::Record {
                            attributes: attrs,
                            additional_attributes: false,
                        }),
                        tokens,
                    ));
                }
            }
        }
        if let Ok((id, tokens)) = parse_id().parse(input) {
            return Ok((
                SchemaType::Type(SchemaTypeVariant::Entity {
                    name: SmolStr::new(id.as_ref()),
                }),
                tokens,
            ));
        }
        return Err(combine::error::UnexpectedParse::Unexpected);
    }
}

fn parse_type<'a>() -> impl Parser<&'a [Token], Output = SchemaType> {
    TypeParser()
}

fn parse_double_colon<'a>() -> impl Parser<&'a [Token], Output = ()> {
    parse_punct(Token::DoubleColon)
}

fn parse_quote<'a>() -> impl Parser<&'a [Token], Output = ()> {
    parse_punct(Token::Quote)
}

fn parse_lbrace<'a>() -> impl Parser<&'a [Token], Output = ()> {
    parse_punct(Token::LBrace)
}

fn parse_rbrace<'a>() -> impl Parser<&'a [Token], Output = ()> {
    parse_punct(Token::RBrace)
}

fn parse_decl<'a>() -> impl Parser<&'a [Token], Output = NamespaceDefinition> {
    many1(parse_et_decl()).map(|et: Vec<(SmolStr, EntityType)>| NamespaceDefinition {
        common_types: HashMap::new(),
        entity_types: HashMap::from_iter(et.into_iter()),
        actions: HashMap::new(),
    })
}

fn parse_str<'a>() -> impl Parser<&'a [Token], Output = SmolStr> {
    satisfy_map(|v| match v {
        Token::Str(s) => Some(s),
        _ => None,
    })
}

fn parse_namespace<'a>() -> impl Parser<&'a [Token], Output = (SmolStr, NamespaceDefinition)> {
    (
        parse_keyword_namespace(),
        parse_str(),
        parse_lbrace(),
        parse_decl(),
        parse_rbrace(),
    )
        .map(|(_, ns_str, _, ns_def, _)| (ns_str, ns_def))
}

fn parse_path<'a>() -> impl Parser<&'a [Token], Output = Name> {
    sep_by1(parse_id(), parse_double_colon())
        .map(|ids: Vec<Id>| Name::new(ids[0].clone(), ids[1..].iter().map(|id| id.clone())))
}

// Entity    := 'entity' IDENT ['in' (EntType | '[' [EntTypes] ']')] [['='] RecType] ';'
fn parse_et_decl<'a>() -> impl Parser<&'a [Token], Output = (SmolStr, EntityType)> {
    (
        accept(Token::Entity),
        parse_id(),
        optional(choice((
            (accept(Token::In), parse_path()).map(|(_, p)| vec![p]),
            parse_ets(),
        )))
        .map(|opt| if let Some(vs) = opt { vs } else { vec![] }),
        optional(
            (
                optional(accept(Token::Eq)),
                between(accept(Token::LBrace), accept(Token::RBrace), AttrParser()),
            )
                .map(|(_, attrs)| attrs),
        )
        .map(|opt| {
            if let Some(attrs) = opt {
                AttributesOrContext(SchemaType::Type(SchemaTypeVariant::Record {
                    attributes: attrs,
                    additional_attributes: false,
                }))
            } else {
                AttributesOrContext::default()
            }
        }),
        accept(Token::SemiColon),
    )
        .map(|(_, id, ancestors, attrs, _)| {
            (
                SmolStr::new(id),
                EntityType {
                    member_of_types: ancestors
                        .into_iter()
                        .map(|n| SmolStr::new(n.to_string()))
                        .collect_vec(),
                    shape: attrs,
                },
            )
        })
}

// '[' [EntTypes] ']'
fn parse_ets<'a>() -> impl Parser<&'a [Token], Output = Vec<Name>> {
    between(
        accept(Token::LBracket),
        accept(Token::RBracket),
        sep_by1(parse_path(), accept(Token::Comma)),
    )
}

fn get_tokens(input: &str) -> Vec<Token> {
    Token::lexer(input)
        .spanned()
        .map(|p| p.0.unwrap())
        .collect_vec()
}

#[cfg(test)]
mod test_parser {
    use std::str::FromStr;

    use super::*;
    use cedar_policy_core::ast::Id;
    use combine::Parser;
    #[test]
    fn test_parse_id() {
        let tokens = get_tokens("lol");
        let id: Id = parse_id().parse(&tokens).expect("should parse").0;
        assert!(id == Id::from_str("lol").unwrap());
    }
    #[test]
    fn test_parse_type() {
        let tokens = get_tokens("{lol: Set <String>, abc: { efg: Bool}}");
        let ty = parse_type().parse(&tokens).expect("should parse").0;
        assert!(
            ty != SchemaType::Type(SchemaTypeVariant::Set {
                element: Box::new(SchemaType::Type(SchemaTypeVariant::String))
            }),
            "{ty:?}"
        );
    }
    #[test]
    fn test_parse_et_decl() {
        let tokens = get_tokens(
            " entity Issue {
            repo: Repository,
            reporter: User
        };",
        );
        let et = parse_et_decl().parse(&tokens);
        assert!(et.is_ok());
    }
    #[test]
    fn test_parse_ns_decl() {
        let tokens = get_tokens(
            "namespace \"lol\" {
            entity Application;
        }",
        );
        let ns = parse_namespace().parse(&tokens);
        assert!(ns.is_ok());
    }
}

#[cfg(test)]
mod test_lexer {
    use super::Token;
    use logos::Logos;
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
