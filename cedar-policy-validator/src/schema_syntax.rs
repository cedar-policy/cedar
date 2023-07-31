use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

use cedar_policy_core::ast::{Id, Name};
use combine::{
    between, choice, eof, many, many1, optional, parser, satisfy_map, sep_by1, Parser, Stream,
};
use itertools::Itertools;
use logos::{Logos, Span};
use smol_str::SmolStr;

use crate::{
    ActionEntityUID, ActionType, ApplySpec, AttributesOrContext, EntityType, NamespaceDefinition,
    SchemaType, SchemaTypeVariant, TypeOfAttribute,
};

// Cedar tokens
#[derive(Logos, Clone, Debug, PartialEq)]
enum Token {
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

struct AppParser();

impl<'a> Parser<&'a [Token]> for AppParser {
    type Output = ApplySpec;
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
        if let Ok((id, tokens)) = choice((
            accept(Token::VarPrincipal).map(|_| "principal"),
            accept(Token::VarResource).map(|_| "resource"),
        ))
        .parse(input)
        {
            if let Ok((_, tokens)) = accept(Token::Colon).parse(tokens) {
                if let Ok((ty, tokens)) = parse_ets().parse(tokens) {
                    let singleton = {
                        match id {
                            "principal" => ApplySpec {
                                resource_types: None,
                                principal_types: Some(
                                    ty.into_iter()
                                        .map(|n| SmolStr::new(n.to_string()))
                                        .collect_vec(),
                                ),
                                context: AttributesOrContext::default(),
                            },
                            "resource" => ApplySpec {
                                resource_types: Some(
                                    ty.into_iter()
                                        .map(|n| SmolStr::new(n.to_string()))
                                        .collect_vec(),
                                ),
                                principal_types: None,
                                context: AttributesOrContext::default(),
                            },
                            _ => unreachable!("wrong id"),
                        }
                    };
                    if let Ok((_, tokens)) = accept(Token::Comma).parse(tokens) {
                        if let Ok((cdr, tokens)) = self.parse(tokens) {
                            let merge = |lst1: Option<Vec<SmolStr>>, lst2| match (lst1, lst2) {
                                (Some(l1), Some(l2)) => Some([l1, l2].concat()),
                                (Some(l1), None) => Some(l1),
                                (None, Some(l2)) => Some(l2),
                                _ => None,
                            };
                            let lst = ApplySpec {
                                principal_types: merge(
                                    singleton.principal_types,
                                    cdr.principal_types,
                                ),
                                resource_types: merge(singleton.resource_types, cdr.resource_types),
                                context: AttributesOrContext::default(),
                            };
                            return Ok((lst, tokens));
                        }
                        return Ok((singleton, tokens));
                    }
                    return Ok((singleton, tokens));
                }
            }
        }
        return Err(combine::error::UnexpectedParse::Unexpected);
    }
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
    let merge_nds = |nds: Vec<NamespaceDefinition>| {
        let mut common_types = HashMap::new();
        let mut entity_types = HashMap::new();
        let mut actions = HashMap::new();
        for nd in nds.into_iter() {
            common_types.extend(nd.common_types);
            entity_types.extend(nd.entity_types);
            actions.extend(nd.actions);
        }
        NamespaceDefinition {
            common_types,
            entity_types,
            actions,
        }
    };
    many1(choice((
        parse_et_decl().map(|et| NamespaceDefinition {
            common_types: HashMap::new(),
            entity_types: HashMap::from_iter(std::iter::once(et)),
            actions: HashMap::new(),
        }),
        parse_action_decl().map(|action| NamespaceDefinition {
            common_types: HashMap::new(),
            entity_types: HashMap::new(),
            actions: action,
        }),
    )))
    .map(move |nds: Vec<NamespaceDefinition>| merge_nds(nds))
}

fn parse_str<'a>() -> impl Parser<&'a [Token], Output = SmolStr> {
    satisfy_map(|v| match v {
        Token::Str(s) => Some(s),
        _ => None,
    })
}

fn parse_name<'a>() -> impl Parser<&'a [Token], Output = SmolStr> {
    satisfy_map(|v| match v {
        Token::Str(s) => Some(s),
        Token::Identifier(id) => Some(id),
        _ => None,
    })
}

fn parse_names<'a>() -> impl Parser<&'a [Token], Output = Vec<SmolStr>> {
    between(
        accept(Token::LBracket),
        accept(Token::RBracket),
        sep_by1(parse_name(), accept(Token::Comma)),
    )
}

fn parse_namespace<'a>() -> impl Parser<&'a [Token], Output = (SmolStr, NamespaceDefinition)> {
    (
        parse_keyword_namespace(),
        parse_str(),
        parse_lbrace(),
        parse_decl(),
        parse_rbrace(),
        eof(),
    )
        .map(|(_, ns_str, _, ns_def, _, _)| (ns_str, ns_def))
}

fn parse_path<'a>() -> impl Parser<&'a [Token], Output = Name> {
    sep_by1(parse_id(), parse_double_colon())
        .map(|ids: Vec<Id>| Name::new(ids[0].clone(), ids[1..].iter().map(|id| id.clone())))
}

// Action    := 'action' Name ['in' (Name | '[' [Names] ']')] [AppliesTo] ';'
fn parse_action_decl<'a>() -> impl Parser<&'a [Token], Output = HashMap<SmolStr, ActionType>> {
    (
        accept(Token::VarAction),
        sep_by1(parse_name(), accept(Token::Comma)).map(|vs: Vec<SmolStr>| vs),
        optional(
            (
                accept(Token::In),
                choice((parse_name().map(|p| vec![p]), parse_names())),
            )
                .map(|(_, ns)| ns),
        ),
        optional(
            (
                accept(Token::AppliesTo),
                between(accept(Token::LBrace), accept(Token::RBrace), AppParser()),
            )
                .map(|(_, apps)| apps),
        ),
        accept(Token::SemiColon),
    )
        .map(|(_, ids, ancestors, apps, _)| {
            HashMap::from_iter(ids.into_iter().map(|id| {
                (
                    SmolStr::new(id),
                    ActionType {
                        attributes: None,
                        applies_to: apps.clone(),
                        member_of: ancestors.clone().map(|ns| {
                            ns.into_iter()
                                .map(|n| ActionEntityUID { id: n, ty: None })
                                .collect_vec()
                        }),
                    },
                )
            }))
        })
}

// Entity    := 'entity' IDENT ['in' (EntType | '[' [EntTypes] ']')] [['='] RecType] ';'
fn parse_et_decl<'a>() -> impl Parser<&'a [Token], Output = (SmolStr, EntityType)> {
    (
        accept(Token::Entity),
        parse_id(),
        optional((
            accept(Token::In),
            choice((parse_path().map(|p| vec![p]), parse_ets())),
        ))
        .map(|opt| if let Some((_, vs)) = opt { vs } else { vec![] }),
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
        let tokens = get_tokens(" entity User in [Team,Application] { name: String };");
        let et = parse_et_decl().parse(&tokens);
        assert!(et.is_ok());
    }
    #[test]
    fn test_parse_action_decl() {
        let tokens = get_tokens(
            " action CreateList
            appliesTo { principal: [User], resource: [Application] };",
        );
        let action = parse_action_decl().parse(&tokens);
        assert!(action.is_ok());
    }
    #[test]
    fn test_parse_ns_decl() {
        let tokens = get_tokens(
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
        );
        let ns = parse_namespace().parse(&tokens);
        assert!(ns.is_ok(), "{:?}", ns.unwrap_err());
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
