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

//! This module contains step one of the parser for the Cedar language.
//! It converts text to a CST

lalrpop_mod!(
    #[allow(warnings, unused)]
    //PANIC SAFETY: lalrpop uses unwraps, and we are trusting lalrpop to generate correct code
    #[allow(clippy::unwrap_used)]
    //PANIC SAFETY: lalrpop uses slicing, and we are trusting lalrpop to generate correct code
    #[allow(clippy::indexing_slicing)]
    //PANIC SAFETY: lalrpop uses unreachable, and we are trusting lalrpop to generate correct code
    #[allow(clippy::unreachable)]
    pub grammar,
    "/src/parser/grammar.rs"
);

use lazy_static::lazy_static;

use super::*;

// This helper function calls a generated parser, collects errors that could be
// generated multiple ways, and returns a single Result where the error type is
// `err::ParseError`.
fn parse_collect_errors<'a, P, T>(
    parser: &P,
    parse: impl FnOnce(
        &P,
        &mut Vec<err::RawErrorRecovery<'a>>,
        &'a str,
    ) -> Result<T, err::RawParseError<'a>>,
    text: &'a str,
) -> Result<T, Vec<err::ParseError>> {
    // call generated parser
    let mut errs = Vec::new();
    let result = parse(parser, &mut errs, text);

    // convert both parser error types to the local error type
    let mut errors: Vec<err::ParseError> = errs
        .into_iter()
        .map(|recovery| err::ToCSTError::from_raw_err_recovery(recovery).into())
        .collect();
    let result = result.map_err(|err| err::ToCSTError::from_raw_parse_err(err).into());

    // decide to return errors or success
    match result {
        Ok(parsed) => {
            if !errors.is_empty() {
                // In this case, `parsed` contains internal errors but could
                // still be used. However, for now, we do not use `parsed` --
                // we just return the errors from this parsing phase and stop.
                Err(errors)
            } else {
                Ok(parsed)
            }
        }
        Err(e) => {
            errors.push(e);
            Err(errors)
        }
    }
}

// Thread-safe "global" parsers, initialized at first use
lazy_static! {
    static ref POLICIES_PARSER: grammar::PoliciesParser = grammar::PoliciesParser::new();
    static ref POLICY_PARSER: grammar::PolicyParser = grammar::PolicyParser::new();
    static ref EXPR_PARSER: grammar::ExprParser = grammar::ExprParser::new();
    static ref REF_PARSER: grammar::RefParser = grammar::RefParser::new();
    static ref PRIMARY_PARSER: grammar::PrimaryParser = grammar::PrimaryParser::new();
    static ref NAME_PARSER: grammar::NameParser = grammar::NameParser::new();
    static ref IDENT_PARSER: grammar::IdentParser = grammar::IdentParser::new();
}

/// Create CST for multiple policies from text
pub fn parse_policies(
    text: &str,
) -> Result<node::ASTNode<Option<cst::Policies>>, Vec<err::ParseError>> {
    parse_collect_errors(&*POLICIES_PARSER, grammar::PoliciesParser::parse, text)
}

/// Create CST for one policy statement from text
pub fn parse_policy(
    text: &str,
) -> Result<node::ASTNode<Option<cst::Policy>>, Vec<err::ParseError>> {
    parse_collect_errors(&*POLICY_PARSER, grammar::PolicyParser::parse, text)
}

/// Create CST for one Expression from text
pub fn parse_expr(text: &str) -> Result<node::ASTNode<Option<cst::Expr>>, Vec<err::ParseError>> {
    parse_collect_errors(&*EXPR_PARSER, grammar::ExprParser::parse, text)
}

/// Create CST for one Entity Ref (i.e., UID) from text
pub fn parse_ref(text: &str) -> Result<node::ASTNode<Option<cst::Ref>>, Vec<err::ParseError>> {
    parse_collect_errors(&*REF_PARSER, grammar::RefParser::parse, text)
}

/// Create CST for one Primary value from text
pub fn parse_primary(
    text: &str,
) -> Result<node::ASTNode<Option<cst::Primary>>, Vec<err::ParseError>> {
    parse_collect_errors(&*PRIMARY_PARSER, grammar::PrimaryParser::parse, text)
}

/// Parse text as a Name, or fail if it does not parse as a Name
pub fn parse_name(text: &str) -> Result<node::ASTNode<Option<cst::Name>>, Vec<err::ParseError>> {
    parse_collect_errors(&*NAME_PARSER, grammar::NameParser::parse, text)
}

/// Parse text as an identifier, or fail if it does not parse as an identifier
pub fn parse_ident(text: &str) -> Result<node::ASTNode<Option<cst::Ident>>, Vec<err::ParseError>> {
    parse_collect_errors(&*IDENT_PARSER, grammar::IdentParser::parse, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expr1() {
        assert!(parse_expr(
            r#"
        1
        "#
        )
        .expect("parser fail")
        .node
        .is_some());
    }

    #[test]
    fn expr2() {
        assert!(parse_expr(
            r#"
        "string"
        "#
        )
        .expect("parser fail")
        .node
        .is_some());
    }

    #[test]
    fn expr3() {
        assert!(parse_expr(
            r#"
        "string".foo == !7
        "#
        )
        .expect("parser fail")
        .node
        .is_some());
    }

    #[test]
    fn expr4() {
        let result = parse_expr(
            r#"
        5 < 3 || -7 == 2 && 3 >= 6
        "#,
        )
        .expect("parser fail")
        .node;
        assert!(result.is_some());
    }

    #[test]
    fn expr5() {
        assert!(parse_expr(
            r#"
        if 7 then 6 > 5 else !5 || "thursday"
        "#
        )
        .expect("parser fail")
        .node
        .is_some());
    }

    #[test]
    fn expr6() {
        let result = parse_expr(
            r#"
        if 7 then 6 > 5 else !5 || "thursday" && ((8) >= "fish")
        "#,
        )
        .expect("parser fail")
        .node;
        assert!(result.is_some());
    }

    #[test]
    fn expr_overflow() {
        // an error is not a crash!
        assert!(parse_expr(
            r#"
            principal == -5555555555555555555555
        "#
        )
        .is_err());
        assert!(parse_expr(
            r#"
            principal == 5555555555555555555555
        "#
        )
        .is_err());
    }

    #[test]
    fn variable1() {
        let policy = parse_policy(
            r#"
                permit(principal, action, var:h in 1);
            "#,
        );
        assert!(policy.is_ok());
    }

    #[test]
    fn variable2() {
        let policy = parse_policy(
            r#"
                permit(principal, action, more in 2);
            "#,
        );
        assert!(policy.is_ok());
    }

    #[test]
    fn variable3() {
        let policy = parse_policy(
            r#"
                permit(principal, action:a_name, resource);
            "#,
        );
        assert!(policy.is_ok());
    }

    #[test]
    fn variable4() {
        let policy = parse_policy(
            r#"
                permit(principalorsomeotherident, action, resource);
            "#,
        );
        assert!(policy.is_ok());
    }

    #[test]
    fn variable6() {
        let policy = parse_policy(
            r#"
                permit(var : in 6, action, resource);
            "#,
        );
        assert!(policy.is_err());
    }

    #[test]
    fn member1() {
        let policy = parse_policy(
            r#"
                permit(principal, action, resource)
                when{
                    2._field // oh, look, comments!
                };
            "#,
        );
        assert!(policy.is_ok());
    }

    #[test]
    fn member2() {
        let policy = parse_policy(
            r#"
                permit(principal, action, resource)
                when{
                    "first".some_ident()
                };
            "#,
        );
        assert!(policy.is_ok());
    }

    #[test]
    fn member3() {
        let policy = parse_policy(
            r#"
                permit(principal, action, resource)
                when{
                    [2,3,4].foo[2]
                };
            "#,
        );
        assert!(policy.is_ok());
    }

    #[test]
    fn member4() {
        let policy = parse_policy(
            r#"
                permit(principal, action, resource)
                when{
                    {3<-4:"what?","ok then":-5>4}
                };
            "#,
        );
        assert!(policy.is_ok());
    }

    #[test]
    fn member5() {
        let policy = parse_policy(
            r#"
                permit(principal, action, resource)
                when{
                    [3<4,"ok then",17,("none")]
                };
            "#,
        );
        assert!(policy.is_ok());
    }

    #[test]
    fn member6() {
        let policy = parse_policy(
            r#"
                permit(principal, action, resource)
                when{
                    one.two
                };
            "#,
        );
        assert!(policy.is_ok());
    }

    #[test]
    #[should_panic] // we no longer support structs
    fn member7() {
        let policy = parse_policy(
            r#"
                permit(principal, action, resource)
                when{
                    one{num:true,trivia:"first!"}
                };
            "#,
        );
        assert!(policy.is_ok());
    }

    #[test]
    fn member8() {
        let policy = parse_policy(
            r#"
                permit(principal, action, resource)
                when{
                    {2:true,4:me}.with["pizza"]
                };
            "#,
        );
        assert!(policy.is_ok());
    }

    #[test]
    fn member9() {
        let policy = parse_policy(
            r#"
                permit(principal, action, resource)
                when{
                    AllRects({two:2,four:3+5/5})
                };
            "#,
        );
        assert!(policy.is_ok());
    }

    #[test]
    fn ident1() {
        let ident = parse_ident(
            r#"
                principal
            "#,
        );
        assert!(ident.is_ok());
    }

    #[test]
    fn ident2() {
        let ident = parse_ident(
            r#"
                if
            "#,
        );
        // specialized parser for idents has no limits
        assert!(ident.is_ok());
        let ident = parse_ident(
            r#"
                false
            "#,
        );
        // specialized parser for idents has no limits
        assert!(ident.is_ok());
    }

    #[test]
    fn ident3() {
        let ident = parse_expr(
            r#"
                if
            "#,
        );
        // Not a valid variable name (but then, only the 4 special vars make it to AST)
        assert!(ident.is_err());
        let name = parse_expr(
            r#"
                if::then::else
            "#,
        );
        // is a valid path component
        assert!(name.is_ok());
        let names = parse_expr(
            r#"
                if::true::then::false::else::true
            "#,
        );
        // is a valid path component
        assert!(names.is_ok());
    }

    #[test]
    fn ident4() {
        let ident = parse_expr(
            r#"
                true(true)
            "#,
        );
        // can be used as a function
        assert!(ident.is_ok());
        let ident = parse_expr(
            r#"
                if(true)
            "#,
        );
        // but this on cannot because of parse confusion
        assert!(ident.is_err());
    }

    #[test]
    fn ident5() {
        let ident = parse_expr(
            r#"
                {true : false}
            "#,
        );
        // can be used as record init, but this may not parse to AST
        // because true is a value, not an identifier
        assert!(ident.is_ok());
        let ident = parse_expr(
            r#"
                { if : true }
            "#,
        );
        // special case allows this one to be an identifier
        assert!(ident.is_ok());
    }

    #[test]
    fn ident6() {
        let ident = parse_expr(
            r#"
                {true : false} has false
            "#,
        );
        // can be used as record init, but this may not parse to AST
        // because true is a value, not an identifier
        assert!(ident.is_ok());
        let ident = parse_expr(
            r#"
                { if : true } has if
            "#,
        );
        // special case allows this one to be an identifier
        assert!(ident.is_ok());
    }

    #[test]
    fn comments_has() {
        // single line comments (`// ...`) are valid anywhere
        let policy_text = r#"
                permit(principal, action,resource)
                when{ principal //comment p
                has //comment has
                age //comment
                };
            "#;
        let policy = parse_policy(policy_text);
        assert!(policy.is_ok());
    }

    #[test]
    fn comments_like() {
        // single line comments (`// ...`) are valid anywhere
        let policy_text = r#"
                permit(principal, action,resource)
                when{ principal //comment p
                like //comment like

                age //comment
                };
            "#;
        let policy = parse_policy(policy_text);
        assert!(policy.is_ok());
    }

    #[test]
    fn comments_and() {
        // single line comments (`// ...`) are valid anywhere
        let policy_text = r#"
                permit(principal, action,resource)
                when{ 1 //comment p
                &&  //comment &&
                    //comment &&
                "hello" //comment
                };
            "#;
        let policy = parse_policy(policy_text);
        assert!(policy.is_ok());
    }

    #[test]
    fn comments_or() {
        // single line comments (`// ...`) are valid anywhere
        let policy_text = r#"
                permit(principal, action,resource)
                when{ 1 //comment 1
                      //  comment 1
                ||  //comment ||
                    //comments ||
                "hello" //comment
                        //comment hello
                };
            "#;
        let policy = parse_policy(policy_text);
        assert!(policy.is_ok());
    }

    #[test]
    fn comments_add() {
        // single line comments (`// ...`) are valid anywhere
        let policy_text = r#"
                permit(principal, action,resource)
                when{ 1 //comment 1
                        //comment 1_2
                + //comment +
                   //comment +
                 2 //comment 2
                    //comment 2
                };
            "#;
        let policy = parse_policy(policy_text);
        assert!(policy.is_ok());
    }

    #[test]
    fn comments_paren() {
        // single line comments (`// ...`) are valid anywhere
        let policy_text = r#"
                permit(principal, action,resource)
                when{
                ( //comment 1
                    ( //comment 2
                 1
                    ) //comment 3
                ) //comment 4
                };
            "#;
        let policy = parse_policy(policy_text);
        assert!(policy.is_ok());
    }

    #[test]
    fn comments_set() {
        // single line comments (`// ...`) are valid anywhere
        let policy_text = r#"
                permit(principal, action,resource)
                when{
                [ // comment 1
                "hello" //comment 2
                , // comment 3
                 // comment 3-2
                1 //comment 4
                    //comment 5
                ]  //comment 5-0

                .  //comment 5-1

                contains //comment 5-2

                ( //comment 6

                "a"  //comment 7

                ) //comment 20
                };
            "#;
        let policy = parse_policy(policy_text);
        assert!(policy.is_ok());
    }

    #[test]
    fn comments_if() {
        // single line comments (`// ...`) are valid anywhere
        let policy_text = r#"
                permit(principal, action,resource)
                when{
                ( //comment open outer
                ( //comment open inner
                 if //comment if
                  1             //comment
                  < //comment <
                  2 //commment 2
                  then // comment then
                  "hello" //comment hello
                else  //comment else
                    1 //comment 1
                    ) //comment close inner
                    ) //comment close outer
                };
            "#;
        let policy = parse_policy(policy_text);
        assert!(policy.is_ok());
    }

    #[test]
    fn comments_member_access() {
        // single line comments (`// ...`) are valid anywhere
        let policy_text = r#"
                permit(principal, action,resource)
                when{ principal. //comment .
                age // comment age
                };
            "#;
        let policy = parse_policy(policy_text);
        assert!(policy.is_ok());
    }

    #[test]
    fn comments_principal() {
        // single line comments (`// ...`) are valid anywhere
        let policy_text = r#"
                permit(principal //comment 1
                 ==
                  User::"alice" //comment 3
                  ,  //comment 4
                   action,resource);
            "#;
        let policy = parse_policy(policy_text);
        assert!(policy.is_ok());
    }

    #[test]
    fn comments_annotation() {
        // single line comments (`// ...`) are valid anywhere
        let policy_text = r#"
        //comment policy
        // comment policy 2
        @anno("good annotation")  // comments after annotation
        // comments after annotation 2
                permit(principal //comment 1
                 ==
                  User::"alice" //comment 3
                  ,  //comment 4
                   action,resource);
            "#;
        let policy = parse_policy(policy_text);
        assert!(policy.is_ok());
    }

    #[test]
    fn comments_policy() {
        // single line comments (`// ...`) are valid anywhere
        let policy_text = r#"
                //comment policy 1
                //comment policy 2
                permit( //comment 3
                   // comment 4
                principal //comment principal
                == //comment == 1
                   //comment == 2
                User::"alice" //comment alice
                , //comment comma 1
                            //comment comma 2
                action //comment action 1
                //comment action 2
                , //comment comma action
                resource // comment resource
                )
                //comment 5
                //comment 6
                ;
            "#;
        let policy = parse_policy(policy_text);
        assert!(policy.is_ok());
        //multi-line comments (`/* ... */`) are not allowed
        let policy = parse_policy(
            r#" /* multi-line
            comment */
                permit(principal, action, resource)
                when{
                    one.two
                };
            "#,
        );
        assert!(policy.is_err());
        let expr = parse_expr(
            r#"
            1 /* multi-line
            comment */d
            "#,
        );
        assert!(expr.is_err());
    }

    #[test]
    fn no_comments_policy() {
        // single line comments (`// ...`) are valid anywhere
        let policy_text = r#"
               permit(
                principal
                ==
                User::"alice"
                ,
                action

                ,
                resource
                )
                ;
            "#;
        let policy = parse_policy(policy_text);
        assert!(policy.is_ok());
    }

    #[test]
    fn no_comments_policy2() {
        let policy_text = r#"permit (
    principal == IAM::Principal::"arn:aws:iam::12345678901:user/Dave",
    action == S3::Action::"GetAccountPublicAccessBlock",
    resource == Account::"12345678901"
    );"#;
        let policy = parse_policy(policy_text);
        assert!(policy.is_ok());
    }

    #[test]
    fn no_comments_policy4() {
        let policy_text = r#"
    permit(principal,action,resource,context)
    when {
    context.contains(3,"four",five(6,7))
};"#;
        let policy = parse_policy(policy_text);
        assert!(policy.is_ok());
    }
    #[test]
    fn no_comments_policy5() {
        let policy_text = r#"
    permit (
    principal,
    action,
    resource == Album::{uid: "772358b3-de11-42dc-8681-f0a32e34aab8",
    displayName: "vacation_photos"}
);"#;
        let policy = parse_policy(policy_text);
        assert!(policy.is_ok());
    }

    #[test]
    fn policies1() {
        let policy = parse_policy(
            r#"
                permit(principal:p,action:a,resource:r)when{w}unless{u}advice{"doit"};
            "#,
        );
        assert!(policy.is_ok());
    }

    #[test]
    fn policies2() {
        let result = parse_policies(
            r#"
                permit(
                    principal in Group::"jane_friends",  // Policy c1
                    action in [PhotoOp::"view", PhotoOp::"comment"],
                    resource in Album::"jane_trips",
                    context:Group
                );
            "#,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn policies3() {
        assert!(parse_policies(
            r#"
            forbid(principal, action, resource)           // Policy c2
            when   { "private" in resource.tags }  // resource.tags is a set of strings
            unless { resource in user.account };
        "#
        )
        // check that all policy statements are successful
        .expect("parse fail")
        .node
        .expect("no data")
        .0
        .iter()
        .all(|p| p.node.is_some()));
    }

    #[test]
    // repeat of prior test but with a typo
    // typos are not caught by the cst parser
    fn policies3p() {
        assert!(parse_policies(
            r#"
            forbid(principality, action, resource)           // Policy c2
            when   { "private" in resource.tags }  // resource.tags is a set of strings
            unless { resource in user.account };
        "#
        )
        // check that all policy statements are successful
        .expect("parse fail")
        .node
        .expect("no data")
        .0
        .iter()
        .all(|p| p.node.is_some()));
    }

    #[test]
    fn policies4() {
        let result = parse_policies(
            r#"
            permit(principal:p,action:a,resource:r)when{w}unless{u}advice{"doit"};

            permit(principal in Group::"jane_friends",  // Policy c1
            action in [PhotoOp::"view", PhotoOp::"comment"],
            resource in Album::"jane_trips");

            forbid(principal, action, resource)           // Policy c2
            when   { "private" in resource.tags }  // resource.tags is a set of strings
            unless { resource in user.account };
        "#,
        )
        .expect("parse fail")
        .node
        .expect("no data");
        assert!(result.0.iter().all(|p| p.node.is_some()));
    }

    #[test]
    fn policies5() {
        assert!(parse_policies(
            r#"
            permit (
                principal == User::"alice",
                action in PhotoflashRole::"viewer",
                resource in Account::"jane"
            )
            advice {
                "{\"type\":\"PhotoFilterInstruction\", \"anonymize\":true}"
            };
        "#
        )
        .expect("parse fail")
        .node
        .expect("no data")
        .0
        .into_iter()
        .all(|p| p.node.is_some()));
    }

    #[test]
    fn policies6() {
        // test that an error doesn't stop the parser
        let policies = POLICIES_PARSER
            .parse(
                &mut Vec::new(),
                r#"
                // use a number to error
                3(principal:p,action:a,resource:r)when{w}unless{u}advice{"doit"};
                permit(principal:p,action:a,resource:r)when{w}unless{u}advice{"doit"};
                permit(principal:p,action:a,resource:r)when{w}unless{u}advice{"doit"};
            "#,
            )
            .expect("parser error")
            .node
            .expect("no data");
        let success = policies
            .0
            .into_iter()
            .filter_map(|p| p.node)
            .collect::<Vec<_>>();
        assert!(success.len() == 2);
    }

    #[test]
    fn policy_annotations() {
        let policies = parse_policies(
            r#"
            @anno("good annotation") permit (principal, action, resource);
            @anno1("good")@anno2("annotation") permit (principal, action, resource);
            @long6wordphraseisident007("good annotation") permit (principal, action, resource);
            @   spacy  (  "  good  annotation  "  )   permit (principal, action, resource);
        "#,
        )
        .expect("parse fail")
        .node
        .expect("no data");
        let success = policies
            .0
            .into_iter()
            .filter_map(|p| p.node)
            .collect::<Vec<_>>();
        assert!(success.len() == 4);

        let _policy = parse_policy(
            r#"
            @bad-annotation("bad") permit (principal, action, resource);
        "#,
        )
        .expect_err("should fail on dash");

        let _policy = parse_policy(
            r#"
            @bad_annotation("bad","annotation") permit (principal, action, resource);
        "#,
        )
        .expect_err("should fail on list");

        let _policy = parse_policy(
            r#"
            @bad_annotation(bad_annotation) permit (principal, action, resource);
        "#,
        )
        .expect_err("should fail without string");

        let _policy = parse_policy(
            r#"
            permit (@comment("your name here") principal, action, resource);
        "#,
        )
        .expect_err("should fail with poor placement");
    }

    #[test]
    fn parse_idempotent() {
        let many_policies =
            std::fs::read_to_string("src/parser/testfiles/policies.txt").expect("missing file");
        let cst1 = parse_policies(&many_policies)
            .expect("parse fail")
            .node
            .expect("no data");
        let revert = format!("{}", cst1);
        //println!("{:#}", cst1);
        let cst2 = parse_policies(&revert)
            .expect("parse fail")
            .node
            .expect("no data");
        assert!(cst1 == cst2);
    }
}
