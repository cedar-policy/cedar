/*
 * Copyright Cedar Contributors
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
    //PANIC SAFETY: lalrpop uses panic, and we are trusting lalrpop to generate correct code
    #[allow(clippy::panic)]
    pub grammar,
    "/src/parser/grammar.rs"
);

use super::*;
use std::sync::Arc;

/// This helper function calls a generated parser, collects errors that could be
/// generated multiple ways, and returns a single Result where the error type is
/// [`err::ParseErrors`].
fn parse_collect_errors<'a, P, T>(
    parser: &P,
    parse: impl FnOnce(
        &P,
        &mut Vec<err::RawErrorRecovery<'a>>,
        &Arc<str>,
        &'a str,
    ) -> Result<T, err::RawParseError<'a>>,
    text: &'a str,
) -> Result<T, err::ParseErrors> {
    let mut errs = Vec::new();
    let result = parse(parser, &mut errs, &Arc::from(text), text);

    let errors = errs
        .into_iter()
        .map(err::ToCSTError::from_raw_err_recovery)
        .map(Into::into);
    let parsed = match result {
        Ok(parsed) => parsed,
        Err(e) => {
            return Err(err::ParseErrors::new(
                err::ToCSTError::from_raw_parse_err(e).into(),
                errors,
            ));
        }
    };
    match err::ParseErrors::from_iter(errors) {
        Some(errors) => Err(errors),
        None => Ok(parsed),
    }
}

// Thread-safe "global" parsers, initialized at first use
lazy_static::lazy_static! {
    static ref POLICIES_PARSER: grammar::PoliciesParser = grammar::PoliciesParser::new();
    static ref POLICY_PARSER: grammar::PolicyParser = grammar::PolicyParser::new();
    static ref EXPR_PARSER: grammar::ExprParser = grammar::ExprParser::new();
    static ref REF_PARSER: grammar::RefParser = grammar::RefParser::new();
    static ref PRIMARY_PARSER: grammar::PrimaryParser = grammar::PrimaryParser::new();
    static ref NAME_PARSER: grammar::NameParser = grammar::NameParser::new();
    static ref IDENT_PARSER: grammar::IdentParser = grammar::IdentParser::new();
}

/// Create CST for multiple policies from text
pub fn parse_policies(text: &str) -> Result<Node<Option<cst::Policies>>, err::ParseErrors> {
    parse_collect_errors(&*POLICIES_PARSER, grammar::PoliciesParser::parse, text)
}

/// Create CST for one policy statement from text
pub fn parse_policy(text: &str) -> Result<Node<Option<cst::Policy>>, err::ParseErrors> {
    parse_collect_errors(&*POLICY_PARSER, grammar::PolicyParser::parse, text)
}

/// Create CST for one Expression from text
pub fn parse_expr(text: &str) -> Result<Node<Option<cst::Expr>>, err::ParseErrors> {
    parse_collect_errors(&*EXPR_PARSER, grammar::ExprParser::parse, text)
}

/// Create CST for one Entity Ref (i.e., UID) from text
pub fn parse_ref(text: &str) -> Result<Node<Option<cst::Ref>>, err::ParseErrors> {
    parse_collect_errors(&*REF_PARSER, grammar::RefParser::parse, text)
}

/// Create CST for one Primary value from text
pub fn parse_primary(text: &str) -> Result<Node<Option<cst::Primary>>, err::ParseErrors> {
    parse_collect_errors(&*PRIMARY_PARSER, grammar::PrimaryParser::parse, text)
}

/// Parse text as a Name, or fail if it does not parse as a Name
pub fn parse_name(text: &str) -> Result<Node<Option<cst::Name>>, err::ParseErrors> {
    parse_collect_errors(&*NAME_PARSER, grammar::NameParser::parse, text)
}

/// Parse text as an identifier, or fail if it does not parse as an identifier
pub fn parse_ident(text: &str) -> Result<Node<Option<cst::Ident>>, err::ParseErrors> {
    parse_collect_errors(&*IDENT_PARSER, grammar::IdentParser::parse, text)
}

// PANIC SAFETY unit test code
#[allow(clippy::panic)]
// PANIC SAFETY unit test code
#[allow(clippy::indexing_slicing)]
#[cfg(test)]
mod tests {
    use crate::parser::test_utils::*;
    use crate::test_utils::*;

    use super::*;

    #[track_caller]
    fn assert_parse_succeeds<T>(
        parse: impl FnOnce(&str) -> Result<Node<Option<T>>, err::ParseErrors>,
        text: &str,
    ) -> T {
        parse(text)
            .unwrap_or_else(|errs| panic!("failed to parse:\n{:?}", miette::Report::new(errs)))
            .node
            .expect("failed get CST")
    }

    #[track_caller]
    fn assert_parse_fails<T: std::fmt::Debug>(
        parse: impl FnOnce(&str) -> Result<Node<Option<T>>, err::ParseErrors>,
        text: &str,
    ) -> err::ParseErrors {
        match parse(text) {
            Ok(node) => {
                panic!("parsing should have failed, but succeeded with:\n{node:?}")
            }
            Err(errs) => errs,
        }
    }

    #[test]
    fn expr1() {
        assert_parse_succeeds(
            parse_expr,
            r#"
        1
        "#,
        );
    }

    #[test]
    fn expr2() {
        assert_parse_succeeds(
            parse_expr,
            r#"
        "string"
        "#,
        );
    }

    #[test]
    fn expr3() {
        assert_parse_succeeds(
            parse_expr,
            r#"
        "string".foo == !7
        "#,
        );
    }

    #[test]
    fn expr4() {
        assert_parse_succeeds(
            parse_expr,
            r#"
        5 < 3 || -7 == 2 && 3 >= 6
        "#,
        );
    }

    #[test]
    fn expr5() {
        assert_parse_succeeds(
            parse_expr,
            r#"
        if 7 then 6 > 5 else !5 || "thursday"
        "#,
        );
    }

    #[test]
    fn expr6() {
        assert_parse_succeeds(
            parse_expr,
            r#"
        if 7 then 6 > 5 else !5 || "thursday" && ((8) >= "fish")
        "#,
        );
    }

    #[test]
    fn expr_overflow() {
        // an error is not a crash!
        let src = r#"
            principal == -5555555555555555555555
        "#;
        let errs = assert_parse_fails(parse_expr, src);
        expect_exactly_one_error(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "integer parse error: number too large to fit in target type",
            )
            .exactly_one_underline("5555555555555555555555")
            .build(),
        );
        let src = r#"
            principal == 5555555555555555555555
        "#;
        let errs = assert_parse_fails(parse_expr, src);
        expect_exactly_one_error(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "integer parse error: number too large to fit in target type",
            )
            .exactly_one_underline("5555555555555555555555")
            .build(),
        );
    }

    #[test]
    fn variable1() {
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action, var:h in 1);
            "#,
        );
    }

    #[test]
    fn variable2() {
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action, more in 2);
            "#,
        );
    }

    #[test]
    fn variable3() {
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action:a_name, resource);
            "#,
        );
    }

    #[test]
    fn variable4() {
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principalorsomeotherident, action, resource);
            "#,
        );
    }

    #[test]
    fn variable6() {
        let src = r#"
            permit(var : in 6, action, resource);
        "#;
        let errs = assert_parse_fails(parse_policy, src);
        expect_exactly_one_error(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `6`")
                .exactly_one_underline_with_label(
                    "6",
                    "expected `!=`, `)`, `,`, `::`, `<`, `<=`, `==`, `>`, `>=`, `in`, or `is`",
                )
                .build(),
        );
    }

    #[test]
    fn member1() {
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action, resource)
                when{
                    2._field // oh, look, comments!
                };
            "#,
        );
    }

    #[test]
    fn member2() {
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action, resource)
                when{
                    "first".some_ident()
                };
            "#,
        );
    }

    #[test]
    fn member3() {
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action, resource)
                when{
                    [2,3,4].foo[2]
                };
            "#,
        );
    }

    #[test]
    fn member4() {
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action, resource)
                when{
                    {3<-4:"what?","ok then":-5>4}
                };
            "#,
        );
    }

    #[test]
    fn member5() {
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action, resource)
                when{
                    [3<4,"ok then",17,("none")]
                };
            "#,
        );
    }

    #[test]
    fn member6() {
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action, resource)
                when{
                    one.two
                };
            "#,
        );
    }

    #[test] // we no longer support named structs
    fn member7() {
        let src = r#"
            permit(principal, action, resource)
            when{
                one{num:true,trivia:"first!"}
            };
        "#;
        let errs = assert_parse_fails(parse_policy, src);
        expect_n_errors(src, &errs, 2);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `{`")
                .exactly_one_underline_with_label("{", "expected `!=`, `&&`, `(`, `*`, `+`, `-`, `.`, `::`, `<`, `<=`, `==`, `>`, `>=`, `[`, `||`, `}`, `has`, `in`, `is`, or `like`")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `}`")
                .exactly_one_underline_with_label("}", "expected `;` or identifier")
                .build(),
        );
    }

    #[test]
    fn member8() {
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action, resource)
                when{
                    {2:true,4:me}.with["pizza"]
                };
            "#,
        );
    }

    #[test]
    fn member9() {
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action, resource)
                when{
                    AllRects({two:2,four:3+5/5})
                };
            "#,
        );
    }

    #[test]
    fn ident1() {
        assert_parse_succeeds(
            parse_ident,
            r#"
                principal
            "#,
        );
    }

    #[test]
    fn ident2() {
        // specialized parser for idents does not care about keywords
        assert_parse_succeeds(
            parse_ident,
            r#"
                if
            "#,
        );
        // specialized parser for idents does not care about keywords
        assert_parse_succeeds(
            parse_ident,
            r#"
                false
            "#,
        );
    }

    #[test]
    fn ident3() {
        // keywords are not valid variable names
        let src = r#"
            if
        "#;
        let errs = assert_parse_fails(parse_expr, src);
        expect_exactly_one_error(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected end of input")
                .exactly_one_underline_with_label("", "expected `!`, `(`, `-`, `::`, `[`, `{`, `false`, identifier, `if`, number, `?principal`, `?resource`, string literal, or `true`")
                .build(),
        );
        // other random variable names are fine at this stage, although an error
        // will be raised during the CST->AST step
        assert_parse_succeeds(
            parse_expr,
            r#"
                foo
            "#,
        );
        // valid variable names are obviously ok
        assert_parse_succeeds(
            parse_expr,
            r#"
                foo
            "#,
        );
        // keywords are ok to use in paths at this stage, although an error will
        // be raised during the CST->AST step
        assert_parse_succeeds(
            parse_expr,
            r#"
                if::then::else
            "#,
        );
        assert_parse_succeeds(
            parse_expr,
            r#"
                if::true::then::false::else::true
            "#,
        );
    }

    #[test]
    fn ident4() {
        // some keywords can be used as functions
        assert_parse_succeeds(
            parse_expr,
            r#"
                true(true)
            "#,
        );
        // but some keywords cannot because of parse confusion
        let src = r#"
            if(true)
        "#;
        let errs = assert_parse_fails(parse_expr, src);
        expect_exactly_one_error(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected end of input")
                .exactly_one_underline_with_label("", "expected `then`")
                .build(),
        );
    }

    #[test]
    fn ident5() {
        // keywords are ok to use as attributes at this stage, although an error
        // will be raised during the CST->AST step
        assert_parse_succeeds(
            parse_expr,
            r#"
                {true : false}
            "#,
        );
        assert_parse_succeeds(
            parse_expr,
            r#"
                { if : true }
            "#,
        );
    }

    #[test]
    fn ident6() {
        // keywords are ok to use as attributes at this stage, although an error
        // will be raised during the CST->AST step
        assert_parse_succeeds(
            parse_expr,
            r#"
                {true : false} has false
            "#,
        );
        assert_parse_succeeds(
            parse_expr,
            r#"
                { if : true } has if
            "#,
        );
    }

    #[test]
    fn comments_has() {
        // single line comments (`// ...`) are valid anywhere
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action,resource)
                when{ principal //comment p
                has //comment has
                age //comment
                };
            "#,
        );
    }

    #[test]
    fn comments_like() {
        // single line comments (`// ...`) are valid anywhere
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action,resource)
                when{ principal //comment p
                like //comment like

                age //comment
                };
            "#,
        );
    }

    #[test]
    fn comments_and() {
        // single line comments (`// ...`) are valid anywhere
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action,resource)
                when{ 1 //comment p
                &&  //comment &&
                    //comment &&
                "hello" //comment
                };
            "#,
        );
    }

    #[test]
    fn comments_or() {
        // single line comments (`// ...`) are valid anywhere
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action,resource)
                when{ 1 //comment 1
                      //  comment 1
                ||  //comment ||
                    //comments ||
                "hello" //comment
                        //comment hello
                };
            "#,
        );
    }

    #[test]
    fn comments_add() {
        // single line comments (`// ...`) are valid anywhere
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action,resource)
                when{ 1 //comment 1
                        //comment 1_2
                + //comment +
                   //comment +
                 2 //comment 2
                    //comment 2
                };
            "#,
        );
    }

    #[test]
    fn comments_paren() {
        // single line comments (`// ...`) are valid anywhere
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action,resource)
                when{
                ( //comment 1
                    ( //comment 2
                 1
                    ) //comment 3
                ) //comment 4
                };
            "#,
        );
    }

    #[test]
    fn comments_set() {
        // single line comments (`// ...`) are valid anywhere
        assert_parse_succeeds(
            parse_policy,
            r#"
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
            "#,
        );
    }

    #[test]
    fn comments_if() {
        // single line comments (`// ...`) are valid anywhere
        assert_parse_succeeds(
            parse_policy,
            r#"
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
            "#,
        );
    }

    #[test]
    fn comments_member_access() {
        // single line comments (`// ...`) are valid anywhere
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal, action,resource)
                when{ principal. //comment .
                age // comment age
                };
            "#,
        );
    }

    #[test]
    fn comments_principal() {
        // single line comments (`// ...`) are valid anywhere
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal //comment 1
                 ==
                  User::"alice" //comment 3
                  ,  //comment 4
                   action,resource);
            "#,
        );
    }

    #[test]
    fn comments_annotation() {
        // single line comments (`// ...`) are valid anywhere
        assert_parse_succeeds(
            parse_policy,
            r#"
        //comment policy
        // comment policy 2
        @anno("good annotation")  // comments after annotation
        // comments after annotation 2
                permit(principal //comment 1
                 ==
                  User::"alice" //comment 3
                  ,  //comment 4
                   action,resource);
            "#,
        );
    }

    #[test]
    fn comments_policy() {
        // single line comments (`// ...`) are valid anywhere
        assert_parse_succeeds(
            parse_policy,
            r#"
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
            "#,
        );
        //multi-line comments (`/* ... */`) are not allowed
        let src = r#" /* multi-line
            comment */
                permit(principal, action, resource)
                when{
                    one.two
                };
            "#;
        let errs = assert_parse_fails(parse_policy, src);
        expect_exactly_one_error(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `/`")
                .exactly_one_underline_with_label("/", "expected `@` or identifier")
                .build(),
        );
        let src = r#"
            1 /* multi-line
            comment */d
            "#;
        let errs = assert_parse_fails(parse_expr, src);
        expect_exactly_one_error(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `*`")
                .exactly_one_underline_with_label("*", "expected `!`, `(`, `-`, `[`, `{`, `false`, identifier, `if`, number, `?principal`, `?resource`, string literal, or `true`")
                .build(),
        );
    }

    #[test]
    fn no_comments_policy() {
        // single line comments (`// ...`) are valid anywhere
        assert_parse_succeeds(
            parse_policy,
            r#"
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
            "#,
        );
    }

    #[test]
    fn no_comments_policy2() {
        assert_parse_succeeds(
            parse_policy,
            r#"permit (
    principal == IAM::Principal::"arn:aws:iam::12345678901:user/Dave",
    action == S3::Action::"GetAccountPublicAccessBlock",
    resource == Account::"12345678901"
    );"#,
        );
    }

    #[test]
    fn no_comments_policy4() {
        assert_parse_succeeds(
            parse_policy,
            r#"
    permit(principal,action,resource,context)
    when {
    context.contains(3,"four",five(6,7))
};"#,
        );
    }
    #[test]
    fn no_comments_policy5() {
        assert_parse_succeeds(
            parse_policy,
            r#"
    permit (
    principal,
    action,
    resource == Album::{uid: "772358b3-de11-42dc-8681-f0a32e34aab8",
    displayName: "vacation_photos"}
);"#,
        );
    }

    #[test]
    fn policies1() {
        assert_parse_succeeds(
            parse_policy,
            r#"
                permit(principal:p,action:a,resource:r)when{w}unless{u}advice{"doit"};
            "#,
        );
    }

    #[test]
    fn policies2() {
        assert_parse_succeeds(
            parse_policies,
            r#"
                permit(
                    principal in Group::"jane_friends",  // Policy c1
                    action in [PhotoOp::"view", PhotoOp::"comment"],
                    resource in Album::"jane_trips",
                    context:Group
                );
            "#,
        );
    }

    #[test]
    fn policies3() {
        let policies = assert_parse_succeeds(
            parse_policies,
            r#"
            forbid(principal, action, resource)           // Policy c2
            when   { "private" in resource.tags }  // resource.tags is a set of strings
            unless { resource in user.account };
        "#,
        );

        // Check that internal nodes successfully parsed
        assert!(
            policies.0.iter().all(|p| p.node.is_some()),
            "Unexpected parser failure"
        );
    }

    #[test]
    // repeat of prior test but with a typo
    // typos are not caught by the cst parser
    fn policies3p() {
        let policies = assert_parse_succeeds(
            parse_policies,
            r#"
            forbid(principality, action, resource)           // Policy c2
            when   { "private" in resource.tags }  // resource.tags is a set of strings
            unless { resource in user.account };
        "#,
        );

        // Check that internal nodes successfully parsed
        assert!(
            policies.0.iter().all(|p| p.node.is_some()),
            "Unexpected parser failure"
        );
    }

    #[test]
    fn policies4() {
        let policies = assert_parse_succeeds(
            parse_policies,
            r#"
            permit(principal:p,action:a,resource:r)when{w}unless{u}advice{"doit"};

            permit(principal in Group::"jane_friends",  // Policy c1
            action in [PhotoOp::"view", PhotoOp::"comment"],
            resource in Album::"jane_trips");

            forbid(principal, action, resource)           // Policy c2
            when   { "private" in resource.tags }  // resource.tags is a set of strings
            unless { resource in user.account };
        "#,
        );

        // Check that internal nodes successfully parsed
        assert!(
            policies.0.iter().all(|p| p.node.is_some()),
            "Unexpected parser failure"
        );
    }

    #[test]
    fn policies5() {
        let policies = assert_parse_succeeds(
            parse_policies,
            r#"
            permit (
                principal == User::"alice",
                action in PhotoflashRole::"viewer",
                resource in Account::"jane"
            )
            advice {
                "{\"type\":\"PhotoFilterInstruction\", \"anonymize\":true}"
            };
        "#,
        );

        // Check that internal nodes successfully parsed
        assert!(
            policies.0.iter().all(|p| p.node.is_some()),
            "Unexpected parser failure"
        );
    }

    #[test]
    fn policies6() {
        // test that an error doesn't stop the parser
        let src = r#"
            // use a number to error
            3(principal:p,action:a,resource:r)when{w}unless{u}advice{"doit"};
            permit(principal:p,action:a,resource:r)when{w}unless{u}advice{"doit"};
            permit(principal:p,action:a,resource:r)when{w}unless{u}advice{"doit"};
            "#;
        let policies = POLICIES_PARSER
            .parse(&mut Vec::new(), &Arc::from(src), src)
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
        let policies = assert_parse_succeeds(
            parse_policies,
            r#"
            @anno("good annotation") permit (principal, action, resource);
            @anno1("good")@anno2("annotation") permit (principal, action, resource);
            @long6wordphraseisident007("good annotation") permit (principal, action, resource);
            @   spacy  (  "  good  annotation  "  )   permit (principal, action, resource);
        "#,
        );
        // should have successfully parsed 4 policies
        assert_eq!(
            policies
                .0
                .into_iter()
                .filter_map(|p| p.node)
                .collect::<Vec<_>>()
                .len(),
            4
        );

        let src = r#"
            @bad-annotation("bad") permit (principal, action, resource);
        "#;
        let errs = assert_parse_fails(parse_policies, src);
        expect_n_errors(src, &errs, 2);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `-`")
                .exactly_one_underline_with_label("-", "expected `(`")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `\"bad\"`")
                .exactly_one_underline_with_label("\"bad\"", "expected `)` or identifier")
                .build(),
        );

        let src = r#"
            @bad_annotation("bad","annotation") permit (principal, action, resource);
        "#;
        let errs = assert_parse_fails(parse_policies, src);
        expect_exactly_one_error(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `,`")
                .exactly_one_underline_with_label(",", "expected `)`")
                .build(),
        );

        let src = r#"
            @bad_annotation(bad_annotation) permit (principal, action, resource);
        "#;
        let errs = assert_parse_fails(parse_policies, src);
        expect_n_errors(src, &errs, 2);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `bad_annotation`")
                .exactly_one_underline_with_label("bad_annotation", "expected string literal")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `)`")
                .exactly_one_underline_with_label(")", "expected `(`")
                .build(),
        );

        let src = r#"
            permit (@comment("your name here") principal, action, resource);
        "#;
        let errs = assert_parse_fails(parse_policies, src);
        expect_n_errors(src, &errs, 4);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `@`")
                .exactly_one_underline_with_label("@", "expected `)` or identifier")
                .build(),
        );
        // 2 copies of the `,` error
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `,`")
                .exactly_one_underline_with_label(",", "expected `(`")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `)`")
                .exactly_one_underline_with_label(")", "expected `(`")
                .build(),
        );

        let src = r#"
            @hi mom("this should be invalid")
            permit(principal, action, resource);
        "#;
        let errs = assert_parse_fails(parse_policies, src);
        expect_n_errors(src, &errs, 2);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `mom`")
                .exactly_one_underline_with_label("mom", "expected `(`")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `\"this should be invalid\"`")
                .exactly_one_underline_with_label(
                    "\"this should be invalid\"",
                    "expected `)` or identifier",
                )
                .build(),
        );

        let src = r#"
            @hi+mom("this should be invalid")
            permit(principal, action, resource);
        "#;
        let errs = assert_parse_fails(parse_policies, src);
        expect_n_errors(src, &errs, 2);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `+`")
                .exactly_one_underline_with_label("+", "expected `(`")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("unexpected token `\"this should be invalid\"`")
                .exactly_one_underline_with_label(
                    "\"this should be invalid\"",
                    "expected `)` or identifier",
                )
                .build(),
        );
    }

    #[test]
    fn parse_idempotent() {
        let many_policies =
            std::fs::read_to_string("src/parser/testfiles/policies.cedar").expect("missing file");
        let cst1 = assert_parse_succeeds(parse_policies, &many_policies);
        let revert = format!("{}", cst1);
        let cst2 = assert_parse_succeeds(parse_policies, &revert);
        assert_eq!(cst1, cst2);
    }
}
