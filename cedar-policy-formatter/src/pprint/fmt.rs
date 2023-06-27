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

use miette::{miette, Result, WrapErr};

use cedar_policy_core::ast::{PolicySet, Template};
use cedar_policy_core::parser::parse_policyset;
use cedar_policy_core::parser::{err::ParseErrors, text_to_cst::parse_policies};

use crate::token::get_comment;

use super::lexer::get_token_stream;
use super::utils::remove_empty_lines;

use super::config::{self, Config};
use super::doc::*;

fn tree_to_pretty<T: Doc>(t: &T, context: &mut config::Context<'_>) -> String {
    let mut w = Vec::new();
    let config = context.config;
    let doc = t.to_doc(context);
    doc.render(config.line_width, &mut w).unwrap();
    String::from_utf8(w).unwrap()
}

fn soundness_check(ps: &str, ast: &PolicySet) -> Result<()> {
    let formatted_ast = parse_policyset(ps)
        .map_err(ParseErrors)
        .wrap_err("formatter produces invalid policies")?;
    let (formatted_policies, policies) = (
        formatted_ast.templates().collect::<Vec<&Template>>(),
        ast.templates().collect::<Vec<&Template>>(),
    );

    if formatted_policies.len() != policies.len() {
        return Err(miette!("missing formatted policies"));
    }

    for (f_p, p) in formatted_policies.into_iter().zip(policies.into_iter()) {
        let (f_anno, anno) = (
            f_p.annotations()
                .collect::<std::collections::HashMap<_, _>>(),
            p.annotations().collect::<std::collections::HashMap<_, _>>(),
        );
        if !(f_anno == anno
            && f_p.effect() == p.effect()
            && f_p.principal_constraint() == p.principal_constraint()
            && f_p.action_constraint() == p.action_constraint()
            && f_p.resource_constraint() == p.resource_constraint()
            && f_p
                .non_head_constraints()
                .eq_shape(p.non_head_constraints()))
        {
            return Err(miette!(format!(
                "policies differ:\nformatted: {}\ninput: {}",
                f_p, p
            )));
        }
    }
    Ok(())
}

pub fn policies_str_to_pretty(ps: &str, config: &Config) -> Result<String> {
    let cst = parse_policies(ps)
        .map_err(ParseErrors)
        .wrap_err("cannot parse input policies to CSTs")?;
    let mut errs = Vec::new();
    let ast = cst
        .to_policyset(&mut errs)
        .ok_or(ParseErrors(errs))
        .wrap_err("cannot parse input policies to ASTs")?;
    let tokens = get_token_stream(ps);
    let end_comment_str = &ps[tokens.last().unwrap().span.end..];
    let mut context = config::Context { config, tokens };
    let mut formatted_policies = cst
        .as_inner()
        .unwrap()
        .0
        .iter()
        .map(|p| remove_empty_lines(tree_to_pretty(p, &mut context).trim()))
        .collect::<Vec<String>>()
        .join("\n\n");
    // handle comment at the end of a policyset
    let (trailing_comment, end_comment) = match end_comment_str.split_once('\n') {
        Some((f, r)) => (get_comment(f), get_comment(r)),
        None => (get_comment(end_comment_str), String::new()),
    };
    match (trailing_comment.as_ref(), end_comment.as_ref()) {
        ("", "") => {}
        (_, "") => {
            formatted_policies.push(' ');
            formatted_policies.push_str(&trailing_comment);
        }
        ("", _) => {
            formatted_policies.push('\n');
            formatted_policies.push_str(&end_comment);
        }
        _ => {
            formatted_policies.push(' ');
            formatted_policies.push_str(&trailing_comment);
            formatted_policies.push_str(&end_comment);
        }
    };
    // add soundness check to make sure formatting doesn't alter policy ASTs
    soundness_check(&formatted_policies, &ast)?;
    Ok(formatted_policies)
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_CONFIG: &Config = &Config {
        line_width: 40,
        indent_width: 2,
    };

    #[test]
    fn trivial_permit() {
        let policy = r#"permit (principal, action, resource);"#;
        assert_eq!(policies_str_to_pretty(policy, TEST_CONFIG).unwrap(), policy);
    }

    #[test]
    fn trivial_forbid() {
        let policy = r#"forbid (principal, action, resource);"#;
        assert_eq!(policies_str_to_pretty(policy, TEST_CONFIG).unwrap(), policy);
    }

    #[test]
    fn action_in_set() {
        let policy = r#"permit (
        principal in UserGroup::"abc",
        action in [Action::"viewPhoto", Action::"viewComments"],
        resource in Album::"one"
      );"#;
        assert_eq!(
            policies_str_to_pretty(policy, TEST_CONFIG).unwrap(),
            r#"permit (
  principal in UserGroup::"abc",
  action in
    [Action::"viewPhoto",
     Action::"viewComments"],
  resource in Album::"one"
);"#
        );
    }

    #[test]
    fn test_format_files() {
        use std::fs::read_to_string;
        use std::path::Path;

        let config = Config {
            line_width: 80,
            indent_width: 2,
        };
        let dir_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let pairs = vec![
            ("test.txt", "test_formatted.txt"),
            ("policies.txt", "policies_formatted.txt"),
        ];
        for (pf, ef) in pairs {
            // editors or cargo run try to append a newline at the end of files
            // we should remove them for equality testing
            assert_eq!(
                policies_str_to_pretty(&read_to_string(dir_path.join(pf)).unwrap(), &config)
                    .unwrap()
                    .trim_end_matches('\n'),
                read_to_string(dir_path.join(ef))
                    .unwrap()
                    .trim_end_matches('\n')
            );
        }
    }
}
