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

use std::collections::BTreeMap;

use miette::{miette, Result, WrapErr};

use cedar_policy_core::ast::PolicySet;
use cedar_policy_core::parser::parse_policyset;
use cedar_policy_core::parser::text_to_cst::parse_policies;
use smol_str::ToSmolStr;

use super::lexer::get_token_stream;
use super::utils::remove_empty_lines;

use super::config::{self, Config};
use super::doc::*;

fn tree_to_pretty<T: Doc>(t: &T, context: &mut config::Context<'_>) -> Result<String> {
    let mut w = Vec::new();
    let config = context.config;
    let doc = t.to_doc(context);
    doc.ok_or(miette!("failed to produce doc"))?
        .render(config.line_width, &mut w)
        .map_err(|err| miette!(format!("failed to render doc: {err}")))?;
    String::from_utf8(w)
        .map_err(|err| miette!(format!("failed to convert rendered doc to string: {err}")))
}

fn soundness_check(ps: &str, ast: &PolicySet) -> Result<()> {
    let formatted_ast =
        parse_policyset(ps).wrap_err(format!("formatter produced an invalid policy set:\n{ps}"))?;
    let (formatted_policies, policies) = (
        formatted_ast
            .policies()
            .map(|p| (p.id().to_smolstr(), p))
            .collect::<BTreeMap<_, _>>(),
        ast.policies()
            .map(|p| (p.id().to_smolstr(), p))
            .collect::<BTreeMap<_, _>>(),
    );

    if formatted_policies.len() != policies.len() {
        return Err(miette!(
            "formatter changed the number of policies from {} to {}",
            policies.len(),
            formatted_policies.len()
        ));
    }
    for ((f_p_id, f_p), (p_id, p)) in formatted_policies.into_iter().zip(policies.into_iter()) {
        if f_p_id != p_id {
            return Err(miette!(
                "formatter changed the policy id from {p_id} to {f_p_id}"
            ));
        }
        let (f_anno, anno) = (
            f_p.annotations()
                .map(|(k, v)| (k, &v.val))
                .collect::<std::collections::BTreeMap<_, _>>(),
            p.annotations()
                .map(|(k, v)| (k, &v.val))
                .collect::<std::collections::BTreeMap<_, _>>(),
        );
        if f_anno != anno {
            return Err(miette!(
                "formatter changed the annotations from {anno:?} to {f_anno:?}"
            ));
        }
        if !(f_p.effect() == p.effect()
            && f_p.principal_constraint() == p.principal_constraint()
            && f_p.action_constraint() == p.action_constraint()
            && f_p.resource_constraint() == p.resource_constraint()
            && f_p
                .non_scope_constraints()
                .eq_shape(p.non_scope_constraints()))
        {
            return Err(miette!(
                "formatter changed the policy structure:\noriginal:\n{p}\nformatted:\n{f_p}"
            ));
        }
    }
    Ok(())
}

pub fn policies_str_to_pretty(ps: &str, config: &Config) -> Result<String> {
    let cst = parse_policies(ps).wrap_err("cannot parse input policies")?;
    let ast = cst.to_policyset().wrap_err("cannot parse input policies")?;
    let (tokens, end_of_file_comment) =
        get_token_stream(ps).ok_or(miette!("cannot get token stream"))?;
    let mut context = config::Context { config, tokens };
    let mut formatted_policies = cst
        .as_inner()
        .ok_or(miette!("fail to get input policy CST"))?
        .0
        .iter()
        .map(|p| Ok(remove_empty_lines(&tree_to_pretty(p, &mut context)?)))
        .collect::<Result<Vec<String>>>()?
        .join("\n\n");
    // handle comment at the end of a policyset
    if !end_of_file_comment.is_empty() {
        formatted_policies.push('\n');
        formatted_policies.push_str(&end_of_file_comment);
    }

    // add soundness check to make sure formatting doesn't alter policy ASTs
    soundness_check(&formatted_policies, &ast).wrap_err(
        "internal error: please file an issue at <https://github.com/cedar-policy/cedar/issues>",
    )?;
    Ok(formatted_policies)
}

#[cfg(test)]
mod tests {
    use insta::{assert_snapshot, glob, with_settings};
    use std::fs;

    use super::*;

    #[test]
    fn test_soundness_check() {
        let p1 = r#"permit (principal, action, resource)
        when { "
        
        a
        " };"#;
        let p2 = r#"permit (principal, action, resource)
        when { "
        a
        " };"#;
        assert!(soundness_check(p2, &parse_policyset(p1).unwrap()).is_err());

        let p1 = r#"
        permit (principal, action, resource)
        when { "a"};
        permit (principal, action, resource)
        when { "
        
        a
        " };"#;
        let p2 = r#"
        permit (principal, action, resource)
        when { "
        a
        " };
        permit (principal, action, resource)
        when { "a"};"#;
        assert!(soundness_check(p2, &parse_policyset(p1).unwrap()).is_err());

        let p1 = r#"
        permit (principal, action, resource)
        when { "a"   };
        permit (principal, action, resource)
        when { "b" };"#;
        let p2 = r#"
        permit (principal, action, resource)
        when { "a" };
        permit (principal, action, resource)
        when { "b"};"#;
        assert!(soundness_check(p2, &parse_policyset(p1).unwrap()).is_ok());
    }

    #[test]
    fn test_format_files() {
        let config = Config {
            line_width: 80,
            indent_width: 2,
        };

        // This test uses `insta` to test the current output of the formatter
        // against the output from prior versions. Run the test as usual with
        // `cargo test`.
        //
        // If it fails, then use `cargo insta review` to review the diff between
        // the current output and the snapshot. If the change is expected, you
        // can accept the changes to make `insta` update the snapshot which you
        // should the commit to the repository.
        //
        // Add new tests by placing a `.cedar` file in the test directory. The
        // next run of `cargo test` will fail. Use `cargo insta review` to check
        // the formatted output is expected.
        with_settings!(
            { snapshot_path => "../../tests/snapshots/" },
            {
                glob!("../../tests", "*.cedar", |path| {
                    let cedar_source = fs::read_to_string(path).unwrap();
                    let formatted = policies_str_to_pretty(&cedar_source, &config).unwrap();
                    assert_snapshot!(formatted);
                });
            }
        );

        // Also check the CLI sample files.
        with_settings!(
            { snapshot_path => "../../tests/cli-snapshots/" },
            {
                glob!("../../../cedar-policy-cli/sample-data", "**/*.cedar", |path| {
                    let cedar_source = fs::read_to_string(path).unwrap();
                    let formatted = policies_str_to_pretty(&cedar_source, &config).unwrap();
                    assert_snapshot!(formatted);
                });
            }
        )
    }
}
