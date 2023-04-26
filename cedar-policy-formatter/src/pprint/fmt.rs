use cedar_policy_core::ast::{PolicySet, Template};
use cedar_policy_core::parser::parse_policyset;
use cedar_policy_core::parser::{err::ParseErrors, text_to_cst::parse_policies};
use anyhow::{anyhow, Context, Result};

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
        .context("formatter produces invalid policies")?;
    let (formatted_policies, policies) = (
        formatted_ast.templates().collect::<Vec<&Template>>(),
        ast.templates().collect::<Vec<&Template>>(),
    );

    if formatted_policies.len() != policies.len() {
        return Err(anyhow!("missing formatted policies"));
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
            return Err(anyhow!(format!(
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
        .context("cannot parse input policies to CSTs")?;
    let mut errs = Vec::new();
    let ast = cst
        .to_policyset(&mut errs)
        .ok_or(ParseErrors(errs))
        .context("cannot parse input policies to ASTs")?;
    let tokens = get_token_stream(ps);
    let mut context = config::Context { config, tokens };
    let formatted_policies = cst
        .as_inner()
        .unwrap()
        .0
        .iter()
        .map(|p| remove_empty_lines(tree_to_pretty(p, &mut context).trim()))
        .collect::<Vec<String>>()
        .join("\n\n");
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
            assert_eq!(
                policies_str_to_pretty(&read_to_string(dir_path.join(pf)).unwrap(), &config)
                    .unwrap(),
                read_to_string(dir_path.join(ef))
                    .unwrap()
                    // editors or cargo run try to append a newline at the end of files
                    // we should remove them for equality testing
                    .trim_end_matches('\n')
            );
        }
    }
}
