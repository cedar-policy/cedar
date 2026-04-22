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

use cedar_policy::{Policy, PolicySet, Template};
use clap::{Args, ValueEnum};
use miette::{miette, IntoDiagnostic, NamedSource, Report, Result, WrapErr};
use std::{path::Path, str::FromStr};

use crate::{add_template_links_to_set, read_from_file_or_stdin};

/// This struct contains the arguments that together specify an input policy or policy set.
#[derive(Args, Debug)]
pub struct PoliciesArgs {
    /// File containing the static Cedar policies and/or templates. If not provided, read policies from stdin.
    #[arg(short, long = "policies", value_name = "FILE")]
    pub policies_file: Option<String>,
    /// Format of policies in the `--policies` file
    #[arg(long = "policy-format", default_value_t, value_enum)]
    pub policy_format: PolicyFormat,
    /// File containing template-linked policies
    #[arg(short = 'k', long = "template-linked", value_name = "FILE")]
    pub template_linked_file: Option<String>,
}

impl PoliciesArgs {
    /// Turn this `PoliciesArgs` into the appropriate `PolicySet` object
    pub(crate) fn get_policy_set(&self) -> Result<PolicySet> {
        let mut pset = match self.policy_format {
            PolicyFormat::Cedar => read_cedar_policy_set(self.policies_file.as_ref()),
            PolicyFormat::Json => read_json_policy_set(self.policies_file.as_ref()),
        }?;
        if let Some(links_filename) = self.template_linked_file.as_ref() {
            add_template_links_to_set(links_filename, &mut pset)?;
        }
        Ok(pset)
    }
}

/// This struct contains the arguments that together specify an input policy or policy set,
/// for commands where policies are optional.
#[derive(Args, Debug)]
pub struct OptionalPoliciesArgs {
    /// File containing static Cedar policies and/or templates
    #[arg(short, long = "policies", value_name = "FILE")]
    pub policies_file: Option<String>,
    /// Format of policies in the `--policies` file
    #[arg(long = "policy-format", default_value_t, value_enum)]
    pub policy_format: PolicyFormat,
    /// File containing template-linked policies. Ignored if `--policies` is not
    /// present (because in that case there are no templates to link against)
    #[arg(short = 'k', long = "template-linked", value_name = "FILE")]
    pub template_linked_file: Option<String>,
}

impl OptionalPoliciesArgs {
    /// Turn this `OptionalPoliciesArgs` into the appropriate `PolicySet`
    /// object, or `None` if no policies were provided
    pub(crate) fn get_policy_set(&self) -> Result<Option<PolicySet>> {
        match &self.policies_file {
            None => Ok(None),
            Some(policies_file) => {
                let pargs = PoliciesArgs {
                    policies_file: Some(policies_file.clone()),
                    policy_format: self.policy_format,
                    template_linked_file: self.template_linked_file.clone(),
                };
                pargs.get_policy_set().map(Some)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum PolicyFormat {
    /// The standard Cedar policy format, documented at <https://docs.cedarpolicy.com/policies/syntax-policy.html>
    #[default]
    Cedar,
    /// Cedar's JSON policy format, documented at <https://docs.cedarpolicy.com/policies/json-format.html>
    Json,
}

/// Read a policy set, in Cedar syntax, from the file given in `filename`,
/// or from stdin if `filename` is `None`.
pub(crate) fn read_cedar_policy_set(
    filename: Option<impl AsRef<Path> + std::marker::Copy>,
) -> Result<PolicySet> {
    let context = "policy set";
    let ps_str = read_from_file_or_stdin(filename.as_ref(), context)?;
    let ps = PolicySet::from_str(&ps_str)
        .map_err(|err| {
            let name = filename.map_or_else(
                || "<stdin>".to_owned(),
                |n| n.as_ref().display().to_string(),
            );
            Report::new(err).with_source_code(NamedSource::new(name, ps_str))
        })
        .wrap_err_with(|| format!("failed to parse {context}"))?;
    rename_from_id_annotation(&ps)
}

/// Read a policy set, static policy or policy template, in Cedar JSON (EST) syntax, from the file given
/// in `filename`, or from stdin if `filename` is `None`.
pub(crate) fn read_json_policy_set(
    filename: Option<impl AsRef<Path> + std::marker::Copy>,
) -> Result<PolicySet> {
    let context = "JSON policy";
    let json_source = read_from_file_or_stdin(filename.as_ref(), context)?;
    let json = serde_json::from_str::<serde_json::Value>(&json_source).into_diagnostic()?;
    let policy_type = get_json_policy_type(&json)?;

    let add_json_source = |report: Report| {
        let name = filename.map_or_else(
            || "<stdin>".to_owned(),
            |n| n.as_ref().display().to_string(),
        );
        report.with_source_code(NamedSource::new(name, json_source.clone()))
    };

    match policy_type {
        JsonPolicyType::SinglePolicy => match Policy::from_json(None, json.clone()) {
            Ok(policy) => PolicySet::from_policies([policy])
                .wrap_err_with(|| format!("failed to create policy set from {context}")),
            Err(_) => match Template::from_json(None, json)
                .map_err(|err| add_json_source(Report::new(err)))
            {
                Ok(template) => {
                    let mut ps = PolicySet::new();
                    ps.add_template(template)?;
                    Ok(ps)
                }
                Err(err) => Err(err).wrap_err_with(|| format!("failed to parse {context}")),
            },
        },
        JsonPolicyType::PolicySet => PolicySet::from_json_value(json)
            .map_err(|err| add_json_source(Report::new(err)))
            .wrap_err_with(|| format!("failed to create policy set from {context}")),
    }
}

fn get_json_policy_type(json: &serde_json::Value) -> Result<JsonPolicyType> {
    let policy_set_properties = ["staticPolicies", "templates", "templateLinks"];
    let policy_properties = ["action", "effect", "principal", "resource", "conditions"];

    let json_has_property = |p| json.get(p).is_some();
    let has_any_policy_set_property = policy_set_properties.iter().any(json_has_property);
    let has_any_policy_property = policy_properties.iter().any(json_has_property);

    match (has_any_policy_set_property, has_any_policy_property) {
        (false, false) => Err(miette!("cannot determine if json policy is a single policy or a policy set. Found no matching properties from either format")),
        (true, true) => Err(miette!("cannot determine if json policy is a single policy or a policy set. Found matching properties from both formats")),
        (true, _) => Ok(JsonPolicyType::PolicySet),
        (_, true) => Ok(JsonPolicyType::SinglePolicy),
    }
}

enum JsonPolicyType {
    SinglePolicy,
    PolicySet,
}

/// Renames policies and templates based on (@id("new_id") annotation.
/// If no such annotation exists, it keeps the current id.
///
/// This will rename template-linked policies to the id of their template, which may
/// cause id conflicts, so only call this function before instancing
/// templates into the policy set.
fn rename_from_id_annotation(ps: &PolicySet) -> Result<PolicySet> {
    let mut new_ps = PolicySet::new();
    let t_iter = ps.templates().map(|t| match t.annotation("id") {
        None => Ok(t.clone()),
        Some(anno) => anno.parse().map(|a| t.new_id(a)),
    });
    for t in t_iter {
        let template = t.unwrap_or_else(|never| match never {});
        new_ps
            .add_template(template)
            .wrap_err("failed to add template to policy set")?;
    }
    let p_iter = ps.policies().map(|p| match p.annotation("id") {
        None => Ok(p.clone()),
        Some(anno) => anno.parse().map(|a| p.new_id(a)),
    });
    for p in p_iter {
        let policy = p.unwrap_or_else(|never| match never {});
        new_ps
            .add(policy)
            .wrap_err("failed to add template to policy set")?;
    }
    Ok(new_ps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{render_err, TEMPFILE_FILTER};
    use std::io::Write;

    #[test]
    fn cedar_policy_from_file_parse_error() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"not a valid policy").unwrap();
        let err = read_cedar_policy_set(Some(f.path())).unwrap_err();
        insta::with_settings!({filters => vec![TEMPFILE_FILTER]}, {
            insta::assert_snapshot!(render_err(&err), @r"
             × failed to parse policy set
             ╰─▶ unexpected token `a`
              ╭────
            1 │ not a valid policy
              ·     ┬
              ·     ╰── expected `(`
              ╰────
            ");
        });
    }

    #[test]
    fn json_policy_from_file_invalid_json() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"not json at all").unwrap();
        let err = read_json_policy_set(Some(f.path())).unwrap_err();
        insta::with_settings!({filters => vec![TEMPFILE_FILTER]}, {
            insta::assert_snapshot!(render_err(&err), @"  × expected ident at line 1 column 2");
        });
    }

    #[test]
    fn json_policy_from_file_bad_policy() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        // Valid JSON with policy properties, but invalid policy content —
        // hits the Template::from_json fallback and the wrap_err "failed to parse" path
        f.write_all(br#"{"effect":"permit","principal":{"op":"bogus"},"action":{"op":"All"},"resource":{"op":"All"},"conditions":[]}"#).unwrap();
        let err = read_json_policy_set(Some(f.path())).unwrap_err();
        insta::with_settings!({filters => vec![TEMPFILE_FILTER]}, {
            insta::assert_snapshot!(render_err(&err), @r#"
            × failed to parse JSON policy
            ├─▶ error deserializing a policy/template from JSON
            ╰─▶ unknown variant `bogus`, expected one of `All`, `all`, `==`, `in`, `is`
            "#);
        });
    }
}
