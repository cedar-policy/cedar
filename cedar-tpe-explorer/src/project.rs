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

//! Loading a schema and policy set.

use cedar_policy::{Policy, PolicyId, PolicySet, Schema};
use cedar_policy_core::ast;
use smol_str::SmolStr;
use std::collections::BTreeSet;
use std::str::FromStr;

/// Error loading a [`Project`].
#[derive(Debug, thiserror::Error)]
pub enum ProjectError {
    #[error("schema: {0}")]
    Schema(String),
    #[error("policies: {0}")]
    Policies(String),
}

/// A policy in the project, in source order.
#[derive(Debug, Clone)]
pub struct PolicyInfo {
    /// Policy id: the `@id` annotation if present, otherwise `policyN`.
    pub id: ast::PolicyID,
    pub effect: ast::Effect,
    /// Original source text of this policy.
    pub source: String,
}

/// A schema and the policies being explored.
#[derive(Debug, Clone)]
pub struct Project {
    pub schema: Schema,
    pub schema_src: String,
    pub policies_src: String,
    pub policy_set: PolicySet,
    pub policies: Vec<PolicyInfo>,
}

impl Project {
    /// Parse a Cedar schema (human-readable or JSON) and a policy set.
    pub fn new(schema_src: &str, policies_src: &str) -> Result<Self, ProjectError> {
        let schema = parse_schema(schema_src)?;
        let parsed = PolicySet::from_str(policies_src)
            .map_err(|e| ProjectError::Policies(format_located(&e, policies_src)))?;
        if parsed.templates().next().is_some() {
            return Err(ProjectError::Policies(
                "templates are not supported by partial evaluation".into(),
            ));
        }
        // Rename policies using their `@id` annotation, preserving source order.
        let mut originals: Vec<Policy> = parsed.policies().cloned().collect();
        originals.sort_by_key(|p| p.as_ref().loc().map(|l| l.start()).unwrap_or(usize::MAX));
        let mut policy_set = PolicySet::new();
        let mut policies = Vec::new();
        for p in originals {
            let id = p
                .annotation("id")
                .map(PolicyId::new)
                .unwrap_or_else(|| p.id().clone());
            let source = p
                .as_ref()
                .loc()
                .and_then(|l| policies_src.get(l.start()..l.end()))
                .map(str::to_string)
                .unwrap_or_else(|| p.to_string());
            let renamed = p.new_id(id.clone());
            policy_set
                .add(renamed.clone())
                .map_err(|e| ProjectError::Policies(format_miette(&e)))?;
            policies.push(PolicyInfo {
                id: <PolicyId as AsRef<ast::PolicyID>>::as_ref(&id).clone(),
                effect: renamed.as_ref().effect(),
                source,
            });
        }
        // Validate so that residual analysis can rely on well-typed policies.
        let validator = cedar_policy::Validator::new(schema.clone());
        let result = validator.validate(&policy_set, cedar_policy::ValidationMode::Strict);
        if !result.validation_passed() {
            let msgs: Vec<String> = result
                .validation_errors()
                .map(|e| format_located(e, policies_src))
                .collect();
            return Err(ProjectError::Policies(msgs.join("\n")));
        }
        Ok(Self {
            schema,
            schema_src: schema_src.to_string(),
            policies_src: policies_src.to_string(),
            policy_set,
            policies,
        })
    }

    /// The core validator schema.
    pub fn vschema(&self) -> &cedar_policy_core::validator::ValidatorSchema {
        self.schema.as_ref()
    }

    /// String literals and entity uids that appear in the policies.
    pub fn literals(&self) -> (BTreeSet<SmolStr>, BTreeSet<ast::EntityUID>) {
        let mut strings = BTreeSet::new();
        let mut uids = BTreeSet::new();
        for p in self.policy_set.policies() {
            let cond = p.as_ref().condition();
            for e in cond.subexpressions() {
                if let ast::ExprKind::Lit(lit) = e.expr_kind() {
                    match lit {
                        ast::Literal::String(s) => {
                            strings.insert(s.clone());
                        }
                        ast::Literal::EntityUID(u) => {
                            uids.insert(u.as_ref().clone());
                        }
                        _ => {}
                    }
                }
            }
        }
        (strings, uids)
    }

    /// Literal tag keys the policies test with `getTag`/`hasTag`.
    pub fn tag_keys(&self) -> BTreeSet<SmolStr> {
        let mut keys = BTreeSet::new();
        for p in self.policy_set.policies() {
            for e in p.as_ref().condition().subexpressions() {
                if let ast::ExprKind::BinaryApp {
                    op: ast::BinaryOp::GetTag | ast::BinaryOp::HasTag,
                    arg2,
                    ..
                } = e.expr_kind()
                {
                    if let ast::ExprKind::Lit(ast::Literal::String(k)) = arg2.expr_kind() {
                        keys.insert(k.clone());
                    }
                }
            }
        }
        keys
    }

    pub fn policy(&self, id: &ast::PolicyID) -> Option<&PolicyInfo> {
        self.policies.iter().find(|p| &p.id == id)
    }

    /// All actions declared in the schema, sorted.
    pub fn actions(&self) -> Vec<ast::EntityUID> {
        let mut v: Vec<_> = self
            .vschema()
            .action_ids()
            .map(|a| a.name().clone())
            .collect();
        v.sort();
        v
    }
}

fn parse_schema(src: &str) -> Result<Schema, ProjectError> {
    if src.trim_start().starts_with('{') {
        Schema::from_json_str(src).map_err(|e| ProjectError::Schema(format_miette(&e)))
    } else {
        Schema::from_cedarschema_str(src)
            .map(|(s, _warnings)| s)
            .map_err(|e| ProjectError::Schema(format_located(&e, src)))
    }
}

/// Like [`format_miette`], prefixed with `line L, column C:` for each
/// location the diagnostic points at in `src`. Also descends into related
/// diagnostics, which is where parsers put the individual errors.
pub(crate) fn format_located(e: &dyn miette::Diagnostic, src: &str) -> String {
    let mut parts = Vec::new();
    collect_located(e, src, &mut parts);
    if parts.is_empty() {
        format_miette(e)
    } else {
        parts.join("\n")
    }
}

fn collect_located(e: &dyn miette::Diagnostic, src: &str, out: &mut Vec<String>) {
    let mut related = e.related().into_iter().flatten().peekable();
    if related.peek().is_some() {
        for r in related {
            collect_located(r, src, out);
        }
        return;
    }
    let loc = e
        .labels()
        .into_iter()
        .flatten()
        .next()
        .map(|l| line_col(src, l.offset()));
    out.push(match loc {
        Some((line, col)) => format!("line {line}, column {col}: {}", format_miette(e)),
        None => format_miette(e),
    });
}

/// 1-based line and column of a byte offset.
pub fn line_col(src: &str, offset: usize) -> (usize, usize) {
    let before = src.get(..offset).unwrap_or(src);
    let line = before.matches('\n').count() + 1;
    let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
    (line, col)
}

pub(crate) fn format_miette(e: &dyn miette::Diagnostic) -> String {
    match e.help() {
        Some(help) => format!("{e} (help: {help})"),
        None => e.to_string(),
    }
}
