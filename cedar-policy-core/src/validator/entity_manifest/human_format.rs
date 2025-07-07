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

//! Human-readable format for entity manifests.

use std::collections::HashMap;

use crate::ast::{self, Expr, RequestType};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::{AccessDag, AccessTerm, AccessTermVariant, EntityManifest, RequestTypeTerms};
use crate::validator::ValidatorSchema;
// Import errors directly
use crate::validator::entity_manifest::errors::{ConversionError, PathExpressionParseError};

/// A human-readable format for entity manifests.
/// Currently used only for testing.
#[doc = include_str!("../../../experimental_warning.md")]
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HumanEntityManifest {
    /// A map from request types to lists of term expressions
    #[serde_as(as = "Vec<(_, _)>")]
    pub per_action: HashMap<RequestType, Vec<ExprStr>>,
}

/// Wrapper for [`ast::Expr`] that serializes to a string with the expr inside
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExprStr {
    /// The wrapped expression
    pub expr: ast::Expr,
}

impl ExprStr {
    pub fn new(expr: ast::Expr) -> Self {
        ExprStr { expr }
    }
}

impl Serialize for ExprStr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize the expression as a string
        serializer.serialize_str(&self.expr.to_string())
    }
}

impl<'de> Deserialize<'de> for ExprStr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize from a string by parsing it as a Cedar expression
        let expr_str = String::deserialize(deserializer)?;
        let expr = crate::parser::parse_expr(&expr_str)
            .map_err(|e| serde::de::Error::custom(format!("Failed to parse expression: {e}")))?;

        Ok(ExprStr { expr })
    }
}

impl From<ast::Expr> for ExprStr {
    fn from(expr: ast::Expr) -> Self {
        ExprStr { expr }
    }
}

impl Default for HumanEntityManifest {
    fn default() -> Self {
        Self::new()
    }
}

impl HumanEntityManifest {
    /// Create a new empty `HumanEntityManifest`
    pub fn new() -> Self {
        Self {
            per_action: HashMap::new(),
        }
    }

    /// Convert an AST Cedar expression to an `AccessTerm`
    pub(crate) fn expr_to_access_term(
        &self,
        expr: &ast::Expr,
        dag: &mut AccessDag,
    ) -> Result<AccessTerm, PathExpressionParseError> {
        match expr.expr_kind() {
            ast::ExprKind::Lit(lit) => {
                // Handle literal values
                match lit {
                    ast::Literal::EntityUID(euid) => {
                        Ok(dag.add_term(AccessTermVariant::Literal((**euid).clone())))
                    }
                    ast::Literal::String(s) => {
                        Ok(dag.add_term(AccessTermVariant::String(s.clone())))
                    }
                    _ => Err(PathExpressionParseError::InvalidRoot(
                        "Unsupported literal type".to_string(),
                    )),
                }
            }
            ast::ExprKind::Var(var) => {
                // Handle variables (principal, resource, action, context)
                Ok(dag.add_term(AccessTermVariant::Var(*var)))
            }
            ast::ExprKind::GetAttr { expr, attr } => {
                // Handle attribute access (e.g., principal.attr)
                let base_term = self.expr_to_access_term(expr, dag)?;
                Ok(dag.add_term(AccessTermVariant::Attribute {
                    of: base_term,
                    attr: attr.clone(),
                }))
            }
            ast::ExprKind::BinaryApp { op, arg1, arg2 } => match op {
                ast::BinaryOp::GetTag => {
                    // Handle tag access (e.g., principal.getTag("tag"))
                    let base_term = self.expr_to_access_term(arg1, dag)?;
                    let tag_term = self.expr_to_access_term(arg2, dag)?;
                    Ok(dag.add_term(AccessTermVariant::Tag {
                        of: base_term,
                        tag: tag_term,
                    }))
                }
                ast::BinaryOp::In => {
                    // Handle ancestor relationship (e.g., principal in resource)
                    let entity_term = self.expr_to_access_term(arg1, dag)?;
                    let ancestor_term = self.expr_to_access_term(arg2, dag)?;
                    Ok(dag.add_term(AccessTermVariant::Ancestor {
                        of: entity_term,
                        ancestor: ancestor_term,
                    }))
                }
                _ => Err(PathExpressionParseError::UnsupportedBinaryOperator {
                    operator: format!("{:?}", op),
                }),
            },
            _ => Err(PathExpressionParseError::UnsupportedExpressionType {
                expr_type: "unsupported expression type".to_string(),
            }),
        }
    }

    /// Convert this `HumanEntityManifest` to a DAG-based `EntityManifest`
    pub fn to_entity_manifest(
        &self,
        schema: &ValidatorSchema,
    ) -> Result<EntityManifest, ConversionError> {
        let mut manifest = EntityManifest::new();

        for (request_type, term_expressions) in &self.per_action {
            let mut terms_for_request_type = RequestTypeTerms::new(request_type.clone());

            for expr_str in term_expressions {
                let term =
                    self.expr_to_access_term(&expr_str.expr, &mut terms_for_request_type.dag)?;
                terms_for_request_type.access_terms.insert(term);
            }

            manifest
                .per_action
                .insert(request_type.clone(), terms_for_request_type);
        }

        // Add type annotations
        manifest.add_types(schema).map_err(|e| e.into())
    }

    /// Convert this `HumanEntityManifest` to a JSON string
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Create a `HumanEntityManifest` from a JSON string
    pub fn from_json_str(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl EntityManifest {
    /// Convert this `EntityManifest` to a human-readable format
    pub fn to_human_format(&self) -> HumanEntityManifest {
        let mut per_action = HashMap::new();

        for (request_type, terms_for_request_type) in &self.per_action {
            let mut term_expressions = Vec::new();

            for term in &terms_for_request_type.access_terms.terms {
                // PANIC SAFETY: these access terms come directly from the same manifest, so conversion succeeds
                #[allow(clippy::unwrap_used)]
                term_expressions.push(ExprStr::new(
                    self.access_term_to_expr(term, request_type).unwrap(),
                ));
            }

            per_action.insert(request_type.clone(), term_expressions);
        }

        HumanEntityManifest { per_action }
    }

    /// Convert an `AccessTerm` to a Cedar expression
    fn access_term_to_expr(
        &self,
        term: &AccessTerm,
        request_type: &RequestType,
    ) -> Result<ast::Expr, super::AccessTermNotFoundError> {
        // Find the terms for this request type
        if let Some(terms_for_request_type) = self.per_action.get(request_type) {
            term.to_expr(&terms_for_request_type.dag)
        } else {
            // return an error, you used an access term with the wrong request type
            Err(super::AccessTermNotFoundError { path_id: term.id })
        }
    }

    /// Convert this `EntityManifest` to a human-readable JSON string
    pub fn to_human_json_string(&self) -> Result<String, serde_json::Error> {
        let human = self.to_human_format();
        serde_json::to_string_pretty(&human)
    }

    /// Create an `EntityManifest` from a human-readable JSON string
    pub fn from_human_json_str(
        json: &str,
        schema: &ValidatorSchema,
    ) -> Result<Self, ConversionError> {
        let human: HumanEntityManifest = serde_json::from_str(json)?;
        human.to_entity_manifest(schema)
    }
}

impl AccessTerm {
    pub(crate) fn to_expr(
        &self,
        dag: &AccessDag,
    ) -> Result<ast::Expr, super::AccessTermNotFoundError> {
        // Find the variant for this term
        if let Some(variant) = dag.manifest_store.get(self.id) {
            Ok(match variant {
                AccessTermVariant::Literal(euid) => {
                    Expr::val(ast::Literal::EntityUID(std::sync::Arc::new(euid.clone())))
                }
                AccessTermVariant::Var(var) => Expr::var(*var),
                AccessTermVariant::String(s) => Expr::val(ast::Literal::String(s.clone())),
                AccessTermVariant::Attribute { of, attr } => {
                    let base_expr = of.to_expr(dag)?;
                    Expr::get_attr(base_expr, attr.clone())
                }
                AccessTermVariant::Tag { of, tag } => {
                    let base_expr = of.to_expr(dag)?;
                    let tag_expr = tag.to_expr(dag)?;
                    Expr::get_tag(base_expr, tag_expr)
                }
                AccessTermVariant::Ancestor { of, ancestor } => {
                    // For ancestor relationships, use the in keyword
                    let ancestor_expr = ancestor.to_expr(dag)?;
                    let entity_expr = of.to_expr(dag)?;
                    Expr::is_in(entity_expr, ancestor_expr)
                }
            })
        } else {
            // return an error, you used an access term with the wrong entity manifest
            Err(super::AccessTermNotFoundError { path_id: self.id })
        }
    }
}
