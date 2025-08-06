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

use std::{collections::BTreeMap, sync::Arc};

use cedar_policy_core::ast::{Expr, ExprKind, Literal, Var};

use crate::policy::TypeInferenceContext;
use crate::policy::{
    cedar::{Attribute, CedarTypeKind},
    DocumentContext, GetType,
};

mod attr;
mod binary;
mod is;

pub(crate) use attr::*;
pub(crate) use binary::*;
pub(crate) use is::*;

/// Contains information about an expression whose properties might be accessed.
///
/// This context keeps track of the expression being accessed (the "receiver"),
/// providing information for determining what attributes or types might be
/// available on that expression.
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct ReceiverContext {
    /// The expression whose attributes are being accessed.
    ///
    /// Common receivers include `principal`, `resource`, and `context`, but can also be
    /// more complex expressions that evaluate to an entity or record.
    receiver: Arc<Expr>,
}

impl ReceiverContext {
    #[must_use]
    pub(crate) fn new(receiver: Arc<Expr>) -> Self {
        Self { receiver }
    }
}

impl GetType for ReceiverContext {
    fn get_type(&self, cx: &DocumentContext<'_>) -> Option<CedarTypeKind> {
        self.receiver.expr_kind().get_type(cx)
    }

    fn get_type_with_cx(&self, cx: &mut TypeInferenceContext<'_>) -> Option<CedarTypeKind> {
        self.receiver.expr_kind().get_type_with_cx(cx)
    }
}

impl GetType for ExprKind {
    fn get_type(&self, cx: &DocumentContext<'_>) -> Option<CedarTypeKind> {
        match self {
            Self::Lit(literal) => literal.get_type(cx),
            Self::Var(var) => var.get_type(cx),
            Self::ExtensionFunctionApp { fn_name, .. } => {
                Some(CedarTypeKind::Extension(fn_name.clone()))
            }
            Self::GetAttr { expr, attr } | Self::HasAttr { expr, attr } => {
                let ty = expr.expr_kind().get_type(cx);
                ty.and_then(|ty| ty.attribute_type(attr, cx.schema()))
            }
            Self::Record(fields) => {
                let mut record_fields = BTreeMap::new();
                for (key, value) in fields.iter() {
                    let value_type = value.expr_kind().get_type(cx);
                    let attr = Attribute::new(key.clone(), true, value_type);
                    record_fields.insert(key.clone(), attr);
                }
                Some(CedarTypeKind::Record(Arc::new(record_fields).into()))
            }
            Self::Set(exprs) => match exprs.first() {
                Some(first) => Some(CedarTypeKind::Set(Box::new(
                    first.expr_kind().get_type(cx)?,
                ))),
                None => Some(CedarTypeKind::EmptySet),
            },
            Self::Error { .. } => Some(CedarTypeKind::Error),
            _ => None,
        }
    }

    fn get_type_with_cx(&self, cx: &mut TypeInferenceContext<'_>) -> Option<CedarTypeKind> {
        match self {
            Self::Lit(literal) => literal
                .get_type_with_cx(cx)
                .inspect(|ty| cx.set_base_type(ty.clone())),
            Self::Var(var) => var
                .get_type_with_cx(cx)
                .inspect(|ty| cx.set_base_type(ty.clone())),
            Self::ExtensionFunctionApp { fn_name, .. } => {
                Some(CedarTypeKind::Extension(fn_name.clone()))
            }
            Self::GetAttr { expr, attr } | Self::HasAttr { expr, attr } => {
                let ty = expr.expr_kind().get_type_with_cx(cx);
                cx.add_attr(attr);
                ty.and_then(|ty| ty.attribute_type(attr, cx.document_context.schema()))
            }
            Self::Record(fields) => {
                let mut record_fields = BTreeMap::new();
                for (key, value) in fields.iter() {
                    let value_type = value.expr_kind().get_type_with_cx(cx);
                    let attr = Attribute::new(key.clone(), true, value_type);
                    record_fields.insert(key.clone(), attr);
                }
                Some(CedarTypeKind::Record(Arc::new(record_fields).into()))
            }
            Self::Set(exprs) => match exprs.first() {
                Some(first) => Some(CedarTypeKind::Set(Box::new(
                    first.expr_kind().get_type_with_cx(cx)?,
                ))),
                None => Some(CedarTypeKind::EmptySet),
            },
            Self::Error { .. } => Some(CedarTypeKind::Error),
            _ => None,
        }
    }
}

impl GetType for Var {
    fn get_type(&self, cx: &DocumentContext<'_>) -> Option<CedarTypeKind> {
        let ty = match self {
            Self::Principal => CedarTypeKind::EntityType(cx.resolve_principal_type()),
            Self::Resource => CedarTypeKind::EntityType(cx.resolve_resource_type()),
            Self::Context => CedarTypeKind::Context(cx.resolve_context_type()),
            Self::Action => CedarTypeKind::Action,
        };
        Some(ty)
    }
}

impl GetType for Literal {
    fn get_type(&self, _cx: &DocumentContext<'_>) -> Option<CedarTypeKind> {
        Some(self.into())
    }
}
