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

use super::utils::unwrap_or_clone;
use super::FromJsonError;
use crate::ast::InputInteger;
use crate::entities::{
    CedarValueJson, EscapeKind, FnAndArg, JsonDeserializationError,
    JsonDeserializationErrorContext, TypeAndId,
};
use crate::extensions::Extensions;
use crate::parser::cst::{self, Ident};
use crate::parser::err::{ParseErrors, ToASTError, ToASTErrorKind};
use crate::parser::{unescape, Loc, Node};
use crate::{ast, FromNormalizedStr};
use either::Either;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;
use std::collections::HashMap;
use std::sync::Arc;

/// Serde JSON structure for a Cedar expression in the EST format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Expr {
    /// Any Cedar expression other than an extension function call.
    /// We try to match this first, see docs on #[serde(untagged)].
    ExprNoExt(ExprNoExt),
    /// If that didn't match (because the key is not one of the keys defined in
    /// `ExprNoExt`), we assume we have an extension function call, where the
    /// key is the name of an extension function or method.
    ExtFuncCall(ExtFuncCall),
}

/// Serde JSON structure for [any Cedar expression other than an extension
/// function call] in the EST format
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExprNoExt {
    /// Literal value (including anything that's legal to express in the
    /// attribute-value JSON format)
    Value(CedarValueJson),
    /// Var
    Var(ast::Var),
    /// Template slot
    Slot(ast::SlotId),
    /// Unknown (for partial evaluation)
    Unknown {
        /// Name of the unknown
        name: SmolStr,
    },
    /// `!`
    #[serde(rename = "!")]
    Not {
        /// Argument
        arg: Arc<Expr>,
    },
    /// `-`
    #[serde(rename = "neg")]
    Neg {
        /// Argument
        arg: Arc<Expr>,
    },
    /// `==`
    #[serde(rename = "==")]
    Eq {
        /// Left-hand argument
        left: Arc<Expr>,
        /// Right-hand argument
        right: Arc<Expr>,
    },
    /// `!=`
    #[serde(rename = "!=")]
    NotEq {
        /// Left-hand argument
        left: Arc<Expr>,
        /// Right-hand argument
        right: Arc<Expr>,
    },
    /// `in`
    #[serde(rename = "in")]
    In {
        /// Left-hand argument
        left: Arc<Expr>,
        /// Right-hand argument
        right: Arc<Expr>,
    },
    /// `<`
    #[serde(rename = "<")]
    Less {
        /// Left-hand argument
        left: Arc<Expr>,
        /// Right-hand argument
        right: Arc<Expr>,
    },
    /// `<=`
    #[serde(rename = "<=")]
    LessEq {
        /// Left-hand argument
        left: Arc<Expr>,
        /// Right-hand argument
        right: Arc<Expr>,
    },
    /// `>`
    #[serde(rename = ">")]
    Greater {
        /// Left-hand argument
        left: Arc<Expr>,
        /// Right-hand argument
        right: Arc<Expr>,
    },
    /// `>=`
    #[serde(rename = ">=")]
    GreaterEq {
        /// Left-hand argument
        left: Arc<Expr>,
        /// Right-hand argument
        right: Arc<Expr>,
    },
    /// `&&`
    #[serde(rename = "&&")]
    And {
        /// Left-hand argument
        left: Arc<Expr>,
        /// Right-hand argument
        right: Arc<Expr>,
    },
    /// `||`
    #[serde(rename = "||")]
    Or {
        /// Left-hand argument
        left: Arc<Expr>,
        /// Right-hand argument
        right: Arc<Expr>,
    },
    /// `+`
    #[serde(rename = "+")]
    Add {
        /// Left-hand argument
        left: Arc<Expr>,
        /// Right-hand argument
        right: Arc<Expr>,
    },
    /// `-`
    #[serde(rename = "-")]
    Sub {
        /// Left-hand argument
        left: Arc<Expr>,
        /// Right-hand argument
        right: Arc<Expr>,
    },
    /// `*`
    #[serde(rename = "*")]
    Mul {
        /// Left-hand argument
        left: Arc<Expr>,
        /// Right-hand argument
        right: Arc<Expr>,
    },
    /// `contains()`
    #[serde(rename = "contains")]
    Contains {
        /// Left-hand argument (receiver)
        left: Arc<Expr>,
        /// Right-hand argument (inside the `()`)
        right: Arc<Expr>,
    },
    /// `containsAll()`
    #[serde(rename = "containsAll")]
    ContainsAll {
        /// Left-hand argument (receiver)
        left: Arc<Expr>,
        /// Right-hand argument (inside the `()`)
        right: Arc<Expr>,
    },
    /// `containsAny()`
    #[serde(rename = "containsAny")]
    ContainsAny {
        /// Left-hand argument (receiver)
        left: Arc<Expr>,
        /// Right-hand argument (inside the `()`)
        right: Arc<Expr>,
    },
    /// Get-attribute
    #[serde(rename = ".")]
    GetAttr {
        /// Left-hand argument
        left: Arc<Expr>,
        /// Attribute name
        attr: SmolStr,
    },
    /// `has`
    #[serde(rename = "has")]
    HasAttr {
        /// Left-hand argument
        left: Arc<Expr>,
        /// Attribute name
        attr: SmolStr,
    },
    /// `like`
    #[serde(rename = "like")]
    Like {
        /// Left-hand argument
        left: Arc<Expr>,
        /// Pattern
        pattern: SmolStr,
    },
    /// `<entity> is <entity_type> in <entity_or_entity_set> `
    #[serde(rename = "is")]
    Is {
        /// Left-hand entity argument
        left: Arc<Expr>,
        /// Entity type
        entity_type: SmolStr,
        /// Entity or entity set
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "in")]
        in_expr: Option<Arc<Expr>>,
    },
    /// Ternary
    #[serde(rename = "if-then-else")]
    If {
        /// Condition
        #[serde(rename = "if")]
        cond_expr: Arc<Expr>,
        /// `then` expression
        #[serde(rename = "then")]
        then_expr: Arc<Expr>,
        /// `else` expression
        #[serde(rename = "else")]
        else_expr: Arc<Expr>,
    },
    /// Set literal, whose elements may be arbitrary expressions
    /// (which is why we need this case specifically and can't just
    /// use Expr::Value)
    Set(Vec<Expr>),
    /// Record literal, whose elements may be arbitrary expressions
    /// (which is why we need this case specifically and can't just
    /// use Expr::Value)
    Record(#[serde_as(as = "serde_with::MapPreventDuplicates<_,_>")] HashMap<SmolStr, Expr>),
}

/// Serde JSON structure for an extension function call in the EST format
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtFuncCall {
    /// maps the name of the function to a JSON list/array of the arguments.
    /// Note that for method calls, the method receiver is the first argument.
    /// For example, for `a.isInRange(b)`, the first argument is `a` and the
    /// second argument is `b`.
    ///
    /// INVARIANT: This map should always have exactly one k-v pair (not more or
    /// less), but we make it a map in order to get the correct JSON structure
    /// we want.
    #[serde(flatten)]
    #[serde_as(as = "serde_with::MapPreventDuplicates<_,_>")]
    call: HashMap<SmolStr, Vec<Expr>>,
}

#[allow(clippy::should_implement_trait)] // the names of arithmetic constructors alias with those of certain trait methods such as `add` of `std::ops::Add`
impl Expr {
    /// literal
    pub fn lit(lit: CedarValueJson) -> Self {
        Expr::ExprNoExt(ExprNoExt::Value(lit))
    }

    /// principal, action, resource, context
    pub fn var(var: ast::Var) -> Self {
        Expr::ExprNoExt(ExprNoExt::Var(var))
    }

    /// Template slots
    pub fn slot(slot: ast::SlotId) -> Self {
        Expr::ExprNoExt(ExprNoExt::Slot(slot))
    }

    /// Partial-evaluation unknowns
    pub fn unknown(name: impl Into<SmolStr>) -> Self {
        Expr::ExprNoExt(ExprNoExt::Unknown { name: name.into() })
    }

    /// `!`
    pub fn not(e: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::Not { arg: Arc::new(e) })
    }

    /// `-`
    pub fn neg(e: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::Neg { arg: Arc::new(e) })
    }

    /// `==`
    pub fn eq(left: Expr, right: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::Eq {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `!=`
    pub fn noteq(left: Expr, right: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::NotEq {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `in`
    pub fn _in(left: Expr, right: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::In {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `<`
    pub fn less(left: Expr, right: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::Less {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `<=`
    pub fn lesseq(left: Expr, right: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::LessEq {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `>`
    pub fn greater(left: Expr, right: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::Greater {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `>=`
    pub fn greatereq(left: Expr, right: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::GreaterEq {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `&&`
    pub fn and(left: Expr, right: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::And {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `||`
    pub fn or(left: Expr, right: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::Or {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `+`
    pub fn add(left: Expr, right: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::Add {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `-`
    pub fn sub(left: Expr, right: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::Sub {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `*`
    pub fn mul(left: Expr, right: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::Mul {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `left.contains(right)`
    pub fn contains(left: Arc<Expr>, right: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::Contains {
            left,
            right: Arc::new(right),
        })
    }

    /// `left.containsAll(right)`
    pub fn contains_all(left: Arc<Expr>, right: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::ContainsAll {
            left,
            right: Arc::new(right),
        })
    }

    /// `left.containsAny(right)`
    pub fn contains_any(left: Arc<Expr>, right: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::ContainsAny {
            left,
            right: Arc::new(right),
        })
    }

    /// `left.attr`
    pub fn get_attr(left: Expr, attr: SmolStr) -> Self {
        Expr::ExprNoExt(ExprNoExt::GetAttr {
            left: Arc::new(left),
            attr,
        })
    }

    /// `left has attr`
    pub fn has_attr(left: Expr, attr: SmolStr) -> Self {
        Expr::ExprNoExt(ExprNoExt::HasAttr {
            left: Arc::new(left),
            attr,
        })
    }

    /// `left like pattern`
    pub fn like(left: Expr, pattern: SmolStr) -> Self {
        Expr::ExprNoExt(ExprNoExt::Like {
            left: Arc::new(left),
            pattern,
        })
    }

    /// `left is entity_type`
    pub fn is_entity_type(left: Expr, entity_type: SmolStr) -> Self {
        Expr::ExprNoExt(ExprNoExt::Is {
            left: Arc::new(left),
            entity_type,
            in_expr: None,
        })
    }

    /// `left is entity_type in entity`
    pub fn is_entity_type_in(left: Expr, entity_type: SmolStr, entity: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::Is {
            left: Arc::new(left),
            entity_type,
            in_expr: Some(Arc::new(entity)),
        })
    }

    /// `if cond_expr then then_expr else else_expr`
    pub fn ite(cond_expr: Expr, then_expr: Expr, else_expr: Expr) -> Self {
        Expr::ExprNoExt(ExprNoExt::If {
            cond_expr: Arc::new(cond_expr),
            then_expr: Arc::new(then_expr),
            else_expr: Arc::new(else_expr),
        })
    }

    /// e.g. [1+2, !(context has department)]
    pub fn set(elements: Vec<Expr>) -> Self {
        Expr::ExprNoExt(ExprNoExt::Set(elements))
    }

    /// e.g. {foo: 1+2, bar: !(context has department)}
    pub fn record(map: HashMap<SmolStr, Expr>) -> Self {
        Expr::ExprNoExt(ExprNoExt::Record(map))
    }

    /// extension function call, including method calls
    pub fn ext_call(fn_name: SmolStr, args: Vec<Expr>) -> Self {
        Expr::ExtFuncCall(ExtFuncCall {
            call: [(fn_name, args)].into_iter().collect(),
        })
    }

    /// Consume the `Expr`, producing a string literal if it was a string literal, otherwise returns the literal in the `Err` variant.
    pub fn into_string_literal(self) -> Result<SmolStr, Self> {
        match self {
            Expr::ExprNoExt(ExprNoExt::Value(CedarValueJson::String(s))) => Ok(s),
            _ => Err(self),
        }
    }
}

impl Expr {
    /// Attempt to convert this `est::Expr` into an `ast::Expr`
    ///
    /// `id`: the ID of the policy this `Expr` belongs to, used only for reporting errors
    pub fn try_into_ast(self, id: ast::PolicyID) -> Result<ast::Expr, FromJsonError> {
        match self {
            Expr::ExprNoExt(ExprNoExt::Value(jsonvalue)) => jsonvalue
                .into_expr(|| JsonDeserializationErrorContext::Policy { id: id.clone() })
                .map(Into::into)
                .map_err(Into::into),
            Expr::ExprNoExt(ExprNoExt::Var(var)) => Ok(ast::Expr::var(var)),
            Expr::ExprNoExt(ExprNoExt::Slot(slot)) => Ok(ast::Expr::slot(slot)),
            Expr::ExprNoExt(ExprNoExt::Unknown { name }) => {
                Ok(ast::Expr::unknown(ast::Unknown::new_untyped(name)))
            }
            Expr::ExprNoExt(ExprNoExt::Not { arg }) => {
                Ok(ast::Expr::not((*arg).clone().try_into_ast(id)?))
            }
            Expr::ExprNoExt(ExprNoExt::Neg { arg }) => {
                Ok(ast::Expr::neg((*arg).clone().try_into_ast(id)?))
            }
            Expr::ExprNoExt(ExprNoExt::Eq { left, right }) => Ok(ast::Expr::is_eq(
                (*left).clone().try_into_ast(id.clone())?,
                (*right).clone().try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::NotEq { left, right }) => Ok(ast::Expr::noteq(
                (*left).clone().try_into_ast(id.clone())?,
                (*right).clone().try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::In { left, right }) => Ok(ast::Expr::is_in(
                (*left).clone().try_into_ast(id.clone())?,
                (*right).clone().try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::Less { left, right }) => Ok(ast::Expr::less(
                (*left).clone().try_into_ast(id.clone())?,
                (*right).clone().try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::LessEq { left, right }) => Ok(ast::Expr::lesseq(
                (*left).clone().try_into_ast(id.clone())?,
                (*right).clone().try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::Greater { left, right }) => Ok(ast::Expr::greater(
                (*left).clone().try_into_ast(id.clone())?,
                (*right).clone().try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::GreaterEq { left, right }) => Ok(ast::Expr::greatereq(
                (*left).clone().try_into_ast(id.clone())?,
                (*right).clone().try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::And { left, right }) => Ok(ast::Expr::and(
                (*left).clone().try_into_ast(id.clone())?,
                (*right).clone().try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::Or { left, right }) => Ok(ast::Expr::or(
                (*left).clone().try_into_ast(id.clone())?,
                (*right).clone().try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::Add { left, right }) => Ok(ast::Expr::add(
                (*left).clone().try_into_ast(id.clone())?,
                (*right).clone().try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::Sub { left, right }) => Ok(ast::Expr::sub(
                (*left).clone().try_into_ast(id.clone())?,
                (*right).clone().try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::Mul { left, right }) => {
                let left: ast::Expr = (*left).clone().try_into_ast(id.clone())?;
                let right: ast::Expr = (*right).clone().try_into_ast(id)?;
                let left_c = match left.expr_kind() {
                    ast::ExprKind::Lit(ast::Literal::Long(c)) => Some(c),
                    _ => None,
                };
                let right_c = match right.expr_kind() {
                    ast::ExprKind::Lit(ast::Literal::Long(c)) => Some(c),
                    _ => None,
                };
                match (left_c, right_c) {
                    (_, Some(c)) => Ok(ast::Expr::mul(left, *c)),
                    (Some(c), _) => Ok(ast::Expr::mul(right, *c)),
                    (None, None) => Err(FromJsonError::MultiplicationByNonConstant {
                        arg1: left,
                        arg2: right,
                    })?,
                }
            }
            Expr::ExprNoExt(ExprNoExt::Contains { left, right }) => Ok(ast::Expr::contains(
                (*left).clone().try_into_ast(id.clone())?,
                (*right).clone().try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::ContainsAll { left, right }) => Ok(ast::Expr::contains_all(
                (*left).clone().try_into_ast(id.clone())?,
                (*right).clone().try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::ContainsAny { left, right }) => Ok(ast::Expr::contains_any(
                (*left).clone().try_into_ast(id.clone())?,
                (*right).clone().try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::GetAttr { left, attr }) => {
                Ok(ast::Expr::get_attr((*left).clone().try_into_ast(id)?, attr))
            }
            Expr::ExprNoExt(ExprNoExt::HasAttr { left, attr }) => {
                Ok(ast::Expr::has_attr((*left).clone().try_into_ast(id)?, attr))
            }
            Expr::ExprNoExt(ExprNoExt::Like { left, pattern }) => {
                match unescape::to_pattern(&pattern) {
                    Ok(pattern) => Ok(ast::Expr::like((*left).clone().try_into_ast(id)?, pattern)),
                    Err(errs) => Err(FromJsonError::UnescapeError(errs)),
                }
            }
            Expr::ExprNoExt(ExprNoExt::Is {
                left,
                entity_type,
                in_expr,
            }) => ast::Name::from_normalized_str(entity_type.as_str())
                .map_err(FromJsonError::InvalidEntityType)
                .and_then(|entity_type_name| {
                    let left: ast::Expr = (*left).clone().try_into_ast(id.clone())?;
                    let is_expr = ast::Expr::is_entity_type(left.clone(), entity_type_name);
                    match in_expr {
                        // The AST doesn't have an `... is ... in ..` node, so
                        // we represent it as a conjunction of `is` and `in`.
                        Some(in_expr) => Ok(ast::Expr::and(
                            is_expr,
                            ast::Expr::is_in(left, (*in_expr).clone().try_into_ast(id)?),
                        )),
                        None => Ok(is_expr),
                    }
                }),
            Expr::ExprNoExt(ExprNoExt::If {
                cond_expr,
                then_expr,
                else_expr,
            }) => Ok(ast::Expr::ite(
                (*cond_expr).clone().try_into_ast(id.clone())?,
                (*then_expr).clone().try_into_ast(id.clone())?,
                (*else_expr).clone().try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::Set(elements)) => Ok(ast::Expr::set(
                elements
                    .into_iter()
                    .map(|el| el.try_into_ast(id.clone()))
                    .collect::<Result<Vec<_>, FromJsonError>>()?,
            )),
            Expr::ExprNoExt(ExprNoExt::Record(map)) => {
                // PANIC SAFETY: can't have duplicate keys here because the input was already a HashMap
                #[allow(clippy::expect_used)]
                Ok(ast::Expr::record(
                    map.into_iter()
                        .map(|(k, v)| Ok((k, v.try_into_ast(id.clone())?)))
                        .collect::<Result<HashMap<SmolStr, _>, FromJsonError>>()?,
                )
                .expect("can't have duplicate keys here because the input was already a HashMap"))
            }
            Expr::ExtFuncCall(ExtFuncCall { call }) => {
                match call.len() {
                    0 => Err(FromJsonError::MissingOperator),
                    1 => {
                        // PANIC SAFETY checked that `call.len() == 1`
                        #[allow(clippy::expect_used)]
                        let (fn_name, args) = call
                            .into_iter()
                            .next()
                            .expect("already checked that len was 1");
                        let fn_name = fn_name.parse().map_err(|errs| {
                            JsonDeserializationError::ParseEscape {
                                kind: EscapeKind::Extension,
                                value: fn_name.to_string(),
                                errs,
                            }
                        })?;
                        Ok(ast::Expr::call_extension_fn(
                            fn_name,
                            args.into_iter()
                                .map(|arg| arg.try_into_ast(id.clone()))
                                .collect::<Result<_, _>>()?,
                        ))
                    }
                    _ => Err(FromJsonError::MultipleOperators {
                        ops: call.into_keys().collect(),
                    }),
                }
            }
        }
    }
}

impl From<ast::Expr> for Expr {
    fn from(expr: ast::Expr) -> Expr {
        match expr.into_expr_kind() {
            ast::ExprKind::Lit(lit) => lit.into(),
            ast::ExprKind::Var(var) => var.into(),
            ast::ExprKind::Slot(slot) => slot.into(),
            ast::ExprKind::Unknown(ast::Unknown { name, .. }) => Expr::unknown(name),
            ast::ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => Expr::ite(
                unwrap_or_clone(test_expr).into(),
                unwrap_or_clone(then_expr).into(),
                unwrap_or_clone(else_expr).into(),
            ),
            ast::ExprKind::And { left, right } => {
                Expr::and(unwrap_or_clone(left).into(), unwrap_or_clone(right).into())
            }
            ast::ExprKind::Or { left, right } => {
                Expr::or(unwrap_or_clone(left).into(), unwrap_or_clone(right).into())
            }
            ast::ExprKind::UnaryApp { op, arg } => {
                let arg = unwrap_or_clone(arg).into();
                match op {
                    ast::UnaryOp::Not => Expr::not(arg),
                    ast::UnaryOp::Neg => Expr::neg(arg),
                }
            }
            ast::ExprKind::BinaryApp { op, arg1, arg2 } => {
                let arg1 = unwrap_or_clone(arg1).into();
                let arg2 = unwrap_or_clone(arg2).into();
                match op {
                    ast::BinaryOp::Eq => Expr::eq(arg1, arg2),
                    ast::BinaryOp::In => Expr::_in(arg1, arg2),
                    ast::BinaryOp::Less => Expr::less(arg1, arg2),
                    ast::BinaryOp::LessEq => Expr::lesseq(arg1, arg2),
                    ast::BinaryOp::Add => Expr::add(arg1, arg2),
                    ast::BinaryOp::Sub => Expr::sub(arg1, arg2),
                    ast::BinaryOp::Contains => Expr::contains(Arc::new(arg1), arg2),
                    ast::BinaryOp::ContainsAll => Expr::contains_all(Arc::new(arg1), arg2),
                    ast::BinaryOp::ContainsAny => Expr::contains_any(Arc::new(arg1), arg2),
                }
            }
            ast::ExprKind::MulByConst { arg, constant } => Expr::mul(
                unwrap_or_clone(arg).into(),
                Expr::lit(CedarValueJson::Long(constant as InputInteger)),
            ),
            ast::ExprKind::ExtensionFunctionApp { fn_name, args } => {
                let args = unwrap_or_clone(args).into_iter().map(Into::into).collect();
                Expr::ext_call(fn_name.to_string().into(), args)
            }
            ast::ExprKind::GetAttr { expr, attr } => {
                Expr::get_attr(unwrap_or_clone(expr).into(), attr)
            }
            ast::ExprKind::HasAttr { expr, attr } => {
                Expr::has_attr(unwrap_or_clone(expr).into(), attr)
            }
            ast::ExprKind::Like { expr, pattern } => {
                Expr::like(unwrap_or_clone(expr).into(), pattern.to_string().into())
            }
            ast::ExprKind::Is { expr, entity_type } => {
                Expr::is_entity_type(unwrap_or_clone(expr).into(), entity_type.to_string().into())
            }
            ast::ExprKind::Set(set) => {
                Expr::set(unwrap_or_clone(set).into_iter().map(Into::into).collect())
            }
            ast::ExprKind::Record(map) => Expr::record(
                unwrap_or_clone(map)
                    .into_iter()
                    .map(|(k, v)| (k, v.into()))
                    .collect(),
            ),
        }
    }
}

impl From<ast::Literal> for Expr {
    fn from(lit: ast::Literal) -> Expr {
        Expr::lit(CedarValueJson::from_lit(lit))
    }
}

impl From<ast::Var> for Expr {
    fn from(var: ast::Var) -> Expr {
        Expr::var(var)
    }
}

impl From<ast::SlotId> for Expr {
    fn from(slot: ast::SlotId) -> Expr {
        Expr::slot(slot)
    }
}

impl TryFrom<&Node<Option<cst::Expr>>> for Expr {
    type Error = ParseErrors;
    fn try_from(e: &Node<Option<cst::Expr>>) -> Result<Expr, ParseErrors> {
        match &*e.ok_or_missing()?.expr {
            cst::ExprData::Or(node) => node.try_into(),
            cst::ExprData::If(if_node, then_node, else_node) => {
                let cond_expr = if_node.try_into()?;
                let then_expr = then_node.try_into()?;
                let else_expr = else_node.try_into()?;
                Ok(Expr::ite(cond_expr, then_expr, else_expr))
            }
        }
    }
}

impl TryFrom<&Node<Option<cst::Or>>> for Expr {
    type Error = ParseErrors;
    fn try_from(o: &Node<Option<cst::Or>>) -> Result<Expr, ParseErrors> {
        let o_node = o.ok_or_missing()?;
        let mut expr = (&o_node.initial).try_into()?;
        for node in &o_node.extended {
            let rhs = node.try_into()?;
            expr = Expr::or(expr, rhs);
        }
        Ok(expr)
    }
}

impl TryFrom<&Node<Option<cst::And>>> for Expr {
    type Error = ParseErrors;
    fn try_from(a: &Node<Option<cst::And>>) -> Result<Expr, ParseErrors> {
        let a_node = a.ok_or_missing()?;
        let mut expr = (&a_node.initial).try_into()?;
        for node in &a_node.extended {
            let rhs = node.try_into()?;
            expr = Expr::and(expr, rhs);
        }
        Ok(expr)
    }
}

impl TryFrom<&Node<Option<cst::Relation>>> for Expr {
    type Error = ParseErrors;
    fn try_from(r: &Node<Option<cst::Relation>>) -> Result<Expr, ParseErrors> {
        match r.ok_or_missing()? {
            cst::Relation::Common { initial, extended } => {
                let mut expr = initial.try_into()?;
                for (op, node) in extended {
                    let rhs = node.try_into()?;
                    match op {
                        cst::RelOp::Eq => {
                            expr = Expr::eq(expr, rhs);
                        }
                        cst::RelOp::NotEq => {
                            expr = Expr::noteq(expr, rhs);
                        }
                        cst::RelOp::In => {
                            expr = Expr::_in(expr, rhs);
                        }
                        cst::RelOp::Less => {
                            expr = Expr::less(expr, rhs);
                        }
                        cst::RelOp::LessEq => {
                            expr = Expr::lesseq(expr, rhs);
                        }
                        cst::RelOp::Greater => {
                            expr = Expr::greater(expr, rhs);
                        }
                        cst::RelOp::GreaterEq => {
                            expr = Expr::greatereq(expr, rhs);
                        }
                    }
                }
                Ok(expr)
            }
            cst::Relation::Has { target, field } => {
                let target_expr = target.try_into()?;
                match Expr::try_from(field) {
                    Ok(field_expr) => {
                        let field_str = field_expr
                            .into_string_literal()
                            .map_err(|_| field.to_ast_err(ToASTErrorKind::HasNonLiteralRHS))?;
                        Ok(Expr::has_attr(target_expr, field_str))
                    }
                    Err(_) => match is_add_name(field.ok_or_missing()?) {
                        Some(name) => Ok(Expr::has_attr(target_expr, name.to_string().into())),
                        None => Err(field.to_ast_err(ToASTErrorKind::HasNonLiteralRHS).into()),
                    },
                }
            }
            cst::Relation::Like { target, pattern } => {
                let target_expr = target.try_into()?;
                let pat_expr: Expr = pattern.try_into()?;
                let pat_str = pat_expr.into_string_literal().map_err(|e| {
                    pattern.to_ast_err(ToASTErrorKind::InvalidPattern(
                        serde_json::to_string(&e).unwrap_or_else(|_| "<malformed est>".to_string()),
                    ))
                })?;
                Ok(Expr::like(target_expr, pat_str))
            }
            cst::Relation::IsIn {
                target,
                entity_type,
                in_entity,
            } => {
                let target = target.try_into()?;
                let type_str = entity_type.ok_or_missing()?.to_string().into();
                match in_entity {
                    Some(in_entity) => Ok(Expr::is_entity_type_in(
                        target,
                        type_str,
                        in_entity.try_into()?,
                    )),
                    None => Ok(Expr::is_entity_type(target, type_str)),
                }
            }
        }
    }
}

impl TryFrom<&Node<Option<cst::Add>>> for Expr {
    type Error = ParseErrors;
    fn try_from(a: &Node<Option<cst::Add>>) -> Result<Expr, ParseErrors> {
        let a_node = a.ok_or_missing()?;
        let mut expr = (&a_node.initial).try_into()?;
        for (op, node) in &a_node.extended {
            let rhs = node.try_into()?;
            match op {
                cst::AddOp::Plus => {
                    expr = Expr::add(expr, rhs);
                }
                cst::AddOp::Minus => {
                    expr = Expr::sub(expr, rhs);
                }
            }
        }
        Ok(expr)
    }
}

/// Returns `Some` if this is just a cst::Name. For example the
/// `foobar` in `context has foobar`
fn is_add_name(add: &cst::Add) -> Option<&cst::Name> {
    if add.extended.is_empty() {
        match &add.initial.node {
            Some(mult) => is_mult_name(mult),
            None => None,
        }
    } else {
        None
    }
}

/// Returns `Some` if this is just a cst::Name. For example the
/// `foobar` in `context has foobar`
fn is_mult_name(mult: &cst::Mult) -> Option<&cst::Name> {
    if mult.extended.is_empty() {
        match &mult.initial.node {
            Some(unary) => is_unary_name(unary),
            None => None,
        }
    } else {
        None
    }
}

/// Returns `Some` if this is just a cst::Name. For example the
/// `foobar` in `context has foobar`
fn is_unary_name(unary: &cst::Unary) -> Option<&cst::Name> {
    if unary.op.is_none() {
        match &unary.item.node {
            Some(mem) => is_mem_name(mem),
            None => None,
        }
    } else {
        None
    }
}

/// Returns `Some` if this is just a cst::Name. For example the
/// `foobar` in `context has foobar`
fn is_mem_name(mem: &cst::Member) -> Option<&cst::Name> {
    if mem.access.is_empty() {
        match &mem.item.node {
            Some(primary) => is_primary_name(primary),
            None => None,
        }
    } else {
        None
    }
}

/// Returns `Some` if this is just a cst::Name. For example the
/// `foobar` in `context has foobar`
fn is_primary_name(primary: &cst::Primary) -> Option<&cst::Name> {
    match primary {
        cst::Primary::Name(node) => node.node.as_ref(),
        _ => None,
    }
}

impl TryFrom<&Node<Option<cst::Mult>>> for Expr {
    type Error = ParseErrors;
    fn try_from(m: &Node<Option<cst::Mult>>) -> Result<Expr, ParseErrors> {
        let m_node = m.ok_or_missing()?;
        let mut expr = (&m_node.initial).try_into()?;
        for (op, node) in &m_node.extended {
            let rhs = node.try_into()?;
            match op {
                cst::MultOp::Times => {
                    expr = Expr::mul(expr, rhs);
                }
                cst::MultOp::Divide => {
                    return Err(node.to_ast_err(ToASTErrorKind::UnsupportedDivision).into())
                }
                cst::MultOp::Mod => {
                    return Err(node.to_ast_err(ToASTErrorKind::UnsupportedModulo).into())
                }
            }
        }
        Ok(expr)
    }
}

impl TryFrom<&Node<Option<cst::Unary>>> for Expr {
    type Error = ParseErrors;
    fn try_from(u: &Node<Option<cst::Unary>>) -> Result<Expr, ParseErrors> {
        let u_node = u.ok_or_missing()?;

        match u_node.op {
            Some(cst::NegOp::Bang(num_bangs)) => {
                let inner = (&u_node.item).try_into()?;
                match num_bangs {
                    0 => Ok(inner),
                    1 => Ok(Expr::not(inner)),
                    2 => Ok(Expr::not(Expr::not(inner))),
                    3 => Ok(Expr::not(Expr::not(Expr::not(inner)))),
                    4 => Ok(Expr::not(Expr::not(Expr::not(Expr::not(inner))))),
                    _ => Err(u
                        .to_ast_err(ToASTErrorKind::UnaryOpLimit(ast::UnaryOp::Not))
                        .into()),
                }
            }
            Some(cst::NegOp::Dash(0)) => Ok((&u_node.item).try_into()?),
            Some(cst::NegOp::Dash(mut num_dashes)) => {
                let inner = match &u_node.item.to_lit() {
                    Some(cst::Literal::Num(num))
                        if num
                            .checked_sub(1)
                            .map(|y| y == InputInteger::MAX as u64)
                            .unwrap_or(false) =>
                    {
                        num_dashes -= 1;
                        Expr::ExprNoExt(ExprNoExt::Value(CedarValueJson::Long(InputInteger::MIN)))
                    }
                    _ => (&u_node.item).try_into()?,
                };
                let inner = match inner {
                    Expr::ExprNoExt(ExprNoExt::Value(CedarValueJson::Long(n)))
                        if n != InputInteger::MIN =>
                    {
                        // collapse the negated literal into a single negative literal.
                        // Important for multiplication-by-constant to allow multiplication by negative constants.
                        num_dashes -= 1;
                        Expr::lit(CedarValueJson::Long(-n))
                    }
                    _ => inner,
                };
                match num_dashes {
                    0 => Ok(inner),
                    1 => Ok(Expr::neg(inner)),
                    2 => {
                        // not safe to collapse `--` to nothing
                        Ok(Expr::neg(Expr::neg(inner)))
                    }
                    3 => Ok(Expr::neg(Expr::neg(Expr::neg(inner)))),
                    4 => Ok(Expr::neg(Expr::neg(Expr::neg(Expr::neg(inner))))),
                    _ => Err(u
                        .to_ast_err(ToASTErrorKind::UnaryOpLimit(ast::UnaryOp::Neg))
                        .into()),
                }
            }
            Some(cst::NegOp::OverBang) => Err(u
                .to_ast_err(ToASTErrorKind::UnaryOpLimit(ast::UnaryOp::Not))
                .into()),
            Some(cst::NegOp::OverDash) => Err(u
                .to_ast_err(ToASTErrorKind::UnaryOpLimit(ast::UnaryOp::Neg))
                .into()),
            None => Ok((&u_node.item).try_into()?),
        }
    }
}

/// Convert the given `cst::Primary` into either a (possibly namespaced)
/// function name, or an `Expr`.
///
/// (Upstream, the case where the `Primary` is a function name needs special
/// handling, because in that case it is not a valid expression. In all other
/// cases a `Primary` can be converted into an `Expr`.)
fn interpret_primary(
    p: &Node<Option<cst::Primary>>,
) -> Result<Either<ast::Name, Expr>, ParseErrors> {
    match p.ok_or_missing()? {
        cst::Primary::Literal(lit) => Ok(Either::Right(lit.try_into()?)),
        cst::Primary::Ref(node) => match node.ok_or_missing()? {
            cst::Ref::Uid { path, eid } => {
                let mut errs = ParseErrors::new();
                let maybe_name = path.to_name(&mut errs);
                let maybe_eid = eid.as_valid_string(&mut errs);

                match (maybe_name, maybe_eid) {
                    (Some(name), Some(eid)) => {
                        Ok(Either::Right(Expr::lit(CedarValueJson::EntityEscape {
                            __entity: TypeAndId::from(ast::EntityUID::from_components(
                                name,
                                ast::Eid::new(eid.clone()),
                            )),
                        })))
                    }
                    _ => Err(errs),
                }
            }
            cst::Ref::Ref { .. } => Err(node
                .to_ast_err(ToASTErrorKind::UnsupportedEntityLiterals)
                .into()),
        },
        cst::Primary::Name(node) => {
            let name = node.ok_or_missing()?;
            let base_name = name.name.ok_or_missing()?;
            match (&name.path[..], base_name) {
                (&[], cst::Ident::Principal) => Ok(Either::Right(Expr::var(ast::Var::Principal))),
                (&[], cst::Ident::Action) => Ok(Either::Right(Expr::var(ast::Var::Action))),
                (&[], cst::Ident::Resource) => Ok(Either::Right(Expr::var(ast::Var::Resource))),
                (&[], cst::Ident::Context) => Ok(Either::Right(Expr::var(ast::Var::Context))),
                (path, cst::Ident::Ident(id)) => Ok(Either::Left(ast::Name::new(
                    id.parse()?,
                    path.iter()
                        .map(|node| {
                            node.ok_or_missing()
                                .map_err(Into::into)
                                .and_then(|id| id.to_string().parse().map_err(Into::into))
                        })
                        .collect::<Result<Vec<ast::Id>, ParseErrors>>()?,
                ))),
                (path, id) => {
                    let (l, r, src) = match (path.first(), path.last()) {
                        (Some(l), Some(r)) => (
                            l.loc.start(),
                            r.loc.end() + ident_to_str_len(id),
                            Arc::clone(&l.loc.src),
                        ),
                        (_, _) => (0, 0, Arc::from("")),
                    };
                    Err(ToASTError::new(
                        ToASTErrorKind::InvalidExpression(cst::Name {
                            path: path.to_vec(),
                            name: Node::with_source_loc(Some(id.clone()), node.loc.span(l..r)),
                        }),
                        Loc::new(l..r, src),
                    )
                    .into())
                }
            }
        }
        cst::Primary::Slot(node) => Ok(Either::Right(Expr::slot(
            node.ok_or_missing()?
                .try_into()
                .map_err(|e| node.to_ast_err(e))?,
        ))),
        cst::Primary::Expr(e) => Ok(Either::Right(e.try_into()?)),
        cst::Primary::EList(nodes) => nodes
            .iter()
            .map(|node| node.try_into())
            .collect::<Result<Vec<Expr>, _>>()
            .map(Expr::set)
            .map(Either::Right),
        cst::Primary::RInits(nodes) => nodes
            .iter()
            .map(|node| {
                let cst::RecInit(k, v) = node.ok_or_missing()?;
                let mut errs = ParseErrors::new();
                let s = k
                    .to_expr_or_special(&mut errs)
                    .and_then(|es| es.into_valid_attr(&mut errs));
                if !errs.is_empty() {
                    Err(errs)
                } else {
                    match s {
                        Some(s) => Ok((s, v.try_into()?)),
                        None => Err(node.to_ast_err(ToASTErrorKind::MissingNodeData).into()),
                    }
                }
            })
            .collect::<Result<HashMap<SmolStr, Expr>, ParseErrors>>()
            .map(Expr::record)
            .map(Either::Right),
    }
}

impl TryFrom<&Node<Option<cst::Member>>> for Expr {
    type Error = ParseErrors;
    fn try_from(m: &Node<Option<cst::Member>>) -> Result<Expr, ParseErrors> {
        let m_node = m.ok_or_missing()?;
        let mut item: Either<ast::Name, Expr> = interpret_primary(&m_node.item)?;
        for access in &m_node.access {
            match access.ok_or_missing()? {
                cst::MemAccess::Field(node) => match node.ok_or_missing()? {
                    cst::Ident::Ident(i) => {
                        item = match item {
                            Either::Left(name) => {
                                return Err(node
                                    .to_ast_err(ToASTErrorKind::InvalidAccess(name, i.clone()))
                                    .into())
                            }
                            Either::Right(expr) => Either::Right(Expr::get_attr(expr, i.clone())),
                        };
                    }
                    i => {
                        return Err(node
                            .to_ast_err(ToASTErrorKind::InvalidIdentifier(i.to_string()))
                            .into())
                    }
                },
                cst::MemAccess::Call(args) => {
                    // we have item(args).  We hope item is either:
                    //   - an `ast::Name`, in which case we have a standard function call
                    //   - or an expr of the form `x.y`, in which case y is the method
                    //      name and not a field name. In the previous iteration of the
                    //      `for` loop we would have made `item` equal to
                    //      `Expr::GetAttr(x, y)`. Now we have to undo that to make a
                    //      method call instead.
                    //   - any other expression: it's an illegal call as the target is a higher order expression
                    item = match item {
                        Either::Left(name) => Either::Right(Expr::ext_call(
                            name.to_string().into(),
                            args.iter()
                                .map(|node| node.try_into())
                                .collect::<Result<Vec<_>, _>>()?,
                        )),
                        Either::Right(Expr::ExprNoExt(ExprNoExt::GetAttr { left, attr })) => {
                            let args = args.iter().map(|node| node.try_into()).collect::<Result<
                                Vec<Expr>,
                                ParseErrors,
                            >>(
                            )?;
                            let args = args.into_iter();
                            match attr.as_str() {
                                "contains" => Either::Right(Expr::contains(
                                    left,
                                    extract_single_argument(args, "contains()", &access.loc)?,
                                )),
                                "containsAll" => Either::Right(Expr::contains_all(
                                    left,
                                    extract_single_argument(args, "containsAll()", &access.loc)?,
                                )),
                                "containsAny" => Either::Right(Expr::contains_any(
                                    left,
                                    extract_single_argument(args, "containsAny()", &access.loc)?,
                                )),
                                _ => {
                                    // have to add the "receiver" argument as
                                    // first in the list for the method call
                                    let mut args = args.collect::<Vec<_>>();
                                    args.insert(0, unwrap_or_clone(left));
                                    Either::Right(Expr::ext_call(attr, args))
                                }
                            }
                        }
                        _ => return Err(access.to_ast_err(ToASTErrorKind::ExpressionCall).into()),
                    };
                }
                cst::MemAccess::Index(node) => {
                    let s = Expr::try_from(node)?
                        .into_string_literal()
                        .map_err(|_| node.to_ast_err(ToASTErrorKind::NonStringIndex))?;
                    item = match item {
                        Either::Left(name) => {
                            return Err(node
                                .to_ast_err(ToASTErrorKind::InvalidIndex(name, s))
                                .into())
                        }
                        Either::Right(expr) => Either::Right(Expr::get_attr(expr, s)),
                    };
                }
            }
        }
        match item {
            Either::Left(_) => Err(m.to_ast_err(ToASTErrorKind::MembershipInvariantViolation))?,
            Either::Right(expr) => Ok(expr),
        }
    }
}

/// Return the single argument in `args` iterator, or return a wrong arity error
/// if the iterator has 0 elements or more than 1 element.
pub fn extract_single_argument<T>(
    args: impl ExactSizeIterator<Item = T>,
    fn_name: &'static str,
    loc: &Loc,
) -> Result<T, ToASTError> {
    let mut iter = args.fuse().peekable();
    let first = iter.next();
    let second = iter.peek();
    match (first, second) {
        (None, _) => Err(ToASTError::new(
            ToASTErrorKind::wrong_arity(fn_name, 1, 0),
            loc.clone(),
        )),
        (Some(_), Some(_)) => Err(ToASTError::new(
            ToASTErrorKind::wrong_arity(fn_name, 1, iter.len() + 1),
            loc.clone(),
        )),
        (Some(first), None) => Ok(first),
    }
}

impl TryFrom<&Node<Option<cst::Literal>>> for Expr {
    type Error = ParseErrors;
    fn try_from(lit: &Node<Option<cst::Literal>>) -> Result<Expr, ParseErrors> {
        match lit.ok_or_missing()? {
            cst::Literal::True => Ok(Expr::lit(CedarValueJson::Bool(true))),
            cst::Literal::False => Ok(Expr::lit(CedarValueJson::Bool(false))),
            cst::Literal::Num(n) => Ok(Expr::lit(CedarValueJson::Long(
                (*n).try_into()
                    .map_err(|_| lit.to_ast_err(ToASTErrorKind::IntegerLiteralTooLarge(*n)))?,
            ))),
            cst::Literal::Str(node) => match node.ok_or_missing()? {
                cst::Str::String(s) => Ok(Expr::lit(CedarValueJson::String(s.clone()))),
                cst::Str::Invalid(invalid_str) => Err(node
                    .to_ast_err(ToASTErrorKind::InvalidString(invalid_str.to_string()))
                    .into()),
            },
        }
    }
}

impl TryFrom<&Node<Option<cst::Name>>> for Expr {
    type Error = ParseErrors;
    fn try_from(name: &Node<Option<cst::Name>>) -> Result<Expr, ParseErrors> {
        let name_node = name.ok_or_missing()?;
        let base_name = name_node.name.ok_or_missing()?;
        match (&name_node.path[..], base_name) {
            (&[], cst::Ident::Principal) => Ok(Expr::var(ast::Var::Principal)),
            (&[], cst::Ident::Action) => Ok(Expr::var(ast::Var::Action)),
            (&[], cst::Ident::Resource) => Ok(Expr::var(ast::Var::Resource)),
            (&[], cst::Ident::Context) => Ok(Expr::var(ast::Var::Context)),
            (path, id) => {
                let loc = match (path.first(), path.last()) {
                    (Some(lnode), Some(rnode)) => {
                        let l = lnode.loc.start();
                        let r = rnode.loc.end() + ident_to_str_len(id);
                        Loc::new(l..r, Arc::clone(&lnode.loc.src))
                    }
                    (_, _) => Loc::new(0, Arc::from("")),
                };
                Err(name
                    .to_ast_err(ToASTErrorKind::InvalidExpression(cst::Name {
                        path: path.to_vec(),
                        name: Node::with_source_loc(Some(id.clone()), loc),
                    }))
                    .into())
            }
        }
    }
}

/// Get the string length of an `Ident`. Used to print the source location for error messages
fn ident_to_str_len(i: &Ident) -> usize {
    match i {
        Ident::Principal => 9,
        Ident::Action => 6,
        Ident::Resource => 8,
        Ident::Context => 7,
        Ident::True => 4,
        Ident::False => 5,
        Ident::Permit => 6,
        Ident::Forbid => 6,
        Ident::When => 4,
        Ident::Unless => 6,
        Ident::In => 2,
        Ident::Has => 3,
        Ident::Like => 4,
        Ident::If => 2,
        Ident::Then => 4,
        Ident::Else => 4,
        Ident::Ident(s) => s.len(),
        Ident::Invalid(s) => s.len(),
        Ident::Is => 2,
    }
}

impl std::fmt::Display for Expr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExprNoExt(e) => write!(f, "{e}"),
            Self::ExtFuncCall(e) => write!(f, "{e}"),
        }
    }
}

fn display_cedarvaluejson(f: &mut std::fmt::Formatter<'_>, v: &CedarValueJson) -> std::fmt::Result {
    match v {
        // Add parentheses around negative numeric literals otherwise
        // round-tripping fuzzer fails for expressions like `(-1)["a"]`.
        CedarValueJson::Long(n) if *n < 0 => write!(f, "({n})"),
        CedarValueJson::Long(n) => write!(f, "{n}"),
        CedarValueJson::Bool(b) => write!(f, "{b}"),
        CedarValueJson::String(s) => write!(f, "\"{}\"", s.escape_debug()),
        CedarValueJson::EntityEscape { __entity } => {
            match ast::EntityUID::try_from(__entity.clone()) {
                Ok(euid) => write!(f, "{euid}"),
                Err(e) => write!(f, "(invalid entity uid: {})", e),
            }
        }
        CedarValueJson::ExprEscape { __expr } => write!(f, "({__expr})"),
        CedarValueJson::ExtnEscape {
            __extn: FnAndArg { ext_fn, arg },
        } => {
            // search for the name and callstyle
            let style = Extensions::all_available().all_funcs().find_map(|f| {
                if &f.name().to_string() == ext_fn {
                    Some(f.style())
                } else {
                    None
                }
            });
            match style {
                Some(ast::CallStyle::MethodStyle) => {
                    display_cedarvaluejson(f, arg)?;
                    write!(f, ".{ext_fn}()")?;
                    Ok(())
                }
                Some(ast::CallStyle::FunctionStyle) | None => {
                    write!(f, "{ext_fn}(")?;
                    display_cedarvaluejson(f, arg)?;
                    write!(f, ")")?;
                    Ok(())
                }
            }
        }
        CedarValueJson::Set(v) => {
            write!(f, "[")?;
            for (i, val) in v.iter().enumerate() {
                display_cedarvaluejson(f, val)?;
                if i < (v.len() - 1) {
                    write!(f, ", ")?;
                }
            }
            write!(f, "]")?;
            Ok(())
        }
        CedarValueJson::Record(m) => {
            write!(f, "{{")?;
            for (i, (k, v)) in m.iter().enumerate() {
                write!(f, "\"{}\": ", k.escape_debug())?;
                display_cedarvaluejson(f, v)?;
                if i < (m.len() - 1) {
                    write!(f, ", ")?;
                }
            }
            write!(f, "}}")?;
            Ok(())
        }
    }
}

impl std::fmt::Display for ExprNoExt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            ExprNoExt::Value(v) => display_cedarvaluejson(f, v),
            ExprNoExt::Var(v) => write!(f, "{v}"),
            ExprNoExt::Slot(id) => write!(f, "{id}"),
            ExprNoExt::Unknown { name } => write!(f, "unknown(\"{}\")", name.escape_debug()),
            ExprNoExt::Not { arg } => write!(f, "!{}", maybe_with_parens(arg)),
            ExprNoExt::Neg { arg } => {
                // Always add parentheses instead of calling
                // `maybe_with_parens`.
                // This makes sure that we always get a negation operation back
                // (as opposed to e.g., a negative number) when parsing the
                // printed form, thus preserving the round-tripping property.
                write!(f, "-({arg})")
            }
            ExprNoExt::Eq { left, right } => write!(
                f,
                "{} == {}",
                maybe_with_parens(left),
                maybe_with_parens(right)
            ),
            ExprNoExt::NotEq { left, right } => write!(
                f,
                "{} != {}",
                maybe_with_parens(left),
                maybe_with_parens(right)
            ),
            ExprNoExt::In { left, right } => write!(
                f,
                "{} in {}",
                maybe_with_parens(left),
                maybe_with_parens(right)
            ),
            ExprNoExt::Less { left, right } => write!(
                f,
                "{} < {}",
                maybe_with_parens(left),
                maybe_with_parens(right)
            ),
            ExprNoExt::LessEq { left, right } => write!(
                f,
                "{} <= {}",
                maybe_with_parens(left),
                maybe_with_parens(right)
            ),
            ExprNoExt::Greater { left, right } => write!(
                f,
                "{} > {}",
                maybe_with_parens(left),
                maybe_with_parens(right)
            ),
            ExprNoExt::GreaterEq { left, right } => write!(
                f,
                "{} >= {}",
                maybe_with_parens(left),
                maybe_with_parens(right)
            ),
            ExprNoExt::And { left, right } => write!(
                f,
                "{} && {}",
                maybe_with_parens(left),
                maybe_with_parens(right)
            ),
            ExprNoExt::Or { left, right } => write!(
                f,
                "{} || {}",
                maybe_with_parens(left),
                maybe_with_parens(right)
            ),
            ExprNoExt::Add { left, right } => write!(
                f,
                "{} + {}",
                maybe_with_parens(left),
                maybe_with_parens(right)
            ),
            ExprNoExt::Sub { left, right } => write!(
                f,
                "{} - {}",
                maybe_with_parens(left),
                maybe_with_parens(right)
            ),
            ExprNoExt::Mul { left, right } => write!(
                f,
                "{} * {}",
                maybe_with_parens(left),
                maybe_with_parens(right)
            ),
            ExprNoExt::Contains { left, right } => {
                write!(f, "{}.contains({right})", maybe_with_parens(left))
            }
            ExprNoExt::ContainsAll { left, right } => {
                write!(f, "{}.containsAll({right})", maybe_with_parens(left))
            }
            ExprNoExt::ContainsAny { left, right } => {
                write!(f, "{}.containsAny({right})", maybe_with_parens(left))
            }
            ExprNoExt::GetAttr { left, attr } => write!(
                f,
                "{}[\"{}\"]",
                maybe_with_parens(left),
                attr.escape_debug()
            ),
            ExprNoExt::HasAttr { left, attr } => write!(
                f,
                "{} has \"{}\"",
                maybe_with_parens(left),
                attr.escape_debug()
            ),
            ExprNoExt::Like { left, pattern } => {
                write!(f, "{} like \"{}\"", maybe_with_parens(left), pattern) // intentionally not using .escape_debug() for pattern
            }
            ExprNoExt::Is {
                left,
                entity_type,
                in_expr,
            } => {
                write!(f, "{} is {}", maybe_with_parens(left), entity_type)?;
                match in_expr {
                    Some(in_expr) => write!(f, " in {}", maybe_with_parens(in_expr)),
                    None => Ok(()),
                }
            }
            ExprNoExt::If {
                cond_expr,
                then_expr,
                else_expr,
            } => write!(
                f,
                "if {} then {} else {}",
                maybe_with_parens(cond_expr),
                maybe_with_parens(then_expr),
                maybe_with_parens(else_expr)
            ),
            ExprNoExt::Set(v) => write!(f, "[{}]", v.iter().join(", ")),
            ExprNoExt::Record(m) => write!(
                f,
                "{{{}}}",
                m.iter()
                    .map(|(k, v)| format!("\"{}\": {}", k.escape_debug(), v))
                    .join(", ")
            ),
        }
    }
}

impl std::fmt::Display for ExtFuncCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // PANIC SAFETY: safe due to INVARIANT on `ExtFuncCall`
        #[allow(clippy::unreachable)]
        let Some((fn_name, args)) = self.call.iter().next() else {
            unreachable!("invariant violated: empty ExtFuncCall")
        };
        // search for the name and callstyle
        let style = Extensions::all_available().all_funcs().find_map(|ext_fn| {
            if &ext_fn.name().to_string() == fn_name {
                Some(ext_fn.style())
            } else {
                None
            }
        });
        match (style, args.iter().next()) {
            (Some(ast::CallStyle::MethodStyle), Some(receiver)) => {
                write!(
                    f,
                    "{}.{}({})",
                    maybe_with_parens(receiver),
                    fn_name,
                    args.iter().skip(1).join(", ")
                )
            }
            (_, _) => {
                write!(f, "{}({})", fn_name, args.iter().join(", "))
            }
        }
    }
}

/// returns the `Display` representation of the Expr, adding parens around
/// the entire string if necessary.
/// E.g., won't add parens for constants or `principal` etc, but will for things
/// like `(2 < 5)`.
/// When in doubt, add the parens.
fn maybe_with_parens(expr: &Expr) -> String {
    match expr {
        Expr::ExprNoExt(ExprNoExt::Value(_)) => expr.to_string(),
        Expr::ExprNoExt(ExprNoExt::Var(_)) => expr.to_string(),
        Expr::ExprNoExt(ExprNoExt::Slot(_)) => expr.to_string(),
        Expr::ExprNoExt(ExprNoExt::Unknown { .. }) => expr.to_string(),
        Expr::ExprNoExt(ExprNoExt::Not { .. }) => {
            // we want parens here because things like parse((!x).y)
            // would be printed into !x.y which has a different meaning
            format!("({expr})")
        }
        Expr::ExprNoExt(ExprNoExt::Neg { .. }) => {
            // we want parens here because things like parse((-x).y)
            // would be printed into -x.y which has a different meaning
            format!("({expr})")
        }
        Expr::ExprNoExt(ExprNoExt::Eq { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::NotEq { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::In { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::Less { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::LessEq { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::Greater { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::GreaterEq { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::And { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::Or { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::Add { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::Sub { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::Mul { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::Contains { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::ContainsAll { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::ContainsAny { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::GetAttr { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::HasAttr { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::Like { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::Is { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::If { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::Set(_)) => expr.to_string(),
        Expr::ExprNoExt(ExprNoExt::Record(_)) => expr.to_string(),
        Expr::ExtFuncCall { .. } => format!("({expr})"),
    }
}

#[cfg(test)]
// PANIC SAFETY: this is unit test code
#[allow(clippy::indexing_slicing)]
// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
mod test {
    use crate::parser::err::ParseError;

    use super::*;
    use cool_asserts::assert_matches;

    #[test]
    fn test_invalid_expr_from_cst_name() {
        let src = "some_long_str";
        let path = vec![Node::with_source_loc(
            Some(cst::Ident::Ident(src.into())),
            Loc::new(0..12, Arc::from(src)),
        )];
        let name = Node::with_source_loc(Some(cst::Ident::Else), Loc::new(13..16, Arc::from(src)));
        let cst_name = Node::with_source_loc(
            Some(cst::Name { path, name }),
            Loc::new(0..16, Arc::from(src)),
        );

        assert_matches!(Expr::try_from(&cst_name), Err(e) => {
            assert!(e.len() == 1);
            assert_matches!(&e[0],
                ParseError::ToAST(to_ast_error) => {
                    assert_matches!(to_ast_error.kind(), ToASTErrorKind::InvalidExpression(e) => {
                        println!("{e:?}");
                        assert_eq!(e.name.loc.end(), 16);
                    });
                }
            );
        });
    }
}
