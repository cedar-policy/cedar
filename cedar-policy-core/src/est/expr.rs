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
use crate::ast;
use crate::entities::{
    CedarValueJson, EscapeKind, FnAndArg, JsonDeserializationError,
    JsonDeserializationErrorContext, TypeAndId,
};
use crate::extensions::Extensions;
use crate::parser::cst::{self, Ident};
use crate::parser::err::{ParseError, ParseErrors, ToASTError};
use crate::parser::unescape;
use crate::parser::ASTNode;
use either::Either;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
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
    Record(HashMap<SmolStr, Expr>),
}

/// Serde JSON structure for an extension function call in the EST format
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
            Expr::ExprNoExt(ExprNoExt::Unknown { name }) => Ok(ast::Expr::unknown(name)),
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
            ast::ExprKind::Unknown { name, .. } => Expr::unknown(name),
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
                Expr::lit(CedarValueJson::Long(constant)),
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

impl TryFrom<cst::Expr> for Expr {
    type Error = ParseErrors;
    fn try_from(e: cst::Expr) -> Result<Expr, ParseErrors> {
        match *e.expr {
            cst::ExprData::Or(ASTNode { node, .. }) => match node {
                Some(o) => o.try_into(),
                None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
            },
            cst::ExprData::If(
                ASTNode { node: if_node, .. },
                ASTNode {
                    node: then_node, ..
                },
                ASTNode {
                    node: else_node, ..
                },
            ) => match (if_node, then_node, else_node) {
                (Some(if_node), Some(then_node), Some(else_node)) => {
                    let cond_expr = if_node.try_into()?;
                    let then_expr = then_node.try_into()?;
                    let else_expr = else_node.try_into()?;
                    Ok(Expr::ite(cond_expr, then_expr, else_expr))
                }
                (_, _, _) => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
            },
        }
    }
}

impl TryFrom<cst::Or> for Expr {
    type Error = ParseErrors;
    fn try_from(o: cst::Or) -> Result<Expr, ParseErrors> {
        let mut expr = match o.initial.node {
            Some(a) => a.try_into(),
            None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
        }?;
        for node in o.extended {
            let rhs = match node.node {
                Some(a) => a.try_into(),
                None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
            }?;
            expr = Expr::or(expr, rhs);
        }
        Ok(expr)
    }
}

impl TryFrom<cst::And> for Expr {
    type Error = ParseErrors;
    fn try_from(a: cst::And) -> Result<Expr, ParseErrors> {
        let mut expr = match a.initial.node {
            Some(r) => r.try_into(),
            None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
        }?;
        for node in a.extended {
            let rhs = match node.node {
                Some(r) => r.try_into(),
                None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
            }?;
            expr = Expr::and(expr, rhs);
        }
        Ok(expr)
    }
}

impl TryFrom<cst::Relation> for Expr {
    type Error = ParseErrors;
    fn try_from(r: cst::Relation) -> Result<Expr, ParseErrors> {
        match r {
            cst::Relation::Common { initial, extended } => {
                let mut expr = match initial.node {
                    Some(a) => a.try_into(),
                    None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
                }?;
                for (op, ASTNode { node, .. }) in extended {
                    let rhs = match node {
                        Some(a) => a.try_into(),
                        None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
                    }?;
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
            cst::Relation::Has { target, field } => match (target, field) {
                (
                    ASTNode {
                        node: Some(target), ..
                    },
                    ASTNode {
                        node: Some(field), ..
                    },
                ) => {
                    let target_expr = target.try_into()?;
                    match Expr::try_from(field.clone()) {
                        Ok(field_expr) => {
                            let field_str = field_expr
                                .into_string_literal()
                                .map_err(|_| ParseError::ToAST(ToASTError::HasNonLiteralRHS))?;
                            Ok(Expr::has_attr(target_expr, field_str))
                        }
                        Err(_) => match is_add_name(field) {
                            Some(name) => Ok(Expr::has_attr(target_expr, name.to_string().into())),
                            None => Err(ParseError::ToAST(ToASTError::HasNonLiteralRHS).into()),
                        },
                    }
                }
                (_, _) => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
            },
            cst::Relation::Like { target, pattern } => match (target, pattern) {
                (
                    ASTNode {
                        node: Some(target), ..
                    },
                    ASTNode {
                        node: Some(pattern),
                        ..
                    },
                ) => {
                    let target_expr = target.try_into()?;
                    let pat_expr: Expr = pattern.try_into()?;
                    let pat_str = pat_expr.into_string_literal().map_err(|e| {
                        ParseError::ToAST(ToASTError::InvalidPattern(
                            serde_json::to_string(&e)
                                .unwrap_or_else(|_| "<malformed est>".to_string()),
                        ))
                    })?;
                    Ok(Expr::like(target_expr, pat_str))
                }
                (_, _) => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
            },
        }
    }
}

impl TryFrom<cst::Add> for Expr {
    type Error = ParseErrors;
    fn try_from(a: cst::Add) -> Result<Expr, ParseErrors> {
        let mut expr = match a.initial.node {
            Some(m) => m.try_into(),
            None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
        }?;
        for (op, node) in a.extended {
            let rhs = match node.node {
                Some(m) => m.try_into(),
                None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
            }?;
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
fn is_add_name(add: cst::Add) -> Option<cst::Name> {
    if add.extended.is_empty() {
        match add.initial.node {
            Some(mult) => is_mult_name(mult),
            None => None,
        }
    } else {
        None
    }
}

/// Returns `Some` if this is just a cst::Name. For example the
/// `foobar` in `context has foobar`
fn is_mult_name(mult: cst::Mult) -> Option<cst::Name> {
    if mult.extended.is_empty() {
        match mult.initial.node {
            Some(unary) => is_unary_name(unary),
            None => None,
        }
    } else {
        None
    }
}

/// Returns `Some` if this is just a cst::Name. For example the
/// `foobar` in `context has foobar`
fn is_unary_name(unary: cst::Unary) -> Option<cst::Name> {
    if unary.op.is_none() {
        match unary.item.node {
            Some(mem) => is_mem_name(mem),
            None => None,
        }
    } else {
        None
    }
}

/// Returns `Some` if this is just a cst::Name. For example the
/// `foobar` in `context has foobar`
fn is_mem_name(mem: cst::Member) -> Option<cst::Name> {
    if mem.access.is_empty() {
        match mem.item.node {
            Some(primary) => is_primary_name(primary),
            None => None,
        }
    } else {
        None
    }
}

/// Returns `Some` if this is just a cst::Name. For example the
/// `foobar` in `context has foobar`
fn is_primary_name(primary: cst::Primary) -> Option<cst::Name> {
    match primary {
        cst::Primary::Name(node) => node.node,
        _ => None,
    }
}

impl TryFrom<cst::Mult> for Expr {
    type Error = ParseErrors;
    fn try_from(m: cst::Mult) -> Result<Expr, ParseErrors> {
        let mut expr = match m.initial.node {
            Some(u) => u.try_into(),
            None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
        }?;
        for (op, node) in m.extended {
            let rhs = match node.node {
                Some(u) => u.try_into(),
                None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
            }?;
            match op {
                cst::MultOp::Times => {
                    expr = Expr::mul(expr, rhs);
                }
                cst::MultOp::Divide => {
                    return Err(ParseError::ToAST(ToASTError::UnsupportedDivision).into())
                }
                cst::MultOp::Mod => {
                    return Err(ParseError::ToAST(ToASTError::UnsupportedModulo).into())
                }
            }
        }
        Ok(expr)
    }
}

impl TryFrom<cst::Unary> for Expr {
    type Error = ParseErrors;
    fn try_from(u: cst::Unary) -> Result<Expr, ParseErrors> {
        let inner = match u.item.node {
            Some(m) => m.try_into(),
            None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
        }?;
        match u.op {
            Some(cst::NegOp::Bang(0)) => Ok(inner),
            Some(cst::NegOp::Bang(1)) => Ok(Expr::not(inner)),
            Some(cst::NegOp::Bang(2)) => {
                // not safe to collapse !! to nothing
                Ok(Expr::not(Expr::not(inner)))
            }
            Some(cst::NegOp::Bang(n)) => {
                if n % 2 == 0 {
                    // safe to collapse to !! but not to nothing
                    Ok(Expr::not(Expr::not(inner)))
                } else {
                    // safe to collapse to !
                    Ok(Expr::not(inner))
                }
            }
            Some(cst::NegOp::Dash(0)) => Ok(inner),
            Some(cst::NegOp::Dash(mut num_dashes)) => {
                let inner = match inner {
                    Expr::ExprNoExt(ExprNoExt::Value(CedarValueJson::Long(n)))
                        if n != std::i64::MIN =>
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
                    n => {
                        if n % 2 == 0 {
                            // safe to collapse to `--` but not to nothing
                            Ok(Expr::neg(Expr::neg(inner)))
                        } else {
                            // safe to collapse to -
                            Ok(Expr::neg(inner))
                        }
                    }
                }
            }
            Some(cst::NegOp::OverBang) => {
                Err(ParseError::ToAST(ToASTError::UnaryOpLimit(ast::UnaryOp::Not)).into())
            }
            Some(cst::NegOp::OverDash) => {
                Err(ParseError::ToAST(ToASTError::UnaryOpLimit(ast::UnaryOp::Neg)).into())
            }
            None => Ok(inner),
        }
    }
}

/// Convert the given `cst::Primary` into either a (possibly namespaced)
/// function name, or an `Expr`.
///
/// (Upstream, the case where the `Primary` is a function name needs special
/// handling, because in that case it is not a valid expression. In all other
/// cases a `Primary` can be converted into an `Expr`.)
fn interpret_primary(p: cst::Primary) -> Result<Either<ast::Name, Expr>, ParseErrors> {
    match p {
        cst::Primary::Literal(ASTNode { node, .. }) => match node {
            Some(lit) => Ok(Either::Right(lit.try_into()?)),
            None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
        },
        cst::Primary::Ref(ASTNode { node, .. }) => match node {
            Some(cst::Ref::Uid { path, eid }) => {
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
            Some(cst::Ref::Ref { .. }) => {
                Err(ParseError::ToAST(ToASTError::UnsupportedEntityLiterals).into())
            }
            None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
        },
        cst::Primary::Name(ASTNode { node, .. }) => match node {
            Some(name) => match (&name.path[..], name.name.node) {
                (&[], Some(cst::Ident::Principal)) => {
                    Ok(Either::Right(Expr::var(ast::Var::Principal)))
                }
                (&[], Some(cst::Ident::Action)) => Ok(Either::Right(Expr::var(ast::Var::Action))),
                (&[], Some(cst::Ident::Resource)) => {
                    Ok(Either::Right(Expr::var(ast::Var::Resource)))
                }
                (&[], Some(cst::Ident::Context)) => Ok(Either::Right(Expr::var(ast::Var::Context))),
                (path, Some(cst::Ident::Ident(id))) => Ok(Either::Left(ast::Name::new(
                    id.parse()?,
                    path.iter()
                        .map(|ASTNode { node, .. }| {
                            node.as_ref()
                                .ok_or_else(|| {
                                    ParseErrors(vec![ParseError::ToAST(
                                        ToASTError::MissingNodeData,
                                    )])
                                })
                                .and_then(|id| id.to_string().parse().map_err(Into::into))
                        })
                        .collect::<Result<Vec<ast::Id>, _>>()?,
                ))),
                (path, Some(id)) => {
                    let (l, r) = match (path.first(), path.last()) {
                        (Some(l), Some(r)) => (
                            l.info.range_start(),
                            r.info.range_end() + ident_to_str_len(&id),
                        ),
                        (_, _) => (0, 0),
                    };
                    Err(ParseError::ToAST(ToASTError::InvalidExpression(cst::Name {
                        path: path.to_vec(),
                        name: ASTNode::new(Some(id), l, r),
                    }))
                    .into())
                }
                (_, None) => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
            },
            None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
        },
        cst::Primary::Slot(ASTNode { node, .. }) => match node {
            Some(cst::Slot::Principal) => Ok(Either::Right(Expr::slot(ast::SlotId::principal()))),
            Some(cst::Slot::Resource) => Ok(Either::Right(Expr::slot(ast::SlotId::resource()))),
            None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
        },
        cst::Primary::Expr(ASTNode { node, .. }) => match node {
            Some(e) => Ok(Either::Right(e.try_into()?)),
            None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
        },
        cst::Primary::EList(nodes) => nodes
            .into_iter()
            .map(|node| match node.node {
                Some(e) => e.try_into(),
                None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
            })
            .collect::<Result<Vec<Expr>, _>>()
            .map(Expr::set)
            .map(Either::Right),
        cst::Primary::RInits(nodes) => nodes
            .into_iter()
            .map(|node| match node.node {
                Some(cst::RecInit(k, v)) => {
                    let mut errs = ParseErrors::new();
                    let s = k
                        .to_expr_or_special(&mut errs)
                        .and_then(|es| es.into_valid_attr(&mut errs));
                    if !errs.is_empty() {
                        Err(errs)
                    } else {
                        match (s, v.node) {
                            (Some(s), Some(e)) => Ok((s, e.try_into()?)),
                            (_, _) => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
                        }
                    }
                }
                None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
            })
            .collect::<Result<HashMap<SmolStr, Expr>, ParseErrors>>()
            .map(Expr::record)
            .map(Either::Right),
    }
}

impl TryFrom<cst::Member> for Expr {
    type Error = ParseErrors;
    fn try_from(m: cst::Member) -> Result<Expr, ParseErrors> {
        let mut item: Either<ast::Name, Expr> = match m.item.node {
            Some(p) => interpret_primary(p),
            None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
        }?;
        for access in m.access {
            match access.node {
                Some(cst::MemAccess::Field(ASTNode { node, .. })) => match node {
                    Some(cst::Ident::Ident(i)) => {
                        item = match item {
                            Either::Left(name) => {
                                return Err(
                                    ParseError::ToAST(ToASTError::InvalidAccess(name, i)).into()
                                )
                            }
                            Either::Right(expr) => Either::Right(Expr::get_attr(expr, i)),
                        };
                    }
                    Some(i) => {
                        return Err(
                            ParseError::ToAST(ToASTError::InvalidIdentifier(i.to_string())).into(),
                        )
                    }
                    None => return Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
                },
                Some(cst::MemAccess::Call(args)) => {
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
                            args.into_iter()
                                .map(|ASTNode { node, .. }| match node {
                                    Some(expr) => expr.try_into(),
                                    None => {
                                        Err(ParseError::ToAST(ToASTError::MissingNodeData).into())
                                    }
                                })
                                .collect::<Result<Vec<_>, _>>()?,
                        )),
                        Either::Right(Expr::ExprNoExt(ExprNoExt::GetAttr { left, attr })) => {
                            let args = args
                                .into_iter()
                                .map(|node| match node.node {
                                    Some(arg) => arg.try_into(),
                                    None => {
                                        Err(ParseError::ToAST(ToASTError::MissingNodeData).into())
                                    }
                                })
                                .collect::<Result<Vec<Expr>, ParseErrors>>()?;
                            let args = args.into_iter();
                            match attr.as_str() {
                                "contains" => Either::Right(Expr::contains(
                                    left,
                                    extract_single_argument(args, "contains()")?,
                                )),
                                "containsAll" => Either::Right(Expr::contains_all(
                                    left,
                                    extract_single_argument(args, "containsAll()")?,
                                )),
                                "containsAny" => Either::Right(Expr::contains_any(
                                    left,
                                    extract_single_argument(args, "containsAny()")?,
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
                        _ => return Err(ParseError::ToAST(ToASTError::ExpressionCall).into()),
                    };
                }
                Some(cst::MemAccess::Index(ASTNode {
                    node: Some(node), ..
                })) => {
                    let s = Expr::try_from(node)?
                        .into_string_literal()
                        .map_err(|_| ParseError::ToAST(ToASTError::NonStringIndex))?;
                    item = match item {
                        Either::Left(name) => {
                            return Err(ParseError::ToAST(ToASTError::InvalidIndex(name, s)).into())
                        }
                        Either::Right(expr) => Either::Right(Expr::get_attr(expr, s)),
                    };
                }
                _ => return Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
            }
        }
        match item {
            Either::Left(_) => Err(ParseError::ToAST(ToASTError::MembershipInvariantViolation))?,
            Either::Right(expr) => Ok(expr),
        }
    }
}

fn extract_single_argument(
    es: impl ExactSizeIterator<Item = Expr>,
    fn_name: &'static str,
) -> Result<Expr, ParseErrors> {
    let mut iter = es.fuse().peekable();
    let first = iter.next();
    let second = iter.peek();
    match (first, second) {
        (None, _) => Err(ParseError::ToAST(ToASTError::wrong_arity(fn_name, 1, 0)).into()),
        (Some(_), Some(_)) => {
            Err(ParseError::ToAST(ToASTError::wrong_arity(fn_name, 1, iter.len())).into())
        }
        (Some(first), None) => Ok(first),
    }
}

impl TryFrom<cst::Literal> for Expr {
    type Error = ParseErrors;
    fn try_from(lit: cst::Literal) -> Result<Expr, ParseErrors> {
        match lit {
            cst::Literal::True => Ok(Expr::lit(CedarValueJson::Bool(true))),
            cst::Literal::False => Ok(Expr::lit(CedarValueJson::Bool(false))),
            cst::Literal::Num(n) => Ok(Expr::lit(CedarValueJson::Long(
                n.try_into()
                    .map_err(|_| ParseError::ToAST(ToASTError::IntegerLiteralTooLarge(n)))?,
            ))),
            cst::Literal::Str(ASTNode { node, .. }) => match node {
                Some(cst::Str::String(s)) => Ok(Expr::lit(CedarValueJson::String(s))),
                Some(cst::Str::Invalid(invalid_str)) => Err(ParseError::ToAST(
                    ToASTError::InvalidString(invalid_str.to_string()),
                )
                .into()),
                None => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
            },
        }
    }
}

impl TryFrom<cst::Name> for Expr {
    type Error = ParseErrors;
    fn try_from(name: cst::Name) -> Result<Expr, ParseErrors> {
        match (&name.path[..], name.name.node) {
            (&[], Some(cst::Ident::Principal)) => Ok(Expr::var(ast::Var::Principal)),
            (&[], Some(cst::Ident::Action)) => Ok(Expr::var(ast::Var::Action)),
            (&[], Some(cst::Ident::Resource)) => Ok(Expr::var(ast::Var::Resource)),
            (&[], Some(cst::Ident::Context)) => Ok(Expr::var(ast::Var::Context)),
            (path, Some(id)) => {
                let (l, r) = match (path.first(), path.last()) {
                    (Some(l), Some(r)) => (
                        l.info.range_start(),
                        r.info.range_end() + ident_to_str_len(&id),
                    ),
                    (_, _) => (0, 0),
                };
                Err(ParseError::ToAST(ToASTError::InvalidExpression(cst::Name {
                    path: path.to_vec(),
                    name: ASTNode::new(Some(id), l, r),
                }))
                .into())
            }
            (_, None) => Err(ParseError::ToAST(ToASTError::MissingNodeData).into()),
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
    }
}

#[cfg(test)]
// PANIC SAFETY: this is unit test code
#[allow(clippy::indexing_slicing)]
// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
mod test {
    use super::*;
    #[test]
    fn test_invalid_expr_from_cst_name() {
        let path = vec![ASTNode::new(
            Some(cst::Ident::Ident("some_long_str".into())),
            0,
            12,
        )];
        let name = ASTNode::new(Some(cst::Ident::Else), 13, 16);
        let cst_name = cst::Name { path, name };

        match Expr::try_from(cst_name) {
            Ok(_) => panic!("wrong error"),
            Err(e) => {
                assert!(e.len() == 1);
                match &e[0] {
                    ParseError::ToAST(ToASTError::InvalidExpression(e)) => {
                        println!("{:?}", e);
                        assert_eq!(e.name.info.range_end(), 16);
                    }
                    _ => panic!("wrong error"),
                }
            }
        }
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
                    display_cedarvaluejson(f, &arg)?;
                    write!(f, ".{ext_fn}()")?;
                    Ok(())
                }
                Some(ast::CallStyle::FunctionStyle) | None => {
                    write!(f, "{ext_fn}(")?;
                    display_cedarvaluejson(f, &arg)?;
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
        Expr::ExprNoExt(ExprNoExt::If { .. }) => format!("({expr})"),
        Expr::ExprNoExt(ExprNoExt::Set(_)) => expr.to_string(),
        Expr::ExprNoExt(ExprNoExt::Record(_)) => expr.to_string(),
        Expr::ExtFuncCall { .. } => format!("({expr})"),
    }
}
