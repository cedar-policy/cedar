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

use super::FromJsonError;
#[cfg(feature = "tolerant-ast")]
use crate::ast::expr_allows_errors::AstExprErrorKind;
#[cfg(feature = "tolerant-ast")]
use crate::ast::Infallible;
use crate::ast::{self, BoundedDisplay, EntityUID};
use crate::entities::json::{
    err::EscapeKind, err::JsonDeserializationError, err::JsonDeserializationErrorContext,
    CedarValueJson, FnAndArgs,
};
use crate::expr_builder::ExprBuilder;
use crate::extensions::Extensions;
use crate::jsonvalue::JsonValueWithNoDuplicateKeys;
use crate::parser::cst_to_ast;
use crate::parser::err::ParseErrors;
use crate::parser::Node;
use crate::parser::{cst, Loc};
use itertools::Itertools;
use serde::{de::Visitor, Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::{SmolStr, ToSmolStr};
use std::collections::{btree_map, BTreeMap, HashMap};
use std::sync::Arc;

/// Serde JSON structure for a Cedar expression in the EST format
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum Expr {
    /// Any Cedar expression other than an extension function call.
    ExprNoExt(ExprNoExt),
    /// Extension function call, where the key is the name of an extension
    /// function or method.
    ExtFuncCall(ExtFuncCall),
}

// Manual implementation of `Deserialize` is more efficient than the derived
// implementation with `serde(untagged)`. In particular, if the key is valid for
// `ExprNoExt` but there is a deserialization problem within the corresponding
// value, the derived implementation would backtrack and try to deserialize as
// `ExtFuncCall` with that key as the extension function name, but this manual
// implementation instead eagerly errors out, taking advantage of the fact that
// none of the keys for `ExprNoExt` are valid extension function names.
//
// See #1284.
impl<'de> Deserialize<'de> for Expr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ExprVisitor;
        impl<'de> Visitor<'de> for ExprVisitor {
            type Value = Expr;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON object representing an expression")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let (k, v): (SmolStr, JsonValueWithNoDuplicateKeys) = match map.next_entry()? {
                    None => {
                        return Err(serde::de::Error::custom(
                            "empty map is not a valid expression",
                        ))
                    }
                    Some((k, v)) => (k, v),
                };
                match map.next_key()? {
                    None => (),
                    Some(k2) => {
                        let k2: SmolStr = k2;
                        return Err(serde::de::Error::custom(format!("JSON object representing an `Expr` should have only one key, but found two keys: `{k}` and `{k2}`")));
                    }
                };
                if cst_to_ast::is_known_extension_func_str(&k) {
                    // `k` is the name of an extension function or method. We assume that
                    // no such keys are valid keys for `ExprNoExt`, so we must parse as an
                    // `ExtFuncCall`.
                    let obj = serde_json::json!({ k: v });
                    let extfunccall =
                        serde_json::from_value(obj).map_err(serde::de::Error::custom)?;
                    Ok(Expr::ExtFuncCall(extfunccall))
                } else {
                    // not a valid extension function or method, so we expect it
                    // to work for `ExprNoExt`.
                    let obj = serde_json::json!({ k: v });
                    let exprnoext =
                        serde_json::from_value(obj).map_err(serde::de::Error::custom)?;
                    Ok(Expr::ExprNoExt(exprnoext))
                }
            }
        }

        deserializer.deserialize_map(ExprVisitor)
    }
}

/// Represent an element of a pattern literal
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum PatternElem {
    /// The wildcard asterisk
    Wildcard,
    /// A string without any wildcards
    Literal(SmolStr),
}

impl From<&[PatternElem]> for crate::ast::Pattern {
    fn from(value: &[PatternElem]) -> Self {
        let mut elems = Vec::new();
        for elem in value {
            match elem {
                PatternElem::Wildcard => {
                    elems.push(crate::ast::PatternElem::Wildcard);
                }
                PatternElem::Literal(s) => {
                    elems.extend(s.chars().map(crate::ast::PatternElem::Char));
                }
            }
        }
        Self::from(elems)
    }
}

impl From<crate::ast::PatternElem> for PatternElem {
    fn from(value: crate::ast::PatternElem) -> Self {
        match value {
            crate::ast::PatternElem::Wildcard => Self::Wildcard,
            crate::ast::PatternElem::Char(c) => Self::Literal(c.to_smolstr()),
        }
    }
}

impl From<crate::ast::Pattern> for Vec<PatternElem> {
    fn from(value: crate::ast::Pattern) -> Self {
        value.iter().map(|elem| (*elem).into()).collect()
    }
}

/// Serde JSON structure for [any Cedar expression other than an extension
/// function call] in the EST format
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum ExprNoExt {
    /// Literal value (including anything that's legal to express in the
    /// attribute-value JSON format)
    Value(CedarValueJson),
    /// Var
    Var(ast::Var),
    /// Template slot
    Slot(#[cfg_attr(feature = "wasm", tsify(type = "string"))] ast::SlotId),
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
    /// `isEmpty()`
    #[serde(rename = "isEmpty")]
    IsEmpty {
        /// Argument
        arg: Arc<Expr>,
    },
    /// `getTag()`
    #[serde(rename = "getTag")]
    GetTag {
        /// Left-hand argument (receiver)
        left: Arc<Expr>,
        /// Right-hand argument (inside the `()`)
        right: Arc<Expr>,
    },
    /// `hasTag()`
    #[serde(rename = "hasTag")]
    HasTag {
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
        pattern: Vec<PatternElem>,
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
    Record(
        #[serde_as(as = "serde_with::MapPreventDuplicates<_,_>")]
        #[cfg_attr(feature = "wasm", tsify(type = "Record<string, Expr>"))]
        BTreeMap<SmolStr, Expr>,
    ),
    /// AST Error node - this represents a parsing error in a partially generated AST
    #[cfg(feature = "tolerant-ast")]
    Error(AstExprErrorKind),
}

/// Serde JSON structure for an extension function call in the EST format
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
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
    #[cfg_attr(feature = "wasm", tsify(type = "Record<string, Array<Expr>>"))]
    call: HashMap<SmolStr, Vec<Expr>>,
}

/// Construct an [`Expr`].
#[derive(Clone, Debug)]
pub struct Builder;

impl ExprBuilder for Builder {
    type Expr = Expr;

    type Data = ();
    #[cfg(feature = "tolerant-ast")]
    type ErrorType = Infallible;

    fn with_data(_data: Self::Data) -> Self {
        Self
    }

    fn with_maybe_source_loc(self, _: Option<&Loc>) -> Self {
        self
    }

    fn loc(&self) -> Option<&Loc> {
        None
    }

    fn data(&self) -> &Self::Data {
        &()
    }

    /// literal
    fn val(self, lit: impl Into<ast::Literal>) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Value(CedarValueJson::from_lit(lit.into())))
    }

    /// principal, action, resource, context
    fn var(self, var: ast::Var) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Var(var))
    }

    /// Template slots
    fn slot(self, slot: ast::SlotId) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Slot(slot))
    }

    /// An extension call with one arg, which is the name of the unknown
    fn unknown(self, u: ast::Unknown) -> Expr {
        Expr::ExtFuncCall(ExtFuncCall {
            call: HashMap::from([("unknown".to_smolstr(), vec![Builder::new().val(u.name)])]),
        })
    }

    /// `!`
    fn not(self, e: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Not { arg: Arc::new(e) })
    }

    /// `-`
    fn neg(self, e: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Neg { arg: Arc::new(e) })
    }

    /// `==`
    fn is_eq(self, left: Expr, right: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Eq {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `!=`
    fn noteq(self, left: Expr, right: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::NotEq {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `in`
    fn is_in(self, left: Expr, right: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::In {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `<`
    fn less(self, left: Expr, right: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Less {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `<=`
    fn lesseq(self, left: Expr, right: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::LessEq {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `>`
    fn greater(self, left: Expr, right: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Greater {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `>=`
    fn greatereq(self, left: Expr, right: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::GreaterEq {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `&&`
    fn and(self, left: Expr, right: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::And {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `||`
    fn or(self, left: Expr, right: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Or {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `+`
    fn add(self, left: Expr, right: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Add {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `-`
    fn sub(self, left: Expr, right: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Sub {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `*`
    fn mul(self, left: Expr, right: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Mul {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `left.contains(right)`
    fn contains(self, left: Expr, right: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Contains {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `left.containsAll(right)`
    fn contains_all(self, left: Expr, right: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::ContainsAll {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `left.containsAny(right)`
    fn contains_any(self, left: Expr, right: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::ContainsAny {
            left: Arc::new(left),
            right: Arc::new(right),
        })
    }

    /// `arg.isEmpty()`
    fn is_empty(self, expr: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::IsEmpty {
            arg: Arc::new(expr),
        })
    }

    /// `left.getTag(right)`
    fn get_tag(self, expr: Expr, tag: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::GetTag {
            left: Arc::new(expr),
            right: Arc::new(tag),
        })
    }

    /// `left.hasTag(right)`
    fn has_tag(self, expr: Expr, tag: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::HasTag {
            left: Arc::new(expr),
            right: Arc::new(tag),
        })
    }

    /// `left.attr`
    fn get_attr(self, expr: Expr, attr: SmolStr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::GetAttr {
            left: Arc::new(expr),
            attr,
        })
    }

    /// `left has attr`
    fn has_attr(self, expr: Expr, attr: SmolStr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::HasAttr {
            left: Arc::new(expr),
            attr,
        })
    }

    /// `left like pattern`
    fn like(self, expr: Expr, pattern: ast::Pattern) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Like {
            left: Arc::new(expr),
            pattern: pattern.into(),
        })
    }

    /// `left is entity_type`
    fn is_entity_type(self, left: Expr, entity_type: ast::EntityType) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Is {
            left: Arc::new(left),
            entity_type: entity_type.to_smolstr(),
            in_expr: None,
        })
    }

    /// `left is entity_type in entity`
    fn is_in_entity_type(self, left: Expr, entity_type: ast::EntityType, entity: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Is {
            left: Arc::new(left),
            entity_type: entity_type.to_smolstr(),
            in_expr: Some(Arc::new(entity)),
        })
    }

    /// `if cond_expr then then_expr else else_expr`
    fn ite(self, cond_expr: Expr, then_expr: Expr, else_expr: Expr) -> Expr {
        Expr::ExprNoExt(ExprNoExt::If {
            cond_expr: Arc::new(cond_expr),
            then_expr: Arc::new(then_expr),
            else_expr: Arc::new(else_expr),
        })
    }

    /// e.g. [1+2, !(context has department)]
    fn set(self, elements: impl IntoIterator<Item = Expr>) -> Expr {
        Expr::ExprNoExt(ExprNoExt::Set(elements.into_iter().collect()))
    }

    /// e.g. {foo: 1+2, bar: !(context has department)}
    fn record(
        self,
        map: impl IntoIterator<Item = (SmolStr, Expr)>,
    ) -> Result<Expr, ast::ExpressionConstructionError> {
        let mut dedup_map = BTreeMap::new();
        for (k, v) in map {
            match dedup_map.entry(k) {
                btree_map::Entry::Occupied(oentry) => {
                    return Err(ast::expression_construction_errors::DuplicateKeyError {
                        key: oentry.key().clone(),
                        context: "in record literal",
                    }
                    .into());
                }
                btree_map::Entry::Vacant(ventry) => {
                    ventry.insert(v);
                }
            }
        }
        Ok(Expr::ExprNoExt(ExprNoExt::Record(dedup_map)))
    }

    /// extension function call, including method calls
    fn call_extension_fn(self, fn_name: ast::Name, args: impl IntoIterator<Item = Expr>) -> Expr {
        Expr::ExtFuncCall(ExtFuncCall {
            call: HashMap::from([(fn_name.to_smolstr(), args.into_iter().collect())]),
        })
    }

    #[cfg(feature = "tolerant-ast")]
    fn error(self, parse_errors: ParseErrors) -> Result<Self::Expr, Self::ErrorType> {
        Ok(Expr::ExprNoExt(ExprNoExt::Error(
            AstExprErrorKind::InvalidExpr(parse_errors.to_string()),
        )))
    }
}

impl Expr {
    /// Substitute entity literals
    pub fn sub_entity_literals(
        self,
        mapping: &BTreeMap<EntityUID, EntityUID>,
    ) -> Result<Self, JsonDeserializationError> {
        match self {
            Expr::ExprNoExt(e) => match e {
                ExprNoExt::Value(v) => Ok(Expr::ExprNoExt(ExprNoExt::Value(
                    v.sub_entity_literals(mapping)?,
                ))),
                v @ ExprNoExt::Var(_) => Ok(Expr::ExprNoExt(v)),
                s @ ExprNoExt::Slot(_) => Ok(Expr::ExprNoExt(s)),
                ExprNoExt::Not { arg } => Ok(Expr::ExprNoExt(ExprNoExt::Not {
                    arg: Arc::new(Arc::unwrap_or_clone(arg).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::Neg { arg } => Ok(Expr::ExprNoExt(ExprNoExt::Neg {
                    arg: Arc::new(Arc::unwrap_or_clone(arg).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::Eq { left, right } => Ok(Expr::ExprNoExt(ExprNoExt::Eq {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::NotEq { left, right } => Ok(Expr::ExprNoExt(ExprNoExt::NotEq {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::In { left, right } => Ok(Expr::ExprNoExt(ExprNoExt::In {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::Less { left, right } => Ok(Expr::ExprNoExt(ExprNoExt::Less {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::LessEq { left, right } => Ok(Expr::ExprNoExt(ExprNoExt::LessEq {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::Greater { left, right } => Ok(Expr::ExprNoExt(ExprNoExt::Greater {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::GreaterEq { left, right } => Ok(Expr::ExprNoExt(ExprNoExt::GreaterEq {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::And { left, right } => Ok(Expr::ExprNoExt(ExprNoExt::And {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::Or { left, right } => Ok(Expr::ExprNoExt(ExprNoExt::Or {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::Add { left, right } => Ok(Expr::ExprNoExt(ExprNoExt::Add {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::Sub { left, right } => Ok(Expr::ExprNoExt(ExprNoExt::Sub {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::Mul { left, right } => Ok(Expr::ExprNoExt(ExprNoExt::Mul {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::Contains { left, right } => Ok(Expr::ExprNoExt(ExprNoExt::Contains {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::ContainsAll { left, right } => {
                    Ok(Expr::ExprNoExt(ExprNoExt::ContainsAll {
                        left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                        right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                    }))
                }
                ExprNoExt::ContainsAny { left, right } => {
                    Ok(Expr::ExprNoExt(ExprNoExt::ContainsAny {
                        left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                        right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                    }))
                }
                ExprNoExt::IsEmpty { arg } => Ok(Expr::ExprNoExt(ExprNoExt::IsEmpty {
                    arg: Arc::new(Arc::unwrap_or_clone(arg).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::GetTag { left, right } => Ok(Expr::ExprNoExt(ExprNoExt::GetTag {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::HasTag { left, right } => Ok(Expr::ExprNoExt(ExprNoExt::HasTag {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    right: Arc::new(Arc::unwrap_or_clone(right).sub_entity_literals(mapping)?),
                })),
                ExprNoExt::GetAttr { left, attr } => Ok(Expr::ExprNoExt(ExprNoExt::GetAttr {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    attr,
                })),
                ExprNoExt::HasAttr { left, attr } => Ok(Expr::ExprNoExt(ExprNoExt::HasAttr {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    attr,
                })),
                ExprNoExt::Like { left, pattern } => Ok(Expr::ExprNoExt(ExprNoExt::Like {
                    left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                    pattern,
                })),
                ExprNoExt::Is {
                    left,
                    entity_type,
                    in_expr,
                } => match in_expr {
                    Some(in_expr) => Ok(Expr::ExprNoExt(ExprNoExt::Is {
                        left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                        entity_type,
                        in_expr: Some(Arc::new(
                            Arc::unwrap_or_clone(in_expr).sub_entity_literals(mapping)?,
                        )),
                    })),
                    None => Ok(Expr::ExprNoExt(ExprNoExt::Is {
                        left: Arc::new(Arc::unwrap_or_clone(left).sub_entity_literals(mapping)?),
                        entity_type,
                        in_expr: None,
                    })),
                },
                ExprNoExt::If {
                    cond_expr,
                    then_expr,
                    else_expr,
                } => Ok(Expr::ExprNoExt(ExprNoExt::If {
                    cond_expr: Arc::new(
                        Arc::unwrap_or_clone(cond_expr).sub_entity_literals(mapping)?,
                    ),
                    then_expr: Arc::new(
                        Arc::unwrap_or_clone(then_expr).sub_entity_literals(mapping)?,
                    ),
                    else_expr: Arc::new(
                        Arc::unwrap_or_clone(else_expr).sub_entity_literals(mapping)?,
                    ),
                })),
                ExprNoExt::Set(v) => {
                    let mut new_v = vec![];
                    for e in v {
                        new_v.push(e.sub_entity_literals(mapping)?);
                    }
                    Ok(Expr::ExprNoExt(ExprNoExt::Set(new_v)))
                }
                ExprNoExt::Record(m) => {
                    let mut new_m = BTreeMap::new();
                    for (k, v) in m {
                        new_m.insert(k, v.sub_entity_literals(mapping)?);
                    }
                    Ok(Expr::ExprNoExt(ExprNoExt::Record(new_m)))
                }
                #[cfg(feature = "tolerant-ast")]
                ExprNoExt::Error(_) => Err(JsonDeserializationError::ASTErrorNode),
            },
            Expr::ExtFuncCall(e_fn_call) => {
                let mut new_m = HashMap::new();
                for (k, v) in e_fn_call.call {
                    let mut new_v = vec![];
                    for e in v {
                        new_v.push(e.sub_entity_literals(mapping)?);
                    }
                    new_m.insert(k, new_v);
                }
                Ok(Expr::ExtFuncCall(ExtFuncCall { call: new_m }))
            }
        }
    }
}

impl Expr {
    /// Attempt to convert this `est::Expr` into an `ast::Expr`
    ///
    /// `id`: the ID of the policy this `Expr` belongs to, used only for reporting errors
    pub fn try_into_ast(self, id: &ast::PolicyID) -> Result<ast::Expr, FromJsonError> {
        match self {
            Expr::ExprNoExt(ExprNoExt::Value(jsonvalue)) => jsonvalue
                .into_expr(|| JsonDeserializationErrorContext::Policy { id: id.clone() })
                .map(Into::into)
                .map_err(Into::into),
            Expr::ExprNoExt(ExprNoExt::Var(var)) => Ok(ast::Expr::var(var)),
            Expr::ExprNoExt(ExprNoExt::Slot(slot)) => Ok(ast::Expr::slot(slot)),
            Expr::ExprNoExt(ExprNoExt::Not { arg }) => {
                Ok(ast::Expr::not(Arc::unwrap_or_clone(arg).try_into_ast(id)?))
            }
            Expr::ExprNoExt(ExprNoExt::Neg { arg }) => {
                Ok(ast::Expr::neg(Arc::unwrap_or_clone(arg).try_into_ast(id)?))
            }
            Expr::ExprNoExt(ExprNoExt::Eq { left, right }) => Ok(ast::Expr::is_eq(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::NotEq { left, right }) => Ok(ast::Expr::noteq(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::In { left, right }) => Ok(ast::Expr::is_in(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::Less { left, right }) => Ok(ast::Expr::less(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::LessEq { left, right }) => Ok(ast::Expr::lesseq(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::Greater { left, right }) => Ok(ast::Expr::greater(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::GreaterEq { left, right }) => Ok(ast::Expr::greatereq(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::And { left, right }) => Ok(ast::Expr::and(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::Or { left, right }) => Ok(ast::Expr::or(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::Add { left, right }) => Ok(ast::Expr::add(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::Sub { left, right }) => Ok(ast::Expr::sub(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::Mul { left, right }) => Ok(ast::Expr::mul(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::Contains { left, right }) => Ok(ast::Expr::contains(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::ContainsAll { left, right }) => Ok(ast::Expr::contains_all(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::ContainsAny { left, right }) => Ok(ast::Expr::contains_any(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::IsEmpty { arg }) => Ok(ast::Expr::is_empty(
                Arc::unwrap_or_clone(arg).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::GetTag { left, right }) => Ok(ast::Expr::get_tag(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::HasTag { left, right }) => Ok(ast::Expr::has_tag(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                Arc::unwrap_or_clone(right).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::GetAttr { left, attr }) => Ok(ast::Expr::get_attr(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                attr,
            )),
            Expr::ExprNoExt(ExprNoExt::HasAttr { left, attr }) => Ok(ast::Expr::has_attr(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                attr,
            )),
            Expr::ExprNoExt(ExprNoExt::Like { left, pattern }) => Ok(ast::Expr::like(
                Arc::unwrap_or_clone(left).try_into_ast(id)?,
                crate::ast::Pattern::from(pattern.as_slice()),
            )),
            Expr::ExprNoExt(ExprNoExt::Is {
                left,
                entity_type,
                in_expr,
            }) => ast::EntityType::from_normalized_str(entity_type.as_str())
                .map_err(FromJsonError::InvalidEntityType)
                .and_then(|entity_type_name| {
                    let left: ast::Expr = Arc::unwrap_or_clone(left).try_into_ast(id)?;
                    let is_expr = ast::Expr::is_entity_type(left.clone(), entity_type_name);
                    match in_expr {
                        // The AST doesn't have an `... is ... in ..` node, so
                        // we represent it as a conjunction of `is` and `in`.
                        Some(in_expr) => Ok(ast::Expr::and(
                            is_expr,
                            ast::Expr::is_in(left, Arc::unwrap_or_clone(in_expr).try_into_ast(id)?),
                        )),
                        None => Ok(is_expr),
                    }
                }),
            Expr::ExprNoExt(ExprNoExt::If {
                cond_expr,
                then_expr,
                else_expr,
            }) => Ok(ast::Expr::ite(
                Arc::unwrap_or_clone(cond_expr).try_into_ast(id)?,
                Arc::unwrap_or_clone(then_expr).try_into_ast(id)?,
                Arc::unwrap_or_clone(else_expr).try_into_ast(id)?,
            )),
            Expr::ExprNoExt(ExprNoExt::Set(elements)) => Ok(ast::Expr::set(
                elements
                    .into_iter()
                    .map(|el| el.try_into_ast(id))
                    .collect::<Result<Vec<_>, FromJsonError>>()?,
            )),
            Expr::ExprNoExt(ExprNoExt::Record(map)) => {
                // PANIC SAFETY: can't have duplicate keys here because the input was already a HashMap
                #[allow(clippy::expect_used)]
                Ok(ast::Expr::record(
                    map.into_iter()
                        .map(|(k, v)| Ok((k, v.try_into_ast(id)?)))
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
                        let fn_name: ast::Name = fn_name.parse().map_err(|errs| {
                            JsonDeserializationError::parse_escape(
                                EscapeKind::Extension,
                                fn_name,
                                errs,
                            )
                        })?;
                        if !cst_to_ast::is_known_extension_func_name(&fn_name) {
                            return Err(FromJsonError::UnknownExtensionFunction(fn_name));
                        }
                        Ok(ast::Expr::call_extension_fn(
                            fn_name,
                            args.into_iter()
                                .map(|arg| arg.try_into_ast(id))
                                .collect::<Result<_, _>>()?,
                        ))
                    }
                    _ => Err(FromJsonError::MultipleOperators {
                        ops: call.into_keys().collect(),
                    }),
                }
            }
            #[cfg(feature = "tolerant-ast")]
            Expr::ExprNoExt(ExprNoExt::Error(_)) => Err(FromJsonError::ASTErrorNode),
        }
    }
}

impl From<ast::Literal> for Expr {
    fn from(lit: ast::Literal) -> Expr {
        Builder::new().val(lit)
    }
}

impl From<ast::Var> for Expr {
    fn from(var: ast::Var) -> Expr {
        Builder::new().var(var)
    }
}

impl From<ast::SlotId> for Expr {
    fn from(slot: ast::SlotId) -> Expr {
        Builder::new().slot(slot)
    }
}

impl TryFrom<&Node<Option<cst::Expr>>> for Expr {
    type Error = ParseErrors;
    fn try_from(e: &Node<Option<cst::Expr>>) -> Result<Expr, ParseErrors> {
        e.to_expr::<Builder>()
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

impl BoundedDisplay for Expr {
    fn fmt(&self, f: &mut impl std::fmt::Write, n: Option<usize>) -> std::fmt::Result {
        match self {
            Self::ExprNoExt(e) => BoundedDisplay::fmt(e, f, n),
            Self::ExtFuncCall(e) => BoundedDisplay::fmt(e, f, n),
        }
    }
}

fn display_cedarvaluejson(
    f: &mut impl std::fmt::Write,
    v: &CedarValueJson,
    n: Option<usize>,
) -> std::fmt::Result {
    match v {
        // Add parentheses around negative numeric literals otherwise
        // round-tripping fuzzer fails for expressions like `(-1)["a"]`.
        CedarValueJson::Long(i) if *i < 0 => write!(f, "({i})"),
        CedarValueJson::Long(i) => write!(f, "{i}"),
        CedarValueJson::Bool(b) => write!(f, "{b}"),
        CedarValueJson::String(s) => write!(f, "\"{}\"", s.escape_debug()),
        CedarValueJson::EntityEscape { __entity } => {
            match ast::EntityUID::try_from(__entity.clone()) {
                Ok(euid) => write!(f, "{euid}"),
                Err(e) => write!(f, "(invalid entity uid: {e})"),
            }
        }
        CedarValueJson::ExprEscape { __expr } => write!(f, "({__expr})"),
        CedarValueJson::ExtnEscape {
            __extn: FnAndArgs::Single { ext_fn, arg },
        } => {
            // search for the name and callstyle
            let style = Extensions::all_available().all_funcs().find_map(|f| {
                if &f.name().to_smolstr() == ext_fn {
                    Some(f.style())
                } else {
                    None
                }
            });
            match style {
                Some(ast::CallStyle::MethodStyle) => {
                    display_cedarvaluejson(f, arg, n)?;
                    write!(f, ".{ext_fn}()")?;
                    Ok(())
                }
                Some(ast::CallStyle::FunctionStyle) | None => {
                    write!(f, "{ext_fn}(")?;
                    display_cedarvaluejson(f, arg, n)?;
                    write!(f, ")")?;
                    Ok(())
                }
            }
        }
        CedarValueJson::ExtnEscape {
            __extn: FnAndArgs::Multi { ext_fn, args },
        } => {
            // search for the name and callstyle
            let style = Extensions::all_available().all_funcs().find_map(|f| {
                if &f.name().to_smolstr() == ext_fn {
                    Some(f.style())
                } else {
                    None
                }
            });
            match style {
                Some(ast::CallStyle::MethodStyle) => {
                    // PANIC SAFETY: method-style calls must have more than one argument
                    #[allow(clippy::indexing_slicing)]
                    display_cedarvaluejson(f, &args[0], n)?;
                    write!(f, ".{ext_fn}(")?;
                    // PANIC SAFETY: method-style calls must have more than one argument
                    #[allow(clippy::indexing_slicing)]
                    match &args[1..] {
                        [] => {}
                        [args @ .., last] => {
                            for arg in args {
                                display_cedarvaluejson(f, arg, n)?;
                                write!(f, ", ")?;
                            }
                            display_cedarvaluejson(f, last, n)?;
                        }
                    }
                    write!(f, ")")?;
                    Ok(())
                }
                Some(ast::CallStyle::FunctionStyle) | None => {
                    write!(f, "{ext_fn}(")?;
                    match &args[..] {
                        [] => {}
                        [args @ .., last] => {
                            for arg in args {
                                display_cedarvaluejson(f, arg, n)?;
                                write!(f, ", ")?;
                            }
                            display_cedarvaluejson(f, last, n)?;
                        }
                    }
                    write!(f, ")")?;
                    Ok(())
                }
            }
        }
        CedarValueJson::Set(v) => {
            match n {
                Some(n) if v.len() > n => {
                    // truncate to n elements
                    write!(f, "[")?;
                    for val in v.iter().take(n) {
                        display_cedarvaluejson(f, val, Some(n))?;
                        write!(f, ", ")?;
                    }
                    write!(f, "..]")?;
                    Ok(())
                }
                _ => {
                    // no truncation
                    write!(f, "[")?;
                    for (i, val) in v.iter().enumerate() {
                        display_cedarvaluejson(f, val, n)?;
                        if i < v.len() - 1 {
                            write!(f, ", ")?;
                        }
                    }
                    write!(f, "]")?;
                    Ok(())
                }
            }
        }
        CedarValueJson::Record(r) => {
            match n {
                Some(n) if r.len() > n => {
                    // truncate to n key-value pairs
                    write!(f, "{{")?;
                    for (k, v) in r.iter().take(n) {
                        write!(f, "\"{}\": ", k.escape_debug())?;
                        display_cedarvaluejson(f, v, Some(n))?;
                        write!(f, ", ")?;
                    }
                    write!(f, "..}}")?;
                    Ok(())
                }
                _ => {
                    // no truncation
                    write!(f, "{{")?;
                    for (i, (k, v)) in r.iter().enumerate() {
                        write!(f, "\"{}\": ", k.escape_debug())?;
                        display_cedarvaluejson(f, v, n)?;
                        if i < r.len() - 1 {
                            write!(f, ", ")?;
                        }
                    }
                    write!(f, "}}")?;
                    Ok(())
                }
            }
        }
        CedarValueJson::Null => {
            write!(f, "null")?;
            Ok(())
        }
    }
}

impl std::fmt::Display for ExprNoExt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        BoundedDisplay::fmt_unbounded(self, f)
    }
}

impl BoundedDisplay for ExprNoExt {
    fn fmt(&self, f: &mut impl std::fmt::Write, n: Option<usize>) -> std::fmt::Result {
        match &self {
            ExprNoExt::Value(v) => display_cedarvaluejson(f, v, n),
            ExprNoExt::Var(v) => write!(f, "{v}"),
            ExprNoExt::Slot(id) => write!(f, "{id}"),
            ExprNoExt::Not { arg } => {
                write!(f, "!")?;
                maybe_with_parens(f, arg, n)
            }
            ExprNoExt::Neg { arg } => {
                // Always add parentheses instead of calling
                // `maybe_with_parens`.
                // This makes sure that we always get a negation operation back
                // (as opposed to e.g., a negative number) when parsing the
                // printed form, thus preserving the round-tripping property.
                write!(f, "-({arg})")
            }
            ExprNoExt::Eq { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, " == ")?;
                maybe_with_parens(f, right, n)
            }
            ExprNoExt::NotEq { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, " != ")?;
                maybe_with_parens(f, right, n)
            }
            ExprNoExt::In { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, " in ")?;
                maybe_with_parens(f, right, n)
            }
            ExprNoExt::Less { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, " < ")?;
                maybe_with_parens(f, right, n)
            }
            ExprNoExt::LessEq { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, " <= ")?;
                maybe_with_parens(f, right, n)
            }
            ExprNoExt::Greater { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, " > ")?;
                maybe_with_parens(f, right, n)
            }
            ExprNoExt::GreaterEq { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, " >= ")?;
                maybe_with_parens(f, right, n)
            }
            ExprNoExt::And { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, " && ")?;
                maybe_with_parens(f, right, n)
            }
            ExprNoExt::Or { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, " || ")?;
                maybe_with_parens(f, right, n)
            }
            ExprNoExt::Add { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, " + ")?;
                maybe_with_parens(f, right, n)
            }
            ExprNoExt::Sub { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, " - ")?;
                maybe_with_parens(f, right, n)
            }
            ExprNoExt::Mul { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, " * ")?;
                maybe_with_parens(f, right, n)
            }
            ExprNoExt::Contains { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, ".contains({right})")
            }
            ExprNoExt::ContainsAll { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, ".containsAll({right})")
            }
            ExprNoExt::ContainsAny { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, ".containsAny({right})")
            }
            ExprNoExt::IsEmpty { arg } => {
                maybe_with_parens(f, arg, n)?;
                write!(f, ".isEmpty()")
            }
            ExprNoExt::GetTag { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, ".getTag({right})")
            }
            ExprNoExt::HasTag { left, right } => {
                maybe_with_parens(f, left, n)?;
                write!(f, ".hasTag({right})")
            }
            ExprNoExt::GetAttr { left, attr } => {
                maybe_with_parens(f, left, n)?;
                write!(f, "[\"{}\"]", attr.escape_debug())
            }
            ExprNoExt::HasAttr { left, attr } => {
                maybe_with_parens(f, left, n)?;
                write!(f, " has \"{}\"", attr.escape_debug())
            }
            ExprNoExt::Like { left, pattern } => {
                maybe_with_parens(f, left, n)?;
                write!(
                    f,
                    " like \"{}\"",
                    crate::ast::Pattern::from(pattern.as_slice())
                )
            }
            ExprNoExt::Is {
                left,
                entity_type,
                in_expr,
            } => {
                maybe_with_parens(f, left, n)?;
                write!(f, " is {entity_type}")?;
                match in_expr {
                    Some(in_expr) => {
                        write!(f, " in ")?;
                        maybe_with_parens(f, in_expr, n)
                    }
                    None => Ok(()),
                }
            }
            ExprNoExt::If {
                cond_expr,
                then_expr,
                else_expr,
            } => {
                write!(f, "if ")?;
                maybe_with_parens(f, cond_expr, n)?;
                write!(f, " then ")?;
                maybe_with_parens(f, then_expr, n)?;
                write!(f, " else ")?;
                maybe_with_parens(f, else_expr, n)
            }
            ExprNoExt::Set(v) => {
                match n {
                    Some(n) if v.len() > n => {
                        // truncate to n elements
                        write!(f, "[")?;
                        for element in v.iter().take(n) {
                            BoundedDisplay::fmt(element, f, Some(n))?;
                            write!(f, ", ")?;
                        }
                        write!(f, "..]")?;
                        Ok(())
                    }
                    _ => {
                        // no truncation
                        write!(f, "[")?;
                        for (i, element) in v.iter().enumerate() {
                            BoundedDisplay::fmt(element, f, n)?;
                            if i < v.len() - 1 {
                                write!(f, ", ")?;
                            }
                        }
                        write!(f, "]")?;
                        Ok(())
                    }
                }
            }
            ExprNoExt::Record(m) => {
                match n {
                    Some(n) if m.len() > n => {
                        // truncate to n key-value pairs
                        write!(f, "{{")?;
                        for (k, v) in m.iter().take(n) {
                            write!(f, "\"{}\": ", k.escape_debug())?;
                            BoundedDisplay::fmt(v, f, Some(n))?;
                            write!(f, ", ")?;
                        }
                        write!(f, "..}}")?;
                        Ok(())
                    }
                    _ => {
                        // no truncation
                        write!(f, "{{")?;
                        for (i, (k, v)) in m.iter().enumerate() {
                            write!(f, "\"{}\": ", k.escape_debug())?;
                            BoundedDisplay::fmt(v, f, n)?;
                            if i < m.len() - 1 {
                                write!(f, ", ")?;
                            }
                        }
                        write!(f, "}}")?;
                        Ok(())
                    }
                }
            }
            #[cfg(feature = "tolerant-ast")]
            ExprNoExt::Error(e) => {
                write!(f, "{e}")?;
                Ok(())
            }
        }
    }
}

impl std::fmt::Display for ExtFuncCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        BoundedDisplay::fmt_unbounded(self, f)
    }
}

impl BoundedDisplay for ExtFuncCall {
    fn fmt(&self, f: &mut impl std::fmt::Write, n: Option<usize>) -> std::fmt::Result {
        // PANIC SAFETY: safe due to INVARIANT on `ExtFuncCall`
        #[allow(clippy::unreachable)]
        let Some((fn_name, args)) = self.call.iter().next() else {
            unreachable!("invariant violated: empty ExtFuncCall")
        };
        // search for the name and callstyle
        let style = Extensions::all_available().all_funcs().find_map(|ext_fn| {
            if &ext_fn.name().to_smolstr() == fn_name {
                Some(ext_fn.style())
            } else {
                None
            }
        });
        match (style, args.iter().next()) {
            (Some(ast::CallStyle::MethodStyle), Some(receiver)) => {
                maybe_with_parens(f, receiver, n)?;
                write!(f, ".{}({})", fn_name, args.iter().skip(1).join(", "))
            }
            (_, _) => {
                write!(f, "{}({})", fn_name, args.iter().join(", "))
            }
        }
    }
}

/// returns the `BoundedDisplay` representation of the Expr, adding parens around
/// the entire string if necessary.
/// E.g., won't add parens for constants or `principal` etc, but will for things
/// like `(2 < 5)`.
/// When in doubt, add the parens.
fn maybe_with_parens(
    f: &mut impl std::fmt::Write,
    expr: &Expr,
    n: Option<usize>,
) -> std::fmt::Result {
    match expr {
        Expr::ExprNoExt(ExprNoExt::Set(_)) |
        Expr::ExprNoExt(ExprNoExt::Record(_)) |
        Expr::ExprNoExt(ExprNoExt::Value(_)) |
        Expr::ExprNoExt(ExprNoExt::Var(_)) |
        Expr::ExprNoExt(ExprNoExt::Slot(_)) => BoundedDisplay::fmt(expr, f, n),

        // we want parens here because things like parse((!x).y)
        // would be printed into !x.y which has a different meaning
        Expr::ExprNoExt(ExprNoExt::Not { .. }) |
        // we want parens here because things like parse((-x).y)
        // would be printed into -x.y which has a different meaning
        Expr::ExprNoExt(ExprNoExt::Neg { .. })  |
        Expr::ExprNoExt(ExprNoExt::Eq { .. }) |
        Expr::ExprNoExt(ExprNoExt::NotEq { .. }) |
        Expr::ExprNoExt(ExprNoExt::In { .. }) |
        Expr::ExprNoExt(ExprNoExt::Less { .. }) |
        Expr::ExprNoExt(ExprNoExt::LessEq { .. }) |
        Expr::ExprNoExt(ExprNoExt::Greater { .. }) |
        Expr::ExprNoExt(ExprNoExt::GreaterEq { .. }) |
        Expr::ExprNoExt(ExprNoExt::And { .. }) |
        Expr::ExprNoExt(ExprNoExt::Or { .. }) |
        Expr::ExprNoExt(ExprNoExt::Add { .. }) |
        Expr::ExprNoExt(ExprNoExt::Sub { .. }) |
        Expr::ExprNoExt(ExprNoExt::Mul { .. }) |
        Expr::ExprNoExt(ExprNoExt::Contains { .. }) |
        Expr::ExprNoExt(ExprNoExt::ContainsAll { .. }) |
        Expr::ExprNoExt(ExprNoExt::ContainsAny { .. }) |
        Expr::ExprNoExt(ExprNoExt::IsEmpty { .. }) |
        Expr::ExprNoExt(ExprNoExt::GetAttr { .. }) |
        Expr::ExprNoExt(ExprNoExt::HasAttr { .. }) |
        Expr::ExprNoExt(ExprNoExt::GetTag { .. }) |
        Expr::ExprNoExt(ExprNoExt::HasTag { .. }) |
        Expr::ExprNoExt(ExprNoExt::Like { .. }) |
        Expr::ExprNoExt(ExprNoExt::Is { .. }) |
        Expr::ExprNoExt(ExprNoExt::If { .. }) |
        Expr::ExtFuncCall { .. } => {
            write!(f, "(")?;
            BoundedDisplay::fmt(expr, f, n)?;
            write!(f, ")")?;
            Ok(())
        },
        #[cfg(feature = "tolerant-ast")]
        Expr::ExprNoExt(ExprNoExt::Error { .. }) => {
            write!(f, "(")?;
            BoundedDisplay::fmt(expr, f, n)?;
            write!(f, ")")?;
            Ok(())
        }
    }
}

#[cfg(test)]
// PANIC SAFETY: this is unit test code
#[allow(clippy::indexing_slicing)]
// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
mod test {
    use crate::parser::{
        err::{ParseError, ToASTErrorKind},
        parse_expr,
    };

    use super::*;
    use ast::BoundedToString;
    use cool_asserts::assert_matches;

    #[test]
    fn test_invalid_expr_from_cst_name() {
        let e = crate::parser::text_to_cst::parse_expr("some_long_str::else").unwrap();
        assert_matches!(Expr::try_from(&e), Err(e) => {
            assert!(e.len() == 1);
            assert_matches!(&e[0],
                ParseError::ToAST(to_ast_error) => {
                    assert_matches!(to_ast_error.kind(), ToASTErrorKind::ReservedIdentifier(s) => {
                        assert_eq!(s.to_string(), "else");
                    });
                }
            );
        });
    }

    #[test]
    fn display_and_bounded_display() {
        let expr = parse_expr(r#"[100, [3, 4, 5], -20, "foo"]"#)
            .unwrap()
            .into_expr::<Builder>();
        assert_eq!(format!("{expr}"), r#"[100, [3, 4, 5], (-20), "foo"]"#);
        assert_eq!(
            BoundedToString::to_string(&expr, None),
            r#"[100, [3, 4, 5], (-20), "foo"]"#
        );
        assert_eq!(
            BoundedToString::to_string(&expr, Some(4)),
            r#"[100, [3, 4, 5], (-20), "foo"]"#
        );
        assert_eq!(
            BoundedToString::to_string(&expr, Some(3)),
            r#"[100, [3, 4, 5], (-20), ..]"#
        );
        assert_eq!(
            BoundedToString::to_string(&expr, Some(2)),
            r#"[100, [3, 4, ..], ..]"#
        );
        assert_eq!(BoundedToString::to_string(&expr, Some(1)), r#"[100, ..]"#);
        assert_eq!(BoundedToString::to_string(&expr, Some(0)), r#"[..]"#);

        let expr = parse_expr(
            r#"{
            a: 12,
            b: [3, 4, true],
            c: -20,
            "hello ∞ world": "∂µß≈¥"
        }"#,
        )
        .unwrap()
        .into_expr::<Builder>();
        assert_eq!(
            format!("{expr}"),
            r#"{"a": 12, "b": [3, 4, true], "c": (-20), "hello ∞ world": "∂µß≈¥"}"#
        );
        assert_eq!(
            BoundedToString::to_string(&expr, None),
            r#"{"a": 12, "b": [3, 4, true], "c": (-20), "hello ∞ world": "∂µß≈¥"}"#
        );
        assert_eq!(
            BoundedToString::to_string(&expr, Some(4)),
            r#"{"a": 12, "b": [3, 4, true], "c": (-20), "hello ∞ world": "∂µß≈¥"}"#
        );
        assert_eq!(
            BoundedToString::to_string(&expr, Some(3)),
            r#"{"a": 12, "b": [3, 4, true], "c": (-20), ..}"#
        );
        assert_eq!(
            BoundedToString::to_string(&expr, Some(2)),
            r#"{"a": 12, "b": [3, 4, ..], ..}"#
        );
        assert_eq!(
            BoundedToString::to_string(&expr, Some(1)),
            r#"{"a": 12, ..}"#
        );
        assert_eq!(BoundedToString::to_string(&expr, Some(0)), r#"{..}"#);
    }
}
