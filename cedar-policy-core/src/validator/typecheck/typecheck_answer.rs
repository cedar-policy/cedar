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

use crate::ast::Expr;

use crate::validator::types::{CapabilitySet, Type};

/// [`TypecheckAnswer`] holds the result of typechecking an expression.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum TypecheckAnswer<'a> {
    /// Typechecking succeeded, and we know the type and a possibly empty capability
    /// set for the expression. The capability set is the set of
    /// (expression, attribute) pairs that are known as safe to access under the
    /// assumption that the expression evaluates to true.
    TypecheckSuccess {
        expr_type: Expr<Option<Type>>,
        expr_capability: CapabilitySet<'a>,
    },
    /// Typechecking failed. We might still be able to know the type of the
    /// overall expression, but not always. For instance, an `&&` expression
    /// will always have type `boolean`, so we populate `expr_recovery_type`
    /// with `Some(boolean)` even when there is a type error in the expression.
    TypecheckFail {
        expr_recovery_type: Expr<Option<Type>>,
    },

    /// Recursion limit reached
    RecursionLimit,

    /// Trying to typecheck an error node
    #[cfg(feature = "tolerant-ast")]
    ErrorAstNode,
}

impl<'a> TypecheckAnswer<'a> {
    /// Construct a successful [`TypecheckAnswer`] with a type but with an empty
    /// capability set.
    pub fn success(expr_type: Expr<Option<Type>>) -> Self {
        Self::TypecheckSuccess {
            expr_type,
            expr_capability: CapabilitySet::new(),
        }
    }

    /// Construct a successful [`TypecheckAnswer`] with a type and a capability.
    pub fn success_with_capability(
        expr_type: Expr<Option<Type>>,
        expr_capability: CapabilitySet<'a>,
    ) -> Self {
        Self::TypecheckSuccess {
            expr_type,
            expr_capability,
        }
    }

    /// Construct a failing [`TypecheckAnswer`] with a type.
    pub fn fail(expr_type: Expr<Option<Type>>) -> Self {
        Self::TypecheckFail {
            expr_recovery_type: expr_type,
        }
    }

    /// Check if this [`TypecheckAnswer`] contains a particular type. It
    /// contains a type if the type annotated AST contains `Some`
    /// of the argument type at its root.
    pub fn contains_type(&self, ty: &Type) -> bool {
        match self {
            TypecheckAnswer::TypecheckSuccess { expr_type, .. } => Some(expr_type),
            TypecheckAnswer::TypecheckFail { expr_recovery_type } => Some(expr_recovery_type),
            TypecheckAnswer::RecursionLimit => None,
            #[cfg(feature = "tolerant-ast")]
            TypecheckAnswer::ErrorAstNode => None,
        }
        .and_then(|e| e.data().as_ref())
            == Some(ty)
    }

    pub fn into_typed_expr(self) -> Option<Expr<Option<Type>>> {
        match self {
            TypecheckAnswer::TypecheckSuccess { expr_type, .. } => Some(expr_type),
            TypecheckAnswer::TypecheckFail { expr_recovery_type } => Some(expr_recovery_type),
            TypecheckAnswer::RecursionLimit => None,
            #[cfg(feature = "tolerant-ast")]
            TypecheckAnswer::ErrorAstNode => None,
        }
    }

    /// Return true if this represents successful typechecking.
    pub fn typechecked(&self) -> bool {
        match self {
            TypecheckAnswer::TypecheckSuccess { .. } => true,
            TypecheckAnswer::TypecheckFail { .. } => false,
            TypecheckAnswer::RecursionLimit => false,
            #[cfg(feature = "tolerant-ast")]
            TypecheckAnswer::ErrorAstNode => false,
        }
    }

    /// Transform the capability of this [`TypecheckAnswer`] without modifying the
    /// success or type.
    pub fn map_capability<F>(self, f: F) -> Self
    where
        F: FnOnce(CapabilitySet<'a>) -> CapabilitySet<'a>,
    {
        match self {
            TypecheckAnswer::TypecheckSuccess {
                expr_type,
                expr_capability,
            } => TypecheckAnswer::TypecheckSuccess {
                expr_type,
                expr_capability: f(expr_capability),
            },
            TypecheckAnswer::TypecheckFail { .. } => self,
            TypecheckAnswer::RecursionLimit => self,
            #[cfg(feature = "tolerant-ast")]
            TypecheckAnswer::ErrorAstNode => self,
        }
    }

    /// Convert this [`TypecheckAnswer`] into an equivalent answer for an expression
    /// that has failed to typecheck. If this is already `TypecheckFail`, then no
    /// change is required, otherwise, a `TypecheckFail` is constructed containing
    /// `Some` of the `expr_type`.
    pub fn into_fail(self) -> Self {
        match self {
            TypecheckAnswer::TypecheckSuccess { expr_type, .. } => TypecheckAnswer::fail(expr_type),
            TypecheckAnswer::TypecheckFail { .. } => self,
            TypecheckAnswer::RecursionLimit => self,
            #[cfg(feature = "tolerant-ast")]
            TypecheckAnswer::ErrorAstNode => self,
        }
    }

    /// Sequence another typechecking operation after this answer. The result of
    /// the operation will be adjusted to be a `TypecheckFail` if this is a
    /// `TypecheckFail`, otherwise it will be returned unaltered.
    pub fn then_typecheck<F>(self, f: F) -> Self
    where
        F: FnOnce(Expr<Option<Type>>, CapabilitySet<'a>) -> TypecheckAnswer<'a>,
    {
        match self {
            TypecheckAnswer::TypecheckSuccess {
                expr_type,
                expr_capability,
            } => f(expr_type, expr_capability),
            TypecheckAnswer::TypecheckFail { expr_recovery_type } => {
                f(expr_recovery_type, CapabilitySet::new()).into_fail()
            }
            TypecheckAnswer::RecursionLimit => self,
            #[cfg(feature = "tolerant-ast")]
            TypecheckAnswer::ErrorAstNode => self,
        }
    }

    /// Sequence another typechecking operation after all of the typechecking
    /// answers in the argument. The result of the operation is adjusted in the
    /// same manner as in `then_typecheck`, but accounts for the all the
    /// [`TypecheckAnswer`]s.
    pub fn sequence_all_then_typecheck<F>(
        answers: impl IntoIterator<Item = TypecheckAnswer<'a>>,
        f: F,
    ) -> TypecheckAnswer<'a>
    where
        F: FnOnce(Vec<(Expr<Option<Type>>, CapabilitySet<'a>)>) -> TypecheckAnswer<'a>,
    {
        let mut unwrapped = Vec::new();
        let mut any_failed = false;
        let mut recusion_limit_reached = false;
        #[cfg(feature = "tolerant-ast")]
        let mut ast_has_errors = false;
        for ans in answers {
            any_failed |= !ans.typechecked();
            unwrapped.push(match ans {
                TypecheckAnswer::TypecheckSuccess {
                    expr_type,
                    expr_capability,
                } => (expr_type, expr_capability),
                TypecheckAnswer::TypecheckFail { expr_recovery_type } => {
                    (expr_recovery_type, CapabilitySet::new())
                }
                TypecheckAnswer::RecursionLimit => {
                    recusion_limit_reached = true;
                    break;
                }
                #[cfg(feature = "tolerant-ast")]
                TypecheckAnswer::ErrorAstNode => {
                    ast_has_errors = true;
                    break;
                }
            });
        }

        #[cfg(feature = "tolerant-ast")]
        if ast_has_errors {
            return TypecheckAnswer::ErrorAstNode;
        }

        let ans = f(unwrapped);
        if recusion_limit_reached {
            TypecheckAnswer::RecursionLimit
        } else if any_failed {
            ans.into_fail()
        } else {
            ans
        }
    }
}
