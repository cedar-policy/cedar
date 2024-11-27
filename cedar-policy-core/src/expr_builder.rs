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

//! Contains the trait [`ExprBuilder`], defining a generic interface for
//! building different expression data structures (e.g., AST and EST).

use smol_str::SmolStr;

use crate::{
    ast, est,
    parser::{cst, Loc, Node},
};

/// Defines a generic interface for building different expressions which are
/// annotated with some extra data.
pub trait AnnotatedExprBuilder {
    /// The type of expression constructed by this instance of `ExprBuilder``.
    type Expr;

    /// The type of data carried on the expression, if any. Implementations
    /// should use `type Data = ()` if they do no support storing extra
    /// information on expressions.
    type Data;

    type ExprBuilder: ExprBuilder<Expr = Self::Expr>;

    /// Get an `ExprBuilder` instance which will be used to build an
    /// expression carrying some data. `ExprBuilder` implementations are free to
    /// ignore this data if the expression they construct does not carry extra
    /// information.
    fn with_data(d: Self::Data) -> Self::ExprBuilder;
}

pub trait UnannotatedExprBuilder {
    /// The type of expression constructed by this instance of `ExprBuilder``.
    type Expr;

    type ExprBuilder: ExprBuilder<Expr = Self::Expr>;

    fn new() -> Self::ExprBuilder;
}

/// Defines a generic interface for building different expression data
/// structures.
pub trait ExprBuilder {
    /// The type of expression constructed by this instance of `ExprBuilder``.
    type Expr;

    /// Build an expression located at `l`.
    fn with_source_loc(self, l: &Loc) -> Self;

    /// Construct the expression `e1 && e2`
    fn and(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr;

    /// Construct the expression `e1 has a`
    fn has_attr(self, e1: Self::Expr, a: SmolStr) -> Self::Expr;

    /// Construct the expression `e1.a`
    fn get_attr(self, e1: Self::Expr, a: SmolStr) -> Self::Expr;
}

struct AstBuilder<T> {
    data: T,
    loc: Option<Loc>,
}

impl<T> AnnotatedExprBuilder for AstBuilder<T> {
    type Expr = ast::Expr<T>;

    type Data = T;

    type ExprBuilder = AstBuilder<T>;

    fn with_data(data: Self::Data) -> Self::ExprBuilder {
        Self::ExprBuilder { data, loc: None }
    }
}

impl UnannotatedExprBuilder for AstBuilder<()> {
    type Expr = ast::Expr<()>;

    type ExprBuilder = Self;

    fn new() -> Self::ExprBuilder {
        Self::ExprBuilder {
            data: (),
            loc: None,
        }
    }
}

impl<T> ExprBuilder for AstBuilder<T> {
    type Expr = ast::Expr<T>;

    fn with_source_loc(mut self, l: &Loc) -> Self {
        self.loc = Some(l.clone());
        self
    }

    fn and(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr {
        ast::ExprBuilder::with_data(self.data).and(e1, e2)
    }

    fn has_attr(self, e1: Self::Expr, a: SmolStr) -> Self::Expr {
        ast::ExprBuilder::with_data(self.data).has_attr(e1, a)
    }

    fn get_attr(self, e1: Self::Expr, a: SmolStr) -> Self::Expr {
        ast::ExprBuilder::with_data(self.data).get_attr(e1, a)
    }
}

struct EstBuilder;

impl UnannotatedExprBuilder for EstBuilder {
    type Expr = est::Expr;

    type ExprBuilder = Self;

    fn new() -> Self::ExprBuilder {
        Self
    }
}

impl ExprBuilder for EstBuilder {
    type Expr = est::Expr;

    fn with_source_loc(self, _: &Loc) -> Self {
        self
    }

    fn and(self, e1: Self::Expr, e2: Self::Expr) -> Self::Expr {
        est::Expr::and(e1, e2)
    }

    fn has_attr(self, e1: Self::Expr, a: SmolStr) -> Self::Expr {
        est::Expr::has_attr(e1, a)
    }

    fn get_attr(self, e1: Self::Expr, a: SmolStr) -> Self::Expr {
        est::Expr::get_attr(e1, a)
    }
}

fn construct_exprs_extended_has<Builder: UnannotatedExprBuilder>(
    t: Builder::Expr,
    attrs: nonempty::NonEmpty<SmolStr>,
    loc: &Loc,
) -> Builder::Expr
where
    Builder::Expr: Clone,
{
    let (first, rest) = attrs.split_first();
    let has_expr = Builder::new()
        .with_source_loc(loc)
        .has_attr(t.clone(), first.to_owned());
    let get_expr = Builder::new()
        .with_source_loc(loc)
        .get_attr(t, first.to_owned());
    rest.iter()
        .fold((has_expr, get_expr), |(has_expr, get_expr), attr| {
            (
                Builder::new().with_source_loc(loc).and(
                    has_expr,
                    Builder::new()
                        .with_source_loc(loc)
                        .has_attr(get_expr.clone(), attr.to_owned()),
                ),
                Builder::new()
                    .with_source_loc(loc)
                    .get_attr(get_expr, attr.to_owned()),
            )
        })
        .0
}
