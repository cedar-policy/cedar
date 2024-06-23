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

use std::collections::HashSet;

use cedar_policy_core::ast::{Expr, ExprShapeOnly};

/// A set of effects. Used to represent knowledge about attribute existence
/// before and after evaluating an expression.
#[derive(Eq, PartialEq, Debug, Clone, Default)]
pub struct EffectSet<'a>(HashSet<Effect<'a>>);

impl<'a> EffectSet<'a> {
    /// An empty effect set
    pub fn new() -> Self {
        EffectSet(HashSet::new())
    }

    /// An effect set with a single [`Effect`]
    pub fn singleton(e: Effect<'a>) -> Self {
        let mut set = Self::new();
        set.0.insert(e);
        set
    }

    /// Construct the union of `self` and `other`
    pub fn union(&self, other: &Self) -> Self {
        EffectSet(self.0.union(&other.0).cloned().collect())
    }

    /// Construct the intersection of `self` and `other`
    pub fn intersect(&self, other: &Self) -> Self {
        EffectSet(self.0.intersection(&other.0).cloned().collect())
    }

    /// Does this effect set contain the given [`Effect`]
    pub fn contains(&self, e: &Effect<'_>) -> bool {
        self.0.contains(e)
    }
}

/// Represent a single effect, which is an expression and some attribute that is
/// known to exist for that expression.
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct Effect<'a> {
    /// For this expression
    on_expr: ExprShapeOnly<'a>,
    /// This attribute is known to exist on that expression
    attribute: &'a str,
}

impl<'a> Effect<'a> {
    /// Construct a new [`Effect`] stating that the attribute `attribute` is
    /// known to exist for the expression `on_expr`
    pub fn new(on_expr: &'a Expr, attribute: &'a str) -> Self {
        Self {
            on_expr: ExprShapeOnly::new(on_expr),
            attribute,
        }
    }
}
