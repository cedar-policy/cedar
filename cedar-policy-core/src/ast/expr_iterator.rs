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

use super::{Expr, ExprKind};

/// This structure implements the iterator used to traverse subexpressions of an
/// expression.
#[derive(Debug)]
pub struct ExprIterator<'a, T = ()> {
    /// The stack of expressions that need to be visited. To get the next
    /// expression, the iterator will pop from the stack. If the stack is empty,
    /// then the iterator is finished. Otherwise, any subexpressions of that
    /// expression are then pushed onto the stack, and the popped expression is
    /// returned.
    expression_stack: Vec<&'a Expr<T>>,
}

impl<'a, T> ExprIterator<'a, T> {
    /// Construct an expr iterator
    pub fn new(expr: &'a Expr<T>) -> Self {
        Self {
            expression_stack: vec![expr],
        }
    }
}

impl<'a, T> Iterator for ExprIterator<'a, T> {
    type Item = &'a Expr<T>;

    fn next(&mut self) -> Option<Self::Item> {
        let next_expr = self.expression_stack.pop()?;
        match next_expr.expr_kind() {
            ExprKind::Lit(_) => (),
            ExprKind::Unknown(_) => (),
            ExprKind::Slot(_) => (),
            ExprKind::Var(_) => (),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                self.expression_stack.push(test_expr);
                self.expression_stack.push(then_expr);
                self.expression_stack.push(else_expr);
            }
            ExprKind::And { left, right } | ExprKind::Or { left, right } => {
                self.expression_stack.push(left);
                self.expression_stack.push(right);
            }
            ExprKind::UnaryApp { arg, .. } => {
                self.expression_stack.push(arg);
            }
            ExprKind::BinaryApp { arg1, arg2, .. } => {
                self.expression_stack.push(arg1);
                self.expression_stack.push(arg2);
            }
            ExprKind::GetAttr { expr, attr: _ }
            | ExprKind::HasAttr { expr, attr: _ }
            | ExprKind::Like { expr, pattern: _ }
            | ExprKind::Is {
                expr,
                entity_type: _,
            } => {
                self.expression_stack.push(expr);
            }
            ExprKind::ExtensionFunctionApp { args: exprs, .. } | ExprKind::Set(exprs) => {
                self.expression_stack.extend(exprs.as_ref());
            }
            ExprKind::Record(map) => {
                self.expression_stack.extend(map.values());
            }
            #[cfg(feature = "tolerant-ast")]
            ExprKind::Error { .. } => (),
        }
        Some(next_expr)
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use crate::ast::{BinaryOp, Expr, SlotId, UnaryOp, Var};

    #[test]
    fn literals() {
        let e = Expr::val(true);
        let v: HashSet<_> = e.subexpressions().collect();

        assert_eq!(v.len(), 1);
        assert!(v.contains(&Expr::val(true)));
    }

    #[test]
    fn slots() {
        let e = Expr::slot(SlotId::principal());
        let v: HashSet<_> = e.subexpressions().collect();
        assert_eq!(v.len(), 1);
        assert!(v.contains(&Expr::slot(SlotId::principal())));
    }

    #[test]
    fn variables() {
        let e = Expr::var(Var::Principal);
        let v: HashSet<_> = e.subexpressions().collect();
        let s = HashSet::from([&e]);
        assert_eq!(v, s);
    }

    #[test]
    fn ite() {
        let e = Expr::ite(Expr::val(true), Expr::val(false), Expr::val(0));
        let v: HashSet<_> = e.subexpressions().collect();
        assert_eq!(
            v,
            HashSet::from([&e, &Expr::val(true), &Expr::val(false), &Expr::val(0)])
        );
    }

    #[test]
    fn and() {
        // Using `1 && false` because `true && false` would be simplified to
        // `false` by `Expr::and`.
        let e = Expr::and(Expr::val(1), Expr::val(false));
        println!("{e:?}");
        let v: HashSet<_> = e.subexpressions().collect();
        assert_eq!(v, HashSet::from([&e, &Expr::val(1), &Expr::val(false)]));
    }

    #[test]
    fn or() {
        // Using `1 || false` because `true || false` would be simplified to
        // `true` by `Expr::or`.
        let e = Expr::or(Expr::val(1), Expr::val(false));
        let v: HashSet<_> = e.subexpressions().collect();
        assert_eq!(v, HashSet::from([&e, &Expr::val(1), &Expr::val(false)]));
    }

    #[test]
    fn unary() {
        let e = Expr::unary_app(UnaryOp::Not, Expr::val(false));
        assert_eq!(
            e.subexpressions().collect::<HashSet<_>>(),
            HashSet::from([&e, &Expr::val(false)])
        );
    }

    #[test]
    fn binary() {
        let e = Expr::binary_app(BinaryOp::Eq, Expr::val(false), Expr::val(true));
        assert_eq!(
            e.subexpressions().collect::<HashSet<_>>(),
            HashSet::from([&e, &Expr::val(false), &Expr::val(true)])
        );
    }

    #[test]
    fn ext() {
        let e = Expr::call_extension_fn(
            "test".parse().unwrap(),
            vec![Expr::val(false), Expr::val(true)],
        );
        assert_eq!(
            e.subexpressions().collect::<HashSet<_>>(),
            HashSet::from([&e, &Expr::val(false), &Expr::val(true)])
        );
    }

    #[test]
    fn has_attr() {
        let e = Expr::has_attr(Expr::val(false), "test".into());
        assert_eq!(
            e.subexpressions().collect::<HashSet<_>>(),
            HashSet::from([&e, &Expr::val(false)])
        );
    }

    #[test]
    fn get_attr() {
        let e = Expr::get_attr(Expr::val(false), "test".into());
        assert_eq!(
            e.subexpressions().collect::<HashSet<_>>(),
            HashSet::from([&e, &Expr::val(false)])
        );
    }

    #[test]
    fn set() {
        let e = Expr::set(vec![Expr::val(false), Expr::val(true)]);
        assert_eq!(
            e.subexpressions().collect::<HashSet<_>>(),
            HashSet::from([&e, &Expr::val(false), &Expr::val(true)])
        );
    }

    #[test]
    fn set_duplicates() {
        let e = Expr::set(vec![Expr::val(true), Expr::val(true)]);
        let v: Vec<_> = e.subexpressions().collect();
        assert_eq!(v.len(), 3);
        assert!(v.contains(&&Expr::val(true)));
    }

    #[test]
    fn record() {
        let e = Expr::record(vec![
            ("test".into(), Expr::val(true)),
            ("another".into(), Expr::val(false)),
        ])
        .unwrap();
        assert_eq!(
            e.subexpressions().collect::<HashSet<_>>(),
            HashSet::from([&e, &Expr::val(false), &Expr::val(true)])
        );
    }

    #[test]
    fn is() {
        let e = Expr::is_entity_type(Expr::val(1), "T".parse().unwrap());
        assert_eq!(
            e.subexpressions().collect::<HashSet<_>>(),
            HashSet::from([&e, &Expr::val(1)])
        );
    }

    #[test]
    fn duplicates() {
        let e = Expr::ite(Expr::val(true), Expr::val(true), Expr::val(true));
        let v: Vec<_> = e.subexpressions().collect();
        assert_eq!(v.len(), 4);
        assert!(v.contains(&&e));
        assert!(v.contains(&&Expr::val(true)));
    }

    #[test]
    fn deeply_nested() {
        let e = Expr::get_attr(
            Expr::get_attr(Expr::and(Expr::val(1), Expr::val(0)), "attr2".into()),
            "attr1".into(),
        );
        let set: HashSet<_> = e.subexpressions().collect();
        assert!(set.contains(&e));
        assert!(set.contains(&Expr::get_attr(
            Expr::and(Expr::val(1), Expr::val(0)),
            "attr2".into()
        )));
        assert!(set.contains(&Expr::and(Expr::val(1), Expr::val(0))));
        assert!(set.contains(&Expr::val(1)));
        assert!(set.contains(&Expr::val(0)));
    }
}
