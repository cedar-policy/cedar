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

use cedar_policy_core::ast::{
    EntityType, EntityUID, Expr, ExprKind, Literal, Name, PatternElem, Template,
};

/// Returns an iterator over all literal entity uids in the expression.
pub(super) fn expr_entity_uids(expr: &Expr) -> impl Iterator<Item = &EntityUID> {
    expr.subexpressions().filter_map(|e| match e.expr_kind() {
        ExprKind::Lit(Literal::EntityUID(uid)) => Some(uid.as_ref()),
        _ => None,
    })
}

/// Returns an iterator over all literal entity uids in a policy. This iterates
/// over any entities in the policy head condition in addition to any entities
/// in the body.
pub(super) fn policy_entity_uids(template: &Template) -> impl Iterator<Item = &EntityUID> {
    template
        .principal_constraint()
        .as_inner()
        .iter_euids()
        .chain(template.action_constraint().iter_euids())
        .chain(template.resource_constraint().as_inner().iter_euids())
        .chain(expr_entity_uids(template.non_head_constraints()))
}

/// The 3 different "classes" of text in an expression.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum TextKind<'a> {
    /// String Literals
    String(&'a str),
    /// Identifiers
    Identifier(&'a str),
    /// Pattern Strings
    Pattern(&'a [PatternElem]),
}

/// Returns an iterator over all text (strings and identifiers) in the expression.
pub(super) fn expr_text(e: &'_ Expr) -> impl Iterator<Item = TextKind<'_>> {
    e.subexpressions().flat_map(text_in_expr)
}

// Returns a vector containing the text in the top level expression
fn text_in_expr(e: &'_ Expr) -> impl IntoIterator<Item = TextKind<'_>> {
    match e.expr_kind() {
        ExprKind::Lit(l) => text_in_lit(l).into_iter().collect(),
        ExprKind::ExtensionFunctionApp { fn_name, .. } => text_in_name(fn_name).collect(),
        ExprKind::GetAttr { attr, .. } => vec![TextKind::Identifier(attr)],
        ExprKind::HasAttr { attr, .. } => vec![TextKind::Identifier(attr)],
        ExprKind::Like { pattern, .. } => vec![TextKind::Pattern(pattern.get_elems())],
        ExprKind::Record { pairs } => pairs
            .iter()
            .map(|(attr, _)| TextKind::Identifier(attr))
            .collect(),
        _ => vec![],
    }
}

fn text_in_lit(l: &'_ Literal) -> impl IntoIterator<Item = TextKind<'_>> {
    match l {
        Literal::Bool(_) => vec![],
        Literal::Long(_) => vec![],
        Literal::String(s) => vec![TextKind::String(s)],
        Literal::EntityUID(euid) => text_in_euid(euid).collect(),
    }
}

fn text_in_euid(euid: &'_ EntityUID) -> impl Iterator<Item = TextKind> {
    text_in_entity_type(euid.entity_type())
        .into_iter()
        .chain(std::iter::once(TextKind::Identifier(euid.eid().as_ref())))
}

fn text_in_entity_type(ty: &'_ EntityType) -> impl IntoIterator<Item = TextKind> {
    match ty {
        EntityType::Concrete(ty) => text_in_name(ty).collect::<Vec<_>>(),
        EntityType::Unspecified => vec![],
    }
}

fn text_in_name(name: &'_ Name) -> impl Iterator<Item = TextKind> {
    name.namespace_components()
        .map(|id| TextKind::Identifier(id.as_ref()))
        .chain(std::iter::once(TextKind::Identifier(
            name.basename().as_ref(),
        )))
}

#[cfg(test)]
mod tests {
    use super::{expr_entity_uids, expr_text};
    use crate::expr_iterator::TextKind;
    use cedar_policy_core::ast::{EntityUID, Expr, Literal, PatternElem, Var};
    use std::{collections::HashSet, str::FromStr};

    #[test]
    fn no_entities() {
        let no_entities = Expr::val(1);
        let entities: Vec<EntityUID> = expr_entity_uids(&no_entities).cloned().collect();
        assert_eq!(Vec::<EntityUID>::new(), entities);
    }

    #[test]
    fn entity_literal() {
        let euid =
            EntityUID::with_eid_and_type("test_entity_type", "foo").expect("valid identifier");
        let entity_lit = Expr::val(euid.clone());

        let entities: Vec<EntityUID> = expr_entity_uids(&entity_lit).cloned().collect();
        assert_eq!(vec![euid], entities);
    }

    #[test]
    fn entity_eq() {
        let euid =
            EntityUID::with_eid_and_type("test_entity_type", "foo").expect("valid identifier");
        let entity_eq = Expr::is_eq(Expr::var(Var::Principal), Expr::val(euid.clone()));

        let entities: Vec<EntityUID> = expr_entity_uids(&entity_eq).cloned().collect();
        assert_eq!(vec![euid], entities);
    }

    #[test]
    fn entity_in() {
        let euid =
            EntityUID::with_eid_and_type("test_entity_type", "foo").expect("valid identifier");
        let entity_eq = Expr::is_in(Expr::var(Var::Principal), Expr::val(euid.clone()));

        let entities: Vec<EntityUID> = expr_entity_uids(&entity_eq).cloned().collect();
        assert_eq!(vec![euid], entities);
    }

    #[test]
    fn entity_and() {
        let euid_foo =
            EntityUID::with_eid_and_type("test_entity_type", "foo").expect("valid identifier");
        let euid_bar =
            EntityUID::with_eid_and_type("test_entity_type", "bar").expect("valid identifier");
        let entity_and = Expr::and(
            Expr::is_eq(Expr::var(Var::Principal), Expr::val(euid_foo.clone())),
            Expr::is_in(Expr::var(Var::Resource), Expr::val(euid_bar.clone())),
        );

        let entities: HashSet<EntityUID> = expr_entity_uids(&entity_and).cloned().collect();
        assert_eq!(HashSet::from([euid_foo, euid_bar]), entities);
    }

    #[test]
    fn entity_in_set() {
        let euid_foo =
            EntityUID::with_eid_and_type("test_entity_type", "foo").expect("valid identifier");
        let euid_bar =
            EntityUID::with_eid_and_type("test_entity_type", "bar").expect("valid identifier");
        let euid_baz =
            EntityUID::with_eid_and_type("test_entity_type", "baz").expect("valid identifier");
        let entity_set = Expr::is_in(
            Expr::var(Var::Action),
            Expr::set(vec![
                Expr::val(euid_foo.clone()),
                Expr::val(euid_bar.clone()),
                Expr::val(euid_baz.clone()),
            ]),
        );

        let entities: HashSet<EntityUID> = expr_entity_uids(&entity_set).cloned().collect();
        assert_eq!(HashSet::from([euid_foo, euid_bar, euid_baz]), entities);
    }

    #[test]
    fn entity_if() {
        let euid_foo =
            EntityUID::with_eid_and_type("test_entity_type", "foo").expect("valid identifier");
        let euid_bar =
            EntityUID::with_eid_and_type("test_entity_type", "bar").expect("valid identifier");
        let euid_baz =
            EntityUID::with_eid_and_type("test_entity_type", "baz").expect("valid identifier");
        let entity_if = Expr::ite(
            Expr::is_in(Expr::var(Var::Principal), Expr::val(euid_foo.clone())),
            Expr::val(euid_bar.clone()),
            Expr::val(euid_baz.clone()),
        );

        let entities: HashSet<EntityUID> = expr_entity_uids(&entity_if).cloned().collect();
        assert_eq!(HashSet::from([euid_foo, euid_bar, euid_baz]), entities);
    }

    #[test]
    fn entity_has_attr() {
        let euid_foo =
            EntityUID::with_eid_and_type("test_entity_type", "foo").expect("valid identifier");
        let entity_has_attr = Expr::has_attr(Expr::val(euid_foo.clone()), "bar".into());

        let entities: Vec<EntityUID> = expr_entity_uids(&entity_has_attr).cloned().collect();
        assert_eq!(vec![euid_foo], entities);
    }

    #[test]
    fn entity_get_attr() {
        let euid_foo =
            EntityUID::with_eid_and_type("test_entity_type", "foo").expect("valid identifier");
        let entity_get_attr = Expr::get_attr(Expr::val(euid_foo.clone()), "bar".into());

        let entities: Vec<EntityUID> = expr_entity_uids(&entity_get_attr).cloned().collect();
        assert_eq!(vec![euid_foo], entities);
    }

    #[test]
    fn entity_record_get_attr() {
        let euid_foo =
            EntityUID::with_eid_and_type("test_entity_type", "foo").expect("valid identifier");
        let entity_get_elem = Expr::get_attr(
            Expr::record(vec![("bar".into(), Expr::val(euid_foo.clone()))]),
            "bar".into(),
        );

        let entities: Vec<EntityUID> = expr_entity_uids(&entity_get_elem).cloned().collect();
        assert_eq!(vec![euid_foo], entities);
    }

    #[test]
    fn entity_record() {
        let euid_foo =
            EntityUID::with_eid_and_type("test_entity_type", "foo").expect("valid identifier");
        let entity_record = Expr::record(vec![("bar".into(), Expr::val(euid_foo.clone()))]);

        let entities: Vec<EntityUID> = expr_entity_uids(&entity_record).cloned().collect();
        assert_eq!(vec![euid_foo], entities);
    }

    #[test]
    fn entity_full_head() {
        let euid_foo =
            EntityUID::with_eid_and_type("test_entity_type", "foo").expect("valid identifier");
        let euid_bar =
            EntityUID::with_eid_and_type("test_entity_type", "bar").expect("valid identifier");
        let euid_baz =
            EntityUID::with_eid_and_type("test_entity_type", "baz").expect("valid identifier");
        let euid_buz =
            EntityUID::with_eid_and_type("test_entity_type", "buz").expect("valid identifier");
        let head = Expr::and(
            Expr::is_eq(Expr::var(Var::Principal), Expr::val(euid_foo.clone())),
            Expr::and(
                Expr::is_in(
                    Expr::var(Var::Action),
                    Expr::set(vec![
                        Expr::val(euid_bar.clone()),
                        Expr::val(euid_baz.clone()),
                    ]),
                ),
                Expr::is_in(Expr::var(Var::Action), Expr::val(euid_buz.clone())),
            ),
        );

        let entities: HashSet<EntityUID> = expr_entity_uids(&head).cloned().collect();
        assert_eq!(
            HashSet::from([euid_foo, euid_bar, euid_baz, euid_buz]),
            entities
        );
    }

    #[test]
    fn test_strs() {
        let p = Expr::and(
            Expr::get_attr(Expr::var(Var::Principal), "test".into()),
            Expr::val(EntityUID::from_str("a::b::\"c\"").unwrap()),
        );
        let strs: HashSet<_> = expr_text(&p).collect();
        assert_eq!(
            HashSet::from([
                TextKind::Identifier("test"),
                TextKind::Identifier("a"),
                TextKind::Identifier("b"),
                TextKind::Identifier("c")
            ]),
            strs
        );
    }

    #[test]
    fn test_strs_lit() {
        let e = Expr::and(
            Expr::val(Literal::Bool(true)),
            Expr::and(
                Expr::val(Literal::Bool(false)),
                Expr::and(
                    Expr::val(EntityUID::from_str("a::b::\"c\"").unwrap()),
                    Expr::and(Expr::val(Literal::Long(123)), Expr::val("this is a test")),
                ),
            ),
        );
        let strs: HashSet<_> = expr_text(&e).collect();
        assert_eq!(
            HashSet::from([
                TextKind::Identifier("a"),
                TextKind::Identifier("b"),
                TextKind::Identifier("c"),
                TextKind::String("this is a test"),
            ]),
            strs
        );
    }

    #[test]
    fn test_strs_atrs() {
        let r = Expr::record([
            ("a1".into(), Expr::val(true)),
            ("a2".into(), Expr::val(false)),
        ]);
        let e = Expr::ite(
            Expr::get_attr(
                Expr::val(EntityUID::from_str("another::\"euid\"").unwrap()),
                "myattr".into(),
            ),
            Expr::has_attr(r, "myattr2".into()),
            Expr::val(false),
        );

        let strs: HashSet<_> = expr_text(&e).collect();

        assert_eq!(
            HashSet::from([
                TextKind::Identifier("a1"),
                TextKind::Identifier("a2"),
                TextKind::Identifier("another"),
                TextKind::Identifier("euid"),
                TextKind::Identifier("myattr"),
                TextKind::Identifier("myattr2"),
            ]),
            strs
        );
    }

    #[test]
    fn test_strs_ext() {
        let e = Expr::call_extension_fn("test".parse().unwrap(), vec![Expr::val("arg")]);
        let strs: HashSet<_> = expr_text(&e).collect();
        assert_eq!(
            HashSet::from([TextKind::Identifier("test"), TextKind::String("arg"),]),
            strs
        );
    }

    #[test]
    fn test_strs_like() {
        let p = vec![PatternElem::Wildcard, PatternElem::Char('a')];
        let e = Expr::like(Expr::val("test"), p.clone());
        let strs: HashSet<_> = expr_text(&e).collect();

        assert_eq!(
            HashSet::from([TextKind::Pattern(&p), TextKind::String("test")]),
            strs
        );
    }
}
