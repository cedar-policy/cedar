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

//! Conversions between PST and AST types

use smol_str::ToSmolStr;

use super::{
    ActionConstraint, BinaryOp, Clause, Effect, EntityOrSlot, EntityType, EntityUID, Expr, Literal,
    Name, PatternElem, Policy, PrincipalConstraint, PstConstructionError, ResourceConstraint,
    SlotId, UnaryOp, Var,
};
use crate::ast;
use crate::expr_builder;
use crate::pst::expr::{ErrorNode, PstBuilder};
use itertools::Itertools;
use std::str::FromStr;
use std::sync::Arc;

impl TryFrom<Policy> for ast::Policy {
    type Error = PstConstructionError;

    fn try_from(policy: Policy) -> Result<Self, Self::Error> {
        // Convert to Template first, then to Policy (following EST pattern)
        let template: ast::Template = policy.try_into()?;
        ast::StaticPolicy::try_from(template)
            .map(Into::into)
            .map_err(|e| {
                PstConstructionError::InvalidConversion(format!(
                    "Failed to convert template to static policy: {:?}",
                    e
                ))
            })
    }
}

impl TryFrom<Policy> for ast::Template {
    type Error = PstConstructionError;

    fn try_from(policy: Policy) -> Result<Self, Self::Error> {
        use crate::expr_builder::ExprBuilder;
        // Convert clauses - fold them into a single expression (following EST pattern)
        let builder = ast::ExprBuilder::<()>::new();
        let mut conds_rev_iter = policy
            .clauses
            .into_iter()
            .map(|clause| match clause {
                Clause::When(expr) => Arc::unwrap_or_clone(expr).try_into(),
                Clause::Unless(expr) => Arc::unwrap_or_clone(expr)
                    .try_into()
                    .map(|x| builder.clone().not(x)),
            })
            .rev()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter();

        let conditions = conds_rev_iter.next().map(|last_expr| {
            conds_rev_iter.fold(last_expr, |acc, prev| builder.clone().and(prev, acc))
        });

        // Convert annotations
        let annotations: ast::Annotations = policy
            .annotations
            .into_iter()
            .map(|(key, val)| {
                let value = if val.is_empty() { None } else { Some(val) };
                (
                    ast::AnyId::new_unchecked(key),
                    ast::Annotation::with_optional_value(value, None),
                )
            })
            .collect();

        Ok(ast::Template::new(
            policy.id.into(),
            None,
            annotations,
            policy.effect.into(),
            policy.principal.try_into()?,
            policy.action.try_into()?,
            policy.resource.try_into()?,
            conditions,
        ))
    }
}

impl TryFrom<PrincipalConstraint> for ast::PrincipalConstraint {
    type Error = PstConstructionError;

    fn try_from(constraint: PrincipalConstraint) -> Result<Self, Self::Error> {
        match constraint {
            PrincipalConstraint::Any => Ok(ast::PrincipalConstraint::any()),
            PrincipalConstraint::Eq(EntityOrSlot::Entity(eos)) => {
                Ok(ast::PrincipalConstraint::is_eq(Arc::new(eos.try_into()?)))
            }
            PrincipalConstraint::In(EntityOrSlot::Entity(eos)) => {
                Ok(ast::PrincipalConstraint::is_in(Arc::new(eos.try_into()?)))
            }
            PrincipalConstraint::Is(entity_type) => Ok(ast::PrincipalConstraint::is_entity_type(
                Arc::new(entity_type.try_into()?),
            )),
            PrincipalConstraint::IsIn(entity_type, EntityOrSlot::Entity(eos)) => {
                Ok(ast::PrincipalConstraint::is_entity_type_in(
                    Arc::new(entity_type.try_into()?),
                    Arc::new(eos.try_into()?),
                ))
            }
            _ => Err(PstConstructionError::NotImplemented("templates".into())),
        }
    }
}

impl TryFrom<ResourceConstraint> for ast::ResourceConstraint {
    type Error = PstConstructionError;

    fn try_from(constraint: ResourceConstraint) -> Result<Self, Self::Error> {
        match constraint {
            ResourceConstraint::Any => Ok(ast::ResourceConstraint::any()),
            ResourceConstraint::Eq(EntityOrSlot::Entity(eos)) => {
                Ok(ast::ResourceConstraint::is_eq(Arc::new(eos.try_into()?)))
            }
            ResourceConstraint::In(EntityOrSlot::Entity(eos)) => {
                Ok(ast::ResourceConstraint::is_in(Arc::new(eos.try_into()?)))
            }
            ResourceConstraint::Is(entity_type) => Ok(ast::ResourceConstraint::is_entity_type(
                Arc::new(entity_type.try_into()?),
            )),
            ResourceConstraint::IsIn(entity_type, EntityOrSlot::Entity(eos)) => {
                Ok(ast::ResourceConstraint::is_entity_type_in(
                    Arc::new(entity_type.try_into()?),
                    Arc::new(eos.try_into()?),
                ))
            }
            _ => Err(PstConstructionError::NotImplemented("templates".into())),
        }
    }
}

impl TryFrom<ActionConstraint> for ast::ActionConstraint {
    type Error = PstConstructionError;

    fn try_from(constraint: ActionConstraint) -> Result<Self, Self::Error> {
        match constraint {
            ActionConstraint::Any => Ok(ast::ActionConstraint::any()),
            ActionConstraint::Eq(uid) => Ok(ast::ActionConstraint::is_eq(uid.try_into()?)),
            ActionConstraint::In(uids) => {
                let ast_uids: Result<Vec<_>, _> =
                    uids.into_iter().map(|uid| uid.try_into()).collect();
                Ok(ast::ActionConstraint::is_in(ast_uids?))
            }
        }
    }
}

fn elements_into_ast_pattern(elems: impl IntoIterator<Item = PatternElem>) -> ast::Pattern {
    let elems = elems.into_iter().map(|elem| match elem {
        PatternElem::Char(c) => ast::PatternElem::Char(c),
        PatternElem::Wildcard => ast::PatternElem::Wildcard,
    });
    ast::Pattern::from_iter(elems)
}

impl TryFrom<Expr> for ast::Expr {
    type Error = PstConstructionError;

    fn try_from(expr: Expr) -> Result<Self, PstConstructionError> {
        expr.try_into_expr::<ast::ExprBuilder<()>>()
    }
}

impl Expr {
    fn try_into_expr<B: expr_builder::ExprBuilder>(self) -> Result<B::Expr, PstConstructionError> {
        let builder = B::new();
        match self {
            Expr::Literal(lit) => match lit {
                Literal::Bool(b) => Ok(builder.val(b)),
                Literal::Long(i) => Ok(builder.val(i)),
                Literal::String(s) => Ok(builder.val(s)),
                Literal::EntityUID(uid) => {
                    let ast_et: ast::EntityType = uid.ty.try_into()?;
                    let ast_eid = ast::Eid::new(uid.eid.as_str());
                    let ast_uid = ast::EntityUID::from_components(ast_et, ast_eid, None);
                    Ok(builder.val(ast_uid))
                }
            },
            Expr::Var(v) => Ok(builder.var(v.into())),
            Expr::Slot(_) => Err(PstConstructionError::NotImplemented("slots".to_string())),
            Expr::UnaryOp { op, expr } => {
                let inner = Arc::unwrap_or_clone(expr).try_into_expr::<B>()?;
                Ok(match op {
                    UnaryOp::Not => builder.not(inner),
                    UnaryOp::Neg => builder.neg(inner),
                    UnaryOp::IsEmpty => builder.is_empty(inner),
                    // The other unary operators are extension functions.
                    _ => match op.to_name() {
                        Some(fn_name) => builder.call_extension_fn(fn_name.clone(), vec![inner]),
                        // This should never occur!
                        None => Err(PstConstructionError::InvalidExpression(format!(
                            "unknown unary operator: {}",
                            op
                        )))?,
                    },
                })
            }
            Expr::BinaryOp { op, left, right } => {
                let left_ast = Arc::unwrap_or_clone(left).try_into_expr::<B>()?;
                let right_ast = Arc::unwrap_or_clone(right).try_into_expr::<B>()?;

                Ok(match op {
                    BinaryOp::Eq => builder.is_eq(left_ast, right_ast),
                    BinaryOp::NotEq => builder.noteq(left_ast, right_ast),
                    BinaryOp::Less => builder.less(left_ast, right_ast),
                    BinaryOp::LessEq => builder.lesseq(left_ast, right_ast),
                    BinaryOp::Greater => builder.greater(left_ast, right_ast),
                    BinaryOp::GreaterEq => builder.greatereq(left_ast, right_ast),
                    BinaryOp::And => builder.and(left_ast, right_ast),
                    BinaryOp::Or => builder.or(left_ast, right_ast),
                    BinaryOp::Add => builder.add(left_ast, right_ast),
                    BinaryOp::Sub => builder.sub(left_ast, right_ast),
                    BinaryOp::Mul => builder.mul(left_ast, right_ast),
                    BinaryOp::In => builder.is_in(left_ast, right_ast),
                    BinaryOp::Contains => builder.contains(left_ast, right_ast),
                    BinaryOp::ContainsAll => builder.contains_all(left_ast, right_ast),
                    BinaryOp::ContainsAny => builder.contains_any(left_ast, right_ast),
                    BinaryOp::GetTag => builder.get_tag(left_ast, right_ast),
                    BinaryOp::HasTag => builder.has_tag(left_ast, right_ast),
                    // The other binary operators are extensions
                    _ => match op.to_name() {
                        Some(fn_name) => {
                            builder.call_extension_fn(fn_name.clone(), vec![left_ast, right_ast])
                        }
                        // This should never occur!
                        None => Err(PstConstructionError::InvalidExpression(format!(
                            "unknown binary operator: {}",
                            op
                        )))?,
                    },
                })
            }
            Expr::Set(exprs) => {
                let ast_exprs: Result<Vec<_>, _> = exprs
                    .into_iter()
                    .map(|e| Arc::unwrap_or_clone(e).try_into_expr::<B>())
                    .collect();
                Ok(builder.set(ast_exprs?))
            }
            Expr::IfThenElse {
                cond,
                then_expr,
                else_expr,
            } => Ok(builder.ite(
                Arc::unwrap_or_clone(cond).try_into_expr::<B>()?,
                Arc::unwrap_or_clone(then_expr).try_into_expr::<B>()?,
                Arc::unwrap_or_clone(else_expr).try_into_expr::<B>()?,
            )),
            Expr::Is {
                expr,
                entity_type,
                in_expr: None,
            } => Ok(builder.is_entity_type(
                Arc::unwrap_or_clone(expr).try_into_expr::<B>()?,
                entity_type.try_into()?,
            )),
            Expr::Is {
                expr,
                entity_type,
                in_expr: Some(e),
            } => Ok(builder.is_in_entity_type(
                Arc::unwrap_or_clone(expr).try_into_expr::<B>()?,
                entity_type.try_into()?,
                Arc::unwrap_or_clone(e).try_into_expr::<B>()?,
            )),
            Expr::GetAttr { expr, attr } => {
                Ok(builder.get_attr(Arc::unwrap_or_clone(expr).try_into_expr::<B>()?, attr))
            }
            Expr::HasAttr { expr, attrs } => {
                Ok(builder
                    .extended_has_attr(Arc::unwrap_or_clone(expr).try_into_expr::<B>()?, &attrs))
            }
            Expr::Like { expr, pattern } => Ok(builder.like(
                Arc::unwrap_or_clone(expr).try_into_expr::<B>()?,
                elements_into_ast_pattern(pattern),
            )),
            Expr::Record(elems) => builder
                .record(
                    elems
                        .into_iter()
                        .map(|(k, v)| Ok((k.into(), Arc::unwrap_or_clone(v).try_into_expr::<B>()?)))
                        .collect::<Result<Vec<_>, PstConstructionError>>()?,
                )
                .map_err(|cstr_err: ast::ExpressionConstructionError| {
                    PstConstructionError::InvalidConversion(cstr_err.to_string())
                }),
            Expr::Unknown { name } => Ok(builder.unknown(ast::Unknown {
                name,
                type_annotation: None,
            })),
            Expr::Error(ErrorNode { error }) => Err(error),
        }
    }
}

impl From<Effect> for ast::Effect {
    fn from(effect: Effect) -> Self {
        match effect {
            Effect::Permit => ast::Effect::Permit,
            Effect::Forbid => ast::Effect::Forbid,
        }
    }
}

impl TryFrom<EntityUID> for ast::EntityUID {
    type Error = PstConstructionError;

    fn try_from(value: EntityUID) -> Result<Self, PstConstructionError> {
        let ast_et: ast::EntityType = value.ty.try_into()?;
        let ast_eid = ast::Eid::new(value.eid.as_str());
        Ok(ast::EntityUID::from_components(ast_et, ast_eid, None))
    }
}

impl TryFrom<EntityOrSlot> for ast::EntityReference {
    type Error = PstConstructionError;

    fn try_from(eos: EntityOrSlot) -> Result<Self, Self::Error> {
        match eos {
            EntityOrSlot::Entity(uid) => Ok(ast::EntityReference::euid(Arc::new(uid.try_into()?))),
            EntityOrSlot::Slot(_) => Err(PstConstructionError::NotImplemented(
                "templates".to_string(),
            )),
        }
    }
}

impl From<ast::EntityType> for EntityType {
    fn from(et: ast::EntityType) -> Self {
        EntityType(et.into_name().into())
    }
}

impl TryFrom<EntityType> for ast::EntityType {
    type Error = PstConstructionError;

    fn try_from(et: EntityType) -> Result<Self, Self::Error> {
        let name: ast::Name = et.0.try_into()?;
        Ok(ast::EntityType::EntityType(name))
    }
}

impl From<ast::Var> for Var {
    fn from(v: ast::Var) -> Self {
        match v {
            ast::Var::Principal => Var::Principal,
            ast::Var::Action => Var::Action,
            ast::Var::Resource => Var::Resource,
            ast::Var::Context => Var::Context,
        }
    }
}

impl From<Var> for ast::Var {
    fn from(v: Var) -> Self {
        match v {
            Var::Principal => ast::Var::Principal,
            Var::Action => ast::Var::Action,
            Var::Resource => ast::Var::Resource,
            Var::Context => ast::Var::Context,
        }
    }
}

impl From<ast::Name> for Name {
    fn from(name: ast::Name) -> Self {
        let ast::Name {
            0: ast::InternalName { id, path, .. },
        } = name;
        Name {
            id: id.into_smolstr(),
            namespace: Arc::new(
                Arc::unwrap_or_clone(path)
                    .into_iter()
                    .map(|id| id.to_smolstr())
                    .collect(),
            ),
        }
    }
}

impl TryFrom<Name> for ast::Name {
    type Error = PstConstructionError;

    fn try_from(name: Name) -> Result<Self, Self::Error> {
        let basename = ast::Id::from_str(&name.id)?;
        let path: Vec<ast::Id> = name
            .namespace
            .iter()
            .map(|s| ast::Id::from_str(s.as_str()))
            .try_collect()?;
        Ok(ast::Name(ast::InternalName::new(basename, path, None)))
    }
}

impl From<ast::SlotId> for SlotId {
    fn from(slot: ast::SlotId) -> Self {
        match slot.0 {
            ast::ValidSlotId::Principal => SlotId::Principal,
            ast::ValidSlotId::Resource => SlotId::Resource,
        }
    }
}

impl From<SlotId> for ast::SlotId {
    fn from(slot: SlotId) -> Self {
        match slot {
            SlotId::Principal => ast::SlotId::principal(),
            SlotId::Resource => ast::SlotId::resource(),
        }
    }
}

impl From<PatternElem> for ast::PatternElem {
    fn from(elem: PatternElem) -> Self {
        match elem {
            PatternElem::Char(c) => ast::PatternElem::Char(c),
            PatternElem::Wildcard => ast::PatternElem::Wildcard,
        }
    }
}

impl From<ast::Pattern> for Vec<PatternElem> {
    fn from(pattern: ast::Pattern) -> Self {
        pattern
            .iter()
            .map(|elem| match elem {
                ast::PatternElem::Char(c) => PatternElem::Char(*c),
                ast::PatternElem::Wildcard => PatternElem::Wildcard,
            })
            .collect()
    }
}

impl From<ast::Literal> for Literal {
    fn from(value: ast::Literal) -> Self {
        match value {
            ast::Literal::Bool(b) => Literal::Bool(b),
            ast::Literal::Long(i) => Literal::Long(i),
            ast::Literal::String(s) => Literal::String(s),
            ast::Literal::EntityUID(uid) => Literal::EntityUID(Arc::unwrap_or_clone(uid).into()),
        }
    }
}

impl From<ast::EntityUID> for EntityUID {
    fn from(uid: ast::EntityUID) -> Self {
        let (ty, eid) = uid.components();
        EntityUID {
            ty: ty.into(),
            eid: eid.into_smolstr(),
        }
    }
}

impl From<ast::Expr> for Expr {
    fn from(ast_expr: ast::Expr) -> Self {
        ast::Expr::into_expr::<PstBuilder>(ast_expr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    /// Helper to create AST expressions from Cedar text
    fn parse_expr(s: &str) -> ast::Expr {
        parser::parse_expr(s).expect("parse failed")
    }

    /// Test roundtrip: ast::Expr -> pst::Expr -> ast::Expr
    fn assert_expr_roundtrip(ast_expr: ast::Expr) {
        let pst_expr: Expr = ast_expr.clone().into();
        let ast_expr2: ast::Expr = pst_expr.try_into().expect("conversion failed");
        assert_eq!(ast_expr, ast_expr2, "roundtrip failed");
    }

    #[test]
    fn test_literal_roundtrips() {
        let cases = ["true", "false", "42", r#""hello""#];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_variable_roundtrips() {
        let cases = ["principal", "action", "resource", "context"];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_unary_op_roundtrips() {
        let cases = ["!true", "-42", "[].isEmpty()"];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    /// Test the binary operators that roundtrip -- not all do
    fn test_binary_op_roundtrips() {
        let cases = [
            "1 + 2",
            "5 - 3",
            "2 * 3",
            "1 == 2",
            "1 != 2",
            "1 < 2",
            "1 <= 2",
            "1 > 2",
            "1 >= 2",
            "true && false",
            "true || false",
            r#""a" in "abc""#,
            r#"User::"alice" in Group::"admins""#,
            r#"[1, 2, 3].contains(2)"#,
            r#"[1, 2].containsAll([1])"#,
            r#"[1, 2].containsAny([2, 3])"#,
            r#"User::"alice".getTag("role")"#,
            r#"User::"alice".hasTag("role")"#,
        ];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_if_then_else_roundtrip() {
        let expr = parse_expr("if true then 1 else 2");
        assert_expr_roundtrip(expr);
    }

    #[test]
    fn test_set_roundtrips() {
        let cases = ["[]", "[1]", "[1, 2, 3]"];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_record_roundtrips() {
        let cases = [
            "{}",
            r#"{"a": 1}"#,
            r#"{"a": 1, "b": 2}"#,
            r#"{"nested": {"x": 1}}"#,
            r#"{"if": 1}"#,
            r#"{"a-b": 1}"#,
        ];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_entity_uid_roundtrip() {
        let cases = [r#"User::"alice""#, r#"MyApp::User::"alice""#];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_get_attr_roundtrips() {
        let cases = [r#"principal.name"#, r#"resource.owner.id"#];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_has_attr_roundtrip() {
        let expr = parse_expr(r#"principal has name"#);
        assert_expr_roundtrip(expr);
    }

    #[test]
    fn test_like_roundtrip() {
        let cases = [
            r#"principal.name like "a*b""#,
            r#""test" like "*""#,
            r#""test" like "*est""#,
            r#""test" like "test*""#,
        ];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_is_roundtrip() {
        let cases = [
            r#"principal is User"#,
            r#"principal is MyApp::User"#,
            r#"principal is User in Group::"admins""#,
            r#"principal is User in Group::"admins" || principal is User in Group::"users""#,
        ];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_function_call_roundtrips() {
        let cases = [
            r#"decimal("1.23")"#,
            r#"ip("127.0.0.1")"#,
            r#"datetime("2024-01-01")"#,
            r#"ip("127.0.0.1").isIpv4()"#,
            r#"ip("127.0.0.1").isInRange(ip("127.0.0.0/24"))"#,
        ];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    /// Test that extension methods that normalize to operators convert correctly
    /// These don't roundtrip to identical AST, but should convert without error
    #[test]
    fn test_extension_method_normalization() {
        let cases = [
            (
                r#"decimal("1.23").lessThan(decimal("2.0"))"#,
                "decimal lessThan -> <",
            ),
            (
                r#"decimal("1.23").lessThanOrEqual(decimal("2.0"))"#,
                "decimal lessThanOrEqual -> <=",
            ),
            (
                r#"decimal("1.23").greaterThan(decimal("2.0"))"#,
                "decimal greaterThan -> >",
            ),
            (
                r#"decimal("1.23").greaterThanOrEqual(decimal("2.0"))"#,
                "decimal greaterThanOrEqual -> >=",
            ),
        ];

        for (expr_str, desc) in cases {
            let ast_expr = parse_expr(expr_str);
            // Convert to PST
            let pst_expr: Expr = ast_expr.into();
            // Convert back to AST - should succeed even if structure differs
            let _ast_expr2: ast::Expr = pst_expr.try_into().expect(desc);
        }
    }

    #[test]
    fn test_complex_nested_expression() {
        let cases = [
            r#"if principal.age >= 18 && resource.public == true then
                    [1, 2, 3].contains(action.level)
                else
                    false"#,
            r#"((1 + 2) * 3) - 4"#,
            r#"!(!true)"#,
            r#"true && (false || true)"#,
            r#"principal has name && principal has age"#,
        ];

        for expr_str in cases {
            let expr = parse_expr(expr_str);
            assert_expr_roundtrip(expr);
        }
    }

    #[test]
    fn test_unknown_expr() {
        // Unknown is created programmatically, not parsed
        use crate::ast;
        let unknown = ast::Unknown::new_untyped("test");
        let ast_expr = ast::Expr::unknown(unknown);
        let pst_expr: Expr = ast_expr.clone().into();
        let ast_expr2: ast::Expr = pst_expr.try_into().expect("conversion failed");
        assert_eq!(ast_expr, ast_expr2);
    }

    /// Test PST policy -> AST conversion (one direction only)
    #[test]
    fn test_policy_to_ast_conversion() {
        use crate::pst::{
            ActionConstraint, Clause, Effect, Policy, PolicyID, PrincipalConstraint,
            ResourceConstraint,
        };
        use std::collections::BTreeMap;

        // Helper to normalize whitespace for comparison
        let normalize = |s: &str| -> String {
            s.replace('\n', " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };

        let cases = [
            (
                Policy {
                    id: PolicyID("policy0".into()),
                    effect: Effect::Permit,
                    principal: PrincipalConstraint::Any,
                    action: ActionConstraint::Any,
                    resource: ResourceConstraint::Any,
                    clauses: vec![],
                    annotations: BTreeMap::new(),
                },
                "permit( principal, action, resource );",
                "minimal permit policy",
            ),
            (
                Policy {
                    id: PolicyID("policy1".into()),
                    effect: Effect::Forbid,
                    principal: PrincipalConstraint::Any,
                    action: ActionConstraint::Any,
                    resource: ResourceConstraint::Any,
                    clauses: vec![],
                    annotations: BTreeMap::new(),
                },
                "forbid( principal, action, resource );",
                "forbid policy",
            ),
            (
                Policy {
                    id: PolicyID("policy2".into()),
                    effect: Effect::Permit,
                    principal: PrincipalConstraint::Any,
                    action: ActionConstraint::Any,
                    resource: ResourceConstraint::Any,
                    clauses: vec![Clause::When(Arc::new(Expr::Literal(Literal::Bool(true))))],
                    annotations: BTreeMap::new(),
                },
                "permit( principal, action, resource ) when { true };",
                "policy with when clause",
            ),
            (
                Policy {
                    id: PolicyID("policy3".into()),
                    effect: Effect::Permit,
                    principal: PrincipalConstraint::Any,
                    action: ActionConstraint::Any,
                    resource: ResourceConstraint::Any,
                    clauses: vec![Clause::Unless(Arc::new(Expr::Literal(Literal::Bool(
                        false,
                    ))))],
                    annotations: BTreeMap::new(),
                },
                "permit( principal, action, resource ) when { !false };",
                "policy with unless clause",
            ),
            (
                Policy {
                    id: PolicyID("policy4".into()),
                    effect: Effect::Permit,
                    principal: PrincipalConstraint::Any,
                    action: ActionConstraint::Any,
                    resource: ResourceConstraint::Any,
                    clauses: vec![
                        Clause::When(Arc::new(Expr::Literal(Literal::Bool(true)))),
                        Clause::Unless(Arc::new(Expr::Literal(Literal::Bool(false)))),
                    ],
                    annotations: BTreeMap::new(),
                },
                "permit( principal, action, resource ) when { true && (!false) };",
                "policy with when and unless",
            ),
            (
                Policy {
                    id: PolicyID("policy5".into()),
                    effect: Effect::Permit,
                    principal: PrincipalConstraint::Any,
                    action: ActionConstraint::Any,
                    resource: ResourceConstraint::Any,
                    clauses: vec![],
                    annotations: [("id".to_string(), "test".to_smolstr())]
                        .into_iter()
                        .collect(),
                },
                "@id(\"test\") permit( principal, action, resource );",
                "policy with annotation",
            ),
        ];

        for (pst_policy, expected_output, desc) in cases {
            let ast_policy: ast::Policy = pst_policy.try_into().expect("pst->ast failed");
            let actual = normalize(&ast_policy.to_string());
            let expected = normalize(expected_output);
            assert_eq!(actual, expected, "failed: {}", desc);
        }
    }

    /// Test policy constraints (principal, action, resource)
    #[test]
    fn test_policy_constraint_conversions() {
        use crate::pst::{
            ActionConstraint, Effect, EntityOrSlot, EntityType, EntityUID, Name, Policy, PolicyID,
            PrincipalConstraint, ResourceConstraint,
        };
        use std::collections::BTreeMap;

        let normalize = |s: &str| -> String {
            s.replace('\n', " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };

        let user_alice = EntityUID {
            ty: EntityType(Name {
                id: "User".into(),
                namespace: Arc::new(vec![]),
            }),
            eid: "alice".into(),
        };

        let action_view = EntityUID {
            ty: EntityType(Name {
                id: "Action".into(),
                namespace: Arc::new(vec![]),
            }),
            eid: "view".into(),
        };

        let cases = [
            (
                Policy {
                    id: PolicyID("p0".into()),
                    effect: Effect::Permit,
                    principal: PrincipalConstraint::Eq(EntityOrSlot::Entity(user_alice.clone())),
                    action: ActionConstraint::Any,
                    resource: ResourceConstraint::Any,
                    clauses: vec![],
                    annotations: BTreeMap::new(),
                },
                "permit( principal == User::\"alice\", action, resource );",
                "principal eq constraint",
            ),
            (
                Policy {
                    id: PolicyID("p1".into()),
                    effect: Effect::Permit,
                    principal: PrincipalConstraint::In(EntityOrSlot::Entity(user_alice.clone())),
                    action: ActionConstraint::Any,
                    resource: ResourceConstraint::Any,
                    clauses: vec![],
                    annotations: BTreeMap::new(),
                },
                "permit( principal in User::\"alice\", action, resource );",
                "principal in constraint",
            ),
            (
                Policy {
                    id: PolicyID("p2".into()),
                    effect: Effect::Permit,
                    principal: PrincipalConstraint::Is(EntityType(Name {
                        id: "User".into(),
                        namespace: Arc::new(vec![]),
                    })),
                    action: ActionConstraint::Any,
                    resource: ResourceConstraint::Any,
                    clauses: vec![],
                    annotations: BTreeMap::new(),
                },
                "permit( principal is User, action, resource );",
                "principal is constraint",
            ),
            (
                Policy {
                    id: PolicyID("p3".into()),
                    effect: Effect::Permit,
                    principal: PrincipalConstraint::IsIn(
                        EntityType(Name {
                            id: "User".into(),
                            namespace: Arc::new(vec![]),
                        }),
                        EntityOrSlot::Entity(user_alice.clone()),
                    ),
                    action: ActionConstraint::Any,
                    resource: ResourceConstraint::Any,
                    clauses: vec![],
                    annotations: BTreeMap::new(),
                },
                "permit( principal is User in User::\"alice\", action, resource );",
                "principal is-in constraint",
            ),
            (
                Policy {
                    id: PolicyID("p4".into()),
                    effect: Effect::Permit,
                    principal: PrincipalConstraint::Any,
                    action: ActionConstraint::Eq(action_view.clone()),
                    resource: ResourceConstraint::Any,
                    clauses: vec![],
                    annotations: BTreeMap::new(),
                },
                "permit( principal, action == Action::\"view\", resource );",
                "action eq constraint",
            ),
            (
                Policy {
                    id: PolicyID("p5".into()),
                    effect: Effect::Permit,
                    principal: PrincipalConstraint::Any,
                    action: ActionConstraint::In(vec![action_view.clone()]),
                    resource: ResourceConstraint::Any,
                    clauses: vec![],
                    annotations: BTreeMap::new(),
                },
                "permit( principal, action in [Action::\"view\"], resource );",
                "action in constraint",
            ),
            (
                Policy {
                    id: PolicyID("p6".into()),
                    effect: Effect::Permit,
                    principal: PrincipalConstraint::Any,
                    action: ActionConstraint::Any,
                    resource: ResourceConstraint::In(EntityOrSlot::Entity(user_alice.clone())),
                    clauses: vec![],
                    annotations: BTreeMap::new(),
                },
                "permit( principal, action, resource in User::\"alice\" );",
                "resource in constraint",
            ),
            (
                Policy {
                    id: PolicyID("p7".into()),
                    effect: Effect::Permit,
                    principal: PrincipalConstraint::Any,
                    action: ActionConstraint::Any,
                    resource: ResourceConstraint::Eq(EntityOrSlot::Entity(user_alice.clone())),
                    clauses: vec![],
                    annotations: BTreeMap::new(),
                },
                "permit( principal, action, resource == User::\"alice\" );",
                "resource eq constraint",
            ),
            (
                Policy {
                    id: PolicyID("p8".into()),
                    effect: Effect::Permit,
                    principal: PrincipalConstraint::Any,
                    action: ActionConstraint::Any,
                    resource: ResourceConstraint::Is(EntityType(Name {
                        id: "Photo".into(),
                        namespace: Arc::new(vec![]),
                    })),
                    clauses: vec![],
                    annotations: BTreeMap::new(),
                },
                "permit( principal, action, resource is Photo );",
                "resource is constraint",
            ),
            (
                Policy {
                    id: PolicyID("p9".into()),
                    effect: Effect::Permit,
                    principal: PrincipalConstraint::Any,
                    action: ActionConstraint::Any,
                    resource: ResourceConstraint::IsIn(
                        EntityType(Name {
                            id: "Photo".into(),
                            namespace: Arc::new(vec![]),
                        }),
                        EntityOrSlot::Entity(user_alice),
                    ),
                    clauses: vec![],
                    annotations: BTreeMap::new(),
                },
                "permit( principal, action, resource is Photo in User::\"alice\" );",
                "resource is-in constraint",
            ),
        ];

        for (pst_policy, expected_output, desc) in cases {
            let ast_policy: ast::Policy = pst_policy.try_into().expect("pst->ast failed");
            let actual = normalize(&ast_policy.to_string());
            let expected = normalize(expected_output);
            assert_eq!(actual, expected, "failed: {}", desc);
            println!("✓ {}", desc);
        }
    }

    /// Test expressions that get desugared/normalized during AST conversion
    #[test]
    fn test_expression_desugaring() {
        let cases = [
            ("1 != 2", "!(1 == 2)", "!= desugars to !(==)"),
            ("1 > 2", "!(1 <= 2)", "> desugars to !(<=)"),
            ("1 >= 2", "!(1 < 2)", ">= desugars to !(<)"),
        ];

        for (input, expected_output, desc) in cases {
            let ast_expr = parse_expr(input);
            let pst_expr: Expr = ast_expr.into();
            let ast_expr2: ast::Expr = pst_expr.try_into().expect("conversion failed");

            // Normalize both for comparison
            let actual = ast_expr2
                .to_string()
                .replace('\n', " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let expected = expected_output
                .replace('\n', " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");

            assert_eq!(actual, expected, "failed: {}", desc);
        }
    }

    /// Test that ErrorNode in PST results in conversion error
    #[test]
    fn test_error_node_conversion() {
        use crate::pst::expr::ErrorNode;

        let error_expr = Expr::Error(ErrorNode {
            error: PstConstructionError::InvalidExpression("test error".into()),
        });

        let result: Result<ast::Expr, PstConstructionError> = error_expr.try_into();
        assert!(result.is_err(), "ErrorNode should fail conversion");

        match result {
            Err(PstConstructionError::InvalidExpression(msg)) => {
                assert_eq!(msg, "test error");
                println!("✓ ErrorNode correctly produces conversion error");
            }
            Err(e) => panic!("Expected InvalidExpression error, got: {:?}", e),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }
}
