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

//! Which facts a residual still depends on, and what its outcome can be.
//!
//! Residuals are policy syntax trees ([`cedar_policy::pst::Expr`]). An *atom*
//! is a maximal sub-expression blocked on one [`SlotId`], e.g. `principal`,
//! `context.authn_method`, or `User::"alice" in Group::"admins"`.

use cedar_policy::pst::{self, BinaryOp, Expr, Literal, Var};
use cedar_policy_core::ast::{Eid, EntityType, EntityUID};
use cedar_policy_core::validator::types::{Attributes, Type};
use cedar_policy_core::validator::ValidatorSchema;
use smol_str::SmolStr;
use std::str::FromStr;

use crate::facts::{attr_at, context_attrs, SlotId};
use crate::{Facts, Project};

/// Why a residual depends on a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NeedKind {
    /// The principal/resource id itself is tested.
    Id,
    /// Data about the principal/resource is read, which first needs its id.
    BlockedOnId,
    Value,
    Parents,
    Tags,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Need {
    pub slot: SlotId,
    pub kind: NeedKind,
}

/// Schema information for typing attribute paths, since residuals carry no types.
#[derive(Debug, Clone, Copy)]
pub struct TypeEnv<'a> {
    pub schema: &'a ValidatorSchema,
    pub action: &'a EntityUID,
}

impl<'a> TypeEnv<'a> {
    pub fn new(project: &'a Project, facts: &'a Facts) -> Self {
        Self {
            schema: project.vschema(),
            action: &facts.action,
        }
    }

    fn entity_attrs(&self, ety: &EntityType) -> Option<&'a Attributes> {
        Some(self.schema.get_entity_type(ety)?.attributes())
    }

    fn context_attrs(&self) -> Option<&'a Attributes> {
        context_attrs(self.schema, self.action)
    }
}

pub fn ast_uid(u: &pst::EntityUID) -> Option<EntityUID> {
    let ty = EntityType::from_str(&u.ty.to_string()).ok()?;
    Some(EntityUID::from_components(
        ty,
        Eid::new(u.eid.clone()),
        None,
    ))
}

fn as_entity(e: &Expr) -> Option<EntityUID> {
    match e {
        Expr::Literal(Literal::EntityUID(u)) => ast_uid(u),
        _ => None,
    }
}

fn as_string(e: &Expr) -> Option<&SmolStr> {
    match e {
        Expr::Literal(Literal::String(s)) => Some(s),
        _ => None,
    }
}

/// If `e` is an atom, the slot it depends on.
pub fn atom(e: &Expr, env: TypeEnv<'_>) -> Option<Need> {
    let need = |slot, kind| Some(Need { slot, kind });
    match e {
        Expr::Var(Var::Principal) => need(SlotId::Principal, NeedKind::Id),
        Expr::Var(Var::Resource) => need(SlotId::Resource, NeedKind::Id),
        Expr::GetAttr { .. } | Expr::HasAttr { .. } => attr_chain_atom(e, env),
        Expr::BinaryOp {
            op: BinaryOp::In,
            left,
            ..
        } => need(SlotId::Parents(as_entity(left)?), NeedKind::Parents),
        Expr::BinaryOp {
            op: BinaryOp::GetTag | BinaryOp::HasTag,
            left,
            right,
        } => {
            as_string(right)?;
            need(SlotId::Tags(as_entity(left)?), NeedKind::Tags)
        }
        _ => None,
    }
}

/// Split an attribute access chain into its base and the attributes read.
pub fn attr_chain(e: &Expr) -> (&Expr, Vec<SmolStr>) {
    let mut path: Vec<SmolStr> = Vec::new();
    // `e has a.b.c` tests a path below `e`.
    let mut cur = if let Expr::HasAttr { expr, attrs } = e {
        path.extend(attrs.iter().rev().cloned());
        expr.as_ref()
    } else {
        e
    };
    while let Expr::GetAttr { expr, attr } = cur {
        path.push(attr.clone());
        cur = expr.as_ref();
    }
    path.reverse();
    (cur, path)
}

/// Cut `path` after its first entity-typed step: what follows is blocked on
/// that entity reference.
fn truncate_at_entity(base: Option<&Attributes>, mut path: Vec<SmolStr>) -> Vec<SmolStr> {
    if let Some(base) = base {
        let first_entity = (1..=path.len()).find(|&i| {
            path.get(..i)
                .and_then(|p| attr_at(base, p))
                .is_some_and(|a| matches!(a.attr_type.as_ref(), Type::Entity(_)))
        });
        if let Some(i) = first_entity {
            path.truncate(i);
        }
    }
    path
}

fn attr_chain_atom(e: &Expr, env: TypeEnv<'_>) -> Option<Need> {
    let (base, path) = attr_chain(e);
    let (slot, kind) = match base {
        Expr::Var(Var::Principal) => (SlotId::Principal, NeedKind::BlockedOnId),
        Expr::Var(Var::Resource) => (SlotId::Resource, NeedKind::BlockedOnId),
        Expr::Var(Var::Context) => (
            SlotId::Context(truncate_at_entity(env.context_attrs(), path)),
            NeedKind::Value,
        ),
        _ => {
            let uid = as_entity(base)?;
            let path = truncate_at_entity(env.entity_attrs(uid.entity_type()), path);
            (SlotId::Attr(uid, path), NeedKind::Value)
        }
    };
    Some(Need { slot, kind })
}

/// Immediate sub-expressions, in print order.
pub fn children(e: &Expr) -> Vec<&Expr> {
    match e {
        Expr::UnaryOp { expr, .. }
        | Expr::GetAttr { expr, .. }
        | Expr::HasAttr { expr, .. }
        | Expr::Like { expr, .. } => vec![expr.as_ref()],
        Expr::Is { expr, in_expr, .. } => std::iter::once(expr.as_ref())
            .chain(in_expr.as_deref())
            .collect(),
        Expr::BinaryOp { left, right, .. } => vec![left.as_ref(), right.as_ref()],
        Expr::IfThenElse {
            cond,
            then_expr,
            else_expr,
        } => vec![cond.as_ref(), then_expr.as_ref(), else_expr.as_ref()],
        Expr::Set(elems) => elems.iter().map(AsRef::as_ref).collect(),
        Expr::Record(fields) => fields.values().map(AsRef::as_ref).collect(),
        _ => vec![],
    }
}

/// Visit `e` and its sub-expressions, pre-order. `f` returns whether to
/// descend into the node's children.
fn walk<'e>(e: &'e Expr, f: &mut impl FnMut(&'e Expr) -> bool) {
    if f(e) {
        for c in children(e) {
            walk(c, f);
        }
    }
}

fn push_unique<T: PartialEq>(out: &mut Vec<T>, x: T) {
    if !out.contains(&x) {
        out.push(x);
    }
}

/// The slots a residual depends on, in first-occurrence order.
pub fn needs(e: &Expr, env: TypeEnv<'_>) -> Vec<Need> {
    let mut out = Vec::new();
    walk(e, &mut |x| match atom(x, env) {
        Some(n) => {
            push_unique(&mut out, n);
            // `E in rhs` also depends on whatever `rhs` does.
            matches!(
                x,
                Expr::BinaryOp {
                    op: BinaryOp::In,
                    ..
                }
            )
        }
        None => true,
    });
    out
}

pub fn has_error(e: &Expr) -> bool {
    let mut found = false;
    walk(e, &mut |x| {
        found |= matches!(x, Expr::ResidualError);
        !found
    });
    found
}

/// Entity uids that appear literally in `e`.
pub fn literal_uids(e: &Expr) -> Vec<EntityUID> {
    let mut out = Vec::new();
    walk(e, &mut |x| {
        if let Some(u) = as_entity(x) {
            push_unique(&mut out, u);
        }
        true
    });
    out
}

/// Literal tag keys tested on `entity` via `getTag`/`hasTag`.
pub fn tag_keys(e: &Expr, entity: &EntityUID) -> Vec<SmolStr> {
    let mut out = Vec::new();
    walk(e, &mut |x| {
        if let Expr::BinaryOp {
            op: BinaryOp::GetTag | BinaryOp::HasTag,
            left,
            right,
        } = x
        {
            if let (Some(u), Some(k)) = (as_entity(left), as_string(right)) {
                if &u == entity {
                    push_unique(&mut out, k.clone());
                }
            }
        }
        true
    });
    out
}

/// The outcomes a boolean expression might have: a subset of
/// {true, false, error}.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcomes {
    pub t: bool,
    pub f: bool,
    pub err: bool,
}

impl Outcomes {
    const ANY: Self = Self::new(true, true, true);
    const NONE: Self = Self::new(false, false, false);

    const fn new(t: bool, f: bool, err: bool) -> Self {
        Self { t, f, err }
    }

    const fn union(self, o: Self) -> Self {
        Self::new(self.t || o.t, self.f || o.f, self.err || o.err)
    }
}

/// The possible outcomes of `e`, through `&&`, `||`, `!`, and `if`.
/// Anything else may have any outcome.
pub fn outcomes(e: &Expr) -> Outcomes {
    let when = |cond: bool, e: &Expr| if cond { outcomes(e) } else { Outcomes::NONE };
    match e {
        Expr::Literal(Literal::Bool(b)) => Outcomes::new(*b, !*b, false),
        Expr::ResidualError => Outcomes::new(false, false, true),
        Expr::BinaryOp {
            op: BinaryOp::And,
            left,
            right,
        } => {
            let l = outcomes(left);
            Outcomes::new(false, l.f, l.err).union(when(l.t, right))
        }
        Expr::BinaryOp {
            op: BinaryOp::Or,
            left,
            right,
        } => {
            let l = outcomes(left);
            Outcomes::new(l.t, false, l.err).union(when(l.f, right))
        }
        Expr::UnaryOp {
            op: pst::UnaryOp::Not,
            expr,
        } => {
            let x = outcomes(expr);
            Outcomes::new(x.f, x.t, x.err)
        }
        Expr::IfThenElse {
            cond,
            then_expr,
            else_expr,
        } => {
            let c = outcomes(cond);
            Outcomes::new(false, false, c.err)
                .union(when(c.t, then_expr))
                .union(when(c.f, else_expr))
        }
        _ => Outcomes::ANY,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conclusion {
    /// The outcomes are exactly {true}.
    Applies,
    /// True is not a possible outcome.
    CannotApply,
    Unknown,
}

/// What a policy condition's possible outcomes tell us.
pub fn conclude(e: &Expr) -> Conclusion {
    match outcomes(e) {
        Outcomes { t: false, .. } => Conclusion::CannotApply,
        Outcomes {
            t: true,
            f: false,
            err: false,
        } => Conclusion::Applies,
        _ => Conclusion::Unknown,
    }
}
