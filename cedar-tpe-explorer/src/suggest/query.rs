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

//! Solver queries: a policy that matches when a residual has a given outcome.

use cedar_policy::pst::{BinaryOp, Expr, Literal, UnaryOp, Var};
use cedar_policy_core::ast::{EntityUID, PolicyID};
use std::sync::Arc;

use crate::analysis;
use crate::eval::Evaluation;
use crate::facts::{AttrFact, Facts, SlotId, SlotValue};
use crate::project::Project;
use crate::values::record_key;

pub(super) fn request_env(facts: &Facts) -> cedar_policy::RequestEnv {
    cedar_policy::RequestEnv::new(
        facts.principal.ty.clone().into(),
        facts.action.clone().into(),
        facts.resource.ty.clone().into(),
    )
}

/// A policy that matches exactly when the residual of `id` evaluates to
/// `satisfied` (without error), for handing to a solver. The request's
/// principal and resource may not be any of `exclude`.
///
/// Error nodes can't be printed as Cedar, so we print "evaluates to
/// true/false" ([`truth_text`]), where errors are unsatisfiable. And when the
/// facts say an optional attribute is present, TPE drops the policy's `has`
/// guard; we add it back so the query typechecks.
pub(super) fn outcome_policy(
    project: &Project,
    facts: &Facts,
    eval: &Evaluation,
    id: &PolicyID,
    satisfied: bool,
    exclude: &[EntityUID],
) -> Result<cedar_policy::Policy, String> {
    let p = eval.policy(id).ok_or_else(|| format!("no policy «{id}»"))?;
    let mut conds = presence_guards(project, facts, &p.residual);
    for u in exclude {
        for (var, ty) in [
            ("principal", &facts.principal.ty),
            ("resource", &facts.resource.ty),
        ] {
            if u.entity_type() == ty {
                conds.push(format!("{var} != {u}"));
            }
        }
    }
    conds.push(format!(
        "({})",
        truth_text(&lift_branches(&p.residual), satisfied)
    ));
    let text = format!(
        "permit (principal, action, resource) when {{ {} }};",
        conds.join(" && ")
    );
    cedar_policy::Policy::parse(Some(cedar_policy::PolicyId::new(id.as_ref())), &text)
        .map_err(|e| format!("could not build a solver query for «{id}»: {e}"))
}

/// An equivalent expression in which no `if`, `&&`, or `||` that contains an
/// error is an operand of another operator, so that evaluating any other
/// node that contains an error always errors, which [`truth_text`] relies on.
///
/// Every other operator evaluates all its operands and errors if any does,
/// so `f(if c then x else y)` can become `if c then f(x) else f(y)`. `a && b`
/// is read as `if a then (if b then true else false) else false`, which also
/// errors when `b` isn't a boolean. The one other lazy operator, `e is T in
/// x`, is `e is T && e in x`.
fn lift_branches(e: &Expr) -> Expr {
    let e = map_children(e, lift_branches);
    if let Expr::Is {
        expr,
        entity_type,
        in_expr: Some(x),
    } = &e
    {
        if analysis::has_error(x) {
            let is = Expr::Is {
                expr: expr.clone(),
                entity_type: entity_type.clone(),
                in_expr: None,
            };
            let is_in = Expr::BinaryOp {
                op: BinaryOp::In,
                left: expr.clone(),
                right: x.clone(),
            };
            return lift_branches(&Expr::BinaryOp {
                op: BinaryOp::And,
                left: Arc::new(is),
                right: Arc::new(is_in),
            });
        }
    }
    if is_branch(&e) {
        return e;
    }
    let operands = analysis::children(&e);
    let Some((i, branch)) = operands
        .into_iter()
        .enumerate()
        .find(|(_, c)| is_branch(c) && analysis::has_error(c))
    else {
        return e;
    };
    let lit = |b: bool| Arc::new(Expr::Literal(Literal::Bool(b)));
    let as_bool = |b: &Arc<Expr>| {
        Arc::new(Expr::IfThenElse {
            cond: b.clone(),
            then_expr: lit(true),
            else_expr: lit(false),
        })
    };
    let (cond, yes, no) = match branch {
        Expr::IfThenElse {
            cond,
            then_expr,
            else_expr,
        } => (cond, then_expr.clone(), else_expr.clone()),
        Expr::BinaryOp {
            op: BinaryOp::And,
            left,
            right,
        } => (left, as_bool(right), lit(false)),
        Expr::BinaryOp { left, right, .. } => (left, lit(true), as_bool(right)),
        _ => return e,
    };
    let with = |x: &Expr| {
        let mut k = 0;
        let replaced = map_children(&e, |c| {
            k += 1;
            if k == i + 1 {
                x.clone()
            } else {
                c.clone()
            }
        });
        Arc::new(lift_branches(&replaced))
    };
    Expr::IfThenElse {
        cond: cond.clone(),
        then_expr: with(&yes),
        else_expr: with(&no),
    }
}

fn is_branch(e: &Expr) -> bool {
    matches!(
        e,
        Expr::IfThenElse { .. }
            | Expr::BinaryOp {
                op: BinaryOp::And | BinaryOp::Or,
                ..
            }
    )
}

/// `e` with each operand replaced by `f(operand)`, in [`analysis::children`] order.
fn map_children(e: &Expr, mut f: impl FnMut(&Expr) -> Expr) -> Expr {
    let mut g = |x: &Arc<Expr>| Arc::new(f(x));
    match e {
        Expr::UnaryOp { op, expr } => Expr::UnaryOp {
            op: *op,
            expr: g(expr),
        },
        Expr::GetAttr { expr, attr } => Expr::GetAttr {
            expr: g(expr),
            attr: attr.clone(),
        },
        Expr::HasAttr { expr, attrs } => Expr::HasAttr {
            expr: g(expr),
            attrs: attrs.clone(),
        },
        Expr::Like { expr, pattern } => Expr::Like {
            expr: g(expr),
            pattern: pattern.clone(),
        },
        Expr::Is {
            expr,
            entity_type,
            in_expr,
        } => Expr::Is {
            expr: g(expr),
            entity_type: entity_type.clone(),
            in_expr: in_expr.as_ref().map(&mut g),
        },
        Expr::BinaryOp { op, left, right } => Expr::BinaryOp {
            op: *op,
            left: g(left),
            right: g(right),
        },
        Expr::IfThenElse {
            cond,
            then_expr,
            else_expr,
        } => Expr::IfThenElse {
            cond: g(cond),
            then_expr: g(then_expr),
            else_expr: g(else_expr),
        },
        Expr::Set(elems) => Expr::Set(elems.iter().map(&mut g).collect()),
        Expr::Record(fields) => {
            Expr::Record(fields.iter().map(|(k, v)| (k.clone(), g(v))).collect())
        }
        other => other.clone(),
    }
}

/// Cedar text that is `true` exactly when `e` evaluates to `want`.
fn truth_text(e: &Expr, want: bool) -> String {
    let t = |e: &Expr| truth_text(e, true);
    let f = |e: &Expr| truth_text(e, false);
    match e {
        Expr::ResidualError => "false".into(),
        Expr::Literal(Literal::Bool(b)) => (*b == want).to_string(),
        Expr::BinaryOp {
            op: BinaryOp::And,
            left,
            right,
        } if want => format!("({}) && ({})", t(left), t(right)),
        Expr::BinaryOp {
            op: BinaryOp::And,
            left,
            right,
        } => format!("({}) || (({}) && ({}))", f(left), t(left), f(right)),
        Expr::BinaryOp {
            op: BinaryOp::Or,
            left,
            right,
        } if want => format!("({}) || (({}) && ({}))", t(left), f(left), t(right)),
        Expr::BinaryOp {
            op: BinaryOp::Or,
            left,
            right,
        } => format!("({}) && ({})", f(left), f(right)),
        Expr::UnaryOp {
            op: UnaryOp::Not,
            expr,
        } => truth_text(expr, !want),
        Expr::IfThenElse {
            cond,
            then_expr,
            else_expr,
        } => format!(
            "(({}) && ({})) || (({}) && ({}))",
            t(cond),
            truth_text(then_expr, want),
            f(cond),
            truth_text(else_expr, want)
        ),
        _ if analysis::has_error(e) => "false".into(),
        _ if want => format!("({e})"),
        _ => format!("!({e})"),
    }
}

/// `has`/`hasTag` guards for optional attributes and tags that the residual
/// reads and the facts say are present, outermost first.
fn presence_guards(project: &Project, facts: &Facts, e: &Expr) -> Vec<String> {
    let mut found: Vec<(usize, String)> = Vec::new();
    collect_guards(project, facts, e, &mut found);
    found.sort_by_key(|(depth, _)| *depth);
    let mut out: Vec<String> = Vec::new();
    for (_, g) in found {
        if !out.contains(&g) {
            out.push(g);
        }
    }
    out
}

fn known_present(f: Option<&SlotValue>) -> bool {
    let present = |f: &AttrFact| {
        matches!(
            f,
            AttrFact::Value(_) | AttrFact::Unknown | AttrFact::Record(_)
        )
    };
    match f {
        Some(SlotValue::Attr(f) | SlotValue::Tag(Some(f))) => present(f),
        _ => false,
    }
}

/// The base of an attribute access chain that has slots.
enum Base {
    Context,
    Entity(EntityUID),
}

impl Base {
    fn of(e: &Expr) -> Option<Self> {
        match e {
            Expr::Var(Var::Context) => Some(Self::Context),
            Expr::Literal(Literal::EntityUID(u)) => analysis::ast_uid(u).map(Self::Entity),
            _ => None,
        }
    }

    fn slot(&self, path: &[smol_str::SmolStr]) -> SlotId {
        match self {
            Self::Context => SlotId::Context(path.to_vec()),
            Self::Entity(u) => SlotId::Attr(u.clone(), path.to_vec()),
        }
    }

    fn text(&self) -> String {
        match self {
            Self::Context => "context".into(),
            Self::Entity(u) => u.to_string(),
        }
    }
}

fn collect_guards(project: &Project, facts: &Facts, e: &Expr, out: &mut Vec<(usize, String)>) {
    if let Expr::GetAttr { .. } | Expr::HasAttr { .. } = e {
        let (base, path) = analysis::attr_chain(e);
        if let Some(base) = Base::of(base) {
            // A top-level `has` reads only the prefix; its last step is the test.
            let reads = match e {
                Expr::HasAttr { .. } => path.len().saturating_sub(1),
                _ => path.len(),
            };
            let mut prefix = base.text();
            for (i, a) in path.iter().enumerate().take(reads) {
                let slot = base.slot(path.get(..=i).unwrap_or_default());
                if known_present(facts.get(&slot).as_ref())
                    && !facts.slot_required(&slot, project.vschema())
                {
                    out.push((i, format!("{prefix} has {}", record_key(a))));
                }
                prefix.push_str(&access(a));
            }
        }
    }
    if let Expr::BinaryOp {
        op: BinaryOp::GetTag,
        left,
        right,
    } = e
    {
        if let (Expr::Literal(Literal::EntityUID(u)), Expr::Literal(Literal::String(k))) =
            (left.as_ref(), right.as_ref())
        {
            if let Some(uid) = analysis::ast_uid(u) {
                if known_present(facts.get(&SlotId::Tag(uid.clone(), k.clone())).as_ref()) {
                    out.push((0, format!("{uid}.hasTag(\"{}\")", k.escape_debug())));
                }
            }
        }
    }
    for c in analysis::children(e) {
        collect_guards(project, facts, c, out);
    }
}

/// `.a` / `["a b"]`.
fn access(a: &str) -> String {
    if record_key(a) == a {
        format!(".{a}")
    } else {
        format!("[\"{}\"]", a.escape_debug())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy::pst::Clause;
    use cedar_policy::{
        Authorizer, Context, Decision, Entities, PolicySet, Request, RestrictedExpression,
    };

    /// Whether `cond` evaluates to true for a `Doc` resource and this context.
    fn eval_true(cond: &str, b: bool, n: i64) -> bool {
        let policies: PolicySet = format!("permit(principal, action, resource) when {{ {cond} }};")
            .parse()
            .unwrap();
        let context = Context::from_pairs([
            ("b".to_string(), RestrictedExpression::new_bool(b)),
            ("n".to_string(), RestrictedExpression::new_long(n)),
        ])
        .unwrap();
        let r = Request::new(
            r#"User::"u""#.parse().unwrap(),
            r#"Action::"a""#.parse().unwrap(),
            r#"Doc::"d""#.parse().unwrap(),
            context,
            None,
        )
        .unwrap();
        Authorizer::new()
            .is_authorized(&r, &policies, &Entities::empty())
            .decision()
            == Decision::Allow
    }

    /// The condition's PST, with `context.err` (which errors: the request has
    /// no such attribute) as a residual error.
    fn residual(cond: &str) -> Expr {
        fn mark(e: &Expr) -> Expr {
            match e {
                Expr::GetAttr { expr, attr }
                    if attr == "err" && matches!(expr.as_ref(), Expr::Var(Var::Context)) =>
                {
                    Expr::ResidualError
                }
                _ => map_children(e, mark),
            }
        }
        let policy = cedar_policy::Policy::parse(
            None,
            format!("permit(principal, action, resource) when {{ {cond} }};"),
        )
        .unwrap();
        let pst = policy.to_pst().unwrap();
        let when = pst.body().clauses().iter().find_map(|c| match c {
            Clause::When(c) => Some(c.clone()),
            Clause::Unless(_) => None,
        });
        mark(&when.unwrap())
    }

    /// The solver query for each outcome holds exactly when Cedar evaluates
    /// the condition to that outcome.
    #[test]
    fn truth_text_matches_cedar_error_semantics() {
        let conds = [
            "(if context.b then context.err else context.n) == 1",
            "(if context.b then context.err + 1 else 0) + context.n > 0",
            "[if context.b then context.err else 1, context.n].contains(1)",
            "context.n == 1 && (if context.b then context.err else true)",
            "(context.b || context.err) == context.b",
            "!(context.b && context.err)",
            "(context.b && context.err) || context.n == 1",
            r#"resource is Admin in context.err"#,
            r#"resource is Doc in context.err"#,
            r#"resource is Admin in (if context.b then context.err else Group::"g")"#,
            "if context.err then true else context.b",
        ];
        for cond in conds {
            let e = lift_branches(&residual(cond));
            for want in [true, false] {
                let text = truth_text(&e, want);
                for (b, n) in [(true, 0), (true, 1), (false, 0), (false, 1)] {
                    let actual = if want {
                        eval_true(cond, b, n)
                    } else {
                        eval_true(&format!("!({cond})"), b, n)
                    };
                    assert_eq!(
                        eval_true(&text, b, n),
                        actual,
                        "{cond} => {want} with b={b}, n={n}: query `{text}`"
                    );
                }
            }
        }
    }
}
