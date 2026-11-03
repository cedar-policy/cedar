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

#![expect(clippy::unwrap_used, reason = "test code")]

use cedar_tpe_explorer::doc::{render_facts, render_residuals, Gutter};
use cedar_tpe_explorer::{evaluate, AttrFact, Facts, PartialUid, Project, SlotId, SlotValue};

fn project() -> Project {
    Project::new(
        include_str!("../sample-data/photoapp/photoapp.cedarschema"),
        include_str!("../sample-data/photoapp/policies.cedar"),
    )
    .unwrap()
}

fn dump(lines: &[cedar_tpe_explorer::doc::Line]) -> String {
    lines
        .iter()
        .map(|l| {
            let g = match l.gutter {
                Gutter::None => "  ".to_string(),
                Gutter::Bare => String::new(),
                Gutter::Needed => "◀ ".to_string(),
                Gutter::Policy(m) => format!("{} ", m.symbol()),
            };
            format!("{g}{}", l.text())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn walkthrough() {
    let p = project();
    let s = p.vschema();
    let mut f = Facts::initial(&p).unwrap();
    let e = evaluate(&p, &f).unwrap();
    println!(
        "{}\n----\n{}",
        dump(&render_facts(&p, &f, Some(&e))),
        dump(&render_residuals(
            cedar_tpe_explorer::analysis::TypeEnv::new(&p, &f),
            &e,
            70
        ))
    );
    println!("{}", e.describe_slot_need(&SlotId::Principal));
    println!("{}", e.describe_slot_need(&SlotId::Resource));
    assert_eq!(e.decision, None);

    f.set(
        &SlotId::Principal,
        SlotValue::Uid(PartialUid {
            ty: f.principal.ty.clone(),
            eid: Some(cedar_policy_core::ast::Eid::new("alice")),
        }),
        s,
    )
    .unwrap();
    f.set(
        &SlotId::Resource,
        SlotValue::Uid(PartialUid {
            ty: f.resource.ty.clone(),
            eid: Some(cedar_policy_core::ast::Eid::new("vacation.jpg")),
        }),
        s,
    )
    .unwrap();
    let e = evaluate(&p, &f).unwrap();
    println!(
        "{}\n----\n{}",
        dump(&render_facts(&p, &f, Some(&e))),
        dump(&render_residuals(
            cedar_tpe_explorer::analysis::TypeEnv::new(&p, &f),
            &e,
            70
        ))
    );
    let photo = f.resource.uid().unwrap();
    f.set(
        &SlotId::Attr(photo, vec!["private".into()]),
        SlotValue::Attr(AttrFact::Value(false.into())),
        s,
    )
    .unwrap();
    let e = evaluate(&p, &f).unwrap();
    println!(
        "{}",
        dump(&render_residuals(
            cedar_tpe_explorer::analysis::TypeEnv::new(&p, &f),
            &e,
            70
        ))
    );
    let alice = f.principal.uid().unwrap();
    println!("{}", e.describe_slot_need(&SlotId::Parents(alice.clone())));
    let admins: cedar_policy_core::ast::EntityUID =
        r#"PhotoApp::UserGroup::"admins""#.parse().unwrap();
    f.set(
        &SlotId::Parents(alice),
        SlotValue::Parents(Some([admins].into())),
        s,
    )
    .unwrap();
    let e = evaluate(&p, &f).unwrap();
    println!(
        "{}\n{}",
        dump(&render_residuals(
            cedar_tpe_explorer::analysis::TypeEnv::new(&p, &f),
            &e,
            70
        )),
        e.describe_settled()
    );
    assert_eq!(
        e.decision,
        Some(cedar_policy_core::authorizer::Decision::Allow)
    );

    let ex = cedar_tpe_explorer::explain::explain(&p, &f)
        .unwrap()
        .unwrap();
    for a in &ex.facts {
        println!("explain: {}", a.describe());
    }
}

#[test]
fn undo_redo() {
    let p = project();
    let mut sess = cedar_tpe_explorer::Session::new(p.clone(), Facts::initial(&p).unwrap());
    let ty = sess.facts.principal.ty.clone();
    let alice = SlotValue::Uid(PartialUid {
        ty: ty.clone(),
        eid: Some(cedar_policy_core::ast::Eid::new("alice")),
    });
    let bob = SlotValue::Uid(PartialUid {
        ty,
        eid: Some(cedar_policy_core::ast::Eid::new("bob")),
    });
    sess.set(&SlotId::Principal, alice.clone()).unwrap();
    sess.set(&SlotId::Principal, bob.clone()).unwrap();
    assert!(sess.undo());
    assert_eq!(sess.facts.get(&SlotId::Principal), Some(alice.clone()));
    assert!(sess.redo());
    assert_eq!(sess.facts.get(&SlotId::Principal), Some(bob));
    assert!(!sess.redo());
    // A new edit after undo discards the redo branch.
    assert!(sess.undo());
    sess.set(
        &SlotId::Resource,
        SlotValue::Uid(PartialUid {
            ty: sess.facts.resource.ty.clone(),
            eid: Some(cedar_policy_core::ast::Eid::new("x")),
        }),
    )
    .unwrap();
    assert!(!sess.can_redo());
    assert_eq!(sess.facts.get(&SlotId::Principal), Some(alice));
}

#[test]
fn model_shape() {
    let p = project();
    let mut f = Facts::initial(&p).unwrap();
    f.set(
        &SlotId::Principal,
        SlotValue::Uid(PartialUid {
            ty: f.principal.ty.clone(),
            eid: Some(cedar_policy_core::ast::Eid::new("alice")),
        }),
        p.vschema(),
    )
    .unwrap();
    let mut s = cedar_tpe_explorer::Session::new(p.clone(), f);
    s.refresh();
    let m = cedar_tpe_explorer::model::model_json(&s.project, &s.facts, s.eval.as_ref());
    if std::env::var("SHOW_MODEL").is_ok() {
        println!("{}", serde_json::to_string_pretty(&m).unwrap());
    }
    assert_eq!(m["decision"]["state"], "undecided");
    assert_eq!(m["entities"][0]["uid"], r#"PhotoApp::User::"alice""#);
    let meta = &m["entities"][0]["attrs"][0];
    assert_eq!(meta["kind"], "record");
    assert_eq!(meta["children"][0]["name"], "dept");
    assert_eq!(meta["children"][0]["needs"]["kind"], "value");
    // Keys round-trip.
    let key = meta["children"][0]["key"].as_str().unwrap();
    let slot = cedar_tpe_explorer::model::parse_slot_key(key).unwrap();
    assert_eq!(cedar_tpe_explorer::model::slot_key(&slot), key);
}

#[test]
fn impossible_residual_does_not_apply() {
    // With authn_method = "mfa", the forbid's residual is `private && false`:
    // it can never apply, so `private` must not be reported as needed.
    let p = project();
    let s = p.vschema();
    let mut f = Facts::initial(&p).unwrap();
    f.set(
        &SlotId::Principal,
        SlotValue::Uid(PartialUid {
            ty: f.principal.ty.clone(),
            eid: Some(cedar_policy_core::ast::Eid::new("alice")),
        }),
        s,
    )
    .unwrap();
    f.set(
        &SlotId::Resource,
        SlotValue::Uid(PartialUid {
            ty: f.resource.ty.clone(),
            eid: Some(cedar_policy_core::ast::Eid::new("vacation.jpg")),
        }),
        s,
    )
    .unwrap();
    f.set(
        &SlotId::Context(vec!["authn_method".into()]),
        SlotValue::Attr(AttrFact::Value(cedar_policy_core::ast::Value::from("mfa"))),
        s,
    )
    .unwrap();
    let e = evaluate(&p, &f).unwrap();
    let forbid = e
        .policy(&cedar_policy_core::ast::PolicyID::from_string(
            "private requires mfa",
        ))
        .unwrap();
    assert_eq!(
        forbid.status,
        cedar_tpe_explorer::Status::False,
        "residual: {}",
        forbid.residual
    );
    assert!(!forbid.relevant);
    let photo = f.resource.uid().unwrap();
    assert!(!e.is_needed(&SlotId::Attr(photo, vec!["private".into()])));
}

#[test]
fn policy_errors_have_locations() {
    let schema = include_str!("../sample-data/photoapp/photoapp.cedarschema");
    let err = Project::new(
        schema,
        "permit (principal, action, resource)\nwhen { principal.meta.dept == };",
    )
    .unwrap_err()
    .to_string();
    println!("{err}");
    assert!(err.contains("line 2"), "{err}");
}

#[test]
fn outcome_sets() {
    use cedar_policy::pst::{BinaryOp, Expr, Literal, UnaryOp, Var};
    use cedar_tpe_explorer::analysis::{conclude, Conclusion};
    use std::sync::Arc;
    let unknown = || {
        Arc::new(Expr::GetAttr {
            expr: Arc::new(Expr::Var(Var::Context)),
            attr: "x".into(),
        })
    };
    let lit = |b| Arc::new(Expr::Literal(Literal::Bool(b)));
    let and = |l, r| Expr::BinaryOp {
        op: BinaryOp::And,
        left: l,
        right: r,
    };
    let or = |l, r| Expr::BinaryOp {
        op: BinaryOp::Or,
        left: l,
        right: r,
    };
    // x && false: {false, error} -> cannot apply
    assert_eq!(
        conclude(&and(unknown(), lit(false))),
        Conclusion::CannotApply
    );
    // x || true: {true, error} -> no conclusion (x may error)
    assert_eq!(conclude(&or(unknown(), lit(true))), Conclusion::Unknown);
    // !(false) : {true} -> applies
    assert_eq!(
        conclude(&Expr::UnaryOp {
            op: UnaryOp::Not,
            expr: lit(false)
        }),
        Conclusion::Applies
    );
    // error && x: {error} -> cannot apply
    assert_eq!(
        conclude(&and(Arc::new(Expr::ResidualError), unknown())),
        Conclusion::CannotApply
    );
    // x: unknown
    assert_eq!(conclude(&unknown()), Conclusion::Unknown);
}
