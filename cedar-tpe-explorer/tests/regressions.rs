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

//! Regression tests for bugs found in review.

use cedar_policy_core::ast::{EntityUID, PolicyID};
use cedar_policy_core::authorizer::Decision;
use cedar_tpe_explorer::edit::{state_value, EditState};
use cedar_tpe_explorer::symcc::LocalModelFinder;
use cedar_tpe_explorer::{
    evaluate, explain, suggest, AttrFact, Facts, PartialUid, Project, SlotId, SlotValue,
};

const SCHEMA: &str = r#"
entity User { nick?: String } tags String;
entity Doc { viewers: Set<User> };
action view appliesTo { principal: User, resource: Doc };
"#;

fn uid(s: &str) -> EntityUID {
    s.parse().unwrap()
}

/// Facts for `policy` with the principal set to `User::"alice"`.
fn alice(policy: &str) -> (Project, Facts) {
    let p = Project::new(SCHEMA, policy).unwrap();
    let mut f = Facts::initial(&p).unwrap();
    let u = uid(r#"User::"alice""#);
    let (ty, eid) = u.components();
    f.set(
        &SlotId::Principal,
        SlotValue::Uid(PartialUid { ty, eid: Some(eid) }),
        p.vschema(),
    )
    .unwrap();
    (p, f)
}

#[test]
fn in_depends_on_its_right_side() {
    let (p, f) =
        alice("permit(principal, action, resource) when { principal in resource.viewers };");
    assert!(evaluate(&p, &f).unwrap().is_needed(&SlotId::Resource));
}

#[test]
fn absent_tags_decide_has_tag() {
    let (p, mut f) =
        alice(r#"permit(principal, action, resource) when { principal.hasTag("k") };"#);
    let slot = SlotId::Tags(uid(r#"User::"alice""#));
    let v = state_value(&p, &f, &slot, EditState::Absent).unwrap();
    f.set(&slot, v, p.vschema()).unwrap();
    assert_eq!(evaluate(&p, &f).unwrap().decision, Some(Decision::Deny));
}

#[test]
fn explain_uses_presence_of_optional_attributes() {
    let (p, mut f) = alice("permit(principal, action, resource) when { principal has nick };");
    let slot = SlotId::Attr(uid(r#"User::"alice""#), vec!["nick".into()]);
    f.set(&slot, SlotValue::Attr(AttrFact::Unknown), p.vschema())
        .unwrap();
    let ex = explain::explain(&p, &f).unwrap().unwrap();
    assert_eq!(ex.decision, Decision::Allow);
}

#[tokio::test(flavor = "current_thread")]
async fn suggestions_avoid_entities_whose_facts_contradict_them() {
    let p = Project::new(
        SCHEMA,
        r#"@id("n") permit(principal, action, resource) when {
            (principal == User::"alice" || principal == User::"bob") && principal has nick };"#,
    )
    .unwrap();
    let mut f = Facts::initial(&p).unwrap();
    let nick = SlotId::Attr(uid(r#"User::"alice""#), vec!["nick".into()]);
    f.set(&nick, SlotValue::Attr(AttrFact::Absent), p.vschema())
        .unwrap();
    let e = evaluate(&p, &f).unwrap();
    let mut finder = LocalModelFinder::new(10_000).unwrap();
    let id = PolicyID::from_string("n");
    let s = suggest::suggest_for_policy(&p, &f, &e, &id, &mut finder)
        .await
        .unwrap();
    assert_eq!(s.len(), 2, "expected a way to satisfy and a way to falsify");
}

#[tokio::test(flavor = "current_thread")]
async fn errors_in_untaken_branches_do_not_block_suggestions() {
    let p = Project::new(
        "entity User; entity Doc;
         action view appliesTo { principal: User, resource: Doc, context: { b: Bool, n: Long } };",
        r#"@id("e") permit(principal, action, resource) when {
            (if context.b then 9223372036854775807 + 1 else context.n) == 1 };"#,
    )
    .unwrap();
    let f = Facts::initial(&p).unwrap();
    let e = evaluate(&p, &f).unwrap();
    let mut finder = LocalModelFinder::new(10_000).unwrap();
    let id = PolicyID::from_string("e");
    let s = suggest::suggest_for_policy(&p, &f, &e, &id, &mut finder)
        .await
        .unwrap();
    println!("residual: {}", e.policy(&id).unwrap().residual);
    assert_eq!(s.len(), 2, "expected a way to satisfy and a way to falsify");
}
