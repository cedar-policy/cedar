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

use cedar_policy_core::ast::Eid;
use cedar_tpe_explorer::suggest::{suggest_for_policy, suggest_for_slot};
use cedar_tpe_explorer::symcc::SymccModelFinder;
use cedar_tpe_explorer::{evaluate, AttrFact, Facts, PartialUid, Project, SlotId, SlotValue};

fn project() -> Project {
    Project::new(
        include_str!("../sample-data/photoapp/photoapp.cedarschema"),
        include_str!("../sample-data/photoapp/policies.cedar"),
    )
    .unwrap()
}

fn show(s: &[cedar_tpe_explorer::Suggestion]) {
    for sug in s {
        for a in &sug.assignments {
            println!("  {}", a.describe());
        }
        for e in &sug.effects {
            println!("      → {}", e.describe());
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn suggestions() {
    let p = project();
    let s = p.vschema();
    let mut finder = SymccModelFinder::new(10_000).unwrap();
    let f = Facts::initial(&p).unwrap();
    let e = evaluate(&p, &f).unwrap();
    for id in e.policies.iter().map(|p| p.id.clone()) {
        println!("policy {id}");
        let sugg = suggest_for_policy(&p, &f, &e, &id, &mut finder)
            .await
            .unwrap();
        show(&sugg);
        assert_eq!(sugg.len(), 2);
    }

    let mut f = f;
    f.set(
        &SlotId::Principal,
        SlotValue::Uid(PartialUid {
            ty: f.principal.ty.clone(),
            eid: Some(Eid::new("alice")),
        }),
        s,
    )
    .unwrap();
    f.set(
        &SlotId::Resource,
        SlotValue::Uid(PartialUid {
            ty: f.resource.ty.clone(),
            eid: Some(Eid::new("vacation.jpg")),
        }),
        s,
    )
    .unwrap();
    let photo = f.resource.uid().unwrap();
    f.set(
        &SlotId::Attr(photo.clone(), vec!["private".into()]),
        SlotValue::Attr(AttrFact::Value(true.into())),
        s,
    )
    .unwrap();
    let e = evaluate(&p, &f).unwrap();
    println!("slot context.authn_method");
    let sugg = suggest_for_slot(
        &p,
        &f,
        &e,
        &SlotId::Context(vec!["authn_method".into()]),
        &mut finder,
    )
    .await
    .unwrap();
    show(&sugg);
    assert_eq!(sugg.len(), 2);
    println!("slot alice parents");
    let sugg = suggest_for_slot(
        &p,
        &f,
        &e,
        &SlotId::Parents(f.principal.uid().unwrap()),
        &mut finder,
    )
    .await
    .unwrap();
    show(&sugg);
}

#[tokio::test(flavor = "current_thread")]
async fn records_and_longs_are_minimized() {
    let p = Project::new(
        include_str!("../sample-data/docs/docs.cedarschema"),
        include_str!("../sample-data/docs/policies.cedar"),
    )
    .unwrap();
    let mut finder = SymccModelFinder::new(10_000).unwrap();
    let f = Facts::initial(&p).unwrap();
    let e = evaluate(&p, &f).unwrap();
    let id: cedar_policy_core::ast::PolicyID =
        cedar_policy_core::ast::PolicyID::from_string("senior verified editors");
    let sugg = suggest_for_policy(&p, &f, &e, &id, &mut finder)
        .await
        .unwrap();
    show(&sugg);
    let applies: Vec<String> = sugg[0].assignments.iter().map(|a| a.describe()).collect();
    assert!(
        applies.contains(&r#"Docs::User::"user-1".level = 5"#.to_string()),
        "{applies:?}"
    );
    assert!(
        applies.contains(&r#"Docs::User::"user-1".profile.verified = true"#.to_string()),
        "{applies:?}"
    );
    assert!(
        !applies.iter().any(|a| a.contains("country")),
        "{applies:?}"
    );
}
