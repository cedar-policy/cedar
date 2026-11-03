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
use cedar_tpe_explorer::doc::render_facts;
use cedar_tpe_explorer::suggest::suggest_for_slot;
use cedar_tpe_explorer::symcc::{LocalModelFinder, SymccModelFinder};
use cedar_tpe_explorer::{evaluate, Facts, PartialUid, Project, SlotId, SlotValue};

fn slots(p: &Project, f: &Facts) -> Vec<SlotId> {
    let e = evaluate(p, f).unwrap();
    let mut out = vec![];
    for l in render_facts(p, f, Some(&e)) {
        for s in l.spans.iter().filter_map(|s| s.slot.clone()) {
            if !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out
}

async fn sweep(name: &str, p: &Project, f: &Facts, finder: &mut LocalModelFinder) -> usize {
    let e = evaluate(p, f).unwrap();
    let mut errs = 0;
    for s in slots(p, f) {
        match suggest_for_slot(p, f, &e, &s, finder).await {
            Ok(v) => println!("[{name}] ok  {} ({} suggestions)", s.label(), v.len()),
            Err(err) => {
                errs += 1;
                println!("[{name}] ERR {}: {err}", s.label())
            }
        }
    }
    errs
}

#[tokio::test(flavor = "current_thread")]
async fn every_slot() {
    let mut finder = SymccModelFinder::new(10_000).unwrap();
    let mut errs = 0;
    for (dir, schema, pid, rid) in [
        ("photoapp", "photoapp.cedarschema", "alice", "vacation.jpg"),
        ("docs", "docs.cedarschema", "bob", "d1"),
    ] {
        let base = format!("{}/sample-data/{dir}", env!("CARGO_MANIFEST_DIR"));
        let p = Project::new(
            &std::fs::read_to_string(format!("{base}/{schema}")).unwrap(),
            &std::fs::read_to_string(format!("{base}/policies.cedar")).unwrap(),
        )
        .unwrap();
        let s = p.vschema();
        let mut f = Facts::initial(&p).unwrap();
        errs += sweep(dir, &p, &f, &mut finder).await;
        f.set(
            &SlotId::Principal,
            SlotValue::Uid(PartialUid {
                ty: f.principal.ty.clone(),
                eid: Some(Eid::new(pid)),
            }),
            s,
        )
        .unwrap();
        errs += sweep(dir, &p, &f, &mut finder).await;
        f.set(
            &SlotId::Resource,
            SlotValue::Uid(PartialUid {
                ty: f.resource.ty.clone(),
                eid: Some(Eid::new(rid)),
            }),
            s,
        )
        .unwrap();
        errs += sweep(dir, &p, &f, &mut finder).await;
        // Every non-value state of every slot.
        for sl in slots(&p, &f) {
            for st in cedar_tpe_explorer::edit::allowed_states(&p, &f, &sl) {
                let Ok(v) = cedar_tpe_explorer::edit::state_value(&p, &f, &sl, st) else {
                    continue;
                };
                let mut g = f.clone();
                if g.set(&sl, v, s).is_err() {
                    continue;
                }
                let Ok(e) = evaluate(&p, &g) else {
                    println!("[{dir}] EVAL ERR after {} {:?}", sl.label(), st);
                    errs += 1;
                    continue;
                };
                for sl2 in slots(&p, &g) {
                    if let Err(err) = suggest_for_slot(&p, &g, &e, &sl2, &mut finder).await {
                        errs += 1;
                        println!(
                            "[{dir}] ERR {} (after {} := {:?}): {err}",
                            sl2.label(),
                            sl.label(),
                            st
                        );
                    }
                }
            }
        }
        // Walk: apply each slot's suggestions one at a time (depth-first over a few branches).
        let mut frontier = vec![f.clone()];
        for _round in 0..3 {
            let mut next = vec![];
            for f in &frontier {
                let e = evaluate(&p, f).unwrap();
                for sl in slots(&p, f) {
                    match suggest_for_slot(&p, f, &e, &sl, &mut finder).await {
                        Ok(v) => {
                            for sug in v.into_iter().take(2) {
                                let g = cedar_tpe_explorer::suggest::apply(&p, f, &sug.assignments)
                                    .unwrap();
                                if next.len() < 12 {
                                    next.push(g);
                                }
                            }
                        }
                        Err(err) => {
                            errs += 1;
                            println!("[{dir}] ERR {}: {err}\n  facts: {f:?}", sl.label())
                        }
                    }
                }
            }
            frontier = next;
        }
    }
    assert_eq!(errs, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn known_present_tag_is_guarded() {
    let base = format!("{}/sample-data/docs", env!("CARGO_MANIFEST_DIR"));
    let p = Project::new(
        &std::fs::read_to_string(format!("{base}/docs.cedarschema")).unwrap(),
        &std::fs::read_to_string(format!("{base}/policies.cedar")).unwrap(),
    )
    .unwrap();
    let s = p.vschema();
    let mut f = Facts::initial(&p).unwrap();
    let read: cedar_policy_core::ast::EntityUID = r#"Docs::Action::"read""#.parse().unwrap();
    f.set(&SlotId::Action, SlotValue::Action(read), s).unwrap();
    f.set(
        &SlotId::Principal,
        SlotValue::Uid(PartialUid {
            ty: f.principal.ty.clone(),
            eid: Some(Eid::new("bob")),
        }),
        s,
    )
    .unwrap();
    let bob = f.principal.uid().unwrap();
    f.set(
        &SlotId::Tag(bob, "reviewer".into()),
        SlotValue::Tag(Some(cedar_tpe_explorer::AttrFact::Unknown)),
        s,
    )
    .unwrap();
    let e = evaluate(&p, &f).unwrap();
    let id = cedar_policy_core::ast::PolicyID::from_string("drafts by title");
    let mut finder = SymccModelFinder::new(10_000).unwrap();
    let sugg = cedar_tpe_explorer::suggest::suggest_for_policy(&p, &f, &e, &id, &mut finder)
        .await
        .unwrap();
    assert_eq!(sugg.len(), 2);
}
