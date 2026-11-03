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

//! A structured, JSON-serializable model of a session for graphical front
//! ends: forms for the facts, cards for the policies.
//!
//! Unlike [`crate::doc`], which pre-renders text lines, this describes each
//! fact once with its type, state, allowed states, and which policies need
//! it, so a UI can choose its own widgets.
//!
//! Facts are addressed by *slot keys* ([`slot_key`]): the JSON encoding of a
//! [`SlotId`], stable across edits.

use cedar_policy_core::ast::{EntityUID, PolicyID};
use cedar_policy_core::authorizer::Decision;
use cedar_policy_core::validator::types::Type;
use serde_json::{json, Value as Json};
use smol_str::SmolStr;
use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::NeedKind;
use crate::doc::{residual_tokens, Tok};
use crate::edit::{self, EditState};
use crate::eval::{effect_str, Evaluation, SlotNeed, Status};
use crate::facts::{AttrFact, Facts, SlotId};
use crate::project::Project;
use crate::values::{self, can_have_parents, parent_types, single_entity_type};

/// Encode a slot as a stable string key.
pub fn slot_key(s: &SlotId) -> String {
    let path = |p: &[SmolStr]| p.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let j = match s {
        SlotId::Principal => json!(["principal"]),
        SlotId::Action => json!(["action"]),
        SlotId::Resource => json!(["resource"]),
        SlotId::Context(p) => json!(["context", path(p)]),
        SlotId::Parents(e) => json!(["parents", e.to_string()]),
        SlotId::Attr(e, p) => json!(["attr", e.to_string(), path(p)]),
        SlotId::Tags(e) => json!(["tags", e.to_string()]),
        SlotId::Tag(e, k) => json!(["tag", e.to_string(), k.as_str()]),
    };
    j.to_string()
}

/// Decode a key produced by [`slot_key`].
pub fn parse_slot_key(key: &str) -> Result<SlotId, String> {
    let bad = || format!("bad slot key `{key}`");
    let j: Json = serde_json::from_str(key).map_err(|_| bad())?;
    let a = j.as_array().ok_or_else(bad)?;
    let uid = |i: usize| -> Result<EntityUID, String> {
        a.get(i)
            .and_then(Json::as_str)
            .ok_or_else(bad)?
            .parse()
            .map_err(|_| bad())
    };
    let path = |i: usize| -> Result<Vec<SmolStr>, String> {
        a.get(i)
            .and_then(Json::as_array)
            .ok_or_else(bad)?
            .iter()
            .map(|x| x.as_str().map(SmolStr::new).ok_or_else(bad))
            .collect()
    };
    Ok(match a.first().and_then(Json::as_str).ok_or_else(bad)? {
        "principal" => SlotId::Principal,
        "action" => SlotId::Action,
        "resource" => SlotId::Resource,
        "context" => SlotId::Context(path(1)?),
        "parents" => SlotId::Parents(uid(1)?),
        "attr" => SlotId::Attr(uid(1)?, path(2)?),
        "tags" => SlotId::Tags(uid(1)?),
        "tag" => SlotId::Tag(
            uid(1)?,
            SmolStr::new(a.get(2).and_then(Json::as_str).ok_or_else(bad)?),
        ),
        _ => return Err(bad()),
    })
}

pub fn state_name(s: EditState) -> &'static str {
    match s {
        EditState::Value => "value",
        EditState::Present => "present",
        EditState::Absent => "absent",
        EditState::Unknown => "unknown",
    }
}

pub fn parse_state(s: &str) -> Result<EditState, String> {
    EditState::ALL
        .into_iter()
        .find(|x| state_name(*x) == s)
        .ok_or_else(|| format!("unknown state `{s}`"))
}

fn need_kind_name(k: NeedKind) -> &'static str {
    match k {
        NeedKind::Id => "id",
        NeedKind::BlockedOnId => "blocked",
        NeedKind::Value => "value",
        NeedKind::Parents => "parents",
        NeedKind::Tags => "tags",
    }
}

/// Which widget suits a value of this type.
fn value_kind(ty: Option<&Type>) -> &'static str {
    match ty {
        Some(Type::Bool(_)) => "bool",
        Some(Type::Long) => "long",
        Some(Type::String) => "string",
        Some(Type::Entity(_)) => "entity",
        Some(Type::Set { .. }) => "set",
        Some(Type::Record { .. }) => "record",
        Some(Type::ExtensionType { .. }) => "extension",
        _ => "other",
    }
}

struct Ctx<'a> {
    project: &'a Project,
    facts: &'a Facts,
    eval: Option<&'a Evaluation>,
}

impl Ctx<'_> {
    fn needs(&self, slot: &SlotId) -> Json {
        match self.eval.map(|e| e.slot_need(slot)) {
            Some(SlotNeed::Needed(kind, ids)) => json!({
                "kind": need_kind_name(kind),
                "policies": ids.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
                "message": self.eval.map(|e| e.describe_slot_need(slot)),
            }),
            _ => Json::Null,
        }
    }

    /// The common part of every editable fact.
    fn base(&self, slot: &SlotId) -> serde_json::Map<String, Json> {
        let (p, f) = (self.project, self.facts);
        let allowed = edit::allowed_states(p, f, slot);
        let mut m = serde_json::Map::new();
        m.insert("key".into(), json!(slot_key(slot)));
        m.insert("label".into(), json!(slot.label()));
        m.insert(
            "state".into(),
            json!(state_name(edit::current_state(p, f, slot))),
        );
        m.insert(
            "allowedStates".into(),
            json!(allowed.iter().map(|s| state_name(*s)).collect::<Vec<_>>()),
        );
        m.insert("text".into(), json!(edit::current_text(p, f, slot)));
        m.insert("needs".into(), self.needs(slot));
        m
    }

    /// An attribute, context field, or record field.
    fn field(&self, slot: &SlotId, name: &str, fact: &AttrFact) -> Json {
        let schema = self.project.vschema();
        let ty = self.facts.slot_type(slot, schema);
        let mut m = self.base(slot);
        m.insert("name".into(), json!(name));
        m.insert(
            "required".into(),
            json!(self.facts.slot_required(slot, schema)),
        );
        m.insert(
            "typeName".into(),
            json!(ty.as_ref().map(values::type_name).unwrap_or_default()),
        );
        m.insert("valueKind".into(), json!(value_kind(ty.as_ref())));
        if let Some(Type::Entity(kind)) = &ty {
            m.insert(
                "entityType".into(),
                json!(single_entity_type(kind).map(|t| t.to_string())),
            );
        }
        if let AttrFact::Record(children) = fact {
            m.insert("kind".into(), json!("record"));
            let child = |k: &SmolStr| match slot {
                SlotId::Context(p) => SlotId::Context([p.clone(), vec![k.clone()]].concat()),
                SlotId::Attr(e, p) => {
                    SlotId::Attr(e.clone(), [p.clone(), vec![k.clone()]].concat())
                }
                other => other.clone(),
            };
            m.insert(
                "children".into(),
                Json::Array(
                    children
                        .iter()
                        .map(|(k, f)| self.field(&child(k), k, f))
                        .collect(),
                ),
            );
        } else {
            m.insert("kind".into(), json!("value"));
        }
        m.insert("display".into(), json!(fact.describe()));
        Json::Object(m)
    }

    fn uid_slot(
        &self,
        slot: &SlotId,
        ty: &cedar_policy_core::ast::EntityType,
        options: &[String],
    ) -> Json {
        let mut m = self.base(slot);
        m.insert("kind".into(), json!("uid"));
        m.insert("entityType".into(), json!(ty.to_string()));
        m.insert("typeOptions".into(), json!(options));
        Json::Object(m)
    }
}

/// The whole session as JSON. See the module docs.
pub fn model_json(project: &Project, facts: &Facts, eval: Result<&Evaluation, &String>) -> Json {
    let schema = project.vschema();
    let cx = Ctx {
        project,
        facts,
        eval: eval.ok(),
    };

    // Request
    let action = schema.get_action_id(&facts.action);
    let sorted = |it: Vec<String>| {
        let mut v = it;
        v.sort();
        v
    };
    let ptypes = sorted(
        action
            .map(|a| a.applies_to_principals().map(|t| t.to_string()).collect())
            .unwrap_or_default(),
    );
    let rtypes = sorted(
        action
            .map(|a| a.applies_to_resources().map(|t| t.to_string()).collect())
            .unwrap_or_default(),
    );
    let mut action_slot = cx.base(&SlotId::Action);
    action_slot.insert("kind".into(), json!("action"));
    action_slot.insert(
        "options".into(),
        json!(project
            .actions()
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()),
    );
    let request = json!({
        "principal": cx.uid_slot(&SlotId::Principal, &facts.principal.ty, &ptypes),
        "action": Json::Object(action_slot),
        "resource": cx.uid_slot(&SlotId::Resource, &facts.resource.ty, &rtypes),
        "context": facts.context.iter()
            .map(|(k, f)| cx.field(&SlotId::Context(vec![k.clone()]), k, f))
            .collect::<Vec<_>>(),
    });

    // Entities, ordered by type then id
    let mut ents: Vec<_> = facts.entities.iter().collect();
    ents.sort_by_key(|(u, _)| (u.entity_type().to_string(), u.eid().escaped()));
    let entities: Vec<Json> = ents
        .into_iter()
        .map(|(uid, ent)| {
            let parents = can_have_parents(uid.entity_type(), schema).then(|| {
                let slot = SlotId::Parents(uid.clone());
                let mut m = cx.base(&slot);
                m.insert("kind".into(), json!("parents"));
                m.insert(
                    "values".into(),
                    json!(ent
                        .parents
                        .iter()
                        .flatten()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()),
                );
                m.insert(
                    "allowedTypes".into(),
                    json!(sorted(
                        parent_types(uid.entity_type(), schema)
                            .iter()
                            .map(|t| t.to_string())
                            .collect()
                    )),
                );
                Json::Object(m)
            });
            let tags = schema
                .get_entity_type(uid.entity_type())
                .and_then(|t| t.tag_type())
                .map(|tag_ty| {
                    let slot = SlotId::Tags(uid.clone());
                    let mut m = cx.base(&slot);
                    m.insert("kind".into(), json!("tags"));
                    m.insert("typeName".into(), json!(values::type_name(tag_ty)));
                    m.insert(
                        "values".into(),
                        json!(ent
                            .tags
                            .iter()
                            .flatten()
                            .map(|(k, f)| json!({ "key": k.as_str(), "display": f.describe() }))
                            .collect::<Vec<_>>()),
                    );
                    Json::Object(m)
                });
            json!({
                "uid": uid.to_string(),
                "type": uid.entity_type().to_string(),
                "id": uid.eid().as_ref(),
                "isPrincipal": facts.principal.uid().as_ref() == Some(uid),
                "isResource": facts.resource.uid().as_ref() == Some(uid),
                "parents": parents,
                "attrs": ent.attrs.iter()
                    .map(|(k, f)| cx.field(&SlotId::Attr(uid.clone(), vec![k.clone()]), k, f))
                    .collect::<Vec<_>>(),
                "tags": tags,
            })
        })
        .collect();

    // Known entity ids by type, for autocomplete
    let mut known: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut note = |u: &EntityUID| {
        known
            .entry(u.entity_type().to_string())
            .or_default()
            .insert(u.eid().as_ref().to_string());
    };
    for (uid, ent) in &facts.entities {
        note(uid);
        ent.parents.iter().flatten().for_each(&mut note);
    }
    if let Ok(e) = eval {
        for p in &e.policies {
            crate::analysis::literal_uids(&p.residual)
                .iter()
                .for_each(&mut note);
        }
    }
    project.literals().1.iter().for_each(&mut note);

    let (decision, policies) = match eval {
        Err(err) => (json!({ "state": "error", "summary": err }), json!([])),
        Ok(e) => {
            let state = match e.decision {
                Some(Decision::Allow) => "allow",
                Some(Decision::Deny) => "deny",
                None => "undecided",
            };
            let summary = match e.decision {
                Some(_) => {
                    let reasons: Vec<String> = e.reasons().iter().map(|p| p.title()).collect();
                    if reasons.is_empty() {
                        "No permit can apply. Nothing else you fill in can change this.".to_string()
                    } else {
                        format!(
                            "Settled by {}. Nothing else you fill in can change this.",
                            reasons.join(" and ")
                        )
                    }
                }
                None => {
                    let n = e.count(Status::Residual);
                    format!(
                        "{n} {} still {} on unknown facts",
                        if n == 1 { "policy" } else { "policies" },
                        if n == 1 { "depends" } else { "depend" }
                    )
                }
            };
            let policies: Vec<Json> = e
                .policies
                .iter()
                .map(|p| {
                    let residual: Vec<Json> = if p.status == Status::Residual {
                        residual_tokens(
                            &p.residual,
                            crate::analysis::TypeEnv {
                                schema,
                                action: &facts.action,
                            },
                        )
                        .into_iter()
                        .map(|t| match t {
                            Tok::Span(s) => json!({
                                "text": s.text,
                                "style": crate::doc::style_name(s.style),
                                "marks": s.marks.iter().map(slot_key).collect::<Vec<_>>(),
                            }),
                            Tok::Break => {
                                json!({ "text": " ", "style": "plain", "marks": [], "break": true })
                            }
                        })
                        .collect()
                    } else {
                        vec![]
                    };
                    json!({
                        "id": p.id.to_string(),
                        "effect": effect_str(p.effect),
                        "status": match p.status {
                            Status::Residual => "residual",
                            Status::True => "satisfied",
                            Status::False => "not-satisfied",
                            Status::Error => "error",
                        },
                        "relevant": p.relevant,
                        "isReason": e.decision.is_some() && p.relevant,
                        "residual": residual,
                        "needs": p.needs.iter().map(|n| json!({
                            "key": slot_key(&n.slot),
                            "label": n.slot.label(),
                            "kind": need_kind_name(n.kind),
                        })).collect::<Vec<_>>(),
                        "source": project.policy(&p.id).map(|i| i.source.clone()),
                    })
                })
                .collect();
            (
                json!({
                    "state": state,
                    "summary": summary,
                    "reasons": e.reasons().iter().map(|p| p.id.to_string()).collect::<Vec<_>>(),
                    "counts": {
                        "residual": e.count(Status::Residual),
                        "satisfied": e.count(Status::True),
                        "notSatisfied": e.count(Status::False),
                        "error": e.count(Status::Error),
                        "irrelevant": e.irrelevant_count(),
                    },
                    "warnings": e.warnings,
                }),
                Json::Array(policies),
            )
        }
    };

    json!({
        "decision": decision,
        "request": request,
        "entities": entities,
        "policies": policies,
        "knownIds": known.into_iter().map(|(k, v)| (k, json!(v.into_iter().collect::<Vec<_>>()))).collect::<serde_json::Map<_, _>>(),
    })
}

/// Look up a policy id from a string.
pub fn policy_id(s: &str) -> PolicyID {
    PolicyID::from_string(s)
}
