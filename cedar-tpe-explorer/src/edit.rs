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

//! Editing a single slot: which states it can be put in and how to parse
//! typed input.

use cedar_policy_core::ast::{EntityType, Value, ValueKind};
use smol_str::SmolStr;
use std::collections::BTreeMap;

use crate::facts::{unknown_present, AttrFact, Facts, PartialUid, SlotId, SlotValue};
use crate::project::Project;
use crate::values::{self, namespace_of, parse_euid, parse_euid_list, parse_typed_value};

/// The four knowledge states offered for a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditState {
    /// A concrete value (typed by the user).
    Value,
    /// Present, value unknown (`?`).
    Present,
    /// Known not to exist.
    Absent,
    /// Nothing known.
    Unknown,
}

impl EditState {
    pub const ALL: [EditState; 4] = [
        EditState::Value,
        EditState::Present,
        EditState::Absent,
        EditState::Unknown,
    ];

    pub fn label(self) -> &'static str {
        match self {
            EditState::Value => "value",
            EditState::Present => "? present",
            EditState::Absent => "absent",
            EditState::Unknown => "unknown",
        }
    }
}

/// Prompt shown before typed input, e.g. `eid>`.
pub fn prompt(slot: &SlotId) -> &'static str {
    match slot {
        SlotId::Principal | SlotId::Resource => "eid>",
        SlotId::Action => "action>",
        SlotId::Parents(_) => "parents>",
        SlotId::Tags(_) => "tags>",
        _ => "value>",
    }
}

/// Which states make sense for `slot`.
pub fn allowed_states(project: &Project, facts: &Facts, slot: &SlotId) -> Vec<EditState> {
    let schema = project.vschema();
    match slot {
        SlotId::Principal | SlotId::Resource => vec![EditState::Value, EditState::Unknown],
        SlotId::Action => vec![EditState::Value],
        SlotId::Parents(_) | SlotId::Tags(_) => {
            vec![EditState::Value, EditState::Absent, EditState::Unknown]
        }
        SlotId::Context(_) | SlotId::Attr(_, _) | SlotId::Tag(_, _) => {
            if facts.slot_required(slot, schema) {
                vec![EditState::Value, EditState::Present]
            } else {
                EditState::ALL.to_vec()
            }
        }
    }
}

/// The current state of a slot.
pub fn current_state(project: &Project, facts: &Facts, slot: &SlotId) -> EditState {
    match facts.get_or_unknown(slot, project.vschema()) {
        Some(SlotValue::Uid(u)) if u.eid.is_none() => EditState::Unknown,
        Some(SlotValue::Parents(None) | SlotValue::Tags(None) | SlotValue::Tag(None)) => {
            EditState::Unknown
        }
        Some(SlotValue::Tags(Some(t))) if t.values().all(|f| *f == AttrFact::Absent) => {
            EditState::Absent
        }
        Some(SlotValue::Attr(f) | SlotValue::Tag(Some(f))) => match f {
            AttrFact::Unknown => EditState::Present,
            AttrFact::Absent => EditState::Absent,
            AttrFact::UnknownExistence => EditState::Unknown,
            AttrFact::Record(m) if m.values().all(AttrFact::is_unknown) => EditState::Present,
            _ => EditState::Value,
        },
        _ => EditState::Value,
    }
}

/// Text to pre-fill the input with when editing a slot.
pub fn current_text(project: &Project, facts: &Facts, slot: &SlotId) -> String {
    match facts.get_or_unknown(slot, project.vschema()) {
        Some(SlotValue::Uid(PartialUid { eid: Some(e), .. })) => e.as_ref().to_string(),
        Some(SlotValue::Action(a)) => a.to_string(),
        Some(SlotValue::Parents(Some(p))) => values::euid_set_to_string(&p),
        Some(SlotValue::Attr(f) | SlotValue::Tag(Some(f))) => match f.to_value() {
            Some(v) if f.is_known() => match &v.value {
                ValueKind::Lit(cedar_policy_core::ast::Literal::String(s)) => s.to_string(),
                _ => values::value_to_string(&v),
            },
            _ => String::new(),
        },
        // Tags as a record of their known values, which `parse_input` accepts.
        Some(SlotValue::Tags(Some(t))) => {
            let items: Vec<String> = t
                .iter()
                .filter_map(|(k, f)| match f {
                    AttrFact::Value(v) => Some(format!(
                        "{}: {}",
                        values::record_key(k),
                        values::value_to_string(v)
                    )),
                    _ => None,
                })
                .collect();
            format!("{{{}}}", items.join(", "))
        }
        _ => String::new(),
    }
}

/// The slot value for a non-`Value` state.
pub fn state_value(
    project: &Project,
    facts: &Facts,
    slot: &SlotId,
    state: EditState,
) -> Result<SlotValue, String> {
    let schema = project.vschema();
    if !allowed_states(project, facts, slot).contains(&state) {
        return Err(format!("{} cannot be {}", slot.label(), state.label()));
    }
    Ok(match (slot, state) {
        (_, EditState::Value) => return Err("a value needs input".into()),
        (SlotId::Principal | SlotId::Resource, EditState::Unknown) => {
            facts.unknown_value_for(slot, schema)
        }
        (SlotId::Parents(_), EditState::Absent) => SlotValue::Parents(Some(Default::default())),
        (SlotId::Parents(_), _) => SlotValue::Parents(None),
        (SlotId::Tags(_), EditState::Absent) => {
            SlotValue::Tags(Some(closed_tags(project, BTreeMap::new())))
        }
        (SlotId::Tags(_), _) => SlotValue::Tags(None),
        (SlotId::Tag(_, _), EditState::Present) => SlotValue::Tag(Some(AttrFact::Unknown)),
        (SlotId::Tag(_, _), EditState::Absent) => SlotValue::Tag(Some(AttrFact::Absent)),
        (SlotId::Tag(_, _), _) => SlotValue::Tag(None),
        (_, EditState::Present) => SlotValue::Attr(match facts.slot_type(slot, schema) {
            Some(ty) => unknown_present(&ty),
            None => AttrFact::Unknown,
        }),
        (_, EditState::Absent) => SlotValue::Attr(AttrFact::Absent),
        (_, EditState::Unknown) => SlotValue::Attr(AttrFact::UnknownExistence),
    })
}

/// Parse typed input for `slot`.
pub fn parse_input(
    project: &Project,
    facts: &Facts,
    slot: &SlotId,
    input: &str,
) -> Result<SlotValue, String> {
    let schema = project.vschema();
    let input = input.trim();
    if input.is_empty() {
        return Err("type a value, or pick another state".into());
    }
    let ns_of = |e: &EntityType| namespace_of(e);
    match slot {
        SlotId::Principal | SlotId::Resource => {
            let cur = if *slot == SlotId::Principal {
                &facts.principal
            } else {
                &facts.resource
            };
            let ns = ns_of(&cur.ty);
            let uid = parse_euid(input, Some(&cur.ty), ns.as_deref(), schema)?;
            let action = schema
                .get_action_id(&facts.action)
                .ok_or("unknown action")?;
            let ok = if *slot == SlotId::Principal {
                action
                    .applies_to_principals()
                    .any(|t| t == uid.entity_type())
            } else {
                action
                    .applies_to_resources()
                    .any(|t| t == uid.entity_type())
            };
            if !ok {
                return Err(format!(
                    "{} does not apply to {}",
                    facts.action,
                    uid.entity_type()
                ));
            }
            let (ty, eid) = uid.components();
            Ok(SlotValue::Uid(PartialUid { ty, eid: Some(eid) }))
        }
        SlotId::Action => {
            let ns = ns_of(facts.action.entity_type());
            let uid = parse_euid(
                input,
                Some(facts.action.entity_type()),
                ns.as_deref(),
                schema,
            )?;
            if schema.get_action_id(&uid).is_none() {
                return Err(format!("{uid} is not declared in the schema"));
            }
            Ok(SlotValue::Action(uid))
        }
        SlotId::Parents(e) => {
            let ptys = values::parent_types(e.entity_type(), schema);
            let default = if ptys.len() == 1 { ptys.first() } else { None };
            let ns = ns_of(e.entity_type());
            let set = parse_euid_list(input, default, ns.as_deref(), schema)?;
            for p in &set {
                if !ptys.contains(p.entity_type()) {
                    return Err(format!(
                        "{} cannot be a parent of {}",
                        p.entity_type(),
                        e.entity_type()
                    ));
                }
            }
            Ok(SlotValue::Parents(Some(set)))
        }
        SlotId::Tags(e) => {
            let ty = facts
                .slot_type(slot, schema)
                .ok_or_else(|| format!("{} has no tags", e.entity_type()))?;
            let v = values::parse_value_expr(input)?;
            let ValueKind::Record(r) = &v.value else {
                return Err("tags are written as a record, e.g. {\"k\": \"v\"}".into());
            };
            let mut m: BTreeMap<SmolStr, AttrFact> = BTreeMap::new();
            for (k, tv) in r.iter() {
                if !values::conforms(tv, &ty) {
                    return Err(format!("tag `{k}` must be a {}", values::type_name(&ty)));
                }
                m.insert(k.clone(), AttrFact::Value(tv.clone()));
            }
            Ok(SlotValue::Tags(Some(closed_tags(project, m))))
        }
        SlotId::Context(_) | SlotId::Attr(_, _) | SlotId::Tag(_, _) => {
            let ty = facts
                .slot_type(slot, schema)
                .ok_or_else(|| format!("no type for {}", slot.label()))?;
            let ns = slot
                .entity()
                .and_then(|e| ns_of(e.entity_type()))
                .or_else(|| ns_of(facts.action.entity_type()));
            let v: Value = parse_typed_value(input, &ty, ns.as_deref(), schema)?;
            let f = AttrFact::from_value(&v, &ty);
            Ok(match slot {
                SlotId::Tag(_, _) => SlotValue::Tag(Some(f)),
                _ => SlotValue::Attr(f),
            })
        }
    }
}

/// A complete set of tags: TPE treats unlisted tags as unknown, so list every
/// tag the policies test that `tags` lacks as absent.
fn closed_tags(
    project: &Project,
    mut tags: BTreeMap<SmolStr, AttrFact>,
) -> BTreeMap<SmolStr, AttrFact> {
    for k in project.tag_keys() {
        tags.entry(k).or_insert(AttrFact::Absent);
    }
    tags
}
