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

//! Mapping a solver model onto the facts that are still unknown.

use cedar_policy_core::ast::{self, EntityUID, Value, ValueKind};
use cedar_policy_core::validator::types::Type;
use smol_str::SmolStr;
use std::collections::{BTreeMap, BTreeSet};

use super::{Assignment, Model};
use crate::analysis;
use crate::eval::Evaluation;
use crate::facts::{
    record_type, unknown_record, AttrFact, EntityFacts, Facts, PartialUid, SlotId, SlotValue,
};
use crate::project::Project;
use crate::values::can_have_parents;

/// Assignments, from `model`, for the slots that are unknown in `facts`.
pub(super) fn model_assignments(
    project: &Project,
    facts: &Facts,
    eval: &Evaluation,
    model: &Model,
) -> Vec<Assignment> {
    let schema = project.vschema();
    let mut out = Vec::new();
    let req: &ast::Request = model.request.as_ref();

    if let (Some(ast::Context::Value(m)), Some(ty)) =
        (req.context(), schema.context_type(&facts.action))
    {
        fill_record(
            &facts.context,
            Some(m.as_ref()),
            ty,
            &mut vec![],
            &mut |p, f| {
                out.push(Assignment {
                    slot: SlotId::Context(p),
                    value: SlotValue::Attr(f),
                });
            },
        );
    }
    for (pu, entry, slot) in [
        (&facts.principal, req.principal(), SlotId::Principal),
        (&facts.resource, req.resource(), SlotId::Resource),
    ] {
        if let (None, Some(u)) = (&pu.eid, entry.uid()) {
            if u.entity_type() == &pu.ty {
                out.push(Assignment {
                    slot,
                    value: SlotValue::Uid(PartialUid {
                        ty: pu.ty.clone(),
                        eid: Some(u.eid().clone()),
                    }),
                });
            }
        }
    }

    // Order entities as the request, then the residuals, mention them.
    let mut mentioned: Vec<&EntityUID> = [req.principal().uid(), req.resource().uid()]
        .into_iter()
        .flatten()
        .collect();
    for u in eval
        .policies
        .iter()
        .flat_map(|p| &p.needs)
        .filter_map(|n| n.slot.entity())
    {
        if !mentioned.contains(&u) {
            mentioned.push(u);
        }
    }
    let entities: &cedar_policy_core::entities::Entities = model.entities.as_ref();
    let mut ordered: Vec<_> = entities.iter().filter(|e| !e.uid().is_action()).collect();
    ordered.sort_by_key(|e| {
        let pos = mentioned.iter().position(|u| *u == e.uid());
        (pos.unwrap_or(usize::MAX), e.uid().clone())
    });

    for e in ordered {
        let uid = e.uid();
        let Some(et) = schema.get_entity_type(uid.entity_type()) else {
            continue;
        };
        let known = facts
            .entities
            .get(uid)
            .cloned()
            .unwrap_or_else(|| EntityFacts::unknown(uid.entity_type(), schema));
        if known.parents.is_none() && can_have_parents(uid.entity_type(), schema) {
            out.push(Assignment {
                slot: SlotId::Parents(uid.clone()),
                value: SlotValue::Parents(Some(e.ancestors().cloned().collect())),
            });
        }
        let attrs_ty = record_type(et.attributes());
        fill_record(
            &known.attrs,
            Some(&to_values(e.attrs())),
            &attrs_ty,
            &mut vec![],
            &mut |p, f| {
                out.push(Assignment {
                    slot: SlotId::Attr(uid.clone(), p),
                    value: SlotValue::Attr(f),
                });
            },
        );
        if et.tag_type().is_none() {
            continue;
        }
        let model_tags = to_values(e.tags());
        let mut keys: BTreeSet<SmolStr> = model_tags.keys().cloned().collect();
        for p in &eval.policies {
            keys.extend(analysis::tag_keys(&p.residual, uid));
        }
        for k in keys {
            if known
                .tags
                .as_ref()
                .and_then(|t| t.get(&k))
                .is_some_and(AttrFact::is_known)
            {
                continue;
            }
            let f = model_tags
                .get(&k)
                .map_or(AttrFact::Absent, |v| AttrFact::Value(v.clone()));
            out.push(Assignment {
                slot: SlotId::Tag(uid.clone(), k),
                value: SlotValue::Tag(Some(f)),
            });
        }
    }
    out
}

/// Call `out` for each field of `known` that is not yet known, with its value
/// from `model` (a missing key means absent).
fn fill_record(
    known: &BTreeMap<SmolStr, AttrFact>,
    model: Option<&BTreeMap<SmolStr, Value>>,
    ty: &Type,
    prefix: &mut Vec<SmolStr>,
    out: &mut dyn FnMut(Vec<SmolStr>, AttrFact),
) {
    let Type::Record { attrs, .. } = ty else {
        return;
    };
    for (k, f) in known {
        let Some(aty) = attrs.get_attr(k) else {
            continue;
        };
        let mv = model.and_then(|m| m.get(k));
        prefix.push(k.clone());
        match (f, mv) {
            (AttrFact::Value(_) | AttrFact::Absent, _) => {}
            (_, None) => {
                if !aty.is_required {
                    out(prefix.clone(), AttrFact::Absent);
                }
            }
            (AttrFact::Record(sub), Some(v)) => {
                if let ValueKind::Record(r) = &v.value {
                    fill_record(sub, Some(r.as_ref()), &aty.attr_type, prefix, out);
                }
            }
            (AttrFact::Unknown | AttrFact::UnknownExistence, Some(v)) => {
                match (&v.value, aty.attr_type.as_ref()) {
                    // Expand a record so each field can be minimized separately:
                    // first make the record present, then set its fields.
                    (ValueKind::Record(r), Type::Record { attrs: sub, .. }) => {
                        let unknown = unknown_record(sub);
                        out(prefix.clone(), AttrFact::Record(unknown.clone()));
                        fill_record(&unknown, Some(r.as_ref()), &aty.attr_type, prefix, out);
                    }
                    _ => out(prefix.clone(), AttrFact::from_value(v, &aty.attr_type)),
                }
            }
        }
        prefix.pop();
    }
}

fn to_values<'a, V: Clone + 'a>(
    it: impl Iterator<Item = (&'a SmolStr, &'a V)>,
) -> BTreeMap<SmolStr, Value>
where
    Value: TryFrom<V>,
{
    it.filter_map(|(k, v)| Value::try_from(v.clone()).ok().map(|v| (k.clone(), v)))
        .collect()
}
