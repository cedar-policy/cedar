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

//! Shrinking a model to the facts that matter, with readable values.

use cedar_policy_core::ast::{Eid, EntityUID, Literal, Value, ValueKind};
use smol_str::SmolStr;
use std::collections::BTreeSet;

use super::{holds, Assignment};
use crate::eval::Evaluation;
use crate::facts::{AttrFact, Facts, PartialUid, SlotId, SlotValue};
use crate::project::Project;

type Holds<'a> = dyn Fn(&[Assignment]) -> bool + 'a;

/// Greedily drop assignments while `pred` still holds. `None` if it doesn't
/// hold with all of them.
pub fn minimize(
    project: &Project,
    facts: &Facts,
    asg: Vec<Assignment>,
    pred: impl Fn(&Evaluation) -> bool,
) -> Option<Vec<Assignment>> {
    minimize_with(asg, &|a| holds(project, facts, a, &pred))
}

/// [`minimize`], then replace solver-chosen values with small numbers and
/// placeholder names.
pub(super) fn minimize_readable(
    project: &Project,
    facts: &Facts,
    asg: Vec<Assignment>,
    pred: impl Fn(&Evaluation) -> bool,
) -> Option<Vec<Assignment>> {
    let ok = |a: &[Assignment]| holds(project, facts, a, &pred);
    let mut keep = minimize_with(asg, &ok)?;
    shrink_longs(&mut keep, &ok);
    readable_names(project, facts, &mut keep, &ok);
    Some(keep)
}

fn minimize_with(asg: Vec<Assignment>, ok: &Holds<'_>) -> Option<Vec<Assignment>> {
    if !ok(&asg) {
        return None;
    }
    let mut keep = asg;
    // Back to front: entity data before request ids, since an id can only be
    // dropped once nothing depends on it.
    for i in (0..keep.len()).rev() {
        let mut trial = keep.clone();
        trial.remove(i);
        if ok(&trial) {
            keep = trial;
        }
    }
    Some(keep)
}

/// Move each Long toward 0 while the outcome holds.
fn shrink_longs(asg: &mut [Assignment], ok: &Holds<'_>) {
    let long_of = |v: &SlotValue| match v {
        SlotValue::Attr(AttrFact::Value(v)) | SlotValue::Tag(Some(AttrFact::Value(v))) => {
            match v.value {
                ValueKind::Lit(Literal::Long(n)) => Some(n),
                _ => None,
            }
        }
        _ => None,
    };
    for i in 0..asg.len() {
        let Some(orig) = asg.get(i).and_then(|a| long_of(&a.value)) else {
            continue;
        };
        // Set the value to `n`, keeping it only if the outcome holds.
        let mut try_n = |n: i64| {
            let Some(a) = asg.get_mut(i) else {
                return false;
            };
            let new = match a.value {
                SlotValue::Tag(_) => SlotValue::Tag(Some(AttrFact::Value(n.into()))),
                _ => SlotValue::Attr(AttrFact::Value(n.into())),
            };
            let prev = std::mem::replace(&mut a.value, new);
            if ok(asg) {
                return true;
            }
            if let Some(a) = asg.get_mut(i) {
                a.value = prev;
            }
            false
        };
        if try_n(0) {
            continue;
        }
        // Binary search on the magnitude, on the side of 0 the solver chose.
        let signed = |m: u64| {
            if orig < 0 {
                0i64.checked_sub_unsigned(m)
            } else {
                i64::try_from(m).ok()
            }
        };
        let (mut good, mut bad) = (orig.unsigned_abs(), 0u64);
        while good.abs_diff(bad) > 1 {
            let mid = bad.midpoint(good);
            if signed(mid).is_some_and(&mut try_n) {
                good = mid;
            } else {
                bad = mid;
            }
        }
    }
}

/// Rename invented entity ids and strings (`""`, `"A"`) to placeholders like
/// `user-1`, keeping each rename only if the outcome holds. Values from the
/// policies or the known facts are left alone.
pub(super) fn readable_names(
    project: &Project,
    facts: &Facts,
    asg: &mut Vec<Assignment>,
    ok: &Holds<'_>,
) {
    let (policy_strings, policy_uids) = project.literals();
    let known: BTreeSet<EntityUID> = facts
        .entities
        .keys()
        .cloned()
        .chain(facts.principal.uid())
        .chain(facts.resource.uid())
        .collect();

    let mut invented: Vec<EntityUID> = Vec::new();
    for a in asg.iter() {
        let uid = match &a.value {
            SlotValue::Uid(pu) => pu.uid(),
            _ => None,
        };
        for u in uid.iter().chain(a.slot.entity()) {
            if !known.contains(u) && !policy_uids.contains(u) && !invented.contains(u) {
                invented.push(u.clone());
            }
        }
    }
    let mut taken: BTreeSet<String> = known.iter().map(|u| u.eid().as_ref().to_owned()).collect();
    for old in invented {
        let base = old
            .entity_type()
            .name()
            .basename()
            .to_string()
            .to_lowercase();
        let name = fresh(&base, &taken);
        let new =
            EntityUID::from_components(old.entity_type().clone(), Eid::new(name.as_str()), None);
        if Renaming::Uid(&old, &new).try_on(asg, ok) {
            taken.insert(name);
        }
    }

    // Strings are named after the attribute they first set.
    let mut strings: Vec<(SmolStr, SmolStr)> = Vec::new();
    for a in asg.iter() {
        let attr = match &a.slot {
            SlotId::Context(p) | SlotId::Attr(_, p) => p.last(),
            SlotId::Tag(_, k) => Some(k),
            _ => None,
        };
        let (
            Some(attr),
            SlotValue::Attr(AttrFact::Value(v)) | SlotValue::Tag(Some(AttrFact::Value(v))),
        ) = (attr, &a.value)
        else {
            continue;
        };
        if let ValueKind::Lit(Literal::String(s)) = &v.value {
            if !policy_strings.contains(s) && !strings.iter().any(|(x, _)| x == s) {
                strings.push((s.clone(), attr.clone()));
            }
        }
    }
    let mut taken: BTreeSet<String> = policy_strings.iter().map(ToString::to_string).collect();
    for (old, attr) in strings {
        let name = fresh(&attr, &taken);
        if Renaming::Str(&old, &SmolStr::new(&name)).try_on(asg, ok) {
            taken.insert(name);
        }
    }
}

/// The first `base-N` not in `taken`.
fn fresh(base: &str, taken: &BTreeSet<String>) -> String {
    let mut i: u64 = 1;
    loop {
        let name = format!("{base}-{i}");
        if !taken.contains(&name) {
            return name;
        }
        i = i.saturating_add(1);
    }
}

/// Replace one entity uid or one string everywhere in an assignment.
enum Renaming<'a> {
    Uid(&'a EntityUID, &'a EntityUID),
    Str(&'a SmolStr, &'a SmolStr),
}

impl Renaming<'_> {
    /// Rename in `asg` if the outcome still holds afterwards.
    fn try_on(&self, asg: &mut Vec<Assignment>, ok: &Holds<'_>) -> bool {
        let trial: Vec<Assignment> = asg.iter().map(|a| self.assignment(a)).collect();
        let keep = ok(&trial);
        if keep {
            *asg = trial;
        }
        keep
    }

    fn uid(&self, u: &EntityUID) -> EntityUID {
        match self {
            Self::Uid(old, new) if u == *old => (*new).clone(),
            _ => u.clone(),
        }
    }

    fn value(&self, v: &Value) -> Value {
        match &v.value {
            ValueKind::Lit(Literal::EntityUID(e)) => Value::from(self.uid(e)),
            ValueKind::Lit(Literal::String(s)) => match self {
                Self::Str(old, new) if s == *old => Value::from(Literal::String((*new).clone())),
                _ => v.clone(),
            },
            ValueKind::Set(set) => Value::set(set.iter().map(|x| self.value(x)), None),
            ValueKind::Record(r) => {
                Value::record(r.iter().map(|(k, x)| (k.clone(), self.value(x))), None)
            }
            ValueKind::Lit(_) | ValueKind::ExtensionValue(_) => v.clone(),
        }
    }

    fn fact(&self, f: &AttrFact) -> AttrFact {
        match f {
            AttrFact::Value(v) => AttrFact::Value(self.value(v)),
            AttrFact::Record(m) => {
                AttrFact::Record(m.iter().map(|(k, x)| (k.clone(), self.fact(x))).collect())
            }
            other => other.clone(),
        }
    }

    fn assignment(&self, a: &Assignment) -> Assignment {
        let slot = match &a.slot {
            SlotId::Parents(e) => SlotId::Parents(self.uid(e)),
            SlotId::Attr(e, p) => SlotId::Attr(self.uid(e), p.clone()),
            SlotId::Tags(e) => SlotId::Tags(self.uid(e)),
            SlotId::Tag(e, k) => SlotId::Tag(self.uid(e), k.clone()),
            other => other.clone(),
        };
        let value = match &a.value {
            SlotValue::Uid(pu) => SlotValue::Uid(match pu.uid() {
                Some(x) => {
                    let (ty, eid) = self.uid(&x).components();
                    PartialUid { ty, eid: Some(eid) }
                }
                None => pu.clone(),
            }),
            SlotValue::Parents(Some(ps)) => {
                SlotValue::Parents(Some(ps.iter().map(|u| self.uid(u)).collect()))
            }
            SlotValue::Attr(f) => SlotValue::Attr(self.fact(f)),
            SlotValue::Tag(Some(f)) => SlotValue::Tag(Some(self.fact(f))),
            SlotValue::Tags(Some(t)) => SlotValue::Tags(Some(
                t.iter().map(|(k, f)| (k.clone(), self.fact(f))).collect(),
            )),
            other => other.clone(),
        };
        Assignment { slot, value }
    }
}
