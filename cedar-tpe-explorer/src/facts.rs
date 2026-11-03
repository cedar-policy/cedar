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

//! Partial knowledge about a request and the entities it touches.
//!
//! Every individually-settable piece of knowledge is addressed by a
//! [`SlotId`]. Front ends edit facts slot by slot; the suggestion engine
//! proposes sets of `(SlotId, SlotValue)` assignments.

use cedar_policy_core::ast::{Eid, EntityType, EntityUID, Value, ValueKind};
use cedar_policy_core::validator::types::{AttributeType, Attributes, Type};
use cedar_policy_core::validator::ValidatorSchema;
use smol_str::SmolStr;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::project::Project;
use crate::values::{self, can_have_parents, value_to_string};

/// What is known about one attribute (or record field, or tag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrFact {
    /// Present with this (non-record) value.
    Value(Value),
    /// Present, value unknown.
    Unknown,
    /// Known not to exist.
    Absent,
    /// Unknown whether it exists (only meaningful for optional attributes).
    UnknownExistence,
    /// A present record, with per-field knowledge.
    Record(BTreeMap<SmolStr, AttrFact>),
}

impl AttrFact {
    /// Is this fully known (no unknowns anywhere inside)?
    pub fn is_known(&self) -> bool {
        match self {
            AttrFact::Value(_) | AttrFact::Absent => true,
            AttrFact::Unknown | AttrFact::UnknownExistence => false,
            AttrFact::Record(m) => m.values().all(AttrFact::is_known),
        }
    }

    /// Is this a leaf that holds no knowledge at all?
    pub fn is_unknown(&self) -> bool {
        match self {
            AttrFact::Unknown | AttrFact::UnknownExistence => true,
            AttrFact::Record(m) => m.values().all(AttrFact::is_unknown),
            _ => false,
        }
    }

    /// Construct from a concrete value of type `ty`, expanding records so
    /// that each field is individually addressable.
    pub fn from_value(v: &Value, ty: &Type) -> Self {
        match (&v.value, ty) {
            (ValueKind::Record(r), Type::Record { attrs, .. }) => {
                let mut m = BTreeMap::new();
                for (k, a) in attrs.iter() {
                    let f = match r.get(k) {
                        Some(v) => AttrFact::from_value(v, &a.attr_type),
                        None => AttrFact::Absent,
                    };
                    m.insert(k.clone(), f);
                }
                AttrFact::Record(m)
            }
            _ => AttrFact::Value(v.clone()),
        }
    }

    /// Convert back to a concrete value, if fully known and present.
    pub fn to_value(&self) -> Option<Value> {
        match self {
            AttrFact::Value(v) => Some(v.clone()),
            AttrFact::Record(m) => {
                let mut out = BTreeMap::new();
                for (k, f) in m {
                    match f {
                        AttrFact::Absent => {}
                        _ => {
                            out.insert(k.clone(), f.to_value()?);
                        }
                    }
                }
                Some(Value::record(out, None))
            }
            _ => None,
        }
    }

    /// Short rendering used in labels and suggestions.
    pub fn describe(&self) -> String {
        match self {
            AttrFact::Value(v) => value_to_string(v),
            AttrFact::Unknown => "?".into(),
            AttrFact::Absent => "absent".into(),
            AttrFact::UnknownExistence => "unknown".into(),
            AttrFact::Record(_) => match self.to_value() {
                Some(v) => value_to_string(&v),
                None => "{..}".into(),
            },
        }
    }
}

/// Default knowledge for a record type: nothing is known.
pub fn unknown_record(attrs: &Attributes) -> BTreeMap<SmolStr, AttrFact> {
    attrs
        .iter()
        .map(|(k, a)| {
            let f = if a.is_required {
                unknown_present(&a.attr_type)
            } else {
                AttrFact::UnknownExistence
            };
            (k.clone(), f)
        })
        .collect()
}

/// Knowledge for an attribute that is present but whose value is unknown.
pub fn unknown_present(ty: &Type) -> AttrFact {
    match ty {
        Type::Record { attrs, .. } => AttrFact::Record(unknown_record(attrs)),
        _ => AttrFact::Unknown,
    }
}

/// What is known about one entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityFacts {
    /// Direct parents, if known.
    pub parents: Option<BTreeSet<EntityUID>>,
    /// Per-attribute knowledge, one entry per schema attribute.
    pub attrs: BTreeMap<SmolStr, AttrFact>,
    /// Tags, if any knowledge exists. Keys missing from the map are of
    /// unknown existence.
    pub tags: Option<BTreeMap<SmolStr, AttrFact>>,
}

impl EntityFacts {
    /// An entity about which nothing is known.
    pub fn unknown(ety: &EntityType, schema: &ValidatorSchema) -> Self {
        let (attrs, has_tags) = match schema.get_entity_type(ety) {
            Some(t) => (unknown_record(t.attributes()), t.tag_type().is_some()),
            None => (BTreeMap::new(), false),
        };
        Self {
            parents: if can_have_parents(ety, schema) {
                None
            } else {
                Some(BTreeSet::new())
            },
            attrs,
            tags: if has_tags {
                None
            } else {
                Some(BTreeMap::new())
            },
        }
    }

    pub fn is_unknown(&self, ety: &EntityType, schema: &ValidatorSchema) -> bool {
        *self == Self::unknown(ety, schema)
    }
}

/// An entity reference whose id may be unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialUid {
    pub ty: EntityType,
    pub eid: Option<Eid>,
}

impl PartialUid {
    pub fn uid(&self) -> Option<EntityUID> {
        self.eid
            .as_ref()
            .map(|e| EntityUID::from_components(self.ty.clone(), e.clone(), None))
    }
}

impl fmt::Display for PartialUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.uid() {
            Some(u) => write!(f, "{u}"),
            None => write!(f, "{}::?", self.ty),
        }
    }
}

/// Address of a single piece of knowledge.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SlotId {
    Principal,
    Action,
    Resource,
    /// A (possibly nested) context field.
    Context(Vec<SmolStr>),
    /// The parents of an entity.
    Parents(EntityUID),
    /// A (possibly nested) entity attribute.
    Attr(EntityUID, Vec<SmolStr>),
    /// The whole tag map of an entity.
    Tags(EntityUID),
    /// A single tag of an entity.
    Tag(EntityUID, SmolStr),
}

impl SlotId {
    /// The entity this slot belongs to, if any.
    pub fn entity(&self) -> Option<&EntityUID> {
        match self {
            SlotId::Parents(e) | SlotId::Attr(e, _) | SlotId::Tags(e) | SlotId::Tag(e, _) => {
                Some(e)
            }
            _ => None,
        }
    }

    /// Human readable name of the slot, e.g. `PhotoApp::User::"alice".meta.dept`.
    pub fn label(&self) -> String {
        match self {
            SlotId::Principal => "request principal id".into(),
            SlotId::Action => "request action".into(),
            SlotId::Resource => "request resource id".into(),
            SlotId::Context(p) => format!("context.{}", join_path(p)),
            SlotId::Parents(e) => format!("{e} parents"),
            SlotId::Attr(e, p) => format!("{e}.{}", join_path(p)),
            SlotId::Tags(e) => format!("{e} tags"),
            SlotId::Tag(e, k) => format!("{e}.getTag(\"{}\")", k.escape_debug()),
        }
    }

    /// Does `other` live inside this slot (or equal it)?
    pub fn contains(&self, other: &SlotId) -> bool {
        match (self, other) {
            (SlotId::Context(a), SlotId::Context(b)) => b.starts_with(a),
            (SlotId::Attr(e1, a), SlotId::Attr(e2, b)) => e1 == e2 && b.starts_with(a),
            (SlotId::Tags(e1), SlotId::Tag(e2, _)) => e1 == e2,
            _ => self == other,
        }
    }
}

pub fn join_path(p: &[SmolStr]) -> String {
    p.iter()
        .map(|s| values::record_key(s))
        .collect::<Vec<_>>()
        .join(".")
}

/// The value stored in a slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotValue {
    Uid(PartialUid),
    Action(EntityUID),
    Attr(AttrFact),
    Parents(Option<BTreeSet<EntityUID>>),
    Tags(Option<BTreeMap<SmolStr, AttrFact>>),
    /// `None` means the tag's existence is unknown.
    Tag(Option<AttrFact>),
}

impl SlotValue {
    /// Does this value carry no knowledge?
    pub fn is_unknown(&self) -> bool {
        match self {
            SlotValue::Uid(u) => u.eid.is_none(),
            SlotValue::Action(_) => false,
            SlotValue::Attr(f) => f.is_unknown(),
            SlotValue::Parents(p) => p.is_none(),
            SlotValue::Tags(t) => t.is_none(),
            SlotValue::Tag(t) => t.as_ref().is_none_or(AttrFact::is_unknown),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            SlotValue::Uid(u) => u.to_string(),
            SlotValue::Action(a) => a.to_string(),
            SlotValue::Attr(f) => f.describe(),
            SlotValue::Parents(Some(p)) => values::euid_set_to_string(p),
            SlotValue::Parents(None) | SlotValue::Tags(None) | SlotValue::Tag(None) => "?".into(),
            SlotValue::Tags(Some(t)) => {
                let items: Vec<String> = t
                    .iter()
                    .map(|(k, v)| format!("\"{}\": {}", k.escape_debug(), v.describe()))
                    .collect();
                format!("{{{}}}", items.join(", "))
            }
            SlotValue::Tag(Some(f)) => f.describe(),
        }
    }
}

/// Render an assignment like `context.authn_method = "mfa"`.
pub fn describe_assignment(slot: &SlotId, value: &SlotValue) -> String {
    match (slot, value) {
        (SlotId::Principal, v) => format!("principal = {}", v.describe()),
        (SlotId::Resource, v) => format!("resource = {}", v.describe()),
        (SlotId::Action, v) => format!("action = {}", v.describe()),
        (SlotId::Parents(e), v) => format!("{e} in {}", v.describe()),
        (SlotId::Tags(e), v) => format!("{e} tags {}", v.describe()),
        (s, v) => format!("{} = {}", s.label(), v.describe()),
    }
}

/// Everything known about a request and its entities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub principal: PartialUid,
    pub action: EntityUID,
    pub resource: PartialUid,
    pub context: BTreeMap<SmolStr, AttrFact>,
    pub entities: BTreeMap<EntityUID, EntityFacts>,
}

impl Facts {
    /// Facts for `action` with nothing else known. Uses the first principal
    /// and resource type the action applies to.
    pub fn new(project: &Project, action: &EntityUID) -> Result<Self, String> {
        let schema = project.vschema();
        let a = schema
            .get_action_id(action)
            .ok_or_else(|| format!("unknown action {action}"))?;
        let mut ptys: Vec<_> = a.applies_to_principals().cloned().collect();
        let mut rtys: Vec<_> = a.applies_to_resources().cloned().collect();
        ptys.sort();
        rtys.sort();
        let principal = ptys
            .first()
            .cloned()
            .ok_or_else(|| format!("{action} applies to no principals"))?;
        let resource = rtys
            .first()
            .cloned()
            .ok_or_else(|| format!("{action} applies to no resources"))?;
        Ok(Self {
            principal: PartialUid {
                ty: principal,
                eid: None,
            },
            action: action.clone(),
            resource: PartialUid {
                ty: resource,
                eid: None,
            },
            context: context_attrs(schema, action)
                .map(unknown_record)
                .unwrap_or_default(),
            entities: BTreeMap::new(),
        })
    }

    /// Facts for the first action in the schema.
    pub fn initial(project: &Project) -> Result<Self, String> {
        let action = project
            .actions()
            .into_iter()
            .next()
            .ok_or("the schema declares no actions")?;
        Self::new(project, &action)
    }

    /// The declaration of a context field or entity attribute path.
    fn slot_attr<'s>(
        &self,
        slot: &SlotId,
        schema: &'s ValidatorSchema,
    ) -> Option<&'s AttributeType> {
        match slot {
            SlotId::Context(p) => attr_at(context_attrs(schema, &self.action)?, p),
            SlotId::Attr(e, p) => attr_at(schema.get_entity_type(e.entity_type())?.attributes(), p),
            _ => None,
        }
    }

    /// Schema type of a context field, entity attribute path, or tag.
    pub fn slot_type(&self, slot: &SlotId, schema: &ValidatorSchema) -> Option<Type> {
        match slot {
            SlotId::Tag(e, _) | SlotId::Tags(e) => {
                schema.get_entity_type(e.entity_type())?.tag_type().cloned()
            }
            _ => Some(self.slot_attr(slot, schema)?.attr_type.as_ref().clone()),
        }
    }

    /// Is the attribute at this slot required by the schema?
    pub fn slot_required(&self, slot: &SlotId, schema: &ValidatorSchema) -> bool {
        match slot {
            SlotId::Context(_) | SlotId::Attr(_, _) => {
                self.slot_attr(slot, schema).is_some_and(|a| a.is_required)
            }
            SlotId::Tag(_, _) => false,
            _ => true,
        }
    }

    /// Read a slot. `None` if the slot does not exist (e.g. the entity is
    /// not in the facts, or the path goes through an absent record).
    pub fn get(&self, slot: &SlotId) -> Option<SlotValue> {
        match slot {
            SlotId::Principal => Some(SlotValue::Uid(self.principal.clone())),
            SlotId::Resource => Some(SlotValue::Uid(self.resource.clone())),
            SlotId::Action => Some(SlotValue::Action(self.action.clone())),
            SlotId::Context(p) => get_path(&self.context, p).cloned().map(SlotValue::Attr),
            SlotId::Parents(e) => Some(SlotValue::Parents(self.entities.get(e)?.parents.clone())),
            SlotId::Attr(e, p) => get_path(&self.entities.get(e)?.attrs, p)
                .cloned()
                .map(SlotValue::Attr),
            SlotId::Tags(e) => Some(SlotValue::Tags(self.entities.get(e)?.tags.clone())),
            SlotId::Tag(e, k) => Some(SlotValue::Tag(
                self.entities
                    .get(e)?
                    .tags
                    .as_ref()
                    .and_then(|t| t.get(k).cloned()),
            )),
        }
    }

    /// Like [`Facts::get`], but treats missing entities as fully unknown.
    pub fn get_or_unknown(&self, slot: &SlotId, schema: &ValidatorSchema) -> Option<SlotValue> {
        if let Some(e) = slot.entity() {
            if !self.entities.contains_key(e) {
                let mut tmp = self.clone();
                tmp.ensure_entity(e, schema);
                return tmp.get(slot);
            }
        }
        self.get(slot)
    }

    /// Add an entity with nothing known about it, if it's not already present.
    pub fn ensure_entity(&mut self, uid: &EntityUID, schema: &ValidatorSchema) {
        if uid.is_action() || schema.get_entity_type(uid.entity_type()).is_none() {
            return;
        }
        if !self.entities.contains_key(uid) {
            self.entities
                .insert(uid.clone(), EntityFacts::unknown(uid.entity_type(), schema));
        }
    }

    /// Write a slot.
    pub fn set(
        &mut self,
        slot: &SlotId,
        value: SlotValue,
        schema: &ValidatorSchema,
    ) -> Result<(), String> {
        match (slot, value) {
            (SlotId::Principal, SlotValue::Uid(u)) => {
                self.principal = u;
                if let Some(uid) = self.principal.uid() {
                    self.ensure_entity(&uid, schema);
                }
            }
            (SlotId::Resource, SlotValue::Uid(u)) => {
                self.resource = u;
                if let Some(uid) = self.resource.uid() {
                    self.ensure_entity(&uid, schema);
                }
            }
            (SlotId::Action, SlotValue::Action(a)) => {
                if a != self.action {
                    let action = schema
                        .get_action_id(&a)
                        .ok_or_else(|| format!("unknown action {a}"))?;
                    let ptys: Vec<_> = action.applies_to_principals().cloned().collect();
                    let rtys: Vec<_> = action.applies_to_resources().cloned().collect();
                    if !ptys.contains(&self.principal.ty) {
                        self.principal = PartialUid {
                            ty: ptys.into_iter().min().ok_or("action has no principals")?,
                            eid: None,
                        };
                    }
                    if !rtys.contains(&self.resource.ty) {
                        self.resource = PartialUid {
                            ty: rtys.into_iter().min().ok_or("action has no resources")?,
                            eid: None,
                        };
                    }
                    self.context = context_attrs(schema, &a)
                        .map(unknown_record)
                        .unwrap_or_default();
                    self.action = a;
                }
            }
            (SlotId::Context(p), SlotValue::Attr(f)) => {
                let ty = schema.context_type(&self.action).ok_or("unknown action")?;
                set_path(&mut self.context, p, f, ty)?;
            }
            (SlotId::Parents(e), SlotValue::Parents(p)) => {
                self.ensure_entity(e, schema);
                self.entity_mut(e)?.parents = p;
            }
            (SlotId::Attr(e, p), SlotValue::Attr(f)) => {
                self.ensure_entity(e, schema);
                let et = schema
                    .get_entity_type(e.entity_type())
                    .ok_or_else(|| format!("unknown entity type {}", e.entity_type()))?;
                set_path(
                    &mut self.entity_mut(e)?.attrs,
                    p,
                    f,
                    &record_type(et.attributes()),
                )?;
            }
            (SlotId::Tags(e), SlotValue::Tags(t)) => {
                self.ensure_entity(e, schema);
                self.entity_mut(e)?.tags = t;
            }
            (SlotId::Tag(e, k), SlotValue::Tag(t)) => {
                self.ensure_entity(e, schema);
                let ent = self.entity_mut(e)?;
                let tags = ent.tags.get_or_insert_with(BTreeMap::new);
                match t {
                    Some(f) => {
                        tags.insert(k.clone(), f);
                    }
                    None => {
                        tags.remove(k);
                    }
                }
            }
            (s, v) => return Err(format!("cannot assign {v:?} to {}", s.label())),
        }
        Ok(())
    }

    fn entity_mut(&mut self, e: &EntityUID) -> Result<&mut EntityFacts, String> {
        self.entities
            .get_mut(e)
            .ok_or_else(|| format!("{e} has an unknown entity type"))
    }

    /// Drop entities about which nothing is known and which are not
    /// referenced by the request or in `keep`.
    pub fn prune(&mut self, keep: &BTreeSet<EntityUID>, schema: &ValidatorSchema) {
        let p = self.principal.uid();
        let r = self.resource.uid();
        self.entities.retain(|uid, ent| {
            Some(uid) == p.as_ref()
                || Some(uid) == r.as_ref()
                || keep.contains(uid)
                || !ent.is_unknown(uid.entity_type(), schema)
        });
    }

    /// What `f` at `slot` says beyond the schema, on its own: its value,
    /// absence, or (for an optional attribute) presence.
    fn known_fact(
        &self,
        slot: &SlotId,
        f: &AttrFact,
        schema: &ValidatorSchema,
    ) -> Option<AttrFact> {
        let optional = !self.slot_required(slot, schema);
        match f {
            AttrFact::Value(_) | AttrFact::Absent => Some(f.clone()),
            AttrFact::Unknown if optional => Some(AttrFact::Unknown),
            AttrFact::Record(_) if optional => match self.slot_type(slot, schema)? {
                Type::Record { attrs, .. } => Some(AttrFact::Record(unknown_record(&attrs))),
                _ => None,
            },
            AttrFact::Unknown | AttrFact::Record(_) | AttrFact::UnknownExistence => None,
        }
    }

    /// All slots that currently hold knowledge, in a stable order. Used as
    /// the starting point for explanations.
    pub fn known_slots(&self, schema: &ValidatorSchema) -> Vec<(SlotId, SlotValue)> {
        let mut out = Vec::new();
        if self.principal.eid.is_some() {
            out.push((SlotId::Principal, SlotValue::Uid(self.principal.clone())));
        }
        if self.resource.eid.is_some() {
            out.push((SlotId::Resource, SlotValue::Uid(self.resource.clone())));
        }
        collect_known(&self.context, &mut vec![], &mut |p, f| {
            let slot = SlotId::Context(p);
            if let Some(f) = self.known_fact(&slot, f, schema) {
                out.push((slot, SlotValue::Attr(f)));
            }
        });
        for (uid, ent) in &self.entities {
            if let Some(p) = &ent.parents {
                out.push((
                    SlotId::Parents(uid.clone()),
                    SlotValue::Parents(Some(p.clone())),
                ));
            }
            collect_known(&ent.attrs, &mut vec![], &mut |p, f| {
                let slot = SlotId::Attr(uid.clone(), p);
                if let Some(f) = self.known_fact(&slot, f, schema) {
                    out.push((slot, SlotValue::Attr(f)));
                }
            });
            if let Some(t) = &ent.tags {
                for (k, f) in t {
                    out.push((
                        SlotId::Tag(uid.clone(), k.clone()),
                        SlotValue::Tag(Some(f.clone())),
                    ));
                }
            }
        }
        out
    }

    /// The "unknown" value for a slot, used when retracting knowledge.
    pub fn unknown_value_for(&self, slot: &SlotId, schema: &ValidatorSchema) -> SlotValue {
        match slot {
            SlotId::Principal => SlotValue::Uid(PartialUid {
                ty: self.principal.ty.clone(),
                eid: None,
            }),
            SlotId::Resource => SlotValue::Uid(PartialUid {
                ty: self.resource.ty.clone(),
                eid: None,
            }),
            SlotId::Action => SlotValue::Action(self.action.clone()),
            SlotId::Context(_) | SlotId::Attr(_, _) => {
                if self.slot_required(slot, schema) {
                    SlotValue::Attr(match self.slot_type(slot, schema) {
                        Some(ty) => unknown_present(&ty),
                        None => AttrFact::Unknown,
                    })
                } else {
                    SlotValue::Attr(AttrFact::UnknownExistence)
                }
            }
            SlotId::Parents(_) => SlotValue::Parents(None),
            SlotId::Tags(_) => SlotValue::Tags(None),
            SlotId::Tag(_, _) => SlotValue::Tag(None),
        }
    }
}

/// Visit every field, outer records before their fields.
fn collect_known(
    m: &BTreeMap<SmolStr, AttrFact>,
    prefix: &mut Vec<SmolStr>,
    out: &mut dyn FnMut(Vec<SmolStr>, &AttrFact),
) {
    for (k, f) in m {
        prefix.push(k.clone());
        out(prefix.clone(), f);
        if let AttrFact::Record(sub) = f {
            collect_known(sub, prefix, out);
        }
        prefix.pop();
    }
}

/// The attribute declared at a (non-empty) record path.
pub fn attr_at<'a>(attrs: &'a Attributes, path: &[SmolStr]) -> Option<&'a AttributeType> {
    let (first, rest) = path.split_first()?;
    let a = attrs.get_attr(first)?;
    match (rest.is_empty(), a.attr_type.as_ref()) {
        (true, _) => Some(a),
        (false, Type::Record { attrs, .. }) => attr_at(attrs, rest),
        (false, _) => None,
    }
}

/// The context attributes `action` declares; `None` if it is unknown or
/// `external`.
pub fn context_attrs<'s>(
    schema: &'s ValidatorSchema,
    action: &EntityUID,
) -> Option<&'s Attributes> {
    match schema.context_type(action)? {
        Type::Record { attrs, .. } => Some(attrs),
        _ => None,
    }
}

/// A closed record type with these attributes, e.g. an entity's attributes.
pub fn record_type(attrs: &Attributes) -> Type {
    Type::Record {
        attrs: attrs.clone(),
        open_attributes: Default::default(),
    }
}

pub fn get_path<'a>(m: &'a BTreeMap<SmolStr, AttrFact>, path: &[SmolStr]) -> Option<&'a AttrFact> {
    let (first, rest) = path.split_first()?;
    let f = m.get(first)?;
    if rest.is_empty() {
        Some(f)
    } else {
        match f {
            AttrFact::Record(sub) => get_path(sub, rest),
            _ => None,
        }
    }
}

/// Set a field at `path`, materializing intermediate records as needed.
fn set_path(
    m: &mut BTreeMap<SmolStr, AttrFact>,
    path: &[SmolStr],
    f: AttrFact,
    ty: &Type,
) -> Result<(), String> {
    let (first, rest) = path.split_first().ok_or("empty path")?;
    let Type::Record { attrs, .. } = ty else {
        return Err("not a record".into());
    };
    let aty = attrs
        .get_attr(first)
        .ok_or_else(|| format!("no attribute `{first}`"))?;
    if rest.is_empty() {
        let f = match f {
            AttrFact::Value(v) => AttrFact::from_value(&v, &aty.attr_type),
            AttrFact::Unknown => unknown_present(&aty.attr_type),
            other => other,
        };
        if aty.is_required && matches!(f, AttrFact::Absent | AttrFact::UnknownExistence) {
            return Err(format!("`{first}` is required, so it must be present"));
        }
        m.insert(first.clone(), f);
        Ok(())
    } else {
        let entry = m.entry(first.clone()).or_insert(AttrFact::UnknownExistence);
        if !matches!(entry, AttrFact::Record(_)) {
            *entry = unknown_present(&aty.attr_type);
        }
        let AttrFact::Record(sub) = entry else {
            return Err(format!("`{first}` is not a record"));
        };
        set_path(sub, rest, f, &aty.attr_type)
    }
}
