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

//! Cedar values: parsing user input against a schema type, and display.

use cedar_policy_core::ast::{self, EntityType, EntityUID, Literal, Value, ValueKind};
use cedar_policy_core::evaluator::RestrictedEvaluator;
use cedar_policy_core::extensions::Extensions;
use cedar_policy_core::validator::types::{EntityKind, Type};
use cedar_policy_core::validator::ValidatorSchema;
use smol_str::SmolStr;
use std::collections::BTreeSet;
use std::str::FromStr;

/// Evaluate a restricted expression (in Cedar syntax) to a value.
pub fn parse_value_expr(src: &str) -> Result<Value, String> {
    let expr = ast::RestrictedExpr::from_str(src).map_err(|e| e.to_string())?;
    RestrictedEvaluator::new(Extensions::all_available())
        .interpret(expr.as_borrowed())
        .map_err(|e| e.to_string())
}

/// The namespace of an entity type, if any (`PhotoApp` for `PhotoApp::User`).
pub fn namespace_of(ety: &EntityType) -> Option<String> {
    let ns = ety.name().as_ref().namespace();
    if ns.is_empty() {
        None
    } else {
        Some(ns)
    }
}

/// Parse an entity uid, accepting `Type::"id"` with or without the namespace
/// of `default_ns`, or a bare id when `default_ty` is given.
pub fn parse_euid(
    src: &str,
    default_ty: Option<&EntityType>,
    default_ns: Option<&str>,
    schema: &ValidatorSchema,
) -> Result<EntityUID, String> {
    let src = src.trim();
    if src.contains("::") {
        let direct = EntityUID::from_str(src);
        if let Ok(uid) = &direct {
            if schema.get_entity_type(uid.entity_type()).is_some() || uid.is_action() {
                return Ok(uid.clone());
            }
        }
        if let Some(ns) = default_ns {
            if let Ok(uid) = EntityUID::from_str(&format!("{ns}::{src}")) {
                if schema.get_entity_type(uid.entity_type()).is_some() || uid.is_action() {
                    return Ok(uid);
                }
            }
        }
        return match direct {
            Ok(uid) => Err(format!("unknown entity type `{}`", uid.entity_type())),
            Err(e) => Err(e.to_string()),
        };
    }
    match default_ty {
        Some(ty) => Ok(EntityUID::from_components(
            ty.clone(),
            ast::Eid::new(unquote(src)),
            None,
        )),
        None => Err("expected an entity uid like `Type::\"id\"`".into()),
    }
}

/// Strip surrounding double quotes (unescaping), if present.
pub fn unquote(s: &str) -> SmolStr {
    let t = s.trim();
    let Some(inner) = t.strip_prefix('"').and_then(|x| x.strip_suffix('"')) else {
        return SmolStr::new(t);
    };
    match parse_value_expr(t).map(|v| v.value) {
        Ok(ValueKind::Lit(Literal::String(s))) => s,
        _ => SmolStr::new(inner),
    }
}

/// Parse user input as a value of type `ty`.
///
/// Strings may be given without quotes; entity references may omit the
/// namespace or (when the type is unambiguous) be just an id.
pub fn parse_typed_value(
    src: &str,
    ty: &Type,
    default_ns: Option<&str>,
    schema: &ValidatorSchema,
) -> Result<Value, String> {
    let src = src.trim();
    let entity_set = match ty {
        Type::Set {
            element_type: Some(elt),
        } => match elt.as_ref() {
            Type::Entity(kind) => Some(kind),
            _ => None,
        },
        _ => None,
    };
    let value = match ty {
        Type::String if !src.starts_with('"') => Value::from(Literal::String(SmolStr::new(src))),
        Type::Entity(kind) => Value::from(parse_euid(
            src,
            single_entity_type(kind).as_ref(),
            default_ns,
            schema,
        )?),
        _ if entity_set.is_some() => {
            let ety = entity_set.and_then(single_entity_type);
            let uids = parse_euid_list(src, ety.as_ref(), default_ns, schema)?;
            Value::set(uids.into_iter().map(Value::from), None)
        }
        // Bare extension literals: `10.0.0.1` for an ipaddr, etc.
        Type::ExtensionType { name } if !src.contains('(') => {
            let ctor = match name.to_string().as_str() {
                "ipaddr" => "ip",
                other => other,
            }
            .to_string();
            let lit = if src.starts_with('"') {
                src.to_string()
            } else {
                format!("\"{}\"", src.escape_debug())
            };
            parse_value_expr(&format!("{ctor}({lit})"))?
        }
        _ => parse_value_expr(src)?,
    };
    if conforms(&value, ty) {
        Ok(value)
    } else {
        Err(format!("expected a value of type {}", type_name(ty)))
    }
}

/// Parse a list of entity uids: `[A::"x", A::"y"]`, `A::"x", A::"y"`, or bare ids.
pub fn parse_euid_list(
    src: &str,
    default_ty: Option<&EntityType>,
    default_ns: Option<&str>,
    schema: &ValidatorSchema,
) -> Result<BTreeSet<EntityUID>, String> {
    let inner = src.trim();
    let inner = inner
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(inner);
    let mut out = BTreeSet::new();
    for item in split_top_level(inner) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        out.insert(parse_euid(item, default_ty, default_ns, schema)?);
    }
    Ok(out)
}

/// Split on commas that are not inside quotes.
fn split_top_level(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_str = false;
    let mut escaped = false;
    for c in s.chars() {
        if in_str {
            cur.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
            cur.push(c);
        } else if c == ',' {
            parts.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    parts.push(cur);
    parts
}

pub fn single_entity_type(kind: &EntityKind) -> Option<EntityType> {
    match kind {
        EntityKind::Entity(lub) => lub.get_single_entity().cloned(),
        EntityKind::AnyEntity => None,
    }
}

/// Does `v` conform to `ty`?
pub fn conforms(v: &Value, ty: &Type) -> bool {
    match (&v.value, ty) {
        (_, Type::Never) => false,
        (ValueKind::Lit(Literal::Bool(_)), Type::Bool(_)) => true,
        (ValueKind::Lit(Literal::Long(_)), Type::Long) => true,
        (ValueKind::Lit(Literal::String(_)), Type::String) => true,
        (ValueKind::Lit(Literal::EntityUID(uid)), Type::Entity(kind)) => match kind {
            EntityKind::AnyEntity => true,
            EntityKind::Entity(lub) => lub
                .get_single_entity()
                .is_none_or(|t| t == uid.entity_type()),
        },
        (ValueKind::Set(s), Type::Set { element_type }) => match element_type {
            None => true,
            Some(elt) => s.iter().all(|e| conforms(e, elt)),
        },
        (ValueKind::Record(r), Type::Record { attrs, .. }) => {
            attrs.iter().all(|(k, a)| match r.get(k) {
                Some(v) => conforms(v, &a.attr_type),
                None => !a.is_required,
            }) && r.keys().all(|k| attrs.get_attr(k).is_some())
        }
        (ValueKind::ExtensionValue(e), Type::ExtensionType { name }) => &e.typename() == name,
        _ => false,
    }
}

/// Short, user-facing name for a type (`String`, `Set<User>`, ...).
pub fn type_name(ty: &Type) -> String {
    match ty {
        Type::Bool(_) => "Bool".into(),
        Type::Long => "Long".into(),
        Type::String => "String".into(),
        Type::Entity(EntityKind::Entity(lub)) => match lub.get_single_entity() {
            Some(e) => e.name().basename().to_string(),
            None => "Entity".into(),
        },
        Type::Entity(EntityKind::AnyEntity) => "Entity".into(),
        Type::Set {
            element_type: Some(elt),
        } => format!("Set<{}>", type_name(elt)),
        Type::Set { element_type: None } => "Set".into(),
        Type::Record { .. } => "Record".into(),
        Type::ExtensionType { name } => name.to_string(),
        Type::Never => "Never".into(),
    }
}

/// Render a value in Cedar syntax.
pub fn value_to_string(v: &Value) -> String {
    match &v.value {
        ValueKind::Lit(Literal::String(s)) => format!("\"{}\"", s.escape_debug()),
        ValueKind::Lit(Literal::EntityUID(u)) => u.to_string(),
        ValueKind::Lit(l) => l.to_string(),
        ValueKind::Set(s) => {
            let mut items: Vec<String> = s.iter().map(value_to_string).collect();
            items.sort();
            format!("[{}]", items.join(", "))
        }
        ValueKind::Record(r) => {
            let items: Vec<String> = r
                .iter()
                .map(|(k, v)| format!("{}: {}", record_key(k), value_to_string(v)))
                .collect();
            format!("{{{}}}", items.join(", "))
        }
        ValueKind::ExtensionValue(_) => v.to_string(),
    }
}

/// A record key, quoted unless it is a valid identifier.
pub fn record_key(k: &str) -> String {
    let ident = !k.is_empty()
        && k.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ident {
        k.to_string()
    } else {
        format!("\"{}\"", k.escape_debug())
    }
}

/// A list of entity uids rendered as a Cedar set literal.
pub fn euid_set_to_string<'a>(uids: impl IntoIterator<Item = &'a EntityUID>) -> String {
    let items: Vec<String> = uids.into_iter().map(|u| u.to_string()).collect();
    format!("[{}]", items.join(", "))
}

pub fn can_have_parents(ety: &EntityType, schema: &ValidatorSchema) -> bool {
    !parent_types(ety, schema).is_empty()
}

/// Entity types that can be parents of `ety`.
pub fn parent_types(ety: &EntityType, schema: &ValidatorSchema) -> Vec<EntityType> {
    schema
        .entity_types()
        .filter(|t| t.has_descendant_entity_type(ety))
        .map(|t| t.name().clone())
        .collect()
}
