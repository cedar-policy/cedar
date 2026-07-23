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

//! Shared test helpers for constructing protobuf model values.
//!
//! These helpers reduce boilerplate when writing tests that operate on
//! `models::*` types directly.

use super::models;
use std::collections::HashMap;

// ====================================================================
// Name / EntityUid helpers
// ====================================================================

/// Create a `models::Name` with no namespace path.
///
/// ```ignore
/// name("User") => Name { id: "User", path: [] }
/// ```
pub fn name(id: &str) -> models::Name {
    models::Name {
        id: id.to_string(),
        path: vec![],
    }
}

/// Create a `models::Name` with a namespace path.
///
/// ```ignore
/// qualified_name("User", &["MyApp", "Types"])
///   => Name { id: "User", path: ["MyApp", "Types"] }
/// ```
pub fn qualified_name(id: &str, path: &[&str]) -> models::Name {
    models::Name {
        id: id.to_string(),
        path: path.iter().map(|s| (*s).to_string()).collect(),
    }
}

/// Create a `models::EntityUid`.
///
/// ```ignore
/// entity_uid("User", "alice") => EntityUid { ty: Name("User"), eid: "alice" }
/// ```
pub fn entity_uid(ty: models::Name, eid: &str) -> models::EntityUid {
    models::EntityUid {
        ty: Some(ty),
        eid: eid.to_string(),
    }
}

// ====================================================================
// Type helpers
// ====================================================================

/// Primitive `Bool` type.
pub fn bool_type() -> models::Type {
    models::Type {
        data: Some(models::r#type::Data::Prim(
            models::r#type::Prim::Bool.into(),
        )),
    }
}

/// Primitive `Long` type.
pub fn long_type() -> models::Type {
    models::Type {
        data: Some(models::r#type::Data::Prim(
            models::r#type::Prim::Long.into(),
        )),
    }
}

/// Primitive `String` type.
pub fn string_type() -> models::Type {
    models::Type {
        data: Some(models::r#type::Data::Prim(
            models::r#type::Prim::String.into(),
        )),
    }
}

/// `Set<element>` type.
pub fn set_type(element: models::Type) -> models::Type {
    models::Type {
        data: Some(models::r#type::Data::SetElem(Box::new(element))),
    }
}

/// Entity reference type.
pub fn entity_type(ty: &str) -> models::Type {
    models::Type {
        data: Some(models::r#type::Data::Entity(name(ty))),
    }
}

/// Extension type (e.g., `"decimal"`, `"ipaddr"`).
pub fn extension_type(ext_name: &str) -> models::Type {
    models::Type {
        data: Some(models::r#type::Data::Ext(name(ext_name))),
    }
}

/// Record type with the given attributes.
///
/// ```ignore
/// record_type([("age", required(long_type())), ("name", optional(string_type()))])
/// ```
pub fn record_type(
    attrs: impl IntoIterator<Item = (&'static str, models::AttributeType)>,
) -> models::Type {
    models::Type {
        data: Some(models::r#type::Data::Record(models::r#type::Record {
            attrs: attrs.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        })),
    }
}

/// A required attribute of the given type.
pub fn required(ty: models::Type) -> models::AttributeType {
    models::AttributeType {
        attr_type: Some(ty),
        is_required: true,
    }
}

/// An optional attribute of the given type.
pub fn optional(ty: models::Type) -> models::AttributeType {
    models::AttributeType {
        attr_type: Some(ty),
        is_required: false,
    }
}

// ====================================================================
// Expr helpers
// ====================================================================

/// Boolean literal expression.
pub fn lit_bool(b: bool) -> models::Expr {
    models::Expr {
        expr_kind: Some(models::expr::ExprKind::Lit(models::expr::Literal {
            lit: Some(models::expr::literal::Lit::B(b)),
        })),
    }
}

/// Integer literal expression.
pub fn lit_long(i: i64) -> models::Expr {
    models::Expr {
        expr_kind: Some(models::expr::ExprKind::Lit(models::expr::Literal {
            lit: Some(models::expr::literal::Lit::I(i)),
        })),
    }
}

/// String literal expression.
pub fn lit_str(s: &str) -> models::Expr {
    models::Expr {
        expr_kind: Some(models::expr::ExprKind::Lit(models::expr::Literal {
            lit: Some(models::expr::literal::Lit::S(s.to_string())),
        })),
    }
}

/// Entity UID literal expression.
pub fn lit_euid(ty: &str, eid: &str) -> models::Expr {
    models::Expr {
        expr_kind: Some(models::expr::ExprKind::Lit(models::expr::Literal {
            lit: Some(models::expr::literal::Lit::Euid(entity_uid(name(ty), eid))),
        })),
    }
}

/// Variable expression (`principal`, `action`, `resource`, `context`).
pub fn var(v: models::expr::Var) -> models::Expr {
    models::Expr {
        expr_kind: Some(models::expr::ExprKind::Var(v.into())),
    }
}

/// Unary not: `!expr`.
pub fn not(expr: models::Expr) -> models::Expr {
    models::Expr {
        expr_kind: Some(models::expr::ExprKind::UApp(Box::new(
            models::expr::UnaryApp {
                op: models::expr::unary_app::Op::Not.into(),
                expr: Some(Box::new(expr)),
            },
        ))),
    }
}

/// Binary operation.
pub fn binary(
    op: models::expr::binary_app::Op,
    left: models::Expr,
    right: models::Expr,
) -> models::Expr {
    models::Expr {
        expr_kind: Some(models::expr::ExprKind::BApp(Box::new(
            models::expr::BinaryApp {
                op: op.into(),
                left: Some(Box::new(left)),
                right: Some(Box::new(right)),
            },
        ))),
    }
}

/// If-then-else expression.
pub fn if_then_else(test: models::Expr, then: models::Expr, els: models::Expr) -> models::Expr {
    models::Expr {
        expr_kind: Some(models::expr::ExprKind::If(Box::new(models::expr::If {
            test_expr: Some(Box::new(test)),
            then_expr: Some(Box::new(then)),
            else_expr: Some(Box::new(els)),
        }))),
    }
}

/// Attribute access: `expr.attr`.
pub fn get_attr(expr: models::Expr, attr: &str) -> models::Expr {
    models::Expr {
        expr_kind: Some(models::expr::ExprKind::GetAttr(Box::new(
            models::expr::GetAttr {
                expr: Some(Box::new(expr)),
                attr: attr.to_string(),
            },
        ))),
    }
}

/// Has-attribute test: `expr has attr`.
pub fn has_attr(expr: models::Expr, attr: &str) -> models::Expr {
    models::Expr {
        expr_kind: Some(models::expr::ExprKind::HasAttr(Box::new(
            models::expr::HasAttr {
                expr: Some(Box::new(expr)),
                attr: attr.to_string(),
            },
        ))),
    }
}

/// Set literal: `[elems...]`.
pub fn set(elems: impl IntoIterator<Item = models::Expr>) -> models::Expr {
    models::Expr {
        expr_kind: Some(models::expr::ExprKind::Set(models::expr::Set {
            elements: elems.into_iter().collect(),
        })),
    }
}

/// Record literal: `{ key: value, ... }`.
pub fn record(items: impl IntoIterator<Item = (&'static str, models::Expr)>) -> models::Expr {
    models::Expr {
        expr_kind: Some(models::expr::ExprKind::Record(models::expr::Record {
            items: items.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        })),
    }
}

/// Extension function call.
pub fn ext_call(fn_name: &str, args: impl IntoIterator<Item = models::Expr>) -> models::Expr {
    models::Expr {
        expr_kind: Some(models::expr::ExprKind::ExtApp(
            models::expr::ExtensionFunctionApp {
                fn_name: Some(name(fn_name)),
                args: args.into_iter().collect(),
            },
        )),
    }
}

// ====================================================================
// Entity / EntityDecl / Schema helpers
// ====================================================================

/// Create a `models::Entity` with the given uid, attributes, and no ancestors/tags.
pub fn entity(
    ty: &str,
    eid: &str,
    attrs: impl IntoIterator<Item = (&'static str, models::Expr)>,
) -> models::Entity {
    models::Entity {
        uid: Some(entity_uid(name(ty), eid)),
        attrs: attrs.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        ancestors: vec![],
        tags: HashMap::new(),
    }
}

/// Create a `models::Entity` with attributes, ancestors, and tags.
pub fn entity_full(
    ty: &str,
    eid: &str,
    attrs: impl IntoIterator<Item = (&'static str, models::Expr)>,
    ancestors: impl IntoIterator<Item = models::EntityUid>,
    tags: impl IntoIterator<Item = (&'static str, models::Expr)>,
) -> models::Entity {
    models::Entity {
        uid: Some(entity_uid(name(ty), eid)),
        attrs: attrs.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        ancestors: ancestors.into_iter().collect(),
        tags: tags.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
    }
}

/// Create a simple `models::EntityDecl` with the given name and attributes.
pub fn entity_decl(
    ty: &str,
    attrs: impl IntoIterator<Item = (&'static str, models::AttributeType)>,
) -> models::EntityDecl {
    models::EntityDecl {
        name: Some(name(ty)),
        descendants: vec![],
        attributes: attrs.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        tags: None,
        enum_choices: vec![],
    }
}

/// Create an `models::EntityDecl` with all fields.
pub fn entity_decl_full(
    ty: &str,
    descendants: impl IntoIterator<Item = &'static str>,
    attrs: impl IntoIterator<Item = (&'static str, models::AttributeType)>,
    tags: Option<models::Type>,
) -> models::EntityDecl {
    models::EntityDecl {
        name: Some(name(ty)),
        descendants: descendants.into_iter().map(name).collect(),
        attributes: attrs.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        tags,
        enum_choices: vec![],
    }
}

/// Create a `models::Schema` with entity declarations only.
pub fn schema(entity_decls: impl IntoIterator<Item = models::EntityDecl>) -> models::Schema {
    models::Schema {
        entity_decls: entity_decls.into_iter().collect(),
        action_decls: vec![],
    }
}

/// Create a `models::Schema` with both entity and action declarations.
pub fn schema_full(
    entity_decls: impl IntoIterator<Item = models::EntityDecl>,
    action_decls: impl IntoIterator<Item = models::ActionDecl>,
) -> models::Schema {
    models::Schema {
        entity_decls: entity_decls.into_iter().collect(),
        action_decls: action_decls.into_iter().collect(),
    }
}

/// Create a `models::ActionDecl`.
pub fn action_decl(
    action_entity: (&str, &str),
    principal_types: impl IntoIterator<Item = &'static str>,
    resource_types: impl IntoIterator<Item = &'static str>,
    context: impl IntoIterator<Item = (&'static str, models::AttributeType)>,
) -> models::ActionDecl {
    models::ActionDecl {
        name: Some(entity_uid(name(action_entity.0), action_entity.1)),
        descendants: vec![],
        principal_types: principal_types.into_iter().map(name).collect(),
        resource_types: resource_types.into_iter().map(name).collect(),
        context: context
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    }
}
