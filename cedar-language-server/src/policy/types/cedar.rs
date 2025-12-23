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

use std::{
    borrow::Cow,
    collections::BTreeMap,
    fmt::{Display, Write},
    hash::Hash,
    sync::Arc,
};

use cedar_policy_core::{
    ast::EntityUID,
    validator::{
        types::{EntityKind, Primitive, Type},
        ValidatorSchema,
    },
};
use cedar_policy_core::{
    ast::{Literal, Name},
    extensions::{datetime, decimal, ipaddr},
};

mod attribute;
mod context;
mod entity;
mod method;

pub(crate) use attribute::*;
pub(crate) use context::*;
pub(crate) use entity::*;
pub(crate) use method::*;

use crate::{
    documentation::{
        BoolDocumentation, ContainsAllDocumentation, ContainsAnyDocumentation,
        ContainsDocumentation, ExtensionName, IsEmptyDocumentation, LongDocumentation,
        SetDocumentation, StringDocumentation, ToDocumentationString,
    },
    markdown::MarkdownBuilder,
};

/// Represents the type system for Cedar policy expressions.
///
/// This enum captures the various types that can occur in Cedar policies,
/// including primitive types, collections, entities, and special types.
/// It's used for type checking, type inference, and providing context-aware
/// completions in the language server.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum CedarTypeKind {
    /// Boolean type, representing `true` or `false` values.
    Bool,
    /// Long integer type for numeric values.
    Long,
    /// String type for text values.
    String,
    /// Set type, containing elements of a specific type.
    ///
    /// Example: `[1, 2, 3]` is a set of `Long` values.
    Set(Box<CedarTypeKind>),
    /// Empty set type, with indeterminate element type.
    EmptySet,
    /// Record type, containing named attributes with potentially different types.
    ///
    /// Example: `{ "name": "Alice", "age": 30 }`
    Record(Record),
    /// Entity type, representing principal or resource types in policies.
    ///
    /// Example: `User`, `Photo`
    EntityType(EntityTypeKind),
    /// Extension function type, representing custom functions.
    Extension(Name),
    /// Context object type, containing request context data.
    Context(ContextKind),
    /// Action type, representing policy actions.
    ///
    /// Example: `Action::"view"`, `Action::"edit"`
    Action,
    /// Error type, representing an expression with a type error.
    Error,
}

impl CedarTypeKind {
    /// Determines the type of an attribute on this Cedar type.
    ///
    /// This method resolves the type of a specific attribute when accessed on
    /// this type, using schema information when available to provide accurate
    /// type information for entities, records, and context objects.
    ///
    /// ## Returns
    ///
    /// The resolved type of the attribute if it exists on this type, or `None` if:
    /// - The attribute doesn't exist on this type
    /// - This type doesn't support attributes (like primitives)
    /// - Schema information is needed but not provided
    #[must_use]
    pub(crate) fn attribute_type(
        &self,
        attr: &str,
        schema: Option<&ValidatorSchema>,
    ) -> Option<Self> {
        match self {
            Self::Record(fields) => fields.attr(attr).and_then(attribute::Attribute::cedar_type),
            Self::EntityType(entity_type_kind) => {
                schema.and_then(|schema| entity_type_kind.attribute_type(attr, schema))
            }
            Self::Context(context_kind) => {
                schema.and_then(|schema| context_kind.attribute_type(schema, attr))
            }
            _ => None,
        }
    }

    /// Retrieves all available attributes for this Cedar type.
    ///
    /// This method gathers information about all attributes that can be accessed
    /// on this type, using schema information when available to provide complete
    /// attribute information for entities, records, and context objects.
    ///
    /// ## Returns
    ///
    /// A vector of `Attribute` objects representing all attributes available on this type.
    /// Returns an empty vector for types that don't have attributes (like primitives).
    #[must_use]
    pub(crate) fn attributes(&self, schema: Option<&ValidatorSchema>) -> Vec<Attribute> {
        match self {
            Self::EntityType(et) => et.attributes(schema),
            Self::Record(fields) => fields.attrs.values().cloned().collect(),
            Self::Context(kind) => kind.attributes(schema),
            _ => Vec::new(),
        }
    }

    /// Retrieves all available methods for this Cedar type.
    ///
    /// This method determines what methods can be called on values of this type,
    /// providing information about built-in functions and extension methods
    /// that can operate on this type.
    ///
    /// ## Returns
    ///
    /// A vector of `MethodInfo` objects representing all methods available on this type.
    /// Returns an empty vector for types that don't have defined methods.
    #[must_use]
    pub(crate) fn methods(&self) -> Vec<MethodInfo> {
        match self {
            Self::EmptySet => get_set_methods("?"),
            Self::Set(element_type) => get_set_methods(element_type.to_string()),
            Self::Extension(name) if name.to_string() == "ip" => {
                MethodInfo::from_extension(&ipaddr::extension())
            }
            Self::Extension(name) if name.to_string() == "decimal" => {
                MethodInfo::from_extension(&decimal::extension())
            }
            Self::Extension(name) if name.to_string() == "datetime" => {
                MethodInfo::from_extension(&datetime::extension())
            }
            _ => Vec::new(),
        }
    }
}

impl Display for CedarTypeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool => write!(f, "bool"),
            Self::Long => write!(f, "long"),
            Self::String => write!(f, "string"),
            Self::Set(element_type) => write!(f, "Set<{element_type}>"),
            Self::Record(fields) => {
                let field_strs: Vec<String> = fields
                    .attrs
                    .iter()
                    .map(|(name, typ)| {
                        format!(
                            "{}: {}",
                            name,
                            typ.cedar_type()
                                .map_or_else(|| typ.name().to_string(), |ct| ct.to_string())
                        )
                    })
                    .collect();
                write!(f, "{{ {} }}", field_strs.join(", "))
            }
            Self::Extension(name) => write!(f, "{name}"),
            Self::EmptySet => write!(f, "Set<?>"),
            Self::Context(kind) => {
                write!(f, "Context<{kind}>")
            }
            Self::EntityType(entity_type_kind) => write!(f, "{entity_type_kind}"),
            Self::Error => write!(f, "Error"),
            Self::Action => write!(f, "actionKind"),
        }
    }
}

#[expect(
    clippy::fallible_impl_from,
    reason = "see comment on `expect(clippy::unwrap_used)` below"
)]
impl From<Type> for CedarTypeKind {
    fn from(ty: Type) -> Self {
        match ty {
            Type::Never => Self::Error,
            Type::True | Type::False => Self::Bool,
            Type::Primitive { primitive_type } => match primitive_type {
                Primitive::Bool => Self::Bool,
                Primitive::Long => Self::Long,
                Primitive::String => Self::String,
            },
            Type::Set { element_type } => element_type.map_or(Self::EmptySet, |ty| {
                Self::Set(Box::new(Self::from(ty.as_ref().clone())))
            }),
            Type::Record { attrs, .. } => {
                let m = attrs
                    .into_iter()
                    .map(|kv_pair| (kv_pair.0.clone(), Attribute::from(kv_pair)))
                    .collect::<BTreeMap<_, _>>();
                let record = Record { attrs: m.into() };
                Self::Record(record)
            }
            Type::Entity(entity_record_kind) => match entity_record_kind {
                EntityKind::AnyEntity => Self::Error,
                EntityKind::Entity(entity_lub) => {
                    // FIXME: This feels like an easy assumption to break. We should handle it gracefully
                    #[expect(
                        clippy::unwrap_used,
                        reason = "LSP is only used with strict validation, so all entities are singleton"
                    )]
                    let e = entity_lub.into_single_entity().unwrap();
                    Self::EntityType(EntityTypeKind::Concrete(Arc::new(e)))
                }
            },
            Type::ExtensionType { name } => Self::Extension(name),
        }
    }
}

impl From<&EntityUID> for CedarTypeKind {
    fn from(euid: &EntityUID) -> Self {
        CedarTypeKind::EntityType(EntityTypeKind::Concrete(Arc::new(
            euid.entity_type().clone(),
        )))
    }
}

impl ToDocumentationString for CedarTypeKind {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> Cow<'static, str> {
        match self {
            Self::Long => LongDocumentation.to_documentation_string(schema),
            Self::String => StringDocumentation.to_documentation_string(schema),
            Self::Bool => BoolDocumentation.to_documentation_string(schema),
            Self::Record(fields) => {
                let mut builder = MarkdownBuilder::new();
                builder.header("Record Type");

                let mut code = String::from("{\n");
                let mut sorted_fields: Vec<_> = fields.attrs.iter().collect();
                sorted_fields.sort_by(|(a, _), (b, _)| a.cmp(b));

                for (name, typ) in sorted_fields {
                    let _ = write!(code, "    {name}: ");
                    if let Some(ct) = typ.cedar_type() {
                        let _ = writeln!(code, "{ct}");
                    } else {
                        let _ = writeln!(code, "{}", typ.name());
                    }
                }
                code.push('}');

                builder
                    .code_block("cedar", &code)
                    .paragraph(&format!("*Contains {} fields*", fields.attrs.len()))
                    .build()
                    .into()
            }
            Self::Set(element_type) => {
                SetDocumentation::new(element_type.as_ref().clone()).to_documentation_string(schema)
            }
            Self::EmptySet => SetDocumentation::default().to_documentation_string(schema),
            Self::Extension(name) => {
                ExtensionName(&name.to_string()).to_documentation_string(schema)
            }
            Self::EntityType(kind) => kind.to_documentation_string(schema),
            _ => self.to_string().into(),
        }
    }
}

impl From<&Literal> for CedarTypeKind {
    fn from(literal: &Literal) -> Self {
        match literal {
            Literal::Bool(_) => Self::Bool,
            Literal::Long(_) => Self::Long,
            Literal::String(_) => Self::String,
            Literal::EntityUID(entity_uid) => entity_uid.as_ref().into(),
        }
    }
}

fn get_set_methods<T: Into<String>>(element_type_str: T) -> Vec<MethodInfo> {
    let element_type_str: String = element_type_str.into();
    vec![
        MethodInfo::new(
            "containsAll",
            Some(ContainsAllDocumentation.to_documentation_string(None)),
            vec![("other".to_string(), format!("Set<{}>", &element_type_str))],
            "bool",
        ),
        MethodInfo::new(
            "containsAny",
            Some(ContainsAnyDocumentation.to_documentation_string(None)),
            vec![("other".to_string(), format!("Set<{}>", &element_type_str))],
            "bool",
        ),
        MethodInfo::new(
            "contains",
            Some(ContainsDocumentation.to_documentation_string(None)),
            vec![("element".to_string(), element_type_str)],
            "bool",
        ),
        MethodInfo::new(
            "isEmpty",
            Some(IsEmptyDocumentation.to_documentation_string(None)),
            vec![],
            "bool",
        ),
    ]
}
