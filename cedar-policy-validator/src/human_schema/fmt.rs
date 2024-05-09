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

use std::{collections::HashSet, fmt::Display};

use cedar_policy_core::ast::Name;
use itertools::Itertools;
use miette::Diagnostic;
use nonempty::NonEmpty;
use smol_str::{SmolStr, ToSmolStr};
use thiserror::Error;

use crate::{
    ActionType, EntityType, NamespaceDefinition, SchemaFragment, SchemaType, SchemaTypeVariant,
};

impl Display for SchemaFragment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (ns, def) in &self.0 {
            match ns {
                None => write!(f, "{def}")?,
                Some(ns) => write!(f, "namespace {ns} {{\n{def}}}")?,
            }
        }
        Ok(())
    }
}

impl Display for NamespaceDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (n, ty) in &self.common_types {
            writeln!(f, "type {n} = {ty};")?
        }
        for (n, ty) in &self.entity_types {
            writeln!(f, "entity {n}{ty};")?
        }
        for (n, a) in &self.actions {
            writeln!(f, "action \"{}\"{a};", n.escape_debug())?
        }
        Ok(())
    }
}

impl Display for SchemaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaType::Type(ty) => match ty {
                SchemaTypeVariant::Boolean => write!(f, "__cedar::Bool"),
                SchemaTypeVariant::Entity { name } => write!(f, "{name}"),
                SchemaTypeVariant::Extension { name } => write!(f, "__cedar::{name}"),
                SchemaTypeVariant::Long => write!(f, "__cedar::Long"),
                SchemaTypeVariant::Record {
                    attributes,
                    additional_attributes: _,
                } => {
                    write!(f, "{{")?;
                    for (i, (n, ty)) in attributes.iter().enumerate() {
                        write!(
                            f,
                            "\"{}\"{}: {}",
                            n.escape_debug(),
                            if ty.required { "" } else { "?" },
                            ty.ty
                        )?;
                        if i < (attributes.len() - 1) {
                            write!(f, ", ")?;
                        }
                    }
                    write!(f, "}}")?;
                    Ok(())
                }
                SchemaTypeVariant::Set { element } => write!(f, "Set < {element} >"),
                SchemaTypeVariant::String => write!(f, "__cedar::String"),
            },
            SchemaType::TypeDef { type_name } => write!(f, "{type_name}"),
        }
    }
}

/// Create a non-empty with borrowed contents from a slice
fn non_empty_slice<T>(v: &[T]) -> Option<NonEmpty<&T>> {
    let vs: Vec<&T> = v.iter().collect();
    NonEmpty::from_vec(vs)
}

fn fmt_vec<T: Display>(f: &mut std::fmt::Formatter<'_>, ets: NonEmpty<T>) -> std::fmt::Result {
    let contents = ets.iter().map(T::to_string).join(", ");
    write!(f, "[{contents}]")
}

impl Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(non_empty) = non_empty_slice(&self.member_of_types) {
            write!(f, " in ")?;
            fmt_vec(f, non_empty)?;
        }

        let ty = &self.shape.0;
        // Don't print `= { }`
        if !ty.is_empty_record() {
            write!(f, " = {ty}")?;
        }

        Ok(())
    }
}

impl Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(parents) = self
            .member_of
            .as_ref()
            .and_then(|refs| non_empty_slice(refs.as_slice()))
        {
            write!(f, " in ")?;
            fmt_vec(f, parents)?;
        }
        if let Some(spec) = &self.applies_to {
            match (
                spec.principal_types
                    .as_ref()
                    .map(|refs| non_empty_slice(refs.as_slice())),
                spec.resource_types
                    .as_ref()
                    .map(|refs| non_empty_slice(refs.as_slice())),
            ) {
                // One of the lists is empty
                // This can only be represented by the empty action
                // This implies an action group
                (Some(None), _) | (_, Some(None)) => {
                    write!(f, "")?;
                }
                // Both list are present and non empty
                (Some(Some(ps)), Some(Some(rs))) => {
                    write!(f, " appliesTo {{")?;
                    write!(f, "\n  principal: ")?;
                    fmt_vec(f, ps)?;
                    write!(f, ",\n  resource: ")?;
                    fmt_vec(f, rs)?;
                    write!(f, ",\n  context: {}", &spec.context.0)?;
                    write!(f, "\n}}")?;
                }
                // Only principals are present, resource is unspecified
                (Some(Some(ps)), None) => {
                    write!(f, " appliesTo {{")?;
                    write!(f, "\n  principal: ")?;
                    fmt_vec(f, ps)?;
                    write!(f, ",\n  context: {}", &spec.context.0)?;
                    write!(f, "\n}}")?;
                }
                // Only resources is present, principal is unspecified
                (None, Some(Some(rs))) => {
                    write!(f, " appliesTo {{")?;
                    write!(f, "\n  resource: ")?;
                    fmt_vec(f, rs)?;
                    write!(f, ",\n  context: {}", &spec.context.0)?;
                    write!(f, "\n}}")?;
                }
                // Neither are present, both principal and resource are unspecified
                (None, None) => {
                    write!(f, " appliesTo {{")?;
                    write!(f, "\n  context: {}", &spec.context.0)?;
                    write!(f, "\n}}")?;
                }
            }
        } else {
            // No `appliesTo` key: both principal and resource must be unspecified entities
            write!(f, " appliesTo {{")?;
            // context is an empty record
            write!(f, "\n  context: {{}}")?;
            write!(f, "\n}}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Diagnostic, Error)]
pub enum ToHumanSchemaStrError {
    #[error("There exist type name collisions: {:?}", .0)]
    NameCollisions(NonEmpty<SmolStr>),
}

pub fn json_schema_to_custom_schema_str(
    json_schema: &SchemaFragment,
) -> Result<String, ToHumanSchemaStrError> {
    let mut name_collisions: Vec<SmolStr> = Vec::new();
    for (name, ns) in json_schema.0.iter().filter(|(name, _)| !name.is_none()) {
        let entity_types: HashSet<SmolStr> = ns
            .entity_types
            .keys()
            .map(|ty_name| {
                Name::unqualified_name(ty_name.clone())
                    .prefix_namespace_if_unqualified(name.as_ref())
                    .to_smolstr()
            })
            .collect();
        let common_types: HashSet<SmolStr> = ns
            .common_types
            .keys()
            .map(|ty_name| {
                Name::unqualified_name(ty_name.clone())
                    .prefix_namespace_if_unqualified(name.as_ref())
                    .to_smolstr()
            })
            .collect();
        name_collisions.extend(entity_types.intersection(&common_types).cloned());
    }
    if let Some((head, tail)) = name_collisions.split_first() {
        return Err(ToHumanSchemaStrError::NameCollisions(NonEmpty {
            head: head.clone(),
            tail: tail.to_vec(),
        }));
    }
    Ok(json_schema.to_string())
}
