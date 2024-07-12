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

//! `Display` implementations for formatting a schema in human syntax

use std::{collections::HashSet, fmt::Display};

use itertools::Itertools;
use miette::Diagnostic;
use nonempty::NonEmpty;
use smol_str::{SmolStr, ToSmolStr};
use thiserror::Error;

use crate::{
    ActionType, EntityType, NamespaceDefinition, RawName, SchemaFragment, SchemaType,
    SchemaTypeVariant,
};

impl<N: Display> Display for SchemaFragment<N> {
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

impl<N: Display> Display for NamespaceDefinition<N> {
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

impl<N: Display> Display for SchemaType<N> {
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
            SchemaType::CommonTypeRef { type_name } => write!(f, "{type_name}"),
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

impl<N: Display> Display for EntityType<N> {
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

impl<N: Display> Display for ActionType<N> {
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
                non_empty_slice(spec.principal_types.as_slice()),
                non_empty_slice(spec.resource_types.as_slice()),
            ) {
                // One of the lists is empty
                // This can only be represented by the empty action
                // This implies an action group
                (None, _) | (_, None) => {
                    write!(f, "")?;
                }
                // Both list are non empty
                (Some(ps), Some(rs)) => {
                    write!(f, " appliesTo {{")?;
                    write!(f, "\n  principal: ")?;
                    fmt_vec(f, ps)?;
                    write!(f, ",\n  resource: ")?;
                    fmt_vec(f, rs)?;
                    write!(f, ",\n  context: {}", &spec.context.0)?;
                    write!(f, "\n}}")?;
                }
            }
        }
        // No `appliesTo` key: action does not apply to anything
        Ok(())
    }
}

/// Error converting a schema to human syntax
#[derive(Debug, Diagnostic, Error)]
pub enum ToHumanSchemaSyntaxError {
    /// Collisions between names prevented the conversion to human syntax
    #[diagnostic(transparent)]
    #[error(transparent)]
    NameCollisions(#[from] NameCollisionsError),
}

/// Duplicate names were found in the schema
#[derive(Debug, Error, Diagnostic)]
#[error("There are name collisions: [{}]", .names.iter().join(", "))]
pub struct NameCollisionsError {
    /// Names that had collisions
    names: NonEmpty<SmolStr>,
}

impl NameCollisionsError {
    /// Get the names that had collisions
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(smol_str::SmolStr::as_str)
    }
}

/// Convert a [`SchemaFragment`] to a string containing human schema syntax
pub fn json_schema_to_custom_schema_str<N: Display>(
    json_schema: &SchemaFragment<N>,
) -> Result<String, ToHumanSchemaSyntaxError> {
    let mut name_collisions: Vec<SmolStr> = Vec::new();
    for (name, ns) in json_schema.0.iter().filter(|(name, _)| !name.is_none()) {
        let entity_types: HashSet<SmolStr> = ns
            .entity_types
            .keys()
            .map(|ty_name| {
                RawName::new(ty_name.clone())
                    .qualify_with(name.as_ref())
                    .to_smolstr()
            })
            .collect();
        let common_types: HashSet<SmolStr> = ns
            .common_types
            .keys()
            .map(|ty_name| {
                RawName::new(ty_name.clone())
                    .qualify_with(name.as_ref())
                    .to_smolstr()
            })
            .collect();
        name_collisions.extend(entity_types.intersection(&common_types).cloned());
    }
    if let Some(non_empty_collisions) = NonEmpty::from_vec(name_collisions) {
        return Err(NameCollisionsError {
            names: non_empty_collisions,
        }
        .into());
    }
    Ok(json_schema.to_string())
}
