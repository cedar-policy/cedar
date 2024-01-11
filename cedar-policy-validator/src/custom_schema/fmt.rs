use std::{collections::HashSet, fmt::Display};

use nonempty::NonEmpty;
use smol_str::SmolStr;
use thiserror::Error;

use crate::{
    ActionType, EntityType, NamespaceDefinition, SchemaError, SchemaFragment, SchemaType,
    SchemaTypeVariant, ValidatorSchema,
};

impl Display for SchemaFragment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (ns, def) in &self.0 {
            if ns.is_empty() {
                write!(f, "{def}")?
            } else {
                write!(f, "namespace {ns} {{{def}}}")?
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
            writeln!(f, "entity {n} {ty};")?
        }
        for (n, a) in &self.actions {
            writeln!(f, "action \"{}\" {a};", n.escape_debug())?
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
                    write!(f, "{{ ")?;
                    for (n, ty) in attributes {
                        writeln!(
                            f,
                            "\"{}\"{}: {},",
                            n.escape_debug(),
                            if ty.required { "" } else { "?" },
                            ty.ty
                        )?;
                    }
                    write!(f, " }}")?;
                    Ok(())
                }
                SchemaTypeVariant::Set { element } => write!(f, "Set < {element} >"),
                SchemaTypeVariant::String => write!(f, "__cedar::String"),
            },
            SchemaType::TypeDef { type_name } => write!(f, "{type_name}"),
        }
    }
}

fn fmt_vec<T: Display>(f: &mut std::fmt::Formatter<'_>, ets: &[T]) -> std::fmt::Result {
    match ets.split_last() {
        Some((tail, head)) => {
            if head.is_empty() {
                write!(f, "{tail}")
            } else {
                write!(f, "[")?;
                for et in head {
                    write!(f, "{et}, ")?
                }
                write!(f, "{tail}")?;
                write!(f, "]")?;
                Ok(())
            }
        }
        // PANIC SAFETY: input should be non-empty a slice
        #[allow(clippy::unreachable)]
        None => unreachable!("input list must not be empty"),
    }
}
impl Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ps = &self.member_of_types;
        if !ps.is_empty() {
            write!(f, "in ")?;
            fmt_vec(f, ps)?;
        }
        let ty = &self.shape.0;
        write!(f, " = {ty}")?;
        Ok(())
    }
}

impl Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.member_of {
            Some(ps) if !ps.is_empty() => {
                write!(f, "in ")?;
                fmt_vec(f, ps)?;
            }
            _ => {}
        }
        match &self.applies_to {
            Some(spec) => {
                match (&spec.principal_types, &spec.resource_types) {
                    (Some(ps), _) if ps.is_empty() => {
                        // "absurd" action
                        write!(f, "")?;
                    }
                    (_, Some(rs)) if rs.is_empty() => {
                        // "absurd" action
                        write!(f, "")?;
                    }
                    (Some(ps), Some(rs)) => {
                        write!(f, "appliesTo {{")?;
                        write!(f, "  principal: ")?;
                        fmt_vec(f, ps)?;
                        write!(f, ", \n  resource: ")?;
                        fmt_vec(f, rs)?;
                        write!(f, ", \n  context: {}", &spec.context.0)?;
                        write!(f, "\n}}")?;
                    }
                    (Some(ps), None) => {
                        write!(f, "appliesTo {{")?;
                        write!(f, "  principal: ")?;
                        fmt_vec(f, ps)?;
                        write!(f, ", \n  context: {}", &spec.context.0)?;
                        write!(f, "\n}}")?;
                    }
                    (None, Some(rs)) => {
                        write!(f, "appliesTo {{")?;
                        write!(f, "  resource: ")?;
                        fmt_vec(f, rs)?;
                        write!(f, ", \n  context: {}", &spec.context.0)?;
                        write!(f, "\n}}")?;
                    }
                    (None, None) => {
                        write!(f, "appliesTo {{")?;
                        write!(f, "  context: {}", &spec.context.0)?;
                        write!(f, "\n}}")?;
                    }
                }
            }
            // applies to unspecified principals and resources
            None => {
                write!(f, " appliesTo {{ context: {{}}}}")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ToCustomSchemaStrError {
    #[error("There exist type name collisions: {:?}", .0)]
    NameCollisions(NonEmpty<SmolStr>),
    #[error(transparent)]
    Invalid(#[from] SchemaError),
}

pub fn json_schema_to_custom_schema_str(
    json_schema: &SchemaFragment,
) -> Result<String, ToCustomSchemaStrError> {
    let mut name_collisions: Vec<SmolStr> = Vec::new();
    let _: ValidatorSchema = json_schema.clone().try_into()?;
    for (name, ns) in json_schema.0.iter().filter(|(name, _)| !name.is_empty()) {
        let entity_types: HashSet<SmolStr> = ns
            .entity_types
            .keys()
            .map(|ty_name| format!("{name}::{ty_name}").into())
            .collect();
        let common_types: HashSet<SmolStr> = ns
            .common_types
            .keys()
            .map(|ty_name| format!("{name}::{ty_name}").into())
            .collect();
        name_collisions.extend(entity_types.intersection(&common_types).cloned());
    }
    if let Some((head, tail)) = name_collisions.split_first() {
        return Err(ToCustomSchemaStrError::NameCollisions(NonEmpty {
            head: head.clone(),
            tail: tail.to_vec(),
        }));
    }
    Ok(json_schema.to_string())
}
