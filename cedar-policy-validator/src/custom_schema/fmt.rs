use std::fmt::Display;

use crate::{
    ActionType, EntityType, NamespaceDefinition, SchemaFragment, SchemaType, SchemaTypeVariant,
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
                SchemaTypeVariant::Boolean => write!(f, "Bool"),
                SchemaTypeVariant::Entity { name } => write!(f, "{name}"),
                SchemaTypeVariant::Extension { name } => write!(f, "{name}"),
                SchemaTypeVariant::Long => write!(f, "Long"),
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
                SchemaTypeVariant::String => write!(f, "String"),
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
        None => unreachable!("entity type list must not be empty"),
    }
}
impl Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ps = &self.member_of_types;
        if !ps.is_empty() {
            write!(f, "in ")?;
            fmt_vec(f, &ps)?;
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
                fmt_vec(f, &ps)?;
            }
            _ => {}
        }
        match &self.applies_to {
            Some(spec) => {
                match (&spec.principal_types, &spec.resource_types) {
                    (Some(ps), Some(rs)) if ps.is_empty() || rs.is_empty() => {
                        // "absurd" action
                        write!(f, "")?;
                    }
                    (Some(ps), Some(rs)) => {
                        write!(f, "appliesTo {{")?;
                        write!(f, "principal: ")?;
                        fmt_vec(f, &ps)?;
                        write!(f, ", \nresource: ")?;
                        fmt_vec(f, &rs)?;
                        write!(f, ", \ncontext: {}", &spec.context.0)?;
                        write!(f, "}}")?;
                    }
                    (Some(ps), None) => {
                        write!(f, "appliesTo {{")?;
                        write!(f, "principal: ")?;
                        fmt_vec(f, &ps)?;
                        write!(f, ", \ncontext: {}", &spec.context.0)?;
                        write!(f, "}}")?;
                    }
                    (None, Some(rs)) => {
                        write!(f, "appliesTo {{")?;
                        write!(f, "resource: ")?;
                        fmt_vec(f, &rs)?;
                        write!(f, ", \ncontext: {}", &spec.context.0)?;
                        write!(f, "}}")?;
                    }
                    (None, None) => {
                        write!(f, "appliesTo {{")?;
                        write!(f, "context: {}", &spec.context.0)?;
                        write!(f, "}}")?;
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
