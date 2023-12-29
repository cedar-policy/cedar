use cedar_policy_validator::{
    ApplySpec, EntityType, NamespaceDefinition, SchemaFragment, SchemaType, SchemaTypeVariant,
    TypeOfAttribute,
};
use pretty::RcDoc;

use super::doc::Doc;

impl Doc for SchemaFragment {
    fn to_doc(&self, context: &mut crate::Context<'_>) -> Option<RcDoc<'_>> {
        Some(RcDoc::intersperse(
            self.0.iter().map(|(ns, nsd)| {
                if ns.is_empty() {
                    nsd.to_doc(context)
                } else {
                    Some(
                        RcDoc::text("namespace")
                            .append(RcDoc::space())
                            .append(RcDoc::text(ns.to_string()))
                            .append(RcDoc::text(" {"))
                            .append(
                                RcDoc::hardline()
                                    .append(nsd.to_doc(context))
                                    .nest(context.config.indent_width)
                                    .append(RcDoc::hardline()),
                            )
                            .append(RcDoc::text("}")),
                    )
                }
            }),
            RcDoc::hardline(),
        ))
    }
}

impl Doc for NamespaceDefinition {
    fn to_doc(&self, context: &mut crate::Context<'_>) -> Option<pretty::RcDoc<'_>> {
        let action_types = self.merge_actions_by_type();
        Some(
            RcDoc::text("// Entity type declarations")
                .append(RcDoc::hardline())
                .append(RcDoc::intersperse(
                    self.entity_types.iter().map(|(n, et)| {
                        RcDoc::text("entity")
                            .append(RcDoc::space())
                            .append(RcDoc::text(n.to_string()))
                            .append(et.to_doc(context))
                    }),
                    RcDoc::hardline(),
                ))
                .append(RcDoc::hardline())
                .append(RcDoc::hardline())
                .append(
                    RcDoc::text("// Common type declarations")
                        .append(RcDoc::hardline())
                        .append(RcDoc::intersperse(
                            self.common_types.iter().map(|(ty_name, ty)| {
                                RcDoc::text("type")
                                    .append(RcDoc::space())
                                    .append(RcDoc::text(ty_name.to_string()))
                                    .append(RcDoc::space())
                                    .append(RcDoc::text("="))
                                    .append(RcDoc::space())
                                    .append(ty.to_doc(context))
                                    .append(";")
                            }),
                            RcDoc::hardline(),
                        )),
                )
                .append(RcDoc::hardline())
                .append(RcDoc::hardline())
                .append(
                    RcDoc::text("// Action declarations")
                        .append(RcDoc::hardline())
                        .append(RcDoc::intersperse(
                            action_types.into_iter().map(|(act_ty, ids)| {
                                RcDoc::text("action")
                                    .append(RcDoc::space())
                                    .append(RcDoc::intersperse(
                                        ids.iter().map(|id| RcDoc::text(id.to_string())),
                                        RcDoc::text(", "),
                                    ))
                                    .append(RcDoc::line())
                                    .append(act_ty.applies_to.as_ref().map(|v| v.to_doc(context)))
                                    .nest(context.config.indent_width)
                                    .group()
                                    .append(RcDoc::text(";"))
                            }),
                            RcDoc::hardline(),
                        )),
                ),
        )
    }
}

impl Doc for ApplySpec {
    fn to_doc(&self, context: &mut crate::Context<'_>) -> Option<RcDoc<'_>> {
        Some(
            RcDoc::text("appliesTo")
                .append(RcDoc::text(" {"))
                .append(
                    RcDoc::line()
                        .append(RcDoc::intersperse(
                            vec![
                                if let Some(principals) = &self.principal_types {
                                    Some(
                                        RcDoc::text("principal: [")
                                            .append(RcDoc::intersperse(
                                                principals
                                                    .iter()
                                                    .map(|t| RcDoc::text(t.to_string())),
                                                RcDoc::text(", "),
                                            ))
                                            .append(RcDoc::text("]")),
                                    )
                                } else {
                                    None
                                },
                                if let Some(resources) = &self.resource_types {
                                    Some(
                                        RcDoc::text("resource: [")
                                            .append(RcDoc::intersperse(
                                                resources
                                                    .iter()
                                                    .map(|t| RcDoc::text(t.to_string())),
                                                RcDoc::text(", "),
                                            ))
                                            .append(RcDoc::text("]")),
                                    )
                                } else {
                                    None
                                },
                                if let SchemaType::Type(SchemaTypeVariant::Record {
                                    attributes,
                                    additional_attributes: _,
                                }) = &self.context.0
                                {
                                    if attributes.is_empty() {
                                        None
                                    } else {
                                        Some(
                                            RcDoc::text("context: ")
                                                .append(self.context.0.to_doc(context)),
                                        )
                                    }
                                } else {
                                    None
                                },
                            ]
                            .into_iter()
                            .filter(|doc| doc.is_some()),
                            RcDoc::text(",").append(RcDoc::line()),
                        ))
                        .nest(context.config.indent_width)
                        .append(RcDoc::line())
                        .append(RcDoc::text("}")),
                )
                .group(),
        )
    }
}
impl Doc for EntityType {
    fn to_doc(&self, context: &mut crate::Context<'_>) -> Option<RcDoc<'_>> {
        if let SchemaType::Type(SchemaTypeVariant::Record {
            attributes,
            additional_attributes: _,
        }) = &self.shape.0
        {
            Some(
                if self.member_of_types.is_empty() {
                    RcDoc::nil()
                } else {
                    RcDoc::space()
                        .append(RcDoc::text("in "))
                        .append(RcDoc::text("["))
                        .append(
                            RcDoc::intersperse(
                                self.member_of_types
                                    .iter()
                                    .map(|ancestor| RcDoc::text(ancestor.to_string())),
                                RcDoc::text(", "),
                            )
                            .append(RcDoc::text("]")),
                        )
                }
                .append(if attributes.is_empty() {
                    RcDoc::nil()
                } else {
                    RcDoc::space().append(self.shape.0.to_doc(context)?)
                })
                .append(RcDoc::text(";")),
            )
        } else {
            None
        }
    }
}

impl Doc for SchemaType {
    fn to_doc(&self, context: &mut crate::Context<'_>) -> Option<pretty::RcDoc<'_>> {
        Some(match self {
            Self::Type(ty) => ty.to_doc(context)?,
            Self::TypeDef { type_name } => RcDoc::text(type_name.to_string()),
        })
    }
}

impl Doc for TypeOfAttribute {
    fn to_doc(&self, context: &mut crate::Context<'_>) -> Option<RcDoc<'_>> {
        self.ty.to_doc(context)
    }
}

impl Doc for SchemaTypeVariant {
    fn to_doc(&self, context: &mut crate::Context<'_>) -> Option<RcDoc<'_>> {
        Some(match self {
            Self::Boolean => RcDoc::text("Bool"),
            Self::Entity { name } => RcDoc::text(name.to_string()),
            Self::Extension { name } => RcDoc::text(format!("__cedar::{name}")),
            Self::Long => RcDoc::text("Long"),
            Self::Record {
                attributes,
                additional_attributes: _,
            } => {
                if attributes.is_empty() {
                    RcDoc::text("{}")
                } else {
                    RcDoc::text("{")
                        .append(RcDoc::line())
                        .append(RcDoc::intersperse(
                            attributes.iter().map(|(attr, ty)| {
                                Some(
                                    RcDoc::text(attr.to_string())
                                        .append(RcDoc::text(": "))
                                        .append(ty.to_doc(context)?),
                                )
                            }),
                            RcDoc::text(",").append(RcDoc::line()),
                        ))
                        .nest(context.config.indent_width)
                        .append(RcDoc::line())
                        .append(RcDoc::text("}"))
                        .group()
                }
            }
            Self::Set { element } => RcDoc::text("Set")
                .append(RcDoc::text("<"))
                .append(element.to_doc(context)?)
                .append(RcDoc::text(">")),
            Self::String => RcDoc::text("String"),
        })
    }
}
