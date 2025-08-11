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

#![allow(clippy::use_self)]

use super::models;
use cedar_policy_core::{ast, FromNormalizedStr};
use std::collections::HashMap;

use cedar_policy_core::{
    est,
    validator::{json_schema, RawName},
};
use smol_str::ToSmolStr;

impl From<&models::TemplateType> for json_schema::Type<RawName> {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::TemplateType) -> Self {
        let ty_variant = match &v.data.as_ref().expect("data field should exist") {
            models::template_type::Data::Other(ty) => json_schema::TypeVariant::EntityOrCommon {
                type_name: RawName::from(ty),
            },
            models::template_type::Data::SetElem(ty) => json_schema::TypeVariant::Set {
                element: Box::new(json_schema::Type::from(ty.as_ref())),
            },
            models::template_type::Data::Record(r) => {
                json_schema::TypeVariant::Record(template_model_to_attributes(&r.attrs))
            }
        };
        json_schema::Type::Type {
            ty: ty_variant,
            loc: None,
        }
    }
}

// PANIC SAFETY: experimental feature
#[allow(clippy::fallible_impl_from)]
impl From<&json_schema::Type<RawName>> for models::TemplateType {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::unreachable)]
    fn from(v: &json_schema::Type<RawName>) -> Self {
        match v {
            json_schema::Type::Type { ty, loc: _ } => match &ty {
                json_schema::TypeVariant::EntityOrCommon { type_name } => Self {
                    data: Some(models::template_type::Data::Other(models::Name::from(
                        type_name,
                    ))),
                },
                json_schema::TypeVariant::Set { element } => Self {
                    data: Some(models::template_type::Data::SetElem(Box::new(
                        models::TemplateType::from(element.as_ref()),
                    ))),
                },
                json_schema::TypeVariant::Record(r) => {
                    let record: models::template_type::Record = models::template_type::Record {
                        attrs: template_attributes_to_model(r),
                    };
                    Self {
                        data: Some(models::template_type::Data::Record(record)),
                    }
                }
                _ => unreachable!(),
            },
            json_schema::Type::CommonTypeRef { .. } => unreachable!(),
        }
    }
}

fn template_model_to_attributes(
    attr: &HashMap<String, models::AttributeTemplateType>,
) -> json_schema::RecordType<RawName> {
    json_schema::RecordType {
        attributes: attr
            .iter()
            .map(|(key, value)| (key.to_smolstr(), json_schema::TypeOfAttribute::from(value)))
            .collect(),
        additional_attributes: false,
    }
}

fn template_attributes_to_model(
    v: &json_schema::RecordType<RawName>,
) -> HashMap<String, models::AttributeTemplateType> {
    v.attributes
        .iter()
        .map(|(key, value)| (key.to_string(), models::AttributeTemplateType::from(value)))
        .collect()
}

// PANIC SAFETY: experimental feature
#[allow(clippy::fallible_impl_from)]
impl From<&models::AttributeTemplateType> for json_schema::TypeOfAttribute<RawName> {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::unwrap_used)]
    fn from(v: &models::AttributeTemplateType) -> Self {
        let ty = json_schema::Type::<RawName>::from(v.attr_type.as_ref().unwrap());
        let annotations = est::Annotations::default();
        let required = v.is_required;

        Self {
            ty,
            annotations,
            required,
            #[cfg(feature = "extended-schema")]
            loc: None,
        }
    }
}

impl From<&json_schema::TypeOfAttribute<RawName>> for models::AttributeTemplateType {
    fn from(v: &json_schema::TypeOfAttribute<RawName>) -> Self {
        Self {
            attr_type: Some(models::TemplateType::from(&v.ty)),
            is_required: v.required,
        }
    }
}

impl From<&models::Policy> for ast::LiteralPolicy {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::Policy) -> Self {
        let mut values: ast::SlotEnv = HashMap::new();
        let mut generalized_values: ast::GeneralizedSlotEnv = HashMap::new();

        if v.principal_euid.is_some() {
            values.insert(
                ast::SlotId::principal(),
                ast::EntityUID::from(
                    v.principal_euid
                        .as_ref()
                        .expect("principal_euid field should exist"),
                ),
            );
        }
        if v.resource_euid.is_some() {
            values.insert(
                ast::SlotId::resource(),
                ast::EntityUID::from(
                    v.resource_euid
                        .as_ref()
                        .expect("resource_euid field should exist"),
                ),
            );
        }

        for (key, value) in &v.generalized_values {
            generalized_values.insert(
                key.parse().expect("invalid slot name"),
                ast::RestrictedExpr::new(ast::Expr::from(value)).expect("invalid value"),
            );
        }

        let template_id = ast::PolicyID::from_string(v.template_id.clone());

        if v.is_template_link {
            Self::template_linked_policy(
                template_id,
                ast::PolicyID::from_string(v.link_id.as_ref().expect("link_id field should exist")),
                values,
                generalized_values,
            )
        } else {
            Self::static_policy(template_id)
        }
    }
}

impl TryFrom<&models::Policy> for ast::Policy {
    type Error = ast::ReificationError;
    fn try_from(policy: &models::Policy) -> Result<Self, Self::Error> {
        // TODO: do we need to provide a nonempty `templates` argument to `.reify()`
        ast::LiteralPolicy::from(policy).reify(&HashMap::new())
    }
}

impl From<&ast::LiteralPolicy> for models::Policy {
    fn from(v: &ast::LiteralPolicy) -> Self {
        let generalized_values = v
            .generalized_values()
            .iter()
            .map(|(key, value)| {
                let expr = ast::Expr::from(value.clone());
                let models_expr = models::Expr::from(&expr);
                (key.to_string(), models_expr)
            })
            .collect();

        Self {
            template_id: v.template_id().as_ref().to_string(),
            link_id: if v.is_static() {
                None
            } else {
                Some(v.id().as_ref().to_string())
            },
            is_template_link: !v.is_static(),
            principal_euid: v
                .value(&ast::SlotId::principal())
                .map(models::EntityUid::from),
            resource_euid: v
                .value(&ast::SlotId::resource())
                .map(models::EntityUid::from),
            generalized_values,
        }
    }
}

impl From<&ast::Policy> for models::Policy {
    fn from(v: &ast::Policy) -> Self {
        let generalized_values = v
            .generalized_env()
            .iter()
            .map(|(key, value)| {
                let expr = ast::Expr::from(value.clone());
                let models_expr = models::Expr::from(&expr);
                (key.to_string(), models_expr)
            })
            .collect();

        Self {
            template_id: v.template().id().as_ref().to_string(),
            link_id: if v.is_static() {
                None
            } else {
                Some(v.id().as_ref().to_string())
            },
            is_template_link: !v.is_static(),
            principal_euid: v
                .env()
                .get(&ast::SlotId::principal())
                .map(models::EntityUid::from),
            resource_euid: v
                .env()
                .get(&ast::SlotId::resource())
                .map(models::EntityUid::from),
            generalized_values,
        }
    }
}

impl From<&models::TemplateBody> for ast::Template {
    fn from(v: &models::TemplateBody) -> Self {
        ast::Template::from(ast::TemplateBody::from(v))
    }
}

impl From<&models::TemplateBody> for ast::TemplateBody {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn from(v: &models::TemplateBody) -> Self {
        let generalized_slots_declaration: ast::GeneralizedSlotsDeclaration = v
            .generalized_slots_declaration
            .iter()
            .map(|(key, value)| {
                (
                    key.parse().unwrap(),
                    json_schema::Type::<RawName>::from(value),
                )
            })
            .collect();

        ast::TemplateBody::new(
            ast::PolicyID::from_string(v.id.clone()),
            None,
            v.annotations
                .iter()
                .map(|(key, value)| {
                    (
                        ast::AnyId::from_normalized_str(key).unwrap(),
                        ast::Annotation {
                            val: value.into(),
                            loc: None,
                        },
                    )
                })
                .collect(),
            generalized_slots_declaration,
            ast::Effect::from(&models::Effect::try_from(v.effect).expect("decode should succeed")),
            ast::PrincipalConstraint::from(
                v.principal_constraint
                    .as_ref()
                    .expect("principal_constraint field should exist"),
            ),
            ast::ActionConstraint::from(
                v.action_constraint
                    .as_ref()
                    .expect("action_constraint field should exist"),
            ),
            ast::ResourceConstraint::from(
                v.resource_constraint
                    .as_ref()
                    .expect("resource_constraint field should exist"),
            ),
            ast::Expr::from(
                v.non_scope_constraints
                    .as_ref()
                    .expect("non_scope_constraints field should exist"),
            ),
        )
    }
}

impl From<&ast::TemplateBody> for models::TemplateBody {
    fn from(v: &ast::TemplateBody) -> Self {
        let annotations: HashMap<String, String> = v
            .annotations()
            .map(|(key, value)| (key.as_ref().into(), value.as_ref().into()))
            .collect();

        let generalized_slots_declaration: HashMap<String, models::TemplateType> = v
            .generalized_slots_declaration()
            .map(|(k, v)| (k.to_string(), models::TemplateType::from(v)))
            .collect();

        Self {
            id: v.id().as_ref().to_string(),
            annotations,
            effect: models::Effect::from(&v.effect()).into(),
            principal_constraint: Some(models::PrincipalOrResourceConstraint::from(
                v.principal_constraint(),
            )),
            action_constraint: Some(models::ActionConstraint::from(v.action_constraint())),
            resource_constraint: Some(models::PrincipalOrResourceConstraint::from(
                v.resource_constraint(),
            )),
            non_scope_constraints: Some(models::Expr::from(v.non_scope_constraints())),
            generalized_slots_declaration,
        }
    }
}

impl From<&ast::Template> for models::TemplateBody {
    fn from(v: &ast::Template) -> Self {
        models::TemplateBody::from(&ast::TemplateBody::from(v.clone()))
    }
}

impl From<&models::PrincipalOrResourceConstraint> for ast::PrincipalConstraint {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::PrincipalOrResourceConstraint) -> Self {
        Self::new(ast::PrincipalOrResourceConstraint::from(v))
    }
}

impl From<&ast::PrincipalConstraint> for models::PrincipalOrResourceConstraint {
    fn from(v: &ast::PrincipalConstraint) -> Self {
        models::PrincipalOrResourceConstraint::from(v.as_inner())
    }
}

impl From<&models::PrincipalOrResourceConstraint> for ast::ResourceConstraint {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::PrincipalOrResourceConstraint) -> Self {
        Self::new(ast::PrincipalOrResourceConstraint::from(v))
    }
}

impl From<&ast::ResourceConstraint> for models::PrincipalOrResourceConstraint {
    fn from(v: &ast::ResourceConstraint) -> Self {
        models::PrincipalOrResourceConstraint::from(v.as_inner())
    }
}

impl From<&models::EntityReference> for ast::EntityReference {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::EntityReference) -> Self {
        match v.data.as_ref().expect("data field should exist") {
            models::entity_reference::Data::Slot(slot) => {
                match models::entity_reference::Slot::try_from(*slot)
                    .expect("decode should succeed")
                {
                    models::entity_reference::Slot::Unit => ast::EntityReference::Slot(None),
                }
            }
            models::entity_reference::Data::Euid(euid) => {
                ast::EntityReference::euid(ast::EntityUID::from(euid).into())
            }
        }
    }
}

impl From<&ast::EntityReference> for models::EntityReference {
    fn from(v: &ast::EntityReference) -> Self {
        match v {
            ast::EntityReference::EUID(euid) => Self {
                data: Some(models::entity_reference::Data::Euid(
                    models::EntityUid::from(euid.as_ref()),
                )),
            },
            ast::EntityReference::Slot(_) => Self {
                data: Some(models::entity_reference::Data::Slot(
                    models::entity_reference::Slot::Unit.into(),
                )),
            },
        }
    }
}

impl From<&models::PrincipalOrResourceConstraint> for ast::PrincipalOrResourceConstraint {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::PrincipalOrResourceConstraint) -> Self {
        match v.data.as_ref().expect("data field should exist") {
            models::principal_or_resource_constraint::Data::Any(unit) => {
                match models::principal_or_resource_constraint::Any::try_from(*unit)
                    .expect("decode should succeed")
                {
                    models::principal_or_resource_constraint::Any::Unit => {
                        ast::PrincipalOrResourceConstraint::Any
                    }
                }
            }
            models::principal_or_resource_constraint::Data::In(msg) => {
                ast::PrincipalOrResourceConstraint::In(ast::EntityReference::from(
                    msg.er.as_ref().expect("er field should exist"),
                ))
            }
            models::principal_or_resource_constraint::Data::Eq(msg) => {
                ast::PrincipalOrResourceConstraint::Eq(ast::EntityReference::from(
                    msg.er.as_ref().expect("er field should exist"),
                ))
            }
            models::principal_or_resource_constraint::Data::Is(msg) => {
                ast::PrincipalOrResourceConstraint::Is(
                    ast::EntityType::from(
                        msg.entity_type
                            .as_ref()
                            .expect("entity_type field should exist"),
                    )
                    .into(),
                )
            }
            models::principal_or_resource_constraint::Data::IsIn(msg) => {
                ast::PrincipalOrResourceConstraint::IsIn(
                    ast::EntityType::from(
                        msg.entity_type
                            .as_ref()
                            .expect("entity_type field should exist"),
                    )
                    .into(),
                    ast::EntityReference::from(msg.er.as_ref().expect("er field should exist")),
                )
            }
        }
    }
}

impl From<&ast::PrincipalOrResourceConstraint> for models::PrincipalOrResourceConstraint {
    fn from(v: &ast::PrincipalOrResourceConstraint) -> Self {
        match v {
            ast::PrincipalOrResourceConstraint::Any => Self {
                data: Some(models::principal_or_resource_constraint::Data::Any(
                    models::principal_or_resource_constraint::Any::Unit.into(),
                )),
            },
            ast::PrincipalOrResourceConstraint::In(er) => Self {
                data: Some(models::principal_or_resource_constraint::Data::In(
                    models::principal_or_resource_constraint::InMessage {
                        er: Some(models::EntityReference::from(er)),
                    },
                )),
            },
            ast::PrincipalOrResourceConstraint::Eq(er) => Self {
                data: Some(models::principal_or_resource_constraint::Data::Eq(
                    models::principal_or_resource_constraint::EqMessage {
                        er: Some(models::EntityReference::from(er)),
                    },
                )),
            },
            ast::PrincipalOrResourceConstraint::Is(na) => Self {
                data: Some(models::principal_or_resource_constraint::Data::Is(
                    models::principal_or_resource_constraint::IsMessage {
                        entity_type: Some(models::Name::from(na.as_ref())),
                    },
                )),
            },
            ast::PrincipalOrResourceConstraint::IsIn(na, er) => Self {
                data: Some(models::principal_or_resource_constraint::Data::IsIn(
                    models::principal_or_resource_constraint::IsInMessage {
                        er: Some(models::EntityReference::from(er)),
                        entity_type: Some(models::Name::from(na.as_ref())),
                    },
                )),
            },
        }
    }
}

impl From<&models::ActionConstraint> for ast::ActionConstraint {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::ActionConstraint) -> Self {
        match v.data.as_ref().expect("data.as_ref()") {
            models::action_constraint::Data::Any(unit) => {
                match models::action_constraint::Any::try_from(*unit)
                    .expect("decode should succeed")
                {
                    models::action_constraint::Any::Unit => ast::ActionConstraint::Any,
                }
            }
            models::action_constraint::Data::In(msg) => ast::ActionConstraint::In(
                msg.euids
                    .iter()
                    .map(|value| ast::EntityUID::from(value).into())
                    .collect(),
            ),
            models::action_constraint::Data::Eq(msg) => ast::ActionConstraint::Eq(
                ast::EntityUID::from(msg.euid.as_ref().expect("euid field should exist")).into(),
            ),
        }
    }
}

impl From<&ast::ActionConstraint> for models::ActionConstraint {
    fn from(v: &ast::ActionConstraint) -> Self {
        match v {
            ast::ActionConstraint::Any => Self {
                data: Some(models::action_constraint::Data::Any(
                    models::action_constraint::Any::Unit.into(),
                )),
            },
            ast::ActionConstraint::In(euids) => {
                let mut peuids: Vec<models::EntityUid> = Vec::with_capacity(euids.len());
                for value in euids {
                    peuids.push(models::EntityUid::from(value.as_ref()));
                }
                Self {
                    data: Some(models::action_constraint::Data::In(
                        models::action_constraint::InMessage { euids: peuids },
                    )),
                }
            }
            ast::ActionConstraint::Eq(euid) => Self {
                data: Some(models::action_constraint::Data::Eq(
                    models::action_constraint::EqMessage {
                        euid: Some(models::EntityUid::from(euid.as_ref())),
                    },
                )),
            },
            #[cfg(feature = "tolerant-ast")]
            ast::ActionConstraint::ErrorConstraint =>
            // Treat an error constraint as an Any constraint for Protobufs since Protobufs schema model has no Error
            {
                Self {
                    data: Some(models::action_constraint::Data::Any(
                        models::action_constraint::Any::Unit.into(),
                    )),
                }
            }
        }
    }
}

impl From<&models::Effect> for ast::Effect {
    fn from(v: &models::Effect) -> Self {
        match v {
            models::Effect::Forbid => ast::Effect::Forbid,
            models::Effect::Permit => ast::Effect::Permit,
        }
    }
}

impl From<&ast::Effect> for models::Effect {
    fn from(v: &ast::Effect) -> Self {
        match v {
            ast::Effect::Permit => models::Effect::Permit,
            ast::Effect::Forbid => models::Effect::Forbid,
        }
    }
}

impl From<&models::PolicySet> for ast::LiteralPolicySet {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::PolicySet) -> Self {
        let templates = v.templates.iter().map(|tb| {
            (
                ast::PolicyID::from_string(&tb.id),
                ast::Template::from(ast::TemplateBody::from(tb)),
            )
        });

        let links = v.links.iter().map(|p| {
            // per docs in core.proto, for static policies, `link_id` is omitted/ignored,
            // and the ID of the policy is the `template_id`.
            let id = if p.is_template_link {
                p.link_id
                    .as_ref()
                    .expect("template link should have a link_id")
            } else {
                &p.template_id
            };
            (ast::PolicyID::from_string(id), ast::LiteralPolicy::from(p))
        });

        Self::new(templates, links)
    }
}

impl From<&ast::LiteralPolicySet> for models::PolicySet {
    fn from(v: &ast::LiteralPolicySet) -> Self {
        let templates = v.templates().map(models::TemplateBody::from).collect();
        let links = v.policies().map(models::Policy::from).collect();
        Self { templates, links }
    }
}

impl From<&ast::PolicySet> for models::PolicySet {
    fn from(v: &ast::PolicySet) -> Self {
        let templates = v.all_templates().map(models::TemplateBody::from).collect();
        let links = v.policies().map(models::Policy::from).collect();
        Self { templates, links }
    }
}

impl TryFrom<&models::PolicySet> for ast::PolicySet {
    type Error = ast::ReificationError;
    fn try_from(pset: &models::PolicySet) -> Result<Self, Self::Error> {
        ast::PolicySet::try_from(ast::LiteralPolicySet::from(pset))
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::*;

    // We add `PartialOrd` and `Ord` implementations for both `models::Policy` and
    // `models::TemplateBody`, so that these can be sorted for testing purposes
    impl PartialOrd for models::Policy {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for models::Policy {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            // assumes that (link-id, template-id) pair is unique, otherwise we're
            // technically violating `Ord` contract because there could exist two
            // policies that return `Ordering::Equal` but are not equal with `Eq`
            self.link_id()
                .cmp(other.link_id())
                .then_with(|| self.template_id.cmp(&other.template_id))
        }
    }
    impl Eq for models::Policy {}
    impl Eq for models::TemplateBody {}
    impl PartialOrd for models::TemplateBody {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for models::TemplateBody {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            // assumes that IDs are unique, otherwise we're technically violating
            // `Ord` contract because there could exist two template-bodies that
            // return `Ordering::Equal` but are not equal with `Eq`
            self.id.cmp(&other.id)
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn policy_roundtrip() {
        let annotation1 = ast::Annotation {
            val: "".into(),
            loc: None,
        };

        let annotation2 = ast::Annotation {
            val: "Hello World".into(),
            loc: None,
        };

        assert_eq!(
            ast::Effect::Permit,
            ast::Effect::from(&models::Effect::from(&ast::Effect::Permit))
        );
        assert_eq!(
            ast::Effect::Forbid,
            ast::Effect::from(&models::Effect::from(&ast::Effect::Forbid))
        );

        let er1 = ast::EntityReference::euid(Arc::new(
            ast::EntityUID::with_eid_and_type("A", "foo").unwrap(),
        ));
        assert_eq!(
            er1,
            ast::EntityReference::from(&models::EntityReference::from(&er1))
        );
        assert_eq!(
            ast::EntityReference::Slot(None),
            ast::EntityReference::from(&models::EntityReference::from(
                &ast::EntityReference::Slot(None)
            ))
        );

        let read_euid = Arc::new(ast::EntityUID::with_eid_and_type("Action", "read").unwrap());
        let write_euid = Arc::new(ast::EntityUID::with_eid_and_type("Action", "write").unwrap());
        let ac1 = ast::ActionConstraint::Eq(read_euid.clone());
        let ac2 = ast::ActionConstraint::In(vec![read_euid, write_euid]);
        assert_eq!(
            ast::ActionConstraint::Any,
            ast::ActionConstraint::from(&models::ActionConstraint::from(
                &ast::ActionConstraint::Any
            ))
        );
        assert_eq!(
            ac1,
            ast::ActionConstraint::from(&models::ActionConstraint::from(&ac1))
        );
        assert_eq!(
            ac2,
            ast::ActionConstraint::from(&models::ActionConstraint::from(&ac2))
        );

        let euid1 = Arc::new(ast::EntityUID::with_eid_and_type("A", "friend").unwrap());
        let name1 = Arc::new(ast::EntityType::from(
            ast::Name::from_normalized_str("B::C::D").unwrap(),
        ));
        let prc1 = ast::PrincipalOrResourceConstraint::is_eq(euid1.clone());
        let prc2 = ast::PrincipalOrResourceConstraint::is_in(euid1.clone());
        let prc3 = ast::PrincipalOrResourceConstraint::is_entity_type(name1.clone());
        let prc4 = ast::PrincipalOrResourceConstraint::is_entity_type_in(name1, euid1);
        assert_eq!(
            ast::PrincipalOrResourceConstraint::any(),
            ast::PrincipalOrResourceConstraint::from(&models::PrincipalOrResourceConstraint::from(
                &ast::PrincipalOrResourceConstraint::any()
            ))
        );
        assert_eq!(
            prc1,
            ast::PrincipalOrResourceConstraint::from(&models::PrincipalOrResourceConstraint::from(
                &prc1
            ))
        );
        assert_eq!(
            prc2,
            ast::PrincipalOrResourceConstraint::from(&models::PrincipalOrResourceConstraint::from(
                &prc2
            ))
        );
        assert_eq!(
            prc3,
            ast::PrincipalOrResourceConstraint::from(&models::PrincipalOrResourceConstraint::from(
                &prc3
            ))
        );
        assert_eq!(
            prc4,
            ast::PrincipalOrResourceConstraint::from(&models::PrincipalOrResourceConstraint::from(
                &prc4
            ))
        );

        let pc = ast::PrincipalConstraint::new(prc1);
        let rc = ast::ResourceConstraint::new(prc3);
        assert_eq!(
            pc,
            ast::PrincipalConstraint::from(&models::PrincipalOrResourceConstraint::from(&pc))
        );
        assert_eq!(
            rc,
            ast::ResourceConstraint::from(&models::PrincipalOrResourceConstraint::from(&rc))
        );

        assert_eq!(
            ast::Effect::Permit,
            ast::Effect::from(&models::Effect::from(&ast::Effect::Permit))
        );
        assert_eq!(
            ast::Effect::Forbid,
            ast::Effect::from(&models::Effect::from(&ast::Effect::Forbid))
        );

        let tb = ast::TemplateBody::new(
            ast::PolicyID::from_string("template"),
            None,
            ast::Annotations::from_iter([
                (
                    ast::AnyId::from_normalized_str("read").unwrap(),
                    annotation1,
                ),
                (
                    ast::AnyId::from_normalized_str("write").unwrap(),
                    annotation2,
                ),
            ]),
            ast::GeneralizedSlotsDeclaration::default(),
            ast::Effect::Permit,
            pc.clone(),
            ac1.clone(),
            rc.clone(),
            ast::Expr::val(true),
        );
        assert_eq!(
            tb,
            ast::TemplateBody::from(&models::TemplateBody::from(&tb))
        );

        let policy = ast::LiteralPolicy::template_linked_policy(
            ast::PolicyID::from_string("template"),
            ast::PolicyID::from_string("id"),
            HashMap::from_iter([(
                ast::SlotId::principal(),
                ast::EntityUID::with_eid_and_type("A", "eid").unwrap(),
            )]),
            HashMap::new(),
        );
        assert_eq!(
            policy,
            ast::LiteralPolicy::from(&models::Policy::from(&policy))
        );

        let tb = ast::TemplateBody::new(
            ast::PolicyID::from_string("\0\n \' \"+-$^!"),
            None,
            ast::Annotations::from_iter([]),
            ast::GeneralizedSlotsDeclaration::default(),
            ast::Effect::Permit,
            pc,
            ac1,
            rc,
            ast::Expr::val(true),
        );
        assert_eq!(
            tb,
            ast::TemplateBody::from(&models::TemplateBody::from(&tb))
        );

        let policy = ast::LiteralPolicy::template_linked_policy(
            ast::PolicyID::from_string("template\0\n \' \"+-$^!"),
            ast::PolicyID::from_string("link\0\n \' \"+-$^!"),
            HashMap::from_iter([(
                ast::SlotId::principal(),
                ast::EntityUID::with_eid_and_type("A", "eid").unwrap(),
            )]),
            HashMap::new(),
        );
        assert_eq!(
            policy,
            ast::LiteralPolicy::from(&models::Policy::from(&policy))
        );
    }

    #[test]
    fn policyset_roundtrip() {
        let tb = ast::TemplateBody::new(
            ast::PolicyID::from_string("template"),
            None,
            ast::Annotations::from_iter(vec![(
                ast::AnyId::from_normalized_str("read").unwrap(),
                ast::Annotation {
                    val: "".into(),
                    loc: None,
                },
            )]),
            ast::GeneralizedSlotsDeclaration::default(),
            ast::Effect::Permit,
            ast::PrincipalConstraint::is_eq_slot(),
            ast::ActionConstraint::Eq(
                ast::EntityUID::with_eid_and_type("Action", "read")
                    .unwrap()
                    .into(),
            ),
            ast::ResourceConstraint::is_entity_type(
                ast::EntityType::from(ast::Name::from_normalized_str("photo").unwrap()).into(),
            ),
            ast::Expr::val(true),
        );

        let policy1 = ast::Policy::from_when_clause(
            ast::Effect::Permit,
            ast::Expr::val(true),
            ast::PolicyID::from_string("permit-true-trivial"),
            None,
        );
        let policy2 = ast::Policy::from_when_clause(
            ast::Effect::Forbid,
            ast::Expr::is_eq(
                ast::Expr::var(ast::Var::Principal),
                ast::Expr::val(ast::EntityUID::with_eid_and_type("A", "dog").unwrap()),
            ),
            ast::PolicyID::from_string("forbid-dog"),
            None,
        );

        let mut ps = ast::PolicySet::new();
        ps.add_template(ast::Template::from(tb))
            .expect("Failed to add template to policy set.");
        ps.add(policy1).expect("Failed to add policy to policy set");
        ps.add(policy2).expect("Failed to add policy to policy set");
        ps.link(
            ast::PolicyID::from_string("template"),
            ast::PolicyID::from_string("link"),
            HashMap::from_iter([(
                ast::SlotId::principal(),
                ast::EntityUID::with_eid_and_type("A", "friend").unwrap(),
            )]),
            HashMap::new(),
            None,
        )
        .unwrap();
        let mut mps = models::PolicySet::from(&ps);
        let mut mps_roundtrip = models::PolicySet::from(&ast::LiteralPolicySet::from(&mps));

        // we accept permutations as equivalent, so before comparison, we sort
        // both `.templates` and `.links`
        mps.templates.sort();
        mps_roundtrip.templates.sort();
        mps.links.sort();
        mps_roundtrip.links.sort();

        // Can't compare `models::PolicySet` directly, so we compare their fields
        assert_eq!(mps.templates, mps_roundtrip.templates);
        assert_eq!(mps.links, mps_roundtrip.links);
    }

    #[test]
    fn policyset_roundtrip_escapes() {
        let tb = ast::TemplateBody::new(
            ast::PolicyID::from_string("template\0\n \' \"+-$^!"),
            None,
            ast::Annotations::from_iter(vec![(
                ast::AnyId::from_normalized_str("read").unwrap(),
                ast::Annotation {
                    val: "".into(),
                    loc: None,
                },
            )]),
            ast::GeneralizedSlotsDeclaration::default(),
            ast::Effect::Permit,
            ast::PrincipalConstraint::is_eq_slot(),
            ast::ActionConstraint::Eq(
                ast::EntityUID::with_eid_and_type("Action", "read")
                    .unwrap()
                    .into(),
            ),
            ast::ResourceConstraint::is_entity_type(
                ast::EntityType::from(ast::Name::from_normalized_str("photo").unwrap()).into(),
            ),
            ast::Expr::val(true),
        );

        let policy1 = ast::Policy::from_when_clause(
            ast::Effect::Permit,
            ast::Expr::val(true),
            ast::PolicyID::from_string("permit-true-trivial\0\n \' \"+-$^!"),
            None,
        );
        let policy2 = ast::Policy::from_when_clause(
            ast::Effect::Forbid,
            ast::Expr::is_eq(
                ast::Expr::var(ast::Var::Principal),
                ast::Expr::val(ast::EntityUID::with_eid_and_type("A", "dog").unwrap()),
            ),
            ast::PolicyID::from_string("forbid-dog\0\n \' \"+-$^!"),
            None,
        );

        let mut ps = ast::PolicySet::new();
        ps.add_template(ast::Template::from(tb))
            .expect("Failed to add template to policy set.");
        ps.add(policy1).expect("Failed to add policy to policy set");
        ps.add(policy2).expect("Failed to add policy to policy set");
        ps.link(
            ast::PolicyID::from_string("template\0\n \' \"+-$^!"),
            ast::PolicyID::from_string("link\0\n \' \"+-$^!"),
            HashMap::from_iter([(
                ast::SlotId::principal(),
                ast::EntityUID::with_eid_and_type("A", "friend").unwrap(),
            )]),
            HashMap::new(),
            None,
        )
        .unwrap();
        let mut mps = models::PolicySet::from(&ps);
        let mut mps_roundtrip = models::PolicySet::from(&ast::LiteralPolicySet::from(&mps));

        // we accept permutations as equivalent, so before comparison, we sort
        // both `.templates` and `.links`
        mps.templates.sort();
        mps_roundtrip.templates.sort();
        mps.links.sort();
        mps_roundtrip.links.sort();

        // Can't compare `models::PolicySet` directly, so we compare their fields
        assert_eq!(mps.templates, mps_roundtrip.templates);
        assert_eq!(mps.links, mps_roundtrip.links);
    }

    mod generalized_template {
        use super::*;
        use cedar_policy_core::est::Annotations;
        use std::collections::BTreeMap;

        #[test]
        fn template_types_roundtrip() {
            let bool_ty = json_schema::Type::Type {
                ty: json_schema::TypeVariant::EntityOrCommon {
                    type_name: RawName::new("Bool".parse().unwrap(), None),
                },
                loc: None,
            };

            assert_eq!(
                bool_ty,
                json_schema::Type::<RawName>::from(&models::TemplateType::from(&bool_ty))
            );

            let long_ty = json_schema::Type::Type {
                ty: json_schema::TypeVariant::EntityOrCommon {
                    type_name: RawName::new("Long".parse().unwrap(), None),
                },
                loc: None,
            };

            assert_eq!(
                long_ty,
                json_schema::Type::<RawName>::from(&models::TemplateType::from(&long_ty))
            );

            let set_ty = json_schema::Type::Type {
                ty: json_schema::TypeVariant::Set {
                    element: Box::new(bool_ty.clone()),
                },
                loc: None,
            };

            assert_eq!(
                set_ty,
                json_schema::Type::<RawName>::from(&models::TemplateType::from(&set_ty))
            );

            let record_ty = json_schema::Type::Type {
                ty: json_schema::TypeVariant::Record(json_schema::RecordType {
                    attributes: BTreeMap::from_iter([(
                        "date".parse().unwrap(),
                        json_schema::TypeOfAttribute {
                            ty: long_ty,
                            required: false,
                            annotations: Annotations::default(),
                            loc: None,
                        },
                    )]),
                    additional_attributes: false,
                }),
                loc: None,
            };

            assert_eq!(
                record_ty,
                json_schema::Type::<RawName>::from(&models::TemplateType::from(&record_ty))
            );
        }

        #[test]
        fn template_body_roundtrip() {
            let bool_ty = json_schema::Type::Type {
                ty: json_schema::TypeVariant::EntityOrCommon {
                    type_name: RawName::new("Bool".parse().unwrap(), None),
                },
                loc: None,
            };

            let set_ty = json_schema::Type::Type {
                ty: json_schema::TypeVariant::Set {
                    element: Box::new(bool_ty.clone()),
                },
                loc: None,
            };

            let entity_ty = json_schema::Type::Type {
                ty: json_schema::TypeVariant::EntityOrCommon {
                    type_name: RawName::new("User".parse().unwrap(), None),
                },
                loc: None,
            };

            let slot0 = ast::SlotId::generalized_slot("slot0".parse().unwrap());
            let slot1 = ast::SlotId::generalized_slot("slot1".parse().unwrap());

            let tb = ast::TemplateBody::new(
                ast::PolicyID::from_string("template"),
                None,
                ast::Annotations::from_iter(vec![(
                    ast::AnyId::from_normalized_str("read").unwrap(),
                    ast::Annotation {
                        val: "".into(),
                        loc: None,
                    },
                )]),
                ast::GeneralizedSlotsDeclaration::from_iter([
                    (slot0.clone(), bool_ty),
                    (slot1.clone(), set_ty),
                    (ast::SlotId::principal(), entity_ty),
                ]),
                ast::Effect::Permit,
                ast::PrincipalConstraint::is_eq_slot(),
                ast::ActionConstraint::Eq(
                    ast::EntityUID::with_eid_and_type("Action", "read")
                        .unwrap()
                        .into(),
                ),
                ast::ResourceConstraint::is_entity_type(
                    ast::EntityType::from(ast::Name::from_normalized_str("photo").unwrap()).into(),
                ),
                ast::Expr::contains(ast::Expr::slot(slot1), ast::Expr::slot(slot0)),
            );

            assert_eq!(
                tb,
                ast::TemplateBody::from(&models::TemplateBody::from(&tb))
            );
        }

        #[test]
        fn linked_literal_policy_roundtrip() {
            let policy = ast::LiteralPolicy::template_linked_policy(
                ast::PolicyID::from_string("policy0"),
                ast::PolicyID::from_string("link"),
                HashMap::new(),
                HashMap::from_iter([(
                    ast::SlotId::generalized_slot("folder".parse().unwrap()),
                    ast::RestrictedExpr::val(
                        ast::EntityUID::with_eid_and_type("Folder", "A").unwrap(),
                    ),
                )]),
            );

            assert_eq!(
                policy,
                ast::LiteralPolicy::from(&models::Policy::from(&policy))
            );
        }
    }
}
