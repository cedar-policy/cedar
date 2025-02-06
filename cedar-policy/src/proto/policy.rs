use super::*;
use cedar_policy_core::{ast, FromNormalizedStr};
use std::collections::HashMap;

impl From<&LiteralPolicy> for ast::LiteralPolicy {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &LiteralPolicy) -> Self {
        let mut values: ast::SlotEnv = HashMap::new();
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

        let template_id = ast::PolicyID::from_string(v.template_id.clone());

        if v.link_id_specified {
            Self::template_linked_policy(
                template_id,
                ast::PolicyID::from_string(v.link_id.clone()),
                values,
            )
        } else {
            Self::static_policy(template_id)
        }
    }
}

impl TryFrom<&LiteralPolicy> for ast::Policy {
    type Error = ast::ReificationError;
    fn try_from(policy: &LiteralPolicy) -> Result<Self, Self::Error> {
        // TODO: do we need to provide a nonempty `templates` argument to `.reify()`
        ast::LiteralPolicy::from(policy).reify(&HashMap::new())
    }
}

impl From<&ast::LiteralPolicy> for LiteralPolicy {
    fn from(v: &ast::LiteralPolicy) -> Self {
        Self {
            template_id: v.template_id().to_string(),
            link_id: if v.is_static() {
                String::new()
            } else {
                v.id().to_string()
            },
            link_id_specified: !v.is_static(),
            principal_euid: v.value(&ast::SlotId::principal()).map(EntityUid::from),
            resource_euid: v.value(&ast::SlotId::resource()).map(EntityUid::from),
        }
    }
}

impl From<&ast::Policy> for LiteralPolicy {
    fn from(v: &ast::Policy) -> Self {
        Self {
            template_id: v.template().id().to_string(),
            link_id: if v.is_static() {
                String::new()
            } else {
                v.id().to_string()
            },
            link_id_specified: !v.is_static(),
            principal_euid: v.env().get(&ast::SlotId::principal()).map(EntityUid::from),
            resource_euid: v.env().get(&ast::SlotId::resource()).map(EntityUid::from),
        }
    }
}

impl From<&TemplateBody> for ast::Template {
    fn from(v: &TemplateBody) -> Self {
        ast::Template::from(ast::TemplateBody::from(v))
    }
}

impl From<&TemplateBody> for ast::TemplateBody {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &TemplateBody) -> Self {
        let annotations: ast::Annotations =
            ast::Annotations::from_iter(v.annotations.iter().map(|(key, value)| {
                (
                    ast::AnyId::from_normalized_str(key).unwrap(),
                    ast::Annotation::from(value),
                )
            }));

        ast::TemplateBody::new(
            ast::PolicyID::from_string(v.id.clone()),
            None,
            annotations,
            ast::Effect::from(&Effect::try_from(v.effect).expect("decode should succeed")),
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

impl From<&ast::TemplateBody> for TemplateBody {
    fn from(v: &ast::TemplateBody) -> Self {
        let annotations: HashMap<String, Annotation> = v
            .annotations()
            .map(|(key, value)| (String::from(key.as_ref()), Annotation::from(value)))
            .collect();

        Self {
            id: v.id().to_string(),
            annotations,
            effect: Effect::from(&v.effect()).into(),
            principal_constraint: Some(PrincipalConstraint::from(v.principal_constraint())),
            action_constraint: Some(ActionConstraint::from(v.action_constraint())),
            resource_constraint: Some(ResourceConstraint::from(v.resource_constraint())),
            non_scope_constraints: Some(Expr::from(v.non_scope_constraints())),
        }
    }
}

impl From<&ast::Template> for TemplateBody {
    fn from(v: &ast::Template) -> Self {
        TemplateBody::from(&ast::TemplateBody::from(v.clone()))
    }
}

impl From<&PrincipalConstraint> for ast::PrincipalConstraint {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &PrincipalConstraint) -> Self {
        Self::new(ast::PrincipalOrResourceConstraint::from(
            v.constraint
                .as_ref()
                .expect("constraint field should exist"),
        ))
    }
}

impl From<&ast::PrincipalConstraint> for PrincipalConstraint {
    fn from(v: &ast::PrincipalConstraint) -> Self {
        Self {
            constraint: Some(PrincipalOrResourceConstraint::from(v.as_inner())),
        }
    }
}

impl From<&ResourceConstraint> for ast::ResourceConstraint {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &ResourceConstraint) -> Self {
        Self::new(ast::PrincipalOrResourceConstraint::from(
            v.constraint
                .as_ref()
                .expect("constraint field should exist"),
        ))
    }
}

impl From<&ast::ResourceConstraint> for ResourceConstraint {
    fn from(v: &ast::ResourceConstraint) -> Self {
        Self {
            constraint: Some(PrincipalOrResourceConstraint::from(v.as_inner())),
        }
    }
}

impl From<&EntityReference> for ast::EntityReference {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &EntityReference) -> Self {
        match v.data.as_ref().expect("data field should exist") {
            entity_reference::Data::Ty(ty) => {
                match entity_reference::Ty::try_from(ty.to_owned()).expect("decode should succeed")
                {
                    entity_reference::Ty::Slot => ast::EntityReference::Slot(None),
                }
            }
            entity_reference::Data::Euid(euid) => {
                ast::EntityReference::euid(ast::EntityUID::from(euid).into())
            }
        }
    }
}

impl From<&ast::EntityReference> for EntityReference {
    fn from(v: &ast::EntityReference) -> Self {
        match v {
            ast::EntityReference::EUID(euid) => Self {
                data: Some(entity_reference::Data::Euid(EntityUid::from(euid.as_ref()))),
            },
            ast::EntityReference::Slot(_) => Self {
                data: Some(entity_reference::Data::Ty(
                    entity_reference::Ty::Slot.into(),
                )),
            },
        }
    }
}

impl From<&PrincipalOrResourceConstraint> for ast::PrincipalOrResourceConstraint {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &PrincipalOrResourceConstraint) -> Self {
        match v.data.as_ref().expect("data field should exist") {
            principal_or_resource_constraint::Data::Ty(ty) => {
                match principal_or_resource_constraint::Ty::try_from(ty.to_owned())
                    .expect("decode should succeed")
                {
                    principal_or_resource_constraint::Ty::Any => {
                        ast::PrincipalOrResourceConstraint::Any
                    }
                }
            }
            principal_or_resource_constraint::Data::In(msg) => {
                ast::PrincipalOrResourceConstraint::In(ast::EntityReference::from(
                    msg.er.as_ref().expect("er field should exist"),
                ))
            }
            principal_or_resource_constraint::Data::Eq(msg) => {
                ast::PrincipalOrResourceConstraint::Eq(ast::EntityReference::from(
                    msg.er.as_ref().expect("er field should exist"),
                ))
            }
            principal_or_resource_constraint::Data::Is(msg) => {
                ast::PrincipalOrResourceConstraint::Is(
                    ast::EntityType::from(msg.et.as_ref().expect("et field should exist")).into(),
                )
            }
            principal_or_resource_constraint::Data::IsIn(msg) => {
                ast::PrincipalOrResourceConstraint::IsIn(
                    ast::EntityType::from(msg.et.as_ref().expect("et field should exist")).into(),
                    ast::EntityReference::from(msg.er.as_ref().expect("er field should exist")),
                )
            }
        }
    }
}

impl From<&ast::PrincipalOrResourceConstraint> for PrincipalOrResourceConstraint {
    fn from(v: &ast::PrincipalOrResourceConstraint) -> Self {
        match v {
            ast::PrincipalOrResourceConstraint::Any => Self {
                data: Some(principal_or_resource_constraint::Data::Ty(
                    principal_or_resource_constraint::Ty::Any.into(),
                )),
            },
            ast::PrincipalOrResourceConstraint::In(er) => Self {
                data: Some(principal_or_resource_constraint::Data::In(
                    principal_or_resource_constraint::InMessage {
                        er: Some(EntityReference::from(er)),
                    },
                )),
            },
            ast::PrincipalOrResourceConstraint::Eq(er) => Self {
                data: Some(principal_or_resource_constraint::Data::Eq(
                    principal_or_resource_constraint::EqMessage {
                        er: Some(EntityReference::from(er)),
                    },
                )),
            },
            ast::PrincipalOrResourceConstraint::Is(na) => Self {
                data: Some(principal_or_resource_constraint::Data::Is(
                    principal_or_resource_constraint::IsMessage {
                        et: Some(EntityType::from(na.as_ref())),
                    },
                )),
            },
            ast::PrincipalOrResourceConstraint::IsIn(na, er) => Self {
                data: Some(principal_or_resource_constraint::Data::IsIn(
                    principal_or_resource_constraint::IsInMessage {
                        er: Some(EntityReference::from(er)),
                        et: Some(EntityType::from(na.as_ref())),
                    },
                )),
            },
        }
    }
}

impl From<&ActionConstraint> for ast::ActionConstraint {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &ActionConstraint) -> Self {
        match v.data.as_ref().expect("data.as_ref()") {
            action_constraint::Data::Ty(ty) => {
                match action_constraint::Ty::try_from(ty.to_owned()).expect("decode should succeed")
                {
                    action_constraint::Ty::Any => ast::ActionConstraint::Any,
                }
            }
            action_constraint::Data::In(msg) => ast::ActionConstraint::In(
                msg.euids
                    .iter()
                    .map(|value| ast::EntityUID::from(value).into())
                    .collect(),
            ),
            action_constraint::Data::Eq(msg) => ast::ActionConstraint::Eq(
                ast::EntityUID::from(msg.euid.as_ref().expect("euid field should exist")).into(),
            ),
        }
    }
}

impl From<&ast::ActionConstraint> for ActionConstraint {
    fn from(v: &ast::ActionConstraint) -> Self {
        match v {
            ast::ActionConstraint::Any => Self {
                data: Some(action_constraint::Data::Ty(
                    action_constraint::Ty::Any.into(),
                )),
            },
            ast::ActionConstraint::In(euids) => {
                let mut peuids: Vec<EntityUid> = Vec::with_capacity(euids.len());
                for value in euids {
                    peuids.push(EntityUid::from(value.as_ref()));
                }
                Self {
                    data: Some(action_constraint::Data::In(action_constraint::InMessage {
                        euids: peuids,
                    })),
                }
            }
            ast::ActionConstraint::Eq(euid) => Self {
                data: Some(action_constraint::Data::Eq(action_constraint::EqMessage {
                    euid: Some(EntityUid::from(euid.as_ref())),
                })),
            },
        }
    }
}

impl From<&Effect> for ast::Effect {
    fn from(v: &Effect) -> Self {
        match v {
            Effect::Forbid => ast::Effect::Forbid,
            Effect::Permit => ast::Effect::Permit,
        }
    }
}

impl From<&ast::Effect> for Effect {
    fn from(v: &ast::Effect) -> Self {
        match v {
            ast::Effect::Permit => Effect::Permit,
            ast::Effect::Forbid => Effect::Forbid,
        }
    }
}

impl From<&LiteralPolicySet> for ast::LiteralPolicySet {
    fn from(v: &LiteralPolicySet) -> Self {
        let templates = v.templates.iter().map(|(key, value)| {
            (
                ast::PolicyID::from_string(key),
                ast::Template::from(ast::TemplateBody::from(value)),
            )
        });

        let links = v.links.iter().map(|(key, value)| {
            (
                ast::PolicyID::from_string(key),
                ast::LiteralPolicy::from(value),
            )
        });

        Self::new(templates, links)
    }
}

impl From<&ast::LiteralPolicySet> for LiteralPolicySet {
    fn from(v: &ast::LiteralPolicySet) -> Self {
        let templates = v
            .templates()
            .map(|template| {
                (
                    String::from(template.id().as_ref()),
                    TemplateBody::from(template),
                )
            })
            .collect();
        let links = v
            .policies()
            .map(|policy| {
                (
                    String::from(policy.id().as_ref()),
                    LiteralPolicy::from(policy),
                )
            })
            .collect();

        Self { templates, links }
    }
}

impl From<&ast::PolicySet> for LiteralPolicySet {
    fn from(v: &ast::PolicySet) -> Self {
        let templates: HashMap<String, TemplateBody> = v
            .templates()
            .map(|t| (String::from(t.id().as_ref()), TemplateBody::from(t)))
            .collect();
        let links: HashMap<String, LiteralPolicy> = v
            .policies()
            .map(|policy| {
                (
                    String::from(policy.id().as_ref()),
                    LiteralPolicy::from(policy),
                )
            })
            .collect();

        Self { templates, links }
    }
}

impl TryFrom<&LiteralPolicySet> for ast::PolicySet {
    type Error = ast::ReificationError;
    fn try_from(pset: &LiteralPolicySet) -> Result<Self, Self::Error> {
        ast::PolicySet::try_from(ast::LiteralPolicySet::from(pset))
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn policy_roundtrip() {
        let annotation1 = ast::Annotation {
            val: "".into(),
            loc: None,
        };
        assert_eq!(
            annotation1,
            ast::Annotation::from(&Annotation::from(&annotation1))
        );

        let annotation2 = ast::Annotation {
            val: "Hello World".into(),
            loc: None,
        };
        assert_eq!(
            annotation2,
            ast::Annotation::from(&Annotation::from(&annotation2))
        );

        assert_eq!(
            ast::Effect::Permit,
            ast::Effect::from(&Effect::from(&ast::Effect::Permit))
        );
        assert_eq!(
            ast::Effect::Forbid,
            ast::Effect::from(&Effect::from(&ast::Effect::Forbid))
        );

        let er1 = ast::EntityReference::euid(Arc::new(
            ast::EntityUID::with_eid_and_type("A", "foo").unwrap(),
        ));
        assert_eq!(
            er1,
            ast::EntityReference::from(&EntityReference::from(&er1))
        );
        assert_eq!(
            ast::EntityReference::Slot(None),
            ast::EntityReference::from(&EntityReference::from(&ast::EntityReference::Slot(None)))
        );

        let read_euid = Arc::new(ast::EntityUID::with_eid_and_type("Action", "read").unwrap());
        let write_euid = Arc::new(ast::EntityUID::with_eid_and_type("Action", "write").unwrap());
        let ac1 = ast::ActionConstraint::Eq(read_euid.clone());
        let ac2 = ast::ActionConstraint::In(vec![read_euid, write_euid]);
        assert_eq!(
            ast::ActionConstraint::Any,
            ast::ActionConstraint::from(&ActionConstraint::from(&ast::ActionConstraint::Any))
        );
        assert_eq!(
            ac1,
            ast::ActionConstraint::from(&ActionConstraint::from(&ac1))
        );
        assert_eq!(
            ac2,
            ast::ActionConstraint::from(&ActionConstraint::from(&ac2))
        );

        let euid1 = Arc::new(ast::EntityUID::with_eid_and_type("A", "friend").unwrap());
        let name1 = Arc::new(ast::EntityType::from(
            ast::Name::from_normalized_str("B::C::D").unwrap(),
        ));
        let prc1 = ast::PrincipalOrResourceConstraint::is_eq(euid1.to_owned());
        let prc2 = ast::PrincipalOrResourceConstraint::is_in(euid1.to_owned());
        let prc3 = ast::PrincipalOrResourceConstraint::is_entity_type(name1.to_owned());
        let prc4 = ast::PrincipalOrResourceConstraint::is_entity_type_in(name1, euid1);
        assert_eq!(
            ast::PrincipalOrResourceConstraint::any(),
            ast::PrincipalOrResourceConstraint::from(&PrincipalOrResourceConstraint::from(
                &ast::PrincipalOrResourceConstraint::any()
            ))
        );
        assert_eq!(
            prc1,
            ast::PrincipalOrResourceConstraint::from(&PrincipalOrResourceConstraint::from(&prc1))
        );
        assert_eq!(
            prc2,
            ast::PrincipalOrResourceConstraint::from(&PrincipalOrResourceConstraint::from(&prc2))
        );
        assert_eq!(
            prc3,
            ast::PrincipalOrResourceConstraint::from(&PrincipalOrResourceConstraint::from(&prc3))
        );
        assert_eq!(
            prc4,
            ast::PrincipalOrResourceConstraint::from(&PrincipalOrResourceConstraint::from(&prc4))
        );

        let pc = ast::PrincipalConstraint::new(prc1);
        let rc = ast::ResourceConstraint::new(prc3);
        assert_eq!(
            pc,
            ast::PrincipalConstraint::from(&PrincipalConstraint::from(&pc))
        );
        assert_eq!(
            rc,
            ast::ResourceConstraint::from(&ResourceConstraint::from(&rc))
        );

        assert_eq!(
            ast::Effect::Permit,
            ast::Effect::from(&Effect::from(&ast::Effect::Permit))
        );
        assert_eq!(
            ast::Effect::Forbid,
            ast::Effect::from(&Effect::from(&ast::Effect::Forbid))
        );

        let tb = ast::TemplateBody::new(
            ast::PolicyID::from_string("template"),
            None,
            ast::Annotations::from_iter([(
                ast::AnyId::from_normalized_str("read").unwrap(),
                annotation1,
            )]),
            ast::Effect::Permit,
            pc,
            ac1,
            rc,
            ast::Expr::val(true),
        );
        assert_eq!(tb, ast::TemplateBody::from(&TemplateBody::from(&tb)));

        let policy = ast::LiteralPolicy::template_linked_policy(
            ast::PolicyID::from_string("template"),
            ast::PolicyID::from_string("id"),
            HashMap::from_iter([(
                ast::SlotId::principal(),
                ast::EntityUID::with_eid_and_type("A", "eid").unwrap(),
            )]),
        );
        assert_eq!(
            policy,
            ast::LiteralPolicy::from(&LiteralPolicy::from(&policy))
        );
    }

    #[test]
    fn policyset_roundtrip() {
        let annotation1 = ast::Annotation {
            val: "".into(),
            loc: None,
        };
        let pc = ast::PrincipalConstraint::is_eq(
            ast::EntityUID::with_eid_and_type("A", "friend")
                .unwrap()
                .into(),
        );
        let ac = ast::ActionConstraint::Eq(
            ast::EntityUID::with_eid_and_type("Action", "read")
                .unwrap()
                .into(),
        );
        let rc = ast::ResourceConstraint::is_entity_type(
            ast::EntityType::from(ast::Name::from_normalized_str("photo").unwrap()).into(),
        );

        let tb = ast::TemplateBody::new(
            ast::PolicyID::from_string("template"),
            None,
            ast::Annotations::from_iter(vec![(
                ast::AnyId::from_normalized_str("read").unwrap(),
                annotation1,
            )]),
            ast::Effect::Permit,
            pc,
            ac,
            rc,
            ast::Expr::val(true),
        );

        let policy = ast::Policy::from_when_clause(
            ast::Effect::Permit,
            ast::Expr::val(true),
            ast::PolicyID::from_string("alice"),
            None,
        );

        let mut ps = ast::PolicySet::new();
        ps.add_template(ast::Template::from(tb))
            .expect("Failed to add template to policy set.");
        ps.add(policy).expect("Failed to add policy to policy set.");
        let lps = LiteralPolicySet::from(&ps);
        let lps_roundtrip = LiteralPolicySet::from(&ast::LiteralPolicySet::from(&lps));

        // Can't compare LiteralPolicySets directly, so we compare their fields
        assert_eq!(lps.templates, lps_roundtrip.templates);
        assert_eq!(lps.links, lps_roundtrip.links);
    }

    #[test]
    fn policyset_roundtrip_forbids() {
        let annotation1 = ast::Annotation {
            val: "".into(),
            loc: None,
        };
        let pc = ast::PrincipalConstraint::is_eq(
            ast::EntityUID::with_eid_and_type("A", "friend")
                .unwrap()
                .into(),
        );
        let ac = ast::ActionConstraint::Eq(
            ast::EntityUID::with_eid_and_type("Action", "read")
                .unwrap()
                .into(),
        );
        let rc = ast::ResourceConstraint::is_entity_type(
            ast::EntityType::from(ast::Name::from_normalized_str("photo").unwrap()).into(),
        );

        let tb = ast::TemplateBody::new(
            ast::PolicyID::from_string("template"),
            None,
            ast::Annotations::from_iter([(
                ast::AnyId::from_normalized_str("read").unwrap(),
                annotation1,
            )]),
            ast::Effect::Forbid,
            pc,
            ac,
            rc,
            ast::Expr::val(true),
        );

        let policy = ast::Policy::from_when_clause(
            ast::Effect::Permit,
            ast::Expr::val(true),
            ast::PolicyID::from_string("alice"),
            None,
        );

        let mut ps = ast::PolicySet::new();
        ps.add_template(ast::Template::from(tb))
            .expect("Failed to add template to policy set.");
        ps.add(policy.clone())
            .expect("Failed to add policy to policy set.");
        let lps = LiteralPolicySet::from(&ps);
        let lps_roundtrip = LiteralPolicySet::from(&ast::LiteralPolicySet::from(&lps));

        // Can't compare LiteralPolicySets directly, so we compare their fields
        assert_eq!(lps.templates, lps_roundtrip.templates);
        assert_eq!(lps.links, lps_roundtrip.links);

        ps.remove_static(policy.id()).unwrap();
        let policy = ast::Policy::from_when_clause(
            ast::Effect::Forbid,
            ast::Expr::val(true),
            ast::PolicyID::from_string("alice"),
            None,
        );
        ps.add(policy).expect("Failed to add policy to policy set.");
        let lps = LiteralPolicySet::from(&ps);
        // Static policies have templates, so not equal
        assert_ne!(lps.templates, lps_roundtrip.templates);
        // The static policies are identical except for the template, so links are equal
        assert_eq!(lps.links, lps_roundtrip.links);
    }
}
