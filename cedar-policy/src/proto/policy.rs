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

#![allow(clippy::use_self, reason = "readability")]

use super::ast::ProtobufConversionError;
use super::models;
use cedar_policy_core::{ast, FromNormalizedStr};
use std::collections::{HashMap, HashSet};

impl TryFrom<models::Policy> for ast::LiteralPolicy {
    type Error = ProtobufConversionError;
    fn try_from(v: models::Policy) -> Result<Self, Self::Error> {
        let mut values: ast::SlotEnv = HashMap::new();
        if let Some(principal_euid) = v.principal_euid {
            values.insert(
                ast::SlotId::principal(),
                ast::EntityUID::try_from(principal_euid)?,
            );
        }
        if let Some(resource_euid) = v.resource_euid {
            values.insert(
                ast::SlotId::resource(),
                ast::EntityUID::try_from(resource_euid)?,
            );
        }

        let template_id = ast::PolicyID::from_string(v.template_id);

        if v.is_template_link {
            Ok(Self::template_linked_policy(
                template_id,
                ast::PolicyID::from_string(
                    v.link_id
                        .as_ref()
                        .ok_or_else(|| ProtobufConversionError::missing("link_id"))?,
                ),
                values,
            ))
        } else {
            Ok(Self::static_policy(template_id))
        }
    }
}

impl From<&ast::LiteralPolicy> for models::Policy {
    fn from(v: &ast::LiteralPolicy) -> Self {
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
        }
    }
}

impl From<&ast::Policy> for models::Policy {
    fn from(v: &ast::Policy) -> Self {
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
        }
    }
}

impl TryFrom<models::TemplateBody> for ast::Template {
    type Error = ProtobufConversionError;
    fn try_from(v: models::TemplateBody) -> Result<Self, Self::Error> {
        Ok(ast::Template::from(ast::TemplateBody::try_from(v)?))
    }
}

impl TryFrom<models::TemplateBody> for ast::TemplateBody {
    type Error = ProtobufConversionError;
    fn try_from(v: models::TemplateBody) -> Result<Self, Self::Error> {
        let effect = models::Effect::try_from(v.effect)
            .map_err(|e| ProtobufConversionError::InvalidValue(format!("invalid effect: {e}")))?;
        Ok(ast::TemplateBody::new(
            ast::PolicyID::from_string(v.id),
            None,
            v.annotations
                .into_iter()
                .map(|(key, value)| {
                    ast::AnyId::from_normalized_str(&key)
                        .map(|k| {
                            (
                                k,
                                ast::Annotation {
                                    val: value.into(),
                                    loc: None,
                                },
                            )
                        })
                        .map_err(|e| {
                            ProtobufConversionError::InvalidValue(format!(
                                "invalid annotation key `{key}`: {e}"
                            ))
                        })
                })
                .collect::<Result<_, _>>()?,
            ast::Effect::from(effect),
            ast::PrincipalConstraint::try_from(
                v.principal_constraint
                    .ok_or_else(|| ProtobufConversionError::missing("principal_constraint"))?,
            )?,
            ast::ActionConstraint::try_from(
                v.action_constraint
                    .ok_or_else(|| ProtobufConversionError::missing("action_constraint"))?,
            )?,
            ast::ResourceConstraint::try_from(
                v.resource_constraint
                    .ok_or_else(|| ProtobufConversionError::missing("resource_constraint"))?,
            )?,
            v.non_scope_constraints
                .map(ast::Expr::try_from)
                .transpose()?,
        ))
    }
}

impl From<&ast::TemplateBody> for models::TemplateBody {
    fn from(v: &ast::TemplateBody) -> Self {
        let annotations: HashMap<String, String> = v
            .annotations()
            .map(|(key, value)| (key.as_ref().into(), value.as_ref().into()))
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
            non_scope_constraints: v.non_scope_constraints().map(models::Expr::from),
        }
    }
}

impl From<&ast::Template> for models::TemplateBody {
    fn from(v: &ast::Template) -> Self {
        models::TemplateBody::from(&ast::TemplateBody::from(v.clone()))
    }
}

impl TryFrom<models::PrincipalOrResourceConstraint> for ast::PrincipalConstraint {
    type Error = ProtobufConversionError;
    fn try_from(v: models::PrincipalOrResourceConstraint) -> Result<Self, Self::Error> {
        Ok(Self::new(ast::PrincipalOrResourceConstraint::try_from(v)?))
    }
}

impl From<&ast::PrincipalConstraint> for models::PrincipalOrResourceConstraint {
    fn from(v: &ast::PrincipalConstraint) -> Self {
        models::PrincipalOrResourceConstraint::from(v.as_inner())
    }
}

impl TryFrom<models::PrincipalOrResourceConstraint> for ast::ResourceConstraint {
    type Error = ProtobufConversionError;
    fn try_from(v: models::PrincipalOrResourceConstraint) -> Result<Self, Self::Error> {
        Ok(Self::new(ast::PrincipalOrResourceConstraint::try_from(v)?))
    }
}

impl From<&ast::ResourceConstraint> for models::PrincipalOrResourceConstraint {
    fn from(v: &ast::ResourceConstraint) -> Self {
        models::PrincipalOrResourceConstraint::from(v.as_inner())
    }
}

impl TryFrom<models::EntityReference> for ast::EntityReference {
    type Error = ProtobufConversionError;
    fn try_from(v: models::EntityReference) -> Result<Self, Self::Error> {
        match v
            .data
            .ok_or_else(|| ProtobufConversionError::missing("data"))?
        {
            models::entity_reference::Data::Slot(slot) => {
                match models::entity_reference::Slot::try_from(slot).map_err(|e| {
                    ProtobufConversionError::InvalidValue(format!(
                        "invalid entity reference slot: {e}"
                    ))
                })? {
                    models::entity_reference::Slot::Unit => Ok(ast::EntityReference::Slot(None)),
                }
            }
            models::entity_reference::Data::Euid(euid) => Ok(ast::EntityReference::euid(
                ast::EntityUID::try_from(euid)?.into(),
            )),
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

impl TryFrom<models::PrincipalOrResourceConstraint> for ast::PrincipalOrResourceConstraint {
    type Error = ProtobufConversionError;
    fn try_from(v: models::PrincipalOrResourceConstraint) -> Result<Self, Self::Error> {
        match v
            .data
            .ok_or_else(|| ProtobufConversionError::missing("data"))?
        {
            models::principal_or_resource_constraint::Data::Any(unit) => {
                match models::principal_or_resource_constraint::Any::try_from(unit).map_err(
                    |e| {
                        ProtobufConversionError::InvalidValue(format!(
                            "invalid principal/resource constraint: {e}"
                        ))
                    },
                )? {
                    models::principal_or_resource_constraint::Any::Unit => {
                        Ok(ast::PrincipalOrResourceConstraint::Any)
                    }
                }
            }
            models::principal_or_resource_constraint::Data::In(msg) => Ok(
                ast::PrincipalOrResourceConstraint::In(ast::EntityReference::try_from(
                    msg.er
                        .ok_or_else(|| ProtobufConversionError::missing("er"))?,
                )?),
            ),
            models::principal_or_resource_constraint::Data::Eq(msg) => Ok(
                ast::PrincipalOrResourceConstraint::Eq(ast::EntityReference::try_from(
                    msg.er
                        .ok_or_else(|| ProtobufConversionError::missing("er"))?,
                )?),
            ),
            models::principal_or_resource_constraint::Data::Is(msg) => {
                Ok(ast::PrincipalOrResourceConstraint::Is(
                    ast::EntityType::try_from(
                        msg.entity_type
                            .ok_or_else(|| ProtobufConversionError::missing("entity_type"))?,
                    )?
                    .into(),
                ))
            }
            models::principal_or_resource_constraint::Data::IsIn(msg) => {
                Ok(ast::PrincipalOrResourceConstraint::IsIn(
                    ast::EntityType::try_from(
                        msg.entity_type
                            .ok_or_else(|| ProtobufConversionError::missing("entity_type"))?,
                    )?
                    .into(),
                    ast::EntityReference::try_from(
                        msg.er
                            .ok_or_else(|| ProtobufConversionError::missing("er"))?,
                    )?,
                ))
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

impl TryFrom<models::ActionConstraint> for ast::ActionConstraint {
    type Error = ProtobufConversionError;
    fn try_from(v: models::ActionConstraint) -> Result<Self, Self::Error> {
        match v
            .data
            .ok_or_else(|| ProtobufConversionError::missing("data"))?
        {
            models::action_constraint::Data::Any(unit) => {
                match models::action_constraint::Any::try_from(unit).map_err(|e| {
                    ProtobufConversionError::InvalidValue(format!("invalid action constraint: {e}"))
                })? {
                    models::action_constraint::Any::Unit => Ok(ast::ActionConstraint::Any),
                }
            }
            models::action_constraint::Data::In(msg) => Ok(ast::ActionConstraint::In(
                msg.euids
                    .into_iter()
                    .map(|value| Ok(ast::EntityUID::try_from(value)?.into()))
                    .collect::<Result<_, ProtobufConversionError>>()?,
            )),
            models::action_constraint::Data::Eq(msg) => Ok(ast::ActionConstraint::Eq(
                ast::EntityUID::try_from(
                    msg.euid
                        .ok_or_else(|| ProtobufConversionError::missing("euid"))?,
                )?
                .into(),
            )),
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
            #[expect(clippy::unimplemented, reason = "experimental feature")]
            ast::ActionConstraint::ErrorConstraint => {
                unimplemented!("tolerant-ast cannot be used with the protobuf feature")
            }
        }
    }
}

impl From<models::Effect> for ast::Effect {
    fn from(v: models::Effect) -> Self {
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

impl TryFrom<models::PolicySet> for ast::LiteralPolicySet {
    type Error = ProtobufConversionError;
    fn try_from(v: models::PolicySet) -> Result<Self, Self::Error> {
        let mut template_ids: HashSet<ast::PolicyID> = HashSet::new();
        let mut link_ids: HashSet<ast::PolicyID> = HashSet::new();

        let templates = v
            .templates
            .into_iter()
            .map(|tb| {
                let id = ast::PolicyID::from_string(&tb.id);
                if !template_ids.insert(id.clone()) {
                    return Err(ProtobufConversionError::InvalidValue(format!(
                        "duplicate template id `{id}`"
                    )));
                }
                Ok((id, ast::Template::from(ast::TemplateBody::try_from(tb)?)))
            })
            .collect::<Result<Vec<_>, ProtobufConversionError>>()?;

        let links = v
            .links
            .into_iter()
            .map(|p| {
                // per docs in core.proto, for static policies, `link_id` is omitted/ignored,
                // and the ID of the policy is the `template_id`.
                let id = if p.is_template_link {
                    p.link_id
                        .as_ref()
                        .ok_or_else(|| ProtobufConversionError::missing("link_id"))?
                } else {
                    &p.template_id
                };
                let id = ast::PolicyID::from_string(id);
                if !link_ids.insert(id.clone()) {
                    return Err(ProtobufConversionError::InvalidValue(format!(
                        "duplicate link id `{id}`"
                    )));
                }
                // Template ids and links ids must not conflict!
                if p.is_template_link && template_ids.contains(&id) {
                    return Err(ProtobufConversionError::InvalidValue(format!(
                        "link id `{id}` conflicts with a template id"
                    )));
                }
                Ok((id, ast::LiteralPolicy::try_from(p)?))
            })
            .collect::<Result<Vec<_>, ProtobufConversionError>>()?;

        Ok(Self::new(templates, links))
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

impl TryFrom<models::PolicySet> for ast::PolicySet {
    type Error = ProtobufConversionError;
    fn try_from(pset: models::PolicySet) -> Result<Self, Self::Error> {
        let literal = ast::LiteralPolicySet::try_from(pset)?;
        ast::PolicySet::try_from(literal)
            .map_err(|e| ProtobufConversionError::InvalidValue(format!("invalid policy set: {e}")))
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::*;
    use cool_asserts::assert_matches;

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

    /// A `PrincipalOrResourceConstraint` model matching any principal/resource.
    fn principal_or_resource_constraint_any() -> models::PrincipalOrResourceConstraint {
        models::PrincipalOrResourceConstraint {
            data: Some(models::principal_or_resource_constraint::Data::Any(
                models::principal_or_resource_constraint::Any::Unit.into(),
            )),
        }
    }

    /// An `ActionConstraint` model matching any action.
    fn action_constraint_any() -> models::ActionConstraint {
        models::ActionConstraint {
            data: Some(models::action_constraint::Data::Any(
                models::action_constraint::Any::Unit.into(),
            )),
        }
    }

    /// A minimal `TemplateBody` model with the given id and unconstrained scope.
    fn trivial_template_body(id: &str) -> models::TemplateBody {
        models::TemplateBody {
            id: id.to_string(),
            annotations: Default::default(),
            effect: models::Effect::Permit.into(),
            principal_constraint: Some(principal_or_resource_constraint_any()),
            action_constraint: Some(action_constraint_any()),
            resource_constraint: Some(principal_or_resource_constraint_any()),
            non_scope_constraints: None,
        }
    }

    /// A static policy link (not a template-linked policy) with the given id.
    fn static_policy_link(id: &str) -> models::Policy {
        models::Policy {
            template_id: id.to_string(),
            link_id: None,
            is_template_link: false,
            principal_euid: None,
            resource_euid: None,
        }
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "unit test code")]
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
            ast::Effect::from(models::Effect::from(&ast::Effect::Permit))
        );
        assert_eq!(
            ast::Effect::Forbid,
            ast::Effect::from(models::Effect::from(&ast::Effect::Forbid))
        );

        let er1 = ast::EntityReference::euid(Arc::new(
            ast::EntityUID::with_eid_and_type("A", "foo").unwrap(),
        ));
        assert_eq!(
            er1,
            ast::EntityReference::try_from(models::EntityReference::from(&er1)).unwrap()
        );
        assert_eq!(
            ast::EntityReference::Slot(None),
            ast::EntityReference::try_from(models::EntityReference::from(
                &ast::EntityReference::Slot(None)
            ))
            .unwrap()
        );

        let read_euid = Arc::new(ast::EntityUID::with_eid_and_type("Action", "read").unwrap());
        let write_euid = Arc::new(ast::EntityUID::with_eid_and_type("Action", "write").unwrap());
        let ac1 = ast::ActionConstraint::Eq(read_euid.clone());
        let ac2 = ast::ActionConstraint::In(vec![read_euid, write_euid]);
        assert_eq!(
            ast::ActionConstraint::Any,
            ast::ActionConstraint::try_from(models::ActionConstraint::from(
                &ast::ActionConstraint::Any
            ))
            .unwrap()
        );
        assert_eq!(
            ac1,
            ast::ActionConstraint::try_from(models::ActionConstraint::from(&ac1)).unwrap()
        );
        assert_eq!(
            ac2,
            ast::ActionConstraint::try_from(models::ActionConstraint::from(&ac2)).unwrap()
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
            ast::PrincipalOrResourceConstraint::try_from(
                models::PrincipalOrResourceConstraint::from(
                    &ast::PrincipalOrResourceConstraint::any()
                )
            )
            .unwrap()
        );
        assert_eq!(
            prc1,
            ast::PrincipalOrResourceConstraint::try_from(
                models::PrincipalOrResourceConstraint::from(&prc1)
            )
            .unwrap()
        );
        assert_eq!(
            prc2,
            ast::PrincipalOrResourceConstraint::try_from(
                models::PrincipalOrResourceConstraint::from(&prc2)
            )
            .unwrap()
        );
        assert_eq!(
            prc3,
            ast::PrincipalOrResourceConstraint::try_from(
                models::PrincipalOrResourceConstraint::from(&prc3)
            )
            .unwrap()
        );
        assert_eq!(
            prc4,
            ast::PrincipalOrResourceConstraint::try_from(
                models::PrincipalOrResourceConstraint::from(&prc4)
            )
            .unwrap()
        );

        let pc = ast::PrincipalConstraint::new(prc1);
        let rc = ast::ResourceConstraint::new(prc3);
        assert_eq!(
            pc,
            ast::PrincipalConstraint::try_from(models::PrincipalOrResourceConstraint::from(&pc))
                .unwrap()
        );
        assert_eq!(
            rc,
            ast::ResourceConstraint::try_from(models::PrincipalOrResourceConstraint::from(&rc))
                .unwrap()
        );

        assert_eq!(
            ast::Effect::Permit,
            ast::Effect::from(models::Effect::from(&ast::Effect::Permit))
        );
        assert_eq!(
            ast::Effect::Forbid,
            ast::Effect::from(models::Effect::from(&ast::Effect::Forbid))
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
            ast::Effect::Permit,
            pc.clone(),
            ac1.clone(),
            rc.clone(),
            None,
        );
        assert_eq!(
            tb,
            ast::TemplateBody::try_from(models::TemplateBody::from(&tb)).unwrap()
        );

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
            ast::LiteralPolicy::try_from(models::Policy::from(&policy)).unwrap()
        );

        let tb = ast::TemplateBody::new(
            ast::PolicyID::from_string("\0\n \' \"+-$^!"),
            None,
            ast::Annotations::from_iter([]),
            ast::Effect::Permit,
            pc,
            ac1,
            rc,
            None,
        );
        assert_eq!(
            tb,
            ast::TemplateBody::try_from(models::TemplateBody::from(&tb)).unwrap()
        );

        let policy = ast::LiteralPolicy::template_linked_policy(
            ast::PolicyID::from_string("template\0\n \' \"+-$^!"),
            ast::PolicyID::from_string("link\0\n \' \"+-$^!"),
            HashMap::from_iter([(
                ast::SlotId::principal(),
                ast::EntityUID::with_eid_and_type("A", "eid").unwrap(),
            )]),
        );
        assert_eq!(
            policy,
            ast::LiteralPolicy::try_from(models::Policy::from(&policy)).unwrap()
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
            None,
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
        )
        .unwrap();
        let mut mps = models::PolicySet::from(&ps);
        let mut mps_roundtrip =
            models::PolicySet::from(&ast::LiteralPolicySet::try_from(mps.clone()).unwrap());

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
            None,
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
        )
        .unwrap();
        let mut mps = models::PolicySet::from(&ps);
        let mut mps_roundtrip =
            models::PolicySet::from(&ast::LiteralPolicySet::try_from(mps.clone()).unwrap());

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
    fn template_body_try_from_missing_principal_constraint() {
        let bad = models::TemplateBody {
            id: "t".to_string(),
            annotations: Default::default(),
            effect: models::Effect::Permit.into(),
            principal_constraint: None,
            action_constraint: Some(action_constraint_any()),
            resource_constraint: Some(principal_or_resource_constraint_any()),
            non_scope_constraints: None,
        };
        assert_matches!(
            ast::TemplateBody::try_from(bad),
            Err(ProtobufConversionError::MissingField(f)) if f == "principal_constraint"
        );
    }

    #[test]
    fn template_body_try_from_invalid_annotation_key() {
        let bad = models::TemplateBody {
            id: "t".to_string(),
            annotations: [("".to_string(), "v".to_string())].into_iter().collect(),
            effect: models::Effect::Permit.into(),
            principal_constraint: Some(principal_or_resource_constraint_any()),
            action_constraint: Some(action_constraint_any()),
            resource_constraint: Some(principal_or_resource_constraint_any()),
            non_scope_constraints: None,
        };
        assert_matches!(
            ast::TemplateBody::try_from(bad),
            Err(ProtobufConversionError::InvalidValue(msg)) if msg.contains("invalid annotation key")
        );
    }

    #[test]
    fn entity_reference_try_from_missing_data() {
        let bad = models::EntityReference { data: None };
        assert_matches!(
            ast::EntityReference::try_from(bad),
            Err(ProtobufConversionError::MissingField(f)) if f == "data"
        );
    }

    #[test]
    fn principal_or_resource_constraint_try_from_missing_data() {
        let bad = models::PrincipalOrResourceConstraint { data: None };
        assert_matches!(
            ast::PrincipalOrResourceConstraint::try_from(bad),
            Err(ProtobufConversionError::MissingField(f)) if f == "data"
        );
    }

    #[test]
    fn principal_or_resource_constraint_try_from_in_missing_er() {
        let bad = models::PrincipalOrResourceConstraint {
            data: Some(models::principal_or_resource_constraint::Data::In(
                models::principal_or_resource_constraint::InMessage { er: None },
            )),
        };
        assert_matches!(
            ast::PrincipalOrResourceConstraint::try_from(bad),
            Err(ProtobufConversionError::MissingField(f)) if f == "er"
        );
    }

    #[test]
    fn principal_or_resource_constraint_try_from_eq_missing_er() {
        let bad = models::PrincipalOrResourceConstraint {
            data: Some(models::principal_or_resource_constraint::Data::Eq(
                models::principal_or_resource_constraint::EqMessage { er: None },
            )),
        };
        assert_matches!(
            ast::PrincipalOrResourceConstraint::try_from(bad),
            Err(ProtobufConversionError::MissingField(f)) if f == "er"
        );
    }

    #[test]
    fn principal_or_resource_constraint_try_from_is_missing_entity_type() {
        let bad = models::PrincipalOrResourceConstraint {
            data: Some(models::principal_or_resource_constraint::Data::Is(
                models::principal_or_resource_constraint::IsMessage { entity_type: None },
            )),
        };
        assert_matches!(
            ast::PrincipalOrResourceConstraint::try_from(bad),
            Err(ProtobufConversionError::MissingField(f)) if f == "entity_type"
        );
    }

    #[test]
    fn principal_or_resource_constraint_try_from_is_in_missing_entity_type() {
        let bad = models::PrincipalOrResourceConstraint {
            data: Some(models::principal_or_resource_constraint::Data::IsIn(
                models::principal_or_resource_constraint::IsInMessage {
                    entity_type: None,
                    er: None,
                },
            )),
        };
        assert_matches!(
            ast::PrincipalOrResourceConstraint::try_from(bad),
            Err(ProtobufConversionError::MissingField(f)) if f == "entity_type"
        );
    }

    #[test]
    fn action_constraint_try_from_missing_data() {
        let bad = models::ActionConstraint { data: None };
        assert_matches!(
            ast::ActionConstraint::try_from(bad),
            Err(ProtobufConversionError::MissingField(f)) if f == "data"
        );
    }

    #[test]
    fn action_constraint_try_from_eq_missing_euid() {
        let bad = models::ActionConstraint {
            data: Some(models::action_constraint::Data::Eq(
                models::action_constraint::EqMessage { euid: None },
            )),
        };
        assert_matches!(
            ast::ActionConstraint::try_from(bad),
            Err(ProtobufConversionError::MissingField(f)) if f == "euid"
        );
    }

    #[test]
    fn literal_policy_try_from_template_link_missing_link_id() {
        let bad = models::Policy {
            template_id: "t".to_string(),
            link_id: None,
            is_template_link: true,
            principal_euid: None,
            resource_euid: None,
        };
        assert_matches!(
            ast::LiteralPolicy::try_from(bad),
            Err(ProtobufConversionError::MissingField(f)) if f == "link_id"
        );
    }

    #[test]
    fn literal_policy_set_try_from_link_missing_link_id() {
        let bad = models::PolicySet {
            templates: vec![trivial_template_body("t")],
            links: vec![models::Policy {
                template_id: "t".to_string(),
                link_id: None,
                is_template_link: true,
                principal_euid: None,
                resource_euid: None,
            }],
        };
        assert_matches!(
            ast::LiteralPolicySet::try_from(bad),
            Err(ProtobufConversionError::MissingField(f)) if f == "link_id"
        );
    }

    #[test]
    fn literal_policy_set_rejects_duplicate_template_ids() {
        let template = trivial_template_body("duplicate");
        let bad = models::PolicySet {
            templates: vec![template.clone(), template], // twice!
            links: vec![],
        };
        assert_matches!(
            ast::LiteralPolicySet::try_from(bad),
            Err(ProtobufConversionError::InvalidValue(msg)) if msg.contains("duplicate template id")
        );
    }

    #[test]
    fn literal_policy_set_rejects_duplicate_link_ids() {
        let bad = models::PolicySet {
            templates: vec![],
            links: vec![
                static_policy_link("duplicate"),
                static_policy_link("duplicate"),
            ],
        };
        assert_matches!(
            ast::LiteralPolicySet::try_from(bad),
            Err(ProtobufConversionError::InvalidValue(msg)) if msg.contains("duplicate link id")
        );
    }

    #[test]
    fn literal_policy_set_rejects_template_link_id_colliding_with_template_id() {
        let euid = models::EntityUid {
            ty: Some(models::Name {
                id: "User".to_string(),
                path: vec![],
            }),
            eid: "alice".to_string(),
        };
        let bad = models::PolicySet {
            templates: vec![trivial_template_body("shared_id")],
            links: vec![models::Policy {
                template_id: "shared_id".to_string(),
                link_id: Some("shared_id".to_string()),
                is_template_link: true,
                principal_euid: Some(euid),
                resource_euid: None,
            }],
        };
        assert_matches!(
            ast::LiteralPolicySet::try_from(bad),
            Err(ProtobufConversionError::InvalidValue(msg)) if msg.contains("conflicts with a template id")
        );
    }

    #[test]
    fn literal_policy_set_allows_static_policy_sharing_template_and_link_id() {
        // Static policies are expected to have the same ID in both templates and links
        let pset = models::PolicySet {
            templates: vec![trivial_template_body("static_policy")],
            links: vec![static_policy_link("static_policy")],
        };
        // This should succeed — static policies legitimately share an ID
        // between their template entry and link entry
        assert_matches!(ast::LiteralPolicySet::try_from(pset), Ok(_));
    }
}
