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

use super::Policy;
use super::PolicySetFromJsonError;
use crate::ast::{self, EntityUID, PolicyID, SlotId};
use crate::entities::json::err::JsonDeserializationErrorContext;
use crate::entities::json::EntityUidJson;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;

/// An EST set of policies
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PolicySet {
    /// The set of templates in a policy set
    pub templates: Vec<PolicyEntry>,
    /// The set of static policies in a policy set
    pub static_policies: Vec<PolicyEntry>,
    /// The set of template links
    pub links: Vec<Link>,
}

impl PolicySet {
    /// Get the static or template-linked policy with the given id.
    /// Returns an `Option` rather than a `Result` because it is expected to be
    /// used in cases where the policy set is guaranteed to be well-formed
    /// (e.g., after successful conversion to an `ast::PolicySet`)
    pub fn get_policy(&self, id: &PolicyID) -> Option<Policy> {
        let maybe_static_policy = self
            .static_policies
            .iter()
            .filter_map(|entry| {
                if &entry.id == id {
                    Some(entry.policy.clone())
                } else {
                    None
                }
            })
            .next();

        let maybe_link = self
            .links
            .iter()
            .filter_map(|link| {
                if &link.id == id {
                    self.get_template(&link.template).and_then(|template| {
                        let unwrapped_est_vals: HashMap<SlotId, EntityUidJson> =
                            link.slots.iter().map(|(k, v)| (*k, v.into())).collect();
                        template.link(&unwrapped_est_vals).ok()
                    })
                } else {
                    None
                }
            })
            .next();

        maybe_static_policy.or(maybe_link)
    }

    /// Get the template with the given id.
    /// Returns an `Option` rather than a `Result` because it is expected to be
    /// used in cases where the policy set is guaranteed to be well-formed
    /// (e.g., after successful conversion to an `ast::PolicySet`)
    pub fn get_template(&self, id: &PolicyID) -> Option<Policy> {
        self.templates
            .iter()
            .filter_map(|entry| {
                if &entry.id == id {
                    Some(entry.policy.clone())
                } else {
                    None
                }
            })
            .next()
    }
}

/// A policy id and EST policy pair
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyEntry {
    /// The id of this policy
    pub id: PolicyID,
    /// The EST of this policy
    pub policy: Policy,
}

/// A record of a template-linked policy
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    /// The id of the link
    pub id: PolicyID,
    /// The id of the template
    pub template: PolicyID,
    /// The mapping between slots and entity uids
    #[serde_as(as = "serde_with::MapPreventDuplicates<_,EntityUidJson<TemplateLinkContext>>")]
    pub slots: HashMap<SlotId, EntityUID>,
}

/// Statically set the deserialization error context to be deserialization of a template link
struct TemplateLinkContext;

impl crate::entities::json::DeserializationContext for TemplateLinkContext {
    fn static_context() -> Option<JsonDeserializationErrorContext> {
        Some(JsonDeserializationErrorContext::TemplateLink)
    }
}

impl TryFrom<PolicySet> for ast::PolicySet {
    type Error = PolicySetFromJsonError;

    fn try_from(value: PolicySet) -> Result<Self, Self::Error> {
        let mut ast_pset = ast::PolicySet::default();

        for PolicyEntry { id, policy } in value.templates {
            let ast = policy.try_into_ast_template(Some(id))?;
            ast_pset.add_template(ast)?;
        }

        for PolicyEntry { id, policy } in value.static_policies {
            let ast = policy.try_into_ast_policy(Some(id))?;
            ast_pset.add(ast)?;
        }

        for Link {
            id,
            template,
            slots: env,
        } in value.links
        {
            ast_pset.link(template, id, env)?;
        }

        Ok(ast_pset)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn link_prevents_duplicates() {
        let value = r#"
            "id" : "foo",
            "template" : "bar",
            "env" : {
                "?principal" : { "type" : "User", "id" : "John" },
                "?principal" : { "type" : "User", "id" : "John" },
            }
        }"#;
        let r: Result<Link, _> = serde_json::from_str(value);
        assert!(r.is_err());
    }
}
