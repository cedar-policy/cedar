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

use super::Clause;
use super::Policy;
use super::PolicySetFromJsonError;
use crate::ast::{self, EntityUID, PolicyID, SlotId};
use crate::entities::json::err::JsonDeserializationErrorContext;
use crate::entities::json::EntityUidJson;
use crate::jsonvalue::deserialize_linked_hash_map_no_duplicates;
use crate::parser::cst::Policies;
use crate::parser::err::ParseErrors;
use crate::parser::Node;
use linked_hash_map::LinkedHashMap;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;

/// Serde JSON structure for a policy set in the EST format
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PolicySet {
    /// The set of templates in a policy set
    #[serde(deserialize_with = "deserialize_linked_hash_map_no_duplicates")]
    pub templates: LinkedHashMap<PolicyID, Policy>,
    /// The set of static policies in a policy set
    #[serde(deserialize_with = "deserialize_linked_hash_map_no_duplicates")]
    pub static_policies: LinkedHashMap<PolicyID, Policy>,
    /// The set of template links
    pub template_links: Vec<TemplateLink>,
}

impl PolicySet {
    /// Get the static or template-linked policy with the given id.
    /// Returns an `Option` rather than a `Result` because it is expected to be
    /// used in cases where the policy set is guaranteed to be well-formed
    /// (e.g., after successful conversion to an `ast::PolicySet`)
    pub fn get_policy(&self, id: &PolicyID) -> Option<Policy> {
        let maybe_static_policy = self.static_policies.get(id).cloned();

        let maybe_link = self
            .template_links
            .iter()
            .filter_map(|link| {
                if &link.new_id == id {
                    self.get_template(&link.template_id).and_then(|template| {
                        let unwrapped_est_vals: HashMap<SlotId, EntityUidJson> =
                            link.values.iter().map(|(k, v)| (*k, v.into())).collect();
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
        self.templates.get(id).cloned()
    }

    /// Return the largest `Expr::height` across every condition body in
    /// every static policy and template in this policy set.
    /// Returns `None` when there are no conditions.
    pub fn max_expr_height(&self) -> Option<usize> {
        self.static_policies
            .values()
            .chain(self.templates.values())
            .flat_map(|p| &p.conditions)
            .map(|clause| match clause {
                Clause::When(e) | Clause::Unless(e) => e.height(),
            })
            .max()
    }
}

/// Serde JSON structure describing a template-linked policy
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct TemplateLink {
    /// Id of the template to link against
    pub template_id: PolicyID,
    /// Id of the generated policy
    pub new_id: PolicyID,
    /// Mapping between slots and entity uids
    #[serde_as(as = "serde_with::MapPreventDuplicates<_,EntityUidJson<TemplateLinkContext>>")]
    pub values: HashMap<SlotId, EntityUID>,
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

        for (id, policy) in value.static_policies {
            let ast = policy.try_into_ast_policy(Some(id))?;
            ast_pset.add(ast)?;
        }

        for (id, policy) in value.templates {
            let ast = policy.try_into_ast_policy_or_template(Some(id))?;
            ast_pset.add_template(ast)?;
        }

        for TemplateLink {
            template_id,
            new_id,
            values,
        } in value.template_links
        {
            ast_pset.link(template_id, new_id, values)?;
        }

        Ok(ast_pset)
    }
}

impl TryFrom<Node<Option<Policies>>> for PolicySet {
    type Error = ParseErrors;

    fn try_from(policies: Node<Option<Policies>>) -> Result<Self, Self::Error> {
        let mut templates = LinkedHashMap::new();
        let mut static_policies = LinkedHashMap::new();
        let mut all_errs: Vec<ParseErrors> = vec![];
        for (policy_id, policy) in policies.with_generated_policyids()? {
            match policy.try_as_inner() {
                Ok(cst) => match Policy::try_from(cst.clone()) {
                    Ok(est) => {
                        if est.is_template() {
                            templates.insert(policy_id, est);
                        } else {
                            static_policies.insert(policy_id, est);
                        }
                    }
                    Err(e) => {
                        all_errs.push(e);
                    }
                },
                Err(e) => {
                    all_errs.push(e.into());
                }
            };
        }
        // fail on any error
        if let Some(errs) = ParseErrors::flatten(all_errs) {
            Err(errs)
        } else {
            Ok(PolicySet {
                templates,
                static_policies,
                template_links: Vec::new(),
            })
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    #[test]
    fn valid_example() {
        let json = json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": {
                        "op": "==",
                        "entity": { "type": "User", "id": "alice" }
                    },
                    "action": {
                        "op": "==",
                        "entity": { "type": "Action", "id": "view" }
                    },
                    "resource": {
                        "op": "in",
                        "entity": { "type": "Folder", "id": "foo" }
                    },
                    "conditions": []
                }
            },
            "templates": {
                "template": {
                    "effect" : "permit",
                    "principal" : {
                        "op" : "==",
                        "slot" : "?principal"
                    },
                    "action" : {
                        "op" : "all"
                    },
                    "resource" : {
                        "op" : "all",
                    },
                    "conditions": []
                }
            },
            "templateLinks" : [
                {
                    "newId" : "link",
                    "templateId" : "template",
                    "values" : {
                        "?principal" : { "type" : "User", "id" : "bob" }
                    }
                }
            ]
        });

        let est_policy_set: PolicySet =
            serde_json::from_value(json).expect("failed to parse from JSON");
        let ast_policy_set: ast::PolicySet =
            est_policy_set.try_into().expect("failed to convert to AST");
        assert_eq!(ast_policy_set.policies().count(), 2);
        assert_eq!(ast_policy_set.templates().count(), 1);
        assert!(ast_policy_set
            .get_template_arc(&PolicyID::from_string("template"))
            .is_some());
        let link = ast_policy_set.get(&PolicyID::from_string("link")).unwrap();
        assert_eq!(link.template().id(), &PolicyID::from_string("template"));
        assert_eq!(
            link.env(),
            &HashMap::from_iter([(SlotId::principal(), r#"User::"bob""#.parse().unwrap())])
        );
        assert_eq!(
            ast_policy_set
                .get_linked_policies(&PolicyID::from_string("template"))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn unknown_field() {
        let json = json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": {
                        "op": "==",
                        "entity": { "type": "User", "id": "alice" }
                    },
                    "action": {
                        "op" : "all"
                    },
                    "resource": {
                        "op" : "all"
                    },
                    "conditions": []
                }
            },
            "templates": {},
            "links" : []
        });

        let err = serde_json::from_value::<PolicySet>(json)
            .expect_err("should have failed to parse from JSON");
        assert_eq!(
            err.to_string(),
            "unknown field `links`, expected one of `templates`, `staticPolicies`, `templateLinks`"
        );
    }

    #[test]
    fn duplicate_policy_ids() {
        let str = r#"{
            "staticPolicies" : {
                "policy0": {
                    "effect": "permit",
                    "principal": {
                        "op": "==",
                        "entity": { "type": "User", "id": "alice" }
                    },
                    "action": {
                        "op" : "all"
                    },
                    "resource": {
                        "op" : "all"
                    },
                    "conditions": []
                },
                "policy0": {
                    "effect": "permit",
                    "principal": {
                        "op": "==",
                        "entity": { "type": "User", "id": "alice" }
                    },
                    "action": {
                        "op" : "all"
                    },
                    "resource": {
                        "op" : "all"
                    },
                    "conditions": []
                }
            },
            "templates" : {},
            "templateLinks" : []
        }"#;
        let err = serde_json::from_str::<PolicySet>(str)
            .expect_err("should have failed to parse from JSON");
        assert_eq!(
            err.to_string(),
            "invalid entry: found duplicate key at line 31 column 13"
        );
    }

    #[test]
    fn duplicate_slot_ids() {
        let str = r#"{
            "newId" : "foo",
            "templateId" : "bar",
            "values" : {
                "?principal" : { "type" : "User", "id" : "John" },
                "?principal" : { "type" : "User", "id" : "John" },
            }
        }"#;
        let err = serde_json::from_str::<TemplateLink>(str)
            .expect_err("should have failed to parse from JSON");
        assert_eq!(
            err.to_string(),
            "invalid entry: found duplicate key at line 6 column 65"
        );
    }

    #[test]
    fn try_from_policies_static_only() {
        let src = r#"
            permit(principal == User::"alice", action, resource);
            permit(principal, action == Action::"view", resource);
        "#;
        let node = crate::parser::text_to_cst::parse_policies(src).expect("Policies should parse");
        let policy_set =
            PolicySet::try_from(node).expect("Conversion to policy set should succeed");
        assert_eq!(policy_set.static_policies.len(), 2);
        assert!(policy_set.templates.is_empty());
        assert!(policy_set.template_links.is_empty());
    }

    #[test]
    fn try_from_policies_static_and_templates() {
        let src = r#"
            permit(principal == User::"alice", action, resource);
            permit(principal == ?principal, action == Action::"view", resource);
        "#;
        let node = crate::parser::text_to_cst::parse_policies(src).expect("Policies should parse");
        let policy_set =
            PolicySet::try_from(node).expect("Conversion to policy set should succeed");
        assert_eq!(policy_set.static_policies.len(), 1);
        assert_eq!(policy_set.templates.len(), 1);
        assert!(policy_set.template_links.is_empty());
    }

    #[test]
    fn try_from_policies_with_parse_error() {
        let src = r#"principal(p, action, resource);"#;
        let node = crate::parser::text_to_cst::parse_policies(src).expect("policies should parse");
        PolicySet::try_from(node).expect_err("Expected parse error to result in err");
    }

    #[test]
    fn max_expr_height_empty_policy_set() {
        let json = json!({
            "staticPolicies": {},
            "templates": {},
            "templateLinks": []
        });
        let policy_set: PolicySet =
            serde_json::from_value(json).expect("failed to parse from JSON");
        assert_eq!(policy_set.max_expr_height(), None);
    }

    #[test]
    fn max_expr_height_no_conditions() {
        let json = json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action": { "op": "All" },
                    "resource": { "op": "All" },
                    "conditions": []
                }
            },
            "templates": {},
            "templateLinks": []
        });
        let policy_set: PolicySet =
            serde_json::from_value(json).expect("failed to parse from JSON");
        assert_eq!(policy_set.max_expr_height(), None);
    }

    #[test]
    fn max_expr_height_single_literal_condition() {
        let json = json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action": { "op": "All" },
                    "resource": { "op": "All" },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": { "Value": true }
                        }
                    ]
                }
            },
            "templates": {},
            "templateLinks": []
        });
        let policy_set: PolicySet =
            serde_json::from_value(json).expect("failed to parse from JSON");
        assert_eq!(policy_set.max_expr_height(), Some(0));
    }

    #[test]
    fn max_expr_height_nested_expression() {
        let json = json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action": { "op": "All" },
                    "resource": { "op": "All" },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "==": {
                                    "left": { "Value": 1 },
                                    "right": { "Value": 2 }
                                }
                            }
                        }
                    ]
                }
            },
            "templates": {},
            "templateLinks": []
        });
        let policy_set: PolicySet =
            serde_json::from_value(json).expect("failed to parse from JSON");
        assert_eq!(policy_set.max_expr_height(), Some(1));
    }

    #[test]
    fn max_expr_height_multiple_policies_takes_max() {
        // policy1 condition: `true` => height 0
        // policy2 condition: `!(1 == 2)` => height 2
        let json = json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action": { "op": "All" },
                    "resource": { "op": "All" },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": { "Value": true }
                        }
                    ]
                },
                "policy2": {
                    "effect": "forbid",
                    "principal": { "op": "All" },
                    "action": { "op": "All" },
                    "resource": { "op": "All" },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "!": {
                                    "arg": {
                                        "==": {
                                            "left": { "Value": 1 },
                                            "right": { "Value": 2 }
                                        }
                                    }
                                }
                            }
                        }
                    ]
                }
            },
            "templates": {},
            "templateLinks": []
        });
        let policy_set: PolicySet =
            serde_json::from_value(json).expect("failed to parse from JSON");
        assert_eq!(policy_set.max_expr_height(), Some(2));
    }

    #[test]
    fn max_expr_height_unless_clause() {
        // `unless { 1 == 2 }` => height 1
        let json = json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action": { "op": "All" },
                    "resource": { "op": "All" },
                    "conditions": [
                        {
                            "kind": "unless",
                            "body": {
                                "==": {
                                    "left": { "Value": 1 },
                                    "right": { "Value": 2 }
                                }
                            }
                        }
                    ]
                }
            },
            "templates": {},
            "templateLinks": []
        });
        let policy_set: PolicySet =
            serde_json::from_value(json).expect("failed to parse from JSON");
        assert_eq!(policy_set.max_expr_height(), Some(1));
    }

    #[test]
    fn max_expr_height_templates_included() {
        // static policy condition: `true` => height 0
        // template condition: `!(1 == 2)` => height 2
        // max should be 2 (from template)
        let json = json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action": { "op": "All" },
                    "resource": { "op": "All" },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": { "Value": true }
                        }
                    ]
                }
            },
            "templates": {
                "template1": {
                    "effect": "permit",
                    "principal": { "op": "==", "slot": "?principal" },
                    "action": { "op": "All" },
                    "resource": { "op": "All" },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "!": {
                                    "arg": {
                                        "==": {
                                            "left": { "Value": 1 },
                                            "right": { "Value": 2 }
                                        }
                                    }
                                }
                            }
                        }
                    ]
                }
            },
            "templateLinks": []
        });
        let policy_set: PolicySet =
            serde_json::from_value(json).expect("failed to parse from JSON");
        assert_eq!(policy_set.max_expr_height(), Some(2));
    }

    #[test]
    fn max_expr_height_multiple_conditions_per_policy() {
        // Two conditions on one policy:
        //   when { true } => height 0
        //   when { 1 == 2 } => height 1
        // Max should be 1
        let json = json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action": { "op": "All" },
                    "resource": { "op": "All" },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": { "Value": true }
                        },
                        {
                            "kind": "when",
                            "body": {
                                "==": {
                                    "left": { "Value": 1 },
                                    "right": { "Value": 2 }
                                }
                            }
                        }
                    ]
                }
            },
            "templates": {},
            "templateLinks": []
        });
        let policy_set: PolicySet =
            serde_json::from_value(json).expect("failed to parse from JSON");
        assert_eq!(policy_set.max_expr_height(), Some(1));
    }

    #[test]
    fn max_expr_height_literal_nested_set_matches_non_literal() {
        // A literal set-of-set-of-set expressed as a Value node:
        // Value(Set([Set([Set([Long(1)])])])) has CedarValueJson height 3,
        // which is added to the Value node's depth (0), giving height 3.
        let json_literal = json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action": { "op": "All" },
                    "resource": { "op": "All" },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "Value": [[[1]]]
                            }
                        }
                    ]
                }
            },
            "templates": {},
            "templateLinks": []
        });
        let policy_set_literal: PolicySet =
            serde_json::from_value(json_literal).expect("failed to parse from JSON");
        assert_eq!(policy_set_literal.max_expr_height(), Some(3));
        // The same nesting expressed as non-literal Expr Set nodes:
        // Set([Set([Set([Value(1)])])])
        // 3 edges on the longest root-to-leaf path => height 3
        let json_non_literal = json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action": { "op": "All" },
                    "resource": { "op": "All" },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "Set": [
                                    { "Set": [
                                        { "Set": [
                                            { "Value": 1 }
                                        ]}
                                    ]}
                                ]
                            }
                        }
                    ]
                }
            },
            "templates": {},
            "templateLinks": []
        });
        let policy_set_non_literal: PolicySet =
            serde_json::from_value(json_non_literal).expect("failed to parse from JSON");
        assert_eq!(policy_set_non_literal.max_expr_height(), Some(3));
        // Both representations have the same height
        assert_eq!(
            policy_set_literal.max_expr_height(),
            policy_set_non_literal.max_expr_height()
        );
    }

    #[test]
    fn max_expr_height_deeply_nested() {
        // !(!(!(true))): 3 edges on the longest root-to-leaf path => height 3
        let json = json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": { "op": "All" },
                    "action": { "op": "All" },
                    "resource": { "op": "All" },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "!": {
                                    "arg": {
                                        "!": {
                                            "arg": {
                                                "!": {
                                                    "arg": { "Value": true }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    ]
                }
            },
            "templates": {},
            "templateLinks": []
        });
        let policy_set: PolicySet =
            serde_json::from_value(json).expect("failed to parse from JSON");
        assert_eq!(policy_set.max_expr_height(), Some(3));
    }
}
