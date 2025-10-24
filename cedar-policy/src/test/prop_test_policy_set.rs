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

use super::super::*;
use itertools::Itertools;
use proptest::prelude::*;
use similar_asserts::assert_eq;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Production `PolicySet` along with simplified model of policy set
/// for Proptesting
///
/// We model the `PolicySet` state machine as lists of static policies, links and templates.
/// In the real policy set, a static policy will be a in both `ast.links` and `ast.templates`
/// (with the same `PolicyId`). Links and templates will be in `ast.links` and `ast.templates`
/// respectively.
///
/// In the model, no name should occur in multiple lists or in the same list multiple times.
/// Every links should have a templates and a template should store a (possibly empty) list of it's links.
struct PolicySetModel {
    //The production PolicySet implementation
    policy_set: PolicySet,

    // The model
    static_policy_names: BTreeSet<String>,
    link_names: BTreeSet<String>,
    template_names: BTreeSet<String>,

    //Every existent template has a (possibly empty) vector of the links to that template
    template_to_link_map: BTreeMap<String, Vec<String>>,

    //Every link points to its template
    link_to_template_map: BTreeMap<String, String>,
}

/// Model of a `PolicySet` where ops that shouldn't be allowed have no effect
/// e.g., `remove_static` with no static policies does nothing
impl PolicySetModel {
    fn new() -> Self {
        Self {
            policy_set: PolicySet::new(),
            static_policy_names: BTreeSet::new(),
            link_names: BTreeSet::new(),
            template_names: BTreeSet::new(),
            template_to_link_map: BTreeMap::new(),
            link_to_template_map: BTreeMap::new(),
        }
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_name_unique(&self, policy_id: &str) {
        assert!(
            self.is_name_unique(policy_id),
            "expected that {policy_id} would be unique\nstatic: {:?}\nlinks: {:?}\ntemplate: {:?}",
            self.static_policy_names,
            self.link_names,
            self.template_names
        );
    }

    fn is_name_unique(&self, policy_id: &str) -> bool {
        !self.static_policy_names.iter().any(|p| p == policy_id)
            && !self.link_names.iter().any(|p| p == policy_id)
            && !self.template_names.iter().any(|p| p == policy_id)
    }

    fn add_static(&mut self, policy_name: &str, variant: bool) {
        let policy_str = if variant {
            "permit(principal, action, resource);"
        } else {
            "forbid(principal, action, resource);"
        };
        let p = Policy::parse(Some(PolicyId::new(policy_name)), policy_str).unwrap();
        if self.policy_set.add(p).is_ok() {
            self.assert_name_unique(policy_name);
            self.static_policy_names.insert(policy_name.to_owned());
        }
    }

    fn add_template(&mut self, template_name: &str, variant: bool) {
        let template_str = if variant {
            "permit(principal == ?principal, action, resource);"
        } else {
            "forbid(principal == ?principal, action, resource);"
        };
        let template = Template::parse(Some(PolicyId::new(template_name)), template_str).unwrap();
        if self.policy_set.add_template(template).is_ok() {
            self.assert_name_unique(template_name);
            self.template_names.insert(template_name.to_owned());
            self.template_to_link_map
                .insert(template_name.to_owned(), Vec::new());
        }
    }

    fn link(&mut self, policy_name: &str, variant: bool) {
        if !self.template_names.is_empty() {
            let euid = if variant {
                EntityUid::from_strs("User", "alice")
            } else {
                EntityUid::from_strs("User", "bob")
            };
            let template_name = self.template_names.last().unwrap();
            let vals = HashMap::from([(SlotId::principal(), euid)]);
            if self
                .policy_set
                .link(
                    PolicyId::new(template_name),
                    PolicyId::new(policy_name),
                    vals,
                )
                .is_ok()
            {
                self.assert_name_unique(policy_name);
                self.link_names.insert(policy_name.to_owned());
                match self.template_to_link_map.entry(template_name.clone()) {
                    Entry::Occupied(v) => v.into_mut().push(policy_name.to_owned()),
                    Entry::Vacant(_) => {
                        panic!("template to link map should have Vec for existing template")
                    }
                }
                assert!(!self.link_to_template_map.contains_key(policy_name));
                self.link_to_template_map
                    .insert(policy_name.to_owned(), template_name.clone());
            }
        }
    }

    #[track_caller]
    fn remove_policy_name(names: &mut BTreeSet<String>, policy_name: &str) {
        let removed = names.remove(policy_name);
        assert!(removed, "Should find policy_name {policy_name}");
    }

    fn remove_static(&mut self, policy_id: &str) {
        //Remove from PolicySet and `link_names`
        if self
            .policy_set
            .remove_static(PolicyId::new(policy_id))
            .is_ok()
        {
            println!("Remove_static {policy_id}");
            Self::remove_policy_name(&mut self.static_policy_names, policy_id);
        }
    }

    fn remove_template(&mut self, template_name: &str) {
        if self
            .policy_set
            .remove_template(PolicyId::new(template_name))
            .is_ok()
        {
            println!("Remove_template {template_name}");
            //Assert no link exists
            assert!(!self
                .link_to_template_map
                .iter()
                .any(|(_, v)| v == template_name));
            //Remove from `template_to_link_map`, `template_names` and the PolicySet
            self.template_to_link_map
                .remove(template_name)
                .expect("Template should exist");
            Self::remove_policy_name(&mut self.template_names, template_name);
        }
    }

    fn unlink(&mut self, policy_id: &str) {
        if self.policy_set.unlink(PolicyId::new(policy_id)).is_ok() {
            println!("Unlink {policy_id}");
            if let Some(template_name) = self.link_to_template_map.get(policy_id) {
                let template_name = template_name.clone();
                self.link_to_template_map
                    .remove(policy_id)
                    .expect("Template should exist");
                match self.template_to_link_map.entry(template_name) {
                    Entry::Occupied(e) => {
                        let v = e.into_mut();
                        let idx = v
                            .iter()
                            .position(|r| r == policy_id)
                            .expect("Should find index for link");
                        v.remove(idx);
                    }
                    Entry::Vacant(_) => {
                        panic!("template to link map should have Vec for existing template")
                    }
                }
            }
            Self::remove_policy_name(&mut self.link_names, policy_id);
        }
    }

    #[track_caller]
    fn get_renaming(
        &self,
        renaming: &HashMap<PolicyId, PolicyId>,
        id: &str,
        assert_unique: bool,
    ) -> String {
        if self.is_name_unique(id) {
            assert!(
                !renaming.contains_key(&PolicyId::new(id)),
                "id shouldn't need to be renamed"
            );
            id.to_string()
        } else {
            if let Some(id) = renaming.get(&PolicyId::new(id)) {
                if assert_unique {
                    self.assert_name_unique(&id.to_string());
                }
                id.to_string()
            } else {
                // Policies aren't renamed if they're identical. The model
                // doesn't track policy contents, so we have to assume that
                // is fine.
                id.to_string()
            }
        }
    }

    fn merge(&mut self, other: &Self) {
        let renaming = self.policy_set.merge(&other.policy_set, true).unwrap();

        for static_policy in &other.static_policy_names {
            let static_policy = self.get_renaming(&renaming, static_policy, true);
            self.static_policy_names.insert(static_policy);
        }

        for link in &other.link_names {
            let link = self.get_renaming(&renaming, link, true);
            self.link_names.insert(link);
        }

        for template in &other.template_names {
            let template = self.get_renaming(&renaming, template, true);
            self.template_names.insert(template);
        }

        for (template, links) in &other.template_to_link_map {
            let links = links
                .iter()
                .map(|id| self.get_renaming(&renaming, id, false))
                .collect_vec();
            let template = self.get_renaming(&renaming, template, false);
            self.template_to_link_map
                .entry(template)
                .or_default()
                .extend_from_slice(&links)
        }

        for (link, template) in &other.link_to_template_map {
            let link = self.get_renaming(&renaming, link, false);
            let template = self.get_renaming(&renaming, template, false);
            self.link_to_template_map.insert(link, template);
        }
    }

    /// Panics if `policy_set.policies`() or `policy_set.templates`() doesn't match the model's
    /// static policies, links or templates
    fn check_equiv(&self) {
        let real_static: BTreeSet<_> = self
            .policy_set
            .policies()
            .filter(|p| p.is_static())
            .map(|p| p.id().to_string())
            .collect();
        assert_eq!(real: real_static, model: self.static_policy_names);

        let real_links: BTreeSet<_> = self
            .policy_set
            .policies()
            .filter(|p| !p.is_static())
            .map(|p| p.id().to_string())
            .collect();
        assert_eq!(real: real_links, model: self.link_names);

        let real_link_to_template: BTreeMap<_, _> = self
            .policy_set
            .policies()
            .filter_map(|p| {
                p.template_id()
                    .map(|tid| (p.id().to_string(), tid.to_string()))
            })
            .collect();
        assert_eq!(real: real_link_to_template, model: self.link_to_template_map);

        let real_policy_set_templates: BTreeSet<_> = self
            .policy_set
            .templates()
            .map(|p| p.id().to_string())
            .collect();
        assert_eq!(real: real_policy_set_templates, model: self.template_names);
    }
}

#[derive(Debug, Copy, Clone)]
enum PolicySetOp {
    Add(bool),
    RemoveStatic,
    AddTemplate(bool),
    RemoveTemplate,
    Link(bool),
    Unlink,
    Merge,
}

// String format is (op, policy_id, policy_set_id) where each
// of op, policy_id, variant_selector, and policy_set_id is exactly one character.
// * op must be in [0-9]. This defines the operation to perform
// * policy_id must a base-10 digit ([0-9]).  This defines the policy id to create/delete/etc.
// * policy_set_id is either 0 or 1. This decides which policy set to modify.
fn string_to_policy_set_ops(s: &str) {
    let n_to_op_map: HashMap<u32, PolicySetOp> = HashMap::from([
        (0, PolicySetOp::Add(true)),
        (1, PolicySetOp::Add(false)),
        (2, PolicySetOp::RemoveStatic),
        (3, PolicySetOp::AddTemplate(true)),
        (4, PolicySetOp::AddTemplate(false)),
        (5, PolicySetOp::RemoveTemplate),
        (6, PolicySetOp::Link(true)),
        (7, PolicySetOp::Link(false)),
        (8, PolicySetOp::Unlink),
        (9, PolicySetOp::Merge),
    ]);

    let ops = s
        .chars()
        .map(|c| c.to_digit(10).expect("Should be able to convert to ints"))
        .tuples()
        .map(|(op_n, policy_n, policy_set_n)| {
            let op = n_to_op_map
                .get(&op_n)
                .expect("Should be able to convert to op");
            (*op, policy_n, policy_set_n)
        });

    let mut ps0 = PolicySetModel::new();
    let mut ps1 = PolicySetModel::new();

    for (op, policy_n, policy_set_n) in ops {
        let (my_policy_set, other_policy_set) = match policy_set_n {
            0 => (&mut ps0, &ps1),
            1 => (&mut ps1, &ps0),
            _ => panic!("policy set index out of range"),
        };
        match op {
            PolicySetOp::Add(variant) => {
                my_policy_set.add_static(&format!("policy{policy_n}"), variant)
            }
            PolicySetOp::RemoveStatic => my_policy_set.remove_static(&format!("policy{policy_n}")),
            PolicySetOp::AddTemplate(variant) => {
                my_policy_set.add_template(&format!("policy{policy_n}"), variant)
            }
            PolicySetOp::RemoveTemplate => {
                my_policy_set.remove_template(&format!("policy{policy_n}"));
            }
            PolicySetOp::Link(variant) => my_policy_set.link(&format!("policy{policy_n}"), variant),
            PolicySetOp::Unlink => my_policy_set.unlink(&format!("policy{policy_n}")),
            PolicySetOp::Merge => my_policy_set.merge(other_policy_set),
        }

        my_policy_set.check_equiv();
    }
}

proptest! {
    #[test]
    fn doesnt_crash(s in "([0-9][0-9][01]){20}") {
        string_to_policy_set_ops(&s);
    }
}
