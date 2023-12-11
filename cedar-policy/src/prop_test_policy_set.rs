#![cfg(test)]
// PANIC SAFETY unit tests
#![allow(clippy::panic)]

use super::*;
use proptest::prelude::*;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::str::FromStr;

/// Production PolicySet along with simplified model of policy set
/// for Proptesting
///
/// We model the PolicySet state machine as lists of static policies, links and templates.
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
    static_policy_names: Vec<String>,
    link_names: Vec<String>,
    template_names: Vec<String>,

    //Every existent template has a (possibly empty) vector of the links to that template
    template_to_link_map: HashMap<String, Vec<String>>,

    //Every link points to its template
    link_to_template_map: HashMap<String, String>,
}

/// Model of a PolicySet where ops that shouldn't be allowed have no effect
/// e.g., remove_static with no static policies does nothing
impl PolicySetModel {
    fn new() -> Self {
        Self {
            policy_set: PolicySet::new(),
            static_policy_names: Vec::new(),
            link_names: Vec::new(),
            template_names: Vec::new(),
            template_to_link_map: HashMap::new(),
            link_to_template_map: HashMap::new(),
        }
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_name_unique(&self, policy_id: &String) {
        assert!(!self.static_policy_names.iter().any(|p| p == policy_id));
        assert!(!self.link_names.iter().any(|p| p == policy_id));
        assert!(!self.template_names.iter().any(|p| p == policy_id));
    }

    fn add_static(&mut self, policy_name: String) {
        let policy_str = "permit(principal, action, resource);";
        let p = Policy::parse(Some(policy_name.clone()), policy_str).unwrap();
        if self.policy_set.add(p).is_ok() {
            self.assert_name_unique(&policy_name);
            self.static_policy_names.push(policy_name);
        }
    }

    fn add_template(&mut self, template_name: String) {
        let template_str = "permit(principal == ?principal, action, resource);";
        let template = Template::parse(Some(template_name.clone()), template_str).unwrap();
        if self.policy_set.add_template(template).is_ok() {
            self.assert_name_unique(&template_name);
            self.template_names.push(template_name.clone());
            self.template_to_link_map.insert(template_name, Vec::new());
        }
    }

    fn link(&mut self, policy_name: String) {
        if self.template_names.len() > 0 {
            let euid = EntityUid::from_strs("User", "alice");
            let template_name = self.template_names.last().unwrap();
            let vals = HashMap::from([(SlotId::principal(), euid)]);
            if self
                .policy_set
                .link(
                    PolicyId::from_str(template_name).unwrap(),
                    PolicyId::from_str(&policy_name).unwrap(),
                    vals,
                )
                .is_ok()
            {
                self.assert_name_unique(&policy_name);
                self.link_names.push(policy_name.clone());
                match self.template_to_link_map.entry(template_name.clone()) {
                    Entry::Occupied(v) => v.into_mut().push(policy_name.clone()),
                    Entry::Vacant(_) => {
                        panic!("template to link map should have Vec for existing template")
                    }
                };
                assert!(self.link_to_template_map.get(&policy_name).is_none());
                self.link_to_template_map
                    .insert(policy_name, template_name.clone());
            }
        }
    }

    fn remove_policy_name(names: &mut Vec<String>, policy_name: String) {
        let idx = names
            .iter()
            .position(|r| r == &policy_name)
            .expect(&format!("Should find policy_name {policy_name}"));
        names.remove(idx);
    }

    fn remove_static(&mut self, policy_id: String) {
        //Remove from PolicySet and `link_names`
        if self
            .policy_set
            .remove_static(PolicyId::from_str(&policy_id).unwrap())
            .is_ok()
        {
            println!("Remove_static {policy_id}");
            Self::remove_policy_name(&mut self.static_policy_names, policy_id);
        }
    }

    fn remove_template(&mut self, template_name: String) {
        if self
            .policy_set
            .remove_template(PolicyId::from_str(&template_name).unwrap())
            .is_ok()
        {
            println!("Remove_template {template_name}");
            //Assert no link exists
            assert!(!self
                .link_to_template_map
                .iter()
                .any(|(_, v)| v == &template_name));
            //Remove from `template_to_link_map`, `template_names` and the PolicySet
            self.template_to_link_map
                .remove(&template_name)
                .expect("Template should exist");
            Self::remove_policy_name(&mut self.template_names, template_name);
        }
    }

    fn unlink(&mut self, policy_id: String) {
        if self
            .policy_set
            .unlink(PolicyId::from_str(&policy_id).unwrap())
            .is_ok()
        {
            println!("Unlink {policy_id}");
            if let Some(template_name) = self.link_to_template_map.get(&policy_id) {
                let template_name = template_name.clone();
                self.link_to_template_map
                    .remove(&policy_id)
                    .expect("Template should exist");
                match self.template_to_link_map.entry(template_name.clone()) {
                    Entry::Occupied(e) => {
                        let v = e.into_mut();
                        let idx = v
                            .iter()
                            .position(|r| r == &policy_id)
                            .expect("Should find index for link");
                        v.remove(idx);
                    }
                    Entry::Vacant(_) => {
                        panic!("template to link map should have Vec for existing template")
                    }
                };
                Self::remove_policy_name(&mut self.link_names, policy_id);
            } else {
                //Then it was a static_policy
                Self::remove_policy_name(&mut self.link_names, policy_id);
            }
        }
    }

    /// Panics if policy_set.policies() or policy_set.templates() doesn't match the model's
    /// static policies, links or templates
    fn check_equiv(&self) {
        let real_policy_set_links: Vec<_> = self.policy_set.policies().collect();
        let real_policy_set_templates: Vec<_> = self.policy_set.templates().collect();
        // A static policy (in the model) should be in the `PolicySet`'s ast.links and ast.templates,
        // but is only returned by policy_set.policies().
        for policy_name in &self.static_policy_names {
            assert!(real_policy_set_links
                .iter()
                .any(|p| p.id() == &PolicyId::from_str(&policy_name).unwrap()));
        }
        for policy_name in &self.link_names {
            assert!(real_policy_set_links
                .iter()
                .any(|p| p.id() == &PolicyId::from_str(&policy_name).unwrap()));
        }

        for link_name in real_policy_set_links {
            assert!(
                self.static_policy_names
                    .iter()
                    .any(|p| link_name.id() == &PolicyId::from_str(p).unwrap())
                    || self
                        .link_names
                        .iter()
                        .any(|p| link_name.id() == &PolicyId::from_str(p).unwrap())
            );
        }

        for template_name in &self.template_names {
            assert!(real_policy_set_templates
                .iter()
                .any(|p| p.id() == &PolicyId::from_str(&template_name).unwrap()));
        }
        for template_name in real_policy_set_templates {
            assert!(self
                .template_names
                .iter()
                .any(|p| template_name.id() == &PolicyId::from_str(p).unwrap()));
        }
    }
}

fn string_to_policy_set_ops(s: &str) {
    let mut my_policy_set = PolicySetModel::new();
    enum PolicySetOp {
        Add,
        RemoveStatic,
        AddTemplate,
        RemoveTemplate,
        Link,
        Unlink,
    }
    use PolicySetOp::*;
    let n_to_op_map: HashMap<u32, PolicySetOp> = HashMap::from([
        (0, Add),
        (1, RemoveStatic),
        (2, AddTemplate),
        (3, RemoveTemplate),
        (4, Link),
        (5, Unlink),
    ]);

    let mut ints: Vec<(u32, u32)> = Vec::new();
    let mut last_int: Option<u32> = None;
    for c in s.chars() {
        let n = c.to_digit(10);
        match n {
            Some(n) => match last_int {
                Some(i) => {
                    ints.push((i, n));
                    last_int = None;
                }
                None => last_int = Some(n),
            },
            None => panic!("Should be able to convert to ints"),
        }
    }

    for (op_n, policy_n) in ints {
        if op_n > 5 {
            panic!("Testing harness sending numbers greater than 5");
        }
        let op = n_to_op_map.get(&op_n).unwrap();
        match op {
            Add => my_policy_set.add_static(format!("policy{policy_n}")),
            RemoveStatic => my_policy_set.remove_static(format!("policy{policy_n}")),
            AddTemplate => my_policy_set.add_template(format!("policy{policy_n}")),
            RemoveTemplate => my_policy_set.remove_template(format!("policy{policy_n}")),
            Link => my_policy_set.link(format!("policy{policy_n}")),
            Unlink => my_policy_set.unlink(format!("policy{policy_n}")),
        };

        my_policy_set.check_equiv();
    }
}

proptest! {
    #[test]
    fn doesnt_crash(s in "[0-5]{20}") {
        string_to_policy_set_ops(&s);
    }
}
